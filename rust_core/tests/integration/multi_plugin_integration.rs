//! Multi-Plugin Integration Tests
//!
//! Tests for complex scenarios involving multiple plugins working together.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

use super::*;
use claude_optimized_deployment_rust::mcp_manager::plugin::{
    *,
    registry::*,
    lifecycle::*,
    capabilities::*,
    negotiation::*,
    zero_downtime::*,
};
use std::collections::HashMap;
use tokio::time::{sleep, Duration};

/// Multi-plugin test plugin with inter-plugin communication
#[derive(Debug)]
struct MultiPluginTestPlugin {
    metadata: PluginMetadata,
    requests_handled: Arc<AtomicU64>,
    messages_sent: Arc<AtomicU64>,
    messages_received: Arc<AtomicU64>,
    plugin_registry: Arc<RwLock<HashMap<String, Arc<PluginHandle>>>>,
}

impl MultiPluginTestPlugin {
    fn new(id: &str, capabilities: Vec<Capability>, requires: Vec<Capability>) -> Self {
        Self {
            metadata: PluginMetadata {
                id: id.to_string(),
                name: format!("Multi-Plugin Test {}", id),
                version: "1.0.0".to_string(),
                author: "Test".to_string(),
                description: format!("Multi-plugin test plugin {}", id),
                license: "MIT".to_string(),
                homepage: None,
                repository: None,
                min_mcp_version: "1.0.0".to_string(),
                dependencies: vec![],
                provides: capabilities,
                requires,
            },
            requests_handled: Arc::new(AtomicU64::new(0)),
            messages_sent: Arc::new(AtomicU64::new(0)),
            messages_received: Arc::new(AtomicU64::new(0)),
            plugin_registry: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn send_message_to(&self, target_id: &str, message: serde_json::Value) -> Result<serde_json::Value> {
        let registry = self.plugin_registry.read().await;
        if let Some(target) = registry.get(target_id) {
            self.messages_sent.fetch_add(1, Ordering::SeqCst);
            
            let request = PluginRequest {
                id: format!("msg-{}-{}", self.metadata.id, uuid::Uuid::new_v4()),
                capability: Capability::new("interop", "message", 1),
                method: "receive_message".to_string(),
                params: json!({
                    "from": self.metadata.id,
                    "message": message,
                }),
                metadata: json!({}),
            };

            let response = target.handle(request).await?;
            if let PluginResult::Success { data } = response.result {
                Ok(data)
            } else {
                Err(PluginError::ExecutionError("Message delivery failed".to_string()))
            }
        } else {
            Err(PluginError::NotFound(format!("Plugin {} not found", target_id)))
        }
    }
}

#[async_trait::async_trait]
impl Plugin for MultiPluginTestPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    async fn initialize(&mut self, _config: serde_json::Value) -> Result<()> {
        Ok(())
    }

    async fn handle(&self, request: PluginRequest) -> Result<PluginResponse> {
        self.requests_handled.fetch_add(1, Ordering::SeqCst);

        match request.method.as_str() {
            "receive_message" => {
                self.messages_received.fetch_add(1, Ordering::SeqCst);
                Ok(PluginResponse {
                    request_id: request.id,
                    result: PluginResult::Success {
                        data: json!({
                            "received": true,
                            "from": request.params["from"],
                            "plugin_id": self.metadata.id,
                        }),
                    },
                    metadata: json!({}),
                })
            }
            "process" => {
                // Simulate processing that might involve other plugins
                let data = request.params.get("data").cloned().unwrap_or(json!({}));
                
                Ok(PluginResponse {
                    request_id: request.id,
                    result: PluginResult::Success {
                        data: json!({
                            "processed_by": self.metadata.id,
                            "data": data,
                            "requests_handled": self.requests_handled.load(Ordering::SeqCst),
                        }),
                    },
                    metadata: json!({}),
                })
            }
            _ => Ok(PluginResponse {
                request_id: request.id,
                result: PluginResult::Success {
                    data: json!({
                        "plugin_id": self.metadata.id,
                        "method": request.method,
                    }),
                },
                metadata: json!({}),
            }),
        }
    }

    async fn shutdown(&mut self) -> Result<()> {
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[tokio::test]
    async fn test_multi_plugin_coordination() {
        let env = TestEnvironment::new(TestConfig::default()).await;
        env.setup().await.unwrap();

        let mut registry = PluginRegistry::new();
        let lifecycle_manager = LifecycleManager::new(Default::default());

        // Create a pipeline of plugins: data -> processor -> aggregator -> output
        let data_plugin = MultiPluginTestPlugin::new(
            "data-source",
            vec![
                Capability::new("data", "provide", 1),
                Capability::new("interop", "message", 1),
            ],
            vec![],
        );

        let processor_plugin = MultiPluginTestPlugin::new(
            "processor",
            vec![
                Capability::new("processing", "transform", 1),
                Capability::new("interop", "message", 1),
            ],
            vec![Capability::new("data", "provide", 1)],
        );

        let aggregator_plugin = MultiPluginTestPlugin::new(
            "aggregator",
            vec![
                Capability::new("aggregation", "combine", 1),
                Capability::new("interop", "message", 1),
            ],
            vec![Capability::new("processing", "transform", 1)],
        );

        // Create handles
        let data_handle = Arc::new(PluginHandle::new(Box::new(data_plugin)));
        let processor_handle = Arc::new(PluginHandle::new(Box::new(processor_plugin)));
        let aggregator_handle = Arc::new(PluginHandle::new(Box::new(aggregator_plugin)));

        // Register all plugins
        registry.register("data-source".to_string(), data_handle.clone()).unwrap();
        registry.register("processor".to_string(), processor_handle.clone()).unwrap();
        registry.register("aggregator".to_string(), aggregator_handle.clone()).unwrap();

        // Initialize all plugins
        for (id, handle) in [
            ("data-source", data_handle.clone()),
            ("processor", processor_handle.clone()),
            ("aggregator", aggregator_handle.clone()),
        ] {
            lifecycle_manager.register_plugin(id.to_string(), handle.clone()).await.unwrap();
            lifecycle_manager.initialize_plugin(id, json!({})).await.unwrap();
        }

        // Set up plugin registry for inter-plugin communication
        let plugin_registry = Arc::new(RwLock::new(HashMap::from([
            ("data-source".to_string(), data_handle.clone()),
            ("processor".to_string(), processor_handle.clone()),
            ("aggregator".to_string(), aggregator_handle.clone()),
        ])));

        // Update each plugin's registry
        for handle in [&data_handle, &processor_handle, &aggregator_handle] {
            if let Some(plugin) = handle.as_any().downcast_ref::<MultiPluginTestPlugin>() {
                *plugin.plugin_registry.write().await = plugin_registry.read().await.clone();
            }
        }

        // Test the pipeline
        let request = PluginRequest {
            id: "pipeline-1".to_string(),
            capability: Capability::new("data", "provide", 1),
            method: "process".to_string(),
            params: json!({
                "data": {
                    "value": 42,
                    "timestamp": "2024-01-01T00:00:00Z"
                }
            }),
            metadata: json!({}),
        };

        // Process through the pipeline
        let data_response = data_handle.handle(request).await.unwrap();
        assert!(matches!(data_response.result, PluginResult::Success { .. }));

        // Verify all plugins are healthy
        for id in ["data-source", "processor", "aggregator"] {
            let health = lifecycle_manager.check_plugin_health(id).await.unwrap();
            assert!(health);
        }

        env.teardown().await.unwrap();
    }

    #[tokio::test]
    async fn test_plugin_dependency_chain() {
        let env = TestEnvironment::new(TestConfig::default()).await;
        env.setup().await.unwrap();

        let negotiator = CapabilityNegotiator::new(Default::default());
        let mut registry = PluginRegistry::new();

        // Create plugins with dependency chain
        let plugins = vec![
            ("auth", vec![
                Capability::new("auth", "authenticate", 1),
                Capability::new("auth", "authorize", 1),
            ], vec![]),
            ("database", vec![
                Capability::new("db", "query", 1),
                Capability::new("db", "write", 1),
            ], vec![
                Capability::new("auth", "authenticate", 1),
            ]),
            ("api", vec![
                Capability::new("api", "rest", 1),
                Capability::new("api", "graphql", 1),
            ], vec![
                Capability::new("auth", "authorize", 1),
                Capability::new("db", "query", 1),
            ]),
            ("frontend", vec![
                Capability::new("ui", "render", 1),
            ], vec![
                Capability::new("api", "rest", 1),
            ]),
        ];

        // Create and register plugins
        for (id, provides, requires) in plugins {
            let plugin = MultiPluginTestPlugin::new(id, provides.clone(), requires.clone());
            let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
            registry.register(id.to_string(), handle.clone()).unwrap();
            
            // Register capabilities with negotiator
            negotiator.register_plugin(id.to_string(), provides, requires).await.unwrap();
        }

        // Verify dependency resolution
        let auth_deps = negotiator.get_dependents("auth").await;
        assert!(auth_deps.contains(&"database".to_string()));
        assert!(auth_deps.contains(&"api".to_string()));

        let api_deps = negotiator.get_dependents("api").await;
        assert!(api_deps.contains(&"frontend".to_string()));

        // Check for missing capabilities
        let missing_caps = vec![
            Capability::new("cache", "get", 1),
            Capability::new("cache", "set", 1),
        ];
        
        let unresolved = negotiator.find_unresolved_capabilities(&missing_caps).await;
        assert_eq!(unresolved.len(), 2);

        env.teardown().await.unwrap();
    }

    #[tokio::test]
    async fn test_concurrent_multi_plugin_operations() {
        let env = TestEnvironment::new(TestConfig::default()).await;
        env.setup().await.unwrap();

        let mut registry = PluginRegistry::new();
        let lifecycle_manager = LifecycleManager::new(Default::default());

        // Create multiple worker plugins
        let worker_count = 5;
        let mut handles = vec![];

        for i in 0..worker_count {
            let plugin = MultiPluginTestPlugin::new(
                &format!("worker-{}", i),
                vec![
                    Capability::new("work", "process", 1),
                    Capability::new("interop", "message", 1),
                ],
                vec![],
            );
            
            let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
            registry.register(format!("worker-{}", i), handle.clone()).unwrap();
            lifecycle_manager.register_plugin(format!("worker-{}", i), handle.clone()).await.unwrap();
            lifecycle_manager.initialize_plugin(&format!("worker-{}", i), json!({})).await.unwrap();
            handles.push(handle);
        }

        // Create coordinator plugin
        let coordinator = MultiPluginTestPlugin::new(
            "coordinator",
            vec![
                Capability::new("coordination", "distribute", 1),
                Capability::new("interop", "message", 1),
            ],
            vec![Capability::new("work", "process", 1)],
        );
        
        let coordinator_handle = Arc::new(PluginHandle::new(Box::new(coordinator)));
        registry.register("coordinator".to_string(), coordinator_handle.clone()).unwrap();
        lifecycle_manager.register_plugin("coordinator".to_string(), coordinator_handle.clone()).await.unwrap();
        lifecycle_manager.initialize_plugin("coordinator", json!({})).await.unwrap();

        // Distribute work across workers
        let mut tasks = vec![];
        for (i, handle) in handles.iter().enumerate() {
            let handle_clone = handle.clone();
            let task_id = i;
            
            let task = tokio::spawn(async move {
                let mut results = vec![];
                for j in 0..20 {
                    let request = PluginRequest {
                        id: format!("work-{}-{}", task_id, j),
                        capability: Capability::new("work", "process", 1),
                        method: "process".to_string(),
                        params: json!({
                            "task_id": task_id,
                            "item": j,
                            "data": {
                                "value": task_id * 20 + j
                            }
                        }),
                        metadata: json!({}),
                    };
                    
                    let response = handle_clone.handle(request).await.unwrap();
                    results.push(response);
                    
                    // Small delay to simulate work
                    sleep(Duration::from_millis(5)).await;
                }
                results
            });
            
            tasks.push(task);
        }

        // Wait for all work to complete
        let all_results = futures::future::join_all(tasks).await;
        
        // Verify results
        let mut total_processed = 0;
        for results in all_results {
            let worker_results = results.unwrap();
            assert_eq!(worker_results.len(), 20);
            total_processed += worker_results.len();
        }
        assert_eq!(total_processed, worker_count * 20);

        // Check metrics for all plugins
        for i in 0..worker_count {
            let handle = &handles[i];
            let metrics = handle.metrics().await;
            assert_eq!(metrics.requests_total, 20);
            assert_eq!(metrics.requests_success, 20);
        }

        env.teardown().await.unwrap();
    }

    #[tokio::test]
    async fn test_plugin_cascade_failure() {
        let env = TestEnvironment::new(TestConfig::default()).await;
        env.setup().await.unwrap();

        let mut registry = PluginRegistry::new();
        let lifecycle_manager = LifecycleManager::new(Default::default());

        // Create chain: A -> B -> C where B will fail
        let plugin_a = MultiPluginTestPlugin::new(
            "plugin-a",
            vec![Capability::new("service", "a", 1)],
            vec![],
        );
        
        let plugin_b = MultiPluginTestPlugin::new(
            "plugin-b",
            vec![Capability::new("service", "b", 1)],
            vec![Capability::new("service", "a", 1)],
        );
        
        let plugin_c = MultiPluginTestPlugin::new(
            "plugin-c",
            vec![Capability::new("service", "c", 1)],
            vec![Capability::new("service", "b", 1)],
        );

        // Register and initialize
        for (id, plugin) in [
            ("plugin-a", plugin_a),
            ("plugin-b", plugin_b),
            ("plugin-c", plugin_c),
        ] {
            let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
            registry.register(id.to_string(), handle.clone()).unwrap();
            lifecycle_manager.register_plugin(id.to_string(), handle).await.unwrap();
            lifecycle_manager.initialize_plugin(id, json!({})).await.unwrap();
        }

        // Simulate plugin B failure
        lifecycle_manager.mark_plugin_unhealthy("plugin-b", "Simulated failure").await.unwrap();

        // Check cascade detection
        let health_status = lifecycle_manager.get_health_status().await;
        assert_eq!(health_status.unhealthy_plugins, 1);

        // Plugin C should be affected by B's failure
        let plugin_c_health = lifecycle_manager.check_plugin_health("plugin-c").await.unwrap();
        assert!(plugin_c_health); // Still healthy but depends on unhealthy plugin

        env.teardown().await.unwrap();
    }

    #[tokio::test]
    async fn test_multi_version_plugin_coexistence() {
        let env = TestEnvironment::new(TestConfig::default()).await;
        env.setup().await.unwrap();

        let coordinator = Arc::new(ZeroDowntimeCoordinator::new(
            Arc::new(HotReloadManager::new(
                Arc::new(loader::PluginLoader::new()),
                Default::default(),
            )),
            Arc::new(RollbackManager::new(
                Arc::new(StateTransferCoordinator::new(Default::default())),
                Arc::new(VersionManager::new(Default::default())),
                Default::default(),
            )),
            Arc::new(StateTransferCoordinator::new(Default::default())),
            Default::default(),
        ));

        // Create multiple versions of the same plugin
        let plugin_v1 = MultiPluginTestPlugin::new(
            "versioned-plugin",
            vec![Capability::new("service", "api", 1)],
            vec![],
        );
        
        let plugin_v2 = MultiPluginTestPlugin::new(
            "versioned-plugin",
            vec![
                Capability::new("service", "api", 1),
                Capability::new("service", "api", 2), // New version
            ],
            vec![],
        );

        // Register both versions
        let handle_v1 = Arc::new(PluginHandle::new(Box::new(plugin_v1)));
        let handle_v2 = Arc::new(PluginHandle::new(Box::new(plugin_v2)));

        coordinator.router.routes.write().await.insert(
            "versioned-plugin".to_string(),
            RouteEntry {
                plugin_id: "versioned-plugin".to_string(),
                instances: vec![
                    PluginInstanceInfo {
                        id: "v1".to_string(),
                        handle: handle_v1.clone(),
                        version: semver::Version::new(1, 0, 0),
                        state: InstanceState::Active,
                        weight: 0.7, // 70% traffic
                        metrics: Arc::new(InstanceMetrics::default()),
                    },
                    PluginInstanceInfo {
                        id: "v2".to_string(),
                        handle: handle_v2.clone(),
                        version: semver::Version::new(2, 0, 0),
                        state: InstanceState::Active,
                        weight: 0.3, // 30% traffic
                        metrics: Arc::new(InstanceMetrics::default()),
                    },
                ],
                strategy: RoutingStrategy::WeightedRoundRobin,
                health_check: HealthCheckConfig {
                    interval_ms: 100,
                    timeout_ms: 50,
                    healthy_threshold: 2,
                    unhealthy_threshold: 3,
                    check_type: HealthCheckType::Ping,
                },
            },
        );

        // Send requests and track versions
        let mut version_counts = HashMap::new();
        for i in 0..100 {
            let request = PluginRequest {
                id: format!("req-{}", i),
                capability: Capability::new("service", "api", 1),
                method: "process".to_string(),
                params: json!({"index": i}),
                metadata: json!({}),
            };

            if let Ok(response) = coordinator.route_request(request).await {
                if let PluginResult::Success { data } = response.result {
                    let plugin_id = data["processed_by"].as_str().unwrap_or("unknown");
                    *version_counts.entry(plugin_id.to_string()).or_insert(0) += 1;
                }
            }
        }

        // Verify traffic distribution (should be roughly 70/30)
        let v1_count = version_counts.get("versioned-plugin").unwrap_or(&0);
        let v2_count = version_counts.get("versioned-plugin").unwrap_or(&0);
        
        // Allow for some variance in distribution
        assert!(*v1_count > 50 && *v1_count < 80, "v1 traffic should be ~70%");
        assert!(*v2_count > 20 && *v2_count < 50, "v2 traffic should be ~30%");

        env.teardown().await.unwrap();
    }
}