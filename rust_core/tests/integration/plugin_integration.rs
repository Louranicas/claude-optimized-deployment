//! Plugin System Integration Tests
//!
//! End-to-end tests for the complete plugin system.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

use super::*;
use claude_optimized_deployment_rust::mcp_manager::plugin::{
    *,
    registry::*,
    loader::*,
    lifecycle::*,
    discovery::*,
    capabilities::*,
    schema::*,
};
use std::path::PathBuf;
use serde_json::json;

/// Integration test plugin
#[derive(Debug)]
struct IntegrationTestPlugin {
    metadata: PluginMetadata,
    request_log: Arc<RwLock<Vec<String>>>,
    config: Arc<RwLock<serde_json::Value>>,
}

impl IntegrationTestPlugin {
    fn new(id: &str, capabilities: Vec<Capability>) -> Self {
        Self {
            metadata: PluginMetadata {
                id: id.to_string(),
                name: format!("Integration Test Plugin {}", id),
                version: "1.0.0".to_string(),
                author: "Integration Test".to_string(),
                description: "Plugin for integration testing".to_string(),
                license: "MIT".to_string(),
                homepage: None,
                repository: None,
                min_mcp_version: "1.0.0".to_string(),
                dependencies: vec![],
                provides: capabilities,
                requires: vec![],
            },
            request_log: Arc::new(RwLock::new(Vec::new())),
            config: Arc::new(RwLock::new(json!({}))),
        }
    }
}

#[async_trait::async_trait]
impl Plugin for IntegrationTestPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    async fn initialize(&mut self, config: serde_json::Value) -> Result<()> {
        *self.config.write().await = config;
        Ok(())
    }

    async fn handle(&self, request: PluginRequest) -> Result<PluginResponse> {
        self.request_log.write().await.push(request.id.clone());
        
        Ok(PluginResponse {
            request_id: request.id,
            result: PluginResult::Success {
                data: json!({
                    "plugin_id": self.metadata.id,
                    "capability": request.capability.to_string(),
                    "method": request.method,
                    "params": request.params,
                }),
            },
            metadata: json!({}),
        })
    }

    async fn shutdown(&mut self) -> Result<()> {
        self.request_log.write().await.clear();
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_full_plugin_lifecycle() {
        let env = TestEnvironment::new(TestConfig::default()).await;
        env.setup().await.unwrap();

        // Create registry and lifecycle manager
        let mut registry = PluginRegistry::new();
        let lifecycle_manager = LifecycleManager::new(Default::default());

        // Create test plugin
        let plugin = IntegrationTestPlugin::new(
            "lifecycle-test",
            vec![
                Capability::new("test", "operation", 1),
                Capability::new("test", "query", 1),
            ],
        );
        
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));

        // Register plugin
        registry.register("lifecycle-test".to_string(), handle.clone()).unwrap();
        lifecycle_manager.register_plugin("lifecycle-test".to_string(), handle.clone()).await.unwrap();

        // Initialize plugin
        let config = json!({
            "setting1": "value1",
            "setting2": 42
        });
        lifecycle_manager.initialize_plugin("lifecycle-test", config).await.unwrap();

        // Verify state
        let state = lifecycle_manager.get_plugin_state("lifecycle-test").await.unwrap();
        assert_eq!(state, PluginState::Ready);

        // Send requests
        for i in 0..5 {
            let request = PluginRequest {
                id: format!("req-{}", i),
                capability: Capability::new("test", "operation", 1),
                method: "test".to_string(),
                params: json!({"index": i}),
                metadata: json!({}),
            };

            let response = handle.handle(request).await.unwrap();
            assert!(matches!(response.result, PluginResult::Success { .. }));
        }

        // Check metrics
        let metrics = handle.metrics().await;
        assert_eq!(metrics.requests_total, 5);
        assert_eq!(metrics.requests_success, 5);

        // Shutdown
        lifecycle_manager.shutdown_plugin("lifecycle-test").await.unwrap();
        let state = lifecycle_manager.get_plugin_state("lifecycle-test").await.unwrap();
        assert_eq!(state, PluginState::Shutdown);

        env.teardown().await.unwrap();
    }

    #[tokio::test]
    async fn test_plugin_discovery_and_loading() {
        let env = TestEnvironment::new(TestConfig::default()).await;
        env.setup().await.unwrap();

        // Create plugin loader
        let mut loader = PluginLoader::new();
        loader.add_search_path(env.temp_dir.path().to_path_buf());

        // Create mock plugin files
        for i in 0..3 {
            let plugin_path = env.temp_dir.path().join(format!("plugin_{}.so", i));
            std::fs::write(&plugin_path, b"mock plugin content").unwrap();
        }

        // Discover plugins
        let discovered = loader.discover_plugins().await;
        assert_eq!(discovered.len(), 3);

        env.teardown().await.unwrap();
    }

    #[tokio::test]
    async fn test_plugin_capability_matching() {
        let env = TestEnvironment::new(TestConfig::default()).await;
        env.setup().await.unwrap();

        let mut registry = PluginRegistry::new();

        // Register plugins with different capabilities
        let docker_caps = vec![
            Capability::new("docker", "container.create", 1),
            Capability::new("docker", "container.list", 1),
            Capability::new("docker", "image.pull", 1),
        ];
        
        let k8s_caps = vec![
            Capability::new("k8s", "pod.create", 1),
            Capability::new("k8s", "pod.list", 1),
            Capability::new("k8s", "service.create", 1),
        ];

        let docker_plugin = IntegrationTestPlugin::new("docker-plugin", docker_caps);
        let k8s_plugin = IntegrationTestPlugin::new("k8s-plugin", k8s_caps);

        registry.register("docker-plugin".to_string(), Arc::new(PluginHandle::new(Box::new(docker_plugin)))).unwrap();
        registry.register("k8s-plugin".to_string(), Arc::new(PluginHandle::new(Box::new(k8s_plugin)))).unwrap();

        // Test capability queries
        let docker_plugins = registry.find_by_capability(&Capability::new("docker", "container.create", 1));
        assert_eq!(docker_plugins.len(), 1);
        assert_eq!(docker_plugins[0], "docker-plugin");

        let all_docker = registry.find_by_namespace("docker");
        assert_eq!(all_docker.len(), 1);

        let all_k8s = registry.find_by_namespace("k8s");
        assert_eq!(all_k8s.len(), 1);

        env.teardown().await.unwrap();
    }

    #[tokio::test]
    async fn test_plugin_configuration_validation() {
        let env = TestEnvironment::new(TestConfig::default()).await;
        env.setup().await.unwrap();

        // Create schema registry
        let mut schema_registry = SchemaRegistry::new();

        // Define plugin configuration schema
        let schema = SchemaBuilder::new("plugin-config")
            .title("Plugin Configuration")
            .description("Configuration schema for test plugin")
            .property(
                "server",
                json!({
                    "type": "object",
                    "properties": {
                        "host": {
                            "type": "string",
                            "format": "hostname"
                        },
                        "port": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 65535
                        }
                    },
                    "required": ["host", "port"]
                }),
                Some("Server configuration".to_string()),
            )
            .property(
                "logging",
                json!({
                    "type": "object",
                    "properties": {
                        "level": {
                            "type": "string",
                            "enum": ["debug", "info", "warn", "error"]
                        },
                        "file": {
                            "type": "string"
                        }
                    }
                }),
                Some("Logging configuration".to_string()),
            )
            .required(vec!["server"])
            .build();

        schema_registry.register(schema).unwrap();

        // Test valid configuration
        let valid_config = json!({
            "server": {
                "host": "localhost",
                "port": 8080
            },
            "logging": {
                "level": "info",
                "file": "/var/log/plugin.log"
            }
        });

        let validation = schema_registry.validate("plugin-config", &valid_config).unwrap();
        assert!(validation.is_valid);

        // Test invalid configuration
        let invalid_config = json!({
            "server": {
                "host": "localhost",
                "port": 99999  // Invalid port
            }
        });

        let validation = schema_registry.validate("plugin-config", &invalid_config).unwrap();
        assert!(!validation.is_valid);
        assert!(!validation.errors.is_empty());

        env.teardown().await.unwrap();
    }

    #[tokio::test]
    async fn test_plugin_dependency_resolution() {
        let env = TestEnvironment::new(TestConfig::default()).await;
        env.setup().await.unwrap();

        let mut registry = PluginRegistry::new();

        // Create plugins with dependencies
        let mut plugin_a = IntegrationTestPlugin::new("plugin-a", vec![]);
        plugin_a.metadata.dependencies = vec![
            PluginDependency {
                id: "plugin-b".to_string(),
                version: "^1.0.0".to_string(),
                optional: false,
            },
        ];

        let plugin_b = IntegrationTestPlugin::new("plugin-b", vec![]);
        let plugin_c = IntegrationTestPlugin::new("plugin-c", vec![]);

        // Register plugins
        registry.register("plugin-a".to_string(), Arc::new(PluginHandle::new(Box::new(plugin_a)))).unwrap();
        registry.register("plugin-b".to_string(), Arc::new(PluginHandle::new(Box::new(plugin_b)))).unwrap();
        registry.register("plugin-c".to_string(), Arc::new(PluginHandle::new(Box::new(plugin_c)))).unwrap();

        // Verify plugin A has dependency on B
        let plugin_a_handle = registry.get("plugin-a").unwrap();
        let metadata = plugin_a_handle.metadata().await;
        assert_eq!(metadata.dependencies.len(), 1);
        assert_eq!(metadata.dependencies[0].id, "plugin-b");

        env.teardown().await.unwrap();
    }

    #[tokio::test]
    async fn test_concurrent_plugin_requests() {
        let env = TestEnvironment::new(TestConfig::default()).await;
        env.setup().await.unwrap();

        // Create plugin
        let plugin = IntegrationTestPlugin::new(
            "concurrent-test",
            vec![Capability::new("test", "concurrent", 1)],
        );
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));

        // Initialize
        handle.initialize(json!({})).await.unwrap();

        // Send concurrent requests
        let mut tasks = vec![];
        for i in 0..100 {
            let handle_clone = handle.clone();
            let task = tokio::spawn(async move {
                let request = PluginRequest {
                    id: format!("concurrent-{}", i),
                    capability: Capability::new("test", "concurrent", 1),
                    method: "test".to_string(),
                    params: json!({"index": i}),
                    metadata: json!({}),
                };

                handle_clone.handle(request).await
            });
            tasks.push(task);
        }

        // Wait for all requests
        let results: Vec<_> = futures::future::join_all(tasks).await;
        
        // All should succeed
        let mut success_count = 0;
        for result in results {
            if let Ok(Ok(_)) = result {
                success_count += 1;
            }
        }
        assert_eq!(success_count, 100);

        // Check metrics
        let metrics = handle.metrics().await;
        assert_eq!(metrics.requests_total, 100);
        assert_eq!(metrics.requests_success, 100);

        env.teardown().await.unwrap();
    }

    #[tokio::test]
    async fn test_plugin_health_monitoring() {
        let env = TestEnvironment::new(TestConfig::default()).await;
        env.setup().await.unwrap();

        let lifecycle_manager = LifecycleManager::new(Default::default());

        // Register multiple plugins
        for i in 0..5 {
            let plugin = IntegrationTestPlugin::new(
                &format!("health-test-{}", i),
                vec![Capability::new("test", "health", 1)],
            );
            let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
            
            lifecycle_manager.register_plugin(
                format!("health-test-{}", i),
                handle,
            ).await.unwrap();
            
            lifecycle_manager.initialize_plugin(
                &format!("health-test-{}", i),
                json!({}),
            ).await.unwrap();
        }

        // Check overall health
        let health_status = lifecycle_manager.get_health_status().await;
        assert_eq!(health_status.total_plugins, 5);
        assert_eq!(health_status.healthy_plugins, 5);
        assert_eq!(health_status.unhealthy_plugins, 0);

        // Check individual plugin health
        for i in 0..5 {
            let health = lifecycle_manager.check_plugin_health(
                &format!("health-test-{}", i)
            ).await.unwrap();
            assert!(health);
        }

        env.teardown().await.unwrap();
    }
}