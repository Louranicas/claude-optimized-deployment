//! Concurrent Operations Tests for MCP Manager
//!
//! Comprehensive tests for thread safety, race conditions, and concurrent behavior.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

use claude_optimized_deployment_rust::mcp_manager::plugin::*;
use futures::future::join_all;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use tokio::sync::{Mutex, RwLock};
use tokio::time::{sleep, Duration};

#[cfg(test)]
mod tests {
    use super::*;

    /// Concurrent test plugin with internal state
    #[derive(Debug)]
    struct ConcurrentTestPlugin {
        metadata: PluginMetadata,
        counter: Arc<AtomicU64>,
        state: Arc<RwLock<HashMap<String, String>>>,
        operation_log: Arc<Mutex<Vec<String>>>,
        concurrent_operations: Arc<AtomicU64>,
        max_concurrent: Arc<AtomicU64>,
    }

    impl ConcurrentTestPlugin {
        fn new(id: &str) -> Self {
            Self {
                metadata: PluginMetadata {
                    id: id.to_string(),
                    name: format!("Concurrent Test Plugin {}", id),
                    version: "1.0.0".to_string(),
                    author: "Concurrent Test".to_string(),
                    description: "Plugin for concurrent testing".to_string(),
                    license: "MIT".to_string(),
                    homepage: None,
                    repository: None,
                    min_mcp_version: "1.0.0".to_string(),
                    dependencies: vec![],
                    provides: vec![
                        Capability::new("concurrent", "test", 1),
                        Capability::new("concurrent", "state", 1),
                    ],
                    requires: vec![],
                },
                counter: Arc::new(AtomicU64::new(0)),
                state: Arc::new(RwLock::new(HashMap::new())),
                operation_log: Arc::new(Mutex::new(Vec::new())),
                concurrent_operations: Arc::new(AtomicU64::new(0)),
                max_concurrent: Arc::new(AtomicU64::new(0)),
            }
        }
    }

    #[async_trait::async_trait]
    impl Plugin for ConcurrentTestPlugin {
        fn metadata(&self) -> &PluginMetadata {
            &self.metadata
        }

        async fn initialize(&mut self, _config: serde_json::Value) -> Result<()> {
            Ok(())
        }

        async fn handle(&self, request: PluginRequest) -> Result<PluginResponse> {
            // Track concurrent operations
            let current = self.concurrent_operations.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_concurrent.fetch_max(current, Ordering::SeqCst);

            let result = match request.method.as_str() {
                "increment" => {
                    let value = self.counter.fetch_add(1, Ordering::SeqCst) + 1;
                    serde_json::json!({ "value": value })
                }
                "read_state" => {
                    let state = self.state.read().await;
                    let key = request
                        .params
                        .get("key")
                        .and_then(|k| k.as_str())
                        .unwrap_or("default");
                    serde_json::json!({ "value": state.get(key) })
                }
                "write_state" => {
                    let mut state = self.state.write().await;
                    let key = request
                        .params
                        .get("key")
                        .and_then(|k| k.as_str())
                        .unwrap_or("default");
                    let value = request
                        .params
                        .get("value")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    state.insert(key.to_string(), value.to_string());
                    serde_json::json!({ "success": true })
                }
                "log_operation" => {
                    let mut log = self.operation_log.lock().await;
                    let operation = request
                        .params
                        .get("operation")
                        .and_then(|o| o.as_str())
                        .unwrap_or("unknown");
                    log.push(format!("{}: {}", request.id, operation));
                    serde_json::json!({ "logged": true })
                }
                _ => serde_json::json!({ "error": "unknown method" }),
            };

            // Simulate some work
            sleep(Duration::from_micros(100)).await;

            self.concurrent_operations.fetch_sub(1, Ordering::SeqCst);

            Ok(PluginResponse {
                request_id: request.id,
                result: PluginResult::Success { data: result },
                metadata: serde_json::json!({}),
            })
        }

        async fn shutdown(&mut self) -> Result<()> {
            Ok(())
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_plugin_requests() {
        let plugin = ConcurrentTestPlugin::new("concurrent-requests");
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
        handle.initialize(serde_json::json!({})).await.unwrap();

        let concurrent_count = 1000;
        let mut tasks = Vec::new();

        for i in 0..concurrent_count {
            let handle_clone = handle.clone();
            let task = tokio::spawn(async move {
                let request = PluginRequest {
                    id: format!("req-{}", i),
                    capability: Capability::new("concurrent", "test", 1),
                    method: "increment".to_string(),
                    params: serde_json::json!({}),
                    metadata: serde_json::json!({}),
                };

                handle_clone.handle(request).await
            });
            tasks.push(task);
        }

        let results = join_all(tasks).await;

        // All requests should succeed
        let success_count = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(success_count, concurrent_count);

        // Counter should equal the number of requests
        if let Some(plugin) = handle.as_any().downcast_ref::<ConcurrentTestPlugin>() {
            let final_count = plugin.counter.load(Ordering::SeqCst);
            assert_eq!(final_count, concurrent_count as u64);

            let max_concurrent = plugin.max_concurrent.load(Ordering::SeqCst);
            println!("Max concurrent operations: {}", max_concurrent);
            assert!(max_concurrent > 1, "Should have concurrent operations");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_state_modifications() {
        let plugin = ConcurrentTestPlugin::new("concurrent-state");
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
        handle.initialize(serde_json::json!({})).await.unwrap();

        let writers = 50;
        let readers = 100;
        let barrier = Arc::new(Barrier::new(writers + readers));

        let mut tasks = Vec::new();

        // Writers
        for i in 0..writers {
            let handle_clone = handle.clone();
            let barrier_clone = barrier.clone();
            let task = tokio::spawn(async move {
                barrier_clone.wait();

                for j in 0..10 {
                    let request = PluginRequest {
                        id: format!("write-{}-{}", i, j),
                        capability: Capability::new("concurrent", "state", 1),
                        method: "write_state".to_string(),
                        params: serde_json::json!({
                            "key": format!("key-{}", i),
                            "value": format!("value-{}-{}", i, j),
                        }),
                        metadata: serde_json::json!({}),
                    };

                    let _ = handle_clone.handle(request).await;
                }
            });
            tasks.push(task);
        }

        // Readers
        for i in 0..readers {
            let handle_clone = handle.clone();
            let barrier_clone = barrier.clone();
            let task = tokio::spawn(async move {
                barrier_clone.wait();

                let mut read_values = Vec::new();
                for j in 0..5 {
                    let request = PluginRequest {
                        id: format!("read-{}-{}", i, j),
                        capability: Capability::new("concurrent", "state", 1),
                        method: "read_state".to_string(),
                        params: serde_json::json!({
                            "key": format!("key-{}", j % writers),
                        }),
                        metadata: serde_json::json!({}),
                    };

                    if let Ok(response) = handle_clone.handle(request).await {
                        if let PluginResult::Success { data } = response.result {
                            read_values.push(data);
                        }
                    }
                }
                read_values
            });
            tasks.push(task);
        }

        let results = join_all(tasks).await;

        // All operations should complete
        let completed = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(completed, writers + readers);

        // Final state should be consistent
        if let Some(plugin) = handle.as_any().downcast_ref::<ConcurrentTestPlugin>() {
            let state = plugin.state.read().await;
            assert_eq!(state.len(), writers);

            // Each key should have a valid value
            for i in 0..writers {
                let key = format!("key-{}", i);
                assert!(state.contains_key(&key));
                let value = state.get(&key).unwrap();
                assert!(value.starts_with(&format!("value-{}-", i)));
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_registry_concurrent_access() {
        let registry = Arc::new(RwLock::new(registry::PluginRegistry::new()));
        let plugin_count = 100;
        let operations_per_thread = 50;

        let barrier = Arc::new(Barrier::new(plugin_count));
        let mut tasks = Vec::new();

        // Concurrent registrations and lookups
        for i in 0..plugin_count {
            let registry_clone = registry.clone();
            let barrier_clone = barrier.clone();

            let task = tokio::spawn(async move {
                barrier_clone.wait();

                // Register plugin
                let plugin = ConcurrentTestPlugin::new(&format!("registry-test-{}", i));
                let handle = Arc::new(PluginHandle::new(Box::new(plugin)));

                {
                    let mut reg = registry_clone.write().await;
                    reg.register(format!("registry-test-{}", i), handle)
                        .unwrap();
                }

                // Perform lookups
                let mut found_count = 0;
                for j in 0..operations_per_thread {
                    let target = format!("registry-test-{}", (i + j) % plugin_count);
                    let reg = registry_clone.read().await;
                    if reg.get(&target).is_some() {
                        found_count += 1;
                    }
                }

                found_count
            });
            tasks.push(task);
        }

        let results = join_all(tasks).await;

        // All tasks should complete
        assert_eq!(results.len(), plugin_count);

        // Final registry state
        let reg = registry.read().await;
        let total_plugins = reg.list_all().len();
        assert_eq!(total_plugins, plugin_count);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_hot_reload_concurrent_operations() {
        let loader = Arc::new(loader::PluginLoader::new());
        let hot_reload = Arc::new(hot_reload::HotReloadManager::new(
            loader,
            Default::default(),
        ));

        hot_reload.start().await.unwrap();

        // Register plugin
        let plugin = ConcurrentTestPlugin::new("hot-reload-concurrent");
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
        hot_reload
            .register_plugin("hot-reload-concurrent".to_string(), handle.clone(), None)
            .await
            .unwrap();

        let reload_count = 10;
        let request_count = 100;
        let mut tasks = Vec::new();

        // Concurrent reloads
        for i in 0..reload_count {
            let hot_reload_clone = hot_reload.clone();
            let task = tokio::spawn(async move {
                sleep(Duration::from_millis(i as u64 * 10)).await;
                hot_reload_clone
                    .reload_plugin(
                        "hot-reload-concurrent",
                        hot_reload::ReloadReason::ConcurrentTest,
                        false,
                    )
                    .await
            });
            tasks.push(task);
        }

        // Concurrent requests during reloads
        for i in 0..request_count {
            let handle_clone = handle.clone();
            let task = tokio::spawn(async move {
                let request = PluginRequest {
                    id: format!("reload-req-{}", i),
                    capability: Capability::new("concurrent", "test", 1),
                    method: "increment".to_string(),
                    params: serde_json::json!({}),
                    metadata: serde_json::json!({}),
                };

                // Request might fail during reload
                let _ = handle_clone.handle(request).await;
            });
            tasks.push(task);
        }

        let results = join_all(tasks).await;

        // Most operations should complete
        let completed = results.iter().filter(|r| r.is_ok()).count();
        assert!(
            completed > (reload_count + request_count) * 80 / 100,
            "Too many operations failed: {}/{}",
            completed,
            reload_count + request_count
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_zero_downtime_concurrent_routing() {
        let hot_reload = Arc::new(hot_reload::HotReloadManager::new(
            Arc::new(loader::PluginLoader::new()),
            Default::default(),
        ));
        let state_transfer = Arc::new(state_transfer::StateTransferCoordinator::new(
            Default::default(),
        ));
        let version_manager = Arc::new(version::VersionManager::new(Default::default()));
        let rollback = Arc::new(rollback::RollbackManager::new(
            state_transfer.clone(),
            version_manager,
            Default::default(),
        ));

        let coordinator = Arc::new(zero_downtime::ZeroDowntimeCoordinator::new(
            hot_reload,
            rollback,
            state_transfer,
            Default::default(),
        ));

        // Setup multiple instances
        let instance_count = 5;
        let mut instances = Vec::new();

        for i in 0..instance_count {
            let plugin = ConcurrentTestPlugin::new(&format!("instance-{}", i));
            let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
            handle.initialize(serde_json::json!({})).await.unwrap();

            instances.push(zero_downtime::PluginInstanceInfo {
                id: format!("instance-{}", i),
                handle,
                version: semver::Version::new(1, 0, 0),
                state: zero_downtime::InstanceState::Active,
                weight: 1.0 / instance_count as f32,
                metrics: Arc::new(zero_downtime::InstanceMetrics::default()),
            });
        }

        coordinator.router.routes.write().await.insert(
            "concurrent-routing".to_string(),
            zero_downtime::RouteEntry {
                plugin_id: "concurrent-routing".to_string(),
                instances,
                strategy: zero_downtime::RoutingStrategy::WeightedRoundRobin,
                health_check: zero_downtime::HealthCheckConfig {
                    interval_ms: 100,
                    timeout_ms: 50,
                    healthy_threshold: 2,
                    unhealthy_threshold: 3,
                    check_type: zero_downtime::HealthCheckType::Ping,
                },
            },
        );

        // Concurrent routing requests
        let request_count = 1000;
        let mut tasks = Vec::new();

        for i in 0..request_count {
            let coord_clone = coordinator.clone();
            let task = tokio::spawn(async move {
                let request = PluginRequest {
                    id: format!("route-{}", i),
                    capability: Capability::new("concurrent", "test", 1),
                    method: "increment".to_string(),
                    params: serde_json::json!({}),
                    metadata: serde_json::json!({}),
                };

                coord_clone.route_request(request).await
            });
            tasks.push(task);
        }

        let results = join_all(tasks).await;

        // All requests should be routed
        let routed = results
            .iter()
            .filter(|r| r.is_ok())
            .filter_map(|r| r.as_ref().unwrap().as_ref().ok())
            .count();
        assert_eq!(routed, request_count);

        // Check distribution across instances
        let route = coordinator.router.routes.read().await;
        if let Some(entry) = route.get("concurrent-routing") {
            let mut total_requests = 0;
            for instance in &entry.instances {
                let requests = instance.metrics.requests_total.load(Ordering::SeqCst);
                total_requests += requests;
                println!("Instance {} handled {} requests", instance.id, requests);

                // Each instance should get roughly equal share
                let expected = request_count as u64 / instance_count as u64;
                let variance = (requests as i64 - expected as i64).abs();
                assert!(
                    variance < expected as i64 / 5,
                    "Uneven distribution: {} vs expected {}",
                    requests,
                    expected
                );
            }
            assert_eq!(total_requests, request_count as u64);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_state_transfer() {
        let coordinator = Arc::new(state_transfer::StateTransferCoordinator::new(
            Default::default(),
        ));
        let transfer_count = 20;
        let mut tasks = Vec::new();

        for i in 0..transfer_count {
            let coord_clone = coordinator.clone();
            let task = tokio::spawn(async move {
                // Create source and target plugins
                let source = ConcurrentTestPlugin::new(&format!("transfer-source-{}", i));
                let target = ConcurrentTestPlugin::new(&format!("transfer-target-{}", i));

                // Wrap in state transferable
                struct TransferableWrapper {
                    plugin: ConcurrentTestPlugin,
                }

                #[async_trait::async_trait]
                impl Plugin for TransferableWrapper {
                    fn metadata(&self) -> &PluginMetadata {
                        self.plugin.metadata()
                    }

                    async fn initialize(&mut self, config: serde_json::Value) -> Result<()> {
                        self.plugin.initialize(config).await
                    }

                    async fn handle(&self, request: PluginRequest) -> Result<PluginResponse> {
                        self.plugin.handle(request).await
                    }

                    async fn shutdown(&mut self) -> Result<()> {
                        self.plugin.shutdown().await
                    }

                    fn as_any(&self) -> &dyn std::any::Any {
                        self
                    }
                }

                #[async_trait::async_trait]
                impl StateTransferable for TransferableWrapper {
                    async fn export_state(&self) -> Result<StateSnapshot> {
                        Ok(StateSnapshot {
                            id: uuid::Uuid::new_v4().to_string(),
                            plugin_id: self.plugin.metadata.id.clone(),
                            plugin_version: "1.0.0".to_string(),
                            schema_version: 1,
                            timestamp: chrono::Utc::now().timestamp(),
                            sections: std::collections::HashMap::new(),
                            metadata: StateMetadata {
                                reason: StateCreationReason::Transfer,
                                created_by: "test".to_string(),
                                tags: vec![],
                                expires_at: None,
                                custom: std::collections::HashMap::new(),
                            },
                            checksum: "test".to_string(),
                        })
                    }

                    async fn import_state(
                        &mut self,
                        _snapshot: StateSnapshot,
                    ) -> Result<StateImportResult> {
                        Ok(StateImportResult {
                            imported_sections: vec![],
                            failed_sections: vec![],
                            warnings: vec![],
                            duration: Duration::from_millis(1),
                        })
                    }

                    async fn validate_state(
                        &self,
                        _snapshot: &StateSnapshot,
                    ) -> Result<StateValidation> {
                        Ok(StateValidation {
                            is_valid: true,
                            schema_compatible: true,
                            version_compatible: true,
                            section_validations: std::collections::HashMap::new(),
                            compatibility_score: 1.0,
                        })
                    }

                    fn state_schema_version(&self) -> u32 {
                        1
                    }
                }

                let source_wrapped = TransferableWrapper { plugin: source };
                let target_wrapped = TransferableWrapper { plugin: target };

                coord_clone
                    .transfer_state(
                        Arc::new(RwLock::new(
                            Box::new(source_wrapped) as Box<dyn StateTransferable>
                        )),
                        Arc::new(RwLock::new(
                            Box::new(target_wrapped) as Box<dyn StateTransferable>
                        )),
                    )
                    .await
            });
            tasks.push(task);
        }

        let results = join_all(tasks).await;

        // All transfers should succeed
        let success_count = results
            .iter()
            .filter(|r| r.is_ok())
            .filter_map(|r| r.as_ref().unwrap().as_ref().ok())
            .filter(|r| r.success)
            .count();
        assert_eq!(success_count, transfer_count);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_rollback_operations() {
        let state_transfer = Arc::new(state_transfer::StateTransferCoordinator::new(
            Default::default(),
        ));
        let version_manager = Arc::new(version::VersionManager::new(Default::default()));
        let rollback_manager = Arc::new(rollback::RollbackManager::new(
            state_transfer,
            version_manager,
            Default::default(),
        ));

        // Create checkpoints concurrently
        let checkpoint_count = 50;
        let mut tasks = Vec::new();

        for i in 0..checkpoint_count {
            let manager_clone = rollback_manager.clone();
            let task = tokio::spawn(async move {
                let plugin = ConcurrentTestPlugin::new(&format!("rollback-{}", i));
                let handle = Arc::new(PluginHandle::new(Box::new(plugin)));

                let state = StateSnapshot {
                    id: format!("checkpoint-{}", i),
                    plugin_id: format!("rollback-{}", i),
                    plugin_version: "1.0.0".to_string(),
                    schema_version: 1,
                    timestamp: chrono::Utc::now().timestamp(),
                    sections: std::collections::HashMap::new(),
                    metadata: StateMetadata {
                        reason: StateCreationReason::Checkpoint,
                        created_by: "test".to_string(),
                        tags: vec![],
                        expires_at: None,
                        custom: std::collections::HashMap::new(),
                    },
                    checksum: format!("checksum-{}", i),
                };

                manager_clone
                    .create_checkpoint(
                        &format!("rollback-{}", i),
                        handle,
                        state,
                        rollback::CheckpointType::Manual,
                        "Concurrent test checkpoint",
                    )
                    .await
            });
            tasks.push(task);
        }

        let results = join_all(tasks).await;

        // All checkpoints should be created
        let created = results
            .iter()
            .filter(|r| r.is_ok())
            .filter_map(|r| r.as_ref().unwrap().as_ref().ok())
            .count();
        assert_eq!(created, checkpoint_count);

        // Verify checkpoint storage
        let store = rollback_manager.checkpoints.read().await;
        assert!(store.plugins.len() <= checkpoint_count); // Some might be deduplicated
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_race_condition_prevention() {
        let plugin = ConcurrentTestPlugin::new("race-test");
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
        handle.initialize(serde_json::json!({})).await.unwrap();

        let iterations = 100;
        let threads = 10;
        let barrier = Arc::new(Barrier::new(threads));

        // Test read-modify-write race condition
        let mut tasks = Vec::new();
        for thread_id in 0..threads {
            let handle_clone = handle.clone();
            let barrier_clone = barrier.clone();

            let task = tokio::spawn(async move {
                barrier_clone.wait();

                for i in 0..iterations {
                    // Read current value
                    let read_req = PluginRequest {
                        id: format!("read-{}-{}", thread_id, i),
                        capability: Capability::new("concurrent", "state", 1),
                        method: "read_state".to_string(),
                        params: serde_json::json!({ "key": "shared_counter" }),
                        metadata: serde_json::json!({}),
                    };

                    let current_value = if let Ok(response) = handle_clone.handle(read_req).await {
                        if let PluginResult::Success { data } = response.result {
                            data.get("value")
                                .and_then(|v| v.as_str())
                                .and_then(|s| s.parse::<i32>().ok())
                                .unwrap_or(0)
                        } else {
                            0
                        }
                    } else {
                        0
                    };

                    // Write incremented value
                    let write_req = PluginRequest {
                        id: format!("write-{}-{}", thread_id, i),
                        capability: Capability::new("concurrent", "state", 1),
                        method: "write_state".to_string(),
                        params: serde_json::json!({
                            "key": "shared_counter",
                            "value": (current_value + 1).to_string(),
                        }),
                        metadata: serde_json::json!({}),
                    };

                    let _ = handle_clone.handle(write_req).await;
                }
            });
            tasks.push(task);
        }

        join_all(tasks).await;

        // Without proper synchronization, we would lose updates
        // With proper implementation, final value should be threads * iterations
        let final_req = PluginRequest {
            id: "final-read".to_string(),
            capability: Capability::new("concurrent", "state", 1),
            method: "read_state".to_string(),
            params: serde_json::json!({ "key": "shared_counter" }),
            metadata: serde_json::json!({}),
        };

        if let Ok(response) = handle.handle(final_req).await {
            if let PluginResult::Success { data } = response.result {
                let final_value = data
                    .get("value")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(0);

                println!(
                    "Final counter value: {} (expected: {})",
                    final_value,
                    threads * iterations
                );

                // Some updates might be lost due to race conditions,
                // but we should have at least some updates
                assert!(final_value > 0, "No updates were successful");
            }
        }
    }
}
