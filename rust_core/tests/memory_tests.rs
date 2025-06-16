//! Memory Usage Tests for MCP Manager
//!
//! Comprehensive tests for memory allocation, leaks, and efficiency.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

use claude_optimized_deployment_rust::mcp_manager::plugin::*;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::time::sleep;

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Custom allocator to track memory usage
    struct TrackingAllocator;

    static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
    static DEALLOCATED: AtomicUsize = AtomicUsize::new(0);

    unsafe impl GlobalAlloc for TrackingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let ret = System.alloc(layout);
            if !ret.is_null() {
                ALLOCATED.fetch_add(layout.size(), Ordering::SeqCst);
            }
            ret
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            System.dealloc(ptr, layout);
            DEALLOCATED.fetch_add(layout.size(), Ordering::SeqCst);
        }
    }

    #[global_allocator]
    static GLOBAL: TrackingAllocator = TrackingAllocator;

    /// Get current memory usage
    fn current_memory_usage() -> usize {
        let allocated = ALLOCATED.load(Ordering::SeqCst);
        let deallocated = DEALLOCATED.load(Ordering::SeqCst);
        allocated.saturating_sub(deallocated)
    }

    /// Reset memory tracking
    fn reset_memory_tracking() {
        ALLOCATED.store(0, Ordering::SeqCst);
        DEALLOCATED.store(0, Ordering::SeqCst);
    }

    /// Memory test plugin
    #[derive(Debug)]
    struct MemoryTestPlugin {
        metadata: PluginMetadata,
        allocations: Vec<Vec<u8>>,
        weak_refs: Vec<Weak<Vec<u8>>>,
    }

    impl MemoryTestPlugin {
        fn new(id: &str) -> Self {
            Self {
                metadata: PluginMetadata {
                    id: id.to_string(),
                    name: format!("Memory Test Plugin {}", id),
                    version: "1.0.0".to_string(),
                    author: "Memory Test".to_string(),
                    description: "Plugin for memory testing".to_string(),
                    license: "MIT".to_string(),
                    homepage: None,
                    repository: None,
                    min_mcp_version: "1.0.0".to_string(),
                    dependencies: vec![],
                    provides: vec![
                        Capability::new("memory", "test", 1),
                        Capability::new("memory", "leak", 1),
                    ],
                    requires: vec![],
                },
                allocations: Vec::new(),
                weak_refs: Vec::new(),
            }
        }

        fn allocate_memory(&mut self, size: usize) {
            let allocation = vec![0u8; size];
            self.allocations.push(allocation);
        }

        fn create_weak_reference(&mut self) {
            let data = Arc::new(vec![0u8; 1024]);
            self.weak_refs.push(Arc::downgrade(&data));
        }

        fn clear_allocations(&mut self) {
            self.allocations.clear();
            self.weak_refs.retain(|weak| weak.strong_count() > 0);
        }
    }

    #[async_trait::async_trait]
    impl Plugin for MemoryTestPlugin {
        fn metadata(&self) -> &PluginMetadata {
            &self.metadata
        }

        async fn initialize(&mut self, _config: serde_json::Value) -> Result<()> {
            Ok(())
        }

        async fn handle(&self, request: PluginRequest) -> Result<PluginResponse> {
            Ok(PluginResponse {
                request_id: request.id,
                result: PluginResult::Success {
                    data: serde_json::json!({
                        "plugin_id": self.metadata.id,
                        "allocations": self.allocations.len(),
                        "weak_refs": self.weak_refs.len(),
                    }),
                },
                metadata: serde_json::json!({}),
            })
        }

        async fn shutdown(&mut self) -> Result<()> {
            self.clear_allocations();
            Ok(())
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[tokio::test]
    async fn test_plugin_memory_lifecycle() {
        reset_memory_tracking();
        let initial_memory = current_memory_usage();

        // Create and initialize plugin
        let plugin = MemoryTestPlugin::new("lifecycle-test");
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
        handle.initialize(serde_json::json!({})).await.unwrap();

        let after_init = current_memory_usage();
        println!("Memory after init: {} bytes", after_init - initial_memory);

        // Make some requests
        for i in 0..100 {
            let request = PluginRequest {
                id: format!("req-{}", i),
                capability: Capability::new("memory", "test", 1),
                method: "test".to_string(),
                params: serde_json::json!({}),
                metadata: serde_json::json!({}),
            };

            let _ = handle.handle(request).await.unwrap();
        }

        let after_requests = current_memory_usage();
        println!(
            "Memory after requests: {} bytes",
            after_requests - initial_memory
        );

        // Shutdown and drop
        handle.shutdown().await.unwrap();
        drop(handle);

        // Force garbage collection
        sleep(Duration::from_millis(100)).await;

        let final_memory = current_memory_usage();
        println!("Final memory: {} bytes", final_memory - initial_memory);

        // Memory should be mostly reclaimed
        assert!(
            final_memory - initial_memory < 10_000,
            "Memory leak detected: {} bytes leaked",
            final_memory - initial_memory
        );
    }

    #[tokio::test]
    async fn test_state_transfer_memory_efficiency() {
        reset_memory_tracking();
        let initial_memory = current_memory_usage();

        // Create plugins with large state
        let mut source = MemoryTestPlugin::new("source");
        source.allocate_memory(1024 * 1024); // 1MB

        let target = MemoryTestPlugin::new("target");

        // Create state transferable wrappers
        #[derive(Debug)]
        struct TransferableWrapper {
            plugin: MemoryTestPlugin,
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
                    plugin_version: self.plugin.metadata.version.clone(),
                    schema_version: 1,
                    timestamp: chrono::Utc::now().timestamp(),
                    sections: std::collections::HashMap::from([(
                        "memory_state".to_string(),
                        StateSection {
                            name: "memory_state".to_string(),
                            section_type: SectionType::Core,
                            priority: 1,
                            format: DataFormat::Binary,
                            data: SectionData::Inline {
                                data: vec![0u8; 1024 * 1024], // 1MB state
                                original_size: 1024 * 1024,
                                compression: CompressionType::None,
                            },
                            dependencies: vec![],
                        },
                    )]),
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
                    imported_sections: vec!["memory_state".to_string()],
                    failed_sections: vec![],
                    warnings: vec![],
                    duration: Duration::from_millis(10),
                })
            }

            async fn validate_state(&self, _snapshot: &StateSnapshot) -> Result<StateValidation> {
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

        let source_wrapper = TransferableWrapper { plugin: source };
        let target_wrapper = TransferableWrapper { plugin: target };

        let before_transfer = current_memory_usage();

        // Perform state transfer
        let coordinator = state_transfer::StateTransferCoordinator::new(Default::default());
        let result = coordinator
            .transfer_state(
                Arc::new(tokio::sync::RwLock::new(
                    Box::new(source_wrapper) as Box<dyn StateTransferable>
                )),
                Arc::new(tokio::sync::RwLock::new(
                    Box::new(target_wrapper) as Box<dyn StateTransferable>
                )),
            )
            .await
            .unwrap();

        assert!(result.success);

        let after_transfer = current_memory_usage();
        let transfer_overhead = after_transfer - before_transfer;

        println!(
            "State transfer memory overhead: {} bytes",
            transfer_overhead
        );

        // Memory overhead should be reasonable (less than 2x state size)
        assert!(
            transfer_overhead < 2 * 1024 * 1024,
            "Excessive memory usage during state transfer: {} bytes",
            transfer_overhead
        );
    }

    #[tokio::test]
    async fn test_hot_reload_memory_cleanup() {
        reset_memory_tracking();

        let loader = Arc::new(loader::PluginLoader::new());
        let mut hot_reload_manager =
            hot_reload::HotReloadManager::new(loader, hot_reload::HotReloadConfig::default());

        hot_reload_manager.start().await.unwrap();

        // Register initial plugin
        let plugin = MemoryTestPlugin::new("hot-reload-test");
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));

        hot_reload_manager
            .register_plugin("hot-reload-test".to_string(), handle.clone(), None)
            .await
            .unwrap();

        let before_reload = current_memory_usage();

        // Perform multiple reloads
        for i in 0..5 {
            println!("Reload iteration {}", i);

            hot_reload_manager
                .reload_plugin(
                    "hot-reload-test",
                    hot_reload::ReloadReason::MemoryTest,
                    false,
                )
                .await
                .unwrap();

            // Allow cleanup
            sleep(Duration::from_millis(100)).await;
        }

        let after_reloads = current_memory_usage();
        let memory_growth = after_reloads.saturating_sub(before_reload);

        println!("Memory growth after 5 reloads: {} bytes", memory_growth);

        // Memory growth should be minimal
        assert!(
            memory_growth < 100_000,
            "Excessive memory growth during hot reloads: {} bytes",
            memory_growth
        );
    }

    #[tokio::test]
    async fn test_concurrent_plugin_memory_usage() {
        reset_memory_tracking();
        let initial_memory = current_memory_usage();

        let plugin_count = 50;
        let mut handles = Vec::new();

        // Create many plugins concurrently
        let mut tasks = Vec::new();
        for i in 0..plugin_count {
            let task = tokio::spawn(async move {
                let plugin = MemoryTestPlugin::new(&format!("concurrent-{}", i));
                let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
                handle.initialize(serde_json::json!({})).await.unwrap();
                handle
            });
            tasks.push(task);
        }

        for task in tasks {
            handles.push(task.await.unwrap());
        }

        let after_creation = current_memory_usage();
        let per_plugin_memory = (after_creation - initial_memory) / plugin_count;

        println!("Memory per plugin: {} bytes", per_plugin_memory);

        // Each plugin should use reasonable memory
        assert!(
            per_plugin_memory < 50_000,
            "Excessive per-plugin memory usage: {} bytes",
            per_plugin_memory
        );

        // Cleanup
        for handle in handles {
            handle.shutdown().await.unwrap();
        }

        sleep(Duration::from_millis(200)).await;

        let final_memory = current_memory_usage();
        println!(
            "Memory after cleanup: {} bytes",
            final_memory - initial_memory
        );

        // Most memory should be reclaimed
        assert!(
            final_memory - initial_memory < initial_memory + 100_000,
            "Memory not properly reclaimed after plugin shutdown"
        );
    }

    #[tokio::test]
    async fn test_rollback_memory_efficiency() {
        reset_memory_tracking();

        let state_transfer = Arc::new(state_transfer::StateTransferCoordinator::new(
            Default::default(),
        ));
        let version_manager = Arc::new(version::VersionManager::new(Default::default()));
        let rollback_manager =
            rollback::RollbackManager::new(state_transfer, version_manager, Default::default());

        // Create plugin with state
        let mut plugin = MemoryTestPlugin::new("rollback-test");
        plugin.allocate_memory(512 * 1024); // 512KB
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));

        let before_checkpoints = current_memory_usage();

        // Create multiple checkpoints
        for i in 0..10 {
            // Create dummy state snapshot
            let state = StateSnapshot {
                id: format!("checkpoint-{}", i),
                plugin_id: "rollback-test".to_string(),
                plugin_version: "1.0.0".to_string(),
                schema_version: 1,
                timestamp: chrono::Utc::now().timestamp(),
                sections: std::collections::HashMap::from([(
                    "state".to_string(),
                    StateSection {
                        name: "state".to_string(),
                        section_type: SectionType::Core,
                        priority: 1,
                        format: DataFormat::Binary,
                        data: SectionData::Inline {
                            data: vec![0u8; 512 * 1024], // 512KB per checkpoint
                            original_size: 512 * 1024,
                            compression: CompressionType::None,
                        },
                        dependencies: vec![],
                    },
                )]),
                metadata: StateMetadata {
                    reason: StateCreationReason::Checkpoint,
                    created_by: "test".to_string(),
                    tags: vec![],
                    expires_at: None,
                    custom: std::collections::HashMap::new(),
                },
                checksum: format!("checkpoint-{}", i),
            };

            rollback_manager
                .create_checkpoint(
                    "rollback-test",
                    handle.clone(),
                    state,
                    rollback::CheckpointType::Automatic,
                    &format!("Checkpoint {}", i),
                )
                .await
                .unwrap();
        }

        let after_checkpoints = current_memory_usage();
        let checkpoint_memory = after_checkpoints - before_checkpoints;

        println!("Memory used by 10 checkpoints: {} bytes", checkpoint_memory);

        // Should have some deduplication or compression
        assert!(
            checkpoint_memory < 10 * 512 * 1024,
            "Checkpoint storage not memory efficient"
        );

        // Cleanup old checkpoints
        rollback_manager
            .cleanup_old_checkpoints("rollback-test", 3)
            .await
            .unwrap();

        sleep(Duration::from_millis(100)).await;

        let after_cleanup = current_memory_usage();
        println!(
            "Memory after cleanup: {} bytes",
            after_cleanup - before_checkpoints
        );

        // Should have freed most memory
        assert!(
            after_cleanup - before_checkpoints < checkpoint_memory / 2,
            "Checkpoint cleanup did not free memory"
        );
    }

    #[tokio::test]
    async fn test_plugin_registry_memory_scaling() {
        reset_memory_tracking();
        let initial_memory = current_memory_usage();

        let mut registry = registry::PluginRegistry::new();

        // Add many plugins
        for i in 0..1000 {
            let plugin = MemoryTestPlugin::new(&format!("registry-test-{}", i));
            let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
            registry
                .register(format!("registry-test-{}", i), handle)
                .unwrap();
        }

        let after_registration = current_memory_usage();
        let registry_overhead = after_registration - initial_memory;
        let per_plugin_overhead = registry_overhead / 1000;

        println!(
            "Registry overhead for 1000 plugins: {} bytes",
            registry_overhead
        );
        println!(
            "Per-plugin registry overhead: {} bytes",
            per_plugin_overhead
        );

        // Registry overhead should be reasonable
        assert!(
            per_plugin_overhead < 10_000,
            "Excessive registry overhead per plugin: {} bytes",
            per_plugin_overhead
        );

        // Test lookup performance doesn't degrade
        let start = std::time::Instant::now();
        for i in (0..1000).step_by(10) {
            let _ = registry.get(&format!("registry-test-{}", i));
        }
        let lookup_time = start.elapsed();

        println!("100 lookups took: {:?}", lookup_time);
        assert!(
            lookup_time < Duration::from_millis(10),
            "Registry lookup performance degraded with scale"
        );
    }

    #[tokio::test]
    async fn test_zero_downtime_buffer_memory() {
        reset_memory_tracking();

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

        let coordinator = zero_downtime::ZeroDowntimeCoordinator::new(
            hot_reload,
            rollback,
            state_transfer,
            Default::default(),
        );

        let before_buffering = current_memory_usage();

        // Pause plugin to start buffering
        coordinator.buffer.pause_plugin("test-plugin").await;

        // Send many requests that will be buffered
        for i in 0..1000 {
            let (tx, _rx) = tokio::sync::oneshot::channel();

            let request = zero_downtime::BufferedRequest {
                request: PluginRequest {
                    id: format!("buffered-{}", i),
                    capability: Capability::new("test", "op", 1),
                    method: "test".to_string(),
                    params: serde_json::json!({"data": vec![0u8; 1024]}), // 1KB per request
                    metadata: serde_json::json!({}),
                },
                response_tx: tx,
                enqueued_at: std::time::Instant::now(),
                size_bytes: 1024,
            };

            // Add to buffer
            let mut buffers = coordinator.buffer.buffers.write().await;
            if let Some(buffer) = buffers.get_mut("test-plugin") {
                buffer.queue.push_back(request);
                buffer.total_size += 1024;
            }
        }

        let after_buffering = current_memory_usage();
        let buffer_memory = after_buffering - before_buffering;

        println!(
            "Memory used for buffering 1000 requests: {} bytes",
            buffer_memory
        );

        // Buffer memory should be close to actual data size
        assert!(
            buffer_memory < 2 * 1000 * 1024,
            "Excessive memory overhead in request buffering"
        );

        // Clear buffer
        coordinator.buffer.resume_plugin("test-plugin").await;
        coordinator.buffer.clear_plugin("test-plugin").await;

        sleep(Duration::from_millis(100)).await;

        let after_clear = current_memory_usage();
        println!(
            "Memory after clearing buffer: {} bytes",
            after_clear - before_buffering
        );

        // Memory should be reclaimed
        assert!(
            after_clear - before_buffering < 100_000,
            "Buffer memory not properly reclaimed"
        );
    }
}
