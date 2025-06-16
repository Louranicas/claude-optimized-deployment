//! Hot Reload Integration Tests
//!
//! Integration tests for the hot reload system with state preservation.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

use super::*;
use claude_optimized_deployment_rust::mcp_manager::plugin::{
    *,
    hot_reload::*,
    state_transfer::*,
    version::*,
    rollback::*,
};
use tokio::time::{sleep, Duration};
use std::sync::atomic::{AtomicU64, Ordering};

/// Hot reload test plugin with state
#[derive(Debug)]
struct HotReloadTestPlugin {
    metadata: PluginMetadata,
    state: Arc<RwLock<PluginState>>,
    request_counter: Arc<AtomicU64>,
    last_request_id: Arc<RwLock<String>>,
    version_marker: String,
}

#[derive(Debug, Default)]
struct PluginState {
    initialized_at: Option<std::time::SystemTime>,
    configuration: serde_json::Value,
    custom_data: HashMap<String, String>,
}

impl HotReloadTestPlugin {
    fn new(version: &str) -> Self {
        Self {
            metadata: PluginMetadata {
                id: "hot-reload-test".to_string(),
                name: "Hot Reload Test Plugin".to_string(),
                version: version.to_string(),
                author: "Test".to_string(),
                description: "Plugin for hot reload testing".to_string(),
                license: "MIT".to_string(),
                homepage: None,
                repository: None,
                min_mcp_version: "1.0.0".to_string(),
                dependencies: vec![],
                provides: vec![
                    Capability::new("hotreload", "test", 1),
                    Capability::new("hotreload", "state", 1),
                ],
                requires: vec![],
            },
            state: Arc::new(RwLock::new(PluginState::default())),
            request_counter: Arc::new(AtomicU64::new(0)),
            last_request_id: Arc::new(RwLock::new(String::new())),
            version_marker: format!("v{}", version),
        }
    }
}

#[async_trait::async_trait]
impl Plugin for HotReloadTestPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    async fn initialize(&mut self, config: serde_json::Value) -> Result<()> {
        let mut state = self.state.write().await;
        state.initialized_at = Some(std::time::SystemTime::now());
        state.configuration = config;
        Ok(())
    }

    async fn handle(&self, request: PluginRequest) -> Result<PluginResponse> {
        let count = self.request_counter.fetch_add(1, Ordering::SeqCst) + 1;
        *self.last_request_id.write().await = request.id.clone();

        Ok(PluginResponse {
            request_id: request.id,
            result: PluginResult::Success {
                data: json!({
                    "version": self.version_marker,
                    "request_count": count,
                    "state": {
                        "initialized": self.state.read().await.initialized_at.is_some(),
                        "custom_data": self.state.read().await.custom_data.clone(),
                    }
                }),
            },
            metadata: json!({}),
        })
    }

    async fn shutdown(&mut self) -> Result<()> {
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[async_trait::async_trait]
impl StateTransferable for HotReloadTestPlugin {
    async fn export_state(&self) -> Result<StateSnapshot> {
        let state = self.state.read().await;
        let count = self.request_counter.load(Ordering::SeqCst);
        let last_id = self.last_request_id.read().await.clone();

        let state_data = json!({
            "request_counter": count,
            "last_request_id": last_id,
            "custom_data": state.custom_data,
            "configuration": state.configuration,
        });

        Ok(StateSnapshot {
            id: uuid::Uuid::new_v4().to_string(),
            plugin_id: self.metadata.id.clone(),
            plugin_version: self.metadata.version.clone(),
            schema_version: 1,
            timestamp: chrono::Utc::now().timestamp(),
            sections: HashMap::from([
                ("core".to_string(), StateSection {
                    name: "core".to_string(),
                    section_type: SectionType::Core,
                    priority: 1,
                    format: DataFormat::Json,
                    data: SectionData::Inline {
                        data: serde_json::to_vec(&state_data).unwrap(),
                        original_size: 1024,
                        compression: CompressionType::None,
                    },
                    dependencies: vec![],
                }),
            ]),
            metadata: StateMetadata {
                reason: StateCreationReason::HotReload,
                created_by: "test".to_string(),
                tags: vec!["test".to_string()],
                expires_at: None,
                custom: HashMap::new(),
            },
            checksum: "test".to_string(),
        })
    }

    async fn import_state(&mut self, snapshot: StateSnapshot) -> Result<StateImportResult> {
        if let Some(section) = snapshot.sections.get("core") {
            if let SectionData::Inline { data, .. } = &section.data {
                let state_data: serde_json::Value = serde_json::from_slice(data).unwrap();
                
                // Restore state
                self.request_counter.store(
                    state_data["request_counter"].as_u64().unwrap_or(0),
                    Ordering::SeqCst,
                );
                *self.last_request_id.write().await = 
                    state_data["last_request_id"].as_str().unwrap_or("").to_string();
                
                let mut state = self.state.write().await;
                state.custom_data = serde_json::from_value(
                    state_data["custom_data"].clone()
                ).unwrap_or_default();
                state.configuration = state_data["configuration"].clone();
            }
        }

        Ok(StateImportResult {
            imported_sections: vec!["core".to_string()],
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
            section_validations: HashMap::new(),
            compatibility_score: 1.0,
        })
    }

    fn state_schema_version(&self) -> u32 {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_hot_reload_with_state_preservation() {
        let env = TestEnvironment::new(TestConfig {
            enable_hot_reload: true,
            ..Default::default()
        }).await;
        env.setup().await.unwrap();

        // Setup hot reload manager
        let loader = Arc::new(loader::PluginLoader::new());
        let mut hot_reload_manager = HotReloadManager::new(loader, HotReloadConfig {
            auto_rollback: true,
            state_transfer_timeout_secs: 10,
            ..Default::default()
        });
        
        hot_reload_manager.start().await.unwrap();

        // Create initial plugin version
        let plugin_v1 = HotReloadTestPlugin::new("1.0.0");
        let handle_v1 = Arc::new(PluginHandle::new(Box::new(plugin_v1)));

        // Register and initialize
        hot_reload_manager.register_plugin(
            "hot-reload-test".to_string(),
            handle_v1.clone(),
            None,
        ).await.unwrap();

        handle_v1.initialize(json!({
            "setting": "initial"
        })).await.unwrap();

        // Make some requests to build state
        for i in 0..10 {
            let request = PluginRequest {
                id: format!("req-{}", i),
                capability: Capability::new("hotreload", "test", 1),
                method: "test".to_string(),
                params: json!({"index": i}),
                metadata: json!({}),
            };

            let response = handle_v1.handle(request).await.unwrap();
            if let PluginResult::Success { data } = response.result {
                assert_eq!(data["version"], "v1.0.0");
                assert_eq!(data["request_count"], i + 1);
            }
        }

        // Subscribe to reload events
        let mut event_receiver = hot_reload_manager.subscribe();

        // Simulate hot reload
        hot_reload_manager.reload_plugin(
            "hot-reload-test",
            ReloadReason::VersionUpgrade,
            true,
        ).await.unwrap();

        // Wait for reload completion
        let mut reload_completed = false;
        let mut state_preserved = false;
        
        while let Ok(Ok(event)) = tokio::time::timeout(
            Duration::from_secs(5),
            event_receiver.recv()
        ).await {
            match event.event_type {
                ReloadEventType::StatePreserved => state_preserved = true,
                ReloadEventType::Completed => {
                    reload_completed = true;
                    break;
                }
                _ => {}
            }
        }

        assert!(reload_completed, "Hot reload should complete");
        assert!(state_preserved, "State should be preserved");

        env.teardown().await.unwrap();
    }

    #[tokio::test]
    async fn test_hot_reload_rollback_on_failure() {
        let env = TestEnvironment::new(TestConfig::default()).await;
        env.setup().await.unwrap();

        // Setup managers
        let loader = Arc::new(loader::PluginLoader::new());
        let state_transfer = Arc::new(StateTransferCoordinator::new(Default::default()));
        let version_manager = Arc::new(VersionManager::new(Default::default()));
        let rollback_manager = Arc::new(RollbackManager::new(
            state_transfer.clone(),
            version_manager,
            Default::default(),
        ));

        let config = HotReloadConfig {
            auto_rollback: true,
            max_reload_attempts: 2,
            ..Default::default()
        };

        let mut hot_reload_manager = HotReloadManager::new(loader, config);
        hot_reload_manager.start().await.unwrap();

        // Create and register healthy plugin
        let plugin = HotReloadTestPlugin::new("1.0.0");
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));

        hot_reload_manager.register_plugin(
            "rollback-test".to_string(),
            handle.clone(),
            None,
        ).await.unwrap();

        handle.initialize(json!({})).await.unwrap();

        // Create checkpoint for rollback
        let state_snapshot = handle.as_any()
            .downcast_ref::<HotReloadTestPlugin>()
            .unwrap()
            .export_state()
            .await
            .unwrap();

        rollback_manager.create_checkpoint(
            "rollback-test",
            handle.clone(),
            state_snapshot,
            CheckpointType::PreUpdate,
            "Pre hot-reload checkpoint",
        ).await.unwrap();

        // Subscribe to events
        let mut event_receiver = hot_reload_manager.subscribe();

        // Attempt reload (will fail due to missing new version)
        hot_reload_manager.reload_plugin(
            "rollback-test",
            ReloadReason::VersionUpgrade,
            true,
        ).await.unwrap();

        // Wait for rollback event
        let mut rollback_occurred = false;
        while let Ok(Ok(event)) = tokio::time::timeout(
            Duration::from_secs(5),
            event_receiver.recv()
        ).await {
            if event.event_type == ReloadEventType::RolledBack {
                rollback_occurred = true;
                break;
            }
        }

        assert!(rollback_occurred, "Rollback should occur on failure");

        env.teardown().await.unwrap();
    }

    #[tokio::test]
    async fn test_hot_reload_version_tracking() {
        let env = TestEnvironment::new(TestConfig::default()).await;
        env.setup().await.unwrap();

        let version_manager = Arc::new(VersionManager::new(Default::default()));

        // Register multiple versions
        for (major, minor, patch) in [(1, 0, 0), (1, 1, 0), (1, 2, 0), (2, 0, 0)] {
            let version_info = VersionInfo {
                version: semver::Version::new(major, minor, patch),
                released_at: chrono::Utc::now(),
                metadata: VersionMetadata {
                    description: format!("Version {}.{}.{}", major, minor, patch),
                    release_notes: "Test release".to_string(),
                    author: "Test".to_string(),
                    stability: StabilityLevel::Stable,
                    deprecated: false,
                    deprecation_notice: None,
                    security_patches: vec![],
                },
                file_info: None,
                dependencies: vec![],
                breaking_changes: vec![],
                migration: None,
            };

            version_manager.register_version(
                "hot-reload-test".to_string(),
                version_info,
            ).await.unwrap();
        }

        // Get version history
        let history = version_manager.get_version_history("hot-reload-test").await.unwrap();
        assert_eq!(history.versions.len(), 4);

        // Check timeline
        assert_eq!(history.timeline.len(), 4);
        for event in &history.timeline {
            assert_eq!(event.event_type, VersionEventType::Released);
        }

        env.teardown().await.unwrap();
    }

    #[tokio::test]
    async fn test_hot_reload_concurrent_requests() {
        let env = TestEnvironment::new(TestConfig::default()).await;
        env.setup().await.unwrap();

        let loader = Arc::new(loader::PluginLoader::new());
        let mut hot_reload_manager = HotReloadManager::new(loader, Default::default());
        hot_reload_manager.start().await.unwrap();

        // Create plugin
        let plugin = HotReloadTestPlugin::new("1.0.0");
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));

        hot_reload_manager.register_plugin(
            "concurrent-test".to_string(),
            handle.clone(),
            None,
        ).await.unwrap();

        handle.initialize(json!({})).await.unwrap();

        // Send concurrent requests during potential reload
        let handle_clone = handle.clone();
        let request_task = tokio::spawn(async move {
            let mut results = vec![];
            for i in 0..50 {
                let request = PluginRequest {
                    id: format!("concurrent-{}", i),
                    capability: Capability::new("hotreload", "test", 1),
                    method: "test".to_string(),
                    params: json!({"index": i}),
                    metadata: json!({}),
                };

                let result = handle_clone.handle(request).await;
                results.push(result);
                
                // Small delay between requests
                sleep(Duration::from_millis(10)).await;
            }
            results
        });

        // Trigger reload after some requests have started
        sleep(Duration::from_millis(100)).await;
        
        hot_reload_manager.reload_plugin(
            "concurrent-test",
            ReloadReason::ManualReload,
            false,
        ).await.unwrap();

        // Wait for requests to complete
        let results = request_task.await.unwrap();
        
        // All requests should either succeed or fail gracefully
        let success_count = results.iter().filter(|r| r.is_ok()).count();
        assert!(success_count > 0, "Some requests should succeed");

        env.teardown().await.unwrap();
    }

    #[tokio::test]
    async fn test_hot_reload_state_migration() {
        let env = TestEnvironment::new(TestConfig::default()).await;
        env.setup().await.unwrap();

        let state_transfer = Arc::new(StateTransferCoordinator::new(Default::default()));

        // Create plugins with different versions
        let plugin_v1 = HotReloadTestPlugin::new("1.0.0");
        let plugin_v2 = HotReloadTestPlugin::new("2.0.0");

        // Set state in v1
        {
            let mut state = plugin_v1.state.write().await;
            state.custom_data.insert("key1".to_string(), "value1".to_string());
            state.custom_data.insert("key2".to_string(), "value2".to_string());
        }
        plugin_v1.request_counter.store(100, Ordering::SeqCst);

        // Transfer state
        let result = state_transfer.transfer_state(
            Arc::new(RwLock::new(Box::new(plugin_v1) as Box<dyn StateTransferable>)),
            Arc::new(RwLock::new(Box::new(plugin_v2) as Box<dyn StateTransferable>)),
        ).await.unwrap();

        assert!(result.success);
        assert!(result.import_result.is_some());

        // Verify state was transferred
        let import_result = result.import_result.unwrap();
        assert_eq!(import_result.imported_sections.len(), 1);
        assert!(import_result.failed_sections.is_empty());

        env.teardown().await.unwrap();
    }
}