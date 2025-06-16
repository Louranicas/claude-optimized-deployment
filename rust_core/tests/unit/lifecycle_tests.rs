//! Plugin Lifecycle Unit Tests
//!
//! Tests for plugin lifecycle management and state transitions.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

use claude_optimized_deployment_rust::mcp_manager::plugin::{*, lifecycle::*};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration};

// Test plugin with lifecycle tracking
#[derive(Debug)]
struct LifecycleTestPlugin {
    metadata: PluginMetadata,
    events: Arc<RwLock<Vec<LifecycleEvent>>>,
    init_delay: Option<Duration>,
    shutdown_delay: Option<Duration>,
    fail_on_init: bool,
    fail_on_shutdown: bool,
}

#[derive(Debug, Clone)]
enum LifecycleEvent {
    Initialized,
    HandleCalled(String),
    ShutdownStarted,
    ShutdownCompleted,
}

impl LifecycleTestPlugin {
    fn new(id: &str) -> Self {
        Self {
            metadata: PluginMetadata {
                id: id.to_string(),
                name: format!("Lifecycle Test Plugin {}", id),
                version: "1.0.0".to_string(),
                author: "Test".to_string(),
                description: "Plugin for lifecycle testing".to_string(),
                license: "MIT".to_string(),
                homepage: None,
                repository: None,
                min_mcp_version: "1.0.0".to_string(),
                dependencies: vec![],
                provides: vec![Capability::new("lifecycle", "test", 1)],
                requires: vec![],
            },
            events: Arc::new(RwLock::new(Vec::new())),
            init_delay: None,
            shutdown_delay: None,
            fail_on_init: false,
            fail_on_shutdown: false,
        }
    }

    fn with_delays(mut self, init: Option<Duration>, shutdown: Option<Duration>) -> Self {
        self.init_delay = init;
        self.shutdown_delay = shutdown;
        self
    }

    fn with_failures(mut self, init: bool, shutdown: bool) -> Self {
        self.fail_on_init = init;
        self.fail_on_shutdown = shutdown;
        self
    }

    async fn get_events(&self) -> Vec<LifecycleEvent> {
        self.events.read().await.clone()
    }
}

#[async_trait::async_trait]
impl Plugin for LifecycleTestPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    async fn initialize(&mut self, _config: serde_json::Value) -> Result<()> {
        if let Some(delay) = self.init_delay {
            sleep(delay).await;
        }

        if self.fail_on_init {
            return Err(PluginError::InitializationFailed("Test failure".to_string()));
        }

        self.events.write().await.push(LifecycleEvent::Initialized);
        Ok(())
    }

    async fn handle(&self, request: PluginRequest) -> Result<PluginResponse> {
        self.events.write().await.push(LifecycleEvent::HandleCalled(request.id.clone()));

        Ok(PluginResponse {
            request_id: request.id,
            result: PluginResult::Success {
                data: serde_json::json!({"status": "handled"}),
            },
            metadata: serde_json::json!({}),
        })
    }

    async fn shutdown(&mut self) -> Result<()> {
        self.events.write().await.push(LifecycleEvent::ShutdownStarted);

        if let Some(delay) = self.shutdown_delay {
            sleep(delay).await;
        }

        if self.fail_on_shutdown {
            return Err(PluginError::ExecutionError("Shutdown failure".to_string()));
        }

        self.events.write().await.push(LifecycleEvent::ShutdownCompleted);
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
    async fn test_lifecycle_manager_basic() {
        let manager = LifecycleManager::new(Default::default());

        // Create plugin
        let plugin = LifecycleTestPlugin::new("test");
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));

        // Register plugin
        manager.register_plugin("test".to_string(), handle.clone()).await.unwrap();

        // Check initial state
        let state = manager.get_plugin_state("test").await.unwrap();
        assert_eq!(state, PluginState::Loaded);

        // Initialize
        manager.initialize_plugin("test", serde_json::json!({})).await.unwrap();
        let state = manager.get_plugin_state("test").await.unwrap();
        assert_eq!(state, PluginState::Ready);

        // Shutdown
        manager.shutdown_plugin("test").await.unwrap();
        let state = manager.get_plugin_state("test").await.unwrap();
        assert_eq!(state, PluginState::Shutdown);
    }

    #[tokio::test]
    async fn test_lifecycle_state_transitions() {
        let manager = LifecycleManager::new(Default::default());

        let plugin = LifecycleTestPlugin::new("test");
        let events = plugin.events.clone();
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));

        manager.register_plugin("test".to_string(), handle).await.unwrap();

        // Initialize
        manager.initialize_plugin("test", serde_json::json!({})).await.unwrap();
        
        let plugin_events = events.read().await;
        assert_eq!(plugin_events.len(), 1);
        assert!(matches!(plugin_events[0], LifecycleEvent::Initialized));
        drop(plugin_events);

        // Handle request
        let plugin_handle = manager.get_plugin("test").await.unwrap();
        let request = PluginRequest {
            id: "req-1".to_string(),
            capability: Capability::new("lifecycle", "test", 1),
            method: "test".to_string(),
            params: serde_json::json!({}),
            metadata: serde_json::json!({}),
        };
        plugin_handle.handle(request).await.unwrap();

        let plugin_events = events.read().await;
        assert_eq!(plugin_events.len(), 2);
        assert!(matches!(plugin_events[1], LifecycleEvent::HandleCalled(_)));
        drop(plugin_events);

        // Shutdown
        manager.shutdown_plugin("test").await.unwrap();

        let plugin_events = events.read().await;
        assert_eq!(plugin_events.len(), 4);
        assert!(matches!(plugin_events[2], LifecycleEvent::ShutdownStarted));
        assert!(matches!(plugin_events[3], LifecycleEvent::ShutdownCompleted));
    }

    #[tokio::test]
    async fn test_lifecycle_initialization_failure() {
        let manager = LifecycleManager::new(Default::default());

        let plugin = LifecycleTestPlugin::new("test").with_failures(true, false);
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));

        manager.register_plugin("test".to_string(), handle).await.unwrap();

        // Initialize should fail
        let result = manager.initialize_plugin("test", serde_json::json!({})).await;
        assert!(result.is_err());

        // State should be Error
        let state = manager.get_plugin_state("test").await.unwrap();
        assert_eq!(state, PluginState::Error);
    }

    #[tokio::test]
    async fn test_lifecycle_shutdown_timeout() {
        let config = LifecycleConfig {
            shutdown_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let manager = LifecycleManager::new(config);

        // Plugin with long shutdown
        let plugin = LifecycleTestPlugin::new("test")
            .with_delays(None, Some(Duration::from_secs(1)));
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));

        manager.register_plugin("test".to_string(), handle).await.unwrap();
        manager.initialize_plugin("test", serde_json::json!({})).await.unwrap();

        // Shutdown should timeout
        let start = std::time::Instant::now();
        let result = manager.shutdown_plugin("test").await;
        let elapsed = start.elapsed();

        assert!(result.is_err());
        assert!(elapsed < Duration::from_millis(200));
    }

    #[tokio::test]
    async fn test_lifecycle_multiple_plugins() {
        let manager = LifecycleManager::new(Default::default());

        // Register multiple plugins
        for i in 0..5 {
            let plugin = LifecycleTestPlugin::new(&format!("plugin-{}", i));
            let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
            manager.register_plugin(format!("plugin-{}", i), handle).await.unwrap();
        }

        // Initialize all
        manager.initialize_all(serde_json::json!({})).await.unwrap();

        // Check all are ready
        for i in 0..5 {
            let state = manager.get_plugin_state(&format!("plugin-{}", i)).await.unwrap();
            assert_eq!(state, PluginState::Ready);
        }

        // Shutdown all
        manager.shutdown_all().await.unwrap();

        // Check all are shutdown
        for i in 0..5 {
            let state = manager.get_plugin_state(&format!("plugin-{}", i)).await.unwrap();
            assert_eq!(state, PluginState::Shutdown);
        }
    }

    #[tokio::test]
    async fn test_lifecycle_health_check() {
        let manager = LifecycleManager::new(Default::default());

        let plugin = LifecycleTestPlugin::new("test");
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));

        manager.register_plugin("test".to_string(), handle).await.unwrap();
        manager.initialize_plugin("test", serde_json::json!({})).await.unwrap();

        // Health check should pass
        let health = manager.check_plugin_health("test").await.unwrap();
        assert!(health);

        // Get health status
        let status = manager.get_health_status().await;
        assert_eq!(status.total_plugins, 1);
        assert_eq!(status.healthy_plugins, 1);
        assert_eq!(status.unhealthy_plugins, 0);
    }

    #[tokio::test]
    async fn test_lifecycle_concurrent_operations() {
        let manager = Arc::new(LifecycleManager::new(Default::default()));

        // Register plugins
        for i in 0..10 {
            let plugin = LifecycleTestPlugin::new(&format!("concurrent-{}", i));
            let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
            manager.register_plugin(format!("concurrent-{}", i), handle).await.unwrap();
        }

        // Spawn concurrent initialization tasks
        let mut tasks = vec![];
        for i in 0..10 {
            let manager_clone = manager.clone();
            let task = tokio::spawn(async move {
                manager_clone.initialize_plugin(
                    &format!("concurrent-{}", i),
                    serde_json::json!({}),
                ).await
            });
            tasks.push(task);
        }

        // Wait for all tasks
        let results: Vec<_> = futures::future::join_all(tasks).await;
        for result in results {
            assert!(result.is_ok());
            assert!(result.unwrap().is_ok());
        }

        // All should be ready
        for i in 0..10 {
            let state = manager.get_plugin_state(&format!("concurrent-{}", i)).await.unwrap();
            assert_eq!(state, PluginState::Ready);
        }
    }

    #[tokio::test]
    async fn test_lifecycle_restart_plugin() {
        let manager = LifecycleManager::new(Default::default());

        let plugin = LifecycleTestPlugin::new("test");
        let events = plugin.events.clone();
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));

        manager.register_plugin("test".to_string(), handle).await.unwrap();

        // Initialize
        manager.initialize_plugin("test", serde_json::json!({})).await.unwrap();

        // Restart
        manager.restart_plugin("test", serde_json::json!({})).await.unwrap();

        // Check events
        let plugin_events = events.read().await;
        // Should have: Initialized, ShutdownStarted, ShutdownCompleted, Initialized
        assert!(plugin_events.len() >= 4);
        assert!(matches!(plugin_events[0], LifecycleEvent::Initialized));
        assert!(matches!(plugin_events[plugin_events.len() - 1], LifecycleEvent::Initialized));
    }

    #[tokio::test]
    async fn test_lifecycle_state_history() {
        let manager = LifecycleManager::new(Default::default());

        let plugin = LifecycleTestPlugin::new("test");
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));

        manager.register_plugin("test".to_string(), handle).await.unwrap();

        // Perform state transitions
        manager.initialize_plugin("test", serde_json::json!({})).await.unwrap();
        manager.shutdown_plugin("test").await.unwrap();

        // Get state history
        let history = manager.get_state_history("test").await.unwrap();
        assert!(history.len() >= 3); // Loaded -> Ready -> Shutdown
    }

    #[tokio::test]
    async fn test_lifecycle_plugin_not_found() {
        let manager = LifecycleManager::new(Default::default());

        // Operations on non-existent plugin should fail
        let result = manager.initialize_plugin("non-existent", serde_json::json!({})).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PluginError::NotFound(_)
        ));

        let result = manager.shutdown_plugin("non-existent").await;
        assert!(result.is_err());

        let result = manager.get_plugin_state("non-existent").await;
        assert!(result.is_err());
    }
}