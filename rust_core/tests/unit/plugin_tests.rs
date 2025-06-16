//! Plugin Core Unit Tests
//!
//! Tests for the fundamental plugin trait and core functionality.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

use claude_optimized_deployment_rust::mcp_manager::plugin::*;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Mock plugin for testing
#[derive(Debug)]
struct MockPlugin {
    metadata: PluginMetadata,
    initialized: Arc<RwLock<bool>>,
    shutdown: Arc<RwLock<bool>>,
    handle_count: Arc<RwLock<u64>>,
    fail_on_init: bool,
    fail_on_handle: bool,
}

impl MockPlugin {
    fn new(id: &str, version: &str) -> Self {
        Self {
            metadata: PluginMetadata {
                id: id.to_string(),
                name: format!("Mock Plugin {}", id),
                version: version.to_string(),
                author: "Test".to_string(),
                description: "Mock plugin for testing".to_string(),
                license: "MIT".to_string(),
                homepage: None,
                repository: None,
                min_mcp_version: "1.0.0".to_string(),
                dependencies: vec![],
                provides: vec![
                    Capability::new("mock", "test", 1),
                    Capability::new("mock", "echo", 1),
                ],
                requires: vec![],
            },
            initialized: Arc::new(RwLock::new(false)),
            shutdown: Arc::new(RwLock::new(false)),
            handle_count: Arc::new(RwLock::new(0)),
            fail_on_init: false,
            fail_on_handle: false,
        }
    }

    fn with_failure(mut self, on_init: bool, on_handle: bool) -> Self {
        self.fail_on_init = on_init;
        self.fail_on_handle = on_handle;
        self
    }
}

#[async_trait::async_trait]
impl Plugin for MockPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    async fn initialize(&mut self, _config: serde_json::Value) -> Result<()> {
        if self.fail_on_init {
            return Err(PluginError::InitializationFailed("Mock failure".to_string()));
        }
        *self.initialized.write().await = true;
        Ok(())
    }

    async fn handle(&self, request: PluginRequest) -> Result<PluginResponse> {
        if self.fail_on_handle {
            return Err(PluginError::ExecutionError("Mock handle failure".to_string()));
        }

        let mut count = self.handle_count.write().await;
        *count += 1;

        Ok(PluginResponse {
            request_id: request.id,
            result: PluginResult::Success {
                data: json!({
                    "echo": request.params,
                    "count": *count,
                }),
            },
            metadata: json!({}),
        })
    }

    async fn shutdown(&mut self) -> Result<()> {
        *self.shutdown.write().await = true;
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_parsing() {
        // Valid capability
        let cap = Capability::parse("docker.container.create:1").unwrap();
        assert_eq!(cap.namespace, "docker");
        assert_eq!(cap.name, "container.create");
        assert_eq!(cap.version, 1);

        // Test to_string
        assert_eq!(cap.to_string(), "docker.container.create:1");

        // Complex name
        let cap2 = Capability::parse("k8s.pod.status.get:2").unwrap();
        assert_eq!(cap2.namespace, "k8s");
        assert_eq!(cap2.name, "pod.status.get");
        assert_eq!(cap2.version, 2);
    }

    #[test]
    fn test_capability_invalid_formats() {
        assert!(Capability::parse("invalid").is_err());
        assert!(Capability::parse("missing:version:extra").is_err());
        assert!(Capability::parse("namespace.name:abc").is_err());
        assert!(Capability::parse("justnamespace:1").is_err());
    }

    #[test]
    fn test_plugin_dependency() {
        let dep = PluginDependency {
            id: "test-dep".to_string(),
            version: "^1.0.0".to_string(),
            optional: false,
        };

        assert_eq!(dep.id, "test-dep");
        assert!(!dep.optional);
    }

    #[tokio::test]
    async fn test_plugin_handle_lifecycle() {
        let plugin = MockPlugin::new("test", "1.0.0");
        let handle = PluginHandle::new(Box::new(plugin));

        // Initial state
        assert_eq!(handle.state().await, PluginState::Loaded);

        // Initialize
        handle.initialize(json!({})).await.unwrap();
        assert_eq!(handle.state().await, PluginState::Ready);

        // Handle request
        let request = PluginRequest {
            id: "req-1".to_string(),
            capability: Capability::new("mock", "test", 1),
            method: "test".to_string(),
            params: json!({"key": "value"}),
            metadata: json!({}),
        };

        let response = handle.handle(request).await.unwrap();
        assert_eq!(response.request_id, "req-1");

        // Check metrics
        let metrics = handle.metrics().await;
        assert_eq!(metrics.requests_total, 1);
        assert_eq!(metrics.requests_success, 1);
        assert_eq!(metrics.requests_failed, 0);

        // Shutdown
        handle.shutdown().await.unwrap();
        assert_eq!(handle.state().await, PluginState::Shutdown);
    }

    #[tokio::test]
    async fn test_plugin_initialization_failure() {
        let plugin = MockPlugin::new("test", "1.0.0").with_failure(true, false);
        let handle = PluginHandle::new(Box::new(plugin));

        // Initialize should fail
        let result = handle.initialize(json!({})).await;
        assert!(result.is_err());
        assert_eq!(handle.state().await, PluginState::Error);
    }

    #[tokio::test]
    async fn test_plugin_handle_failure() {
        let plugin = MockPlugin::new("test", "1.0.0").with_failure(false, true);
        let handle = PluginHandle::new(Box::new(plugin));

        // Initialize successfully
        handle.initialize(json!({})).await.unwrap();

        // Handle should fail
        let request = PluginRequest {
            id: "req-1".to_string(),
            capability: Capability::new("mock", "test", 1),
            method: "test".to_string(),
            params: json!({}),
            metadata: json!({}),
        };

        let result = handle.handle(request).await;
        assert!(result.is_err());

        // Check metrics
        let metrics = handle.metrics().await;
        assert_eq!(metrics.requests_total, 1);
        assert_eq!(metrics.requests_success, 0);
        assert_eq!(metrics.requests_failed, 1);
    }

    #[tokio::test]
    async fn test_plugin_not_ready() {
        let plugin = MockPlugin::new("test", "1.0.0");
        let handle = PluginHandle::new(Box::new(plugin));

        // Try to handle without initialization
        let request = PluginRequest {
            id: "req-1".to_string(),
            capability: Capability::new("mock", "test", 1),
            method: "test".to_string(),
            params: json!({}),
            metadata: json!({}),
        };

        let result = handle.handle(request).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PluginError::ExecutionError(_)
        ));
    }

    #[tokio::test]
    async fn test_plugin_health_check() {
        let plugin = MockPlugin::new("test", "1.0.0");
        let handle = PluginHandle::new(Box::new(plugin));

        // Health check should succeed
        let health = handle.health_check().await.unwrap();
        assert!(health);

        // Check metrics
        let metrics = handle.metrics().await;
        assert!(metrics.last_health_check.is_some());
    }

    #[tokio::test]
    async fn test_plugin_metadata() {
        let plugin = MockPlugin::new("test-plugin", "2.0.0");
        let handle = PluginHandle::new(Box::new(plugin));

        let metadata = handle.metadata().await;
        assert_eq!(metadata.id, "test-plugin");
        assert_eq!(metadata.version, "2.0.0");
        assert_eq!(metadata.provides.len(), 2);
    }

    #[test]
    fn test_plugin_result_serialization() {
        // Success result
        let success = PluginResult::Success {
            data: json!({"result": "ok"}),
        };
        let json = serde_json::to_value(&success).unwrap();
        assert_eq!(json["status"], "success");
        assert_eq!(json["data"]["result"], "ok");

        // Error result
        let error = PluginResult::Error {
            code: "E001".to_string(),
            message: "Test error".to_string(),
            details: Some(json!({"field": "value"})),
        };
        let json = serde_json::to_value(&error).unwrap();
        assert_eq!(json["status"], "error");
        assert_eq!(json["code"], "E001");
        assert_eq!(json["message"], "Test error");
    }

    #[test]
    fn test_plugin_state_transitions() {
        let states = vec![
            PluginState::Loaded,
            PluginState::Initializing,
            PluginState::Ready,
            PluginState::ShuttingDown,
            PluginState::Shutdown,
            PluginState::Error,
        ];

        for state in states {
            // Ensure all states are distinct
            let json = serde_json::to_value(&state).unwrap();
            let restored: PluginState = serde_json::from_value(json).unwrap();
            assert_eq!(state, restored);
        }
    }

    #[tokio::test]
    async fn test_concurrent_requests() {
        let plugin = MockPlugin::new("test", "1.0.0");
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));

        // Initialize
        handle.initialize(json!({})).await.unwrap();

        // Send multiple concurrent requests
        let mut tasks = vec![];
        for i in 0..10 {
            let handle_clone = handle.clone();
            let task = tokio::spawn(async move {
                let request = PluginRequest {
                    id: format!("req-{}", i),
                    capability: Capability::new("mock", "echo", 1),
                    method: "echo".to_string(),
                    params: json!({"index": i}),
                    metadata: json!({}),
                };

                handle_clone.handle(request).await
            });
            tasks.push(task);
        }

        // Wait for all requests
        let results: Vec<_> = futures::future::join_all(tasks).await;
        assert_eq!(results.len(), 10);

        // All should succeed
        for result in results {
            assert!(result.is_ok());
            assert!(result.unwrap().is_ok());
        }

        // Check total metrics
        let metrics = handle.metrics().await;
        assert_eq!(metrics.requests_total, 10);
        assert_eq!(metrics.requests_success, 10);
    }
}