//! Plugin Registry Unit Tests
//!
//! Tests for the plugin registry and registration system.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

use claude_optimized_deployment_rust::mcp_manager::plugin::{*, registry::*};
use std::sync::Arc;
use tokio::sync::RwLock;

// Mock plugin for registry testing
#[derive(Debug)]
struct RegistryTestPlugin {
    metadata: PluginMetadata,
}

impl RegistryTestPlugin {
    fn new(id: &str, capabilities: Vec<Capability>) -> Self {
        Self {
            metadata: PluginMetadata {
                id: id.to_string(),
                name: format!("Registry Test Plugin {}", id),
                version: "1.0.0".to_string(),
                author: "Test".to_string(),
                description: "Test plugin".to_string(),
                license: "MIT".to_string(),
                homepage: None,
                repository: None,
                min_mcp_version: "1.0.0".to_string(),
                dependencies: vec![],
                provides: capabilities,
                requires: vec![],
            },
        }
    }
}

#[async_trait::async_trait]
impl Plugin for RegistryTestPlugin {
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
                data: serde_json::json!({"status": "ok"}),
            },
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_plugin_registry_basic() {
        let mut registry = PluginRegistry::new();

        // Register a plugin
        let plugin = RegistryTestPlugin::new(
            "test-plugin",
            vec![
                Capability::new("test", "operation", 1),
                Capability::new("test", "query", 1),
            ],
        );
        
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
        registry.register("test-plugin".to_string(), handle.clone()).unwrap();

        // Check if registered
        assert!(registry.is_registered("test-plugin"));
        assert!(!registry.is_registered("non-existent"));

        // Get plugin
        let retrieved = registry.get("test-plugin").unwrap();
        assert_eq!(retrieved.metadata().await.id, "test-plugin");

        // List plugins
        let plugins = registry.list_plugins();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0], "test-plugin");
    }

    #[tokio::test]
    async fn test_plugin_registry_duplicate() {
        let mut registry = PluginRegistry::new();

        // Register first plugin
        let plugin1 = RegistryTestPlugin::new("test-plugin", vec![]);
        let handle1 = Arc::new(PluginHandle::new(Box::new(plugin1)));
        registry.register("test-plugin".to_string(), handle1).unwrap();

        // Try to register duplicate
        let plugin2 = RegistryTestPlugin::new("test-plugin", vec![]);
        let handle2 = Arc::new(PluginHandle::new(Box::new(plugin2)));
        let result = registry.register("test-plugin".to_string(), handle2);
        
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PluginError::AlreadyLoaded(_)
        ));
    }

    #[tokio::test]
    async fn test_plugin_registry_unregister() {
        let mut registry = PluginRegistry::new();

        // Register plugin
        let plugin = RegistryTestPlugin::new("test-plugin", vec![]);
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
        registry.register("test-plugin".to_string(), handle).unwrap();

        // Unregister
        let removed = registry.unregister("test-plugin").unwrap();
        assert_eq!(removed.metadata().await.id, "test-plugin");

        // Should not be registered anymore
        assert!(!registry.is_registered("test-plugin"));
        assert!(registry.get("test-plugin").is_none());

        // Unregister non-existent
        assert!(registry.unregister("non-existent").is_none());
    }

    #[tokio::test]
    async fn test_plugin_registry_capability_search() {
        let mut registry = PluginRegistry::new();

        // Register plugins with different capabilities
        let plugin1 = RegistryTestPlugin::new(
            "docker-plugin",
            vec![
                Capability::new("docker", "container.create", 1),
                Capability::new("docker", "container.list", 1),
                Capability::new("docker", "image.pull", 1),
            ],
        );
        
        let plugin2 = RegistryTestPlugin::new(
            "k8s-plugin",
            vec![
                Capability::new("k8s", "pod.create", 1),
                Capability::new("k8s", "pod.list", 1),
                Capability::new("k8s", "service.create", 1),
            ],
        );

        registry.register("docker-plugin".to_string(), Arc::new(PluginHandle::new(Box::new(plugin1)))).unwrap();
        registry.register("k8s-plugin".to_string(), Arc::new(PluginHandle::new(Box::new(plugin2)))).unwrap();

        // Find plugins by capability
        let docker_plugins = registry.find_by_capability(&Capability::new("docker", "container.create", 1));
        assert_eq!(docker_plugins.len(), 1);
        assert_eq!(docker_plugins[0], "docker-plugin");

        let k8s_plugins = registry.find_by_capability(&Capability::new("k8s", "pod.list", 1));
        assert_eq!(k8s_plugins.len(), 1);
        assert_eq!(k8s_plugins[0], "k8s-plugin");

        // Non-existent capability
        let none = registry.find_by_capability(&Capability::new("unknown", "operation", 1));
        assert_eq!(none.len(), 0);
    }

    #[tokio::test]
    async fn test_plugin_registry_namespace_search() {
        let mut registry = PluginRegistry::new();

        // Register plugins in different namespaces
        let plugin1 = RegistryTestPlugin::new(
            "docker-plugin",
            vec![
                Capability::new("docker", "operation1", 1),
                Capability::new("docker", "operation2", 1),
            ],
        );
        
        let plugin2 = RegistryTestPlugin::new(
            "docker-extra",
            vec![
                Capability::new("docker", "operation3", 1),
            ],
        );
        
        let plugin3 = RegistryTestPlugin::new(
            "k8s-plugin",
            vec![
                Capability::new("k8s", "operation1", 1),
            ],
        );

        registry.register("docker-plugin".to_string(), Arc::new(PluginHandle::new(Box::new(plugin1)))).unwrap();
        registry.register("docker-extra".to_string(), Arc::new(PluginHandle::new(Box::new(plugin2)))).unwrap();
        registry.register("k8s-plugin".to_string(), Arc::new(PluginHandle::new(Box::new(plugin3)))).unwrap();

        // Find by namespace
        let docker_plugins = registry.find_by_namespace("docker");
        assert_eq!(docker_plugins.len(), 2);
        assert!(docker_plugins.contains(&"docker-plugin".to_string()));
        assert!(docker_plugins.contains(&"docker-extra".to_string()));

        let k8s_plugins = registry.find_by_namespace("k8s");
        assert_eq!(k8s_plugins.len(), 1);
        assert_eq!(k8s_plugins[0], "k8s-plugin");
    }

    #[tokio::test]
    async fn test_plugin_registry_clear() {
        let mut registry = PluginRegistry::new();

        // Register multiple plugins
        for i in 0..5 {
            let plugin = RegistryTestPlugin::new(&format!("plugin-{}", i), vec![]);
            let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
            registry.register(format!("plugin-{}", i), handle).unwrap();
        }

        assert_eq!(registry.list_plugins().len(), 5);

        // Clear registry
        registry.clear();
        assert_eq!(registry.list_plugins().len(), 0);
    }

    #[tokio::test]
    async fn test_plugin_registry_metadata_access() {
        let mut registry = PluginRegistry::new();

        // Register plugin with metadata
        let plugin = RegistryTestPlugin::new(
            "metadata-test",
            vec![
                Capability::new("test", "cap1", 1),
                Capability::new("test", "cap2", 2),
            ],
        );
        
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
        registry.register("metadata-test".to_string(), handle).unwrap();

        // Access metadata through registry
        let plugin_handle = registry.get("metadata-test").unwrap();
        let metadata = plugin_handle.metadata().await;
        
        assert_eq!(metadata.id, "metadata-test");
        assert_eq!(metadata.version, "1.0.0");
        assert_eq!(metadata.provides.len(), 2);
        assert_eq!(metadata.provides[0].name, "cap1");
        assert_eq!(metadata.provides[1].version, 2);
    }

    #[tokio::test]
    async fn test_plugin_registry_concurrent_access() {
        let registry = Arc::new(RwLock::new(PluginRegistry::new()));

        // Spawn multiple tasks to register plugins
        let mut tasks = vec![];
        for i in 0..10 {
            let registry_clone = registry.clone();
            let task = tokio::spawn(async move {
                let plugin = RegistryTestPlugin::new(&format!("concurrent-{}", i), vec![]);
                let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
                
                let mut reg = registry_clone.write().await;
                reg.register(format!("concurrent-{}", i), handle)
            });
            tasks.push(task);
        }

        // Wait for all registrations
        let results: Vec<_> = futures::future::join_all(tasks).await;
        for result in results {
            assert!(result.is_ok());
            assert!(result.unwrap().is_ok());
        }

        // Verify all plugins are registered
        let reg = registry.read().await;
        assert_eq!(reg.list_plugins().len(), 10);
    }

    #[tokio::test]
    async fn test_plugin_registry_lifecycle() {
        let mut registry = PluginRegistry::new();

        // Register and initialize plugin
        let plugin = RegistryTestPlugin::new("lifecycle-test", vec![]);
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
        
        // Initialize before registering
        handle.initialize(serde_json::json!({})).await.unwrap();
        
        registry.register("lifecycle-test".to_string(), handle.clone()).unwrap();

        // Verify plugin is ready
        assert_eq!(handle.state().await, PluginState::Ready);

        // Unregister and shutdown
        let removed = registry.unregister("lifecycle-test").unwrap();
        removed.shutdown().await.unwrap();
        
        assert_eq!(removed.state().await, PluginState::Shutdown);
    }
}