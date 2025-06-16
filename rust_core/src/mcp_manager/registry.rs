//! MCP Server Registry
//! 
//! Thread-safe registry for managing MCP server instances

use crate::mcp_manager::{
    server::McpServer,
    errors::{McpError, Result},
};
use dashmap::DashMap;
use std::sync::Arc;
use tracing::{info, warn};

/// Thread-safe MCP server registry
pub struct McpRegistry {
    /// Server storage using lock-free DashMap
    servers: Arc<DashMap<String, Arc<McpServer>>>,
}

impl McpRegistry {
    /// Create a new registry
    pub fn new() -> Self {
        Self {
            servers: Arc::new(DashMap::new()),
        }
    }
    
    /// Register a server
    pub async fn register(&self, name: String, server: Arc<McpServer>) -> Result<()> {
        if self.servers.contains_key(&name) {
            warn!("Server {} already registered, updating", name);
        }
        
        self.servers.insert(name.clone(), server);
        info!("✅ Registered server: {}", name);
        
        Ok(())
    }
    
    /// Get a server by name
    pub fn get(&self, name: &str) -> Option<Arc<McpServer>> {
        self.servers.get(name).map(|entry| entry.clone())
    }
    
    /// Remove a server
    pub async fn unregister(&self, name: &str) -> Result<()> {
        if self.servers.remove(name).is_some() {
            info!("Unregistered server: {}", name);
            Ok(())
        } else {
            Err(McpError::NotFound(format!("Server {} not found", name)))
        }
    }
    
    /// List all registered servers
    pub fn list_servers(&self) -> Vec<String> {
        self.servers.iter().map(|entry| entry.key().clone()).collect()
    }
    
    /// Get server count
    pub fn count(&self) -> usize {
        self.servers.len()
    }
    
    /// Clear all servers
    pub async fn clear(&self) {
        self.servers.clear();
        info!("Cleared all servers from registry");
    }
    
    /// Get all servers
    pub fn all(&self) -> Vec<Arc<McpServer>> {
        self.servers.iter().map(|entry| entry.value().clone()).collect()
    }
}

/// Alias for backward compatibility
pub type ServerRegistry = McpRegistry;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_manager::config::{ServerConfig, ServerType};
    
    #[tokio::test]
    async fn test_registry_operations() {
        let registry = McpRegistry::new();
        
        // Create test server
        let config = ServerConfig {
            name: "test".to_string(),
            server_type: ServerType::Docker,
            url: "http://localhost:8001".to_string(),
            port: 8001,
            auth: None,
            capabilities: vec![],
            max_connections: 10,
            timeout_ms: 5000,
            retry_policy: Default::default(),
            priority: 5,
            tags: vec!["test".to_string()],
        };
        
        let server = Arc::new(McpServer::new("test".to_string(), config).unwrap());
        
        // Register
        registry.register("test".to_string(), server.clone()).await.unwrap();
        assert_eq!(registry.count(), 1);
        
        // Get
        let retrieved = registry.get("test");
        assert!(retrieved.is_some());
        
        // List
        let servers = registry.list_servers();
        assert_eq!(servers.len(), 1);
        assert!(servers.contains(&"test".to_string()));
        
        // Unregister
        registry.unregister("test").await.unwrap();
        assert_eq!(registry.count(), 0);
    }
}