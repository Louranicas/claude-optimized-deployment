//! Migration utilities for transitioning from shared-state to actor model
//! 
//! This module provides adapters and compatibility layers to allow gradual
//! migration from the old McpManager to the new McpManagerV2.

use crate::mcp_manager::{
    manager_v2::McpManagerV2,
    config::McpConfig,
    errors::Result,
    ServerRegistry,
    DeploymentManager,
    HealthMonitor,
    MetricsCollector,
};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Adapter that provides the old McpManager interface using the new actor-based implementation
pub struct McpManagerAdapter {
    /// The new actor-based manager
    inner: McpManagerV2,
    /// Compatibility registry (read-only view)
    registry: Arc<RwLock<ServerRegistry>>,
}

impl McpManagerAdapter {
    /// Create a new adapter
    pub fn new(config: McpConfig) -> Self {
        let inner = McpManagerV2::new(config);
        let registry = Arc::new(RwLock::new(ServerRegistry::new()));
        
        Self {
            inner,
            registry,
        }
    }
    
    /// Start the manager (compatibility method)
    pub async fn start(&self) -> Result<()> {
        self.inner.initialize().await
    }
    
    /// Stop the manager (compatibility method)
    pub async fn stop(&self) -> Result<()> {
        // In the new architecture, we don't have a separate stop
        // Servers are managed through deploy/undeploy
        Ok(())
    }
    
    /// Get registry (compatibility method)
    /// Note: This returns a fake registry for compatibility
    pub fn registry(&self) -> &Arc<RwLock<ServerRegistry>> {
        &self.registry
    }
    
    /// Get the inner V2 manager for new code
    pub fn v2(&self) -> &McpManagerV2 {
        &self.inner
    }
}

/// Feature flags for gradual migration
#[derive(Debug, Clone)]
pub struct MigrationFlags {
    /// Use actor model for server deployment
    pub use_actor_deployment: bool,
    /// Use actor model for health checks
    pub use_actor_health: bool,
    /// Use actor model for metrics
    pub use_actor_metrics: bool,
    /// Use actor model for execution
    pub use_actor_execution: bool,
}

impl Default for MigrationFlags {
    fn default() -> Self {
        Self {
            use_actor_deployment: true,  // Start with deployment
            use_actor_health: false,     // Migrate health checks later
            use_actor_metrics: false,    // Migrate metrics later
            use_actor_execution: false,  // Migrate execution last
        }
    }
}

/// Hybrid manager that can use both old and new implementations
pub struct HybridMcpManager {
    /// Old implementation (being phased out)
    old: Option<super::McpManager>,
    /// New implementation (being phased in)
    new: McpManagerV2,
    /// Migration flags
    flags: MigrationFlags,
}

impl HybridMcpManager {
    /// Create a new hybrid manager
    pub fn new(config: McpConfig, flags: MigrationFlags) -> Self {
        let new = McpManagerV2::new(config.clone());
        
        // Only create old manager if needed
        let old = if !flags.use_actor_deployment || 
                    !flags.use_actor_health || 
                    !flags.use_actor_metrics || 
                    !flags.use_actor_execution {
            Some(super::McpManager::new(config))
        } else {
            None
        };
        
        Self {
            old,
            new,
            flags,
        }
    }
    
    /// Deploy a server using the appropriate implementation
    pub async fn deploy_server(&self, config: crate::mcp_manager::config::ServerConfig) -> Result<String> {
        if self.flags.use_actor_deployment {
            self.new.deploy_server(config).await
        } else if let Some(old) = &self.old {
            // Use old deployment manager
            let deployment_manager = old.deployment_manager();
            let name = config.name.clone();
            deployment_manager.deploy_server(name.clone(), config).await?;
            Ok(name)
        } else {
            // Fallback to new if old doesn't exist
            self.new.deploy_server(config).await
        }
    }
    
    /// Execute a request using the appropriate implementation
    pub async fn execute(
        &self,
        server_id: &str,
        request: serde_json::Value,
    ) -> Result<serde_json::Value> {
        if self.flags.use_actor_execution {
            self.new.execute(server_id, request).await
        } else if let Some(old) = &self.old {
            // Use old registry and server
            let registry = old.registry().read().await;
            let server = registry.get(server_id)
                .ok_or_else(|| crate::mcp_manager::errors::McpError::ServerNotFound(server_id.to_string()))?;
            server.execute(request).await
        } else {
            // Fallback to new if old doesn't exist
            self.new.execute(server_id, request).await
        }
    }
    
    /// Get metrics using the appropriate implementation
    pub async fn get_metrics(&self) -> Result<serde_json::Value> {
        if self.flags.use_actor_metrics {
            let metrics = self.new.get_metrics(None).await?;
            Ok(serde_json::to_value(metrics)?)
        } else if let Some(old) = &self.old {
            // Use old metrics collector
            let metrics = old.metrics_collector().get_all_metrics().await;
            Ok(serde_json::to_value(metrics)?)
        } else {
            // Fallback to new if old doesn't exist
            let metrics = self.new.get_metrics(None).await?;
            Ok(serde_json::to_value(metrics)?)
        }
    }
}

/// Migration plan documentation
pub mod migration_plan {
    //! # Migration Plan from Shared State to Actor Model
    //! 
    //! ## Phase 1: Parallel Implementation (COMPLETE)
    //! - ✅ Create actor-based McpRuntime
    //! - ✅ Create McpManagerV2 with same interface
    //! - ✅ Create adapters for compatibility
    //! 
    //! ## Phase 2: Gradual Migration (IN PROGRESS)
    //! - Deploy one component at a time using feature flags
    //! - Start with deployment (lowest risk)
    //! - Monitor performance and stability
    //! - Roll back if issues arise
    //! 
    //! ## Phase 3: Performance Testing
    //! - Benchmark old vs new implementation
    //! - Verify no lock contention
    //! - Measure latency improvements
    //! - Test under high load
    //! 
    //! ## Phase 4: Complete Migration
    //! - Remove old implementation
    //! - Clean up compatibility layers
    //! - Update all documentation
    //! - Release as v2.0
    //! 
    //! ## Rollback Strategy
    //! - Feature flags allow instant rollback
    //! - Both implementations coexist
    //! - No data migration required
    //! - Zero downtime switching
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_adapter_compatibility() {
        let config = McpConfig::default();
        let adapter = McpManagerAdapter::new(config);
        
        // Test compatibility methods
        assert!(adapter.start().await.is_ok());
        assert!(adapter.stop().await.is_ok());
        
        // Can access v2 directly
        let servers = adapter.v2().list_servers().await.unwrap();
        assert!(servers.is_empty() || !servers.is_empty());
    }
    
    #[tokio::test]
    async fn test_hybrid_manager() {
        let config = McpConfig::default();
        let flags = MigrationFlags {
            use_actor_deployment: true,
            use_actor_health: false,
            use_actor_metrics: false,
            use_actor_execution: false,
        };
        
        let hybrid = HybridMcpManager::new(config, flags);
        
        // Test that it works (would need actual servers to fully test)
        let metrics = hybrid.get_metrics().await;
        assert!(metrics.is_ok());
    }
}