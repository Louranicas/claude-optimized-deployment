//! MCP Manager Module - Main entry point
//! 
//! Provides comprehensive management for MCP (Model Context Protocol) servers
//! with advanced features like circuit breaking, health monitoring, and distributed coordination.

pub mod server;
pub mod registry;
pub mod deployment;
pub mod health;
pub mod circuit_breaker;
pub mod metrics;
pub mod config;
pub mod connection_pool;
pub mod errors;
pub mod python_bindings;
pub mod async_traits;
pub mod launcher;

// Plugin system
pub mod plugin;
pub mod plugins;

// Submodules
pub mod server_types;
pub mod distributed;
pub mod resilience;
pub mod optimization;
pub mod actor;
pub mod manager_v2;
pub mod migration;

#[cfg(test)]
mod actor_tests;

// Re-exports for convenience
pub use server::{McpServer, ServerState};
pub use registry::ServerRegistry;
pub use deployment::DeploymentManager;
pub use health::HealthMonitor;
pub use circuit_breaker::CircuitBreaker;
pub use metrics::MetricsCollector;
pub use config::McpConfig;
pub use connection_pool::ConnectionPool;
pub use errors::{McpError, Result};

use std::sync::Arc;
use tokio::sync::RwLock;

/// Main MCP Manager struct that coordinates all components
pub struct McpManager {
    registry: Arc<RwLock<ServerRegistry>>,
    deployment_manager: Arc<DeploymentManager>,
    health_monitor: Arc<HealthMonitor>,
    metrics_collector: Arc<MetricsCollector>,
    config: Arc<McpConfig>,
}

impl McpManager {
    /// Create a new MCP Manager instance
    pub fn new(config: McpConfig) -> Self {
        let config = Arc::new(config);
        let registry = Arc::new(RwLock::new(ServerRegistry::new()));
        let metrics_collector = Arc::new(MetricsCollector::new());
        let health_monitor = Arc::new(HealthMonitor::new(
            registry.clone(),
            metrics_collector.clone(),
        ));
        let deployment_manager = Arc::new(DeploymentManager::new(
            registry.clone(),
            config.clone(),
        ));

        Self {
            registry,
            deployment_manager,
            health_monitor,
            metrics_collector,
            config,
        }
    }

    /// Start the MCP Manager
    pub async fn start(&self) -> Result<()> {
        // Start health monitoring
        self.health_monitor.start().await?;
        
        // Start metrics collection
        self.metrics_collector.start().await?;
        
        // Initialize deployment manager
        self.deployment_manager.initialize().await?;
        
        Ok(())
    }

    /// Stop the MCP Manager gracefully
    pub async fn stop(&self) -> Result<()> {
        self.health_monitor.stop().await?;
        self.metrics_collector.stop().await?;
        self.deployment_manager.shutdown().await?;
        Ok(())
    }

    /// Get a reference to the server registry
    pub fn registry(&self) -> &Arc<RwLock<ServerRegistry>> {
        &self.registry
    }

    /// Get a reference to the deployment manager
    pub fn deployment_manager(&self) -> &Arc<DeploymentManager> {
        &self.deployment_manager
    }

    /// Get a reference to the health monitor
    pub fn health_monitor(&self) -> &Arc<HealthMonitor> {
        &self.health_monitor
    }

    /// Get a reference to the metrics collector
    pub fn metrics_collector(&self) -> &Arc<MetricsCollector> {
        &self.metrics_collector
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mcp_manager_creation() {
        let config = McpConfig::default();
        let manager = McpManager::new(config);
        assert!(manager.start().await.is_ok());
        assert!(manager.stop().await.is_ok());
    }
}