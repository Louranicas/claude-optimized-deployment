//! MCP Learning System Core Library
//! 
//! High-performance Rust implementation for MCP protocol handling,
//! state management, and inter-process communication.

#![warn(missing_docs)]
#![deny(unsafe_code)]

pub mod protocol;
pub mod state;
pub mod router;
pub mod monitor;
pub mod shared_memory;
pub mod error;

use std::sync::Arc;
use dashmap::DashMap;
use tokio::sync::RwLock;
use tracing::{info, instrument};

pub use error::{CoreError, Result};

/// Core configuration for the MCP Learning System
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CoreConfig {
    /// Maximum number of concurrent connections
    pub max_connections: usize,
    /// Size of the message buffer in bytes
    pub message_buffer_size: usize,
    /// Size of the state cache in bytes
    pub state_cache_size: usize,
    /// Shared memory region size in bytes
    pub shared_memory_size: usize,
    /// Ring buffer size in bytes
    pub ring_buffer_size: usize,
    /// Maximum message size in bytes
    pub max_message_size: usize,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            max_connections: 10_000,
            message_buffer_size: 1_048_576,     // 1MB
            state_cache_size: 2_147_483_648,    // 2GB
            shared_memory_size: 4_294_967_296,  // 4GB
            ring_buffer_size: 1_073_741_824,    // 1GB
            max_message_size: 1_048_576,        // 1MB
        }
    }
}

/// Main entry point for the MCP Learning Core
pub struct MCPLearningCore {
    config: CoreConfig,
    protocol_handler: Arc<protocol::ProtocolHandler>,
    state_manager: Arc<state::StateManager>,
    message_router: Arc<router::MessageRouter>,
    performance_monitor: Arc<monitor::PerformanceMonitor>,
    shared_memory: Arc<shared_memory::SharedMemoryRegion>,
}

impl MCPLearningCore {
    /// Create a new MCP Learning Core instance
    #[instrument(skip_all)]
    pub async fn new(config: CoreConfig) -> Result<Self> {
        info!("Initializing MCP Learning Core");
        
        // Initialize shared memory region
        let shared_memory = Arc::new(
            shared_memory::SharedMemoryRegion::new(&config)?
        );
        
        // Initialize components
        let protocol_handler = Arc::new(
            protocol::ProtocolHandler::new(config.max_connections)?
        );
        
        let state_manager = Arc::new(
            state::StateManager::new(config.state_cache_size)?
        );
        
        let message_router = Arc::new(
            router::MessageRouter::new(
                config.message_buffer_size,
                shared_memory.clone()
            )?
        );
        
        let performance_monitor = Arc::new(
            monitor::PerformanceMonitor::new()?
        );
        
        Ok(Self {
            config,
            protocol_handler,
            state_manager,
            message_router,
            performance_monitor,
            shared_memory,
        })
    }
    
    /// Start the core system
    #[instrument(skip_all)]
    pub async fn start(&self) -> Result<()> {
        info!("Starting MCP Learning Core");
        
        // Start all components
        tokio::try_join!(
            self.protocol_handler.start(),
            self.state_manager.start(),
            self.message_router.start(),
            self.performance_monitor.start(),
        )?;
        
        info!("MCP Learning Core started successfully");
        Ok(())
    }
    
    /// Shutdown the core system gracefully
    #[instrument(skip_all)]
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down MCP Learning Core");
        
        // Shutdown all components
        tokio::try_join!(
            self.protocol_handler.shutdown(),
            self.state_manager.shutdown(),
            self.message_router.shutdown(),
            self.performance_monitor.shutdown(),
        )?;
        
        info!("MCP Learning Core shutdown complete");
        Ok(())
    }
    
    /// Get a reference to the protocol handler
    pub fn protocol_handler(&self) -> &Arc<protocol::ProtocolHandler> {
        &self.protocol_handler
    }
    
    /// Get a reference to the state manager
    pub fn state_manager(&self) -> &Arc<state::StateManager> {
        &self.state_manager
    }
    
    /// Get a reference to the message router
    pub fn message_router(&self) -> &Arc<router::MessageRouter> {
        &self.message_router
    }
    
    /// Get a reference to the performance monitor
    pub fn performance_monitor(&self) -> &Arc<monitor::PerformanceMonitor> {
        &self.performance_monitor
    }
    
    /// Get a reference to the shared memory region
    pub fn shared_memory(&self) -> &Arc<shared_memory::SharedMemoryRegion> {
        &self.shared_memory
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_core_initialization() {
        let config = CoreConfig::default();
        let core = MCPLearningCore::new(config).await;
        assert!(core.is_ok());
    }
}