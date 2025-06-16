//! MCP Learning System Core Library
//! 
//! High-performance Rust implementation for MCP protocol handling,
//! state management, and inter-process communication.

#![warn(missing_docs)]
// Allow unsafe code for FFI and shared memory operations
#![allow(unsafe_code)]

pub mod error;
pub mod state;
// pub mod protocol;
// pub mod router;
// pub mod monitor;
// pub mod shared_memory;
// pub mod ffi;

use std::sync::Arc;

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
    state_manager: Arc<state::StateManager>,
    // protocol_handler: Arc<protocol::ProtocolHandler>,
    // message_router: Arc<router::MessageRouter>,
    // performance_monitor: Arc<monitor::PerformanceMonitor>,
    // shared_memory: Arc<shared_memory::SharedMemoryRegion>,
}

impl MCPLearningCore {
    /// Create a new MCP Learning Core instance
    pub async fn new(config: CoreConfig) -> Result<Self> {
        tracing::info!("Initializing MCP Learning Core");
        
        // Initialize state manager
        let state_manager = Arc::new(
            state::StateManager::new(config.state_cache_size)?
        );
        
        Ok(Self {
            config,
            state_manager,
        })
    }
    
    /// Start the core system
    pub async fn start(&self) -> Result<()> {
        tracing::info!("Starting MCP Learning Core");
        
        // Start state manager
        self.state_manager.start().await?;
        
        tracing::info!("MCP Learning Core started successfully");
        Ok(())
    }
    
    /// Shutdown the core system gracefully
    pub async fn shutdown(&self) -> Result<()> {
        tracing::info!("Shutting down MCP Learning Core");
        
        // Shutdown state manager
        self.state_manager.shutdown().await?;
        
        tracing::info!("MCP Learning Core shutdown complete");
        Ok(())
    }
    
    /// Get a reference to the state manager
    pub fn state_manager(&self) -> &Arc<state::StateManager> {
        &self.state_manager
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