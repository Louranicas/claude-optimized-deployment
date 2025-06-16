//! Error types for the MCP Learning Core

use thiserror::Error;

/// Result type alias for MCP Learning Core operations
pub type Result<T> = std::result::Result<T, CoreError>;

/// Core error types for the MCP Learning System
#[derive(Error, Debug)]
pub enum CoreError {
    /// Protocol handling error
    #[error("Protocol error: {0}")]
    Protocol(String),
    
    /// State management error
    #[error("State error: {0}")]
    State(String),
    
    /// Message routing error
    #[error("Routing error: {0}")]
    Routing(String),
    
    /// Shared memory error
    #[error("Shared memory error: {0}")]
    SharedMemory(String),
    
    /// Performance monitoring error
    #[error("Monitoring error: {0}")]
    Monitoring(String),
    
    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),
    
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    /// Timeout error
    #[error("Operation timed out: {0}")]
    Timeout(String),
    
    /// Resource exhausted error
    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),
    
    /// Generic error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl CoreError {
    /// Create a new protocol error
    pub fn protocol(msg: impl Into<String>) -> Self {
        Self::Protocol(msg.into())
    }
    
    /// Create a new state error
    pub fn state(msg: impl Into<String>) -> Self {
        Self::State(msg.into())
    }
    
    /// Create a new routing error
    pub fn routing(msg: impl Into<String>) -> Self {
        Self::Routing(msg.into())
    }
    
    /// Create a new shared memory error
    pub fn shared_memory(msg: impl Into<String>) -> Self {
        Self::SharedMemory(msg.into())
    }
    
    /// Create a new monitoring error
    pub fn monitoring(msg: impl Into<String>) -> Self {
        Self::Monitoring(msg.into())
    }
    
    /// Create a new configuration error
    pub fn configuration(msg: impl Into<String>) -> Self {
        Self::Configuration(msg.into())
    }
    
    /// Create a new serialization error
    pub fn serialization(msg: impl Into<String>) -> Self {
        Self::Serialization(msg.into())
    }
    
    /// Create a new timeout error
    pub fn timeout(msg: impl Into<String>) -> Self {
        Self::Timeout(msg.into())
    }
    
    /// Create a new resource exhausted error
    pub fn resource_exhausted(msg: impl Into<String>) -> Self {
        Self::ResourceExhausted(msg.into())
    }
    
    /// Create a new internal error
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}