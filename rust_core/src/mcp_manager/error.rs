use std::fmt;
use thiserror::Error;

/// MCP Manager error types
#[derive(Error, Debug, Clone)]
pub enum MCPError {
    #[error("Connection error: {0}")]
    Connection(String),
    
    #[error("Protocol error: {0}")]
    Protocol(String),
    
    #[error("Server not found: {0}")]
    ServerNotFound(String),
    
    #[error("Configuration error: {0}")]
    Configuration(String),
    
    #[error("Load balancing error: {0}")]
    LoadBalancing(String),
    
    #[error("Health check failed: {0}")]
    HealthCheck(String),
    
    #[error("Timeout error: operation timed out after {0}ms")]
    Timeout(u64),
    
    #[error("Capacity error: {0}")]
    Capacity(String),
    
    #[error("Authentication error: {0}")]
    Authentication(String),
    
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type for MCP operations
pub type MCPResult<T> = Result<T, MCPError>;

impl From<std::io::Error> for MCPError {
    fn from(err: std::io::Error) -> Self {
        MCPError::Connection(err.to_string())
    }
}

impl From<tokio::time::error::Elapsed> for MCPError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        MCPError::Timeout(5000) // Default timeout
    }
}