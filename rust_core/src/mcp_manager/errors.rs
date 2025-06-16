//! Error types for the MCP Manager module

use std::fmt;
use std::error::Error;

/// Result type alias for MCP operations
pub type Result<T> = std::result::Result<T, McpError>;

/// Main error type for MCP operations
#[derive(Debug)]
pub enum McpError {
    /// Server not found in registry
    ServerNotFound(String),
    
    /// Resource not found
    NotFound(String),
    
    /// Connection error
    ConnectionError(String),
    
    /// Configuration error
    ConfigError(String),
    
    /// General configuration error
    Configuration(String),
    
    /// Deployment error
    DeploymentError(String),
    
    /// Health check failed
    HealthCheckFailed(String),
    
    /// Circuit breaker is open
    CircuitBreakerOpen(String),
    
    /// Resource exhausted
    ResourceExhausted(String),
    
    /// Timeout error
    Timeout(String),
    
    /// Authentication error
    AuthenticationError(String),
    
    /// Authorization error
    AuthorizationError(String),
    
    /// Serialization/Deserialization error
    SerializationError(String),
    
    /// IO error
    IoError(std::io::Error),
    
    /// Generic error with message
    Other(String),
    
    /// Runtime has been shutdown
    RuntimeShutdown,
    
    /// Already exists error
    AlreadyExists(String),
    
    /// Internal error
    InternalError(String),
}

impl fmt::Display for McpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            McpError::ServerNotFound(id) => write!(f, "Server not found: {}", id),
            McpError::NotFound(msg) => write!(f, "Not found: {}", msg),
            McpError::ConnectionError(msg) => write!(f, "Connection error: {}", msg),
            McpError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            McpError::Configuration(msg) => write!(f, "Configuration error: {}", msg),
            McpError::DeploymentError(msg) => write!(f, "Deployment error: {}", msg),
            McpError::HealthCheckFailed(msg) => write!(f, "Health check failed: {}", msg),
            McpError::CircuitBreakerOpen(server) => write!(f, "Circuit breaker open for server: {}", server),
            McpError::ResourceExhausted(resource) => write!(f, "Resource exhausted: {}", resource),
            McpError::Timeout(operation) => write!(f, "Operation timed out: {}", operation),
            McpError::AuthenticationError(msg) => write!(f, "Authentication error: {}", msg),
            McpError::AuthorizationError(msg) => write!(f, "Authorization error: {}", msg),
            McpError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            McpError::IoError(err) => write!(f, "IO error: {}", err),
            McpError::Other(msg) => write!(f, "Error: {}", msg),
            McpError::RuntimeShutdown => write!(f, "Runtime has been shutdown"),
            McpError::AlreadyExists(msg) => write!(f, "Already exists: {}", msg),
            McpError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl Error for McpError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            McpError::IoError(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for McpError {
    fn from(err: std::io::Error) -> Self {
        McpError::IoError(err)
    }
}

impl From<serde_json::Error> for McpError {
    fn from(err: serde_json::Error) -> Self {
        McpError::SerializationError(err.to_string())
    }
}

impl From<tokio::time::error::Elapsed> for McpError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        McpError::Timeout("Operation timed out".to_string())
    }
}

/// Error recovery strategies
#[derive(Debug, Clone, Copy)]
pub enum RecoveryStrategy {
    /// Retry the operation
    Retry,
    /// Fail over to another server
    Failover,
    /// Circuit break the server
    CircuitBreak,
    /// Propagate the error
    Propagate,
}

/// Trait for determining recovery strategy based on error type
pub trait ErrorRecovery {
    fn recovery_strategy(&self) -> RecoveryStrategy;
}

impl ErrorRecovery for McpError {
    fn recovery_strategy(&self) -> RecoveryStrategy {
        match self {
            McpError::ConnectionError(_) => RecoveryStrategy::Retry,
            McpError::Timeout(_) => RecoveryStrategy::Retry,
            McpError::ServerNotFound(_) => RecoveryStrategy::Failover,
            McpError::HealthCheckFailed(_) => RecoveryStrategy::CircuitBreak,
            McpError::CircuitBreakerOpen(_) => RecoveryStrategy::Failover,
            McpError::ResourceExhausted(_) => RecoveryStrategy::CircuitBreak,
            McpError::AuthenticationError(_) => RecoveryStrategy::Propagate,
            McpError::AuthorizationError(_) => RecoveryStrategy::Propagate,
            _ => RecoveryStrategy::Propagate,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = McpError::ServerNotFound("test-server".to_string());
        assert_eq!(err.to_string(), "Server not found: test-server");
    }

    #[test]
    fn test_error_recovery_strategy() {
        let err = McpError::ConnectionError("connection failed".to_string());
        assert!(matches!(err.recovery_strategy(), RecoveryStrategy::Retry));
        
        let err = McpError::AuthenticationError("invalid token".to_string());
        assert!(matches!(err.recovery_strategy(), RecoveryStrategy::Propagate));
    }
}