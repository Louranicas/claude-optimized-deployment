/*!
 * Error Types and Handling for Rust MCP Server
 */

use thiserror::Error;

/// Server result type alias
pub type ServerResult<T> = Result<T, ServerError>;

/// Main server error types
#[derive(Error, Debug)]
pub enum ServerError {
    #[error("Tool not found: {0}")]
    ToolNotFound(String),
    
    #[error("Resource not found: {0}")]
    ResourceNotFound(String),
    
    #[error("Invalid arguments: {0}")]
    InvalidArguments(String),
    
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),
    
    #[error("Internal server error: {0}")]
    InternalError(String),
    
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("Authorization failed: {0}")]
    AuthorizationFailed(String),
    
    #[error("Timeout error: {0}")]
    Timeout(String),
}

impl ServerError {
    /// Check if the error is retryable
    pub fn is_retryable(&self) -> bool {
        match self {
            ServerError::NetworkError(_) => true,
            ServerError::HttpError(_) => true,
            ServerError::ServiceUnavailable(_) => true,
            ServerError::Timeout(_) => true,
            ServerError::InternalError(_) => true,
            _ => false,
        }
    }
    
    /// Get error code for JSON-RPC responses
    pub fn error_code(&self) -> i32 {
        match self {
            ServerError::ToolNotFound(_) => -32601, // Method not found
            ServerError::ResourceNotFound(_) => -32601, // Method not found
            ServerError::InvalidArguments(_) => -32602, // Invalid params
            ServerError::ConfigurationError(_) => -32603, // Internal error
            ServerError::NetworkError(_) => -32603, // Internal error
            ServerError::SerializationError(_) => -32700, // Parse error
            ServerError::IoError(_) => -32603, // Internal error
            ServerError::HttpError(_) => -32603, // Internal error
            ServerError::InternalError(_) => -32603, // Internal error
            ServerError::ServiceUnavailable(_) => -32603, // Internal error
            ServerError::RateLimitExceeded => -32603, // Internal error
            ServerError::AuthenticationFailed(_) => -32603, // Internal error
            ServerError::AuthorizationFailed(_) => -32603, // Internal error
            ServerError::Timeout(_) => -32603, // Internal error
        }
    }
    
    /// Convert to JSON-RPC error object
    pub fn to_json_rpc_error(&self) -> serde_json::Value {
        serde_json::json!({
            "code": self.error_code(),
            "message": self.to_string(),
            "data": {
                "retryable": self.is_retryable(),
                "error_type": self.error_type()
            }
        })
    }
    
    /// Get error type as string
    pub fn error_type(&self) -> &'static str {
        match self {
            ServerError::ToolNotFound(_) => "tool_not_found",
            ServerError::ResourceNotFound(_) => "resource_not_found",
            ServerError::InvalidArguments(_) => "invalid_arguments",
            ServerError::ConfigurationError(_) => "configuration_error",
            ServerError::NetworkError(_) => "network_error",
            ServerError::SerializationError(_) => "serialization_error",
            ServerError::IoError(_) => "io_error",
            ServerError::HttpError(_) => "http_error",
            ServerError::InternalError(_) => "internal_error",
            ServerError::ServiceUnavailable(_) => "service_unavailable",
            ServerError::RateLimitExceeded => "rate_limit_exceeded",
            ServerError::AuthenticationFailed(_) => "authentication_failed",
            ServerError::AuthorizationFailed(_) => "authorization_failed",
            ServerError::Timeout(_) => "timeout",
        }
    }
}