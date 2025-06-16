use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use anyhow::Result;
use tokio::sync::mpsc;
use bytes::Bytes;

pub mod http;
pub mod websocket;
pub mod grpc;

/// MCP protocol version
pub const MCP_VERSION: &str = "1.0.0";

/// Message types in the MCP protocol
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MessageType {
    Request {
        id: String,
        method: String,
        params: serde_json::Value,
    },
    Response {
        id: String,
        result: Option<serde_json::Value>,
        error: Option<ErrorResponse>,
    },
    Notification {
        method: String,
        params: serde_json::Value,
    },
    Error {
        code: i32,
        message: String,
        data: Option<serde_json::Value>,
    },
}

/// Error response structure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ErrorResponse {
    pub code: i32,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

/// Protocol capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolCapabilities {
    pub compression: bool,
    pub streaming: bool,
    pub multiplexing: bool,
    pub max_message_size: usize,
    pub timeout: Duration,
    pub keep_alive: bool,
    pub retry_policy: RetryPolicy,
}

/// Retry policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub exponential_base: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            exponential_base: 2.0,
        }
    }
}

/// Connection state
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    Connecting,
    Connected,
    Reconnecting,
    Disconnected,
    Failed(String),
}

/// Protocol-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case")]
pub enum ProtocolConfig {
    Http {
        endpoint: String,
        headers: std::collections::HashMap<String, String>,
        timeout: Duration,
        max_connections: usize,
        keep_alive: bool,
    },
    WebSocket {
        url: String,
        subprotocols: Vec<String>,
        ping_interval: Duration,
        pong_timeout: Duration,
        max_frame_size: usize,
    },
    Grpc {
        endpoint: String,
        tls: bool,
        ca_cert: Option<String>,
        client_cert: Option<String>,
        client_key: Option<String>,
        timeout: Duration,
        max_message_size: usize,
    },
}

/// Core MCP protocol trait
#[async_trait]
pub trait McpProtocol: Send + Sync {
    /// Initialize the protocol connection
    async fn connect(&mut self) -> Result<()>;
    
    /// Send a message through the protocol
    async fn send(&mut self, message: MessageType) -> Result<()>;
    
    /// Receive a message from the protocol
    async fn receive(&mut self) -> Result<Option<MessageType>>;
    
    /// Send a request and wait for response
    async fn request(&mut self, method: String, params: serde_json::Value) -> Result<serde_json::Value>;
    
    /// Send a notification (no response expected)
    async fn notify(&mut self, method: String, params: serde_json::Value) -> Result<()>;
    
    /// Check if the connection is alive
    async fn is_connected(&self) -> bool;
    
    /// Get current connection state
    fn connection_state(&self) -> ConnectionState;
    
    /// Close the connection gracefully
    async fn disconnect(&mut self) -> Result<()>;
    
    /// Get protocol capabilities
    fn capabilities(&self) -> &ProtocolCapabilities;
    
    /// Handle protocol-specific keep-alive
    async fn keep_alive(&mut self) -> Result<()>;
    
    /// Get protocol metrics
    fn metrics(&self) -> ProtocolMetrics;
}

/// Protocol metrics for monitoring
#[derive(Debug, Clone, Default)]
pub struct ProtocolMetrics {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub errors: u64,
    pub reconnects: u64,
    pub average_latency_ms: f64,
    pub last_activity: Option<std::time::Instant>,
}

/// Stream handler for bidirectional communication
#[async_trait]
pub trait StreamHandler: Send + Sync {
    /// Handle incoming stream of messages
    async fn handle_stream(
        &self,
        incoming: mpsc::Receiver<MessageType>,
        outgoing: mpsc::Sender<MessageType>,
    ) -> Result<()>;
}

/// Message framing for stream protocols
pub trait MessageFramer: Send + Sync {
    /// Frame a message for transmission
    fn frame(&self, message: &MessageType) -> Result<Bytes>;
    
    /// Extract messages from a byte stream
    fn unframe(&mut self, data: &mut Bytes) -> Result<Vec<MessageType>>;
}

/// Compression handler
#[async_trait]
pub trait CompressionHandler: Send + Sync {
    /// Compress data
    async fn compress(&self, data: Bytes) -> Result<Bytes>;
    
    /// Decompress data
    async fn decompress(&self, data: Bytes) -> Result<Bytes>;
}

/// Protocol negotiation
#[async_trait]
pub trait ProtocolNegotiator: Send + Sync {
    /// Negotiate protocol version and capabilities
    async fn negotiate(&mut self, offered: &ProtocolCapabilities) -> Result<ProtocolCapabilities>;
}

/// Connection pool trait for reusable connections
#[async_trait]
pub trait ConnectionPool: Send + Sync {
    type Connection: McpProtocol;
    
    /// Get a connection from the pool
    async fn get(&self) -> Result<Self::Connection>;
    
    /// Return a connection to the pool
    async fn put(&self, conn: Self::Connection) -> Result<()>;
    
    /// Check pool health
    async fn health_check(&self) -> Result<()>;
    
    /// Get pool statistics
    fn stats(&self) -> PoolStats;
}

/// Connection pool statistics
#[derive(Debug, Clone, Default)]
pub struct PoolStats {
    pub total_connections: usize,
    pub active_connections: usize,
    pub idle_connections: usize,
    pub wait_time_ms: f64,
    pub timeouts: u64,
}

/// Protocol factory for creating protocol instances
#[async_trait]
pub trait ProtocolFactory: Send + Sync {
    type Protocol: McpProtocol;
    
    /// Create a new protocol instance
    async fn create(&self, config: ProtocolConfig) -> Result<Self::Protocol>;
}

/// Error codes for MCP protocol
pub mod error_codes {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;
    pub const TIMEOUT_ERROR: i32 = -32001;
    pub const CONNECTION_ERROR: i32 = -32002;
    pub const PROTOCOL_ERROR: i32 = -32003;
}

/// Standard MCP methods
pub mod methods {
    pub const INITIALIZE: &str = "initialize";
    pub const SHUTDOWN: &str = "shutdown";
    pub const LIST_TOOLS: &str = "tools/list";
    pub const CALL_TOOL: &str = "tools/call";
    pub const LIST_RESOURCES: &str = "resources/list";
    pub const READ_RESOURCE: &str = "resources/read";
    pub const SUBSCRIBE_RESOURCE: &str = "resources/subscribe";
    pub const UNSUBSCRIBE_RESOURCE: &str = "resources/unsubscribe";
    pub const LIST_PROMPTS: &str = "prompts/list";
    pub const GET_PROMPT: &str = "prompts/get";
    pub const COMPLETE: &str = "completion/complete";
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_message_type_serialization() {
        let request = MessageType::Request {
            id: "123".to_string(),
            method: "test".to_string(),
            params: serde_json::json!({"key": "value"}),
        };
        
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: MessageType = serde_json::from_str(&json).unwrap();
        
        assert_eq!(request, deserialized);
    }
    
    #[test]
    fn test_protocol_capabilities_default() {
        let retry_policy = RetryPolicy::default();
        assert_eq!(retry_policy.max_retries, 3);
        assert_eq!(retry_policy.exponential_base, 2.0);
    }
}