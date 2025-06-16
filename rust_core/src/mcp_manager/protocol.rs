use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;
use crate::mcp_manager::error::{MCPError, MCPResult};

/// MCP Protocol types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MCPProtocol {
    Http,
    WebSocket,
    Grpc,
    Custom(String),
}

/// MCP Request structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MCPRequest {
    pub id: String,
    pub method: String,
    pub params: serde_json::Value,
}

impl MCPRequest {
    /// Create a new MCP request with auto-generated ID
    pub fn new(method: impl Into<String>, params: serde_json::Value) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            method: method.into(),
            params,
        }
    }
    
    /// Create a new MCP request with specific ID
    pub fn with_id(id: String, method: String, params: serde_json::Value) -> Self {
        Self { id, method, params }
    }
}

/// MCP Response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MCPResponse {
    pub id: String,
    pub result: Option<serde_json::Value>,
    pub error: Option<MCPResponseError>,
}

/// MCP Response Error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MCPResponseError {
    pub code: i32,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

impl MCPResponse {
    /// Create a successful response
    pub fn success(result: impl Into<serde_json::Value>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            result: Some(result.into()),
            error: None,
        }
    }
    
    /// Create an error response
    pub fn error(code: i32, message: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            result: None,
            error: Some(MCPResponseError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

/// MCP Connection trait
#[async_trait]
pub trait MCPConnection: Send + Sync {
    /// Connect to the server
    async fn connect(&self, timeout: Duration) -> MCPResult<()>;
    
    /// Disconnect from the server
    async fn disconnect(&self) -> MCPResult<()>;
    
    /// Send a request and receive response
    async fn send_request(&self, request: MCPRequest) -> MCPResult<MCPResponse>;
    
    /// Check if connection is active
    fn is_connected(&self) -> bool;
}

/// HTTP-based MCP connection
pub struct HttpMCPConnection {
    server_url: String,
    client: reqwest::Client,
    connected: Arc<tokio::sync::RwLock<bool>>,
}

impl HttpMCPConnection {
    pub fn new(server_url: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Unexpected None/Error");
            
        Self {
            server_url,
            client,
            connected: Arc::new(tokio::sync::RwLock::new(false)),
        }
    }
}

#[async_trait]
impl MCPConnection for HttpMCPConnection {
    async fn connect(&self, timeout: Duration) -> MCPResult<()> {
        // For HTTP, connection is established per-request
        *self.connected.write().await = true;
        Ok(())
    }
    
    async fn disconnect(&self) -> MCPResult<()> {
        *self.connected.write().await = false;
        Ok(())
    }
    
    async fn send_request(&self, request: MCPRequest) -> MCPResult<MCPResponse> {
        if !self.is_connected() {
            return Err(MCPError::Connection("Not connected".to_string()));
        }
        
        let response = self.client
            .post(&self.server_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| MCPError::Connection(e.to_string()))?;
            
        if !response.status().is_success() {
            return Err(MCPError::Protocol(format!(
                "HTTP {} {}",
                response.status().as_u16(),
                response.status().canonical_reason().unwrap_or("Unknown")
            )));
        }
        
        let mcp_response = response
            .json::<MCPResponse>()
            .await
            .map_err(|e| MCPError::Protocol(format!("Invalid response format: {}", e)))?;
            
        Ok(mcp_response)
    }
    
    fn is_connected(&self) -> bool {
        futures::executor::block_on(async { *self.connected.read().await })
    }
}

/// WebSocket-based MCP connection
pub struct WebSocketMCPConnection {
    server_url: String,
    // WebSocket implementation would go here
    connected: Arc<tokio::sync::RwLock<bool>>,
}

impl WebSocketMCPConnection {
    pub fn new(server_url: String) -> Self {
        Self {
            server_url,
            connected: Arc::new(tokio::sync::RwLock::new(false)),
        }
    }
}

#[async_trait]
impl MCPConnection for WebSocketMCPConnection {
    async fn connect(&self, _timeout: Duration) -> MCPResult<()> {
        // WebSocket connection implementation
        *self.connected.write().await = true;
        Ok(())
    }
    
    async fn disconnect(&self) -> MCPResult<()> {
        *self.connected.write().await = false;
        Ok(())
    }
    
    async fn send_request(&self, _request: MCPRequest) -> MCPResult<MCPResponse> {
        if !self.is_connected() {
            return Err(MCPError::Connection("Not connected".to_string()));
        }
        
        // WebSocket request/response implementation
        Ok(MCPResponse::success("WebSocket response"))
    }
    
    fn is_connected(&self) -> bool {
        futures::executor::block_on(async { *self.connected.read().await })
    }
}