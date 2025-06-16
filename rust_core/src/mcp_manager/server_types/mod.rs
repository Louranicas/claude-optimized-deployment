//! Server type implementations

pub mod infrastructure;
pub mod monitoring;
pub mod security;

use crate::mcp_manager::{
    config::ServerType,
    errors::Result,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Base trait for server-specific functionality
#[async_trait]
pub trait ServerTypeHandler: Send + Sync {
    /// Get server type
    fn server_type(&self) -> ServerType;
    
    /// Validate server configuration
    async fn validate_config(&self, config: &serde_json::Value) -> Result<()>;
    
    /// Transform request before sending
    async fn transform_request(&self, request: serde_json::Value) -> Result<serde_json::Value>;
    
    /// Transform response after receiving
    async fn transform_response(&self, response: serde_json::Value) -> Result<serde_json::Value>;
    
    /// Get server-specific metrics
    async fn collect_metrics(&self) -> Result<ServerMetrics>;
}

/// Server-specific metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerMetrics {
    /// Custom metrics by name
    pub custom: std::collections::HashMap<String, f64>,
}

/// Create a server type handler based on type
pub fn create_handler(server_type: &ServerType) -> Box<dyn ServerTypeHandler> {
    match server_type {
        // Monitoring servers
        ServerType::Prometheus => Box::new(monitoring::MonitoringHandler::new()),
        // Infrastructure servers
        ServerType::S3 | ServerType::CloudStorage | 
        ServerType::Slack | ServerType::Commander => {
            Box::new(infrastructure::InfrastructureHandler::new())
        }
        // Security servers
        ServerType::SAST | ServerType::SecurityScanner | ServerType::SupplyChain => {
            Box::new(security::SecurityHandler::new())
        }
        // Default handler for all other types
        _ => Box::new(DefaultHandler::new()),
    }
}

/// Default handler for generic server types
struct DefaultHandler;

impl DefaultHandler {
    fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ServerTypeHandler for DefaultHandler {
    fn server_type(&self) -> ServerType {
        // Return Docker as the default/generic server type
        ServerType::Docker
    }
    
    async fn validate_config(&self, _config: &serde_json::Value) -> Result<()> {
        Ok(())
    }
    
    async fn transform_request(&self, request: serde_json::Value) -> Result<serde_json::Value> {
        Ok(request)
    }
    
    async fn transform_response(&self, response: serde_json::Value) -> Result<serde_json::Value> {
        Ok(response)
    }
    
    async fn collect_metrics(&self) -> Result<ServerMetrics> {
        Ok(ServerMetrics {
            custom: std::collections::HashMap::new(),
        })
    }
}