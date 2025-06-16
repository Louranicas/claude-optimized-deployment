//! Infrastructure server type implementation

use super::{ServerTypeHandler, ServerMetrics};
use crate::mcp_manager::{
    config::ServerType,
    errors::{McpError, Result},
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Infrastructure server handler
pub struct InfrastructureHandler {
    /// Supported operations
    supported_ops: Vec<String>,
}

impl InfrastructureHandler {
    pub fn new() -> Self {
        Self {
            supported_ops: vec![
                "deploy".to_string(),
                "scale".to_string(),
                "restart".to_string(),
                "status".to_string(),
                "logs".to_string(),
                "metrics".to_string(),
                "health".to_string(),
            ],
        }
    }
}

#[async_trait]
impl ServerTypeHandler for InfrastructureHandler {
    fn server_type(&self) -> ServerType {
        // Return a representative infrastructure server type
        ServerType::S3
    }
    
    async fn validate_config(&self, config: &serde_json::Value) -> Result<()> {
        // Validate infrastructure-specific configuration
        if !config.is_object() {
            return Err(McpError::ConfigError("Config must be an object".to_string()));
        }
        
        let obj = config.as_object().unwrap();
        
        // Check required fields
        if !obj.contains_key("provider") {
            return Err(McpError::ConfigError("Missing 'provider' field".to_string()));
        }
        
        Ok(())
    }
    
    async fn transform_request(&self, mut request: serde_json::Value) -> Result<serde_json::Value> {
        // Add infrastructure-specific fields
        if let Some(obj) = request.as_object_mut() {
            // Add timestamp
            obj.insert(
                "timestamp".to_string(),
                serde_json::Value::String(chrono::Utc::now().to_rfc3339()),
            );
            
            // Add request ID
            obj.insert(
                "request_id".to_string(),
                serde_json::Value::String(uuid::Uuid::new_v4().to_string()),
            );
            
            // Validate operation
            if let Some(op) = obj.get("operation").and_then(|v| v.as_str()) {
                if !self.supported_ops.contains(&op.to_string()) {
                    return Err(McpError::Other(format!("Unsupported operation: {}", op)));
                }
            }
        }
        
        Ok(request)
    }
    
    async fn transform_response(&self, mut response: serde_json::Value) -> Result<serde_json::Value> {
        // Process infrastructure-specific response
        if let Some(obj) = response.as_object_mut() {
            // Extract and process status
            if let Some(status) = obj.get("status").and_then(|v| v.as_str()) {
                // Map provider-specific status to standard status
                let standard_status = match status {
                    "running" | "active" | "healthy" => "ok",
                    "stopped" | "inactive" => "stopped",
                    "error" | "failed" => "error",
                    _ => "unknown",
                };
                
                obj.insert(
                    "standard_status".to_string(),
                    serde_json::Value::String(standard_status.to_string()),
                );
            }
        }
        
        Ok(response)
    }
    
    async fn collect_metrics(&self) -> Result<ServerMetrics> {
        let mut metrics = HashMap::new();
        
        // Infrastructure-specific metrics
        metrics.insert("deployment_count".to_string(), 0.0);
        metrics.insert("resource_utilization".to_string(), 0.0);
        metrics.insert("cost_estimate".to_string(), 0.0);
        
        Ok(ServerMetrics { custom: metrics })
    }
}

/// Infrastructure request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureRequest {
    /// Operation to perform
    pub operation: InfrastructureOperation,
    /// Target resource
    pub resource: String,
    /// Additional parameters
    pub params: HashMap<String, serde_json::Value>,
}

/// Infrastructure operations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InfrastructureOperation {
    Deploy,
    Scale,
    Restart,
    Status,
    Logs,
    Metrics,
    Health,
}

/// Infrastructure response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureResponse {
    /// Success status
    pub success: bool,
    /// Operation result
    pub result: Option<serde_json::Value>,
    /// Error message if failed
    pub error: Option<String>,
    /// Resource status
    pub status: Option<ResourceStatus>,
}

/// Resource status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceStatus {
    /// Resource ID
    pub id: String,
    /// Current state
    pub state: String,
    /// Health status
    pub health: String,
    /// Resource metrics
    pub metrics: HashMap<String, f64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_infrastructure_handler() {
        let handler = InfrastructureHandler::new();
        
        // Test config validation
        let valid_config = serde_json::json!({
            "provider": "aws"
        });
        assert!(handler.validate_config(&valid_config).await.is_ok());
        
        let invalid_config = serde_json::json!("not an object");
        assert!(handler.validate_config(&invalid_config).await.is_err());
    }

    #[tokio::test]
    async fn test_request_transformation() {
        let handler = InfrastructureHandler::new();
        
        let request = serde_json::json!({
            "operation": "deploy",
            "resource": "app-server"
        });
        
        let transformed = handler.transform_request(request).await.unwrap();
        let obj = transformed.as_object().unwrap();
        
        assert!(obj.contains_key("timestamp"));
        assert!(obj.contains_key("request_id"));
    }

    #[tokio::test]
    async fn test_response_transformation() {
        let handler = InfrastructureHandler::new();
        
        let response = serde_json::json!({
            "status": "running",
            "id": "server-123"
        });
        
        let transformed = handler.transform_response(response).await.unwrap();
        let obj = transformed.as_object().unwrap();
        
        assert_eq!(obj.get("standard_status").unwrap().as_str().unwrap(), "ok");
    }
}