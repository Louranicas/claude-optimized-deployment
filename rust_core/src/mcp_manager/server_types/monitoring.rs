//! Monitoring server type implementation

use super::{ServerTypeHandler, ServerMetrics};
use crate::mcp_manager::{
    config::ServerType,
    errors::{McpError, Result},
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Monitoring server handler
pub struct MonitoringHandler {
    /// Supported metric types
    supported_metrics: Vec<String>,
}

impl MonitoringHandler {
    pub fn new() -> Self {
        Self {
            supported_metrics: vec![
                "cpu".to_string(),
                "memory".to_string(),
                "disk".to_string(),
                "network".to_string(),
                "latency".to_string(),
                "error_rate".to_string(),
                "throughput".to_string(),
            ],
        }
    }
}

#[async_trait]
impl ServerTypeHandler for MonitoringHandler {
    fn server_type(&self) -> ServerType {
        // Return Prometheus as the representative monitoring server
        ServerType::Prometheus
    }
    
    async fn validate_config(&self, config: &serde_json::Value) -> Result<()> {
        if !config.is_object() {
            return Err(McpError::ConfigError("Config must be an object".to_string()));
        }
        
        let obj = config.as_object().unwrap();
        
        // Check for monitoring-specific fields
        if !obj.contains_key("metrics_endpoint") {
            return Err(McpError::ConfigError("Missing 'metrics_endpoint' field".to_string()));
        }
        
        Ok(())
    }
    
    async fn transform_request(&self, mut request: serde_json::Value) -> Result<serde_json::Value> {
        if let Some(obj) = request.as_object_mut() {
            // Add monitoring-specific headers
            let mut headers = obj.get("headers")
                .and_then(|v| v.as_object())
                .cloned()
                .unwrap_or_default();
            
            headers.insert(
                "X-Monitoring-Client".to_string(),
                serde_json::Value::String("mcp-manager".to_string()),
            );
            
            obj.insert("headers".to_string(), serde_json::json!(headers));
            
            // Validate metric types if querying metrics
            if let Some(metrics) = obj.get("metrics").and_then(|v| v.as_array()) {
                for metric in metrics {
                    if let Some(metric_type) = metric.as_str() {
                        if !self.supported_metrics.contains(&metric_type.to_string()) {
                            return Err(McpError::Other(format!("Unsupported metric type: {}", metric_type)));
                        }
                    }
                }
            }
        }
        
        Ok(request)
    }
    
    async fn transform_response(&self, mut response: serde_json::Value) -> Result<serde_json::Value> {
        if let Some(obj) = response.as_object_mut() {
            // Standardize metric format
            if let Some(metrics) = obj.get_mut("metrics").and_then(|v| v.as_object_mut()) {
                let mut standardized = serde_json::Map::new();
                
                for (key, value) in metrics.iter() {
                    // Convert various metric formats to standard format
                    let standard_value = match value {
                        serde_json::Value::Number(n) => n.as_f64().unwrap_or(0.0),
                        serde_json::Value::String(s) => s.parse::<f64>().unwrap_or(0.0),
                        serde_json::Value::Object(m) => {
                            m.get("value")
                                .and_then(|v| v.as_f64())
                                .unwrap_or(0.0)
                        }
                        _ => 0.0,
                    };
                    
                    standardized.insert(
                        key.clone(),
                        serde_json::json!({
                            "value": standard_value,
                            "timestamp": chrono::Utc::now().timestamp(),
                        }),
                    );
                }
                
                obj.insert("standardized_metrics".to_string(), serde_json::json!(standardized));
            }
        }
        
        Ok(response)
    }
    
    async fn collect_metrics(&self) -> Result<ServerMetrics> {
        let mut metrics = HashMap::new();
        
        // Monitoring-specific metrics
        metrics.insert("queries_per_second".to_string(), 0.0);
        metrics.insert("active_alerts".to_string(), 0.0);
        metrics.insert("metric_ingestion_rate".to_string(), 0.0);
        
        Ok(ServerMetrics { custom: metrics })
    }
}

/// Monitoring query request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringQuery {
    /// Query type
    pub query_type: QueryType,
    /// Target metrics
    pub metrics: Vec<String>,
    /// Time range
    pub time_range: TimeRange,
    /// Aggregation method
    pub aggregation: Option<AggregationMethod>,
    /// Filters
    pub filters: HashMap<String, String>,
}

/// Query types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryType {
    Instant,
    Range,
    Aggregate,
    Alert,
}

/// Time range
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    /// Start time (ISO 8601)
    pub start: String,
    /// End time (ISO 8601)
    pub end: String,
    /// Step/resolution
    pub step: Option<String>,
}

/// Aggregation methods
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregationMethod {
    Sum,
    Average,
    Min,
    Max,
    Count,
    Percentile(f64),
}

/// Monitoring response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringResponse {
    /// Query results
    pub results: Vec<MetricResult>,
    /// Execution time
    pub execution_time_ms: u64,
    /// Warnings
    pub warnings: Vec<String>,
}

/// Metric result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricResult {
    /// Metric name
    pub metric: String,
    /// Labels
    pub labels: HashMap<String, String>,
    /// Values
    pub values: Vec<MetricValue>,
}

/// Metric value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricValue {
    /// Timestamp
    pub timestamp: i64,
    /// Value
    pub value: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_monitoring_handler() {
        let handler = MonitoringHandler::new();
        
        // Test config validation
        let valid_config = serde_json::json!({
            "metrics_endpoint": "http://prometheus:9090"
        });
        assert!(handler.validate_config(&valid_config).await.is_ok());
        
        let invalid_config = serde_json::json!({
            "other_field": "value"
        });
        assert!(handler.validate_config(&invalid_config).await.is_err());
    }

    #[tokio::test]
    async fn test_metric_validation() {
        let handler = MonitoringHandler::new();
        
        let request = serde_json::json!({
            "metrics": ["cpu", "memory", "invalid_metric"]
        });
        
        let result = handler.transform_request(request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_response_standardization() {
        let handler = MonitoringHandler::new();
        
        let response = serde_json::json!({
            "metrics": {
                "cpu": 45.5,
                "memory": "1024",
                "disk": {
                    "value": 80.0,
                    "unit": "percent"
                }
            }
        });
        
        let transformed = handler.transform_response(response).await.unwrap();
        let obj = transformed.as_object().unwrap();
        
        assert!(obj.contains_key("standardized_metrics"));
        let std_metrics = obj.get("standardized_metrics").unwrap().as_object().unwrap();
        
        assert!(std_metrics.get("cpu").unwrap().get("value").unwrap().as_f64().unwrap() == 45.5);
        assert!(std_metrics.get("memory").unwrap().get("value").unwrap().as_f64().unwrap() == 1024.0);
        assert!(std_metrics.get("disk").unwrap().get("value").unwrap().as_f64().unwrap() == 80.0);
    }
}