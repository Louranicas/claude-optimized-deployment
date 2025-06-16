/*!
 * MCP Server Base Implementation in Rust
 * 
 * Provides a standardized server structure with health monitoring,
 * error handling, and consistent patterns.
 */

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tokio::time;
use tracing::{info, warn, error, debug};
use uuid::Uuid;

use crate::config::ServerConfig;
use crate::tools::{Tool, ToolRegistry};
use crate::resources::{Resource, ResourceRegistry};
use crate::health::{HealthCheck, HealthStatus, HealthMonitor};
use crate::errors::{ServerError, ServerResult};

/// Server metrics for monitoring and observability
#[derive(Debug, Clone)]
pub struct ServerMetrics {
    pub uptime: Duration,
    pub request_count: u64,
    pub error_count: u64,
    pub tool_calls: u64,
    pub resource_access: u64,
    pub last_activity: Instant,
    pub start_time: Instant,
}

impl Default for ServerMetrics {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            uptime: Duration::default(),
            request_count: 0,
            error_count: 0,
            tool_calls: 0,
            resource_access: 0,
            last_activity: now,
            start_time: now,
        }
    }
}

/// Main MCP Server implementation
pub struct TemplateServer {
    config: ServerConfig,
    tools: Arc<RwLock<ToolRegistry>>,
    resources: Arc<RwLock<ResourceRegistry>>,
    metrics: Arc<Mutex<ServerMetrics>>,
    health_monitor: Arc<HealthMonitor>,
    is_running: Arc<Mutex<bool>>,
}

impl TemplateServer {
    /// Create a new server instance
    pub async fn new(config: ServerConfig) -> Result<Self> {
        info!("Initializing Template MCP Server");
        
        let tools = Arc::new(RwLock::new(ToolRegistry::new()));
        let resources = Arc::new(RwLock::new(ResourceRegistry::new()));
        let metrics = Arc::new(Mutex::new(ServerMetrics::default()));
        let health_monitor = Arc::new(HealthMonitor::new());
        let is_running = Arc::new(Mutex::new(false));
        
        let server = Self {
            config,
            tools,
            resources,
            metrics,
            health_monitor,
            is_running,
        };
        
        // Setup tools and resources
        server.setup_tools().await?;
        server.setup_resources().await?;
        server.setup_health_checks().await?;
        
        info!("Template MCP Server initialized successfully");
        Ok(server)
    }
    
    /// Start the server
    pub async fn start(&self) -> Result<()> {
        info!("Starting Template MCP Server");
        
        {
            let mut running = self.is_running.lock().await;
            *running = true;
        }
        
        // Start metrics collection
        self.start_metrics_collection().await;
        
        // Start health monitoring
        self.health_monitor.start().await?;
        
        // Start the main server loop (stdio-based MCP)
        self.run_stdio_server().await?;
        
        Ok(())
    }
    
    /// Shutdown the server gracefully
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down Template MCP Server");
        
        {
            let mut running = self.is_running.lock().await;
            *running = false;
        }
        
        // Perform cleanup
        self.cleanup().await?;
        
        info!("Template MCP Server shutdown complete");
        Ok(())
    }
    
    /// Setup server tools
    async fn setup_tools(&self) -> Result<()> {
        let mut registry = self.tools.write().await;
        
        // Echo tool
        registry.register(Tool {
            name: "echo".to_string(),
            description: "Echo back the provided message".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "The message to echo back"
                    },
                    "uppercase": {
                        "type": "boolean",
                        "description": "Whether to convert the message to uppercase",
                        "default": false
                    }
                },
                "required": ["message"]
            }),
        });
        
        // API call tool
        registry.register(Tool {
            name: "api_call".to_string(),
            description: "Make a call to the configured API endpoint".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "endpoint": {
                        "type": "string",
                        "description": "API endpoint path (relative to base URL)"
                    },
                    "method": {
                        "type": "string",
                        "enum": ["GET", "POST", "PUT", "DELETE"],
                        "default": "GET",
                        "description": "HTTP method to use"
                    },
                    "data": {
                        "type": "object",
                        "description": "Request body data for POST/PUT requests"
                    }
                },
                "required": ["endpoint"]
            }),
        });
        
        // UUID generation tool
        registry.register(Tool {
            name: "generate_uuid".to_string(),
            description: "Generate a random UUID".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "version": {
                        "type": "number",
                        "enum": [1, 4],
                        "default": 4,
                        "description": "UUID version to generate"
                    }
                }
            }),
        });
        
        info!("Registered {} tools", registry.count());
        Ok(())
    }
    
    /// Setup server resources
    async fn setup_resources(&self) -> Result<()> {
        let mut registry = self.resources.write().await;
        
        // Server info resource
        registry.register(Resource {
            uri: "template://server/info".to_string(),
            name: "Server Information".to_string(),
            description: "Information about this server instance".to_string(),
            mime_type: "application/json".to_string(),
        });
        
        // Configuration resource
        registry.register(Resource {
            uri: "template://server/config".to_string(),
            name: "Server Configuration".to_string(),
            description: "Current server configuration (sanitized)".to_string(),
            mime_type: "application/json".to_string(),
        });
        
        // Logs resource
        registry.register(Resource {
            uri: "template://server/logs".to_string(),
            name: "Server Logs".to_string(),
            description: "Recent server log entries".to_string(),
            mime_type: "text/plain".to_string(),
        });
        
        info!("Registered {} resources", registry.count());
        Ok(())
    }
    
    /// Setup health checks
    async fn setup_health_checks(&self) -> Result<()> {
        // Memory health check
        self.health_monitor.add_check(HealthCheck {
            name: "memory".to_string(),
            description: "System memory usage".to_string(),
            check_fn: Box::new(|| {
                Box::pin(async {
                    use sysinfo::{System, SystemExt};
                    let mut sys = System::new_all();
                    sys.refresh_memory();
                    
                    let used_memory = sys.used_memory();
                    let total_memory = sys.total_memory();
                    let usage_percent = (used_memory as f64 / total_memory as f64) * 100.0;
                    
                    let status = if usage_percent > 90.0 {
                        HealthStatus::Unhealthy
                    } else if usage_percent > 75.0 {
                        HealthStatus::Degraded
                    } else {
                        HealthStatus::Healthy
                    };
                    
                    Ok((status, format!("Memory usage: {:.1}%", usage_percent)))
                })
            }),
            interval: Duration::from_secs(30),
        }).await;
        
        // API connectivity check
        let api_endpoint = self.config.api_endpoint.clone();
        let api_key = self.config.api_key.clone();
        
        self.health_monitor.add_check(HealthCheck {
            name: "api_connectivity".to_string(),
            description: "API endpoint connectivity".to_string(),
            check_fn: Box::new(move || {
                let endpoint = api_endpoint.clone();
                let key = api_key.clone();
                Box::pin(async move {
                    let status = if !key.is_empty() {
                        HealthStatus::Healthy
                    } else {
                        HealthStatus::Degraded
                    };
                    
                    let message = if !key.is_empty() {
                        "API key configured".to_string()
                    } else {
                        "API key not configured".to_string()
                    };
                    
                    Ok((status, message))
                })
            }),
            interval: Duration::from_secs(60),
        }).await;
        
        info!("Health checks configured");
        Ok(())
    }
    
    /// Start metrics collection background task
    async fn start_metrics_collection(&self) {
        let metrics = Arc::clone(&self.metrics);
        let is_running = Arc::clone(&self.is_running);
        
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(1));
            
            loop {
                interval.tick().await;
                
                {
                    let running = is_running.lock().await;
                    if !*running {
                        break;
                    }
                }
                
                {
                    let mut m = metrics.lock().await;
                    m.uptime = m.start_time.elapsed();
                }
            }
        });
    }
    
    /// Run the stdio-based MCP server
    async fn run_stdio_server(&self) -> Result<()> {
        info!("Starting stdio MCP server loop");
        
        // This is a simplified stdio server implementation
        // In a real implementation, you would use the MCP protocol
        // to handle JSON-RPC messages over stdin/stdout
        
        let is_running = Arc::clone(&self.is_running);
        
        while *is_running.lock().await {
            // Simulate server activity
            tokio::time::sleep(Duration::from_millis(100)).await;
            
            // In a real implementation, you would:
            // 1. Read JSON-RPC messages from stdin
            // 2. Parse and validate the messages
            // 3. Route to appropriate handlers (tools/list, tools/call, etc.)
            // 4. Execute the requested operations
            // 5. Send responses to stdout
        }
        
        Ok(())
    }
    
    /// Execute a tool
    pub async fn execute_tool(&self, name: &str, arguments: Value) -> ServerResult<Value> {
        let start_time = Instant::now();
        
        // Update metrics
        {
            let mut metrics = self.metrics.lock().await;
            metrics.tool_calls += 1;
            metrics.request_count += 1;
            metrics.last_activity = Instant::now();
        }
        
        debug!("Executing tool: {}", name);
        
        let result = match name {
            "echo" => self.execute_echo_tool(arguments).await,
            "api_call" => self.execute_api_call_tool(arguments).await,
            "generate_uuid" => self.execute_generate_uuid_tool(arguments).await,
            _ => Err(ServerError::ToolNotFound(name.to_string())),
        };
        
        let duration = start_time.elapsed();
        
        match &result {
            Ok(_) => {
                info!("Tool '{}' executed successfully in {:?}", name, duration);
            }
            Err(e) => {
                error!("Tool '{}' execution failed: {}", name, e);
                let mut metrics = self.metrics.lock().await;
                metrics.error_count += 1;
            }
        }
        
        result
    }
    
    /// Execute echo tool
    async fn execute_echo_tool(&self, args: Value) -> ServerResult<Value> {
        let message = args.get("message")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ServerError::InvalidArguments("message is required".to_string()))?;
        
        let uppercase = args.get("uppercase")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let processed_message = if uppercase {
            message.to_uppercase()
        } else {
            message.to_string()
        };
        
        Ok(json!({
            "echo": processed_message,
            "original_length": message.len(),
            "processed_at": chrono::Utc::now().to_rfc3339()
        }))
    }
    
    /// Execute API call tool
    async fn execute_api_call_tool(&self, args: Value) -> ServerResult<Value> {
        let endpoint = args.get("endpoint")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ServerError::InvalidArguments("endpoint is required".to_string()))?;
        
        let method = args.get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET");
        
        let data = args.get("data").cloned();
        
        if self.config.api_key.is_empty() {
            return Err(ServerError::ConfigurationError("API key not configured".to_string()));
        }
        
        let url = format!("{}{}", self.config.api_endpoint, endpoint);
        
        // Simulate API call (replace with actual HTTP client implementation)
        let response = json!({
            "url": url,
            "method": method,
            "data": data,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "simulated": true,
            "message": "This is a simulated API response. Replace with actual HTTP client implementation."
        });
        
        Ok(response)
    }
    
    /// Execute UUID generation tool
    async fn execute_generate_uuid_tool(&self, args: Value) -> ServerResult<Value> {
        let version = args.get("version")
            .and_then(|v| v.as_u64())
            .unwrap_or(4);
        
        let uuid_str = match version {
            1 => Uuid::now_v1(&[1, 2, 3, 4, 5, 6]).to_string(),
            4 => Uuid::new_v4().to_string(),
            _ => return Err(ServerError::InvalidArguments(format!("Unsupported UUID version: {}", version))),
        };
        
        Ok(json!({
            "uuid": uuid_str,
            "version": version,
            "generated_at": chrono::Utc::now().to_rfc3339()
        }))
    }
    
    /// Read resource content
    pub async fn read_resource(&self, uri: &str) -> ServerResult<Value> {
        let start_time = Instant::now();
        
        // Update metrics
        {
            let mut metrics = self.metrics.lock().await;
            metrics.resource_access += 1;
            metrics.request_count += 1;
            metrics.last_activity = Instant::now();
        }
        
        debug!("Reading resource: {}", uri);
        
        let result = match uri {
            "template://server/info" => self.get_server_info().await,
            "template://server/config" => self.get_server_config().await,
            "template://server/logs" => self.get_server_logs().await,
            _ => Err(ServerError::ResourceNotFound(uri.to_string())),
        };
        
        let duration = start_time.elapsed();
        
        match &result {
            Ok(_) => {
                info!("Resource '{}' read successfully in {:?}", uri, duration);
            }
            Err(e) => {
                error!("Resource '{}' read failed: {}", uri, e);
                let mut metrics = self.metrics.lock().await;
                metrics.error_count += 1;
            }
        }
        
        result
    }
    
    /// Get server information
    async fn get_server_info(&self) -> ServerResult<Value> {
        let metrics = self.metrics.lock().await;
        let tools_count = self.tools.read().await.count();
        let resources_count = self.resources.read().await.count();
        
        Ok(json!({
            "uri": "template://server/info",
            "mimeType": "application/json",
            "text": serde_json::to_string_pretty(&json!({
                "name": "template-server",
                "version": "1.0.0",
                "description": "A template MCP server demonstrating best practices",
                "uptime": metrics.uptime.as_secs(),
                "request_count": metrics.request_count,
                "tool_count": tools_count,
                "resource_count": resources_count
            }))?
        }))
    }
    
    /// Get server configuration (sanitized)
    async fn get_server_config(&self) -> ServerResult<Value> {
        Ok(json!({
            "uri": "template://server/config",
            "mimeType": "application/json",
            "text": serde_json::to_string_pretty(&json!({
                "api_endpoint": self.config.api_endpoint,
                "api_key": if self.config.api_key.is_empty() { "" } else { "***" },
                "max_retries": self.config.max_retries,
                "cache_enabled": self.config.cache_enabled
            }))?
        }))
    }
    
    /// Get server logs
    async fn get_server_logs(&self) -> ServerResult<Value> {
        Ok(json!({
            "uri": "template://server/logs",
            "mimeType": "text/plain",
            "text": "Log entries would be retrieved from your logging system here..."
        }))
    }
    
    /// Get health status
    pub async fn get_health(&self) -> ServerResult<Value> {
        let health_status = self.health_monitor.get_status().await;
        let metrics = self.metrics.lock().await;
        
        Ok(json!({
            "status": match health_status.overall {
                HealthStatus::Healthy => "healthy",
                HealthStatus::Degraded => "degraded",
                HealthStatus::Unhealthy => "unhealthy"
            },
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "checks": health_status.checks,
            "metrics": {
                "uptime": metrics.uptime.as_secs(),
                "request_count": metrics.request_count,
                "error_count": metrics.error_count,
                "tool_calls": metrics.tool_calls,
                "resource_access": metrics.resource_access
            }
        }))
    }
    
    /// Cleanup resources
    async fn cleanup(&self) -> Result<()> {
        info!("Performing server cleanup");
        
        // Stop health monitoring
        self.health_monitor.stop().await;
        
        // Perform any additional cleanup here
        // - Close database connections
        // - Cancel ongoing tasks
        // - Save state if necessary
        
        info!("Server cleanup completed");
        Ok(())
    }
}