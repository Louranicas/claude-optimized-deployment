//! MCP Server Manager
//! 
//! Manages connections to MCP servers and executes tools

use crate::synthex_bashgod::{Result, SBGError};
use crate::synthex_bashgod::mcp_integration::{
    MCPServer, MCPTool, ToolResult, ResourceUsage, ServerType, ServerStatus,
    ToolInfo, MethodInfo, ParameterInfo, MCPServerConfig, ConnectionInfo,
    AuthType, RetryPolicy,
};
use dashmap::DashMap;
use reqwest::Client;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

/// MCP server manager
pub struct MCPServerManager {
    /// Configured servers
    servers: Arc<DashMap<String, MCPServerInstance>>,
    
    /// HTTP client
    client: Client,
    
    /// Connection pool
    connection_pool: Arc<ConnectionPool>,
    
    /// Statistics
    stats: Arc<RwLock<ManagerStats>>,
}

/// MCP server instance
struct MCPServerInstance {
    /// Server configuration
    config: MCPServerConfig,
    
    /// Server metadata
    metadata: ServerMetadata,
    
    /// Health checker
    health_checker: HealthChecker,
    
    /// Rate limiter
    rate_limiter: RateLimiter,
}

/// Server metadata
#[derive(Debug, Clone)]
struct ServerMetadata {
    /// Server info
    info: MCPServer,
    
    /// Last health check
    last_health_check: Instant,
    
    /// Current status
    status: ServerStatus,
    
    /// Available tools cache
    tools_cache: Option<Vec<ToolInfo>>,
}

/// Health checker for server
struct HealthChecker {
    /// Check interval
    interval: Duration,
    
    /// Failure threshold
    failure_threshold: u32,
    
    /// Current failure count
    failure_count: Arc<RwLock<u32>>,
}

/// Rate limiter for API calls
struct RateLimiter {
    /// Requests per second
    rps: u32,
    
    /// Semaphore for rate limiting
    semaphore: Arc<Semaphore>,
}

/// Connection pool
struct ConnectionPool {
    /// Maximum connections per server
    max_connections: usize,
    
    /// Connection semaphores
    semaphores: DashMap<String, Arc<Semaphore>>,
}

/// Manager statistics
#[derive(Debug, Default)]
struct ManagerStats {
    /// Total tool executions
    total_executions: u64,
    
    /// Successful executions
    successful_executions: u64,
    
    /// Failed executions
    failed_executions: u64,
    
    /// Average execution time
    avg_execution_time_ms: f64,
    
    /// Server availability
    server_availability: f32,
}

impl MCPServerManager {
    /// Create new server manager
    pub fn new(configs: Vec<MCPServerConfig>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();
        
        let servers = Arc::new(DashMap::new());
        
        // Initialize servers
        for config in configs {
            let instance = MCPServerInstance::new(config.clone());
            servers.insert(config.name.clone(), instance);
        }
        
        Self {
            servers,
            client,
            connection_pool: Arc::new(ConnectionPool::new(10)),
            stats: Arc::new(RwLock::new(ManagerStats::default())),
        }
    }
    
    /// Execute MCP tool
    pub async fn execute_tool(&self, tool: &MCPTool) -> Result<ToolResult> {
        let start = Instant::now();
        
        // Get server instance
        let server = self.servers.get(&tool.server)
            .ok_or_else(|| SBGError::MCPError(format!("Server '{}' not found", tool.server)))?;
        
        // Check server health
        if !self.is_server_healthy(&server).await {
            return Err(SBGError::MCPError(format!("Server '{}' is unhealthy", tool.server)));
        }
        
        // Apply rate limiting
        server.rate_limiter.acquire().await?;
        
        // Get connection permit
        let _permit = self.connection_pool.acquire(&tool.server).await?;
        
        // Execute tool with retry
        let result = self.execute_with_retry(tool, &server.config).await?;
        
        // Update statistics
        self.update_stats(start.elapsed(), result.success).await;
        
        Ok(result)
    }
    
    /// List available servers
    pub async fn list_servers(&self) -> Result<Vec<MCPServer>> {
        let mut servers = Vec::new();
        
        for entry in self.servers.iter() {
            let server = &entry.value();
            
            // Update health status
            if server.health_checker.should_check() {
                self.check_server_health(entry.key(), server).await;
            }
            
            servers.push(server.metadata.info.clone());
        }
        
        Ok(servers)
    }
    
    /// Execute with retry logic
    async fn execute_with_retry(
        &self,
        tool: &MCPTool,
        config: &MCPServerConfig,
    ) -> Result<ToolResult> {
        let retry_policy = &config.connection.retry_policy;
        let mut delay = Duration::from_millis(retry_policy.initial_delay_ms);
        
        for attempt in 0..=retry_policy.max_retries {
            match self.execute_single(tool, config).await {
                Ok(result) => return Ok(result),
                Err(e) if attempt < retry_policy.max_retries => {
                    warn!(
                        "Tool execution failed (attempt {}/{}): {}",
                        attempt + 1,
                        retry_policy.max_retries,
                        e
                    );
                    
                    sleep(delay).await;
                    
                    // Exponential backoff
                    delay = Duration::from_millis(
                        (delay.as_millis() as f64 * retry_policy.backoff_multiplier as f64)
                            .min(retry_policy.max_delay_ms as f64) as u64
                    );
                }
                Err(e) => return Err(e),
            }
        }
        
        Err(SBGError::MCPError("Max retries exceeded".to_string()))
    }
    
    /// Execute single tool call
    async fn execute_single(
        &self,
        tool: &MCPTool,
        config: &MCPServerConfig,
    ) -> Result<ToolResult> {
        let url = format!("{}/tools/{}/{}", config.connection.url, tool.tool, tool.method);
        
        // Build request
        let mut request = self.client.post(&url)
            .json(&tool.params)
            .timeout(Duration::from_millis(config.connection.timeout_ms));
        
        // Add authentication
        request = match &config.connection.auth_type {
            AuthType::None => request,
            AuthType::ApiKey(key) => request.header("X-API-Key", key),
            AuthType::Bearer(token) => request.bearer_auth(token),
            AuthType::Basic { username, password } => request.basic_auth(username, Some(password)),
            AuthType::Custom(headers) => {
                let mut req = request;
                for (key, value) in headers {
                    req = req.header(key, value);
                }
                req
            }
        };
        
        // Execute request
        let response = request.send().await
            .map_err(|e| SBGError::MCPError(format!("Request failed: {}", e)))?;
        
        // Check status
        if !response.status().is_success() {
            return Err(SBGError::MCPError(format!(
                "Tool execution failed with status: {}",
                response.status()
            )));
        }
        
        // Parse response
        let data: serde_json::Value = response.json().await
            .map_err(|e| SBGError::MCPError(format!("Failed to parse response: {}", e)))?;
        
        // Create result
        Ok(ToolResult {
            success: true,
            data,
            execution_time_ms: 0, // Will be set by caller
            resource_usage: ResourceUsage {
                cpu_percent: 0.0,
                memory_mb: 0,
                network_kb: 1, // Approximate
            },
        })
    }
    
    /// Check if server is healthy
    async fn is_server_healthy(&self, server: &MCPServerInstance) -> bool {
        matches!(server.metadata.status, ServerStatus::Ready | ServerStatus::Busy)
    }
    
    /// Check server health
    async fn check_server_health(&self, name: &str, server: &MCPServerInstance) {
        let health_url = format!("{}/health", server.config.connection.url);
        
        match self.client.get(&health_url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                // Reset failure count
                *server.health_checker.failure_count.write().await = 0;
                
                // Update status
                if let Some(mut entry) = self.servers.get_mut(name) {
                    entry.metadata.status = ServerStatus::Ready;
                    entry.metadata.last_health_check = Instant::now();
                }
            }
            _ => {
                // Increment failure count
                let mut failures = server.health_checker.failure_count.write().await;
                *failures += 1;
                
                // Update status if threshold exceeded
                if *failures >= server.health_checker.failure_threshold {
                    if let Some(mut entry) = self.servers.get_mut(name) {
                        entry.metadata.status = ServerStatus::Unavailable;
                    }
                }
            }
        }
    }
    
    /// Update statistics
    async fn update_stats(&self, duration: Duration, success: bool) {
        let mut stats = self.stats.write().await;
        
        stats.total_executions += 1;
        if success {
            stats.successful_executions += 1;
        } else {
            stats.failed_executions += 1;
        }
        
        // Update average execution time
        let n = stats.total_executions as f64;
        stats.avg_execution_time_ms = 
            (stats.avg_execution_time_ms * (n - 1.0) + duration.as_millis() as f64) / n;
        
        // Update server availability
        let total_servers = self.servers.len() as f32;
        let available_servers = self.servers.iter()
            .filter(|entry| matches!(entry.value().metadata.status, ServerStatus::Ready))
            .count() as f32;
        
        stats.server_availability = if total_servers > 0.0 {
            available_servers / total_servers
        } else {
            0.0
        };
    }
    
    /// Get manager statistics
    pub async fn get_stats(&self) -> (u64, u64, u64, f64, f32) {
        let stats = self.stats.read().await;
        (
            stats.total_executions,
            stats.successful_executions,
            stats.failed_executions,
            stats.avg_execution_time_ms,
            stats.server_availability,
        )
    }
}

impl MCPServerInstance {
    /// Create new server instance
    fn new(config: MCPServerConfig) -> Self {
        let metadata = ServerMetadata {
            info: MCPServer {
                name: config.name.clone(),
                server_type: config.server_type.clone(),
                tools: vec![], // Will be populated on first query
                status: ServerStatus::Starting,
                connection: config.connection.clone(),
            },
            last_health_check: Instant::now(),
            status: ServerStatus::Starting,
            tools_cache: None,
        };
        
        let health_checker = HealthChecker {
            interval: Duration::from_secs(30),
            failure_threshold: 3,
            failure_count: Arc::new(RwLock::new(0)),
        };
        
        let rate_limiter = RateLimiter::new(100); // 100 RPS default
        
        Self {
            config,
            metadata,
            health_checker,
            rate_limiter,
        }
    }
}

impl HealthChecker {
    /// Check if health check is due
    fn should_check(&self) -> bool {
        // For simplicity, always return true
        // In production, check against last_health_check + interval
        true
    }
}

impl RateLimiter {
    /// Create new rate limiter
    fn new(rps: u32) -> Self {
        Self {
            rps,
            semaphore: Arc::new(Semaphore::new(rps as usize)),
        }
    }
    
    /// Acquire rate limit permit
    async fn acquire(&self) -> Result<()> {
        let _permit = self.semaphore.acquire().await
            .map_err(|_| SBGError::MCPError("Rate limiter closed".to_string()))?;
        
        // Release permit after 1 second
        tokio::spawn({
            let sem = self.semaphore.clone();
            async move {
                sleep(Duration::from_secs(1)).await;
                sem.add_permits(1);
            }
        });
        
        Ok(())
    }
}

impl ConnectionPool {
    /// Create new connection pool
    fn new(max_connections: usize) -> Self {
        Self {
            max_connections,
            semaphores: DashMap::new(),
        }
    }
    
    /// Acquire connection permit
    async fn acquire(&self, server: &str) -> Result<tokio::sync::OwnedSemaphorePermit> {
        let semaphore = self.semaphores
            .entry(server.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(self.max_connections)))
            .clone();
        
        let permit = semaphore.acquire_owned().await
            .map_err(|_| SBGError::MCPError("Connection pool closed".to_string()))?;
        
        Ok(permit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_server_manager_creation() {
        let config = MCPServerConfig {
            name: "test-server".to_string(),
            server_type: ServerType::Custom("test".to_string()),
            connection: ConnectionInfo {
                url: "http://localhost:8080".to_string(),
                auth_type: AuthType::None,
                timeout_ms: 5000,
                retry_policy: RetryPolicy {
                    max_retries: 3,
                    initial_delay_ms: 100,
                    backoff_multiplier: 2.0,
                    max_delay_ms: 5000,
                },
            },
            enabled_tools: vec!["test-tool".to_string()],
            settings: Default::default(),
        };
        
        let manager = MCPServerManager::new(vec![config]);
        
        let servers = manager.list_servers().await.unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "test-server");
    }
    
    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(10);
        assert_eq!(limiter.rps, 10);
    }
}