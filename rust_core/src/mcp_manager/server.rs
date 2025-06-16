//! Server abstraction and management

use crate::mcp_manager::{
    config::{ServerConfig, ServerType},
    connection_pool::ConnectionPool,
    errors::{McpError, Result},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};

/// Server state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ServerState {
    /// Server is initializing
    Initializing,
    /// Server is healthy and ready
    Healthy,
    /// Server is degraded but operational
    Degraded,
    /// Server is unhealthy
    Unhealthy,
    /// Server is in maintenance mode
    Maintenance,
    /// Server is stopped
    Stopped,
}

/// Server statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerStats {
    /// Total requests sent
    pub total_requests: u64,
    /// Successful requests
    pub successful_requests: u64,
    /// Failed requests
    pub failed_requests: u64,
    /// Average response time
    pub avg_response_time: Duration,
    /// Last health check time
    #[serde(skip)]
    pub last_health_check: Option<Instant>,
    /// Uptime
    pub uptime: Duration,
}

/// MCP Server abstraction
#[derive(Clone)]
pub struct McpServer {
    /// Server ID
    id: String,
    /// Server configuration
    config: ServerConfig,
    /// Current state
    state: Arc<RwLock<ServerState>>,
    /// Connection pool
    connection_pool: Arc<ConnectionPool>,
    /// Server statistics
    stats: Arc<Mutex<ServerStats>>,
    /// Started time
    started_at: Instant,
}

impl McpServer {
    /// Create a new MCP server instance
    pub fn new(id: String, config: ServerConfig) -> Result<Self> {
        let connection_pool = Arc::new(ConnectionPool::new(
            config.url.clone(),
            config.auth.clone(),
        )?);
        
        Ok(Self {
            id,
            config,
            state: Arc::new(RwLock::new(ServerState::Initializing)),
            connection_pool,
            stats: Arc::new(Mutex::new(ServerStats {
                total_requests: 0,
                successful_requests: 0,
                failed_requests: 0,
                avg_response_time: Duration::from_secs(0),
                last_health_check: None,
                uptime: Duration::from_secs(0),
            })),
            started_at: Instant::now(),
        })
    }

    /// Get current connection count
    pub fn connection_count(&self) -> usize {
        // This would be implemented by checking the connection pool
        // For now, return a placeholder
        0
    }

    /// Get server weight for load balancing
    pub fn weight(&self) -> u32 {
        // Weight based on priority (higher priority = higher weight)
        self.config.priority as u32
    }

    /// Get total request count
    pub fn request_count(&self) -> u64 {
        // Using block_on is not ideal, but necessary for sync context
        futures::executor::block_on(async {
            self.stats.lock().await.total_requests
        })
    }

    /// Get error count
    pub fn error_count(&self) -> u64 {
        futures::executor::block_on(async {
            self.stats.lock().await.failed_requests
        })
    }

    /// Get server ID
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get server name
    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// Get server type
    pub fn server_type(&self) -> &ServerType {
        &self.config.server_type
    }

    /// Get server priority
    pub fn priority(&self) -> u8 {
        self.config.priority
    }

    /// Get server tags
    pub fn tags(&self) -> &[String] {
        &self.config.tags
    }

    /// Get current server state
    pub async fn state(&self) -> ServerState {
        *self.state.read().await
    }

    /// Set server state
    pub async fn set_state(&self, state: ServerState) {
        *self.state.write().await = state;
    }
    
    /// Initialize the server
    pub async fn initialize(&self) -> Result<()> {
        // Set state to healthy (in a real implementation, this would start the server process)
        self.set_state(ServerState::Healthy).await;
        
        // Update stats
        let mut stats = self.stats.lock().await;
        stats.last_health_check = Some(Instant::now());
        
        Ok(())
    }
    
    /// Shutdown the server
    pub async fn shutdown(&self) -> Result<()> {
        // Set state to stopped
        self.set_state(ServerState::Stopped).await;
        
        // Close all connections in the pool
        // In a real implementation, this would gracefully stop the server process
        
        Ok(())
    }

    /// Execute a request on the server
    pub async fn execute<T, R>(&self, request: T) -> Result<R>
    where
        T: Serialize + Send + 'static,
        R: for<'de> Deserialize<'de> + Send + 'static,
    {
        // Check if server is operational
        let state = self.state().await;
        match state {
            ServerState::Healthy | ServerState::Degraded => {},
            _ => return Err(McpError::ServerNotFound(format!(
                "Server {} is in state {:?}", self.id, state
            ))),
        }
        
        // Get connection from pool
        let connection = self.connection_pool.get().await?;
        
        // Record start time
        let start = Instant::now();
        
        // Execute request
        let result = connection.execute(request).await;
        
        // Update statistics
        let mut stats = self.stats.lock().await;
        stats.total_requests += 1;
        
        match &result {
            Ok(_) => {
                stats.successful_requests += 1;
                let duration = start.elapsed();
                
                // Update average response time
                let total_time = stats.avg_response_time.as_millis() as u64 * (stats.successful_requests - 1);
                let new_avg = (total_time + duration.as_millis() as u64) / stats.successful_requests;
                stats.avg_response_time = Duration::from_millis(new_avg);
            }
            Err(_) => {
                stats.failed_requests += 1;
            }
        }
        
        result
    }

    /// Perform health check
    pub async fn health_check(&self) -> Result<bool> {
        // Execute health check
        let healthy = self.connection_pool.health_check().await?;
        
        // Update statistics
        let mut stats = self.stats.lock().await;
        stats.last_health_check = Some(Instant::now());
        
        // Update state based on health
        if healthy {
            self.set_state(ServerState::Healthy).await;
        } else {
            self.set_state(ServerState::Unhealthy).await;
        }
        
        Ok(healthy)
    }

    /// Get server statistics
    pub async fn stats(&self) -> ServerStats {
        let mut stats = self.stats.lock().await.clone();
        stats.uptime = self.started_at.elapsed();
        stats
    }

    /// Check if server matches tags
    pub fn matches_tags(&self, tags: &[String]) -> bool {
        tags.iter().all(|tag| self.config.tags.contains(tag))
    }

    /// Get connection pool metrics
    pub async fn pool_metrics(&self) -> ConnectionPoolMetrics {
        self.connection_pool.metrics().await
    }
}

/// Connection pool metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionPoolMetrics {
    /// Active connections
    pub active_connections: usize,
    /// Idle connections
    pub idle_connections: usize,
    /// Total connections created
    pub total_created: u64,
    /// Total connections closed
    pub total_closed: u64,
    /// Wait time for connections
    pub avg_wait_time: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_manager::config::AuthConfig;

    fn create_test_config() -> ServerConfig {
        ServerConfig {
            name: "test-server".to_string(),
            server_type: ServerType::Docker,
            url: "http://localhost:8080".to_string(),
            port: 8080,
            auth: Some(AuthConfig {
                auth_type: AuthType::ApiKey,
                credentials: {
                    let mut creds = HashMap::new();
                    creds.insert("key".to_string(), "test-key".to_string());
                    creds
                },
            }),
            capabilities: vec![],
            max_connections: 10,
            timeout_ms: 30000,
            retry_policy: RetryPolicy::default(),
            priority: 10,
            tags: vec!["test".to_string()],
        }
    }

    #[tokio::test]
    async fn test_server_creation() {
        let config = create_test_config();
        let server = McpServer::new("test-1".to_string(), config).unwrap();
        
        assert_eq!(server.id(), "test-1");
        assert_eq!(server.name(), "test-server");
        assert_eq!(server.priority(), 10);
        assert_eq!(server.state().await, ServerState::Initializing);
    }

    #[tokio::test]
    async fn test_server_state_transitions() {
        let config = create_test_config();
        let server = McpServer::new("test-1".to_string(), config).unwrap();
        
        assert_eq!(server.state().await, ServerState::Initializing);
        
        server.set_state(ServerState::Healthy).await;
        assert_eq!(server.state().await, ServerState::Healthy);
        
        server.set_state(ServerState::Degraded).await;
        assert_eq!(server.state().await, ServerState::Degraded);
    }

    #[tokio::test]
    async fn test_server_tags() {
        let config = create_test_config();
        let server = McpServer::new("test-1".to_string(), config).unwrap();
        
        assert!(server.matches_tags(&["test".to_string()]));
        assert!(!server.matches_tags(&["prod".to_string()]));
        assert!(!server.matches_tags(&["test".to_string(), "prod".to_string()]));
    }
}