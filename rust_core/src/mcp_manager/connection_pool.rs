//! Connection pooling for MCP servers

use crate::mcp_manager::{
    config::AuthConfig,
    errors::{McpError, Result},
    server::ConnectionPoolMetrics,
};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::timeout;

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionState {
    Active,
    Idle,
    Closed,
}

/// Individual connection in the pool
struct PooledConnection {
    id: u64,
    connection: Box<dyn Connection>,
    state: ConnectionState,
    created_at: Instant,
    last_used: Instant,
}

/// Connection trait that all MCP connections must implement
#[async_trait::async_trait]
pub trait Connection: Send + Sync {
    /// Execute a request - moved generic parameters to trait level to make it dyn-compatible
    async fn execute_raw(&self, request: serde_json::Value) -> Result<serde_json::Value>;
    
    /// Check if connection is healthy
    async fn is_healthy(&self) -> bool;
    
    /// Close the connection
    async fn close(&mut self) -> Result<()>;
}

/// Extension trait for typed execute operations
#[async_trait::async_trait]
pub trait ConnectionExt: Connection {
    /// Execute a typed request
    async fn execute<T, R>(&self, request: T) -> Result<R>
    where
        T: Serialize + Send + 'static,
        R: for<'de> Deserialize<'de> + Send + 'static,
    {
        let raw_request = serde_json::to_value(request)
            .map_err(|e| McpError::SerializationError(e.to_string()))?;
        let raw_response = self.execute_raw(raw_request).await?;
        serde_json::from_value(raw_response)
            .map_err(|e| McpError::SerializationError(e.to_string()))
    }
}

// Blanket implementation for all Connection types
impl<T: Connection + ?Sized> ConnectionExt for T {}

/// Mock connection for testing
#[cfg(test)]
struct MockConnection {
    url: String,
    healthy: bool,
}

#[cfg(test)]
#[async_trait::async_trait]
impl Connection for MockConnection {
    async fn execute_raw(&self, _request: serde_json::Value) -> Result<serde_json::Value> {
        if self.healthy {
            Ok(serde_json::json!({"result": "mock response"}))
        } else {
            Err(McpError::ConnectionError("Mock connection unhealthy".to_string()))
        }
    }
    
    async fn is_healthy(&self) -> bool {
        self.healthy
    }
    
    async fn close(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Connection factory trait
#[async_trait::async_trait]
pub trait ConnectionFactory: Send + Sync {
    /// Create a new connection
    async fn create(&self) -> Result<Box<dyn Connection>>;
}

/// Default connection factory
struct DefaultConnectionFactory {
    url: String,
    auth: Option<AuthConfig>,
}

#[async_trait::async_trait]
impl ConnectionFactory for DefaultConnectionFactory {
    async fn create(&self) -> Result<Box<dyn Connection>> {
        // In production, this would create actual MCP connections
        // For now, we'll create a mock connection for testing
        #[cfg(test)]
        {
            Ok(Box::new(MockConnection {
                url: self.url.clone(),
                healthy: true,
            }))
        }
        
        #[cfg(not(test))]
        {
            // TODO: Implement actual MCP connection creation
            Err(McpError::Other("Connection factory not implemented".to_string()))
        }
    }
}

/// Connection pool for managing MCP connections
#[derive(Clone)]
pub struct ConnectionPool {
    /// Inner pool implementation wrapped in Arc for cheap cloning
    inner: Arc<ConnectionPoolInner>,
}

/// Inner pool implementation
struct ConnectionPoolInner {
    /// Connection factory
    factory: Arc<dyn ConnectionFactory>,
    
    /// Pool of idle connections
    idle_connections: Arc<Mutex<VecDeque<PooledConnection>>>,
    
    /// Active connections count
    active_count: Arc<Mutex<usize>>,
    
    /// Semaphore for limiting total connections
    max_connections: Arc<Semaphore>,
    
    /// Minimum connections to maintain
    min_connections: usize,
    
    /// Maximum connection lifetime
    max_lifetime: Duration,
    
    /// Idle timeout
    idle_timeout: Duration,
    
    /// Connection counter for IDs
    connection_counter: Arc<Mutex<u64>>,
    
    /// Metrics
    metrics: Arc<Mutex<ConnectionPoolMetrics>>,
}

impl ConnectionPool {
    /// Create a new connection pool
    pub fn new(url: String, auth: Option<AuthConfig>) -> Result<Self> {
        let factory = Arc::new(DefaultConnectionFactory { url, auth });
        
        let inner = Arc::new(ConnectionPoolInner {
            factory,
            idle_connections: Arc::new(Mutex::new(VecDeque::new())),
            active_count: Arc::new(Mutex::new(0)),
            max_connections: Arc::new(Semaphore::new(50)), // Default max
            min_connections: 5, // Default min
            max_lifetime: Duration::from_secs(3600), // 1 hour
            idle_timeout: Duration::from_secs(300), // 5 minutes
            connection_counter: Arc::new(Mutex::new(0)),
            metrics: Arc::new(Mutex::new(ConnectionPoolMetrics {
                active_connections: 0,
                idle_connections: 0,
                total_created: 0,
                total_closed: 0,
                avg_wait_time: Duration::from_secs(0),
            })),
        });
        
        Ok(Self { inner })
    }
    
    /// Initialize the connection pool
    pub async fn initialize(&self) -> Result<()> {
        // Pre-create minimum connections
        for _ in 0..self.inner.min_connections {
            let conn = self.create_connection().await?;
            self.inner.idle_connections.lock().await.push_back(conn);
        }
        
        // Start background maintenance task
        self.start_maintenance_task();
        
        Ok(())
    }
    
    /// Get a connection from the pool
    pub async fn get(&self) -> Result<PooledConnectionGuard> {
        let start = Instant::now();
        
        // Try to get an idle connection
        loop {
            if let Some(mut conn) = self.get_idle_connection().await {
                // Check if connection is still valid
                if conn.created_at.elapsed() < self.inner.max_lifetime && conn.connection.is_healthy().await {
                    conn.state = ConnectionState::Active;
                    conn.last_used = Instant::now();
                    
                    *self.inner.active_count.lock().await += 1;
                    
                    // Update metrics
                    let mut metrics = self.inner.metrics.lock().await;
                    metrics.active_connections += 1;
                    let wait_time = start.elapsed();
                    metrics.avg_wait_time = Duration::from_millis(
                        ((metrics.avg_wait_time.as_millis() + wait_time.as_millis()) / 2) as u64
                    );
                    
                    return Ok(PooledConnectionGuard {
                        pool: Arc::new(self.clone()),
                        connection: Some(conn),
                    });
                }
                
                // Connection is invalid, close it
                self.close_connection(conn).await;
            }
            
            // Try to create a new connection
            if let Ok(permit) = self.inner.max_connections.try_acquire() {
                permit.forget(); // We'll manage the permit manually
                
                match timeout(Duration::from_secs(5), self.create_connection()).await {
                    Ok(Ok(conn)) => {
                        *self.inner.active_count.lock().await += 1;
                        
                        // Update metrics
                        let mut metrics = self.inner.metrics.lock().await;
                        metrics.active_connections += 1;
                        let wait_time = start.elapsed();
                        metrics.avg_wait_time = Duration::from_millis(
                            ((metrics.avg_wait_time.as_millis() + wait_time.as_millis()) / 2) as u64
                        );
                        
                        return Ok(PooledConnectionGuard {
                            pool: Arc::new(self.clone()),
                            connection: Some(conn),
                        });
                    }
                    Ok(Err(e)) => return Err(e),
                    Err(_) => return Err(McpError::Timeout("Connection creation timed out".to_string())),
                }
            }
            
            // Wait for a connection to become available
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    
    /// Perform health check on all connections
    pub async fn health_check(&self) -> Result<bool> {
        let mut idle_conns = self.inner.idle_connections.lock().await;
        let mut healthy_count = 0;
        let total_count = idle_conns.len() + *self.inner.active_count.lock().await;
        
        // Check idle connections
        let mut conns_to_remove = Vec::new();
        for (i, conn) in idle_conns.iter().enumerate() {
            if conn.connection.is_healthy().await {
                healthy_count += 1;
            } else {
                conns_to_remove.push(i);
            }
        }
        
        // Remove unhealthy connections
        for i in conns_to_remove.into_iter().rev() {
            if let Some(conn) = idle_conns.remove(i) {
                self.close_connection(conn).await;
            }
        }
        
        // Assume active connections are healthy (they'll be checked when returned)
        healthy_count += *self.inner.active_count.lock().await;
        
        Ok(healthy_count > total_count / 2) // Consider pool healthy if >50% connections are healthy
    }
    
    /// Shutdown the connection pool
    pub async fn shutdown(&self) -> Result<()> {
        // Close all idle connections
        let mut idle_conns = self.inner.idle_connections.lock().await;
        while let Some(conn) = idle_conns.pop_front() {
            self.close_connection(conn).await;
        }
        
        // Wait for active connections to be returned
        let timeout_duration = Duration::from_secs(30);
        let start = Instant::now();
        
        while *self.inner.active_count.lock().await > 0 && start.elapsed() < timeout_duration {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        
        if *self.inner.active_count.lock().await > 0 {
            return Err(McpError::Timeout("Shutdown timed out waiting for active connections".to_string()));
        }
        
        Ok(())
    }
    
    /// Get metrics
    pub async fn metrics(&self) -> ConnectionPoolMetrics {
        let metrics = self.inner.metrics.lock().await;
        let mut result = metrics.clone();
        result.idle_connections = self.inner.idle_connections.lock().await.len();
        result.active_connections = *self.inner.active_count.lock().await;
        result
    }
    
    /// Create a new connection
    async fn create_connection(&self) -> Result<PooledConnection> {
        let connection = self.inner.factory.create().await?;
        
        let mut counter = self.inner.connection_counter.lock().await;
        *counter += 1;
        let id = *counter;
        
        let mut metrics = self.inner.metrics.lock().await;
        metrics.total_created += 1;
        
        Ok(PooledConnection {
            id,
            connection,
            state: ConnectionState::Idle,
            created_at: Instant::now(),
            last_used: Instant::now(),
        })
    }
    
    /// Get an idle connection from the pool
    async fn get_idle_connection(&self) -> Option<PooledConnection> {
        let mut idle_conns = self.inner.idle_connections.lock().await;
        idle_conns.pop_front()
    }
    
    /// Return a connection to the pool
    async fn return_connection(&self, mut conn: PooledConnection) {
        *self.inner.active_count.lock().await -= 1;
        
        let mut metrics = self.inner.metrics.lock().await;
        metrics.active_connections -= 1;
        
        if conn.connection.is_healthy().await {
            conn.state = ConnectionState::Idle;
            conn.last_used = Instant::now();
            self.inner.idle_connections.lock().await.push_back(conn);
        } else {
            self.close_connection(conn).await;
        }
    }
    
    /// Close a connection
    async fn close_connection(&self, mut conn: PooledConnection) {
        let _ = conn.connection.close().await;
        conn.state = ConnectionState::Closed;
        
        let mut metrics = self.inner.metrics.lock().await;
        metrics.total_closed += 1;
        
        // Release permit
        self.inner.max_connections.add_permits(1);
    }
    
    /// Start background maintenance task
    fn start_maintenance_task(&self) {
        let pool = self.clone();
        
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                
                // Clean up expired connections
                let mut idle_conns = pool.inner.idle_connections.lock().await;
                let mut conns_to_remove = Vec::new();
                
                for (i, conn) in idle_conns.iter().enumerate() {
                    if conn.created_at.elapsed() > pool.inner.max_lifetime ||
                       conn.last_used.elapsed() > pool.inner.idle_timeout {
                        conns_to_remove.push(i);
                    }
                }
                
                for i in conns_to_remove.into_iter().rev() {
                    if let Some(conn) = idle_conns.remove(i) {
                        pool.close_connection(conn).await;
                    }
                }
                
                // Ensure minimum connections
                let idle_count = idle_conns.len();
                drop(idle_conns); // Release lock
                
                if idle_count < pool.inner.min_connections {
                    for _ in idle_count..pool.inner.min_connections {
                        if let Ok(conn) = pool.create_connection().await {
                            pool.inner.idle_connections.lock().await.push_back(conn);
                        }
                    }
                }
            }
        });
    }
    
    /// Get pool configuration for display purposes
    pub fn config(&self) -> (usize, usize, Duration, Duration) {
        (
            self.inner.min_connections,
            self.inner.max_connections.available_permits(),
            self.inner.max_lifetime,
            self.inner.idle_timeout,
        )
    }
}

/// Guard for automatically returning connections to the pool
pub struct PooledConnectionGuard {
    pool: Arc<ConnectionPool>,
    connection: Option<PooledConnection>,
}

impl PooledConnectionGuard {
    /// Execute a request on the connection
    pub async fn execute<T, R>(&self, request: T) -> Result<R>
    where
        T: Serialize + Send + 'static,
        R: for<'de> Deserialize<'de> + Send + 'static,
    {
        if let Some(conn) = &self.connection {
            use ConnectionExt;
            conn.connection.execute(request).await
        } else {
            Err(McpError::ConnectionError("No connection available".to_string()))
        }
    }
}

impl Drop for PooledConnectionGuard {
    fn drop(&mut self) {
        if let Some(conn) = self.connection.take() {
            let pool = self.pool.clone();
            tokio::spawn(async move {
                pool.return_connection(conn).await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connection_pool_creation() {
        let pool = ConnectionPool::new(
            "http://localhost:8080".to_string(),
            None,
        ).unwrap();
        
        assert_eq!(pool.min_connections, 5);
        assert_eq!(pool.max_lifetime, Duration::from_secs(3600));
    }

    #[tokio::test]
    async fn test_pool_metrics() {
        let pool = ConnectionPool::new(
            "http://localhost:8080".to_string(),
            None,
        ).unwrap();
        
        let metrics = pool.metrics().await;
        assert_eq!(metrics.active_connections, 0);
        assert_eq!(metrics.idle_connections, 0);
        assert_eq!(metrics.total_created, 0);
        assert_eq!(metrics.total_closed, 0);
    }
}