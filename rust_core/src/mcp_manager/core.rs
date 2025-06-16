use crate::mcp_manager::{
    config::MCPConfig,
    error::{MCPError, MCPResult},
    server::{MCPServer, ServerState},
    registry::ServerRegistry,
    load_balancer::{LoadBalancer, LoadBalancingStrategy},
    health_check::HealthChecker,
    metrics::MCPMetrics,
    protocol::{MCPRequest, MCPResponse, MCPConnection},
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};

/// High-performance MCP Manager
pub struct MCPManager {
    config: MCPConfig,
    registry: Arc<RwLock<ServerRegistry>>,
    load_balancer: Arc<LoadBalancer>,
    health_checker: Arc<HealthChecker>,
    metrics: Arc<MCPMetrics>,
}

impl MCPManager {
    /// Create a new MCP Manager instance
    pub fn new(config: MCPConfig) -> Self {
        let registry = Arc::new(RwLock::new(ServerRegistry::new()));
        let load_balancer = Arc::new(LoadBalancer::new(LoadBalancingStrategy::RoundRobin));
        let health_checker = Arc::new(HealthChecker::new(config.health_check_interval()));
        let metrics = Arc::new(MCPMetrics::new());
        
        Self {
            config,
            registry,
            load_balancer,
            health_checker,
            metrics,
        }
    }
    
    /// Register a new MCP server
    pub async fn register_server(&self, server: MCPServer) -> MCPResult<()> {
        info!("Registering MCP server: {}", server.id());
        
        // Add to registry
        self.registry.write().await.register(server.clone())?;
        
        // Initialize connection pool for this server
        if self.config.enable_connection_pooling {
            // Connection pools are now managed per-server
            server.initialize().await?;
        }
        
        // Start health checks
        if self.config.enable_health_checks {
            self.health_checker.start_monitoring(server.clone()).await;
        }
        
        self.metrics.increment_server_count();
        Ok(())
    }
    
    /// Unregister an MCP server
    pub async fn unregister_server(&self, server_id: &str) -> MCPResult<()> {
        info!("Unregistering MCP server: {}", server_id);
        
        // Stop health checks
        if self.config.enable_health_checks {
            self.health_checker.stop_monitoring(server_id).await;
        }
        
        // Close connections
        if self.config.enable_connection_pooling {
            // Get server and shutdown its pool
            if let Some(server) = self.registry.read().await.get(server_id) {
                server.shutdown().await?;
            }
        }
        
        // Remove from registry
        self.registry.write().await.unregister(server_id)?;
        
        self.metrics.decrement_server_count();
        Ok(())
    }
    
    /// Send a request to an MCP server
    pub async fn send_request(&self, request: MCPRequest) -> MCPResult<MCPResponse> {
        self.metrics.increment_request_count();
        let start = std::time::Instant::now();
        
        // Select server based on load balancing strategy
        let server = if self.config.enable_load_balancing {
            self.select_server_with_load_balancing(&request).await?
        } else {
            self.select_any_healthy_server().await?
        };
        
        debug!("Sending request to server: {}", server.id());
        
        // Execute request through server (which handles pooling internally)
        let response = self.send_with_retry(&server, request).await?;
        
        // Update metrics
        self.metrics.record_request_duration(start.elapsed());
        
        Ok(response)
    }
    
    /// Get all registered servers
    pub async fn get_servers(&self) -> Vec<MCPServer> {
        self.registry.read().await.get_all()
    }
    
    /// Get server by ID
    pub async fn get_server(&self, server_id: &str) -> Option<MCPServer> {
        self.registry.read().await.get(server_id).map(|arc| (*arc).clone())
    }
    
    /// Get current metrics
    pub fn get_metrics(&self) -> &MCPMetrics {
        &self.metrics
    }
    
    // Private helper methods
    
    async fn select_server_with_load_balancing(&self, request: &MCPRequest) -> MCPResult<MCPServer> {
        let servers = self.registry.read().await.get_healthy_servers();
        if servers.is_empty() {
            return Err(MCPError::LoadBalancing("No healthy servers available".to_string()));
        }
        
        self.load_balancer.select_server(&servers, request).await
    }
    
    async fn select_any_healthy_server(&self) -> MCPResult<MCPServer> {
        let servers = self.registry.read().await.get_healthy_servers();
        servers.into_iter().next()
            .ok_or_else(|| MCPError::LoadBalancing("No healthy servers available".to_string()))
    }
    
    async fn send_with_retry(
        &self,
        server: &MCPServer,
        request: MCPRequest,
    ) -> MCPResult<MCPResponse> {
        let mut attempts = 0;
        let mut last_error = None;
        
        while attempts < self.config.max_retries {
            match server.execute::<MCPRequest, MCPResponse>(request.clone()).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    attempts += 1;
                    last_error = Some(e);
                    
                    if attempts < self.config.max_retries {
                        let backoff = (self.config.retry_backoff_multiplier.powi(attempts as i32 - 1) * 1000.0) as u64;
                        warn!("Request failed, retrying in {}ms (attempt {}/{})", backoff, attempts, self.config.max_retries);
                        tokio::time::sleep(tokio::time::Duration::from_millis(backoff)).await;
                    }
                }
            }
        }
        
        error!("Request failed after {} attempts", self.config.max_retries);
        Err(last_error.unwrap_or_else(|| MCPError::Internal("Unknown error".to_string())))
    }
}