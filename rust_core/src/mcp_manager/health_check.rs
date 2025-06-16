use crate::mcp_manager::{
    server::{MCPServer, ServerState},
    protocol::{MCPRequest, MCPResponse},
    error::MCPResult,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use tokio::task::JoinHandle;
use tracing::{info, warn, error};

/// Health status for a server
#[derive(Debug, Clone)]
pub struct HealthStatus {
    pub is_healthy: bool,
    pub last_check: std::time::Instant,
    pub consecutive_failures: u32,
    pub last_error: Option<String>,
    pub response_time: Option<Duration>,
}

impl HealthStatus {
    /// Create a healthy status
    pub fn healthy() -> Self {
        Self {
            is_healthy: true,
            last_check: std::time::Instant::now(),
            consecutive_failures: 0,
            last_error: None,
            response_time: None,
        }
    }
    
    /// Create an unhealthy status
    pub fn unhealthy(error: impl Into<String>) -> Self {
        Self {
            is_healthy: false,
            last_check: std::time::Instant::now(),
            consecutive_failures: 1,
            last_error: Some(error.into()),
            response_time: None,
        }
    }
}

/// Health checker for MCP servers
pub struct HealthChecker {
    check_interval: Duration,
    status_map: Arc<RwLock<HashMap<String, HealthStatus>>>,
    monitoring_tasks: Arc<RwLock<HashMap<String, JoinHandle<()>>>>,
}

impl HealthChecker {
    /// Create a new health checker
    pub fn new(check_interval: Duration) -> Self {
        Self {
            check_interval,
            status_map: Arc::new(RwLock::new(HashMap::new())),
            monitoring_tasks: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Start monitoring a server
    pub async fn start_monitoring(&self, server: MCPServer) {
        let server_id = server.id().to_string();
        let check_interval = self.check_interval;
        let status_map = self.status_map.clone();
        
        // Create monitoring task
        let task = tokio::spawn(async move {
            let mut interval = interval(check_interval);
            interval.tick().await; // Skip first immediate tick
            
            loop {
                interval.tick().await;
                
                // Perform health check
                let start = std::time::Instant::now();
                let health_request = MCPRequest::new("health", serde_json::json!({}));
                
                match server.connect(Duration::from_secs(5)).await {
                    Ok(connection) => {
                        match connection.send_request(health_request).await {
                            Ok(response) => {
                                let response_time = start.elapsed();
                                let mut status_map = status_map.write().await;
                                
                                if response.error.is_none() {
                                    // Healthy response
                                    server.set_state(ServerState::Healthy).await;
                                    status_map.insert(server_id.clone(), HealthStatus {
                                        is_healthy: true,
                                        last_check: std::time::Instant::now(),
                                        consecutive_failures: 0,
                                        last_error: None,
                                        response_time: Some(response_time),
                                    });
                                } else {
                                    // Error response
                                    handle_unhealthy_response(
                                        &server,
                                        &server_id,
                                        &mut status_map,
                                        format!("Error response: {:?}", response.error),
                                    ).await;
                                }
                            }
                            Err(e) => {
                                // Request failed
                                let mut status_map = status_map.write().await;
                                handle_unhealthy_response(
                                    &server,
                                    &server_id,
                                    &mut status_map,
                                    format!("Request failed: {}", e),
                                ).await;
                            }
                        }
                    }
                    Err(e) => {
                        // Connection failed
                        let mut status_map = status_map.write().await;
                        handle_unhealthy_response(
                            &server,
                            &server_id,
                            &mut status_map,
                            format!("Connection failed: {}", e),
                        ).await;
                    }
                }
            }
        });
        
        // Store task handle
        self.monitoring_tasks.write().await.insert(server_id, task);
    }
    
    /// Stop monitoring a server
    pub async fn stop_monitoring(&self, server_id: &str) {
        // Cancel monitoring task
        if let Some(task) = self.monitoring_tasks.write().await.remove(server_id) {
            task.abort();
        }
        
        // Remove status
        self.status_map.write().await.remove(server_id);
    }
    
    /// Get health status for a server
    pub async fn get_status(&self, server_id: &str) -> Option<HealthStatus> {
        self.status_map.read().await.get(server_id).cloned()
    }
    
    /// Get all health statuses
    pub async fn get_all_statuses(&self) -> HashMap<String, HealthStatus> {
        self.status_map.read().await.clone()
    }
    
    /// Check if a server is healthy
    pub async fn is_healthy(&self, server_id: &str) -> bool {
        self.status_map
            .read()
            .await
            .get(server_id)
            .map(|s| s.is_healthy)
            .unwrap_or(false)
    }
}

async fn handle_unhealthy_response(
    server: &MCPServer,
    server_id: &str,
    status_map: &mut HashMap<String, HealthStatus>,
    error: String,
) {
    let consecutive_failures = status_map
        .get(server_id)
        .map(|s| s.consecutive_failures + 1)
        .unwrap_or(1);
    
    // Update server state based on consecutive failures
    let state = if consecutive_failures >= 5 {
        ServerState::Unhealthy
    } else if consecutive_failures >= 2 {
        ServerState::Degraded
    } else {
        ServerState::Degraded
    };
    
    server.set_state(state).await;
    
    status_map.insert(server_id.to_string(), HealthStatus {
        is_healthy: false,
        last_check: std::time::Instant::now(),
        consecutive_failures,
        last_error: Some(error),
        response_time: None,
    });
    
    warn!(
        "Server {} health check failed ({} consecutive failures): {}",
        server_id, consecutive_failures, error
    );
}