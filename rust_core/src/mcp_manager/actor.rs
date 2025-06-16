//! Actor-based message passing architecture for MCP Manager
//! 
//! This module implements the core actor model that replaces shared state
//! with message passing, eliminating lock contention and improving scalability.

use crate::mcp_manager::{
    config::{McpManagerConfig, ServerConfig},
    errors::{McpError, Result},
    server::McpServer,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};
use serde::{Serialize, Deserialize};

/// Server identifier type
pub type ServerId = String;

/// Commands that can be sent to the MCP runtime
#[derive(Debug)]
pub enum McpCommand {
    /// Deploy a new server
    Deploy {
        config: ServerConfig,
        response: oneshot::Sender<Result<ServerId>>,
    },
    
    /// Undeploy a server
    Undeploy {
        server_id: ServerId,
        response: oneshot::Sender<Result<()>>,
    },
    
    /// Execute a request on a server
    Execute {
        server_id: ServerId,
        request: serde_json::Value,
        response: oneshot::Sender<Result<serde_json::Value>>,
    },
    
    /// Get server health status
    HealthCheck {
        server_id: ServerId,
        response: oneshot::Sender<Result<bool>>,
    },
    
    /// List all deployed servers
    ListServers {
        response: oneshot::Sender<Vec<ServerId>>,
    },
    
    /// Get server metrics
    GetMetrics {
        server_id: Option<ServerId>,
        response: oneshot::Sender<Result<Metrics>>,
    },
    
    /// Update server configuration
    UpdateConfig {
        server_id: ServerId,
        config: ServerConfig,
        response: oneshot::Sender<Result<()>>,
    },
    
    /// Shutdown the runtime
    Shutdown {
        response: oneshot::Sender<()>,
    },
}

/// Runtime metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metrics {
    /// Total commands processed
    pub total_commands: u64,
    /// Successful commands
    pub successful_commands: u64,
    /// Failed commands
    pub failed_commands: u64,
    /// Active servers
    pub active_servers: usize,
    /// Command queue depth
    pub queue_depth: usize,
    /// Average command latency in microseconds
    pub avg_latency_us: u64,
}

/// The main MCP runtime actor
pub struct McpRuntime {
    /// Handle to the background task
    handle: JoinHandle<()>,
    /// Command sender
    command_tx: mpsc::Sender<McpCommand>,
}

impl McpRuntime {
    /// Create a new MCP runtime
    pub fn new(config: McpManagerConfig) -> Self {
        let (command_tx, command_rx) = mpsc::channel(100); // Bounded channel for backpressure
        
        let actor = RuntimeActor::new(config, command_rx);
        let handle = tokio::spawn(async move {
            actor.run().await;
        });
        
        Self {
            handle,
            command_tx,
        }
    }
    
    /// Deploy a new server
    pub async fn deploy(&self, config: ServerConfig) -> Result<ServerId> {
        let (response_tx, response_rx) = oneshot::channel();
        
        self.command_tx
            .send(McpCommand::Deploy { config, response: response_tx })
            .await
            .map_err(|_| McpError::RuntimeShutdown)?;
            
        response_rx.await
            .map_err(|_| McpError::RuntimeShutdown)?
    }
    
    /// Undeploy a server
    pub async fn undeploy(&self, server_id: &str) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();
        
        self.command_tx
            .send(McpCommand::Undeploy {
                server_id: server_id.to_string(),
                response: response_tx,
            })
            .await
            .map_err(|_| McpError::RuntimeShutdown)?;
            
        response_rx.await
            .map_err(|_| McpError::RuntimeShutdown)?
    }
    
    /// Execute a request on a server
    pub async fn execute(
        &self,
        server_id: &str,
        request: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let (response_tx, response_rx) = oneshot::channel();
        
        self.command_tx
            .send(McpCommand::Execute {
                server_id: server_id.to_string(),
                request,
                response: response_tx,
            })
            .await
            .map_err(|_| McpError::RuntimeShutdown)?;
            
        response_rx.await
            .map_err(|_| McpError::RuntimeShutdown)?
    }
    
    /// Check server health
    pub async fn health_check(&self, server_id: &str) -> Result<bool> {
        let (response_tx, response_rx) = oneshot::channel();
        
        self.command_tx
            .send(McpCommand::HealthCheck {
                server_id: server_id.to_string(),
                response: response_tx,
            })
            .await
            .map_err(|_| McpError::RuntimeShutdown)?;
            
        response_rx.await
            .map_err(|_| McpError::RuntimeShutdown)?
    }
    
    /// List all deployed servers
    pub async fn list_servers(&self) -> Result<Vec<ServerId>> {
        let (response_tx, response_rx) = oneshot::channel();
        
        self.command_tx
            .send(McpCommand::ListServers { response: response_tx })
            .await
            .map_err(|_| McpError::RuntimeShutdown)?;
            
        Ok(response_rx.await
            .map_err(|_| McpError::RuntimeShutdown)?)
    }
    
    /// Get runtime metrics
    pub async fn get_metrics(&self, server_id: Option<&str>) -> Result<Metrics> {
        let (response_tx, response_rx) = oneshot::channel();
        
        self.command_tx
            .send(McpCommand::GetMetrics {
                server_id: server_id.map(|s| s.to_string()),
                response: response_tx,
            })
            .await
            .map_err(|_| McpError::RuntimeShutdown)?;
            
        response_rx.await
            .map_err(|_| McpError::RuntimeShutdown)?
    }
    
    /// Shutdown the runtime gracefully
    pub async fn shutdown(self) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();
        
        self.command_tx
            .send(McpCommand::Shutdown { response: response_tx })
            .await
            .map_err(|_| McpError::RuntimeShutdown)?;
            
        response_rx.await
            .map_err(|_| McpError::RuntimeShutdown)?;
            
        self.handle.await
            .map_err(|e| McpError::InternalError(e.to_string()))?;
            
        Ok(())
    }
}

/// The internal runtime actor that processes commands
struct RuntimeActor {
    /// Configuration
    config: McpManagerConfig,
    /// Command receiver
    command_rx: mpsc::Receiver<McpCommand>,
    /// Active servers
    servers: HashMap<ServerId, Arc<McpServer>>,
    /// Runtime metrics
    metrics: Metrics,
    /// Start time for latency tracking
    start_time: std::time::Instant,
}

impl RuntimeActor {
    /// Create a new runtime actor
    fn new(config: McpManagerConfig, command_rx: mpsc::Receiver<McpCommand>) -> Self {
        Self {
            config,
            command_rx,
            servers: HashMap::new(),
            metrics: Metrics {
                total_commands: 0,
                successful_commands: 0,
                failed_commands: 0,
                active_servers: 0,
                queue_depth: 0,
                avg_latency_us: 0,
            },
            start_time: std::time::Instant::now(),
        }
    }
    
    /// Run the actor event loop
    async fn run(mut self) {
        info!("MCP Runtime actor started");
        
        while let Some(command) = self.command_rx.recv().await {
            let start = std::time::Instant::now();
            self.metrics.total_commands += 1;
            
            match command {
                McpCommand::Deploy { config, response } => {
                    let result = self.handle_deploy(config).await;
                    if result.is_ok() {
                        self.metrics.successful_commands += 1;
                    } else {
                        self.metrics.failed_commands += 1;
                    }
                    let _ = response.send(result);
                }
                
                McpCommand::Undeploy { server_id, response } => {
                    let result = self.handle_undeploy(&server_id).await;
                    if result.is_ok() {
                        self.metrics.successful_commands += 1;
                    } else {
                        self.metrics.failed_commands += 1;
                    }
                    let _ = response.send(result);
                }
                
                McpCommand::Execute { server_id, request, response } => {
                    let result = self.handle_execute(&server_id, request).await;
                    if result.is_ok() {
                        self.metrics.successful_commands += 1;
                    } else {
                        self.metrics.failed_commands += 1;
                    }
                    let _ = response.send(result);
                }
                
                McpCommand::HealthCheck { server_id, response } => {
                    let result = self.handle_health_check(&server_id).await;
                    if result.is_ok() {
                        self.metrics.successful_commands += 1;
                    } else {
                        self.metrics.failed_commands += 1;
                    }
                    let _ = response.send(result);
                }
                
                McpCommand::ListServers { response } => {
                    let servers = self.servers.keys().cloned().collect();
                    self.metrics.successful_commands += 1;
                    let _ = response.send(servers);
                }
                
                McpCommand::GetMetrics { server_id: _, response } => {
                    self.metrics.active_servers = self.servers.len();
                    self.metrics.queue_depth = self.command_rx.len();
                    let _ = response.send(Ok(self.metrics.clone()));
                    self.metrics.successful_commands += 1;
                }
                
                McpCommand::UpdateConfig { server_id, config, response } => {
                    let result = self.handle_update_config(&server_id, config).await;
                    if result.is_ok() {
                        self.metrics.successful_commands += 1;
                    } else {
                        self.metrics.failed_commands += 1;
                    }
                    let _ = response.send(result);
                }
                
                McpCommand::Shutdown { response } => {
                    info!("MCP Runtime shutting down");
                    self.handle_shutdown().await;
                    let _ = response.send(());
                    break;
                }
            }
            
            // Update average latency
            let latency = start.elapsed().as_micros() as u64;
            if self.metrics.total_commands == 1 {
                self.metrics.avg_latency_us = latency;
            } else {
                // Exponential moving average
                self.metrics.avg_latency_us = 
                    (self.metrics.avg_latency_us * 9 + latency) / 10;
            }
        }
        
        info!("MCP Runtime actor stopped");
    }
    
    /// Handle deploy command
    async fn handle_deploy(&mut self, config: ServerConfig) -> Result<ServerId> {
        let server_id = config.name.clone();
        
        if self.servers.contains_key(&server_id) {
            return Err(McpError::AlreadyExists(format!("Server {} already deployed", server_id)));
        }
        
        debug!("Deploying server: {}", server_id);
        
        let server = Arc::new(McpServer::new(server_id.clone(), config)?);
        server.initialize().await?;
        
        self.servers.insert(server_id.clone(), server);
        info!("✅ Deployed server: {}", server_id);
        
        Ok(server_id)
    }
    
    /// Handle undeploy command
    async fn handle_undeploy(&mut self, server_id: &str) -> Result<()> {
        let server = self.servers.remove(server_id)
            .ok_or_else(|| McpError::NotFound(format!("Server {} not found", server_id)))?;
            
        debug!("Undeploying server: {}", server_id);
        server.shutdown().await?;
        
        info!("✅ Undeployed server: {}", server_id);
        Ok(())
    }
    
    /// Handle execute command
    async fn handle_execute(
        &self,
        server_id: &str,
        request: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let server = self.servers.get(server_id)
            .ok_or_else(|| McpError::NotFound(format!("Server {} not found", server_id)))?;
            
        server.execute(request).await
    }
    
    /// Handle health check command
    async fn handle_health_check(&self, server_id: &str) -> Result<bool> {
        let server = self.servers.get(server_id)
            .ok_or_else(|| McpError::NotFound(format!("Server {} not found", server_id)))?;
            
        server.health_check().await
    }
    
    /// Handle config update command
    async fn handle_update_config(
        &mut self,
        server_id: &str,
        new_config: ServerConfig,
    ) -> Result<()> {
        // For now, we'll undeploy and redeploy
        // In the future, this could be more sophisticated
        self.handle_undeploy(server_id).await?;
        self.handle_deploy(new_config).await?;
        Ok(())
    }
    
    /// Handle shutdown
    async fn handle_shutdown(&mut self) {
        info!("Shutting down all servers...");
        
        for (id, server) in self.servers.drain() {
            if let Err(e) = server.shutdown().await {
                error!("Error shutting down server {}: {}", id, e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_manager::config::{ServerType, RetryPolicy};
    
    #[tokio::test]
    async fn test_runtime_lifecycle() {
        let config = McpManagerConfig::default();
        let runtime = McpRuntime::new(config);
        
        // List servers (should be empty)
        let servers = runtime.list_servers().await.unwrap();
        assert!(servers.is_empty());
        
        // Deploy a server
        let server_config = ServerConfig {
            name: "test-server".to_string(),
            server_type: ServerType::Docker,
            url: "http://localhost:8001".to_string(),
            port: 8001,
            auth: None,
            capabilities: vec![],
            max_connections: 10,
            timeout_ms: 5000,
            retry_policy: RetryPolicy::default(),
            priority: 5,
            tags: vec!["test".to_string()],
        };
        
        let server_id = runtime.deploy(server_config).await.unwrap();
        assert_eq!(server_id, "test-server");
        
        // List servers (should have one)
        let servers = runtime.list_servers().await.unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0], "test-server");
        
        // Get metrics
        let metrics = runtime.get_metrics(None).await.unwrap();
        assert_eq!(metrics.active_servers, 1);
        assert!(metrics.total_commands > 0);
        
        // Undeploy
        runtime.undeploy(&server_id).await.unwrap();
        
        // List servers (should be empty again)
        let servers = runtime.list_servers().await.unwrap();
        assert!(servers.is_empty());
        
        // Shutdown
        runtime.shutdown().await.unwrap();
    }
}