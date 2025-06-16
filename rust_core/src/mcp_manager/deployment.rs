//! Deployment management for MCP servers

use crate::mcp_manager::{
    config::{ DeploymentStrategy, McpConfig, ServerConfig},
    errors::{McpError, Result},
    registry::ServerRegistry,
    server::{McpServer},
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{interval, Duration};

/// Deployment state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeploymentState {
    /// Not deployed
    NotDeployed,
    /// Deployment in progress
    Deploying,
    /// Deployed and running
    Deployed,
    /// Deployment failed
    Failed(String),
    /// Scaling in progress
    Scaling,
    /// Updating in progress
    Updating,
}

/// Deployment info
#[derive(Debug, Clone)]
pub struct DeploymentInfo {
    /// Server configuration
    pub config: ServerConfig,
    /// Current state
    pub state: DeploymentState,
    /// Number of instances
    pub instances: usize,
    /// CPU usage percentage
    pub cpu_usage: f64,
    /// Memory usage percentage
    pub memory_usage: f64,
    /// Last deployment time
    pub last_deployment: Option<std::time::Instant>,
}

/// Deployment manager for MCP servers
pub struct DeploymentManager {
    /// Server registry
    registry: Arc<RwLock<ServerRegistry>>,
    /// Configuration
    config: Arc<McpConfig>,
    /// Deployment information
    deployments: Arc<Mutex<HashMap<String, DeploymentInfo>>>,
    /// Auto-scaling enabled
    auto_scaling: Arc<Mutex<bool>>,
    /// Running flag
    running: Arc<Mutex<bool>>,
}

impl DeploymentManager {
    /// Create a new deployment manager
    pub fn new(registry: Arc<RwLock<ServerRegistry>>, config: Arc<McpConfig>) -> Self {
        Self {
            registry,
            config,
            deployments: Arc::new(Mutex::new(HashMap::new())),
            auto_scaling: Arc::new(Mutex::new(true)),
            running: Arc::new(Mutex::new(false)),
        }
    }

    /// Initialize deployment manager
    pub async fn initialize(&self) -> Result<()> {
        *self.running.lock().await = true;
        
        // Deploy initial servers from configuration
        for server_config in &self.config.servers {
            let id = &server_config.name;
            self.deploy_server(id.clone(), server_config.clone()).await?;
        }
        
        // Start auto-scaling if enabled
        if self.config.deployment.auto_scaling {
            self.start_auto_scaling().await?;
        }
        
        Ok(())
    }

    /// Deploy a new server
    pub async fn deploy_server(
        &self,
        id: String,
        config: ServerConfig,
    ) -> Result<Arc<McpServer>> {
        // Update deployment state
        {
            let mut deployments = self.deployments.lock().await;
            deployments.insert(id.clone(), DeploymentInfo {
                config: config.clone(),
                state: DeploymentState::Deploying,
                instances: 1,
                cpu_usage: 0.0,
                memory_usage: 0.0,
                last_deployment: Some(std::time::Instant::now()),
            });
        }
        
        // Create and initialize server
        let server = Arc::new(McpServer::new(id.clone(), config.clone())?);
        server.initialize().await?;
        
        // Register with registry
        {
            let mut registry = self.registry.write().await;
            registry.register(config.name.clone(), server.clone()).await?;
        }
        
        // Update deployment state
        {
            let mut deployments = self.deployments.lock().await;
            if let Some(info) = deployments.get_mut(&id) {
                info.state = DeploymentState::Deployed;
            }
        }
        
        Ok(server)
    }

    /// Undeploy a server
    pub async fn undeploy_server(&self, id: &str) -> Result<()> {
        // Get server from registry and unregister
        let server = {
            let registry = self.registry.read().await;
            let server = registry.get(id).ok_or_else(|| 
                McpError::NotFound(format!("Server {} not found", id))
            )?;
            server.clone()
        };
        
        // Shutdown server
        server.shutdown().await?;
        
        // Unregister from registry
        {
            let mut registry = self.registry.write().await;
            registry.unregister(id).await?;
        }
        
        // Remove deployment info
        self.deployments.lock().await.remove(id);
        
        Ok(())
    }

    /// Update server deployment
    pub async fn update_server(
        &self,
        id: &str,
        new_config: ServerConfig,
    ) -> Result<Arc<McpServer>> {
        // Update deployment state
        {
            let mut deployments = self.deployments.lock().await;
            if let Some(info) = deployments.get_mut(id) {
                info.state = DeploymentState::Updating;
            }
        }
        
        // Perform update based on strategy
        let server = match &self.config.deployment.strategy {
            DeploymentStrategy::RollingUpdate => {
                self.rolling_update(id, new_config.clone()).await?
            }
            DeploymentStrategy::BlueGreen => {
                self.blue_green_update(id, new_config.clone()).await?
            }
            DeploymentStrategy::Canary { percentage } => {
                self.canary_update(id, new_config.clone(), *percentage).await?
            }
            DeploymentStrategy::Recreate => {
                // Simple recreate strategy: stop old, start new
                self.undeploy_server(id).await?;
                self.deploy_server(id.to_string(), new_config.clone()).await?
            }
        };
        
        // Update deployment state
        {
            let mut deployments = self.deployments.lock().await;
            if let Some(info) = deployments.get_mut(id) {
                info.state = DeploymentState::Deployed;
                info.config = new_config;
            }
        }
        
        Ok(server)
    }

    /// Scale server deployment
    pub async fn scale_server(&self, id: &str, instances: usize) -> Result<()> {
        // Update deployment state
        {
            let mut deployments = self.deployments.lock().await;
            if let Some(info) = deployments.get_mut(id) {
                info.state = DeploymentState::Scaling;
                info.instances = instances;
            } else {
                return Err(McpError::ServerNotFound(id.to_string()));
            }
        }
        
        // In a real implementation, this would:
        // 1. Create or destroy server instances
        // 2. Update load balancer configuration
        // 3. Ensure health checks pass
        
        // Update deployment state
        {
            let mut deployments = self.deployments.lock().await;
            if let Some(info) = deployments.get_mut(id) {
                info.state = DeploymentState::Deployed;
            }
        }
        
        Ok(())
    }

    /// Get deployment info
    pub async fn get_deployment(&self, id: &str) -> Option<DeploymentInfo> {
        self.deployments.lock().await.get(id).cloned()
    }

    /// Get all deployments
    pub async fn list_deployments(&self) -> Vec<(String, DeploymentInfo)> {
        self.deployments.lock().await
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<(String, DeploymentInfo)>>()
    }

    /// Start auto-scaling
    async fn start_auto_scaling(&self) -> Result<()> {
        let manager = self.clone_for_task();
        
        tokio::spawn(async move {
            let mut check_interval = interval(Duration::from_secs(60));
            
            // Check both conditions separately to avoid nested locks
            let running = *manager.running.lock().await;
            let auto_scaling = *manager.auto_scaling.lock().await;
            while running && auto_scaling {
                check_interval.tick().await;
                
                // Check each deployment
                let deployments = manager.deployments.lock().await.clone();
                
                for (id, info) in deployments {
                    if info.state != DeploymentState::Deployed {
                        continue;
                    }
                    
                    // Check CPU usage
                    if info.cpu_usage > manager.config.deployment.scale_up_threshold {
                        let new_instances = std::cmp::min(
                            info.instances + 1,
                            manager.config.deployment.max_instances,
                        );
                        
                        if new_instances > info.instances {
                            let _ = manager.scale_server(&id, new_instances).await;
                        }
                    } else if info.cpu_usage < manager.config.deployment.scale_down_threshold {
                        let new_instances = std::cmp::max(
                            info.instances.saturating_sub(1),
                            manager.config.deployment.min_instances,
                        );
                        
                        if new_instances < info.instances {
                            let _ = manager.scale_server(&id, new_instances).await;
                        }
                    }
                }
            }
        });
        
        Ok(())
    }

    /// Perform rolling update
    async fn rolling_update(
        &self,
        id: &str,
        new_config: ServerConfig,
    ) -> Result<Arc<McpServer>> {
        // In a real implementation:
        // 1. Create new server with new config
        // 2. Wait for health check
        // 3. Gradually shift traffic
        // 4. Remove old server
        
        // For now, just replace the server
        self.undeploy_server(id).await?;
        self.deploy_server(id.to_string(), new_config).await
    }

    /// Perform blue-green update
    async fn blue_green_update(
        &self,
        id: &str,
        new_config: ServerConfig,
    ) -> Result<Arc<McpServer>> {
        // In a real implementation:
        // 1. Deploy new version (green) alongside old (blue)
        // 2. Test green deployment
        // 3. Switch traffic to green
        // 4. Keep blue as backup
        // 5. Remove blue after validation
        
        // For now, just replace the server
        self.undeploy_server(id).await?;
        self.deploy_server(id.to_string(), new_config).await
    }

    /// Perform canary update
    async fn canary_update(
        &self,
        id: &str,
        new_config: ServerConfig,
        _percentage: u8,
    ) -> Result<Arc<McpServer>> {
        // In a real implementation:
        // 1. Deploy new version for percentage of traffic
        // 2. Monitor metrics and errors
        // 3. Gradually increase percentage
        // 4. Full rollout or rollback based on metrics
        
        // For now, just replace the server
        self.undeploy_server(id).await?;
        self.deploy_server(id.to_string(), new_config).await
    }

    /// Shutdown deployment manager
    pub async fn shutdown(&self) -> Result<()> {
        *self.running.lock().await = false;
        *self.auto_scaling.lock().await = false;
        
        // Undeploy all servers
        let deployments: Vec<String> = self.deployments.lock().await
            .keys()
            .cloned()
            .collect();
        
        for id in deployments {
            let _ = self.undeploy_server(&id).await;
        }
        
        Ok(())
    }

    /// Clone for background task
    fn clone_for_task(&self) -> Self {
        Self {
            registry: self.registry.clone(),
            config: self.config.clone(),
            deployments: self.deployments.clone(),
            auto_scaling: self.auto_scaling.clone(),
            running: self.running.clone(),
        }
    }

    /// Update deployment metrics
    pub async fn update_metrics(&self, id: &str, cpu: f64, memory: f64) {
        let mut deployments = self.deployments.lock().await;
        if let Some(info) = deployments.get_mut(id) {
            info.cpu_usage = cpu;
            info.memory_usage = memory;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_manager::config::{AuthConfig, ServerType};

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
    async fn test_deployment_manager_creation() {
        let registry = Arc::new(RwLock::new(ServerRegistry::new()));
        let config = Arc::new(McpConfig::default());
        let manager = DeploymentManager::new(registry, config);
        
        assert!(manager.initialize().await.is_ok());
    }

    #[tokio::test]
    async fn test_deploy_server() {
        let registry = Arc::new(RwLock::new(ServerRegistry::new()));
        let config = Arc::new(McpConfig::default());
        let manager = DeploymentManager::new(registry.clone(), config);
        
        let server_config = create_test_config();
        let server = manager.deploy_server("test-1".to_string(), server_config).await.unwrap();
        
        assert_eq!(server.id(), "test-1");
        
        // Verify server is in registry
        let reg = registry.read().await;
        assert!(reg.get("test-1").is_some());
    }

    #[tokio::test]
    async fn test_deployment_info() {
        let registry = Arc::new(RwLock::new(ServerRegistry::new()));
        let config = Arc::new(McpConfig::default());
        let manager = DeploymentManager::new(registry, config);
        
        let server_config = create_test_config();
        manager.deploy_server("test-1".to_string(), server_config).await.unwrap();
        
        let info = manager.get_deployment("test-1").await.unwrap();
        assert_eq!(info.state, DeploymentState::Deployed);
        assert_eq!(info.instances, 1);
    }
}