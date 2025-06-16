//! High-performance orchestration engine for CODE deployment
//! 
//! This module provides the core orchestration functionality for managing
//! distributed services with sub-millisecond registration and deployment.

pub mod engine;
pub mod scheduler;
pub mod executor;

pub use engine::{OrchestrationEngine, EngineConfig};
pub use scheduler::{Scheduler, SchedulerConfig, DeploymentTask};
pub use executor::{Executor, ExecutorConfig, ExecutionResult};




use uuid::Uuid;
use serde::{Deserialize, Serialize};

/// Result type for orchestration operations
pub type OrchestratorResult<T> = Result<T, OrchestratorError>;

/// Orchestration errors
#[derive(Debug, thiserror::Error)]
pub enum OrchestratorError {
    #[error("Service not found: {0}")]
    ServiceNotFound(String),
    
    #[error("Resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),
    
    #[error("Deployment failed: {0}")]
    DeploymentFailed(String),
    
    #[error("Network allocation failed: {0}")]
    NetworkAllocationFailed(String),
    
    #[error("Health check failed: {0}")]
    HealthCheckFailed(String),
    
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("Lock acquisition failed: {0}")]
    LockError(String),
    
    #[error("Communication error: {0}")]
    CommunicationError(String),
    
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    
    #[error(transparent)]
    SerdeError(#[from] serde_json::Error),
    
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Convert ResourceError to OrchestratorError
impl From<crate::resources::ResourceError> for OrchestratorError {
    fn from(err: crate::resources::ResourceError) -> Self {
        match err {
            crate::resources::ResourceError::InsufficientResources(msg) => 
                OrchestratorError::ResourceLimitExceeded(msg),
            _ => OrchestratorError::Other(anyhow::anyhow!("Resource error: {:?}", err)),
        }
    }
}

/// Service deployment state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DeploymentState {
    Pending,
    Initializing,
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed,
    Recovering,
}

/// Service metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceMetadata {
    pub id: Uuid,
    pub name: String,
    pub version: String,
    pub state: DeploymentState,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub health_status: HealthStatus,
    pub resource_usage: ResourceUsage,
    pub network_config: NetworkConfig,
}

/// Health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub is_healthy: bool,
    pub last_check: chrono::DateTime<chrono::Utc>,
    pub consecutive_failures: u32,
    pub latency_ms: f64,
    pub error_rate: f64,
}

/// Resource usage metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub cpu_percent: f64,
    pub memory_mb: u64,
    pub disk_mb: u64,
    pub network_rx_mbps: f64,
    pub network_tx_mbps: f64,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub internal_port: u16,
    pub external_port: Option<u16>,
    pub protocol: Protocol,
    pub service_mesh_enabled: bool,
    pub load_balancer_config: Option<LoadBalancerConfig>,
}

/// Network protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Http,
    Https,
    Grpc,
    WebSocket,
}

/// Load balancer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancerConfig {
    pub algorithm: LoadBalancingAlgorithm,
    pub health_check_interval_secs: u64,
    pub max_connections: u32,
    pub sticky_sessions: bool,
}

/// Load balancing algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoadBalancingAlgorithm {
    RoundRobin,
    LeastConnections,
    WeightedRoundRobin,
    Random,
    IpHash,
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self {
            is_healthy: true,
            last_check: chrono::Utc::now(),
            consecutive_failures: 0,
            latency_ms: 0.0,
            error_rate: 0.0,
        }
    }
}

impl Default for ResourceUsage {
    fn default() -> Self {
        Self {
            cpu_percent: 0.0,
            memory_mb: 0,
            disk_mb: 0,
            network_rx_mbps: 0.0,
            network_tx_mbps: 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deployment_state_transitions() {
        let state = DeploymentState::Pending;
        assert_eq!(state, DeploymentState::Pending);
    }

    #[test]
    fn test_service_metadata_creation() {
        let metadata = ServiceMetadata {
            id: Uuid::new_v4(),
            name: "test-service".to_string(),
            version: "1.0.0".to_string(),
            state: DeploymentState::Pending,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            health_status: HealthStatus::default(),
            resource_usage: ResourceUsage::default(),
            network_config: NetworkConfig {
                internal_port: 8080,
                external_port: Some(80),
                protocol: Protocol::Http,
                service_mesh_enabled: true,
                load_balancer_config: None,
            },
        };
        
        assert_eq!(metadata.name, "test-service");
        assert_eq!(metadata.state, DeploymentState::Pending);
    }
}