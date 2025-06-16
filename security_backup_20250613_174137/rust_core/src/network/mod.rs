//! Network management modules
//! 
//! Provides port allocation, service mesh integration, and load balancing
//! capabilities.

pub mod port_allocator;
pub mod service_mesh;
pub mod load_balancer;

use std::sync::Arc;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::sync::RwLock;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use dashmap::DashMap;

pub use port_allocator::{PortAllocator, PortAllocation};
pub use service_mesh::{ServiceMesh, MeshConfig};
pub use load_balancer::{LoadBalancer, LoadBalancerBackend};

use crate::orchestrator::{NetworkConfig, Protocol, LoadBalancerConfig};

/// Network management result type
pub type NetworkResult<T> = Result<T, NetworkError>;

/// Network management errors
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("Port not available: {0}")]
    PortNotAvailable(u16),
    
    #[error("Invalid port range: {0}")]
    InvalidPortRange(String),
    
    #[error("Network resource not found: {0}")]
    ResourceNotFound(String),
    
    #[error("Service mesh error: {0}")]
    ServiceMeshError(String),
    
    #[error("Load balancer error: {0}")]
    LoadBalancerError(String),
    
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Network allocator for unified network management
pub struct NetworkAllocator {
    port_allocator: Arc<PortAllocator>,
    service_mesh: Arc<ServiceMesh>,
    load_balancers: Arc<DashMap<Uuid, LoadBalancer>>,
}

impl NetworkAllocator {
    /// Create a new network allocator
    pub fn new() -> Self {
        Self {
            port_allocator: Arc::new(PortAllocator::new()),
            service_mesh: Arc::new(ServiceMesh::new(MeshConfig::default())),
            load_balancers: Arc::new(DashMap::new()),
        }
    }
    
    /// Allocate a port for a service
    pub async fn allocate_port(
        &self,
        service_id: &Uuid,
        protocol: Protocol,
    ) -> Result<NetworkConfig, crate::orchestrator::OrchestratorError> {
        let port_allocation = self.port_allocator
            .allocate_port(service_id, protocol)
            .await
            .map_err(|e| crate::orchestrator::OrchestratorError::NetworkAllocationFailed(e.to_string()))?;
        
        Ok(NetworkConfig {
            internal_port: port_allocation.port,
            external_port: port_allocation.external_port,
            protocol,
            service_mesh_enabled: false,
            load_balancer_config: None,
        })
    }
    
    /// Release port allocation
    pub async fn release_port(&self, service_id: &Uuid) -> Result<(), crate::orchestrator::OrchestratorError> {
        self.port_allocator
            .release_port(service_id)
            .await
            .map_err(|e| crate::orchestrator::OrchestratorError::NetworkAllocationFailed(e.to_string()))
    }
    
    /// Enable service mesh for a service
    pub async fn enable_service_mesh(
        &self,
        service_id: &Uuid,
        service_name: String,
    ) -> NetworkResult<()> {
        self.service_mesh.register_service(service_id, service_name).await
    }
    
    /// Create load balancer for a service
    pub async fn create_load_balancer(
        &self,
        service_id: &Uuid,
        config: LoadBalancerConfig,
    ) -> NetworkResult<()> {
        let lb = LoadBalancer::new(config);
        self.load_balancers.insert(*service_id, lb);
        Ok(())
    }
}