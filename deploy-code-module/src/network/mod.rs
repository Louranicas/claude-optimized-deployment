use anyhow::Result;
use std::sync::Arc;
use std::collections::HashSet;
use tokio::sync::RwLock;
use dashmap::DashMap;
use tracing::{info, debug, warn};

use crate::config::DeploymentConfig;

pub struct NetworkManager {
    config: Arc<DeploymentConfig>,
    allocated_ports: Arc<RwLock<HashSet<u16>>>,
    service_ports: Arc<DashMap<String, Vec<u16>>>,
}

impl NetworkManager {
    pub fn new(config: Arc<DeploymentConfig>) -> Self {
        Self {
            config,
            allocated_ports: Arc::new(RwLock::new(HashSet::new())),
            service_ports: Arc::new(DashMap::new()),
        }
    }
    
    pub async fn validate_configuration(&self) -> Result<()> {
        info!("Validating network configuration...");
        
        // Check port range
        let port_range = &self.config.infrastructure.network.port_range;
        if port_range.start() >= port_range.end() {
            return Err(anyhow::anyhow!("Invalid port range configuration"));
        }
        
        // Check for port conflicts
        let mut required_ports = HashSet::new();
        for (service_name, service_config) in &self.config.services {
            if service_config.enabled {
                for port_config in &service_config.ports {
                    let port = port_config.host_port.unwrap_or(port_config.container_port);
                    if !required_ports.insert(port) {
                        return Err(anyhow::anyhow!(
                            "Port {} is required by multiple services",
                            port
                        ));
                    }
                }
            }
        }
        
        info!("Network configuration validation passed");
        Ok(())
    }
    
    pub async fn allocate_port(&self, service: &str) -> Result<u16> {
        let mut allocated = self.allocated_ports.write().await;
        let port_range = &self.config.infrastructure.network.port_range;
        
        // Find first available port in range
        for port in *port_range.start()..=*port_range.end() {
            if !allocated.contains(&port) {
                allocated.insert(port);
                
                // Track port allocation for service
                self.service_ports
                    .entry(service.to_string())
                    .or_insert_with(Vec::new)
                    .push(port);
                
                debug!("Allocated port {} for service {}", port, service);
                return Ok(port);
            }
        }
        
        Err(anyhow::anyhow!("No available ports in configured range"))
    }
    
    pub async fn allocate_ports(&self, requirements: Vec<(String, u16)>) -> Result<()> {
        let mut allocated = self.allocated_ports.write().await;
        
        // Validate all ports are available first
        for (service, port) in &requirements {
            if allocated.contains(port) {
                return Err(anyhow::anyhow!(
                    "Port {} requested by {} is already allocated",
                    port,
                    service
                ));
            }
        }
        
        // Allocate all ports
        for (service, port) in requirements {
            allocated.insert(port);
            self.service_ports
                .entry(service.clone())
                .or_insert_with(Vec::new)
                .push(port);
        }
        
        info!("Port allocation completed successfully");
        Ok(())
    }
    
    pub async fn deallocate_service_ports(&self, service: &str) -> Result<()> {
        if let Some((_, ports)) = self.service_ports.remove(service) {
            let mut allocated = self.allocated_ports.write().await;
            for port in ports {
                allocated.remove(&port);
            }
            debug!("Deallocated ports for service {}", service);
        }
        Ok(())
    }
    
    pub async fn setup_service_mesh(&self) -> Result<()> {
        info!("Setting up service mesh...");
        
        // In a real implementation, this would:
        // 1. Configure Istio/Linkerd
        // 2. Set up mTLS between services
        // 3. Configure traffic policies
        // 4. Set up observability
        
        // For now, just log
        info!("Service mesh setup completed (simulated)");
        Ok(())
    }
    
    pub async fn get_service_ports(&self, service: &str) -> Vec<u16> {
        self.service_ports
            .get(service)
            .map(|ports| ports.clone())
            .unwrap_or_default()
    }
    
    pub async fn get_allocated_ports(&self) -> Vec<u16> {
        let allocated = self.allocated_ports.read().await;
        allocated.iter().cloned().collect()
    }
}