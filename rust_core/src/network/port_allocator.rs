//! Port allocation and management
//! 
//! Provides efficient port allocation with range management and
//! protocol-specific handling.

use super::*;
use std::collections::HashSet;
use parking_lot::RwLock as ParkingLotRwLock;
use tracing::{debug, instrument};
use crate::orchestrator::Protocol;

/// Port allocation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortAllocation {
    pub service_id: Uuid,
    pub port: u16,
    pub external_port: Option<u16>,
    pub protocol: Protocol,
    pub allocated_at: chrono::DateTime<chrono::Utc>,
}

/// Port allocator configuration
#[derive(Debug, Clone)]
pub struct PortConfig {
    pub min_port: u16,
    pub max_port: u16,
    pub reserved_ports: HashSet<u16>,
    pub enable_external_ports: bool,
    pub external_port_offset: u16,
}

impl Default for PortConfig {
    fn default() -> Self {
        let mut reserved = HashSet::new();
        // Reserve common system ports
        for port in [22, 80, 443, 3306, 5432, 6379, 8080, 9000] {
            reserved.insert(port);
        }
        
        Self {
            min_port: 30000,
            max_port: 32767,
            reserved_ports: reserved,
            enable_external_ports: true,
            external_port_offset: 10000,
        }
    }
}

/// Port allocator
pub struct PortAllocator {
    config: Arc<PortConfig>,
    allocations: Arc<DashMap<Uuid, PortAllocation>>,
    allocated_ports: Arc<ParkingLotRwLock<HashSet<u16>>>,
    next_port: Arc<ParkingLotRwLock<u16>>,
}

impl PortAllocator {
    /// Create a new port allocator
    pub fn new() -> Self {
        Self::with_config(PortConfig::default())
    }
    
    /// Create port allocator with custom configuration
    pub fn with_config(config: PortConfig) -> Self {
        Self {
            next_port: Arc::new(ParkingLotRwLock::new(config.min_port)),
            config: Arc::new(config),
            allocations: Arc::new(DashMap::new()),
            allocated_ports: Arc::new(ParkingLotRwLock::new(HashSet::new())),
        }
    }
    
    /// Allocate a port for a service
    #[instrument(skip(self))]
    pub async fn allocate_port(
        &self,
        service_id: &Uuid,
        protocol: Protocol,
    ) -> NetworkResult<PortAllocation> {
        // Check if already allocated
        if self.allocations.contains_key(service_id) {
            return Err(NetworkError::Other(anyhow::anyhow!(
                "Port already allocated for service {}", service_id
            )));
        }
        
        // Find available port
        let port = self.find_available_port()?;
        
        // Allocate external port if enabled
        let external_port = if self.config.enable_external_ports {
            Some(self.allocate_external_port(port)?)
        } else {
            None
        };
        
        let allocation = PortAllocation {
            service_id: *service_id,
            port,
            external_port,
            protocol,
            allocated_at: chrono::Utc::now(),
        };
        
        // Update state
        {
            let mut allocated = self.allocated_ports.write();
            allocated.insert(port);
            if let Some(ext_port) = external_port {
                allocated.insert(ext_port);
            }
        }
        
        self.allocations.insert(*service_id, allocation.clone());
        
        debug!("Allocated port {} for service {} with protocol {:?}", 
               port, service_id, protocol);
        
        Ok(allocation)
    }
    
    /// Find an available port
    fn find_available_port(&self) -> NetworkResult<u16> {
        let mut next_port = self.next_port.write();
        let allocated = self.allocated_ports.read();
        
        let start_port = *next_port;
        loop {
            // Check if port is available
            if !allocated.contains(&*next_port) && !self.config.reserved_ports.contains(&*next_port) {
                let port = *next_port;
                
                // Update next port
                *next_port += 1;
                if *next_port > self.config.max_port {
                    *next_port = self.config.min_port;
                }
                
                return Ok(port);
            }
            
            // Try next port
            *next_port += 1;
            if *next_port > self.config.max_port {
                *next_port = self.config.min_port;
            }
            
            // Check if we've tried all ports
            if *next_port == start_port {
                return Err(NetworkError::PortNotAvailable(0));
            }
        }
    }
    
    /// Allocate external port
    fn allocate_external_port(&self, internal_port: u16) -> NetworkResult<u16> {
        let external_port = internal_port + self.config.external_port_offset;
        
        // Validate external port
        if external_port > 65535 {
            return Err(NetworkError::InvalidPortRange(
                format!("External port {} exceeds maximum", external_port)
            ));
        }
        
        let allocated = self.allocated_ports.read();
        if allocated.contains(&external_port) {
            return Err(NetworkError::PortNotAvailable(external_port));
        }
        
        Ok(external_port)
    }
    
    /// Release port allocation
    #[instrument(skip(self))]
    pub async fn release_port(&self, service_id: &Uuid) -> NetworkResult<()> {
        let allocation = self.allocations.remove(service_id)
            .ok_or_else(|| NetworkError::ResourceNotFound(service_id.to_string()))?;
        
        // Free ports
        {
            let mut allocated = self.allocated_ports.write();
            allocated.remove(&allocation.1.port);
            if let Some(ext_port) = allocation.1.external_port {
                allocated.remove(&ext_port);
            }
        }
        
        debug!("Released port {} from service {}", allocation.1.port, service_id);
        
        Ok(())
    }
    
    /// Get port allocation for a service
    pub async fn get_allocation(&self, service_id: &Uuid) -> Option<PortAllocation> {
        self.allocations.get(service_id).map(|entry| entry.clone())
    }
    
    /// List all allocations
    pub async fn list_allocations(&self) -> Vec<PortAllocation> {
        self.allocations.iter()
            .map(|entry| entry.value().clone())
            .collect()
    }
    
    /// Check if a port is available
    pub async fn is_port_available(&self, port: u16) -> bool {
        let allocated = self.allocated_ports.read();
        !allocated.contains(&port) && !self.config.reserved_ports.contains(&port)
    }
    
    /// Reserve a specific port
    pub async fn reserve_port(&self, port: u16) -> NetworkResult<()> {
        if !self.is_port_available(port).await {
            return Err(NetworkError::PortNotAvailable(port));
        }
        
        let mut allocated = self.allocated_ports.write();
        allocated.insert(port);
        
        Ok(())
    }
    
    /// Get port usage statistics
    pub async fn get_stats(&self) -> PortStats {
        let allocated = self.allocated_ports.read();
        let total_ports = (self.config.max_port - self.config.min_port + 1) as usize;
        let allocated_count = allocated.len();
        
        PortStats {
            total_ports,
            allocated_ports: allocated_count,
            available_ports: total_ports - allocated_count,
            utilization: (allocated_count as f64 / total_ports as f64) * 100.0,
            min_port: self.config.min_port,
            max_port: self.config.max_port,
        }
    }
    
    /// Allocate a specific port for a service
    pub async fn allocate_specific_port(
        &self,
        service_id: &Uuid,
        port: u16,
        protocol: Protocol,
    ) -> NetworkResult<PortAllocation> {
        // Validate port range
        if port < self.config.min_port || port > self.config.max_port {
            return Err(NetworkError::InvalidPortRange(
                format!("Port {} is outside allowed range {}-{}", 
                       port, self.config.min_port, self.config.max_port)
            ));
        }
        
        // Check availability
        if !self.is_port_available(port).await {
            return Err(NetworkError::PortNotAvailable(port));
        }
        
        // Check if service already has allocation
        if self.allocations.contains_key(service_id) {
            return Err(NetworkError::Other(anyhow::anyhow!(
                "Port already allocated for service {}", service_id
            )));
        }
        
        let allocation = PortAllocation {
            service_id: *service_id,
            port,
            external_port: None,
            protocol,
            allocated_at: chrono::Utc::now(),
        };
        
        // Update state
        {
            let mut allocated = self.allocated_ports.write();
            allocated.insert(port);
        }
        
        self.allocations.insert(*service_id, allocation.clone());
        
        Ok(allocation)
    }
}

/// Port allocation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortStats {
    pub total_ports: usize,
    pub allocated_ports: usize,
    pub available_ports: usize,
    pub utilization: f64,
    pub min_port: u16,
    pub max_port: u16,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_port_allocation() {
        let config = PortConfig {
            min_port: 30000,
            max_port: 30010,
            ..Default::default()
        };
        
        let allocator = PortAllocator::with_config(config);
        
        let service_id = Uuid::new_v4();
        let allocation = allocator.allocate_port(&service_id, Protocol::Http).await.unwrap();
        
        assert!(allocation.port >= 30000 && allocation.port <= 30010);
        assert_eq!(allocation.protocol, Protocol::Http);
        
        // Verify port is marked as allocated
        assert!(!allocator.is_port_available(allocation.port).await);
        
        // Release port
        allocator.release_port(&service_id).await.unwrap();
        assert!(allocator.is_port_available(allocation.port).await);
    }
    
    #[tokio::test]
    async fn test_port_exhaustion() {
        let config = PortConfig {
            min_port: 30000,
            max_port: 30002,
            enable_external_ports: false,
            ..Default::default()
        };
        
        let allocator = PortAllocator::with_config(config);
        
        // Allocate all available ports
        let mut service_ids = vec![];
        for i in 0..3 {
            let service_id = Uuid::new_v4();
            service_ids.push(service_id);
            allocator.allocate_port(&service_id, Protocol::Tcp).await.unwrap();
        }
        
        // Try to allocate one more
        let service_id = Uuid::new_v4();
        let result = allocator.allocate_port(&service_id, Protocol::Tcp).await;
        assert!(result.is_err());
        
        // Release one port and try again
        allocator.release_port(&service_ids[0]).await.unwrap();
        let result = allocator.allocate_port(&service_id, Protocol::Tcp).await;
        assert!(result.is_ok());
    }
    
    #[tokio::test]
    async fn test_specific_port_allocation() {
        let allocator = PortAllocator::new();
        
        let service_id = Uuid::new_v4();
        let port = 31337;
        
        let allocation = allocator.allocate_specific_port(
            &service_id, 
            port, 
            Protocol::Http
        ).await.unwrap();
        
        assert_eq!(allocation.port, port);
        
        // Try to allocate same port again
        let service_id2 = Uuid::new_v4();
        let result = allocator.allocate_specific_port(
            &service_id2, 
            port, 
            Protocol::Http
        ).await;
        assert!(result.is_err());
    }
}