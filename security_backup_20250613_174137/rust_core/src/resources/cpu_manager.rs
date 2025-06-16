//! CPU resource management
//! 
//! Provides CPU core allocation and tracking with NUMA-aware placement
//! and performance optimization.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use parking_lot::RwLock as ParkingLotRwLock;
use tracing::{debug, warn, instrument};

/// CPU allocation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuAllocation {
    pub service_id: Uuid,
    pub cores: f64,
    pub cpu_set: Option<Vec<u32>>,
    pub numa_node: Option<u32>,
    pub priority: i32,
}

/// CPU manager configuration
#[derive(Debug, Clone)]
pub struct CpuConfig {
    pub total_cores: f64,
    pub overcommit_ratio: f64,
    pub numa_aware: bool,
    pub cpu_pinning: bool,
    pub min_allocation: f64,
    pub max_allocation_per_service: f64,
}

impl Default for CpuConfig {
    fn default() -> Self {
        let num_cpus = num_cpus::get() as f64;
        Self {
            total_cores: num_cpus,
            overcommit_ratio: 1.5,
            numa_aware: false,
            cpu_pinning: false,
            min_allocation: 0.1,
            max_allocation_per_service: num_cpus * 0.8,
        }
    }
}

/// CPU resource manager
pub struct CpuManager {
    config: Arc<CpuConfig>,
    allocations: Arc<DashMap<Uuid, CpuAllocation>>,
    total_allocated: Arc<AtomicU64>,
    cpu_topology: Arc<ParkingLotRwLock<CpuTopology>>,
}

/// CPU topology information
#[derive(Debug, Default)]
struct CpuTopology {
    numa_nodes: Vec<NumaNode>,
    cpu_to_numa: HashMap<u32, u32>,
}

/// NUMA node information
#[derive(Debug)]
struct NumaNode {
    id: u32,
    cpus: Vec<u32>,
    allocated_cores: f64,
}

impl CpuManager {
    /// Create a new CPU manager
    pub fn new() -> Self {
        Self::with_config(CpuConfig::default())
    }
    
    /// Create CPU manager with custom configuration
    pub fn with_config(config: CpuConfig) -> Self {
        let topology = Self::detect_topology(&config);
        
        Self {
            config: Arc::new(config),
            allocations: Arc::new(DashMap::new()),
            total_allocated: Arc::new(AtomicU64::new(0)),
            cpu_topology: Arc::new(ParkingLotRwLock::new(topology)),
        }
    }
    
    /// Detect CPU topology
    fn detect_topology(config: &CpuConfig) -> CpuTopology {
        if !config.numa_aware {
            return CpuTopology::default();
        }
        
        // Simplified topology detection
        // In production, would use hwloc or similar
        let num_cpus = num_cpus::get() as u32;
        let numa_nodes = vec![
            NumaNode {
                id: 0,
                cpus: (0..num_cpus).collect(),
                allocated_cores: 0.0,
            }
        ];
        
        let mut cpu_to_numa = HashMap::new();
        for cpu in 0..num_cpus {
            cpu_to_numa.insert(cpu, 0);
        }
        
        CpuTopology {
            numa_nodes,
            cpu_to_numa,
        }
    }
    
    /// Allocate CPU cores for a service
    #[instrument(skip(self))]
    pub async fn allocate(&self, service_id: &Uuid, cores: f64) -> ResourceResult<CpuAllocation> {
        // Validate request
        if cores < self.config.min_allocation {
            return Err(ResourceError::InvalidRequest(
                format!("CPU request {} is below minimum {}", cores, self.config.min_allocation)
            ));
        }
        
        if cores > self.config.max_allocation_per_service {
            return Err(ResourceError::InvalidRequest(
                format!("CPU request {} exceeds maximum {}", cores, self.config.max_allocation_per_service)
            ));
        }
        
        // Check if already allocated
        if self.allocations.contains_key(service_id) {
            return Err(ResourceError::AlreadyAllocated(service_id.to_string()));
        }
        
        // Check available capacity
        let current_allocated = self.get_allocated_cores().await;
        let max_allowed = self.config.total_cores * self.config.overcommit_ratio;
        
        if current_allocated + cores > max_allowed {
            return Err(ResourceError::InsufficientResources(
                format!("Not enough CPU cores: requested {}, available {}", 
                       cores, max_allowed - current_allocated)
            ));
        }
        
        // Select CPU set if pinning enabled
        let (cpu_set, numa_node) = if self.config.cpu_pinning {
            self.select_cpu_set(cores).await?
        } else {
            (None, None)
        };
        
        let allocation = CpuAllocation {
            service_id: *service_id,
            cores,
            cpu_set,
            numa_node,
            priority: 0,
        };
        
        // Update allocations
        self.allocations.insert(*service_id, allocation.clone());
        
        // Update total allocated (convert to fixed point for atomic operations)
        let cores_fixed = (cores * 1000.0) as u64;
        self.total_allocated.fetch_add(cores_fixed, Ordering::SeqCst);
        
        debug!("Allocated {} CPU cores for service {}", cores, service_id);
        
        Ok(allocation)
    }
    
    /// Select CPU set for pinning
    async fn select_cpu_set(&self, cores: f64) -> ResourceResult<(Option<Vec<u32>>, Option<u32>)> {
        if !self.config.cpu_pinning {
            return Ok((None, None));
        }
        
        let topology = self.cpu_topology.read();
        
        // Simple allocation strategy: find NUMA node with enough free cores
        // In production, would use more sophisticated placement algorithms
        for numa_node in &topology.numa_nodes {
            let free_cores = numa_node.cpus.len() as f64 - numa_node.allocated_cores;
            if free_cores >= cores {
                let cpu_count = cores.ceil() as usize;
                let cpu_set: Vec<u32> = numa_node.cpus.iter()
                    .take(cpu_count)
                    .cloned()
                    .collect();
                
                return Ok((Some(cpu_set), Some(numa_node.id)));
            }
        }
        
        // No suitable NUMA node found, allocate across nodes
        Ok((None, None))
    }
    
    /// Release CPU allocation
    #[instrument(skip(self))]
    pub async fn release(&self, service_id: &Uuid) -> ResourceResult<()> {
        let allocation = self.allocations.remove(service_id)
            .ok_or_else(|| ResourceError::ResourceNotFound(service_id.to_string()))?;
        
        // Update total allocated
        let cores_fixed = (allocation.1.cores * 1000.0) as u64;
        self.total_allocated.fetch_sub(cores_fixed, Ordering::SeqCst);
        
        debug!("Released {} CPU cores from service {}", allocation.1.cores, service_id);
        
        Ok(())
    }
    
    /// Get total allocated cores
    pub async fn get_allocated_cores(&self) -> f64 {
        self.total_allocated.load(Ordering::SeqCst) as f64 / 1000.0
    }
    
    /// Get total available cores
    pub async fn get_total_cores(&self) -> f64 {
        self.config.total_cores
    }
    
    /// Get CPU utilization percentage
    pub async fn get_utilization(&self) -> f64 {
        let allocated = self.get_allocated_cores().await;
        let total = self.get_total_cores().await;
        
        if total > 0.0 {
            (allocated / total) * 100.0
        } else {
            0.0
        }
    }
    
    /// Update service CPU allocation (for scaling)
    pub async fn update_allocation(
        &self, 
        service_id: &Uuid, 
        new_cores: f64
    ) -> ResourceResult<CpuAllocation> {
        // Get current allocation
        let current = self.allocations.get(service_id)
            .ok_or_else(|| ResourceError::ResourceNotFound(service_id.to_string()))?;
        
        let delta = new_cores - current.cores;
        
        if delta > 0.0 {
            // Check if we can allocate more
            let current_allocated = self.get_allocated_cores().await;
            let max_allowed = self.config.total_cores * self.config.overcommit_ratio;
            
            if current_allocated + delta > max_allowed {
                return Err(ResourceError::InsufficientResources(
                    format!("Cannot increase allocation by {}", delta)
                ));
            }
        }
        
        // Update allocation
        let mut allocation = current.clone();
        allocation.cores = new_cores;
        
        self.allocations.insert(*service_id, allocation.clone());
        
        // Update total allocated
        if delta > 0.0 {
            let delta_fixed = (delta * 1000.0) as u64;
            self.total_allocated.fetch_add(delta_fixed, Ordering::SeqCst);
        } else {
            let delta_fixed = ((-delta) * 1000.0) as u64;
            self.total_allocated.fetch_sub(delta_fixed, Ordering::SeqCst);
        }
        
        Ok(allocation)
    }
    
    /// Get allocations by service
    pub async fn get_allocations(&self) -> Vec<CpuAllocation> {
        self.allocations.iter()
            .map(|entry| entry.value().clone())
            .collect()
    }
    
    /// Set CPU affinity for a service (if supported)
    pub async fn set_cpu_affinity(&self, service_id: &Uuid) -> ResourceResult<()> {
        if !self.config.cpu_pinning {
            return Ok(());
        }
        
        let allocation = self.allocations.get(service_id)
            .ok_or_else(|| ResourceError::ResourceNotFound(service_id.to_string()))?;
        
        if let Some(cpu_set) = &allocation.cpu_set {
            debug!("Setting CPU affinity for service {} to CPUs: {:?}", service_id, cpu_set);
            // In production, would use libc::sched_setaffinity or similar
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_cpu_allocation() {
        let config = CpuConfig {
            total_cores: 8.0,
            overcommit_ratio: 1.5,
            ..Default::default()
        };
        
        let manager = CpuManager::with_config(config);
        
        let service_id = Uuid::new_v4();
        let allocation = manager.allocate(&service_id, 2.0).await.unwrap();
        
        assert_eq!(allocation.cores, 2.0);
        assert_eq!(manager.get_allocated_cores().await, 2.0);
        
        // Try to allocate more than available
        let service_id2 = Uuid::new_v4();
        let result = manager.allocate(&service_id2, 20.0).await;
        assert!(result.is_err());
        
        // Release allocation
        manager.release(&service_id).await.unwrap();
        assert_eq!(manager.get_allocated_cores().await, 0.0);
    }
    
    #[tokio::test]
    async fn test_cpu_scaling() {
        let manager = CpuManager::new();
        
        let service_id = Uuid::new_v4();
        manager.allocate(&service_id, 1.0).await.unwrap();
        
        // Scale up
        let updated = manager.update_allocation(&service_id, 2.0).await.unwrap();
        assert_eq!(updated.cores, 2.0);
        assert_eq!(manager.get_allocated_cores().await, 2.0);
        
        // Scale down
        let updated = manager.update_allocation(&service_id, 0.5).await.unwrap();
        assert_eq!(updated.cores, 0.5);
        assert_eq!(manager.get_allocated_cores().await, 0.5);
    }
}