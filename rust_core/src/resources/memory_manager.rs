//! Memory resource management
//! 
//! Provides memory allocation with limits, swap management, and
//! memory pressure monitoring.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use parking_lot::RwLock as ParkingLotRwLock;
use tracing::{debug, warn, instrument};

/// Memory allocation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryAllocation {
    pub service_id: Uuid,
    pub memory_mb: u64,
    pub swap_mb: u64,
    pub memory_limit_mb: u64,
    pub oom_score_adj: i32,
}

/// Memory manager configuration
#[derive(Debug, Clone)]
pub struct MemoryConfig {
    pub total_memory_mb: u64,
    pub overcommit_ratio: f64,
    pub swap_enabled: bool,
    pub swap_ratio: f64,
    pub min_allocation_mb: u64,
    pub max_allocation_per_service_mb: u64,
    pub memory_pressure_threshold: f64,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        let total_memory = Self::detect_total_memory();
        Self {
            total_memory_mb: total_memory,
            overcommit_ratio: 1.2,
            swap_enabled: true,
            swap_ratio: 0.5,
            min_allocation_mb: 64,
            max_allocation_per_service_mb: total_memory / 2,
            memory_pressure_threshold: 0.9,
        }
    }
}

impl MemoryConfig {
    fn detect_total_memory() -> u64 {
        // Get system memory in MB
        #[cfg(target_os = "linux")]
        {
            if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
                for line in meminfo.lines() {
                    if line.starts_with("MemTotal:") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            if let Ok(kb) = parts[1].parse::<u64>() {
                                return kb / 1024;
                            }
                        }
                    }
                }
            }
        }
        
        // Fallback to 8GB
        8192
    }
}

/// Memory statistics
#[derive(Debug, Default)]
struct MemoryStats {
    used_mb: u64,
    free_mb: u64,
    cached_mb: u64,
    swap_used_mb: u64,
    swap_free_mb: u64,
}

/// Memory manager
pub struct MemoryManager {
    config: Arc<MemoryConfig>,
    allocations: Arc<DashMap<Uuid, MemoryAllocation>>,
    total_allocated: Arc<AtomicU64>,
    memory_stats: Arc<ParkingLotRwLock<MemoryStats>>,
}

impl MemoryManager {
    /// Create a new memory manager
    pub fn new() -> Self {
        Self::with_config(MemoryConfig::default())
    }
    
    /// Create memory manager with custom configuration
    pub fn with_config(config: MemoryConfig) -> Self {
        Self {
            config: Arc::new(config),
            allocations: Arc::new(DashMap::new()),
            total_allocated: Arc::new(AtomicU64::new(0)),
            memory_stats: Arc::new(ParkingLotRwLock::new(MemoryStats::default())),
        }
    }
    
    /// Allocate memory for a service
    #[instrument(skip(self))]
    pub async fn allocate(&self, service_id: &Uuid, memory_mb: u64) -> ResourceResult<MemoryAllocation> {
        // Validate request
        if memory_mb < self.config.min_allocation_mb {
            return Err(ResourceError::InvalidRequest(
                format!("Memory request {}MB is below minimum {}MB", 
                       memory_mb, self.config.min_allocation_mb)
            ));
        }
        
        if memory_mb > self.config.max_allocation_per_service_mb {
            return Err(ResourceError::InvalidRequest(
                format!("Memory request {}MB exceeds maximum {}MB", 
                       memory_mb, self.config.max_allocation_per_service_mb)
            ));
        }
        
        // Check if already allocated
        if self.allocations.contains_key(service_id) {
            return Err(ResourceError::AlreadyAllocated(service_id.to_string()));
        }
        
        // Check available capacity
        let current_allocated = self.total_allocated.load(Ordering::SeqCst);
        let max_allowed = (self.config.total_memory_mb as f64 * self.config.overcommit_ratio) as u64;
        
        if current_allocated + memory_mb > max_allowed {
            return Err(ResourceError::InsufficientResources(
                format!("Not enough memory: requested {}MB, available {}MB", 
                       memory_mb, max_allowed - current_allocated)
            ));
        }
        
        // Check memory pressure
        if self.is_under_memory_pressure().await {
            warn!("Memory allocation under pressure for service {}", service_id);
        }
        
        // Calculate swap allocation
        let swap_mb = if self.config.swap_enabled {
            (memory_mb as f64 * self.config.swap_ratio) as u64
        } else {
            0
        };
        
        let allocation = MemoryAllocation {
            service_id: *service_id,
            memory_mb,
            swap_mb,
            memory_limit_mb: memory_mb + swap_mb,
            oom_score_adj: 0,
        };
        
        // Update allocations
        self.allocations.insert(*service_id, allocation.clone());
        self.total_allocated.fetch_add(memory_mb, Ordering::SeqCst);
        
        debug!("Allocated {}MB memory for service {}", memory_mb, service_id);
        
        Ok(allocation)
    }
    
    /// Release memory allocation
    #[instrument(skip(self))]
    pub async fn release(&self, service_id: &Uuid) -> ResourceResult<()> {
        let allocation = self.allocations.remove(service_id)
            .ok_or_else(|| ResourceError::ResourceNotFound(service_id.to_string()))?;
        
        self.total_allocated.fetch_sub(allocation.1.memory_mb, Ordering::SeqCst);
        
        debug!("Released {}MB memory from service {}", allocation.1.memory_mb, service_id);
        
        Ok(())
    }
    
    /// Check if system is under memory pressure
    async fn is_under_memory_pressure(&self) -> bool {
        self.update_memory_stats().await;
        
        let stats = self.memory_stats.read();
        let total = self.config.total_memory_mb;
        let used_ratio = stats.used_mb as f64 / total as f64;
        
        used_ratio > self.config.memory_pressure_threshold
    }
    
    /// Update memory statistics
    async fn update_memory_stats(&self) {
        #[cfg(target_os = "linux")]
        {
            if let Ok(meminfo) = tokio::fs::read_to_string("/proc/meminfo").await {
                let mut stats = MemoryStats::default();
                
                for line in meminfo.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Ok(kb) = parts[1].parse::<u64>() {
                            let mb = kb / 1024;
                            match parts[0] {
                                "MemFree:" => stats.free_mb = mb,
                                "Cached:" => stats.cached_mb = mb,
                                "SwapFree:" => stats.swap_free_mb = mb,
                                _ => {}
                            }
                        }
                    }
                }
                
                stats.used_mb = self.config.total_memory_mb - stats.free_mb - stats.cached_mb;
                
                let mut current_stats = self.memory_stats.write();
                *current_stats = stats;
            }
        }
    }
    
    /// Get total allocated memory
    pub async fn get_allocated_memory(&self) -> u64 {
        self.total_allocated.load(Ordering::SeqCst)
    }
    
    /// Get total available memory
    pub async fn get_total_memory(&self) -> u64 {
        self.config.total_memory_mb
    }
    
    /// Get memory utilization percentage
    pub async fn get_utilization(&self) -> f64 {
        let allocated = self.get_allocated_memory().await;
        let total = self.get_total_memory().await;
        
        if total > 0 {
            (allocated as f64 / total as f64) * 100.0
        } else {
            0.0
        }
    }
    
    /// Update service memory allocation (for scaling)
    pub async fn update_allocation(
        &self, 
        service_id: &Uuid, 
        new_memory_mb: u64
    ) -> ResourceResult<MemoryAllocation> {
        // Get current allocation
        let current = self.allocations.get(service_id)
            .ok_or_else(|| ResourceError::ResourceNotFound(service_id.to_string()))?;
        
        let delta = new_memory_mb as i64 - current.memory_mb as i64;
        
        if delta > 0 {
            // Check if we can allocate more
            let current_allocated = self.total_allocated.load(Ordering::SeqCst);
            let max_allowed = (self.config.total_memory_mb as f64 * self.config.overcommit_ratio) as u64;
            
            if current_allocated + delta as u64 > max_allowed {
                return Err(ResourceError::InsufficientResources(
                    format!("Cannot increase allocation by {}MB", delta)
                ));
            }
        }
        
        // Update allocation
        let mut allocation = current.clone();
        allocation.memory_mb = new_memory_mb;
        allocation.swap_mb = if self.config.swap_enabled {
            (new_memory_mb as f64 * self.config.swap_ratio) as u64
        } else {
            0
        };
        allocation.memory_limit_mb = allocation.memory_mb + allocation.swap_mb;
        
        self.allocations.insert(*service_id, allocation.clone());
        
        // Update total allocated
        if delta > 0 {
            self.total_allocated.fetch_add(delta as u64, Ordering::SeqCst);
        } else {
            self.total_allocated.fetch_sub((-delta) as u64, Ordering::SeqCst);
        }
        
        Ok(allocation)
    }
    
    /// Set memory limit for a service (cgroup integration)
    pub async fn set_memory_limit(&self, service_id: &Uuid) -> ResourceResult<()> {
        let allocation = self.allocations.get(service_id)
            .ok_or_else(|| ResourceError::ResourceNotFound(service_id.to_string()))?;
        
        debug!("Setting memory limit for service {} to {}MB", 
               service_id, allocation.memory_limit_mb);
        
        // In production, would integrate with cgroups v2
        // echo "memory.max=$(($MEMORY_MB * 1024 * 1024))" > /sys/fs/cgroup/service_$SERVICE_ID/memory.max
        
        Ok(())
    }
    
    /// Get memory statistics
    pub async fn get_memory_stats(&self) -> MemoryStatsReport {
        self.update_memory_stats().await;
        
        let stats = self.memory_stats.read();
        let allocated = self.total_allocated.load(Ordering::SeqCst);
        
        MemoryStatsReport {
            total_mb: self.config.total_memory_mb,
            allocated_mb: allocated,
            used_mb: stats.used_mb,
            free_mb: stats.free_mb,
            cached_mb: stats.cached_mb,
            swap_used_mb: stats.swap_used_mb,
            swap_free_mb: stats.swap_free_mb,
            pressure: stats.used_mb as f64 / self.config.total_memory_mb as f64,
        }
    }
}

/// Memory statistics report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryStatsReport {
    pub total_mb: u64,
    pub allocated_mb: u64,
    pub used_mb: u64,
    pub free_mb: u64,
    pub cached_mb: u64,
    pub swap_used_mb: u64,
    pub swap_free_mb: u64,
    pub pressure: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_memory_allocation() {
        let config = MemoryConfig {
            total_memory_mb: 8192,
            overcommit_ratio: 1.2,
            ..Default::default()
        };
        
        let manager = MemoryManager::with_config(config);
        
        let service_id = Uuid::new_v4();
        let allocation = manager.allocate(&service_id, 1024).await.unwrap();
        
        assert_eq!(allocation.memory_mb, 1024);
        assert_eq!(manager.get_allocated_memory().await, 1024);
        
        // Try to allocate more than available
        let service_id2 = Uuid::new_v4();
        let result = manager.allocate(&service_id2, 10000).await;
        assert!(result.is_err());
        
        // Release allocation
        manager.release(&service_id).await.unwrap();
        assert_eq!(manager.get_allocated_memory().await, 0);
    }
    
    #[tokio::test]
    async fn test_memory_scaling() {
        let manager = MemoryManager::new();
        
        let service_id = Uuid::new_v4();
        manager.allocate(&service_id, 512).await.unwrap();
        
        // Scale up
        let updated = manager.update_allocation(&service_id, 1024).await.unwrap();
        assert_eq!(updated.memory_mb, 1024);
        assert_eq!(manager.get_allocated_memory().await, 1024);
        
        // Scale down
        let updated = manager.update_allocation(&service_id, 256).await.unwrap();
        assert_eq!(updated.memory_mb, 256);
        assert_eq!(manager.get_allocated_memory().await, 256);
    }
    
    #[tokio::test]
    async fn test_swap_allocation() {
        let config = MemoryConfig {
            total_memory_mb: 8192,
            swap_enabled: true,
            swap_ratio: 0.5,
            ..Default::default()
        };
        
        let manager = MemoryManager::with_config(config);
        
        let service_id = Uuid::new_v4();
        let allocation = manager.allocate(&service_id, 1024).await.unwrap();
        
        assert_eq!(allocation.memory_mb, 1024);
        assert_eq!(allocation.swap_mb, 512);
        assert_eq!(allocation.memory_limit_mb, 1536);
    }
}