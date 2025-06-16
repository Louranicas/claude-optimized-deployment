//! Storage resource management
//! 
//! Provides disk space allocation with quota management, I/O limits,
//! and storage class support.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::path::PathBuf;
use parking_lot::RwLock as ParkingLotRwLock;
use tracing::{debug, warn, instrument};
use std::collections::HashMap;

/// Storage allocation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageAllocation {
    pub service_id: Uuid,
    pub disk_mb: u64,
    pub storage_class: StorageClass,
    pub mount_path: PathBuf,
    pub iops_limit: Option<u64>,
    pub bandwidth_limit_mbps: Option<u64>,
}

/// Storage class
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StorageClass {
    Standard,
    Fast,
    Nvme,
    Network,
}

/// Storage manager configuration
#[derive(Debug, Clone)]
pub struct StorageConfig {
    pub total_storage_mb: u64,
    pub storage_path: PathBuf,
    pub overcommit_ratio: f64,
    pub min_allocation_mb: u64,
    pub max_allocation_per_service_mb: u64,
    pub enable_quotas: bool,
    pub enable_io_limits: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        let total_storage = Self::detect_total_storage();
        Self {
            total_storage_mb: total_storage,
            storage_path: PathBuf::from("/var/lib/code/storage"),
            overcommit_ratio: 1.1,
            min_allocation_mb: 100,
            max_allocation_per_service_mb: total_storage / 4,
            enable_quotas: true,
            enable_io_limits: true,
        }
    }
}

impl StorageConfig {
    fn detect_total_storage() -> u64 {
        // Get available storage in MB
        #[cfg(target_os = "linux")]
        {
            use std::process::Command;
            
            if let Ok(output) = Command::new("df")
                .args(&["-BM", "/"])
                .output() 
            {
                if let Ok(stdout) = String::from_utf8(output.stdout) {
                    for line in stdout.lines().skip(1) {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 4 {
                            if let Ok(available) = parts[3].trim_end_matches('M').parse::<u64>() {
                                return available;
                            }
                        }
                    }
                }
            }
        }
        
        // Fallback to 100GB
        102400
    }
}

/// Storage pool information
#[derive(Debug)]
struct StoragePool {
    class: StorageClass,
    total_mb: u64,
    allocated_mb: u64,
    mount_point: PathBuf,
}

/// Storage manager
pub struct StorageManager {
    config: Arc<StorageConfig>,
    allocations: Arc<DashMap<Uuid, StorageAllocation>>,
    storage_pools: Arc<ParkingLotRwLock<HashMap<StorageClass, StoragePool>>>,
    total_allocated: Arc<AtomicU64>,
}

impl StorageManager {
    /// Create a new storage manager
    pub fn new() -> Self {
        Self::with_config(StorageConfig::default())
    }
    
    /// Create storage manager with custom configuration
    pub fn with_config(config: StorageConfig) -> Self {
        let storage_pools = Self::initialize_storage_pools(&config);
        
        Self {
            config: Arc::new(config),
            allocations: Arc::new(DashMap::new()),
            storage_pools: Arc::new(ParkingLotRwLock::new(storage_pools)),
            total_allocated: Arc::new(AtomicU64::new(0)),
        }
    }
    
    /// Initialize storage pools
    fn initialize_storage_pools(config: &StorageConfig) -> HashMap<StorageClass, StoragePool> {
        let mut pools = HashMap::new();
        
        // Simple allocation: all storage is standard class
        // In production, would detect different storage devices
        pools.insert(StorageClass::Standard, StoragePool {
            class: StorageClass::Standard,
            total_mb: config.total_storage_mb,
            allocated_mb: 0,
            mount_point: config.storage_path.clone(),
        });
        
        pools
    }
    
    /// Allocate storage for a service
    #[instrument(skip(self))]
    pub async fn allocate(&self, service_id: &Uuid, disk_mb: u64) -> ResourceResult<StorageAllocation> {
        self.allocate_with_class(service_id, disk_mb, StorageClass::Standard).await
    }
    
    /// Allocate storage with specific class
    pub async fn allocate_with_class(
        &self, 
        service_id: &Uuid, 
        disk_mb: u64,
        storage_class: StorageClass
    ) -> ResourceResult<StorageAllocation> {
        // Validate request
        if disk_mb < self.config.min_allocation_mb {
            return Err(ResourceError::InvalidRequest(
                format!("Storage request {}MB is below minimum {}MB", 
                       disk_mb, self.config.min_allocation_mb)
            ));
        }
        
        if disk_mb > self.config.max_allocation_per_service_mb {
            return Err(ResourceError::InvalidRequest(
                format!("Storage request {}MB exceeds maximum {}MB", 
                       disk_mb, self.config.max_allocation_per_service_mb)
            ));
        }
        
        // Check if already allocated
        if self.allocations.contains_key(service_id) {
            return Err(ResourceError::AlreadyAllocated(service_id.to_string()));
        }
        
        // Allocate from pool
        let mount_path = {
            let mut pools = self.storage_pools.write();
            
            let pool = (*pools).get_mut(&storage_class)
                .ok_or_else(|| ResourceError::InvalidRequest(
                    format!("Storage class {:?} not available", storage_class)
                ))?;
            
            let max_allowed = (pool.total_mb as f64 * self.config.overcommit_ratio) as u64;
            
            if pool.allocated_mb + disk_mb > max_allowed {
                return Err(ResourceError::InsufficientResources(
                    format!("Not enough storage in {:?} pool: requested {}MB, available {}MB", 
                           storage_class, disk_mb, max_allowed - pool.allocated_mb)
                ));
            }
            
            pool.allocated_mb += disk_mb;
            pool.mount_point.join(service_id.to_string())
        };
        
        // Create mount directory
        if let Err(e) = tokio::fs::create_dir_all(&mount_path).await {
            warn!("Failed to create mount directory: {}", e);
        }
        
        let allocation = StorageAllocation {
            service_id: *service_id,
            disk_mb,
            storage_class,
            mount_path,
            iops_limit: None,
            bandwidth_limit_mbps: None,
        };
        
        // Update allocations
        self.allocations.insert(*service_id, allocation.clone());
        self.total_allocated.fetch_add(disk_mb, Ordering::SeqCst);
        
        // Apply quota if enabled
        if self.config.enable_quotas {
            self.apply_quota(service_id, disk_mb).await?;
        }
        
        debug!("Allocated {}MB storage for service {} in {:?} class", 
               disk_mb, service_id, storage_class);
        
        Ok(allocation)
    }
    
    /// Release storage allocation
    #[instrument(skip(self))]
    pub async fn release(&self, service_id: &Uuid) -> ResourceResult<()> {
        let allocation = self.allocations.remove(service_id)
            .ok_or_else(|| ResourceError::ResourceNotFound(service_id.to_string()))?;
        
        // Update pool
        {
            let mut pools = self.storage_pools.write();
            if let Some(pool) = (*pools).get_mut(&allocation.1.storage_class) {
                pool.allocated_mb = pool.allocated_mb.saturating_sub(allocation.1.disk_mb);
            }
        }
        
        self.total_allocated.fetch_sub(allocation.1.disk_mb, Ordering::SeqCst);
        
        // Remove quota
        if self.config.enable_quotas {
            self.remove_quota(service_id).await?;
        }
        
        // Clean up mount directory
        if let Err(e) = tokio::fs::remove_dir_all(&allocation.1.mount_path).await {
            warn!("Failed to remove mount directory: {}", e);
        }
        
        debug!("Released {}MB storage from service {}", allocation.1.disk_mb, service_id);
        
        Ok(())
    }
    
    /// Apply storage quota
    async fn apply_quota(&self, service_id: &Uuid, disk_mb: u64) -> ResourceResult<()> {
        #[cfg(target_os = "linux")]
        {
            // In production, would use quota tools or btrfs subvolumes
            debug!("Applying {}MB quota for service {}", disk_mb, service_id);
        }
        
        Ok(())
    }
    
    /// Remove storage quota
    async fn remove_quota(&self, service_id: &Uuid) -> ResourceResult<()> {
        #[cfg(target_os = "linux")]
        {
            debug!("Removing quota for service {}", service_id);
        }
        
        Ok(())
    }
    
    /// Set I/O limits for a service
    pub async fn set_io_limits(
        &self, 
        service_id: &Uuid, 
        iops_limit: Option<u64>,
        bandwidth_limit_mbps: Option<u64>
    ) -> ResourceResult<()> {
        if !self.config.enable_io_limits {
            return Ok(());
        }
        
        let mut allocation = self.allocations.get_mut(service_id)
            .ok_or_else(|| ResourceError::ResourceNotFound(service_id.to_string()))?;
        
        allocation.iops_limit = iops_limit;
        allocation.bandwidth_limit_mbps = bandwidth_limit_mbps;
        
        #[cfg(target_os = "linux")]
        {
            // In production, would use cgroups v2 io controller
            if let Some(iops) = iops_limit {
                debug!("Setting IOPS limit {} for service {}", iops, service_id);
            }
            if let Some(bandwidth) = bandwidth_limit_mbps {
                debug!("Setting bandwidth limit {}MB/s for service {}", bandwidth, service_id);
            }
        }
        
        Ok(())
    }
    
    /// Get total allocated storage
    pub async fn get_allocated_storage(&self) -> u64 {
        self.total_allocated.load(Ordering::SeqCst)
    }
    
    /// Get total available storage
    pub async fn get_total_storage(&self) -> u64 {
        self.config.total_storage_mb
    }
    
    /// Get storage utilization percentage
    pub async fn get_utilization(&self) -> f64 {
        let allocated = self.get_allocated_storage().await;
        let total = self.get_total_storage().await;
        
        if total > 0 {
            (allocated as f64 / total as f64) * 100.0
        } else {
            0.0
        }
    }
    
    /// Get storage pool statistics
    pub async fn get_pool_stats(&self) -> Vec<StoragePoolStats> {
        let pools = self.storage_pools.read();
        
        pools.values().map(|pool| {
            StoragePoolStats {
                storage_class: pool.class,
                total_mb: pool.total_mb,
                allocated_mb: pool.allocated_mb,
                free_mb: pool.total_mb - pool.allocated_mb,
                utilization: if pool.total_mb > 0 {
                    (pool.allocated_mb as f64 / pool.total_mb as f64) * 100.0
                } else {
                    0.0
                },
            }
        }).collect()
    }
    
    /// Resize storage allocation
    pub async fn resize_allocation(
        &self,
        service_id: &Uuid,
        new_disk_mb: u64
    ) -> ResourceResult<StorageAllocation> {
        let current = self.allocations.get(service_id)
            .ok_or_else(|| ResourceError::ResourceNotFound(service_id.to_string()))?;
        
        let delta = new_disk_mb as i64 - current.disk_mb as i64;
        
        if delta > 0 {
            // Check if pool has capacity
            let mut pools = self.storage_pools.write();
            let pool = (*pools).get_mut(&current.storage_class)
                .ok_or_else(|| ResourceError::InvalidRequest("Storage pool not found".to_string()))?;
            
            let max_allowed = (pool.total_mb as f64 * self.config.overcommit_ratio) as u64;
            
            if pool.allocated_mb + delta as u64 > max_allowed {
                return Err(ResourceError::InsufficientResources(
                    format!("Cannot increase allocation by {}MB", delta)
                ));
            }
            
            pool.allocated_mb += delta as u64;
        } else {
            let mut pools = self.storage_pools.write();
            if let Some(pool) = (*pools).get_mut(&current.storage_class) {
                pool.allocated_mb = pool.allocated_mb.saturating_sub((-delta) as u64);
            }
        }
        
        // Update allocation
        let mut allocation = current.clone();
        allocation.disk_mb = new_disk_mb;
        
        self.allocations.insert(*service_id, allocation.clone());
        
        // Update total
        if delta > 0 {
            self.total_allocated.fetch_add(delta as u64, Ordering::SeqCst);
        } else {
            self.total_allocated.fetch_sub((-delta) as u64, Ordering::SeqCst);
        }
        
        // Update quota
        if self.config.enable_quotas {
            self.apply_quota(service_id, new_disk_mb).await?;
        }
        
        Ok(allocation)
    }
}

/// Storage pool statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoragePoolStats {
    pub storage_class: StorageClass,
    pub total_mb: u64,
    pub allocated_mb: u64,
    pub free_mb: u64,
    pub utilization: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_storage_allocation() {
        let config = StorageConfig {
            total_storage_mb: 10240,
            storage_path: PathBuf::from("/tmp/test_storage"),
            ..Default::default()
        };
        
        let manager = StorageManager::with_config(config);
        
        let service_id = Uuid::new_v4();
        let allocation = manager.allocate(&service_id, 1024).await.unwrap();
        
        assert_eq!(allocation.disk_mb, 1024);
        assert_eq!(allocation.storage_class, StorageClass::Standard);
        assert_eq!(manager.get_allocated_storage().await, 1024);
        
        // Release allocation
        manager.release(&service_id).await.unwrap();
        assert_eq!(manager.get_allocated_storage().await, 0);
    }
    
    #[tokio::test]
    async fn test_storage_resize() {
        let manager = StorageManager::new();
        
        let service_id = Uuid::new_v4();
        manager.allocate(&service_id, 500).await.unwrap();
        
        // Resize up
        let resized = manager.resize_allocation(&service_id, 1000).await.unwrap();
        assert_eq!(resized.disk_mb, 1000);
        assert_eq!(manager.get_allocated_storage().await, 1000);
        
        // Resize down
        let resized = manager.resize_allocation(&service_id, 250).await.unwrap();
        assert_eq!(resized.disk_mb, 250);
        assert_eq!(manager.get_allocated_storage().await, 250);
    }
    
    #[tokio::test]
    async fn test_io_limits() {
        let manager = StorageManager::new();
        
        let service_id = Uuid::new_v4();
        manager.allocate(&service_id, 1024).await.unwrap();
        
        // Set I/O limits
        manager.set_io_limits(&service_id, Some(1000), Some(100)).await.unwrap();
        
        let allocation = manager.allocations.get(&service_id).unwrap();
        assert_eq!(allocation.iops_limit, Some(1000));
        assert_eq!(allocation.bandwidth_limit_mbps, Some(100));
    }
}