//! Resource management modules
//! 
//! Provides CPU, memory, and storage management with efficient allocation
//! and tracking capabilities.

pub mod cpu_manager;
pub mod memory_manager;
pub mod storage_manager;

use std::sync::Arc;

use uuid::Uuid;
use serde::{Deserialize, Serialize};
use dashmap::DashMap;

pub use cpu_manager::{CpuManager, CpuAllocation};
pub use memory_manager::{MemoryManager, MemoryAllocation};
pub use storage_manager::{StorageManager, StorageAllocation};

/// Resource management result type
pub type ResourceResult<T> = Result<T, ResourceError>;

/// Resource management errors
#[derive(Debug, thiserror::Error)]
pub enum ResourceError {
    #[error("Insufficient resources: {0}")]
    InsufficientResources(String),
    
    #[error("Resource not found: {0}")]
    ResourceNotFound(String),
    
    #[error("Invalid resource request: {0}")]
    InvalidRequest(String),
    
    #[error("Resource already allocated: {0}")]
    AlreadyAllocated(String),
    
    #[error("Resource limit exceeded: {0}")]
    LimitExceeded(String),
    
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Resource request from orchestrator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRequest {
    pub cpu_cores: f64,
    pub memory_mb: u64,
    pub disk_mb: u64,
}

/// Resource allocation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAllocation {
    pub service_id: Uuid,
    pub cpu: CpuAllocation,
    pub memory: MemoryAllocation,
    pub storage: StorageAllocation,
    pub allocated_at: chrono::DateTime<chrono::Utc>,
}

/// Unified resource manager
pub struct ResourceManager {
    cpu_manager: Arc<CpuManager>,
    memory_manager: Arc<MemoryManager>,
    storage_manager: Arc<StorageManager>,
    allocations: Arc<DashMap<Uuid, ResourceAllocation>>,
}

impl ResourceManager {
    /// Create a new resource manager
    pub fn new() -> Self {
        Self {
            cpu_manager: Arc::new(CpuManager::new()),
            memory_manager: Arc::new(MemoryManager::new()),
            storage_manager: Arc::new(StorageManager::new()),
            allocations: Arc::new(DashMap::new()),
        }
    }
    
    /// Allocate resources for a service
    pub async fn allocate_resources(
        &self,
        service_id: &Uuid,
        request: ResourceRequest,
    ) -> ResourceResult<ResourceAllocation> {
        // Check if already allocated
        if self.allocations.contains_key(service_id) {
            return Err(ResourceError::AlreadyAllocated(service_id.to_string()));
        }
        
        // Allocate CPU
        let cpu = self.cpu_manager.allocate(service_id, request.cpu_cores).await?;
        
        // Allocate memory
        let memory = match self.memory_manager.allocate(service_id, request.memory_mb).await {
            Ok(mem) => mem,
            Err(e) => {
                // Rollback CPU allocation
                self.cpu_manager.release(service_id).await.ok();
                return Err(e);
            }
        };
        
        // Allocate storage
        let storage = match self.storage_manager.allocate(service_id, request.disk_mb).await {
            Ok(stor) => stor,
            Err(e) => {
                // Rollback CPU and memory allocations
                self.cpu_manager.release(service_id).await.ok();
                self.memory_manager.release(service_id).await.ok();
                return Err(e);
            }
        };
        
        let allocation = ResourceAllocation {
            service_id: *service_id,
            cpu,
            memory,
            storage,
            allocated_at: chrono::Utc::now(),
        };
        
        self.allocations.insert(*service_id, allocation.clone());
        
        Ok(allocation)
    }
    
    /// Release resources for a service
    pub async fn release_resources(&self, service_id: &Uuid) -> ResourceResult<()> {
        // Remove allocation record
        self.allocations.remove(service_id)
            .ok_or_else(|| ResourceError::ResourceNotFound(service_id.to_string()))?;
        
        // Release individual resources
        self.cpu_manager.release(service_id).await?;
        self.memory_manager.release(service_id).await?;
        self.storage_manager.release(service_id).await?;
        
        Ok(())
    }
    
    /// Get resource allocation for a service
    pub async fn get_allocation(&self, service_id: &Uuid) -> Option<ResourceAllocation> {
        self.allocations.get(service_id).map(|entry| entry.clone())
    }
    
    /// Get total resource utilization
    pub async fn get_total_utilization(&self) -> ResourceResult<f64> {
        let cpu_util = self.cpu_manager.get_utilization().await;
        let mem_util = self.memory_manager.get_utilization().await;
        let storage_util = self.storage_manager.get_utilization().await;
        
        // Average utilization across all resources
        Ok((cpu_util + mem_util + storage_util) / 3.0)
    }
    
    /// Get resource statistics
    pub async fn get_stats(&self) -> ResourceStats {
        ResourceStats {
            total_cpu_cores: self.cpu_manager.get_total_cores().await,
            allocated_cpu_cores: self.cpu_manager.get_allocated_cores().await,
            total_memory_mb: self.memory_manager.get_total_memory().await,
            allocated_memory_mb: self.memory_manager.get_allocated_memory().await,
            total_storage_mb: self.storage_manager.get_total_storage().await,
            allocated_storage_mb: self.storage_manager.get_allocated_storage().await,
            active_allocations: self.allocations.len(),
        }
    }
}

/// Resource statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceStats {
    pub total_cpu_cores: f64,
    pub allocated_cpu_cores: f64,
    pub total_memory_mb: u64,
    pub allocated_memory_mb: u64,
    pub total_storage_mb: u64,
    pub allocated_storage_mb: u64,
    pub active_allocations: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_resource_allocation() {
        let manager = ResourceManager::new();
        
        let service_id = Uuid::new_v4();
        let request = ResourceRequest {
            cpu_cores: 2.0,
            memory_mb: 1024,
            disk_mb: 2048,
        };
        
        let allocation = manager.allocate_resources(&service_id, request).await.unwrap();
        assert_eq!(allocation.service_id, service_id);
        
        // Verify allocation exists
        let retrieved = manager.get_allocation(&service_id).await;
        assert!(retrieved.is_some());
        
        // Release resources
        manager.release_resources(&service_id).await.unwrap();
        
        // Verify allocation removed
        let retrieved = manager.get_allocation(&service_id).await;
        assert!(retrieved.is_none());
    }
}