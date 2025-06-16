use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use tracing::{info, warn, debug};

use crate::config::DeploymentConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAllocation {
    pub service: String,
    pub cpu_cores: f32,
    pub memory_mb: u32,
    pub storage_gb: u32,
    pub gpu_count: u8,
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtilizationMetrics {
    pub cpu_percent: f64,
    pub memory_percent: f64,
    pub storage_percent: f64,
    pub gpu_percent: f64,
}

#[derive(Debug, Clone)]
pub struct ResourceManager {
    config: Arc<DeploymentConfig>,
    allocations: Arc<DashMap<String, ResourceAllocation>>,
    available_resources: Arc<RwLock<SystemResources>>,
}

#[derive(Debug, Clone)]
struct SystemResources {
    cpu_cores: f32,
    memory_mb: u32,
    storage_gb: u32,
    gpu_count: u8,
    allocated_ports: Vec<u16>,
}

impl ResourceManager {
    pub fn new(config: Arc<DeploymentConfig>) -> Self {
        // Initialize with system resources (simplified for now)
        let system_resources = SystemResources {
            cpu_cores: 64.0,  // AMD Ryzen 7 7800X3D has 8 cores, but we're in a larger system
            memory_mb: 524288, // 512GB total system memory
            storage_gb: 2048,  // 2TB storage
            gpu_count: 4,      // Assume 4 GPUs available
            allocated_ports: Vec::new(),
        };
        
        Self {
            config,
            allocations: Arc::new(DashMap::new()),
            available_resources: Arc::new(RwLock::new(system_resources)),
        }
    }
    
    pub async fn get_utilization_metrics(&self) -> UtilizationMetrics {
        let resources = self.available_resources.read().await;
        let total_cpu = 64.0;
        let total_memory = 524288;
        let total_storage = 2048;
        let total_gpu = 4;
        
        UtilizationMetrics {
            cpu_percent: ((total_cpu - resources.cpu_cores) as f64 / total_cpu as f64) * 100.0,
            memory_percent: ((total_memory - resources.memory_mb) as f64 / total_memory as f64) * 100.0,
            storage_percent: ((total_storage - resources.storage_gb) as f64 / total_storage as f64) * 100.0,
            gpu_percent: ((total_gpu - resources.gpu_count) as f64 / total_gpu as f64) * 100.0,
        }
    }
    
    pub async fn get_service_metrics(&self, service: &str) -> Option<ResourceAllocation> {
        self.get_allocation(service).await
    }
    
    pub async fn validate_availability(&self) -> Result<()> {
        let resources = self.available_resources.read().await;
        
        // Calculate total required resources
        let mut total_cpu = 0.0;
        let mut total_memory = 0;
        let mut total_storage = 0;
        let mut total_gpu = 0;
        
        for (_, service_config) in &self.config.services {
            if service_config.enabled {
                total_cpu += service_config.resources.cpu_cores * service_config.replicas as f32;
                total_memory += service_config.resources.memory_mb * service_config.replicas;
                total_storage += service_config.resources.storage_gb * service_config.replicas;
                total_gpu += service_config.resources.gpu_count * service_config.replicas as u8;
            }
        }
        
        // Check if we have enough resources
        if total_cpu > resources.cpu_cores {
            return Err(anyhow::anyhow!(
                "Insufficient CPU cores: required {}, available {}",
                total_cpu,
                resources.cpu_cores
            ));
        }
        
        if total_memory > resources.memory_mb {
            return Err(anyhow::anyhow!(
                "Insufficient memory: required {}MB, available {}MB",
                total_memory,
                resources.memory_mb
            ));
        }
        
        if total_storage > resources.storage_gb {
            return Err(anyhow::anyhow!(
                "Insufficient storage: required {}GB, available {}GB",
                total_storage,
                resources.storage_gb
            ));
        }
        
        if total_gpu > resources.gpu_count {
            return Err(anyhow::anyhow!(
                "Insufficient GPUs: required {}, available {}",
                total_gpu,
                resources.gpu_count
            ));
        }
        
        info!("Resource validation passed");
        info!("Required: CPU={:.1}, Memory={}MB, Storage={}GB, GPU={}",
            total_cpu, total_memory, total_storage, total_gpu);
        
        Ok(())
    }
    
    pub async fn allocate(&self, service: &str, cpu: f32, memory: u32, storage: u32, gpu: u8) -> Result<()> {
        let mut resources = self.available_resources.write().await;
        
        // Check availability
        if cpu > resources.cpu_cores {
            return Err(anyhow::anyhow!("Insufficient CPU cores for {}", service));
        }
        
        if memory > resources.memory_mb {
            return Err(anyhow::anyhow!("Insufficient memory for {}", service));
        }
        
        if storage > resources.storage_gb {
            return Err(anyhow::anyhow!("Insufficient storage for {}", service));
        }
        
        if gpu > resources.gpu_count {
            return Err(anyhow::anyhow!("Insufficient GPUs for {}", service));
        }
        
        // Allocate resources
        resources.cpu_cores -= cpu;
        resources.memory_mb -= memory;
        resources.storage_gb -= storage;
        resources.gpu_count -= gpu;
        
        let allocation = ResourceAllocation {
            service: service.to_string(),
            cpu_cores: cpu,
            memory_mb: memory,
            storage_gb: storage,
            gpu_count: gpu,
            ports: Vec::new(),
        };
        
        self.allocations.insert(service.to_string(), allocation);
        
        debug!("Allocated resources for {}: CPU={}, Memory={}MB, Storage={}GB, GPU={}",
            service, cpu, memory, storage, gpu);
        
        Ok(())
    }
    
    pub async fn allocate_batch(&self, requirements: Vec<(String, f32, u32, u32, u8)>) -> Result<()> {
        // Validate all requirements first
        let mut resources = self.available_resources.write().await;
        
        let mut total_cpu = 0.0;
        let mut total_memory = 0;
        let mut total_storage = 0;
        let mut total_gpu = 0;
        
        for (_, cpu, memory, storage, gpu) in &requirements {
            total_cpu += cpu;
            total_memory += memory;
            total_storage += storage;
            total_gpu += gpu;
        }
        
        // Check total availability
        if total_cpu > resources.cpu_cores ||
           total_memory > resources.memory_mb ||
           total_storage > resources.storage_gb ||
           total_gpu > resources.gpu_count {
            return Err(anyhow::anyhow!("Insufficient resources for batch allocation"));
        }
        
        // Allocate all resources
        for (service, cpu, memory, storage, gpu) in requirements {
            resources.cpu_cores -= cpu;
            resources.memory_mb -= memory;
            resources.storage_gb -= storage;
            resources.gpu_count -= gpu;
            
            let allocation = ResourceAllocation {
                service: service.clone(),
                cpu_cores: cpu,
                memory_mb: memory,
                storage_gb: storage,
                gpu_count: gpu,
                ports: Vec::new(),
            };
            
            self.allocations.insert(service, allocation);
        }
        
        info!("Batch allocation completed successfully");
        Ok(())
    }
    
    pub async fn deallocate(&self, service: &str) -> Result<()> {
        if let Some((_, allocation)) = self.allocations.remove(service) {
            let mut resources = self.available_resources.write().await;
            
            // Return resources to pool
            resources.cpu_cores += allocation.cpu_cores;
            resources.memory_mb += allocation.memory_mb;
            resources.storage_gb += allocation.storage_gb;
            resources.gpu_count += allocation.gpu_count;
            
            debug!("Deallocated resources for {}", service);
            Ok(())
        } else {
            warn!("Attempted to deallocate resources for unknown service: {}", service);
            Ok(())
        }
    }
    
    pub async fn get_allocation(&self, service: &str) -> Option<ResourceAllocation> {
        self.allocations.get(service).map(|a| a.clone())
    }
    
    pub async fn get_available_resources(&self) -> (f32, u32, u32, u8) {
        let resources = self.available_resources.read().await;
        (
            resources.cpu_cores,
            resources.memory_mb,
            resources.storage_gb,
            resources.gpu_count,
        )
    }
}