use anyhow::{Result, Context};
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{info, debug, warn, instrument};
use serde::{Serialize, Deserialize};

use super::{ServiceInfo, ServiceStatus, HealthStatus};

#[derive(Debug, Clone)]
pub struct ServiceRegistry {
    services: Arc<DashMap<String, ServiceInfo>>,
    deployment_tracking: Arc<RwLock<DeploymentTracking>>,
    health_cache: Arc<DashMap<String, CachedHealth>>,
}

#[derive(Debug, Clone)]
struct DeploymentTracking {
    current_deployment_id: Option<String>,
    deployment_services: Vec<String>,
    deployment_start: Option<Instant>,
}

#[derive(Debug, Clone)]
struct CachedHealth {
    status: String,
    health: HealthStatus,
    last_check: Instant,
}

impl ServiceRegistry {
    pub fn new() -> Self {
        Self {
            services: Arc::new(DashMap::new()),
            deployment_tracking: Arc::new(RwLock::new(DeploymentTracking {
                current_deployment_id: None,
                deployment_services: Vec::new(),
                deployment_start: None,
            })),
            health_cache: Arc::new(DashMap::new()),
        }
    }

    #[instrument(skip(self, info))]
    pub async fn register(&self, name: String, info: ServiceInfo) -> Result<()> {
        info!("Registering service: {}", name);
        
        // Validate service info
        if name.is_empty() {
            return Err(anyhow::anyhow!("Service name cannot be empty"));
        }
        
        // Check if service already exists
        if self.services.contains_key(&name) {
            warn!("Service {} already registered, updating", name);
        }
        
        // Insert or update service
        self.services.insert(name.clone(), info);
        
        // Track in current deployment
        let mut tracking = self.deployment_tracking.write().await;
        if tracking.current_deployment_id.is_some() {
            tracking.deployment_services.push(name.clone());
        }
        
        debug!("Service {} registered successfully", name);
        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn unregister(&self, name: &str) -> Result<()> {
        info!("Unregistering service: {}", name);
        
        if self.services.remove(name).is_none() {
            return Err(anyhow::anyhow!("Service {} not found", name));
        }
        
        // Remove from health cache
        self.health_cache.remove(name);
        
        // Remove from deployment tracking
        let mut tracking = self.deployment_tracking.write().await;
        tracking.deployment_services.retain(|s| s != name);
        
        Ok(())
    }

    pub async fn get_service_info(&self, name: &str) -> Result<ServiceInfo> {
        self.services
            .get(name)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| anyhow::anyhow!("Service {} not found", name))
    }

    pub async fn get_service_status(&self, name: &str) -> Result<ServiceStatus> {
        self.services
            .get(name)
            .map(|entry| entry.status.clone())
            .ok_or_else(|| anyhow::anyhow!("Service {} not found", name))
    }

    pub async fn update_status(&self, name: &str, status: ServiceStatus) -> Result<()> {
        self.services
            .get_mut(name)
            .map(|mut entry| {
                entry.status = status.clone();
                if status == ServiceStatus::Running && entry.start_time.is_none() {
                    entry.start_time = Some(Instant::now());
                }
            })
            .ok_or_else(|| anyhow::anyhow!("Service {} not found", name))
    }

    pub async fn update_pid(&self, name: &str, pid: u32) -> Result<()> {
        self.services
            .get_mut(name)
            .map(|mut entry| {
                entry.pid = Some(pid);
            })
            .ok_or_else(|| anyhow::anyhow!("Service {} not found", name))
    }

    pub async fn get_service_health(&self, name: &str) -> Result<String> {
        // Check cache first
        if let Some(cached) = self.health_cache.get(name) {
            if cached.last_check.elapsed().as_secs() < 30 {
                return Ok(cached.status.clone());
            }
        }
        
        // Get fresh health status
        let health_status = self.get_service_health_status(name).await?;
        let status_str = match health_status {
            HealthStatus::Healthy => "healthy",
            HealthStatus::Degraded => "degraded",
            HealthStatus::Unhealthy => "unhealthy",
            HealthStatus::Unknown => "unknown",
        };
        
        // Update cache
        self.health_cache.insert(
            name.to_string(),
            CachedHealth {
                status: status_str.to_string(),
                health: health_status,
                last_check: Instant::now(),
            },
        );
        
        Ok(status_str.to_string())
    }

    pub async fn get_service_health_status(&self, name: &str) -> Result<HealthStatus> {
        self.services
            .get(name)
            .map(|entry| entry.health.clone())
            .ok_or_else(|| anyhow::anyhow!("Service {} not found", name))
    }

    pub async fn update_health(&self, name: &str, health: HealthStatus) -> Result<()> {
        self.services
            .get_mut(name)
            .map(|mut entry| {
                entry.health = health;
            })
            .ok_or_else(|| anyhow::anyhow!("Service {} not found", name))
    }

    pub async fn list_all_services(&self) -> Vec<String> {
        self.services
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    pub async fn list_services_by_status(&self, status: ServiceStatus) -> Vec<String> {
        self.services
            .iter()
            .filter(|entry| entry.status == status)
            .map(|entry| entry.key().clone())
            .collect()
    }

    pub async fn list_services_by_deployment(&self) -> Result<Vec<String>> {
        let tracking = self.deployment_tracking.read().await;
        Ok(tracking.deployment_services.clone())
    }

    pub async fn start_deployment(&self, deployment_id: String) -> Result<()> {
        let mut tracking = self.deployment_tracking.write().await;
        
        if tracking.current_deployment_id.is_some() {
            return Err(anyhow::anyhow!("A deployment is already in progress"));
        }
        
        tracking.current_deployment_id = Some(deployment_id);
        tracking.deployment_services.clear();
        tracking.deployment_start = Some(Instant::now());
        
        Ok(())
    }

    pub async fn end_deployment(&self) -> Result<()> {
        let mut tracking = self.deployment_tracking.write().await;
        
        if tracking.current_deployment_id.is_none() {
            return Err(anyhow::anyhow!("No deployment in progress"));
        }
        
        tracking.current_deployment_id = None;
        tracking.deployment_start = None;
        // Keep deployment_services for rollback purposes
        
        Ok(())
    }

    pub async fn get_service_count(&self) -> ServiceCount {
        let mut count = ServiceCount::default();
        
        for entry in self.services.iter() {
            match entry.status {
                ServiceStatus::NotStarted => count.not_started += 1,
                ServiceStatus::Starting => count.starting += 1,
                ServiceStatus::Running => count.running += 1,
                ServiceStatus::Stopping => count.stopping += 1,
                ServiceStatus::Stopped => count.stopped += 1,
                ServiceStatus::Failed => count.failed += 1,
                ServiceStatus::Unknown => count.unknown += 1,
            }
            count.total += 1;
        }
        
        count
    }

    pub async fn get_healthy_service_count(&self) -> usize {
        self.services
            .iter()
            .filter(|entry| entry.health == HealthStatus::Healthy)
            .count()
    }

    pub async fn export_registry(&self) -> RegistryExport {
        let services: Vec<ServiceInfo> = self.services
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        
        let tracking = self.deployment_tracking.read().await;
        
        RegistryExport {
            services,
            current_deployment: tracking.current_deployment_id.clone(),
            deployment_services: tracking.deployment_services.clone(),
            timestamp: std::time::SystemTime::now(),
        }
    }

    pub async fn import_registry(&self, export: RegistryExport) -> Result<()> {
        // Clear existing services
        self.services.clear();
        self.health_cache.clear();
        
        // Import services
        for service in export.services {
            let name = service.name.clone();
            self.services.insert(name, service);
        }
        
        // Import deployment tracking
        let mut tracking = self.deployment_tracking.write().await;
        tracking.current_deployment_id = export.current_deployment;
        tracking.deployment_services = export.deployment_services;
        
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceCount {
    pub total: usize,
    pub not_started: usize,
    pub starting: usize,
    pub running: usize,
    pub stopping: usize,
    pub stopped: usize,
    pub failed: usize,
    pub unknown: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryExport {
    pub services: Vec<ServiceInfo>,
    pub current_deployment: Option<String>,
    pub deployment_services: Vec<String>,
    pub timestamp: std::time::SystemTime,
}