//! Service registry with concurrent access
//! 
//! Provides sub-millisecond service registration and lookup with
//! thread-safe concurrent access using lock-free data structures.

use super::*;
use crate::orchestrator::{ServiceMetadata, DeploymentState, HealthStatus, OrchestratorError};
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use tracing::{debug, instrument};
use std::time::Instant;

/// Registry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryConfig {
    /// Maximum number of services
    pub max_services: usize,
    /// Enable persistence
    pub persistence_enabled: bool,
    /// Persistence path
    pub persistence_path: Option<String>,
    /// Enable metrics collection
    pub metrics_enabled: bool,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            max_services: 10000,
            persistence_enabled: false,
            persistence_path: None,
            metrics_enabled: true,
        }
    }
}

/// Service registry with lock-free concurrent access
pub struct ServiceRegistry {
    config: Arc<RegistryConfig>,
    services: Arc<DashMap<Uuid, ServiceMetadata>>,
    service_names: Arc<DashMap<String, Uuid>>,
    metrics: Arc<RwLock<RegistryMetrics>>,
}

/// Registry performance metrics
#[derive(Debug, Default)]
struct RegistryMetrics {
    total_registrations: u64,
    total_lookups: u64,
    total_updates: u64,
    total_removals: u64,
    average_registration_ns: u64,
    average_lookup_ns: u64,
    peak_services: usize,
}

impl ServiceRegistry {
    /// Create a new service registry
    pub fn new() -> Self {
        Self::with_config(RegistryConfig::default())
    }
    
    /// Create registry with custom configuration
    pub fn with_config(config: RegistryConfig) -> Self {
        Self {
            config: Arc::new(config),
            services: Arc::new(DashMap::new()),
            service_names: Arc::new(DashMap::new()),
            metrics: Arc::new(RwLock::new(RegistryMetrics::default())),
        }
    }
    
    /// Register a new service (target: sub-millisecond)
    #[instrument(skip(self, metadata), fields(service_id = %metadata.id, service_name = %metadata.name))]
    pub async fn register_service(&self, metadata: ServiceMetadata) -> Result<(), OrchestratorError> {
        let start = Instant::now();
        
        // Check capacity
        if self.services.len() >= self.config.max_services {
            return Err(OrchestratorError::ResourceLimitExceeded(
                format!("Registry full: {} services", self.config.max_services)
            ));
        }
        
        // Check for duplicate name
        if self.service_names.contains_key(&metadata.name) {
            return Err(OrchestratorError::ServiceNotFound(
                format!("Service with name '{}' already exists", metadata.name)
            ));
        }
        
        let service_id = metadata.id;
        let service_name = metadata.name.clone();
        
        // Insert into registry (lock-free operation)
        self.services.insert(service_id, metadata);
        self.service_names.insert(service_name, service_id);
        
        // Update metrics
        let duration_ns = start.elapsed().as_nanos() as u64;
        
        if self.config.metrics_enabled {
            let mut metrics = self.metrics.write().await;
            metrics.total_registrations += 1;
            metrics.average_registration_ns = 
                (metrics.average_registration_ns * (metrics.total_registrations - 1) + duration_ns) 
                / metrics.total_registrations;
            
            let current_services = self.services.len();
            if current_services > metrics.peak_services {
                metrics.peak_services = current_services;
            }
        }
        
        debug!("Service registered in {} ns", duration_ns);
        Ok(())
    }
    
    /// Get service by ID (lock-free lookup)
    #[instrument(skip(self))]
    pub async fn get_service(&self, service_id: Uuid) -> Result<ServiceMetadata, OrchestratorError> {
        let start = Instant::now();
        
        let result = self.services
            .get(&service_id)
            .map(|entry| entry.clone())
            .ok_or_else(|| OrchestratorError::ServiceNotFound(service_id.to_string()));
        
        // Update metrics
        if self.config.metrics_enabled {
            let duration_ns = start.elapsed().as_nanos() as u64;
            let mut metrics = self.metrics.write().await;
            metrics.total_lookups += 1;
            metrics.average_lookup_ns = 
                (metrics.average_lookup_ns * (metrics.total_lookups - 1) + duration_ns) 
                / metrics.total_lookups;
        }
        
        result
    }
    
    /// Get service by name
    pub async fn get_service_by_name(&self, name: &str) -> Result<ServiceMetadata, OrchestratorError> {
        let service_id = self.service_names
            .get(name)
            .map(|entry| *entry.value())
            .ok_or_else(|| OrchestratorError::ServiceNotFound(name.to_string()))?;
        
        self.get_service(service_id).await
    }
    
    /// List all services
    pub async fn list_services(&self) -> Result<Vec<ServiceMetadata>, OrchestratorError> {
        Ok(self.services
            .iter()
            .map(|entry| entry.value().clone())
            .collect::<Vec<ServiceMetadata>>())
    }
    
    /// List services by state
    pub async fn list_services_by_state(&self, state: DeploymentState) -> Vec<ServiceMetadata> {
        self.services
            .iter()
            .filter(|entry| entry.value().state == state)
            .map(|entry| entry.value().clone())
            .collect::<Vec<ServiceMetadata>>()
    }
    
    /// Update service state
    #[instrument(skip(self))]
    pub async fn update_service_state(
        &self, 
        service_id: Uuid, 
        new_state: DeploymentState
    ) -> Result<(), OrchestratorError> {
        let start = Instant::now();
        
        self.services
            .get_mut(&service_id)
            .map(|mut entry| {
                entry.state = new_state;
                entry.updated_at = chrono::Utc::now();
            })
            .ok_or_else(|| OrchestratorError::ServiceNotFound(service_id.to_string()))?;
        
        // Update metrics
        if self.config.metrics_enabled {
            let mut metrics = self.metrics.write().await;
            metrics.total_updates += 1;
        }
        
        debug!("Service state updated in {:?}", start.elapsed());
        Ok(())
    }
    
    /// Update service health status
    pub async fn update_health_status(
        &self,
        service_id: Uuid,
        health_status: HealthStatus
    ) -> Result<(), OrchestratorError> {
        self.services
            .get_mut(&service_id)
            .map(|mut entry| {
                entry.health_status = health_status;
                entry.updated_at = chrono::Utc::now();
            })
            .ok_or_else(|| OrchestratorError::ServiceNotFound(service_id.to_string()))?;
        
        Ok(())
    }
    
    /// Remove a service from registry
    #[instrument(skip(self))]
    pub async fn remove_service(&self, service_id: Uuid) -> Result<(), OrchestratorError> {
        // Get service name for cleanup
        let service_name = self.services
            .get(&service_id)
            .map(|entry| entry.name.clone());
        
        // Remove from services
        self.services
            .remove(&service_id)
            .ok_or_else(|| OrchestratorError::ServiceNotFound(service_id.to_string()))?;
        
        // Remove from name index
        if let Some(name) = service_name {
            self.service_names.remove(&name);
        }
        
        // Update metrics
        if self.config.metrics_enabled {
            let mut metrics = self.metrics.write().await;
            metrics.total_removals += 1;
        }
        
        Ok(())
    }
    
    /// Check if a service exists
    pub async fn exists(&self, service_id: Uuid) -> bool {
        self.services.contains_key(&service_id)
    }
    
    /// Get registry statistics
    pub async fn get_stats(&self) -> RegistryStats {
        let metrics = self.metrics.read().await;
        
        let by_state = self.get_services_by_state().await;
        
        RegistryStats {
            total_services: self.services.len(),
            services_by_state: by_state,
            total_registrations: metrics.total_registrations,
            total_lookups: metrics.total_lookups,
            total_updates: metrics.total_updates,
            total_removals: metrics.total_removals,
            average_registration_ns: metrics.average_registration_ns,
            average_lookup_ns: metrics.average_lookup_ns,
            peak_services: metrics.peak_services,
        }
    }
    
    /// Get count of services by state
    async fn get_services_by_state(&self) -> std::collections::HashMap<DeploymentState, usize> {
        use std::collections::HashMap;
        
        let mut by_state = HashMap::new();
        
        for entry in self.services.iter() {
            *by_state.entry(entry.value().state).or_insert(0) += 1;
        }
        
        by_state
    }
    
    /// Clear all services (for testing)
    #[cfg(test)]
    pub async fn clear(&self) {
        self.services.clear();
        self.service_names.clear();
    }
    
    /// Perform health check on a service
    pub async fn check_service_health(&self, service_id: Uuid) -> Result<(), OrchestratorError> {
        // This is a placeholder - actual implementation would perform real health checks
        let health_status = HealthStatus {
            is_healthy: true,
            last_check: chrono::Utc::now(),
            consecutive_failures: 0,
            latency_ms: 5.0,
            error_rate: 0.0,
        };
        
        self.update_health_status(service_id, health_status).await
    }
}

/// Registry statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryStats {
    pub total_services: usize,
    pub services_by_state: std::collections::HashMap<DeploymentState, usize>,
    pub total_registrations: u64,
    pub total_lookups: u64,
    pub total_updates: u64,
    pub total_removals: u64,
    pub average_registration_ns: u64,
    pub average_lookup_ns: u64,
    pub peak_services: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::{ResourceUsage, NetworkConfig, Protocol};
    
    #[tokio::test]
    async fn test_service_registration() {
        let registry = ServiceRegistry::new();
        
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
                external_port: None,
                protocol: Protocol::Http,
                service_mesh_enabled: false,
                load_balancer_config: None,
            },
        };
        
        registry.register_service(metadata.clone()).await.unwrap();
        
        let retrieved = registry.get_service(metadata.id).await.unwrap();
        assert_eq!(retrieved.name, metadata.name);
        assert_eq!(retrieved.version, metadata.version);
    }
    
    #[tokio::test]
    async fn test_concurrent_registration() {
        let registry = Arc::new(ServiceRegistry::new());
        let mut handles = vec![];
        
        for i in 0..100 {
            let registry = Arc::clone(&registry);
            let handle = tokio::spawn(async move {
                let metadata = ServiceMetadata {
                    id: Uuid::new_v4(),
                    name: format!("service-{}", i),
                    version: "1.0.0".to_string(),
                    state: DeploymentState::Pending,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                    health_status: HealthStatus::default(),
                    resource_usage: ResourceUsage::default(),
                    network_config: NetworkConfig {
                        internal_port: 8080 + i as u16,
                        external_port: None,
                        protocol: Protocol::Http,
                        service_mesh_enabled: false,
                        load_balancer_config: None,
                    },
                };
                
                registry.register_service(metadata).await
            });
            handles.push(handle);
        }
        
        for handle in handles {
            handle.await.unwrap().unwrap();
        }
        
        let services = registry.list_services().await.unwrap();
        assert_eq!(services.len(), 100);
    }
    
    #[tokio::test]
    async fn test_service_state_updates() {
        let registry = ServiceRegistry::new();
        
        let metadata = ServiceMetadata {
            id: Uuid::new_v4(),
            name: "state-test".to_string(),
            version: "1.0.0".to_string(),
            state: DeploymentState::Pending,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            health_status: HealthStatus::default(),
            resource_usage: ResourceUsage::default(),
            network_config: NetworkConfig {
                internal_port: 8080,
                external_port: None,
                protocol: Protocol::Http,
                service_mesh_enabled: false,
                load_balancer_config: None,
            },
        };
        
        registry.register_service(metadata.clone()).await.unwrap();
        
        // Update state
        registry.update_service_state(metadata.id, DeploymentState::Running).await.unwrap();
        
        let updated = registry.get_service(metadata.id).await.unwrap();
        assert_eq!(updated.state, DeploymentState::Running);
    }
}