//! Core orchestration engine implementation
//! 
//! Provides the main orchestration logic with sub-millisecond service registration
//! and concurrent deployment capabilities.

use super::*;
use crate::services::registry::ServiceRegistry;
use crate::resources::{ResourceManager, ResourceRequest};
use crate::network::NetworkAllocator;
use crate::reliability::CircuitBreaker;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock, Mutex, Semaphore};
use tokio::time::{interval, Duration};
use tracing::{info, warn, error, debug, instrument};
use dashmap::DashMap;

/// Orchestration engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    /// Maximum concurrent deployments
    pub max_concurrent_deployments: usize,
    /// Service registration timeout in milliseconds
    pub registration_timeout_ms: u64,
    /// Health check interval in seconds
    pub health_check_interval_secs: u64,
    /// Resource allocation timeout in milliseconds
    pub resource_allocation_timeout_ms: u64,
    /// Enable distributed locking
    pub distributed_locking_enabled: bool,
    /// Maximum retry attempts
    pub max_retry_attempts: u32,
    /// Circuit breaker threshold
    pub circuit_breaker_threshold: f64,
    /// Performance monitoring interval in seconds
    pub perf_monitoring_interval_secs: u64,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            max_concurrent_deployments: 100,
            registration_timeout_ms: 500,
            health_check_interval_secs: 5,
            resource_allocation_timeout_ms: 1000,
            distributed_locking_enabled: true,
            max_retry_attempts: 3,
            circuit_breaker_threshold: 0.5,
            perf_monitoring_interval_secs: 10,
        }
    }
}

/// Main orchestration engine
pub struct OrchestrationEngine {
    config: Arc<EngineConfig>,
    registry: Arc<ServiceRegistry>,
    resource_manager: Arc<ResourceManager>,
    network_allocator: Arc<NetworkAllocator>,
    scheduler: Arc<RwLock<Scheduler>>,
    executor: Arc<Executor>,
    deployment_semaphore: Arc<Semaphore>,
    active_deployments: Arc<DashMap<Uuid, DeploymentHandle>>,
    circuit_breakers: Arc<DashMap<String, CircuitBreaker>>,
    metrics: Arc<RwLock<EngineMetrics>>,
    shutdown_signal: Arc<RwLock<Option<mpsc::Sender<()>>>>,
}

/// Deployment handle for tracking active deployments
#[derive(Debug)]
struct DeploymentHandle {
    id: Uuid,
    service_name: String,
    started_at: chrono::DateTime<chrono::Utc>,
    cancel_token: tokio_util::sync::CancellationToken,
}

/// Engine performance metrics
#[derive(Debug, Default)]
struct EngineMetrics {
    total_deployments: u64,
    successful_deployments: u64,
    failed_deployments: u64,
    average_deployment_time_ms: f64,
    current_resource_utilization: f64,
    health_check_latency_ms: f64,
}

impl OrchestrationEngine {
    /// Create a new orchestration engine
    pub async fn new(config: EngineConfig) -> OrchestratorResult<Self> {
        let deployment_semaphore = Arc::new(Semaphore::new(config.max_concurrent_deployments));
        
        let registry = Arc::new(ServiceRegistry::new());
        let resource_manager = Arc::new(ResourceManager::new());
        let network_allocator = Arc::new(NetworkAllocator::new());
        let scheduler = Arc::new(RwLock::new(Scheduler::new(SchedulerConfig::default())));
        let executor = Arc::new(Executor::new(ExecutorConfig::default()));
        
        let engine = Self {
            config: Arc::new(config),
            registry,
            resource_manager,
            network_allocator,
            scheduler,
            executor,
            deployment_semaphore,
            active_deployments: Arc::new(DashMap::new()),
            circuit_breakers: Arc::new(DashMap::new()),
            metrics: Arc::new(RwLock::new(EngineMetrics::default())),
            shutdown_signal: Arc::new(RwLock::new(None)),
        };
        
        // Start background tasks
        engine.start_background_tasks().await?;
        
        Ok(engine)
    }
    
    /// Deploy a service with sub-millisecond registration
    #[instrument(skip(self))]
    pub async fn deploy_service(
        &self,
        name: String,
        version: String,
        resources: ResourceRequest,
    ) -> OrchestratorResult<ServiceMetadata> {
        let start_time = std::time::Instant::now();
        
        // Check circuit breaker
        if let Some(breaker) = self.circuit_breakers.get(&name) {
            if !breaker.can_proceed() {
                return Err(OrchestratorError::DeploymentFailed(
                    format!("Circuit breaker open for service: {}", name)
                ));
            }
        }
        
        // Acquire deployment permit
        let _permit = self.deployment_semaphore.acquire().await
            .map_err(|_| OrchestratorError::ResourceLimitExceeded(
                "Max concurrent deployments reached".to_string()
            ))?;
        
        // Generate service ID
        let service_id = Uuid::new_v4();
        
        // Allocate resources
        let resource_allocation = self.resource_manager
            .allocate_resources(&service_id, resources.clone())
            .await?;
        
        // Allocate network
        let network_config = self.network_allocator
            .allocate_port(&service_id, Protocol::Http)
            .await?;
        
        // Create service metadata
        let metadata = ServiceMetadata {
            id: service_id,
            name: name.clone(),
            version: version.clone(),
            state: DeploymentState::Pending,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            health_status: HealthStatus::default(),
            resource_usage: ResourceUsage::default(),
            network_config,
        };
        
        // Register service (target: sub-millisecond)
        let registration_start = std::time::Instant::now();
        self.registry.register_service(metadata.clone()).await?;
        let registration_duration = registration_start.elapsed();
        
        debug!("Service registered in {:?}", registration_duration);
        
        // Create deployment handle
        let cancel_token = tokio_util::sync::CancellationToken::new();
        let deployment_handle = DeploymentHandle {
            id: service_id,
            service_name: name.clone(),
            started_at: chrono::Utc::now(),
            cancel_token: cancel_token.clone(),
        };
        
        self.active_deployments.insert(service_id, deployment_handle);
        
        // Schedule deployment
        let task = DeploymentTask {
            service_id,
            service_name: name.clone(),
            version,
            resources,
            priority: 100,
        };
        
        let scheduler = self.scheduler.read().await;
        scheduler.schedule_deployment(task).await?;
        
        // Execute deployment asynchronously
        let executor = Arc::clone(&self.executor);
        let registry = Arc::clone(&self.registry);
        let metrics = Arc::clone(&self.metrics);
        let active_deployments = Arc::clone(&self.active_deployments);
        let circuit_breakers = Arc::clone(&self.circuit_breakers);
        
        tokio::spawn(async move {
            let result = executor.execute_deployment(service_id).await;
            
            match result {
                Ok(_) => {
                    registry.update_service_state(service_id, DeploymentState::Running).await.ok();
                    
                    let mut metrics = metrics.write().await;
                    metrics.successful_deployments += 1;
                    metrics.total_deployments += 1;
                    
                    // Update circuit breaker
                    if let Some(mut breaker) = circuit_breakers.get_mut(&name) {
                        breaker.record_success();
                    }
                }
                Err(e) => {
                    error!("Deployment failed for {}: {:?}", name, e);
                    registry.update_service_state(service_id, DeploymentState::Failed).await.ok();
                    
                    let mut metrics = metrics.write().await;
                    metrics.failed_deployments += 1;
                    metrics.total_deployments += 1;
                    
                    // Update circuit breaker
                    if let Some(mut breaker) = circuit_breakers.get_mut(&name) {
                        breaker.record_failure();
                    }
                }
            }
            
            active_deployments.remove(&service_id);
        });
        
        // Update metrics
        let deployment_time = start_time.elapsed().as_millis() as f64;
        let mut metrics = self.metrics.write().await;
        metrics.average_deployment_time_ms = 
            (metrics.average_deployment_time_ms * (metrics.total_deployments as f64) + deployment_time) 
            / ((metrics.total_deployments + 1) as f64);
        
        Ok(metadata)
    }
    
    /// Get service status
    pub async fn get_service_status(&self, service_id: Uuid) -> OrchestratorResult<ServiceMetadata> {
        self.registry.get_service(service_id).await
    }
    
    /// List all services
    pub async fn list_services(&self) -> OrchestratorResult<Vec<ServiceMetadata>> {
        self.registry.list_services().await
    }
    
    /// Stop a service gracefully
    #[instrument(skip(self))]
    pub async fn stop_service(&self, service_id: Uuid) -> OrchestratorResult<()> {
        // Update state
        self.registry.update_service_state(service_id, DeploymentState::Stopping).await?;
        
        // Cancel deployment if active
        if let Some(handle) = self.active_deployments.remove(&service_id) {
            handle.1.cancel_token.cancel();
        }
        
        // Execute stop
        self.executor.stop_service(service_id).await?;
        
        // Release resources
        self.resource_manager.release_resources(&service_id).await?;
        self.network_allocator.release_port(&service_id).await?;
        
        // Update state
        self.registry.update_service_state(service_id, DeploymentState::Stopped).await?;
        
        Ok(())
    }
    
    /// Start background tasks
    async fn start_background_tasks(&self) -> OrchestratorResult<()> {
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
        *self.shutdown_signal.write().await = Some(shutdown_tx);
        
        // Health check task
        let registry = Arc::clone(&self.registry);
        let health_interval = self.config.health_check_interval_secs;
        let metrics = Arc::clone(&self.metrics);
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(health_interval));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let start = std::time::Instant::now();
                        if let Ok(services) = registry.list_services().await {
                            for service in services {
                                if service.state == DeploymentState::Running {
                                    // Perform health check
                                    registry.check_service_health(service.id).await.ok();
                                }
                            }
                        }
                        let latency = start.elapsed().as_millis() as f64;
                        
                        let mut m = metrics.write().await;
                        m.health_check_latency_ms = latency;
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Health check task shutting down");
                        break;
                    }
                }
            }
        });
        
        // Performance monitoring task
        let metrics = Arc::clone(&self.metrics);
        let resource_manager = Arc::clone(&self.resource_manager);
        let perf_interval = self.config.perf_monitoring_interval_secs;
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(perf_interval));
            loop {
                interval.tick().await;
                
                // Update resource utilization
                if let Ok(utilization) = resource_manager.get_total_utilization().await {
                    let mut m = metrics.write().await;
                    m.current_resource_utilization = utilization;
                }
            }
        });
        
        Ok(())
    }
    
    /// Perform graceful shutdown
    pub async fn shutdown(&self) -> OrchestratorResult<()> {
        info!("Starting graceful shutdown");
        
        // Signal background tasks to stop
        if let Some(shutdown_tx) = self.shutdown_signal.write().await.take() {
            shutdown_tx.send(()).await.ok();
        }
        
        // Stop all active deployments
        let active_ids: Vec<Uuid> = self.active_deployments
            .iter()
            .map(|entry| *entry.key())
            .collect();
        
        for service_id in active_ids {
            self.stop_service(service_id).await.ok();
        }
        
        info!("Graceful shutdown complete");
        Ok(())
    }
    
    /// Get engine metrics
    pub async fn get_metrics(&self) -> EngineMetrics {
        self.metrics.read().await.clone()
    }
}

impl Clone for EngineMetrics {
    fn clone(&self) -> Self {
        Self {
            total_deployments: self.total_deployments,
            successful_deployments: self.successful_deployments,
            failed_deployments: self.failed_deployments,
            average_deployment_time_ms: self.average_deployment_time_ms,
            current_resource_utilization: self.current_resource_utilization,
            health_check_latency_ms: self.health_check_latency_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_engine_creation() {
        let config = EngineConfig::default();
        let engine = OrchestrationEngine::new(config).await.unwrap();
        assert!(engine.list_services().await.unwrap().is_empty());
    }
    
    #[tokio::test]
    async fn test_service_deployment() {
        let config = EngineConfig::default();
        let engine = OrchestrationEngine::new(config).await.unwrap();
        
        let resources = ResourceRequest {
            cpu_cores: 1.0,
            memory_mb: 512,
            disk_mb: 1024,
        };
        
        let metadata = engine.deploy_service(
            "test-service".to_string(),
            "1.0.0".to_string(),
            resources,
        ).await.unwrap();
        
        assert_eq!(metadata.name, "test-service");
        assert_eq!(metadata.version, "1.0.0");
        assert_eq!(metadata.state, DeploymentState::Pending);
    }
}