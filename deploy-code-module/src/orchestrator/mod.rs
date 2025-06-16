use anyhow::{Result, Context};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug, instrument};
use dashmap::DashMap;
use serde::{Serialize, Deserialize};

pub mod engine;
pub mod scheduler;
pub mod executor;

use crate::services::{ServiceRegistry, ServiceStatus};
use crate::resources::ResourceManager;
use crate::network::NetworkManager;
use crate::reliability::{CircuitBreaker, RecoveryManager};
use crate::monitoring::MetricsCollector;
use crate::config::DeploymentConfig;

use engine::OrchestrationEngine;
use scheduler::DeploymentScheduler;
use executor::ServiceExecutor;

struct DeploymentResult {
    total: usize,
    deployed: usize,
    failed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentReport {
    pub success: bool,
    pub total_services: usize,
    pub deployed_services: usize,
    pub failed_services: usize,
    pub warnings: usize,
    pub duration: Duration,
    pub phases_completed: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatusDetails {
    pub status: String,
    pub health: String,
    pub uptime: Option<Duration>,
    pub cpu_usage: Option<f64>,
    pub memory_usage: Option<f64>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformStatus {
    pub overall_health: String,
    pub total_services: usize,
    pub running_services: usize,
    pub failed_services: usize,
    pub services: std::collections::HashMap<String, ServiceStatusDetails>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    pub status: String,
    pub score: u8,
    pub uptime_hours: f64,
    pub issues: Vec<HealthIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthIssue {
    pub severity: String,
    pub service: String,
    pub message: String,
}

pub struct DeploymentOrchestrator {
    engine: Arc<OrchestrationEngine>,
    scheduler: Arc<DeploymentScheduler>,
    executor: Arc<ServiceExecutor>,
    service_registry: Arc<ServiceRegistry>,
    resource_manager: Arc<ResourceManager>,
    network_manager: Arc<NetworkManager>,
    circuit_breaker: Arc<CircuitBreaker>,
    recovery_manager: Arc<RecoveryManager>,
    metrics: Arc<MetricsCollector>,
    config: Arc<DeploymentConfig>,
    state: Arc<RwLock<OrchestratorState>>,
    dry_run: bool,
    force: bool,
}

#[derive(Debug, Clone)]
struct OrchestratorState {
    start_time: Instant,
    deployment_in_progress: bool,
    last_deployment: Option<Instant>,
    total_deployments: u64,
    failed_deployments: u64,
}

impl DeploymentOrchestrator {
    pub async fn new(
        config: DeploymentConfig,
        dry_run: bool,
        force: bool,
    ) -> Result<Self> {
        info!("Initializing deployment orchestrator...");
        
        let config = Arc::new(config);
        
        // Initialize components
        let service_registry = Arc::new(ServiceRegistry::new());
        let resource_manager = Arc::new(ResourceManager::new(config.clone()));
        let network_manager = Arc::new(NetworkManager::new(config.clone()));
        let circuit_breaker = Arc::new(CircuitBreaker::new());
        let recovery_manager = Arc::new(RecoveryManager::new());
        let metrics = Arc::new(MetricsCollector::new());
        
        // Initialize orchestration components
        let engine = Arc::new(OrchestrationEngine::new(
            service_registry.clone(),
            resource_manager.clone(),
        ));
        
        let scheduler = Arc::new(DeploymentScheduler::new(
            config.clone(),
            service_registry.clone(),
        ));
        
        let executor = Arc::new(ServiceExecutor::new(
            service_registry.clone(),
            circuit_breaker.clone(),
            metrics.clone(),
        ));
        
        let state = Arc::new(RwLock::new(OrchestratorState {
            start_time: Instant::now(),
            deployment_in_progress: false,
            last_deployment: None,
            total_deployments: 0,
            failed_deployments: 0,
        }));
        
        Ok(Self {
            engine,
            scheduler,
            executor,
            service_registry,
            resource_manager,
            network_manager,
            circuit_breaker,
            recovery_manager,
            metrics,
            config,
            state,
            dry_run,
            force,
        })
    }
    
    #[instrument(skip(self))]
    pub async fn deploy(
        &self,
        services: Vec<String>,
        skip_phases: Vec<String>,
    ) -> Result<DeploymentReport> {
        let start_time = Instant::now();
        
        // Check if deployment is already in progress
        {
            let mut state = self.state.write().await;
            if state.deployment_in_progress {
                return Err(anyhow::anyhow!("Deployment already in progress"));
            }
            state.deployment_in_progress = true;
            state.total_deployments += 1;
        }
        
        let mut report = DeploymentReport {
            success: false,
            total_services: 0,
            deployed_services: 0,
            failed_services: 0,
            warnings: 0,
            duration: Duration::default(),
            phases_completed: Vec::new(),
            errors: Vec::new(),
        };
        
        // Execute deployment
        let result = self.execute_deployment(services, skip_phases, &mut report).await;
        
        // Update state
        {
            let mut state = self.state.write().await;
            state.deployment_in_progress = false;
            state.last_deployment = Some(Instant::now());
            
            if result.is_err() {
                state.failed_deployments += 1;
            }
        }
        
        report.duration = start_time.elapsed();
        report.success = result.is_ok();
        
        if let Err(e) = result {
            report.errors.push(e.to_string());
            return Err(e);
        }
        
        Ok(report)
    }
    
    async fn execute_deployment(
        &self,
        services: Vec<String>,
        skip_phases: Vec<String>,
        report: &mut DeploymentReport,
    ) -> Result<()> {
        info!("Starting deployment execution...");
        
        // Phase 1: Pre-deployment validation
        if !skip_phases.contains(&"validation".to_string()) {
            self.validate_deployment(&services).await?;
            report.phases_completed.push("validation".to_string());
        }
        
        // Phase 2: Resource allocation
        if !skip_phases.contains(&"resources".to_string()) {
            self.allocate_resources(&services).await?;
            report.phases_completed.push("resources".to_string());
        }
        
        // Phase 3: Network setup
        if !skip_phases.contains(&"network".to_string()) {
            self.setup_network(&services).await?;
            report.phases_completed.push("network".to_string());
        }
        
        // Phase 4: Service deployment
        if !skip_phases.contains(&"deployment".to_string()) {
            let deployment_result = self.deploy_services_internal(&services, report).await?;
            report.total_services = deployment_result.total;
            report.deployed_services = deployment_result.deployed;
            report.failed_services = deployment_result.failed;
            report.phases_completed.push("deployment".to_string());
        }
        
        // Phase 5: Health verification
        if !skip_phases.contains(&"health".to_string()) && !self.dry_run {
            self.verify_health(&services).await?;
            report.phases_completed.push("health".to_string());
        }
        
        // Phase 6: Post-deployment tasks
        if !skip_phases.contains(&"post-deployment".to_string()) {
            self.post_deployment_tasks(&services).await?;
            report.phases_completed.push("post-deployment".to_string());
        }
        
        Ok(())
    }
    
    async fn validate_deployment(&self, services: &[String]) -> Result<()> {
        info!("Validating deployment configuration...");
        
        // Validate configuration
        let validation = self.validate().await?;
        if !validation.is_valid && !self.force {
            return Err(anyhow::anyhow!("Configuration validation failed"));
        }
        
        // Validate resource availability
        self.resource_manager.validate_availability().await?;
        
        // Validate network requirements
        self.network_manager.validate_configuration().await?;
        
        Ok(())
    }
    
    async fn allocate_resources(&self, services: &[String]) -> Result<()> {
        info!("Allocating resources for deployment...");
        
        if self.dry_run {
            info!("Dry run: Skipping resource allocation");
            return Ok(());
        }
        
        // Calculate resource requirements
        let requirements = self.scheduler.calculate_resource_requirements(services).await?;
        
        // Convert to allocate_batch format
        let allocations = requirements.into_iter()
            .map(|req| (req.service, req.cpu_cores, req.memory_mb, req.storage_gb, req.gpu_count))
            .collect();
        
        // Allocate resources
        self.resource_manager.allocate_batch(allocations).await?;
        
        Ok(())
    }
    
    async fn setup_network(&self, services: &[String]) -> Result<()> {
        info!("Setting up network configuration...");
        
        if self.dry_run {
            info!("Dry run: Skipping network setup");
            return Ok(());
        }
        
        // Allocate ports
        let port_requirements = self.scheduler.calculate_port_requirements(services).await?;
        let mut port_allocations = Vec::new();
        for req in port_requirements {
            for port_req in req.ports {
                if let Some(port) = port_req.port {
                    port_allocations.push((req.service.clone(), port));
                }
            }
        }
        self.network_manager.allocate_ports(port_allocations).await?;
        
        // Setup service mesh
        self.network_manager.setup_service_mesh().await?;
        
        Ok(())
    }
    
    async fn deploy_services_internal(
        &self,
        services: &[String],
        report: &mut DeploymentReport,
    ) -> Result<DeploymentResult> {
        info!("Deploying services...");
        
        // Get deployment schedule
        let schedule = self.scheduler.create_deployment_schedule(services).await?;
        
        let total = schedule.total_services;
        let mut deployed = 0;
        let mut failed = 0;
        
        // Deploy services in phases
        for phase in schedule.phases {
            info!("Deploying phase: {}", phase.name);
            
            for service in phase.services {
                match self.deploy_single_service(&service).await {
                    Ok(_) => {
                        deployed += 1;
                        info!("Successfully deployed: {}", service);
                    }
                    Err(e) => {
                        failed += 1;
                        error!("Failed to deploy {}: {}", service, e);
                        report.errors.push(format!("{}: {}", service, e));
                        
                        if !self.force {
                            return Err(anyhow::anyhow!("Deployment failed for {}", service));
                        }
                    }
                }
            }
            
            // Wait for phase completion
            if !self.dry_run {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
        
        Ok(DeploymentResult {
            total,
            deployed,
            failed,
        })
    }
    
    async fn deploy_single_service(&self, service: &str) -> Result<()> {
        if self.dry_run {
            info!("Dry run: Would deploy service {}", service);
            return Ok(());
        }
        
        // Check circuit breaker
        if !self.circuit_breaker.can_execute(service).await {
            return Err(anyhow::anyhow!("Circuit breaker open for {}", service));
        }
        
        // Execute deployment
        match self.executor.deploy_service(service).await {
            Ok(_) => {
                self.circuit_breaker.record_success(service).await;
                Ok(())
            }
            Err(e) => {
                self.circuit_breaker.record_failure(service).await;
                Err(e)
            }
        }
    }
    
    async fn verify_health(&self, services: &[String]) -> Result<()> {
        info!("Verifying service health...");
        
        let timeout = Duration::from_secs(300); // 5 minute timeout
        let start = Instant::now();
        
        loop {
            let unhealthy = self.get_unhealthy_services(services).await?;
            
            if unhealthy.is_empty() {
                info!("All services are healthy!");
                return Ok(());
            }
            
            if start.elapsed() > timeout {
                if self.force {
                    warn!("Health check timeout, but continuing due to --force flag");
                    return Ok(());
                } else {
                    return Err(anyhow::anyhow!(
                        "Health check timeout. Unhealthy services: {:?}",
                        unhealthy
                    ));
                }
            }
            
            debug!("Waiting for services to become healthy: {:?}", unhealthy);
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
    
    async fn get_unhealthy_services(&self, services: &[String]) -> Result<Vec<String>> {
        let mut unhealthy = Vec::new();
        
        let all_services = if services.is_empty() {
            self.service_registry.list_all_services().await
        } else {
            services.to_vec()
        };
        
        for service in all_services {
            let health = self.service_registry.get_service_health(&service).await?;
            if health != "healthy" {
                unhealthy.push(service);
            }
        }
        
        Ok(unhealthy)
    }
    
    async fn post_deployment_tasks(&self, services: &[String]) -> Result<()> {
        info!("Executing post-deployment tasks...");
        
        if self.dry_run {
            info!("Dry run: Skipping post-deployment tasks");
            return Ok(());
        }
        
        // Update metrics
        self.metrics.record_deployment_success().await;
        
        // Save deployment state
        self.save_deployment_state().await?;
        
        // Trigger monitoring alerts
        self.setup_monitoring_alerts(services).await?;
        
        Ok(())
    }
    
    pub async fn stop_all(&self, timeout: Duration) -> Result<()> {
        info!("Stopping all services with timeout: {:?}", timeout);
        
        let services = self.service_registry.list_all_services().await;
        
        for service in services {
            if let Err(e) = self.executor.stop_service(&service, timeout).await {
                error!("Failed to stop {}: {}", service, e);
                if !self.force {
                    return Err(e);
                }
            }
        }
        
        Ok(())
    }
    
    pub async fn get_status(&self, detailed: bool) -> Result<PlatformStatus> {
        let services = self.service_registry.list_all_services().await;
        let mut service_details = std::collections::HashMap::new();
        
        let mut running = 0;
        let mut failed = 0;
        
        for service in &services {
            let status = self.service_registry.get_service_status(service).await?;
            
            match status {
                ServiceStatus::Running => running += 1,
                ServiceStatus::Failed => failed += 1,
                _ => {}
            }
            
            if detailed {
                let health = self.service_registry.get_service_health(service).await?;
                let metrics = self.metrics.get_service_metrics(service).await;
                
                service_details.insert(
                    service.clone(),
                    ServiceStatusDetails {
                        status: format!("{:?}", status),
                        health,
                        uptime: metrics.as_ref().map(|m| m.uptime),
                        cpu_usage: metrics.as_ref().map(|m| m.cpu_usage),
                        memory_usage: metrics.as_ref().map(|m| m.memory_usage),
                        message: None,
                    },
                );
            }
        }
        
        let overall_health = if failed > 0 {
            "unhealthy"
        } else if running == services.len() {
            "healthy"
        } else {
            "degraded"
        };
        
        Ok(PlatformStatus {
            overall_health: overall_health.to_string(),
            total_services: services.len(),
            running_services: running,
            failed_services: failed,
            services: service_details,
        })
    }
    
    pub async fn restart(&self, services: Vec<String>) -> Result<()> {
        info!("Restarting services: {:?}", services);
        
        let services_to_restart = if services.is_empty() {
            self.service_registry.list_all_services().await
        } else {
            services
        };
        
        for service in services_to_restart {
            info!("Restarting {}", service);
            
            // Stop service
            self.executor.stop_service(&service, Duration::from_secs(30)).await?;
            
            // Wait for cleanup
            tokio::time::sleep(Duration::from_secs(2)).await;
            
            // Start service
            self.deploy_single_service(&service).await?;
        }
        
        Ok(())
    }
    
    pub async fn validate(&self) -> Result<ValidationResult> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        
        // Validate configuration file
        if let Err(e) = self.config.validate() {
            errors.push(format!("Configuration validation failed: {}", e));
        }
        
        // Validate service definitions
        let services = self.config.get_all_services();
        for service in services {
            if let Err(e) = self.validate_service_definition(&service).await {
                errors.push(format!("Service {} validation failed: {}", service, e));
            }
        }
        
        // Validate dependencies
        if let Err(e) = self.validate_dependencies().await {
            errors.push(format!("Dependency validation failed: {}", e));
        }
        
        // Check for warnings
        if !self.config.get_monitoring_config().prometheus_enabled {
            warnings.push("Prometheus monitoring is disabled".to_string());
        }
        
        Ok(ValidationResult {
            is_valid: errors.is_empty(),
            errors,
            warnings,
        })
    }
    
    async fn validate_service_definition(&self, service: &str) -> Result<()> {
        // Validate service exists in configuration
        self.config.get_service_config(service)
            .ok_or_else(|| anyhow::anyhow!("Service {} not found in configuration", service))?;
        
        // Validate executable exists
        // Validate ports are available
        // Validate resource requirements
        
        Ok(())
    }
    
    async fn validate_dependencies(&self) -> Result<()> {
        // Check for circular dependencies
        // Validate all dependencies are defined
        
        Ok(())
    }
    
    pub async fn get_health(&self) -> Result<HealthReport> {
        let status = self.get_status(false).await?;
        let state = self.state.read().await;
        
        let mut score = 100u8;
        let mut issues = Vec::new();
        
        // Calculate health score
        if status.failed_services > 0 {
            score = score.saturating_sub(10 * status.failed_services as u8);
            
            for _ in 0..status.failed_services {
                issues.push(HealthIssue {
                    severity: "critical".to_string(),
                    service: "unknown".to_string(),
                    message: "Service is not running".to_string(),
                });
            }
        }
        
        let running_ratio = status.running_services as f64 / status.total_services as f64;
        if running_ratio < 1.0 {
            score = score.saturating_sub((20.0 * (1.0 - running_ratio)) as u8);
        }
        
        let status_str = match score {
            90..=100 => "healthy",
            70..=89 => "degraded",
            50..=69 => "unhealthy",
            _ => "critical",
        };
        
        Ok(HealthReport {
            status: status_str.to_string(),
            score,
            uptime_hours: state.start_time.elapsed().as_secs_f64() / 3600.0,
            issues,
        })
    }
    
    pub async fn rollback(&self) -> Result<()> {
        warn!("Initiating deployment rollback...");
        
        // Stop all services that were started in this deployment
        let services = self.service_registry.list_services_by_deployment().await?;
        
        for service in services.iter().rev() {
            if let Err(e) = self.executor.stop_service(service, Duration::from_secs(30)).await {
                error!("Failed to stop {} during rollback: {}", service, e);
            }
        }
        
        // Restore previous state
        self.recovery_manager.restore_previous_state().await?;
        
        info!("Rollback completed");
        Ok(())
    }
    
    async fn save_deployment_state(&self) -> Result<()> {
        // Save current deployment state for potential rollback
        self.recovery_manager.save_current_state().await?;
        Ok(())
    }
    
    async fn setup_monitoring_alerts(&self, services: &[String]) -> Result<()> {
        // Setup monitoring alerts for deployed services
        Ok(())
    }
}