use anyhow::{Result, Context};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug, instrument};
use dashmap::DashMap;
use serde::{Serialize, Deserialize};

use crate::services::{ServiceRegistry, ServiceStatus};
use crate::resources::ResourceManager;

#[derive(Debug, Clone)]
pub struct OrchestrationEngine {
    service_registry: Arc<ServiceRegistry>,
    resource_manager: Arc<ResourceManager>,
    orchestration_state: Arc<RwLock<OrchestrationState>>,
    service_graph: Arc<DashMap<String, ServiceNode>>,
}

#[derive(Debug, Clone)]
struct OrchestrationState {
    active_deployments: Vec<String>,
    pending_operations: Vec<PendingOperation>,
    last_optimization: Option<Instant>,
}

#[derive(Debug, Clone)]
struct ServiceNode {
    name: String,
    dependencies: Vec<String>,
    dependents: Vec<String>,
    priority: u32,
    resource_requirements: ResourceEstimate,
}

#[derive(Debug, Clone)]
struct PendingOperation {
    operation_type: OperationType,
    service: String,
    scheduled_time: Instant,
    priority: u32,
}

#[derive(Debug, Clone, PartialEq)]
enum OperationType {
    Deploy,
    Scale,
    Update,
    Remove,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResourceEstimate {
    cpu_cores: f32,
    memory_mb: u32,
    storage_gb: u32,
    network_bandwidth_mbps: u32,
}

impl OrchestrationEngine {
    pub fn new(
        service_registry: Arc<ServiceRegistry>,
        resource_manager: Arc<ResourceManager>,
    ) -> Self {
        Self {
            service_registry,
            resource_manager,
            orchestration_state: Arc::new(RwLock::new(OrchestrationState {
                active_deployments: Vec::new(),
                pending_operations: Vec::new(),
                last_optimization: None,
            })),
            service_graph: Arc::new(DashMap::new()),
        }
    }

    #[instrument(skip(self))]
    pub async fn initialize(&self) -> Result<()> {
        info!("Initializing orchestration engine...");
        
        // Build service dependency graph
        self.build_service_graph().await?;
        
        // Validate graph for circular dependencies
        self.validate_dependency_graph().await?;
        
        // Initialize optimization cycle
        self.schedule_optimization().await;
        
        Ok(())
    }

    async fn build_service_graph(&self) -> Result<()> {
        debug!("Building service dependency graph...");
        
        let services = self.service_registry.list_all_services().await;
        
        for service in services {
            let info = self.service_registry.get_service_info(&service).await?;
            
            let node = ServiceNode {
                name: service.clone(),
                dependencies: info.dependencies.clone(),
                dependents: Vec::new(), // Will be populated in next pass
                priority: self.calculate_priority(&info.dependencies),
                resource_requirements: ResourceEstimate {
                    cpu_cores: info.resources.cpu_cores,
                    memory_mb: info.resources.memory_mb,
                    storage_gb: info.resources.storage_gb,
                    network_bandwidth_mbps: info.resources.network_bandwidth_mbps,
                },
            };
            
            self.service_graph.insert(service, node);
        }
        
        // Build reverse dependencies (dependents)
        self.build_dependents_graph().await?;
        
        Ok(())
    }

    async fn build_dependents_graph(&self) -> Result<()> {
        let mut dependents_map: DashMap<String, Vec<String>> = DashMap::new();
        
        // Collect all dependents
        for entry in self.service_graph.iter() {
            let service = entry.key();
            let node = entry.value();
            
            for dep in &node.dependencies {
                dependents_map.entry(dep.clone())
                    .or_insert_with(Vec::new)
                    .push(service.clone());
            }
        }
        
        // Update service nodes with dependents
        for item in dependents_map.iter() {
            let (service, dependents) = item.pair();
            if let Some(mut node) = self.service_graph.get_mut(service) {
                node.dependents = dependents.clone();
            }
        }
        
        Ok(())
    }

    async fn validate_dependency_graph(&self) -> Result<()> {
        debug!("Validating dependency graph for circular dependencies...");
        
        for entry in self.service_graph.iter() {
            let service = entry.key();
            let mut visited = std::collections::HashSet::new();
            let mut stack = std::collections::HashSet::new();
            
            if self.has_circular_dependency(service, &mut visited, &mut stack)? {
                return Err(anyhow::anyhow!(
                    "Circular dependency detected involving service: {}",
                    service
                ));
            }
        }
        
        Ok(())
    }

    fn has_circular_dependency(
        &self,
        service: &str,
        visited: &mut std::collections::HashSet<String>,
        stack: &mut std::collections::HashSet<String>,
    ) -> Result<bool> {
        if stack.contains(service) {
            return Ok(true);
        }
        
        if visited.contains(service) {
            return Ok(false);
        }
        
        visited.insert(service.to_string());
        stack.insert(service.to_string());
        
        if let Some(node) = self.service_graph.get(service) {
            for dep in &node.dependencies {
                if self.has_circular_dependency(dep, visited, stack)? {
                    return Ok(true);
                }
            }
        }
        
        stack.remove(service);
        Ok(false)
    }

    fn calculate_priority(&self, dependencies: &[String]) -> u32 {
        // Services with fewer dependencies have higher priority
        match dependencies.len() {
            0 => 100,
            1..=2 => 80,
            3..=5 => 60,
            _ => 40,
        }
    }

    pub async fn optimize_deployment(&self) -> Result<()> {
        info!("Running deployment optimization...");
        
        let mut state = self.orchestration_state.write().await;
        state.last_optimization = Some(Instant::now());
        
        // Analyze resource utilization
        let utilization = self.resource_manager.get_utilization_metrics().await;
        
        // Identify services that need scaling
        let scaling_candidates = self.identify_scaling_candidates(&utilization).await?;
        
        // Schedule scaling operations
        for (service, scale_type) in scaling_candidates {
            self.schedule_operation(
                OperationType::Scale,
                service,
                scale_type.priority(),
            ).await?;
        }
        
        Ok(())
    }

    async fn identify_scaling_candidates(
        &self,
        utilization: &crate::resources::UtilizationMetrics,
    ) -> Result<Vec<(String, ScaleType)>> {
        let mut candidates = Vec::new();
        
        for entry in self.service_graph.iter() {
            let service = entry.key();
            let node = entry.value();
            
            // Check if service needs scaling based on resource usage
            if let Some(allocation) = self.resource_manager.get_service_metrics(service).await {
                // Simple heuristic: scale up if we're using most of allocated resources
                // In real implementation, would check actual usage vs allocated
                if utilization.cpu_percent > 80.0 || utilization.memory_percent > 85.0 {
                    candidates.push((service.clone(), ScaleType::Up));
                } else if utilization.cpu_percent < 30.0 && utilization.memory_percent < 30.0 {
                    candidates.push((service.clone(), ScaleType::Down));
                }
            }
        }
        
        Ok(candidates)
    }

    async fn schedule_operation(
        &self,
        operation_type: OperationType,
        service: String,
        priority: u32,
    ) -> Result<()> {
        let mut state = self.orchestration_state.write().await;
        
        let operation = PendingOperation {
            operation_type,
            service,
            scheduled_time: Instant::now() + Duration::from_secs(5),
            priority,
        };
        
        state.pending_operations.push(operation);
        
        // Sort by priority and scheduled time
        state.pending_operations.sort_by(|a, b| {
            b.priority.cmp(&a.priority)
                .then(a.scheduled_time.cmp(&b.scheduled_time))
        });
        
        Ok(())
    }

    pub async fn get_deployment_order(&self, services: &[String]) -> Result<Vec<Vec<String>>> {
        info!("Calculating optimal deployment order...");
        
        // Build deployment phases based on dependencies
        let mut phases = Vec::new();
        let mut deployed = std::collections::HashSet::new();
        let mut remaining: std::collections::HashSet<_> = services.iter().cloned().collect();
        
        while !remaining.is_empty() {
            let mut phase = Vec::new();
            
            for service in &remaining.clone() {
                if self.can_deploy(service, &deployed).await? {
                    phase.push(service.clone());
                }
            }
            
            if phase.is_empty() {
                return Err(anyhow::anyhow!(
                    "Cannot resolve deployment order - possible missing dependencies"
                ));
            }
            
            for service in &phase {
                deployed.insert(service.clone());
                remaining.remove(service);
            }
            
            phases.push(phase);
        }
        
        Ok(phases)
    }

    async fn can_deploy(
        &self,
        service: &str,
        deployed: &std::collections::HashSet<String>,
    ) -> Result<bool> {
        if let Some(node) = self.service_graph.get(service) {
            for dep in &node.dependencies {
                if !deployed.contains(dep) {
                    return Ok(false);
                }
            }
            Ok(true)
        } else {
            // Service not in graph, can deploy immediately
            Ok(true)
        }
    }

    async fn schedule_optimization(&self) {
        tokio::spawn({
            let engine = self.clone();
            async move {
                let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes
                
                loop {
                    interval.tick().await;
                    
                    if let Err(e) = engine.optimize_deployment().await {
                        error!("Optimization cycle failed: {}", e);
                    }
                }
            }
        });
    }
}

#[derive(Debug, Clone)]
enum ScaleType {
    Up,
    Down,
}

impl ScaleType {
    fn priority(&self) -> u32 {
        match self {
            ScaleType::Up => 90,
            ScaleType::Down => 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResourceUtilization {
    total_cpu_cores: f32,
    used_cpu_cores: f32,
    total_memory_mb: u32,
    used_memory_mb: u32,
    total_storage_gb: u32,
    used_storage_gb: u32,
}