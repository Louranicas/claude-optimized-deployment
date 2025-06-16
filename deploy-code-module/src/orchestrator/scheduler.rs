use anyhow::{Result, Context};
use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use tokio::sync::RwLock;
use tracing::{info, debug, warn, instrument};
use serde::{Serialize, Deserialize};

use crate::config::DeploymentConfig;
use crate::services::ServiceRegistry;

#[derive(Debug, Clone)]
pub struct DeploymentScheduler {
    config: Arc<DeploymentConfig>,
    service_registry: Arc<ServiceRegistry>,
    schedule_state: Arc<RwLock<ScheduleState>>,
}

#[derive(Debug, Clone)]
struct ScheduleState {
    active_schedules: Vec<DeploymentSchedule>,
    resource_allocations: HashMap<String, ResourceAllocation>,
    port_allocations: HashMap<u16, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentSchedule {
    pub phases: Vec<DeploymentPhase>,
    pub total_services: usize,
    pub estimated_duration: std::time::Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentPhase {
    pub name: String,
    pub services: Vec<String>,
    pub parallel: bool,
    pub timeout: std::time::Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRequirement {
    pub service: String,
    pub cpu_cores: f32,
    pub memory_mb: u32,
    pub storage_gb: u32,
    pub gpu_count: u8,
    pub network_bandwidth_mbps: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortRequirement {
    pub service: String,
    pub ports: Vec<PortRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortRequest {
    pub port: Option<u16>,
    pub protocol: String,
    pub purpose: String,
}

#[derive(Debug, Clone)]
struct ResourceAllocation {
    cpu_cores: f32,
    memory_mb: u32,
    storage_gb: u32,
    gpu_count: u8,
}

impl DeploymentScheduler {
    pub fn new(
        config: Arc<DeploymentConfig>,
        service_registry: Arc<ServiceRegistry>,
    ) -> Self {
        Self {
            config,
            service_registry,
            schedule_state: Arc::new(RwLock::new(ScheduleState {
                active_schedules: Vec::new(),
                resource_allocations: HashMap::new(),
                port_allocations: HashMap::new(),
            })),
        }
    }

    #[instrument(skip(self))]
    pub async fn create_deployment_schedule(
        &self,
        services: &[String],
    ) -> Result<DeploymentSchedule> {
        info!("Creating deployment schedule for {} services", services.len());
        
        // Get service dependencies
        let dependency_graph = self.build_dependency_graph(services).await?;
        
        // Calculate deployment phases
        let phases = self.calculate_deployment_phases(&dependency_graph, services).await?;
        
        // Estimate deployment duration
        let estimated_duration = self.estimate_deployment_duration(&phases).await;
        
        let schedule = DeploymentSchedule {
            phases,
            total_services: services.len(),
            estimated_duration,
        };
        
        // Store active schedule
        let mut state = self.schedule_state.write().await;
        state.active_schedules.push(schedule.clone());
        
        Ok(schedule)
    }

    async fn build_dependency_graph(
        &self,
        services: &[String],
    ) -> Result<HashMap<String, Vec<String>>> {
        let mut graph = HashMap::new();
        
        for service in services {
            let info = self.service_registry.get_service_info(service).await?;
            graph.insert(service.clone(), info.dependencies);
        }
        
        Ok(graph)
    }

    async fn calculate_deployment_phases(
        &self,
        dependency_graph: &HashMap<String, Vec<String>>,
        services: &[String],
    ) -> Result<Vec<DeploymentPhase>> {
        let mut phases = Vec::new();
        let mut deployed = HashSet::new();
        let mut remaining: HashSet<String> = services.iter().cloned().collect();
        let mut phase_num = 0;
        
        while !remaining.is_empty() {
            let mut phase_services = Vec::new();
            
            for service in &remaining.clone() {
                let deps = dependency_graph.get(service)
                    .map(|d| d.as_slice())
                    .unwrap_or(&[]);
                
                if deps.iter().all(|dep| deployed.contains(dep)) {
                    phase_services.push(service.clone());
                }
            }
            
            if phase_services.is_empty() {
                return Err(anyhow::anyhow!(
                    "Cannot create deployment schedule - circular dependencies detected"
                ));
            }
            
            // Update tracking sets
            for service in &phase_services {
                deployed.insert(service.clone());
                remaining.remove(service);
            }
            
            phase_num += 1;
            phases.push(DeploymentPhase {
                name: format!("Phase {}", phase_num),
                services: phase_services,
                parallel: true, // Deploy services in same phase in parallel
                timeout: std::time::Duration::from_secs(300), // 5 minute timeout per phase
            });
        }
        
        Ok(phases)
    }

    async fn estimate_deployment_duration(
        &self,
        phases: &[DeploymentPhase],
    ) -> std::time::Duration {
        // Estimate based on number of phases and services
        let base_time_per_service = std::time::Duration::from_secs(30);
        let phase_overhead = std::time::Duration::from_secs(10);
        
        let mut total_duration = std::time::Duration::ZERO;
        
        for phase in phases {
            // Parallel deployment within phase, so use max service time
            let phase_duration = if phase.parallel {
                base_time_per_service
            } else {
                base_time_per_service * phase.services.len() as u32
            };
            
            total_duration += phase_duration + phase_overhead;
        }
        
        total_duration
    }

    #[instrument(skip(self))]
    pub async fn calculate_resource_requirements(
        &self,
        services: &[String],
    ) -> Result<Vec<ResourceRequirement>> {
        debug!("Calculating resource requirements for {} services", services.len());
        
        let mut requirements = Vec::new();
        
        for service in services {
            let info = self.service_registry.get_service_info(service).await?;
            
            requirements.push(ResourceRequirement {
                service: service.clone(),
                cpu_cores: info.resources.cpu_cores,
                memory_mb: info.resources.memory_mb,
                storage_gb: info.resources.storage_gb,
                gpu_count: info.resources.gpu_count,
                network_bandwidth_mbps: info.resources.network_bandwidth_mbps,
            });
        }
        
        Ok(requirements)
    }

    #[instrument(skip(self))]
    pub async fn calculate_port_requirements(
        &self,
        services: &[String],
    ) -> Result<Vec<PortRequirement>> {
        debug!("Calculating port requirements for {} services", services.len());
        
        let mut requirements = Vec::new();
        let state = self.schedule_state.read().await;
        
        for service in services {
            let service_config = self.config.get_service_config(service)
                .ok_or_else(|| anyhow::anyhow!("Service {} not found in configuration", service))?;
            let mut port_requests = Vec::new();
            
            // Main service port from port configs
            for port_config in &service_config.ports {
                let port_num = port_config.host_port.unwrap_or(port_config.container_port);
                
                // Check if port is already allocated
                if let Some(existing_service) = state.port_allocations.get(&port_num) {
                    if existing_service != service {
                        warn!(
                            "Port {} already allocated to {}, will assign dynamic port to {}",
                                port_num, existing_service, service
                            );
                        port_requests.push(PortRequest {
                            port: None, // Request dynamic allocation
                            protocol: "tcp".to_string(),
                            purpose: "main".to_string(),
                        });
                    } else {
                        port_requests.push(PortRequest {
                            port: Some(port_num),
                            protocol: "tcp".to_string(),
                            purpose: "main".to_string(),
                        });
                    }
                } else {
                    port_requests.push(PortRequest {
                        port: Some(port_num),
                        protocol: "tcp".to_string(),
                        purpose: "main".to_string(),
                    });
                }
            }
            
            
            if !port_requests.is_empty() {
                requirements.push(PortRequirement {
                    service: service.clone(),
                    ports: port_requests,
                });
            }
        }
        
        Ok(requirements)
    }

    pub async fn reserve_resources(
        &self,
        service: &str,
        requirement: &ResourceRequirement,
    ) -> Result<()> {
        let mut state = self.schedule_state.write().await;
        
        state.resource_allocations.insert(
            service.to_string(),
            ResourceAllocation {
                cpu_cores: requirement.cpu_cores,
                memory_mb: requirement.memory_mb,
                storage_gb: requirement.storage_gb,
                gpu_count: requirement.gpu_count,
            },
        );
        
        Ok(())
    }

    pub async fn reserve_port(
        &self,
        service: &str,
        port: u16,
    ) -> Result<()> {
        let mut state = self.schedule_state.write().await;
        
        if let Some(existing_service) = state.port_allocations.get(&port) {
            if existing_service != service {
                return Err(anyhow::anyhow!(
                    "Port {} already allocated to service {}",
                    port,
                    existing_service
                ));
            }
        }
        
        state.port_allocations.insert(port, service.to_string());
        Ok(())
    }

    pub async fn release_resources(&self, service: &str) -> Result<()> {
        let mut state = self.schedule_state.write().await;
        
        // Release resource allocation
        state.resource_allocations.remove(service);
        
        // Release port allocations
        let ports_to_release: Vec<u16> = state.port_allocations
            .iter()
            .filter_map(|(port, svc)| {
                if svc == service {
                    Some(*port)
                } else {
                    None
                }
            })
            .collect();
        
        for port in ports_to_release {
            state.port_allocations.remove(&port);
        }
        
        Ok(())
    }

    pub async fn get_schedule_status(&self) -> Result<ScheduleStatus> {
        let state = self.schedule_state.read().await;
        
        Ok(ScheduleStatus {
            active_schedules: state.active_schedules.len(),
            allocated_services: state.resource_allocations.len(),
            allocated_ports: state.port_allocations.len(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleStatus {
    pub active_schedules: usize,
    pub allocated_services: usize,
    pub allocated_ports: usize,
}