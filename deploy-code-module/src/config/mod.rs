use std::collections::{HashMap, HashSet};
use std::ops::RangeInclusive;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentConfig {
    pub infrastructure: InfrastructureConfig,
    pub services: HashMap<String, ServiceConfig>,
    pub deployment: DeploymentStrategy,
    pub monitoring: MonitoringConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureConfig {
    pub environment: String,
    pub cluster_name: String,
    pub network: NetworkConfig,
    pub storage: StorageConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub port_range: RangeInclusive<u16>,
    pub service_mesh: ServiceMeshConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceMeshConfig {
    pub enabled: bool,
    pub provider: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub root_path: String,
    pub data_path: String,
    pub logs_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub enabled: bool,
    pub service_type: String,
    pub container_image: String,
    pub replicas: u32,
    pub resources: ResourceRequirements,
    pub ports: Vec<PortConfig>,
    pub environment: HashMap<String, String>,
    pub dependencies: Vec<String>,
    pub health_check: HealthCheckConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRequirements {
    pub cpu_cores: f32,
    pub memory_mb: u32,
    pub storage_gb: u32,
    pub gpu_count: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortConfig {
    pub name: String,
    pub container_port: u16,
    pub host_port: Option<u16>,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    pub endpoint: String,
    pub interval_seconds: u32,
    pub timeout_seconds: u32,
    pub retries: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentStrategy {
    pub strategy_type: String,
    pub max_parallel: u32,
    pub rollback_on_failure: bool,
    pub phases: Vec<DeploymentPhase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentPhase {
    pub name: String,
    pub services: Vec<String>,
    pub wait_for_ready: bool,
    pub timeout_seconds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub prometheus_enabled: bool,
    pub prometheus_port: u16,
    pub metrics_interval_seconds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub tls_enabled: bool,
    pub mutual_tls: bool,
    pub rbac_enabled: bool,
}

impl Default for DeploymentConfig {
    fn default() -> Self {
        Self {
            infrastructure: InfrastructureConfig {
                environment: "development".to_string(),
                cluster_name: "code-cluster".to_string(),
                network: NetworkConfig {
                    port_range: 30000..=32000,
                    service_mesh: ServiceMeshConfig {
                        enabled: false,
                        provider: "istio".to_string(),
                    },
                },
                storage: StorageConfig {
                    root_path: "/opt/code".to_string(),
                    data_path: "/opt/code/data".to_string(),
                    logs_path: "/opt/code/logs".to_string(),
                },
            },
            services: HashMap::new(),
            deployment: DeploymentStrategy {
                strategy_type: "sequential".to_string(),
                max_parallel: 5,
                rollback_on_failure: true,
                phases: Vec::new(),
            },
            monitoring: MonitoringConfig {
                prometheus_enabled: true,
                prometheus_port: 9090,
                metrics_interval_seconds: 30,
            },
            security: SecurityConfig {
                tls_enabled: true,
                mutual_tls: false,
                rbac_enabled: true,
            },
        }
    }
}

impl DeploymentConfig {
    pub fn validate(&self) -> Result<(), anyhow::Error> {
        // Validate basic configuration
        if self.services.is_empty() {
            return Err(anyhow::anyhow!("No services configured"));
        }
        
        // Validate port range
        if self.infrastructure.network.port_range.start() > self.infrastructure.network.port_range.end() {
            return Err(anyhow::anyhow!("Invalid port range"));
        }
        
        // Validate deployment strategy
        if self.deployment.phases.is_empty() && !self.services.is_empty() {
            return Err(anyhow::anyhow!("No deployment phases configured"));
        }
        
        Ok(())
    }
    
    pub fn get_all_services(&self) -> Vec<String> {
        self.services.keys().cloned().collect()
    }
    
    pub fn get_service_config(&self, service: &str) -> Option<&ServiceConfig> {
        self.services.get(service)
    }
    
    pub fn get_monitoring_config(&self) -> &MonitoringConfig {
        &self.monitoring
    }
}

pub async fn load_config(path: &std::path::Path) -> anyhow::Result<DeploymentConfig> {
    use std::fs;
    
    let contents = fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Failed to read config file: {}", e))?;
    
    let config: DeploymentConfig = serde_yaml::from_str(&contents)
        .map_err(|e| anyhow::anyhow!("Failed to parse config file: {}", e))?;
    
    config.validate()?;
    
    Ok(config)
}