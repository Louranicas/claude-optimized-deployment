use anyhow::{Result, Context};
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use tracing::{info, debug, warn};

pub mod registry;
pub mod health_check;
pub mod lifecycle;

pub use registry::ServiceRegistry;
pub use health_check::HealthChecker;
pub use lifecycle::LifecycleManager;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceStatus {
    NotStarted,
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub service_type: ServiceType,
    pub status: ServiceStatus,
    pub health: HealthStatus,
    #[serde(skip)]
    pub start_time: Option<Instant>,
    pub pid: Option<u32>,
    pub port: Option<u16>,
    pub dependencies: Vec<String>,
    pub resources: ResourceRequirements,
    pub metadata: ServiceMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceType {
    MCPServer,
    AIProvider,
    Database,
    Cache,
    MessageQueue,
    API,
    Frontend,
    Monitoring,
    Infrastructure,
    Security,
    Storage,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRequirements {
    pub cpu_cores: f32,
    pub memory_mb: u32,
    pub storage_gb: u32,
    pub gpu_count: u8,
    pub network_bandwidth_mbps: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceMetadata {
    pub version: String,
    pub description: String,
    pub labels: std::collections::HashMap<String, String>,
    pub annotations: std::collections::HashMap<String, String>,
}

impl Default for ServiceInfo {
    fn default() -> Self {
        Self {
            name: String::new(),
            service_type: ServiceType::Other("unknown".to_string()),
            status: ServiceStatus::NotStarted,
            health: HealthStatus::Unknown,
            start_time: None,
            pid: None,
            port: None,
            dependencies: Vec::new(),
            resources: ResourceRequirements::default(),
            metadata: ServiceMetadata::default(),
        }
    }
}

impl Default for ResourceRequirements {
    fn default() -> Self {
        Self {
            cpu_cores: 0.5,
            memory_mb: 512,
            storage_gb: 1,
            gpu_count: 0,
            network_bandwidth_mbps: 10,
        }
    }
}

impl Default for ServiceMetadata {
    fn default() -> Self {
        Self {
            version: "1.0.0".to_string(),
            description: String::new(),
            labels: std::collections::HashMap::new(),
            annotations: std::collections::HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServiceDefinition {
    pub name: String,
    pub service_type: ServiceType,
    pub command: String,
    pub args: Vec<String>,
    pub env: std::collections::HashMap<String, String>,
    pub working_dir: Option<String>,
    pub dependencies: Vec<String>,
    pub health_check: HealthCheckConfig,
    pub resources: ResourceRequirements,
    pub ports: Vec<PortMapping>,
    pub restart_policy: RestartPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    pub endpoint: Option<String>,
    pub command: Option<Vec<String>>,
    pub interval: Duration,
    pub timeout: Duration,
    pub retries: u32,
    pub start_period: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    pub container_port: u16,
    pub host_port: Option<u16>,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RestartPolicy {
    Always,
    OnFailure { max_retries: u32 },
    Never,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            endpoint: None,
            command: None,
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(10),
            retries: 3,
            start_period: Duration::from_secs(60),
        }
    }
}

pub struct ServiceManager {
    registry: Arc<ServiceRegistry>,
    health_checker: Arc<HealthChecker>,
    lifecycle: Arc<LifecycleManager>,
    definitions: Arc<DashMap<String, ServiceDefinition>>,
}

impl ServiceManager {
    pub fn new() -> Self {
        let registry = Arc::new(ServiceRegistry::new());
        let health_checker = Arc::new(HealthChecker::new(registry.clone()));
        let lifecycle = Arc::new(LifecycleManager::new(registry.clone()));
        
        Self {
            registry: registry.clone(),
            health_checker,
            lifecycle,
            definitions: Arc::new(DashMap::new()),
        }
    }
    
    pub async fn register_service(&self, definition: ServiceDefinition) -> Result<()> {
        let name = definition.name.clone();
        
        // Store definition
        self.definitions.insert(name.clone(), definition.clone());
        
        // Create service info
        let info = ServiceInfo {
            name: name.clone(),
            service_type: definition.service_type,
            status: ServiceStatus::NotStarted,
            health: HealthStatus::Unknown,
            start_time: None,
            pid: None,
            port: definition.ports.first().map(|p| p.container_port),
            dependencies: definition.dependencies,
            resources: definition.resources,
            metadata: ServiceMetadata {
                version: "1.0.0".to_string(),
                description: format!("Service: {}", name),
                labels: std::collections::HashMap::new(),
                annotations: std::collections::HashMap::new(),
            },
        };
        
        // Register in registry
        self.registry.register(name, info).await?;
        
        Ok(())
    }
    
    pub async fn start_service(&self, name: &str) -> Result<()> {
        let definition = self.definitions
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("Service {} not found", name))?
            .clone();
        
        // Check dependencies
        for dep in &definition.dependencies {
            let status = self.registry.get_service_status(dep).await?;
            if status != ServiceStatus::Running {
                return Err(anyhow::anyhow!(
                    "Dependency {} is not running (status: {:?})",
                    dep,
                    status
                ));
            }
        }
        
        // Start service
        self.lifecycle.start_service(name, &definition).await?;
        
        // Start health checking
        self.health_checker.start_monitoring(name).await?;
        
        Ok(())
    }
    
    pub async fn stop_service(&self, name: &str, timeout: Duration) -> Result<()> {
        // Stop health checking
        self.health_checker.stop_monitoring(name).await?;
        
        // Stop service
        self.lifecycle.stop_service(name, timeout).await?;
        
        Ok(())
    }
    
    pub async fn restart_service(&self, name: &str) -> Result<()> {
        info!("Restarting service: {}", name);
        
        // Stop service
        self.stop_service(name, Duration::from_secs(30)).await?;
        
        // Wait for cleanup
        tokio::time::sleep(Duration::from_secs(2)).await;
        
        // Start service
        self.start_service(name).await?;
        
        Ok(())
    }
    
    pub async fn get_service_info(&self, name: &str) -> Result<ServiceInfo> {
        self.registry.get_service_info(name).await
    }
    
    pub async fn list_services(&self) -> Vec<String> {
        self.registry.list_all_services().await
    }
    
    pub async fn get_service_health(&self, name: &str) -> Result<HealthStatus> {
        self.registry.get_service_health_status(name).await
    }
    
    pub async fn update_service_status(&self, name: &str, status: ServiceStatus) -> Result<()> {
        self.registry.update_status(name, status).await
    }
}