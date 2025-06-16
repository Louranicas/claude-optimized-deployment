use std::sync::Arc;
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use anyhow::Result;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct InfrastructureState {
    services: Arc<DashMap<String, ServiceState>>,
    clusters: Arc<DashMap<String, ClusterState>>,
    nodes: Arc<DashMap<String, NodeState>>,
    networks: Arc<DashMap<String, NetworkState>>,
    storage: Arc<DashMap<String, StorageState>>,
    last_update: Arc<RwLock<DateTime<Utc>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceState {
    pub id: String,
    pub name: String,
    pub version: String,
    pub status: ServiceStatus,
    pub replicas: u32,
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub request_rate: f64,
    pub error_rate: f64,
    pub dependencies: Vec<String>,
    pub health_checks: Vec<HealthCheck>,
    pub last_deployment: DateTime<Utc>,
    pub configuration: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ServiceStatus {
    Running,
    Degraded,
    Down,
    Deploying,
    Scaling,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub name: String,
    pub endpoint: String,
    pub interval: std::time::Duration,
    pub timeout: std::time::Duration,
    pub consecutive_failures: u32,
    pub status: HealthStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterState {
    pub id: String,
    pub name: String,
    pub provider: CloudProvider,
    pub region: String,
    pub node_count: u32,
    pub total_cpu: f64,
    pub total_memory: f64,
    pub used_cpu: f64,
    pub used_memory: f64,
    pub status: ClusterStatus,
    pub kubernetes_version: String,
    pub network_policies: Vec<NetworkPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CloudProvider {
    AWS,
    GCP,
    Azure,
    OnPremise,
    Hybrid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ClusterStatus {
    Active,
    Updating,
    Degraded,
    Maintenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicy {
    pub name: String,
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub direction: TrafficDirection,
    pub protocol: String,
    pub ports: Vec<u16>,
    pub sources: Vec<String>,
    pub destinations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrafficDirection {
    Ingress,
    Egress,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeState {
    pub id: String,
    pub name: String,
    pub cluster_id: String,
    pub instance_type: String,
    pub cpu_cores: u32,
    pub memory_gb: f64,
    pub storage_gb: f64,
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
    pub network_rx: f64,
    pub network_tx: f64,
    pub pod_count: u32,
    pub status: NodeStatus,
    pub labels: std::collections::HashMap<String, String>,
    pub taints: Vec<NodeTaint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NodeStatus {
    Ready,
    NotReady,
    Draining,
    Cordoned,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeTaint {
    pub key: String,
    pub value: String,
    pub effect: TaintEffect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaintEffect {
    NoSchedule,
    PreferNoSchedule,
    NoExecute,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkState {
    pub id: String,
    pub name: String,
    pub cidr: String,
    pub gateway: String,
    pub dns_servers: Vec<String>,
    pub load_balancers: Vec<LoadBalancer>,
    pub ingress_controllers: Vec<IngressController>,
    pub bandwidth_usage: f64,
    pub packet_loss: f64,
    pub latency_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancer {
    pub id: String,
    pub name: String,
    pub type_: LoadBalancerType,
    pub endpoints: Vec<String>,
    pub health_check_path: String,
    pub algorithm: LoadBalancingAlgorithm,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadBalancerType {
    Application,
    Network,
    Classic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadBalancingAlgorithm {
    RoundRobin,
    LeastConnections,
    IPHash,
    Random,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressController {
    pub name: String,
    pub class: String,
    pub rules: Vec<IngressRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressRule {
    pub host: String,
    pub path: String,
    pub service: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageState {
    pub id: String,
    pub name: String,
    pub type_: StorageType,
    pub capacity_gb: f64,
    pub used_gb: f64,
    pub iops: u64,
    pub throughput_mbps: f64,
    pub mount_points: Vec<MountPoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageType {
    SSD,
    HDD,
    NFS,
    ObjectStorage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountPoint {
    pub path: String,
    pub node_id: String,
    pub pod_id: String,
    pub read_only: bool,
}

impl InfrastructureState {
    pub fn new() -> Self {
        Self {
            services: Arc::new(DashMap::new()),
            clusters: Arc::new(DashMap::new()),
            nodes: Arc::new(DashMap::new()),
            networks: Arc::new(DashMap::new()),
            storage: Arc::new(DashMap::new()),
            last_update: Arc::new(RwLock::new(Utc::now())),
        }
    }
    
    pub async fn update_service(&self, service: ServiceState) -> Result<()> {
        self.services.insert(service.id.clone(), service);
        self.update_timestamp().await;
        Ok(())
    }
    
    pub async fn update_cluster(&self, cluster: ClusterState) -> Result<()> {
        self.clusters.insert(cluster.id.clone(), cluster);
        self.update_timestamp().await;
        Ok(())
    }
    
    pub async fn update_node(&self, node: NodeState) -> Result<()> {
        self.nodes.insert(node.id.clone(), node);
        self.update_timestamp().await;
        Ok(())
    }
    
    pub async fn get_service_dependencies(&self, service_id: &str) -> Vec<ServiceState> {
        let mut dependencies = Vec::new();
        
        if let Some(service) = self.services.get(service_id) {
            for dep_id in &service.dependencies {
                if let Some(dep_service) = self.services.get(dep_id) {
                    dependencies.push(dep_service.clone());
                }
            }
        }
        
        dependencies
    }
    
    pub async fn get_cluster_health(&self, cluster_id: &str) -> ClusterHealth {
        let mut health = ClusterHealth::default();
        
        if let Some(cluster) = self.clusters.get(cluster_id) {
            health.cluster_status = cluster.status.clone();
            health.cpu_utilization = cluster.used_cpu / cluster.total_cpu;
            health.memory_utilization = cluster.used_memory / cluster.total_memory;
            
            // Check node health
            for node in self.nodes.iter() {
                if node.cluster_id == cluster_id {
                    health.total_nodes += 1;
                    if node.status == NodeStatus::Ready {
                        health.ready_nodes += 1;
                    }
                }
            }
            
            // Check service health
            for service in self.services.iter() {
                if service.status == ServiceStatus::Running {
                    health.healthy_services += 1;
                } else if service.status == ServiceStatus::Degraded {
                    health.degraded_services += 1;
                }
                health.total_services += 1;
            }
        }
        
        health
    }
    
    pub async fn get_resource_utilization(&self) -> ResourceUtilization {
        let mut util = ResourceUtilization::default();
        
        for cluster in self.clusters.iter() {
            util.total_cpu += cluster.total_cpu;
            util.used_cpu += cluster.used_cpu;
            util.total_memory += cluster.total_memory;
            util.used_memory += cluster.used_memory;
        }
        
        for storage in self.storage.iter() {
            util.total_storage += storage.capacity_gb;
            util.used_storage += storage.used_gb;
        }
        
        for network in self.networks.iter() {
            util.network_bandwidth += network.bandwidth_usage;
        }
        
        util
    }
    
    async fn update_timestamp(&self) {
        let mut last_update = self.last_update.write().await;
        *last_update = Utc::now();
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClusterHealth {
    pub cluster_status: ClusterStatus,
    pub total_nodes: u32,
    pub ready_nodes: u32,
    pub total_services: u32,
    pub healthy_services: u32,
    pub degraded_services: u32,
    pub cpu_utilization: f64,
    pub memory_utilization: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceUtilization {
    pub total_cpu: f64,
    pub used_cpu: f64,
    pub total_memory: f64,
    pub used_memory: f64,
    pub total_storage: f64,
    pub used_storage: f64,
    pub network_bandwidth: f64,
}

impl Default for ClusterStatus {
    fn default() -> Self {
        ClusterStatus::Active
    }
}