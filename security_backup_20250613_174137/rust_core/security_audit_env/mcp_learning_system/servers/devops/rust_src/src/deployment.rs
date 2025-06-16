use std::sync::Arc;
use std::collections::VecDeque;
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc, Duration};
use anyhow::Result;
use tokio::sync::RwLock;
use crate::memory::{MemoryPool, AllocationId};
use crate::remediation::Incident;

const MAX_HISTORY_SIZE: usize = 10000;
const SIMILARITY_THRESHOLD: f64 = 0.85;

#[derive(Debug, Clone)]
pub struct DeploymentHistory {
    memory_pool: Arc<MemoryPool<2_147_483_648>>,
    deployments: Arc<RwLock<VecDeque<CachedDeployment>>>,
    deployment_index: Arc<DashMap<String, Vec<usize>>>,
    pattern_cache: Arc<DashMap<String, DeploymentPattern>>,
    allocations: Arc<DashMap<String, AllocationId>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedDeployment {
    pub id: String,
    pub plan: DeploymentPlan,
    pub result: DeploymentResult,
    pub metrics: DeploymentMetrics,
    pub incidents: Vec<Incident>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentPlan {
    pub service: String,
    pub version: String,
    pub environment: String,
    pub strategy: DeploymentStrategy,
    pub replicas: u32,
    pub resources: ResourceRequirements,
    pub dependencies: Vec<ServiceDependency>,
    pub health_checks: Vec<HealthCheckConfig>,
    pub rollback_policy: RollbackPolicy,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeploymentStrategy {
    RollingUpdate {
        max_surge: u32,
        max_unavailable: u32,
    },
    BlueGreen {
        traffic_split: f64,
    },
    Canary {
        initial_percentage: f64,
        increment: f64,
        interval: Duration,
    },
    Recreate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRequirements {
    pub cpu_cores: f64,
    pub memory_mb: u64,
    pub storage_gb: f64,
    pub network_bandwidth_mbps: f64,
    pub gpu_count: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDependency {
    pub service: String,
    pub version_constraint: String,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    pub type_: HealthCheckType,
    pub interval: Duration,
    pub timeout: Duration,
    pub success_threshold: u32,
    pub failure_threshold: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthCheckType {
    HTTP { path: String, expected_status: u16 },
    TCP { port: u16 },
    Command { cmd: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackPolicy {
    pub automatic: bool,
    pub failure_threshold: f64,
    pub monitoring_duration: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentResult {
    pub success: bool,
    pub duration: Duration,
    pub affected_nodes: Vec<String>,
    pub metrics_before: ServiceMetrics,
    pub metrics_after: ServiceMetrics,
    pub errors: Vec<DeploymentError>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceMetrics {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub request_rate: f64,
    pub error_rate: f64,
    pub p50_latency: f64,
    pub p95_latency: f64,
    pub p99_latency: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentError {
    pub phase: DeploymentPhase,
    pub error_type: String,
    pub message: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeploymentPhase {
    Validation,
    ResourceAllocation,
    ImagePull,
    ContainerStart,
    HealthCheck,
    TrafficSwitch,
    Cleanup,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentMetrics {
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub rollout_duration: Duration,
    pub downtime: Duration,
    pub affected_users: u64,
    pub cost_impact: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentPattern {
    pub pattern_id: String,
    pub service: String,
    pub environment: String,
    pub success_rate: f64,
    pub avg_duration: Duration,
    pub common_failures: Vec<(String, f64)>,
    pub optimal_time_windows: Vec<TimeWindow>,
    pub resource_patterns: ResourcePattern,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    pub day_of_week: u8,
    pub hour_start: u8,
    pub hour_end: u8,
    pub success_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcePattern {
    pub peak_cpu: f64,
    pub peak_memory: f64,
    pub scaling_behavior: ScalingBehavior,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScalingBehavior {
    Linear,
    Exponential,
    StepFunction,
    Irregular,
}

impl DeploymentHistory {
    pub fn new(memory_pool: Arc<MemoryPool<2_147_483_648>>) -> Self {
        Self {
            memory_pool,
            deployments: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_HISTORY_SIZE))),
            deployment_index: Arc::new(DashMap::new()),
            pattern_cache: Arc::new(DashMap::new()),
            allocations: Arc::new(DashMap::new()),
        }
    }
    
    pub async fn add_deployment(&self, deployment: CachedDeployment) -> Result<()> {
        // Serialize deployment for storage
        let serialized = bincode::serialize(&deployment)?;
        let allocation_id = self.memory_pool.allocate(serialized.len())?;
        self.memory_pool.write(allocation_id, &serialized)?;
        
        // Update index
        let service_key = format!("{}:{}", deployment.plan.service, deployment.plan.environment);
        let mut deployments = self.deployments.write().await;
        let index = deployments.len();
        
        // Add to history
        deployments.push_back(deployment.clone());
        if deployments.len() > MAX_HISTORY_SIZE {
            if let Some(old_deployment) = deployments.pop_front() {
                // Deallocate old deployment
                if let Some((_, old_alloc)) = self.allocations.remove(&old_deployment.id) {
                    let _ = self.memory_pool.deallocate(old_alloc);
                }
            }
        }
        
        // Update index
        self.deployment_index
            .entry(service_key.clone())
            .or_insert_with(Vec::new)
            .push(index);
        
        // Store allocation
        self.allocations.insert(deployment.id.clone(), allocation_id);
        
        // Update patterns
        self.update_patterns(&deployment).await?;
        
        Ok(())
    }
    
    pub async fn find_similar(&self, plan: &DeploymentPlan) -> Result<Vec<CachedDeployment>> {
        let deployments = self.deployments.read().await;
        let mut similar = Vec::new();
        
        for deployment in deployments.iter() {
            let similarity = self.calculate_similarity(&deployment.plan, plan);
            if similarity >= SIMILARITY_THRESHOLD {
                similar.push(deployment.clone());
            }
        }
        
        // Sort by similarity and recency
        similar.sort_by(|a, b| {
            b.timestamp.cmp(&a.timestamp)
        });
        
        Ok(similar)
    }
    
    pub async fn find_incident_patterns(&self, incident: &Incident) -> Result<Vec<IncidentPattern>> {
        let deployments = self.deployments.read().await;
        let mut patterns = Vec::new();
        
        for deployment in deployments.iter() {
            for dep_incident in &deployment.incidents {
                if self.incidents_similar(incident, dep_incident) {
                    patterns.push(IncidentPattern {
                        deployment_id: deployment.id.clone(),
                        incident: dep_incident.clone(),
                        resolution: dep_incident.resolution.clone(),
                        prevention_measures: self.extract_prevention_measures(&deployment, dep_incident),
                    });
                }
            }
        }
        
        Ok(patterns)
    }
    
    pub async fn get_recent(&self, duration: Duration) -> Result<Vec<CachedDeployment>> {
        let cutoff = Utc::now() - duration;
        let deployments = self.deployments.read().await;
        
        Ok(deployments
            .iter()
            .filter(|d| d.timestamp > cutoff)
            .cloned()
            .collect())
    }
    
    fn calculate_similarity(&self, plan1: &DeploymentPlan, plan2: &DeploymentPlan) -> f64 {
        let mut score = 0.0;
        let mut weight_sum = 0.0;
        
        // Service match (high weight)
        if plan1.service == plan2.service {
            score += 0.3;
        }
        weight_sum += 0.3;
        
        // Environment match
        if plan1.environment == plan2.environment {
            score += 0.2;
        }
        weight_sum += 0.2;
        
        // Strategy similarity
        let strategy_sim = match (&plan1.strategy, &plan2.strategy) {
            (DeploymentStrategy::RollingUpdate { .. }, DeploymentStrategy::RollingUpdate { .. }) => 1.0,
            (DeploymentStrategy::BlueGreen { .. }, DeploymentStrategy::BlueGreen { .. }) => 1.0,
            (DeploymentStrategy::Canary { .. }, DeploymentStrategy::Canary { .. }) => 1.0,
            (DeploymentStrategy::Recreate, DeploymentStrategy::Recreate) => 1.0,
            _ => 0.0,
        };
        score += strategy_sim * 0.15;
        weight_sum += 0.15;
        
        // Resource similarity
        let cpu_diff = (plan1.resources.cpu_cores - plan2.resources.cpu_cores).abs() / plan1.resources.cpu_cores.max(plan2.resources.cpu_cores);
        let mem_diff = (plan1.resources.memory_mb as f64 - plan2.resources.memory_mb as f64).abs() / (plan1.resources.memory_mb.max(plan2.resources.memory_mb) as f64);
        let resource_sim = 1.0 - (cpu_diff + mem_diff) / 2.0;
        score += resource_sim * 0.15;
        weight_sum += 0.15;
        
        // Dependencies similarity
        let dep1_set: std::collections::HashSet<_> = plan1.dependencies.iter().map(|d| &d.service).collect();
        let dep2_set: std::collections::HashSet<_> = plan2.dependencies.iter().map(|d| &d.service).collect();
        let intersection = dep1_set.intersection(&dep2_set).count();
        let union = dep1_set.union(&dep2_set).count();
        let dep_sim = if union > 0 { intersection as f64 / union as f64 } else { 1.0 };
        score += dep_sim * 0.2;
        weight_sum += 0.2;
        
        score / weight_sum
    }
    
    fn incidents_similar(&self, inc1: &Incident, inc2: &Incident) -> bool {
        inc1.type_ == inc2.type_ && 
        inc1.severity == inc2.severity &&
        inc1.affected_services.iter().any(|s| inc2.affected_services.contains(s))
    }
    
    fn extract_prevention_measures(&self, deployment: &CachedDeployment, incident: &Incident) -> Vec<String> {
        let mut measures = Vec::new();
        
        // Analyze deployment configuration that might prevent the incident
        if incident.type_ == "ResourceExhaustion" {
            measures.push(format!(
                "Increase resource allocation: CPU to {:.1} cores, Memory to {} MB",
                deployment.plan.resources.cpu_cores * 1.5,
                deployment.plan.resources.memory_mb * 1.5
            ));
        }
        
        if incident.type_ == "HealthCheckFailure" {
            measures.push("Review and adjust health check configuration".to_string());
            measures.push("Increase health check timeout and retry attempts".to_string());
        }
        
        measures
    }
    
    async fn update_patterns(&self, deployment: &CachedDeployment) -> Result<()> {
        let pattern_key = format!("{}:{}", deployment.plan.service, deployment.plan.environment);
        
        let mut pattern = self.pattern_cache
            .get(&pattern_key)
            .map(|p| p.clone())
            .unwrap_or_else(|| DeploymentPattern {
                pattern_id: pattern_key.clone(),
                service: deployment.plan.service.clone(),
                environment: deployment.plan.environment.clone(),
                success_rate: 0.0,
                avg_duration: Duration::seconds(0),
                common_failures: Vec::new(),
                optimal_time_windows: Vec::new(),
                resource_patterns: ResourcePattern {
                    peak_cpu: 0.0,
                    peak_memory: 0.0,
                    scaling_behavior: ScalingBehavior::Linear,
                },
            });
        
        // Update pattern with new deployment data
        // This is simplified - in production, use more sophisticated pattern recognition
        if deployment.result.success {
            pattern.success_rate = (pattern.success_rate * 0.9) + 0.1;
        } else {
            pattern.success_rate = pattern.success_rate * 0.9;
        }
        
        self.pattern_cache.insert(pattern_key, pattern);
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentPattern {
    pub deployment_id: String,
    pub incident: Incident,
    pub resolution: Option<String>,
    pub prevention_measures: Vec<String>,
}