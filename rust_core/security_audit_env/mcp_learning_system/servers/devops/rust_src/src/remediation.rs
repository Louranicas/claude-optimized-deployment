use std::sync::Arc;
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use anyhow::{Result, anyhow};
use tokio::sync::RwLock;
use async_trait::async_trait;

use crate::{RemediationResult, RemediationAction, ActionResult, Impact};
use crate::deployment::IncidentPattern;

#[derive(Debug, Clone)]
pub struct RemediationEngine {
    strategies: Arc<DashMap<String, Box<dyn RemediationStrategy>>>,
    execution_history: Arc<RwLock<Vec<RemediationExecution>>>,
    active_remediations: Arc<DashMap<String, ActiveRemediation>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: String,
    pub type_: String,
    pub severity: IncidentSeverity,
    pub description: String,
    pub affected_services: Vec<String>,
    pub affected_nodes: Vec<String>,
    pub detected_at: DateTime<Utc>,
    pub metrics: IncidentMetrics,
    pub root_cause: Option<String>,
    pub resolution: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IncidentSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentMetrics {
    pub error_rate: f64,
    pub response_time: f64,
    pub affected_users: u64,
    pub data_loss_risk: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentClassification {
    pub category: IncidentCategory,
    pub confidence: f64,
    pub suggested_strategies: Vec<String>,
    pub estimated_impact: Impact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IncidentCategory {
    ResourceExhaustion,
    ServiceFailure,
    NetworkIssue,
    SecurityBreach,
    ConfigurationError,
    DependencyFailure,
    PerformanceDegradation,
}

#[async_trait]
pub trait RemediationStrategy: Send + Sync + std::fmt::Debug {
    async fn can_handle(&self, incident: &Incident) -> bool;
    async fn execute(&self, incident: &Incident, context: &RemediationContext) -> Result<Vec<RemediationAction>>;
    fn name(&self) -> &str;
    fn priority(&self) -> u32;
}

#[derive(Debug, Clone)]
pub struct RemediationContext {
    pub patterns: Vec<IncidentPattern>,
    pub infrastructure_state: serde_json::Value,
    pub deployment_history: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RemediationExecution {
    incident_id: String,
    strategy: String,
    started_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
    success: bool,
    actions: Vec<RemediationAction>,
}

#[derive(Debug, Clone)]
struct ActiveRemediation {
    incident_id: String,
    strategy: String,
    started_at: DateTime<Utc>,
    status: RemediationStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum RemediationStatus {
    InProgress,
    RollingBack,
    Completed,
    Failed,
}

impl RemediationEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            strategies: Arc::new(DashMap::new()),
            execution_history: Arc::new(RwLock::new(Vec::new())),
            active_remediations: Arc::new(DashMap::new()),
        };
        
        // Register default strategies
        engine.register_default_strategies();
        engine
    }
    
    pub async fn execute(
        &self,
        incident: &Incident,
        patterns: &[IncidentPattern],
        classification: &IncidentClassification,
    ) -> Result<RemediationResult> {
        let start_time = std::time::Instant::now();
        
        // Check if remediation is already active
        if self.active_remediations.contains_key(&incident.id) {
            return Err(anyhow!("Remediation already in progress for incident {}", incident.id));
        }
        
        // Select strategy
        let strategy = self.select_strategy(incident, classification).await?;
        
        // Mark as active
        self.active_remediations.insert(
            incident.id.clone(),
            ActiveRemediation {
                incident_id: incident.id.clone(),
                strategy: strategy.name().to_string(),
                started_at: Utc::now(),
                status: RemediationStatus::InProgress,
            },
        );
        
        // Prepare context
        let context = RemediationContext {
            patterns: patterns.to_vec(),
            infrastructure_state: serde_json::json!({}), // Would be populated from actual state
            deployment_history: Vec::new(), // Would be populated from history
        };
        
        // Execute strategy
        let actions = match strategy.execute(incident, &context).await {
            Ok(actions) => actions,
            Err(e) => {
                self.active_remediations.remove(&incident.id);
                return Err(e);
            }
        };
        
        // Record execution
        let execution = RemediationExecution {
            incident_id: incident.id.clone(),
            strategy: strategy.name().to_string(),
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
            success: true,
            actions: actions.clone(),
        };
        
        let mut history = self.execution_history.write().await;
        history.push(execution);
        
        // Remove from active
        self.active_remediations.remove(&incident.id);
        
        // Calculate impact
        let prevented_impact = self.calculate_prevented_impact(incident, &actions);
        
        Ok(RemediationResult {
            success: true,
            actions_taken: actions,
            duration: start_time.elapsed(),
            prevented_impact,
        })
    }
    
    async fn select_strategy(&self, incident: &Incident, classification: &IncidentClassification) -> Result<Box<dyn RemediationStrategy>> {
        let mut candidates = Vec::new();
        
        // Find all strategies that can handle this incident
        for strategy in self.strategies.iter() {
            if strategy.can_handle(incident).await {
                candidates.push((strategy.priority(), strategy.value().clone()));
            }
        }
        
        // Sort by priority (higher is better)
        candidates.sort_by_key(|(priority, _)| std::cmp::Reverse(*priority));
        
        candidates
            .into_iter()
            .next()
            .map(|(_, strategy)| strategy)
            .ok_or_else(|| anyhow!("No suitable remediation strategy found for incident type: {}", incident.type_))
    }
    
    fn calculate_prevented_impact(&self, incident: &Incident, actions: &[RemediationAction]) -> Option<Impact> {
        // Calculate based on incident severity and successful actions
        let successful_actions = actions.iter()
            .filter(|a| matches!(a.result, ActionResult::Success))
            .count();
        
        if successful_actions == 0 {
            return None;
        }
        
        Some(Impact {
            affected_services: incident.affected_services.clone(),
            estimated_downtime: std::time::Duration::from_secs(
                match incident.severity {
                    IncidentSeverity::Critical => 3600, // 1 hour
                    IncidentSeverity::High => 1800,     // 30 minutes
                    IncidentSeverity::Medium => 900,    // 15 minutes
                    IncidentSeverity::Low => 300,       // 5 minutes
                }
            ),
            cost_impact: match incident.severity {
                IncidentSeverity::Critical => 10000.0,
                IncidentSeverity::High => 5000.0,
                IncidentSeverity::Medium => 1000.0,
                IncidentSeverity::Low => 100.0,
            },
        })
    }
    
    fn register_default_strategies(&mut self) {
        // Resource exhaustion strategy
        self.strategies.insert(
            "resource_exhaustion".to_string(),
            Box::new(ResourceExhaustionStrategy::new()),
        );
        
        // Service failure strategy
        self.strategies.insert(
            "service_failure".to_string(),
            Box::new(ServiceFailureStrategy::new()),
        );
        
        // Network issue strategy
        self.strategies.insert(
            "network_issue".to_string(),
            Box::new(NetworkIssueStrategy::new()),
        );
        
        // Performance degradation strategy
        self.strategies.insert(
            "performance_degradation".to_string(),
            Box::new(PerformanceDegradationStrategy::new()),
        );
    }
}

// Default remediation strategies

#[derive(Debug, Clone)]
struct ResourceExhaustionStrategy;

impl ResourceExhaustionStrategy {
    fn new() -> Self {
        Self
    }
}

#[async_trait]
impl RemediationStrategy for ResourceExhaustionStrategy {
    async fn can_handle(&self, incident: &Incident) -> bool {
        incident.type_ == "ResourceExhaustion" || 
        incident.type_.contains("OOM") ||
        incident.type_.contains("CPU")
    }
    
    async fn execute(&self, incident: &Incident, _context: &RemediationContext) -> Result<Vec<RemediationAction>> {
        let mut actions = Vec::new();
        
        // Scale up affected services
        for service in &incident.affected_services {
            actions.push(RemediationAction {
                action_type: "scale_service".to_string(),
                target: service.clone(),
                parameters: serde_json::json!({
                    "scale_factor": 1.5,
                    "min_replicas": 3,
                    "max_replicas": 10,
                }),
                result: ActionResult::Success,
            });
        }
        
        // Increase resource limits
        actions.push(RemediationAction {
            action_type: "update_resources".to_string(),
            target: incident.affected_services[0].clone(),
            parameters: serde_json::json!({
                "cpu_increase": "50%",
                "memory_increase": "50%",
            }),
            result: ActionResult::Success,
        });
        
        Ok(actions)
    }
    
    fn name(&self) -> &str {
        "ResourceExhaustionStrategy"
    }
    
    fn priority(&self) -> u32 {
        100
    }
}

#[derive(Debug, Clone)]
struct ServiceFailureStrategy;

impl ServiceFailureStrategy {
    fn new() -> Self {
        Self
    }
}

#[async_trait]
impl RemediationStrategy for ServiceFailureStrategy {
    async fn can_handle(&self, incident: &Incident) -> bool {
        incident.type_ == "ServiceFailure" || 
        incident.type_.contains("Crash") ||
        incident.type_.contains("Unavailable")
    }
    
    async fn execute(&self, incident: &Incident, _context: &RemediationContext) -> Result<Vec<RemediationAction>> {
        let mut actions = Vec::new();
        
        // Restart failed services
        for service in &incident.affected_services {
            actions.push(RemediationAction {
                action_type: "restart_service".to_string(),
                target: service.clone(),
                parameters: serde_json::json!({
                    "graceful": true,
                    "timeout": 30,
                }),
                result: ActionResult::Success,
            });
        }
        
        // Enable circuit breaker
        actions.push(RemediationAction {
            action_type: "enable_circuit_breaker".to_string(),
            target: incident.affected_services[0].clone(),
            parameters: serde_json::json!({
                "failure_threshold": 5,
                "timeout": 60,
            }),
            result: ActionResult::Success,
        });
        
        Ok(actions)
    }
    
    fn name(&self) -> &str {
        "ServiceFailureStrategy"
    }
    
    fn priority(&self) -> u32 {
        90
    }
}

#[derive(Debug, Clone)]
struct NetworkIssueStrategy;

impl NetworkIssueStrategy {
    fn new() -> Self {
        Self
    }
}

#[async_trait]
impl RemediationStrategy for NetworkIssueStrategy {
    async fn can_handle(&self, incident: &Incident) -> bool {
        incident.type_ == "NetworkIssue" || 
        incident.type_.contains("Timeout") ||
        incident.type_.contains("Connection")
    }
    
    async fn execute(&self, incident: &Incident, _context: &RemediationContext) -> Result<Vec<RemediationAction>> {
        let mut actions = Vec::new();
        
        // Update network policies
        actions.push(RemediationAction {
            action_type: "update_network_policy".to_string(),
            target: "cluster".to_string(),
            parameters: serde_json::json!({
                "increase_timeout": true,
                "enable_retry": true,
                "max_retries": 3,
            }),
            result: ActionResult::Success,
        });
        
        // Reroute traffic
        for service in &incident.affected_services {
            actions.push(RemediationAction {
                action_type: "reroute_traffic".to_string(),
                target: service.clone(),
                parameters: serde_json::json!({
                    "strategy": "least_latency",
                    "health_check_interval": 5,
                }),
                result: ActionResult::Success,
            });
        }
        
        Ok(actions)
    }
    
    fn name(&self) -> &str {
        "NetworkIssueStrategy"
    }
    
    fn priority(&self) -> u32 {
        80
    }
}

#[derive(Debug, Clone)]
struct PerformanceDegradationStrategy;

impl PerformanceDegradationStrategy {
    fn new() -> Self {
        Self
    }
}

#[async_trait]
impl RemediationStrategy for PerformanceDegradationStrategy {
    async fn can_handle(&self, incident: &Incident) -> bool {
        incident.type_ == "PerformanceDegradation" || 
        incident.type_.contains("Slow") ||
        incident.type_.contains("Latency")
    }
    
    async fn execute(&self, incident: &Incident, _context: &RemediationContext) -> Result<Vec<RemediationAction>> {
        let mut actions = Vec::new();
        
        // Enable caching
        actions.push(RemediationAction {
            action_type: "enable_caching".to_string(),
            target: incident.affected_services[0].clone(),
            parameters: serde_json::json!({
                "cache_type": "redis",
                "ttl": 300,
                "max_entries": 10000,
            }),
            result: ActionResult::Success,
        });
        
        // Optimize queries
        actions.push(RemediationAction {
            action_type: "optimize_database".to_string(),
            target: "database".to_string(),
            parameters: serde_json::json!({
                "analyze_queries": true,
                "create_indexes": true,
                "vacuum": true,
            }),
            result: ActionResult::Success,
        });
        
        Ok(actions)
    }
    
    fn name(&self) -> &str {
        "PerformanceDegradationStrategy"
    }
    
    fn priority(&self) -> u32 {
        70
    }
}