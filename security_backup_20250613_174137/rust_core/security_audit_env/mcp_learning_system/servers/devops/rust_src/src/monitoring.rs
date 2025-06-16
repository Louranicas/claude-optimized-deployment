use std::sync::Arc;
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc, Duration};
use prometheus::{Registry, Counter, Gauge, Histogram, HistogramOpts, Encoder, TextEncoder};
use lazy_static::lazy_static;
use anyhow::Result;

lazy_static! {
    static ref REGISTRY: Registry = Registry::new();
    
    // Prediction metrics
    static ref PREDICTION_COUNTER: Counter = Counter::new(
        "devops_predictions_total", "Total number of deployment predictions"
    ).expect("metric creation failed");
    
    static ref PREDICTION_SUCCESS_RATE: Gauge = Gauge::new(
        "devops_prediction_success_rate", "Success rate of deployment predictions"
    ).expect("metric creation failed");
    
    static ref PREDICTION_LATENCY: Histogram = Histogram::with_opts(
        HistogramOpts::new("devops_prediction_latency_seconds", "Latency of predictions")
            .buckets(vec![0.1, 0.5, 1.0, 2.0, 5.0])
    ).expect("metric creation failed");
    
    // Deployment metrics
    static ref DEPLOYMENT_COUNTER: Counter = Counter::new(
        "devops_deployments_total", "Total number of deployments processed"
    ).expect("metric creation failed");
    
    static ref DEPLOYMENT_SUCCESS_COUNTER: Counter = Counter::new(
        "devops_deployments_success_total", "Total number of successful deployments"
    ).expect("metric creation failed");
    
    static ref DEPLOYMENT_DURATION: Histogram = Histogram::with_opts(
        HistogramOpts::new("devops_deployment_duration_seconds", "Duration of deployments")
            .buckets(vec![60.0, 180.0, 300.0, 600.0, 1800.0, 3600.0])
    ).expect("metric creation failed");
    
    // Remediation metrics
    static ref REMEDIATION_COUNTER: Counter = Counter::new(
        "devops_remediations_total", "Total number of incident remediations"
    ).expect("metric creation failed");
    
    static ref REMEDIATION_SUCCESS_COUNTER: Counter = Counter::new(
        "devops_remediations_success_total", "Total number of successful remediations"
    ).expect("metric creation failed");
    
    static ref REMEDIATION_LATENCY: Histogram = Histogram::with_opts(
        HistogramOpts::new("devops_remediation_latency_seconds", "Latency of remediations")
            .buckets(vec![1.0, 5.0, 10.0, 30.0, 60.0, 300.0])
    ).expect("metric creation failed");
    
    // Resource metrics
    static ref MEMORY_USAGE: Gauge = Gauge::new(
        "devops_memory_usage_bytes", "Current memory usage in bytes"
    ).expect("metric creation failed");
    
    static ref MEMORY_POOL_UTILIZATION: Gauge = Gauge::new(
        "devops_memory_pool_utilization_ratio", "Memory pool utilization ratio"
    ).expect("metric creation failed");
    
    // Learning metrics
    static ref PATTERNS_DISCOVERED: Counter = Counter::new(
        "devops_patterns_discovered_total", "Total number of patterns discovered"
    ).expect("metric creation failed");
    
    static ref MODEL_ACCURACY: Gauge = Gauge::new(
        "devops_model_accuracy", "Current model accuracy"
    ).expect("metric creation failed");
}

#[derive(Debug, Clone)]
pub struct MonitoringService {
    metrics_store: Arc<DashMap<String, MetricValue>>,
    alert_manager: Arc<AlertManager>,
    health_checker: Arc<HealthChecker>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricValue {
    Counter(f64),
    Gauge(f64),
    Histogram(Vec<f64>),
}

#[derive(Debug, Clone)]
struct AlertManager {
    rules: DashMap<String, AlertRule>,
    active_alerts: DashMap<String, Alert>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AlertRule {
    name: String,
    condition: AlertCondition,
    severity: AlertSeverity,
    actions: Vec<AlertAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum AlertCondition {
    Threshold { metric: String, operator: ComparisonOperator, value: f64 },
    Rate { metric: String, window: Duration, threshold: f64 },
    Absence { metric: String, duration: Duration },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ComparisonOperator {
    GreaterThan,
    LessThan,
    Equal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum AlertSeverity {
    Critical,
    Warning,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum AlertAction {
    Notify { channel: String },
    Webhook { url: String },
    Remediate { strategy: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Alert {
    rule_name: String,
    triggered_at: DateTime<Utc>,
    metric_value: f64,
    message: String,
}

#[derive(Debug, Clone)]
struct HealthChecker {
    checks: DashMap<String, HealthCheck>,
    status: Arc<tokio::sync::RwLock<HealthStatus>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HealthCheck {
    name: String,
    check_fn: String, // Would be a function pointer in real implementation
    interval: Duration,
    timeout: Duration,
    last_check: Option<DateTime<Utc>>,
    status: ComponentHealth,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ComponentHealth {
    Healthy,
    Degraded(String),
    Unhealthy(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub overall: SystemHealth,
    pub components: Vec<ComponentStatus>,
    pub last_check: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SystemHealth {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentStatus {
    pub name: String,
    pub status: ComponentHealth,
    pub message: Option<String>,
}

impl MonitoringService {
    pub fn new() -> Result<Self> {
        // Register metrics
        REGISTRY.register(Box::new(PREDICTION_COUNTER.clone()))?;
        REGISTRY.register(Box::new(PREDICTION_SUCCESS_RATE.clone()))?;
        REGISTRY.register(Box::new(PREDICTION_LATENCY.clone()))?;
        REGISTRY.register(Box::new(DEPLOYMENT_COUNTER.clone()))?;
        REGISTRY.register(Box::new(DEPLOYMENT_SUCCESS_COUNTER.clone()))?;
        REGISTRY.register(Box::new(DEPLOYMENT_DURATION.clone()))?;
        REGISTRY.register(Box::new(REMEDIATION_COUNTER.clone()))?;
        REGISTRY.register(Box::new(REMEDIATION_SUCCESS_COUNTER.clone()))?;
        REGISTRY.register(Box::new(REMEDIATION_LATENCY.clone()))?;
        REGISTRY.register(Box::new(MEMORY_USAGE.clone()))?;
        REGISTRY.register(Box::new(MEMORY_POOL_UTILIZATION.clone()))?;
        REGISTRY.register(Box::new(PATTERNS_DISCOVERED.clone()))?;
        REGISTRY.register(Box::new(MODEL_ACCURACY.clone()))?;
        
        let mut service = Self {
            metrics_store: Arc::new(DashMap::new()),
            alert_manager: Arc::new(AlertManager::new()),
            health_checker: Arc::new(HealthChecker::new()),
        };
        
        // Initialize default alert rules
        service.initialize_alert_rules()?;
        
        Ok(service)
    }
    
    pub fn record_prediction(&self, success: bool, duration: f64) {
        PREDICTION_COUNTER.inc();
        PREDICTION_LATENCY.observe(duration);
        
        if success {
            let current_rate = PREDICTION_SUCCESS_RATE.get();
            PREDICTION_SUCCESS_RATE.set(current_rate * 0.95 + 0.05); // Exponential moving average
        }
    }
    
    pub fn record_deployment(&self, success: bool, duration: f64) {
        DEPLOYMENT_COUNTER.inc();
        DEPLOYMENT_DURATION.observe(duration);
        
        if success {
            DEPLOYMENT_SUCCESS_COUNTER.inc();
        }
    }
    
    pub fn record_remediation(&self, success: bool, duration: f64) {
        REMEDIATION_COUNTER.inc();
        REMEDIATION_LATENCY.observe(duration);
        
        if success {
            REMEDIATION_SUCCESS_COUNTER.inc();
        }
    }
    
    pub fn update_memory_usage(&self, bytes: usize, pool_utilization: f64) {
        MEMORY_USAGE.set(bytes as f64);
        MEMORY_POOL_UTILIZATION.set(pool_utilization);
    }
    
    pub fn record_pattern_discovery(&self, count: usize) {
        for _ in 0..count {
            PATTERNS_DISCOVERED.inc();
        }
    }
    
    pub fn update_model_accuracy(&self, accuracy: f64) {
        MODEL_ACCURACY.set(accuracy);
    }
    
    pub async fn check_alerts(&self) -> Vec<Alert> {
        self.alert_manager.check_all_rules(&self.metrics_store).await
    }
    
    pub async fn get_health_status(&self) -> Result<HealthStatus> {
        self.health_checker.check_all().await
    }
    
    pub fn export_metrics(&self) -> Result<String> {
        let encoder = TextEncoder::new();
        let metric_families = REGISTRY.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8(buffer)?)
    }
    
    fn initialize_alert_rules(&mut self) -> Result<()> {
        // High memory usage alert
        self.alert_manager.add_rule(AlertRule {
            name: "high_memory_usage".to_string(),
            condition: AlertCondition::Threshold {
                metric: "memory_pool_utilization".to_string(),
                operator: ComparisonOperator::GreaterThan,
                value: 0.9,
            },
            severity: AlertSeverity::Critical,
            actions: vec![
                AlertAction::Notify { channel: "ops-team".to_string() },
                AlertAction::Remediate { strategy: "scale_up".to_string() },
            ],
        })?;
        
        // Low prediction success rate
        self.alert_manager.add_rule(AlertRule {
            name: "low_prediction_accuracy".to_string(),
            condition: AlertCondition::Threshold {
                metric: "prediction_success_rate".to_string(),
                operator: ComparisonOperator::LessThan,
                value: 0.8,
            },
            severity: AlertSeverity::Warning,
            actions: vec![
                AlertAction::Notify { channel: "ml-team".to_string() },
            ],
        })?;
        
        // High remediation latency
        self.alert_manager.add_rule(AlertRule {
            name: "high_remediation_latency".to_string(),
            condition: AlertCondition::Threshold {
                metric: "remediation_p95_latency".to_string(),
                operator: ComparisonOperator::GreaterThan,
                value: 300.0, // 5 minutes
            },
            severity: AlertSeverity::Warning,
            actions: vec![
                AlertAction::Notify { channel: "ops-team".to_string() },
                AlertAction::Webhook { url: "https://alerts.example.com/webhook".to_string() },
            ],
        })?;
        
        Ok(())
    }
}

impl AlertManager {
    fn new() -> Self {
        Self {
            rules: DashMap::new(),
            active_alerts: DashMap::new(),
        }
    }
    
    fn add_rule(&self, rule: AlertRule) -> Result<()> {
        self.rules.insert(rule.name.clone(), rule);
        Ok(())
    }
    
    async fn check_all_rules(&self, metrics: &DashMap<String, MetricValue>) -> Vec<Alert> {
        let mut triggered_alerts = Vec::new();
        
        for rule in self.rules.iter() {
            if let Some(alert) = self.check_rule(&rule, metrics) {
                triggered_alerts.push(alert.clone());
                self.active_alerts.insert(rule.name.clone(), alert);
            }
        }
        
        triggered_alerts
    }
    
    fn check_rule(&self, rule: &AlertRule, metrics: &DashMap<String, MetricValue>) -> Option<Alert> {
        match &rule.condition {
            AlertCondition::Threshold { metric, operator, value } => {
                if let Some(metric_value) = metrics.get(metric) {
                    if let MetricValue::Gauge(current) = metric_value.value() {
                        let triggered = match operator {
                            ComparisonOperator::GreaterThan => current > value,
                            ComparisonOperator::LessThan => current < value,
                            ComparisonOperator::Equal => (current - value).abs() < f64::EPSILON,
                        };
                        
                        if triggered {
                            return Some(Alert {
                                rule_name: rule.name.clone(),
                                triggered_at: Utc::now(),
                                metric_value: *current,
                                message: format!("{} is {} (threshold: {})", metric, current, value),
                            });
                        }
                    }
                }
            }
            _ => {} // Other conditions would be implemented similarly
        }
        
        None
    }
}

impl HealthChecker {
    fn new() -> Self {
        let initial_status = HealthStatus {
            overall: SystemHealth::Healthy,
            components: Vec::new(),
            last_check: Utc::now(),
        };
        
        Self {
            checks: DashMap::new(),
            status: Arc::new(tokio::sync::RwLock::new(initial_status)),
        }
    }
    
    async fn check_all(&self) -> Result<HealthStatus> {
        let mut component_statuses = Vec::new();
        let mut has_unhealthy = false;
        let mut has_degraded = false;
        
        for check in self.checks.iter() {
            let status = self.run_check(&check).await?;
            
            match &status.status {
                ComponentHealth::Unhealthy(_) => has_unhealthy = true,
                ComponentHealth::Degraded(_) => has_degraded = true,
                _ => {}
            }
            
            component_statuses.push(status);
        }
        
        let overall = if has_unhealthy {
            SystemHealth::Unhealthy
        } else if has_degraded {
            SystemHealth::Degraded
        } else {
            SystemHealth::Healthy
        };
        
        let health_status = HealthStatus {
            overall,
            components: component_statuses,
            last_check: Utc::now(),
        };
        
        *self.status.write().await = health_status.clone();
        
        Ok(health_status)
    }
    
    async fn run_check(&self, _check: &HealthCheck) -> Result<ComponentStatus> {
        // Simplified health check - in production would run actual checks
        Ok(ComponentStatus {
            name: "devops_server".to_string(),
            status: ComponentHealth::Healthy,
            message: None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub predictions_total: f64,
    pub prediction_success_rate: f64,
    pub deployments_total: f64,
    pub deployment_success_rate: f64,
    pub remediations_total: f64,
    pub remediation_success_rate: f64,
    pub memory_usage_mb: f64,
    pub memory_pool_utilization: f64,
    pub patterns_discovered: f64,
    pub model_accuracy: f64,
    pub timestamp: DateTime<Utc>,
}

impl MonitoringService {
    pub fn get_metrics_snapshot(&self) -> MetricsSnapshot {
        let deployments_total = DEPLOYMENT_COUNTER.get();
        let deployments_success = DEPLOYMENT_SUCCESS_COUNTER.get();
        let remediations_total = REMEDIATION_COUNTER.get();
        let remediations_success = REMEDIATION_SUCCESS_COUNTER.get();
        
        MetricsSnapshot {
            predictions_total: PREDICTION_COUNTER.get(),
            prediction_success_rate: PREDICTION_SUCCESS_RATE.get(),
            deployments_total,
            deployment_success_rate: if deployments_total > 0.0 {
                deployments_success / deployments_total
            } else {
                0.0
            },
            remediations_total,
            remediation_success_rate: if remediations_total > 0.0 {
                remediations_success / remediations_total
            } else {
                0.0
            },
            memory_usage_mb: MEMORY_USAGE.get() / (1024.0 * 1024.0),
            memory_pool_utilization: MEMORY_POOL_UTILIZATION.get(),
            patterns_discovered: PATTERNS_DISCOVERED.get(),
            model_accuracy: MODEL_ACCURACY.get(),
            timestamp: Utc::now(),
        }
    }
}