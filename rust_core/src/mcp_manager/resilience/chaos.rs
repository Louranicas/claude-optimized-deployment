use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex};
use tokio::time::{interval, sleep};
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;

/// Chaos experiment type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExperimentType {
    NetworkLatency,
    NetworkPartition,
    PacketLoss,
    ServiceCrash,
    ResourceExhaustion,
    ClockSkew,
    DiskFailure,
    CPUSpike,
    MemoryLeak,
    RandomKill,
}

/// Chaos experiment configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentConfig {
    pub experiment_type: ExperimentType,
    pub target: String,
    pub duration: Duration,
    pub intensity: f64,
    pub probability: f64,
    pub params: HashMap<String, String>,
}

/// Experiment result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentResult {
    pub id: String,
    pub experiment_type: ExperimentType,
    pub start_time: Instant,
    pub end_time: Option<Instant>,
    pub status: ExperimentStatus,
    pub impact_metrics: HashMap<String, f64>,
    pub recovery_time: Option<Duration>,
    pub errors: Vec<String>,
}

/// Experiment status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExperimentStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Aborted,
}

/// System metrics for monitoring
#[derive(Debug, Clone)]
pub struct SystemMetrics {
    pub availability: f64,
    pub latency_p50: Duration,
    pub latency_p95: Duration,
    pub latency_p99: Duration,
    pub error_rate: f64,
    pub throughput: f64,
    pub cpu_usage: f64,
    pub memory_usage: f64,
}

/// Chaos engineering manager
pub struct ChaosEngineer {
    /// Active experiments
    experiments: Arc<RwLock<HashMap<String, ExperimentResult>>>,
    
    /// Experiment queue
    experiment_queue: Arc<Mutex<Vec<ExperimentConfig>>>,
    
    /// System metrics before experiments
    baseline_metrics: Arc<RwLock<SystemMetrics>>,
    
    /// Current system metrics
    current_metrics: Arc<RwLock<SystemMetrics>>,
    
    /// Safety checks enabled
    safety_enabled: Arc<RwLock<bool>>,
    
    /// Maximum allowed degradation
    max_degradation: f64,
    
    /// Experiment channel
    experiment_tx: mpsc::Sender<(ExperimentConfig, mpsc::Sender<ExperimentResult>)>,
    experiment_rx: Arc<Mutex<mpsc::Receiver<(ExperimentConfig, mpsc::Sender<ExperimentResult>)>>>,
    
    /// Abort channel
    abort_tx: mpsc::Sender<String>,
    abort_rx: Arc<Mutex<mpsc::Receiver<String>>>,
    
    /// Service hooks for injection
    service_hooks: Arc<RwLock<HashMap<String, Box<dyn ServiceHook>>>>,
}

/// Service hook trait for chaos injection
pub trait ServiceHook: Send + Sync {
    fn inject_latency(&self, duration: Duration) -> Result<()>;
    fn inject_error(&self, error_rate: f64) -> Result<()>;
    fn inject_resource_limit(&self, cpu_limit: f64, memory_limit: f64) -> Result<()>;
    fn kill_service(&self) -> Result<()>;
    fn partition_network(&self, target: &str) -> Result<()>;
}

impl ChaosEngineer {
    /// Create a new chaos engineer
    pub fn new() -> Self {
        let (experiment_tx, experiment_rx) = mpsc::channel(100);
        let (abort_tx, abort_rx) = mpsc::channel(100);
        
        Self {
            experiments: Arc::new(RwLock::new(HashMap::new())),
            experiment_queue: Arc::new(Mutex::new(Vec::new())),
            baseline_metrics: Arc::new(RwLock::new(SystemMetrics {
                availability: 1.0,
                latency_p50: Duration::from_millis(10),
                latency_p95: Duration::from_millis(50),
                latency_p99: Duration::from_millis(100),
                error_rate: 0.0,
                throughput: 1000.0,
                cpu_usage: 0.3,
                memory_usage: 0.4,
            })),
            current_metrics: Arc::new(RwLock::new(SystemMetrics {
                availability: 1.0,
                latency_p50: Duration::from_millis(10),
                latency_p95: Duration::from_millis(50),
                latency_p99: Duration::from_millis(100),
                error_rate: 0.0,
                throughput: 1000.0,
                cpu_usage: 0.3,
                memory_usage: 0.4,
            })),
            safety_enabled: Arc::new(RwLock::new(true)),
            max_degradation: 0.3, // 30% max degradation
            experiment_tx,
            experiment_rx: Arc::new(Mutex::new(experiment_rx)),
            abort_tx,
            abort_rx: Arc::new(Mutex::new(abort_rx)),
            service_hooks: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Start the chaos engineer
    pub async fn start(&self) -> Result<()> {
        // Start experiment runner
        let runner_handle = self.start_experiment_runner();
        
        // Start safety monitor
        let safety_handle = self.start_safety_monitor();
        
        // Start metrics collector
        let metrics_handle = self.start_metrics_collector();
        
        // Start abort handler
        let abort_handle = self.start_abort_handler();
        
        // Wait for all tasks
        tokio::select! {
            _ = runner_handle => {},
            _ = safety_handle => {},
            _ = metrics_handle => {},
            _ = abort_handle => {},
        }
        
        Ok(())
    }
    
    /// Schedule an experiment
    pub async fn schedule_experiment(&self, config: ExperimentConfig) -> Result<String> {
        // Validate experiment
        self.validate_experiment(&config)?;
        
        // Check safety
        if *self.safety_enabled.read().unwrap() {
            self.check_safety(&config)?;
        }
        
        // Generate experiment ID
        let id = self.generate_experiment_id();
        
        // Create result entry
        let result = ExperimentResult {
            id: id.clone(),
            experiment_type: config.experiment_type,
            start_time: Instant::now(),
            end_time: None,
            status: ExperimentStatus::Pending,
            impact_metrics: HashMap::new(),
            recovery_time: None,
            errors: Vec::new(),
        };
        
        self.experiments.write().unwrap().insert(id.clone(), result);
        
        // Queue experiment
        self.experiment_queue.lock().await.push(config);
        
        Ok(id)
    }
    
    /// Abort an experiment
    pub async fn abort_experiment(&self, experiment_id: &str) -> Result<()> {
        self.abort_tx.send(experiment_id.to_string()).await
            .map_err(|_| anyhow!("Failed to send abort signal"))?;
        Ok(())
    }
    
    /// Register a service hook
    pub fn register_service_hook(&self, service: String, hook: Box<dyn ServiceHook>) {
        self.service_hooks.write().unwrap().insert(service, hook);
    }
    
    /// Start experiment runner
    fn start_experiment_runner(&self) -> tokio::task::JoinHandle<()> {
        let experiment_rx = self.experiment_rx.clone();
        let experiments = self.experiments.clone();
        let experiment_queue = self.experiment_queue.clone();
        let service_hooks = self.service_hooks.clone();
        
        tokio::spawn(async move {
            let mut rx = experiment_rx.lock().await;
            
            // Also check queue periodically
            let mut interval = interval(Duration::from_secs(1));
            
            loop {
                tokio::select! {
                    Some((config, response_tx)) = rx.recv() => {
                        let result = Self::run_experiment(
                            config.clone(),
                            experiments.clone(),
                            service_hooks.clone()
                        ).await;
                        
                        let _ = response_tx.send(result).await;
                    }
                    _ = interval.tick() => {
                        // Process queued experiments
                        let mut queue = experiment_queue.lock().await;
                        if let Some(config) = queue.pop() {
                            let (tx, mut rx) = mpsc::channel(1);
                            
                            let result = Self::run_experiment(
                                config.clone(),
                                experiments.clone(),
                                service_hooks.clone()
                            ).await;
                            
                            let _ = tx.send(result).await;
                        }
                    }
                }
            }
        })
    }
    
    /// Run a single experiment
    async fn run_experiment(
        config: ExperimentConfig,
        experiments: Arc<RwLock<HashMap<String, ExperimentResult>>>,
        service_hooks: Arc<RwLock<HashMap<String, Box<dyn ServiceHook>>>>,
    ) -> ExperimentResult {
        let experiment_id = experiments.read().unwrap()
            .values()
            .find(|e| e.experiment_type == config.experiment_type && 
                     e.status == ExperimentStatus::Pending)
            .map(|e| e.id.clone())
            .unwrap_or_else(|| "unknown".to_string());
        
        // Update status to running
        if let Some(result) = experiments.write().unwrap().get_mut(&experiment_id) {
            result.status = ExperimentStatus::Running;
            result.start_time = Instant::now();
        }
        
        // Execute experiment based on type
        let mut errors = Vec::new();
        let mut impact_metrics = HashMap::new();
        
        match config.experiment_type {
            ExperimentType::NetworkLatency => {
                if let Some(hook) = service_hooks.read().unwrap().get(&config.target) {
                    let latency = Duration::from_millis((config.intensity * 1000.0) as u64);
                    if let Err(e) = hook.inject_latency(latency) {
                        errors.push(format!("Failed to inject latency: {}", e));
                    }
                    impact_metrics.insert("latency_ms".to_string(), latency.as_millis() as f64);
                }
            }
            ExperimentType::ServiceCrash => {
                if let Some(hook) = service_hooks.read().unwrap().get(&config.target) {
                    if let Err(e) = hook.kill_service() {
                        errors.push(format!("Failed to kill service: {}", e));
                    }
                    impact_metrics.insert("service_killed".to_string(), 1.0);
                }
            }
            ExperimentType::PacketLoss => {
                if let Some(hook) = service_hooks.read().unwrap().get(&config.target) {
                    if let Err(e) = hook.inject_error(config.intensity) {
                        errors.push(format!("Failed to inject packet loss: {}", e));
                    }
                    impact_metrics.insert("packet_loss_rate".to_string(), config.intensity);
                }
            }
            ExperimentType::CPUSpike => {
                if let Some(hook) = service_hooks.read().unwrap().get(&config.target) {
                    let cpu_limit = 1.0 - config.intensity; // High intensity = low CPU limit
                    if let Err(e) = hook.inject_resource_limit(cpu_limit, 1.0) {
                        errors.push(format!("Failed to inject CPU spike: {}", e));
                    }
                    impact_metrics.insert("cpu_limit".to_string(), cpu_limit);
                }
            }
            ExperimentType::MemoryLeak => {
                if let Some(hook) = service_hooks.read().unwrap().get(&config.target) {
                    let memory_limit = 1.0 - config.intensity;
                    if let Err(e) = hook.inject_resource_limit(1.0, memory_limit) {
                        errors.push(format!("Failed to inject memory leak: {}", e));
                    }
                    impact_metrics.insert("memory_limit".to_string(), memory_limit);
                }
            }
            ExperimentType::NetworkPartition => {
                if let Some(hook) = service_hooks.read().unwrap().get(&config.target) {
                    if let Some(partition_target) = config.params.get("partition_target") {
                        if let Err(e) = hook.partition_network(partition_target) {
                            errors.push(format!("Failed to partition network: {}", e));
                        }
                        impact_metrics.insert("partition_active".to_string(), 1.0);
                    }
                }
            }
            _ => {
                errors.push(format!("Experiment type {:?} not implemented", config.experiment_type));
            }
        }
        
        // Wait for experiment duration
        sleep(config.duration).await;
        
        // Update final result
        let end_time = Instant::now();
        if let Some(result) = experiments.write().unwrap().get_mut(&experiment_id) {
            result.end_time = Some(end_time);
            result.status = if errors.is_empty() {
                ExperimentStatus::Completed
            } else {
                ExperimentStatus::Failed
            };
            result.impact_metrics = impact_metrics;
            result.errors = errors;
            
            return result.clone();
        }
        
        // Return default result if not found
        ExperimentResult {
            id: experiment_id,
            experiment_type: config.experiment_type,
            start_time: Instant::now(),
            end_time: Some(end_time),
            status: ExperimentStatus::Failed,
            impact_metrics,
            recovery_time: None,
            errors,
        }
    }
    
    /// Start safety monitor
    fn start_safety_monitor(&self) -> tokio::task::JoinHandle<()> {
        let experiments = self.experiments.clone();
        let baseline_metrics = self.baseline_metrics.clone();
        let current_metrics = self.current_metrics.clone();
        let safety_enabled = self.safety_enabled.clone();
        let max_degradation = self.max_degradation;
        let abort_tx = self.abort_tx.clone();
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(1));
            
            loop {
                interval.tick().await;
                
                if !*safety_enabled.read().unwrap() {
                    continue;
                }
                
                let baseline = baseline_metrics.read().unwrap();
                let current = current_metrics.read().unwrap();
                
                // Check for excessive degradation
                let availability_degradation = (baseline.availability - current.availability) / baseline.availability;
                let error_rate_increase = current.error_rate - baseline.error_rate;
                let latency_increase = current.latency_p99.as_millis() as f64 / baseline.latency_p99.as_millis() as f64 - 1.0;
                
                if availability_degradation > max_degradation ||
                   error_rate_increase > max_degradation ||
                   latency_increase > max_degradation {
                    // Abort all running experiments
                    let running_experiments: Vec<String> = experiments.read().unwrap()
                        .iter()
                        .filter(|(_, e)| e.status == ExperimentStatus::Running)
                        .map(|(id, _)| id.clone())
                        .collect();
                    
                    for exp_id in running_experiments {
                        let _ = abort_tx.send(exp_id).await;
                    }
                }
            }
        })
    }
    
    /// Start metrics collector
    fn start_metrics_collector(&self) -> tokio::task::JoinHandle<()> {
        let current_metrics = self.current_metrics.clone();
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(1));
            
            loop {
                interval.tick().await;
                
                // In real implementation, collect actual metrics
                // For now, simulate metric collection
                let mut metrics = current_metrics.write().unwrap();
                
                // Add some random variation
                let mut rng = thread_rng();
                metrics.availability = 0.95 + rng.gen::<f64>() * 0.05;
                metrics.error_rate = rng.gen::<f64>() * 0.05;
                metrics.latency_p50 = Duration::from_millis(8 + rng.gen_range(0..5));
                metrics.latency_p95 = Duration::from_millis(45 + rng.gen_range(0..15));
                metrics.latency_p99 = Duration::from_millis(90 + rng.gen_range(0..30));
                metrics.throughput = 900.0 + rng.gen::<f64>() * 200.0;
                metrics.cpu_usage = 0.25 + rng.gen::<f64>() * 0.15;
                metrics.memory_usage = 0.35 + rng.gen::<f64>() * 0.15;
            }
        })
    }
    
    /// Start abort handler
    fn start_abort_handler(&self) -> tokio::task::JoinHandle<()> {
        let abort_rx = self.abort_rx.clone();
        let experiments = self.experiments.clone();
        
        tokio::spawn(async move {
            let mut rx = abort_rx.lock().await;
            
            while let Some(experiment_id) = rx.recv().await {
                if let Some(result) = experiments.write().unwrap().get_mut(&experiment_id) {
                    if result.status == ExperimentStatus::Running {
                        result.status = ExperimentStatus::Aborted;
                        result.end_time = Some(Instant::now());
                        result.errors.push("Experiment aborted by safety monitor".to_string());
                    }
                }
            }
        })
    }
    
    /// Validate experiment configuration
    fn validate_experiment(&self, config: &ExperimentConfig) -> Result<()> {
        if config.intensity < 0.0 || config.intensity > 1.0 {
            return Err(anyhow!("Intensity must be between 0.0 and 1.0"));
        }
        
        if config.probability < 0.0 || config.probability > 1.0 {
            return Err(anyhow!("Probability must be between 0.0 and 1.0"));
        }
        
        if config.duration > Duration::from_secs(3600) {
            return Err(anyhow!("Experiment duration cannot exceed 1 hour"));
        }
        
        Ok(())
    }
    
    /// Check safety constraints
    fn check_safety(&self, config: &ExperimentConfig) -> Result<()> {
        let experiments = self.experiments.read().unwrap();
        
        // Check for concurrent experiments on same target
        let concurrent = experiments.values()
            .filter(|e| e.status == ExperimentStatus::Running)
            .count();
        
        if concurrent >= 3 {
            return Err(anyhow!("Too many concurrent experiments"));
        }
        
        // Check for recent failures
        let recent_failures = experiments.values()
            .filter(|e| e.status == ExperimentStatus::Failed &&
                       e.end_time.map(|t| t.elapsed() < Duration::from_secs(300)).unwrap_or(false))
            .count();
        
        if recent_failures >= 2 {
            return Err(anyhow!("Too many recent failures"));
        }
        
        Ok(())
    }
    
    /// Generate experiment ID
    fn generate_experiment_id(&self) -> String {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(12)
            .map(char::from)
            .collect()
    }
    
    /// Get experiment results
    pub fn get_experiment_results(&self, experiment_id: &str) -> Option<ExperimentResult> {
        self.experiments.read().unwrap().get(experiment_id).cloned()
    }
    
    /// Get all experiments
    pub fn get_all_experiments(&self) -> Vec<ExperimentResult> {
        self.experiments.read().unwrap().values().cloned().collect()
    }
    
    /// Get current metrics
    pub fn get_current_metrics(&self) -> SystemMetrics {
        self.current_metrics.read().unwrap().clone()
    }
    
    /// Update baseline metrics
    pub fn update_baseline_metrics(&self) {
        let current = self.current_metrics.read().unwrap().clone();
        *self.baseline_metrics.write().unwrap() = current;
    }
    
    /// Enable/disable safety checks
    pub fn set_safety_enabled(&self, enabled: bool) {
        *self.safety_enabled.write().unwrap() = enabled;
    }
}

/// Mock service hook for testing
pub struct MockServiceHook;

impl ServiceHook for MockServiceHook {
    fn inject_latency(&self, _duration: Duration) -> Result<()> {
        Ok(())
    }
    
    fn inject_error(&self, _error_rate: f64) -> Result<()> {
        Ok(())
    }
    
    fn inject_resource_limit(&self, _cpu_limit: f64, _memory_limit: f64) -> Result<()> {
        Ok(())
    }
    
    fn kill_service(&self) -> Result<()> {
        Ok(())
    }
    
    fn partition_network(&self, _target: &str) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_chaos_engineer_creation() {
        let chaos = ChaosEngineer::new();
        
        assert!(chaos.get_all_experiments().is_empty());
        assert_eq!(chaos.get_current_metrics().availability, 1.0);
    }
    
    #[tokio::test]
    async fn test_experiment_scheduling() {
        let chaos = ChaosEngineer::new();
        chaos.register_service_hook("test-service".to_string(), Box::new(MockServiceHook));
        
        let config = ExperimentConfig {
            experiment_type: ExperimentType::NetworkLatency,
            target: "test-service".to_string(),
            duration: Duration::from_secs(1),
            intensity: 0.5,
            probability: 1.0,
            params: HashMap::new(),
        };
        
        let id = chaos.schedule_experiment(config).await.unwrap();
        assert!(!id.is_empty());
        
        // Wait for experiment to start
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let result = chaos.get_experiment_results(&id);
        assert!(result.is_some());
    }
    
    #[tokio::test]
    async fn test_safety_validation() {
        let chaos = ChaosEngineer::new();
        
        // Invalid intensity
        let config = ExperimentConfig {
            experiment_type: ExperimentType::NetworkLatency,
            target: "test-service".to_string(),
            duration: Duration::from_secs(1),
            intensity: 1.5, // Invalid
            probability: 1.0,
            params: HashMap::new(),
        };
        
        assert!(chaos.schedule_experiment(config).await.is_err());
    }
}