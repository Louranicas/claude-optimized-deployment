//! Health check system with async monitoring
//! 
//! Provides efficient health checking for services with configurable
//! intervals, timeouts, and failure thresholds.

use super::*;
use crate::orchestrator::{ServiceMetadata, HealthStatus};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, mpsc};
use tokio::time::{interval, timeout, Instant};
use tracing::{debug, info, warn, error, instrument};
use dashmap::DashMap;
use uuid::Uuid;

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// Default check interval in seconds
    pub default_interval_secs: u64,
    /// Check timeout in seconds
    pub timeout_secs: u64,
    /// Number of consecutive failures before marking unhealthy
    pub failure_threshold: u32,
    /// Number of consecutive successes before marking healthy
    pub success_threshold: u32,
    /// Enable exponential backoff for failed checks
    pub exponential_backoff: bool,
    /// Maximum backoff interval in seconds
    pub max_backoff_secs: u64,
    /// Number of worker threads
    pub worker_threads: usize,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            default_interval_secs: 30,
            timeout_secs: 10,
            failure_threshold: 3,
            success_threshold: 2,
            exponential_backoff: true,
            max_backoff_secs: 300,
            worker_threads: 4,
        }
    }
}

/// Health check result
#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    pub service_id: Uuid,
    pub is_healthy: bool,
    pub latency_ms: f64,
    pub error: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Service health check configuration
#[derive(Debug, Clone)]
struct ServiceHealthConfig {
    pub interval_secs: u64,
    pub endpoint: String,
    pub check_type: HealthCheckType,
    pub expected_response: Option<String>,
}

/// Health check type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthCheckType {
    Http,
    Tcp,
    Grpc,
    Command,
    Custom,
}

/// Health check task
struct HealthCheckTask {
    service_id: Uuid,
    config: ServiceHealthConfig,
    consecutive_failures: u32,
    consecutive_successes: u32,
    last_check: Option<chrono::DateTime<chrono::Utc>>,
    current_interval_secs: u64,
}

/// Health checker service
pub struct HealthChecker {
    config: Arc<HealthCheckConfig>,
    tasks: Arc<DashMap<Uuid, HealthCheckTask>>,
    results: Arc<RwLock<Vec<HealthCheckResult>>>,
    worker_pool: Arc<tokio::sync::Semaphore>,
    shutdown_tx: Arc<RwLock<Option<mpsc::Sender<()>>>>,
}

impl HealthChecker {
    /// Create a new health checker
    pub fn new(config: HealthCheckConfig) -> Self {
        Self {
            worker_pool: Arc::new(tokio::sync::Semaphore::new(config.worker_threads)),
            config: Arc::new(config),
            tasks: Arc::new(DashMap::new()),
            results: Arc::new(RwLock::new(Vec::new())),
            shutdown_tx: Arc::new(RwLock::new(None)),
        }
    }
    
    /// Start health checking service
    pub async fn start(&self) -> Result<(), ServiceError> {
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
        *self.shutdown_tx.write().await = Some(shutdown_tx);
        
        let tasks = Arc::clone(&self.tasks);
        let config = Arc::clone(&self.config);
        let results = Arc::clone(&self.results);
        let worker_pool = Arc::clone(&self.worker_pool);
        
        // Main health check loop
        tokio::spawn(async move {
            let mut check_interval = interval(Duration::from_secs(1));
            
            loop {
                tokio::select! {
                    _ = check_interval.tick() => {
                        let now = chrono::Utc::now();
                        let tasks_to_check: Vec<_> = tasks.iter()
                            .filter(|entry| {
                                let task = entry.value();
                                task.last_check.is_none() || 
                                (now - task.last_check.unwrap()).num_seconds() >= task.current_interval_secs as i64
                            })
                            .map(|entry| (*entry.key(), entry.value().clone()))
                            .collect();
                        
                        for (service_id, mut task) in tasks_to_check {
                            let permit = worker_pool.clone().acquire_owned().await;
                            if permit.is_err() {
                                continue;
                            }
                            
                            let config = config.clone();
                            let results = results.clone();
                            let tasks = tasks.clone();
                            
                            tokio::spawn(async move {
                                let _permit = permit.unwrap();
                                
                                let result = Self::perform_health_check(
                                    service_id,
                                    &task.config,
                                    config.timeout_secs
                                ).await;
                                
                                // Update task state
                                task.last_check = Some(chrono::Utc::now());
                                
                                if result.is_healthy {
                                    task.consecutive_failures = 0;
                                    task.consecutive_successes += 1;
                                    
                                    // Reset interval on recovery
                                    if task.consecutive_successes >= config.success_threshold {
                                        task.current_interval_secs = task.config.interval_secs;
                                    }
                                } else {
                                    task.consecutive_successes = 0;
                                    task.consecutive_failures += 1;
                                    
                                    // Apply exponential backoff
                                    if config.exponential_backoff && task.consecutive_failures > config.failure_threshold {
                                        task.current_interval_secs = std::cmp::min(
                                            task.current_interval_secs * 2,
                                            config.max_backoff_secs
                                        );
                                    }
                                }
                                
                                // Store result
                                let mut results_vec = results.write().await;
                                results_vec.push(result.clone());
                                
                                // Keep only last 1000 results per service
                                if results_vec.len() > 1000 {
                                    results_vec.drain(0..results_vec.len() - 1000);
                                }
                                
                                // Update task
                                tasks.insert(service_id, task);
                            });
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Health checker shutting down");
                        break;
                    }
                }
            }
        });
        
        Ok(())
    }
    
    /// Register a service for health checking
    #[instrument(skip(self))]
    pub async fn register_service(
        &self,
        service_id: Uuid,
        endpoint: String,
        check_type: HealthCheckType,
    ) -> Result<(), ServiceError> {
        let config = ServiceHealthConfig {
            interval_secs: self.config.default_interval_secs,
            endpoint,
            check_type,
            expected_response: None,
        };
        
        let task = HealthCheckTask {
            service_id,
            config: config.clone(),
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_check: None,
            current_interval_secs: config.interval_secs,
        };
        
        self.tasks.insert(service_id, task);
        
        debug!("Registered service {} for health checking", service_id);
        Ok(())
    }
    
    /// Unregister a service from health checking
    pub async fn unregister_service(&self, service_id: Uuid) -> Result<(), ServiceError> {
        self.tasks.remove(&service_id)
            .ok_or_else(|| ServiceError::NotFound(service_id.to_string()))?;
        
        Ok(())
    }
    
    /// Perform a health check
    async fn perform_health_check(
        service_id: Uuid,
        config: &ServiceHealthConfig,
        timeout_secs: u64,
    ) -> HealthCheckResult {
        let start = Instant::now();
        
        let check_future = async {
            match config.check_type {
                HealthCheckType::Http => Self::check_http(&config.endpoint).await,
                HealthCheckType::Tcp => Self::check_tcp(&config.endpoint).await,
                HealthCheckType::Grpc => Self::check_grpc(&config.endpoint).await,
                HealthCheckType::Command => Self::check_command(&config.endpoint).await,
                HealthCheckType::Custom => Ok(()), // Custom checks would be implemented by users
            }
        };
        
        let result = timeout(Duration::from_secs(timeout_secs), check_future).await;
        
        let latency_ms = start.elapsed().as_millis() as f64;
        
        match result {
            Ok(Ok(())) => HealthCheckResult {
                service_id,
                is_healthy: true,
                latency_ms,
                error: None,
                timestamp: chrono::Utc::now(),
            },
            Ok(Err(e)) => HealthCheckResult {
                service_id,
                is_healthy: false,
                latency_ms,
                error: Some(e.to_string()),
                timestamp: chrono::Utc::now(),
            },
            Err(_) => HealthCheckResult {
                service_id,
                is_healthy: false,
                latency_ms,
                error: Some(format!("Health check timeout after {} seconds", timeout_secs)),
                timestamp: chrono::Utc::now(),
            },
        }
    }
    
    /// HTTP health check
    async fn check_http(endpoint: &str) -> Result<(), ServiceError> {
        let client = reqwest::Client::new();
        let response = client.get(endpoint)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| ServiceError::HealthCheckFailed(e.to_string()))?;
        
        if response.status().is_success() {
            Ok(())
        } else {
            Err(ServiceError::HealthCheckFailed(
                format!("HTTP {}", response.status())
            ))
        }
    }
    
    /// TCP health check
    async fn check_tcp(endpoint: &str) -> Result<(), ServiceError> {
        use tokio::net::TcpStream;
        
        TcpStream::connect(endpoint)
            .await
            .map_err(|e| ServiceError::HealthCheckFailed(e.to_string()))?;
        
        Ok(())
    }
    
    /// gRPC health check
    async fn check_grpc(_endpoint: &str) -> Result<(), ServiceError> {
        // Placeholder for gRPC health check
        // Would use tonic client in production
        Ok(())
    }
    
    /// Command health check
    async fn check_command(command: &str) -> Result<(), ServiceError> {
        use tokio::process::Command;
        
        let output = Command::new("sh")
            .arg("-c")
            .arg(command)
            .output()
            .await
            .map_err(|e| ServiceError::HealthCheckFailed(e.to_string()))?;
        
        if output.status.success() {
            Ok(())
        } else {
            Err(ServiceError::HealthCheckFailed(
                String::from_utf8_lossy(&output.stderr).to_string()
            ))
        }
    }
    
    /// Get health status for a service
    pub async fn get_health_status(&self, service_id: Uuid) -> Option<HealthStatus> {
        let task = self.tasks.get(&service_id)?;
        
        let is_healthy = task.consecutive_failures < self.config.failure_threshold;
        
        let results = self.results.read().await;
        let recent_results: Vec<_> = results.iter()
            .filter(|r| r.service_id == service_id)
            .rev()
            .take(10)
            .collect();
        
        let error_rate = if !recent_results.is_empty() {
            recent_results.iter()
                .filter(|r| !r.is_healthy)
                .count() as f64 / recent_results.len() as f64
        } else {
            0.0
        };
        
        let avg_latency = if !recent_results.is_empty() {
            recent_results.iter()
                .map(|r| r.latency_ms)
                .sum::<f64>() / recent_results.len() as f64
        } else {
            0.0
        };
        
        Some(HealthStatus {
            is_healthy,
            last_check: task.last_check.unwrap_or_else(chrono::Utc::now),
            consecutive_failures: task.consecutive_failures,
            latency_ms: avg_latency,
            error_rate,
        })
    }
    
    /// Get recent health check results
    pub async fn get_recent_results(&self, service_id: Option<Uuid>, limit: usize) -> Vec<HealthCheckResult> {
        let results = self.results.read().await;
        
        if let Some(id) = service_id {
            results.iter()
                .filter(|r| r.service_id == id)
                .rev()
                .take(limit)
                .cloned()
                .collect()
        } else {
            results.iter()
                .rev()
                .take(limit)
                .cloned()
                .collect()
        }
    }
    
    /// Stop health checking
    pub async fn stop(&self) -> Result<(), ServiceError> {
        if let Some(tx) = self.shutdown_tx.write().await.take() {
            tx.send(()).await.ok();
        }
        Ok(())
    }
}

impl Clone for HealthCheckTask {
    fn clone(&self) -> Self {
        Self {
            service_id: self.service_id,
            config: self.config.clone(),
            consecutive_failures: self.consecutive_failures,
            consecutive_successes: self.consecutive_successes,
            last_check: self.last_check,
            current_interval_secs: self.current_interval_secs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_health_checker_creation() {
        let config = HealthCheckConfig::default();
        let checker = HealthChecker::new(config);
        
        checker.start().await.unwrap();
        
        // Register a service
        checker.register_service(
            Uuid::new_v4(),
            "http://localhost:8080/health".to_string(),
            HealthCheckType::Http,
        ).await.unwrap();
        
        checker.stop().await.unwrap();
    }
    
    #[tokio::test]
    async fn test_health_check_results() {
        let config = HealthCheckConfig {
            default_interval_secs: 1,
            ..Default::default()
        };
        let checker = HealthChecker::new(config);
        
        let service_id = Uuid::new_v4();
        
        // Simulate health check result
        let result = HealthCheckResult {
            service_id,
            is_healthy: true,
            latency_ms: 15.5,
            error: None,
            timestamp: chrono::Utc::now(),
        };
        
        let mut results = checker.results.write().await;
        results.push(result);
        drop(results);
        
        let recent = checker.get_recent_results(Some(service_id), 10).await;
        assert_eq!(recent.len(), 1);
        assert!(recent[0].is_healthy);
    }
}