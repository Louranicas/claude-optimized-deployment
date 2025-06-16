//! Task executor for deployment orchestration
//! 
//! Handles the actual execution of deployment tasks with retry logic,
//! timeout handling, and graceful error recovery.

use super::*;
use crate::reliability::{RetryPolicy, RetryConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::{RwLock, oneshot};
use tokio::time::{timeout, sleep};
use tracing::{debug, info, warn, error, instrument, span, Level};
use dashmap::DashMap;

/// Executor configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorConfig {
    /// Deployment timeout in seconds
    pub deployment_timeout_secs: u64,
    /// Stop timeout in seconds
    pub stop_timeout_secs: u64,
    /// Health check timeout in seconds
    pub health_check_timeout_secs: u64,
    /// Number of worker threads
    pub worker_threads: usize,
    /// Enable detailed logging
    pub detailed_logging: bool,
    /// Command execution timeout in seconds
    pub command_timeout_secs: u64,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            deployment_timeout_secs: 300,
            stop_timeout_secs: 60,
            health_check_timeout_secs: 10,
            worker_threads: 4,
            detailed_logging: true,
            command_timeout_secs: 120,
        }
    }
}

/// Execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub service_id: Uuid,
    pub success: bool,
    pub duration_ms: u64,
    pub error: Option<String>,
    pub output: Option<String>,
    pub exit_code: Option<i32>,
}

/// Deployment context
#[derive(Debug, Clone)]
struct DeploymentContext {
    service_id: Uuid,
    service_name: String,
    version: String,
    started_at: chrono::DateTime<chrono::Utc>,
    retry_count: u32,
    last_error: Option<String>,
}

/// Task executor
pub struct Executor {
    config: Arc<ExecutorConfig>,
    retry_policy: Arc<RetryPolicy>,
    active_executions: Arc<DashMap<Uuid, ExecutionHandle>>,
    execution_history: Arc<RwLock<Vec<ExecutionResult>>>,
    worker_pool: Arc<tokio::sync::Semaphore>,
}

/// Execution handle for tracking active executions
struct ExecutionHandle {
    context: DeploymentContext,
    cancel_token: tokio_util::sync::CancellationToken,
    completion_sender: Option<oneshot::Sender<ExecutionResult>>,
}

impl Executor {
    /// Create a new executor
    pub fn new(config: ExecutorConfig) -> Self {
        let retry_config = RetryConfig {
            max_attempts: 3,
            initial_delay_ms: 1000,
            max_delay_ms: 30000,
            exponential_base: 2.0,
            jitter: true,
        };
        
        Self {
            worker_pool: Arc::new(tokio::sync::Semaphore::new(config.worker_threads)),
            config: Arc::new(config),
            retry_policy: Arc::new(RetryPolicy::new(retry_config)),
            active_executions: Arc::new(DashMap::new()),
            execution_history: Arc::new(RwLock::new(Vec::new())),
        }
    }
    
    /// Execute a deployment
    #[instrument(skip(self), fields(service_id = %service_id))]
    pub async fn execute_deployment(&self, service_id: Uuid) -> OrchestratorResult<ExecutionResult> {
        let _permit = self.worker_pool.acquire().await
            .map_err(|_| OrchestratorError::ResourceLimitExceeded(
                "Worker pool exhausted".to_string()
            ))?;
        
        let span = span!(Level::INFO, "deployment", service_id = %service_id);
        let _enter = span.enter();
        
        // Create execution context
        let context = DeploymentContext {
            service_id,
            service_name: "unknown".to_string(), // Should be provided
            version: "unknown".to_string(), // Should be provided
            started_at: chrono::Utc::now(),
            retry_count: 0,
            last_error: None,
        };
        
        // Create cancellation token
        let cancel_token = tokio_util::sync::CancellationToken::new();
        let (tx, rx) = oneshot::channel();
        
        // Register active execution
        let handle = ExecutionHandle {
            context: context.clone(),
            cancel_token: cancel_token.clone(),
            completion_sender: Some(tx),
        };
        
        self.active_executions.insert(service_id, handle);
        
        // Execute with timeout and cancellation
        let config = Arc::clone(&self.config);
        let retry_policy = Arc::clone(&self.retry_policy);
        let active_executions = Arc::clone(&self.active_executions);
        let execution_history = Arc::clone(&self.execution_history);
        
        let execution_task = tokio::spawn(async move {
            let result = tokio::select! {
                result = Self::execute_with_retry(
                    context.clone(),
                    config.clone(),
                    retry_policy.clone()
                ) => result,
                _ = cancel_token.cancelled() => {
                    Err(OrchestratorError::DeploymentFailed(
                        "Deployment cancelled".to_string()
                    ))
                }
            };
            
            // Create execution result
            let duration_ms = (chrono::Utc::now() - context.started_at).num_milliseconds() as u64;
            let execution_result = match result {
                Ok(output) => ExecutionResult {
                    service_id,
                    success: true,
                    duration_ms,
                    error: None,
                    output: Some(output),
                    exit_code: Some(0),
                },
                Err(e) => ExecutionResult {
                    service_id,
                    success: false,
                    duration_ms,
                    error: Some(e.to_string()),
                    output: None,
                    exit_code: Some(1),
                },
            };
            
            // Store in history
            let mut history = execution_history.write().await;
            history.push(execution_result.clone());
            
            // Keep only last 1000 entries
            if history.len() > 1000 {
                let drain_count = history.len() - 1000;
                history.drain(0..drain_count);
            }
            
            // Remove from active executions
            active_executions.remove(&service_id);
            
            execution_result
        });
        
        // Wait with timeout
        match timeout(
            Duration::from_secs(self.config.deployment_timeout_secs),
            execution_task
        ).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => Err(OrchestratorError::DeploymentFailed(
                "Execution task failed".to_string()
            )),
            Err(_) => {
                // Timeout occurred
                if let Some((_, handle)) = self.active_executions.remove(&service_id) {
                    handle.cancel_token.cancel();
                }
                
                Err(OrchestratorError::DeploymentFailed(
                    format!("Deployment timeout after {} seconds", self.config.deployment_timeout_secs)
                ))
            }
        }
    }
    
    /// Execute deployment with retry logic
    async fn execute_with_retry(
        mut context: DeploymentContext,
        config: Arc<ExecutorConfig>,
        retry_policy: Arc<RetryPolicy>,
    ) -> OrchestratorResult<String> {
        loop {
            match Self::execute_deployment_command(&context, &config).await {
                Ok(output) => {
                    info!("Deployment successful for {}", context.service_id);
                    return Ok(output);
                }
                Err(e) => {
                    context.retry_count += 1;
                    context.last_error = Some(e.to_string());
                    
                    if !retry_policy.should_retry(context.retry_count) {
                        error!("Deployment failed after {} retries: {}", context.retry_count, e);
                        return Err(e);
                    }
                    
                    let delay = retry_policy.get_delay(context.retry_count);
                    warn!("Deployment attempt {} failed, retrying in {:?}: {}", 
                          context.retry_count, delay, e);
                    
                    sleep(delay).await;
                }
            }
        }
    }
    
    /// Execute the actual deployment command
    async fn execute_deployment_command(
        context: &DeploymentContext,
        config: &ExecutorConfig,
    ) -> OrchestratorResult<String> {
        debug!("Executing deployment for service {}", context.service_id);
        
        // Simulate deployment command
        // In production, this would execute actual deployment scripts
        let output = Command::new("echo")
            .arg(format!("Deploying service {} version {}", 
                        context.service_name, context.version))
            .output()
            .await
            .map_err(|e| OrchestratorError::DeploymentFailed(
                format!("Command execution failed: {}", e)
            ))?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(OrchestratorError::DeploymentFailed(
                format!("Command failed: {}", stderr)
            ));
        }
        
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        
        // Simulate some work
        sleep(Duration::from_millis(100)).await;
        
        Ok(stdout)
    }
    
    /// Stop a service
    #[instrument(skip(self))]
    pub async fn stop_service(&self, service_id: Uuid) -> OrchestratorResult<()> {
        // Cancel any active deployment
        if let Some((_, handle)) = self.active_executions.remove(&service_id) {
            handle.cancel_token.cancel();
        }
        
        // Execute stop command with timeout
        let stop_future = async {
            debug!("Stopping service {}", service_id);
            
            // Simulate stop command
            let output = Command::new("echo")
                .arg(format!("Stopping service {}", service_id))
                .output()
                .await?;
            
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(OrchestratorError::DeploymentFailed(
                    format!("Stop command failed: {}", stderr)
                ));
            }
            
            Ok(())
        };
        
        timeout(
            Duration::from_secs(self.config.stop_timeout_secs),
            stop_future
        ).await
        .map_err(|_| OrchestratorError::DeploymentFailed(
            format!("Stop timeout after {} seconds", self.config.stop_timeout_secs)
        ))?
    }
    
    /// Check service health
    pub async fn check_health(&self, service_id: Uuid) -> OrchestratorResult<HealthStatus> {
        let check_future = async {
            debug!("Checking health for service {}", service_id);
            
            let start = std::time::Instant::now();
            
            // Simulate health check
            let output = Command::new("echo")
                .arg("OK")
                .output()
                .await?;
            
            let latency_ms = start.elapsed().as_millis() as f64;
            
            let is_healthy = output.status.success();
            
            Ok(HealthStatus {
                is_healthy,
                last_check: chrono::Utc::now(),
                consecutive_failures: if is_healthy { 0 } else { 1 },
                latency_ms,
                error_rate: 0.0,
            })
        };
        
        timeout(
            Duration::from_secs(self.config.health_check_timeout_secs),
            check_future
        ).await
        .map_err(|_| OrchestratorError::HealthCheckFailed(
            format!("Health check timeout after {} seconds", self.config.health_check_timeout_secs)
        ))?
    }
    
    /// Get execution history
    pub async fn get_history(&self) -> Vec<ExecutionResult> {
        self.execution_history.read().await.clone()
    }
    
    /// Get active executions
    pub async fn get_active_executions(&self) -> Vec<Uuid> {
        self.active_executions
            .iter()
            .map(|entry| *entry.key())
            .collect()
    }
    
    /// Cancel an execution
    pub async fn cancel_execution(&self, service_id: Uuid) -> OrchestratorResult<()> {
        if let Some((_, handle)) = self.active_executions.remove(&service_id) {
            handle.cancel_token.cancel();
            Ok(())
        } else {
            Err(OrchestratorError::ServiceNotFound(service_id.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_executor_creation() {
        let config = ExecutorConfig::default();
        let executor = Executor::new(config);
        
        let history = executor.get_history().await;
        assert!(history.is_empty());
        
        let active = executor.get_active_executions().await;
        assert!(active.is_empty());
    }
    
    #[tokio::test]
    async fn test_deployment_execution() {
        let config = ExecutorConfig {
            deployment_timeout_secs: 5,
            ..Default::default()
        };
        let executor = Executor::new(config);
        
        let service_id = Uuid::new_v4();
        let result = executor.execute_deployment(service_id).await.unwrap();
        
        assert!(result.success);
        assert_eq!(result.service_id, service_id);
        assert!(result.duration_ms > 0);
        assert!(result.error.is_none());
    }
    
    #[tokio::test]
    async fn test_execution_cancellation() {
        let config = ExecutorConfig::default();
        let executor = Executor::new(config);
        
        let service_id = Uuid::new_v4();
        
        // Start deployment in background
        let executor_clone = Arc::new(executor);
        let exec_handle = {
            let executor = Arc::clone(&executor_clone);
            tokio::spawn(async move {
                executor.execute_deployment(service_id).await
            })
        };
        
        // Give it time to start
        sleep(Duration::from_millis(50)).await;
        
        // Cancel it
        executor_clone.cancel_execution(service_id).await.unwrap();
        
        // Wait for result
        let result = exec_handle.await.unwrap();
        assert!(result.is_err() || !result.unwrap().success);
    }
}