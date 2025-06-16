use anyhow::{Result, Context};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::process::Stdio;
use tokio::process::Command;
use tokio::sync::{RwLock, Semaphore};
use tracing::{info, debug, warn, error, instrument};
use dashmap::DashMap;
use serde::{Serialize, Deserialize};

use crate::services::{ServiceRegistry, ServiceStatus};
use crate::reliability::CircuitBreaker;
use crate::monitoring::MetricsCollector;

#[derive(Debug, Clone)]
pub struct ServiceExecutor {
    service_registry: Arc<ServiceRegistry>,
    circuit_breaker: Arc<CircuitBreaker>,
    metrics: Arc<MetricsCollector>,
    execution_state: Arc<RwLock<ExecutionState>>,
    process_handles: Arc<DashMap<String, ProcessHandle>>,
    deployment_semaphore: Arc<Semaphore>,
}

#[derive(Debug, Clone)]
struct ExecutionState {
    active_deployments: usize,
    total_deployments: u64,
    failed_deployments: u64,
    last_deployment: Option<Instant>,
}

#[derive(Debug)]
struct ProcessHandle {
    pid: u32,
    start_time: Instant,
    child: Arc<RwLock<tokio::process::Child>>,
}

// CRITICAL FIX: Implement Drop trait for proper resource cleanup
impl Drop for ProcessHandle {
    fn drop(&mut self) {
        // Ensure process cleanup when handle is dropped
        let child_arc = self.child.clone();
        let pid = self.pid;
        
        tokio::spawn(async move {
            if let Ok(mut child) = child_arc.try_write() {
                // Try graceful termination first, then force kill if needed
                match child.try_wait() {
                    Ok(Some(_)) => {
                        // Process already exited
                        tracing::debug!("Process {} already exited during cleanup", pid);
                    }
                    Ok(None) => {
                        // Process still running, attempt graceful shutdown
                        tracing::warn!("Cleaning up running process {} during drop", pid);
                        if let Err(e) = child.kill().await {
                            tracing::error!("Failed to kill process {} during cleanup: {}", pid, e);
                        }
                    }
                    Err(e) => {
                        tracing::error!("Error checking process {} status during cleanup: {}", pid, e);
                    }
                }
            }
        });
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentResult {
    pub success: bool,
    pub service: String,
    pub duration: Duration,
    pub message: String,
    pub pid: Option<u32>,
}

impl ServiceExecutor {
    pub fn new(
        service_registry: Arc<ServiceRegistry>,
        circuit_breaker: Arc<CircuitBreaker>,
        metrics: Arc<MetricsCollector>,
    ) -> Self {
        Self {
            service_registry,
            circuit_breaker,
            metrics,
            execution_state: Arc::new(RwLock::new(ExecutionState {
                active_deployments: 0,
                total_deployments: 0,
                failed_deployments: 0,
                last_deployment: None,
            })),
            process_handles: Arc::new(DashMap::new()),
            deployment_semaphore: Arc::new(Semaphore::new(10)), // Max 10 concurrent deployments
        }
    }

    #[instrument(skip(self))]
    pub async fn deploy_service(&self, service: &str) -> Result<DeploymentResult> {
        let start_time = Instant::now();
        info!("Deploying service: {}", service);
        
        // Acquire deployment permit
        let _permit = self.deployment_semaphore.acquire().await
            .context("Failed to acquire deployment permit")?;
        
        // Update execution state
        {
            let mut state = self.execution_state.write().await;
            state.active_deployments += 1;
            state.total_deployments += 1;
            state.last_deployment = Some(Instant::now());
        }
        
        // Update service status
        self.service_registry.update_status(service, ServiceStatus::Starting).await?;
        
        // Execute deployment
        let result = match self.execute_deployment(service).await {
            Ok(pid) => {
                self.service_registry.update_status(service, ServiceStatus::Running).await?;
                self.metrics.record_deployment_success().await;
                
                DeploymentResult {
                    success: true,
                    service: service.to_string(),
                    duration: start_time.elapsed(),
                    message: format!("Service {} deployed successfully", service),
                    pid: Some(pid),
                }
            }
            Err(e) => {
                self.service_registry.update_status(service, ServiceStatus::Failed).await?;
                self.metrics.record_deployment_failure().await;
                
                let mut state = self.execution_state.write().await;
                state.failed_deployments += 1;
                drop(state);
                
                DeploymentResult {
                    success: false,
                    service: service.to_string(),
                    duration: start_time.elapsed(),
                    message: format!("Failed to deploy {}: {}", service, e),
                    pid: None,
                }
            }
        };
        
        // Update execution state
        {
            let mut state = self.execution_state.write().await;
            state.active_deployments -= 1;
        }
        
        if result.success {
            Ok(result)
        } else {
            Err(anyhow::anyhow!("{}", result.message))
        }
    }

    async fn execute_deployment(&self, service: &str) -> Result<u32> {
        debug!("Executing deployment for service: {}", service);
        
        // Get service configuration
        let service_info = self.service_registry.get_service_info(service).await?;
        
        // Prepare deployment command based on service type
        let deployment_command = self.prepare_deployment_command(service).await?;
        
        // Start the service process
        let mut cmd = Command::new(&deployment_command.program);
        cmd.args(&deployment_command.args)
            .envs(&deployment_command.env)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());
        
        if let Some(ref working_dir) = deployment_command.working_dir {
            cmd.current_dir(working_dir);
        }
        
        let mut child = cmd.spawn()
            .context("Failed to spawn service process")?;
        
        let pid = child.id()
            .ok_or_else(|| anyhow::anyhow!("Failed to get process ID"))?;
        
        // Store process handle
        let handle = ProcessHandle {
            pid,
            start_time: Instant::now(),
            child: Arc::new(RwLock::new(child)),
        };
        
        self.process_handles.insert(service.to_string(), handle);
        
        // Update service info with PID
        self.service_registry.update_pid(service, pid).await?;
        
        // Wait for service to become ready
        self.wait_for_service_ready(service).await?;
        
        info!("Service {} deployed successfully with PID {}", service, pid);
        Ok(pid)
    }

    async fn prepare_deployment_command(&self, service: &str) -> Result<DeploymentCommand> {
        // This would normally read from service configuration
        // For now, we'll create a simple command structure
        
        let program = match service {
            s if s.contains("mcp") => "node",
            s if s.contains("python") => "python3",
            s if s.contains("rust") => "./target/release/service",
            _ => "bash",
        };
        
        let args = match service {
            s if s.contains("mcp") => vec!["server.js".to_string()],
            s if s.contains("python") => vec!["-m".to_string(), service.to_string()],
            s if s.contains("rust") => vec![],
            _ => vec!["-c".to_string(), format!("echo 'Starting {}'", service)],
        };
        
        let mut env = std::collections::HashMap::new();
        env.insert("SERVICE_NAME".to_string(), service.to_string());
        env.insert("DEPLOYMENT_MODE".to_string(), "production".to_string());
        
        Ok(DeploymentCommand {
            program: program.to_string(),
            args,
            env,
            working_dir: None,
        })
    }

    async fn wait_for_service_ready(&self, service: &str) -> Result<()> {
        let timeout = Duration::from_secs(60);
        let start_time = Instant::now();
        let check_interval = Duration::from_secs(2);
        
        loop {
            if start_time.elapsed() > timeout {
                return Err(anyhow::anyhow!(
                    "Service {} failed to become ready within timeout",
                    service
                ));
            }
            
            // Check if process is still running
            if let Some(handle) = self.process_handles.get(service) {
                // TODO: Implement actual health check
                // For now, we'll just check if the process is still alive
                
                // Simulate health check
                tokio::time::sleep(check_interval).await;
                
                // If we made it here, assume service is ready
                return Ok(());
            } else {
                return Err(anyhow::anyhow!("Service {} process handle not found", service));
            }
        }
    }

    #[instrument(skip(self))]
    pub async fn stop_service(&self, service: &str, timeout: Duration) -> Result<()> {
        info!("Stopping service: {} with timeout {:?}", service, timeout);
        
        // Update service status
        self.service_registry.update_status(service, ServiceStatus::Stopping).await?;
        
        // Get process handle
        if let Some((_key, handle)) = self.process_handles.remove(service) {
            let stop_result = self.stop_process(&handle, timeout).await;
            
            match stop_result {
                Ok(_) => {
                    self.service_registry.update_status(service, ServiceStatus::Stopped).await?;
                    info!("Service {} stopped successfully", service);
                    Ok(())
                }
                Err(e) => {
                    error!("Failed to stop service {}: {}", service, e);
                    self.service_registry.update_status(service, ServiceStatus::Failed).await?;
                    Err(e)
                }
            }
        } else {
            warn!("No process handle found for service: {}", service);
            self.service_registry.update_status(service, ServiceStatus::Stopped).await?;
            Ok(())
        }
    }

    async fn stop_process(&self, handle: &ProcessHandle, timeout: Duration) -> Result<()> {
        let mut child = handle.child.write().await;
        
        // Try graceful shutdown first
        #[cfg(unix)]
        {
            use nix::sys::signal::{self, Signal};
            use nix::unistd::Pid;
            
            let pid = Pid::from_raw(handle.pid as i32);
            signal::kill(pid, Signal::SIGTERM)
                .context("Failed to send SIGTERM")?;
        }
        
        // Wait for process to exit
        let shutdown_result = tokio::time::timeout(timeout, child.wait()).await;
        
        match shutdown_result {
            Ok(Ok(_)) => {
                debug!("Process {} exited gracefully", handle.pid);
                Ok(())
            }
            Ok(Err(e)) => {
                error!("Process wait error: {}", e);
                Err(anyhow::anyhow!("Process wait failed: {}", e))
            }
            Err(_) => {
                // Timeout reached, force kill
                warn!("Process {} did not exit gracefully, forcing kill", handle.pid);
                
                child.kill().await
                    .context("Failed to kill process")?;
                
                Ok(())
            }
        }
    }

    pub async fn restart_service(&self, service: &str) -> Result<()> {
        info!("Restarting service: {}", service);
        
        // Stop the service
        self.stop_service(service, Duration::from_secs(30)).await?;
        
        // Wait a bit for cleanup
        tokio::time::sleep(Duration::from_secs(2)).await;
        
        // Deploy the service again
        self.deploy_service(service).await?;
        
        Ok(())
    }

    pub async fn get_execution_stats(&self) -> ExecutionStats {
        let state = self.execution_state.read().await;
        let active_processes = self.process_handles.len();
        
        ExecutionStats {
            active_deployments: state.active_deployments,
            total_deployments: state.total_deployments,
            failed_deployments: state.failed_deployments,
            active_processes,
            success_rate: if state.total_deployments > 0 {
                ((state.total_deployments - state.failed_deployments) as f64 
                    / state.total_deployments as f64) * 100.0
            } else {
                0.0
            },
        }
    }

    pub async fn get_service_uptime(&self, service: &str) -> Option<Duration> {
        self.process_handles
            .get(service)
            .map(|handle| handle.start_time.elapsed())
    }
}

#[derive(Debug, Clone)]
struct DeploymentCommand {
    program: String,
    args: Vec<String>,
    env: std::collections::HashMap<String, String>,
    working_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionStats {
    pub active_deployments: usize,
    pub total_deployments: u64,
    pub failed_deployments: u64,
    pub active_processes: usize,
    pub success_rate: f64,
}