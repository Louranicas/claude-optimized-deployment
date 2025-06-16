use anyhow::{Result, Context};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::process::Stdio;
use tokio::process::{Command, Child};
use tokio::sync::RwLock;
use tracing::{info, debug, warn, error, instrument};
use dashmap::DashMap;
use serde::{Serialize, Deserialize};

use super::{ServiceRegistry, ServiceStatus, ServiceDefinition, RestartPolicy};

#[derive(Debug, Clone)]
pub struct LifecycleManager {
    registry: Arc<ServiceRegistry>,
    processes: Arc<DashMap<String, ProcessInfo>>,
    lifecycle_state: Arc<RwLock<LifecycleState>>,
    restart_tracker: Arc<DashMap<String, RestartInfo>>,
}

#[derive(Debug)]
struct ProcessInfo {
    pid: u32,
    child: Arc<RwLock<Child>>,
    start_time: Instant,
    definition: ServiceDefinition,
}

#[derive(Debug, Clone)]
struct LifecycleState {
    total_starts: u64,
    total_stops: u64,
    total_restarts: u64,
    failed_starts: u64,
    failed_stops: u64,
}

#[derive(Debug, Clone)]
struct RestartInfo {
    count: u32,
    last_restart: Instant,
    backoff_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleEvent {
    pub service: String,
    pub event_type: LifecycleEventType,
    #[serde(skip, default = "Instant::now")]
    pub timestamp: Instant,
    pub success: bool,
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LifecycleEventType {
    Start,
    Stop,
    Restart,
    Crash,
    Recovery,
}

impl LifecycleManager {
    pub fn new(registry: Arc<ServiceRegistry>) -> Self {
        let manager = Self {
            registry,
            processes: Arc::new(DashMap::new()),
            lifecycle_state: Arc::new(RwLock::new(LifecycleState {
                total_starts: 0,
                total_stops: 0,
                total_restarts: 0,
                failed_starts: 0,
                failed_stops: 0,
            })),
            restart_tracker: Arc::new(DashMap::new()),
        };
        
        // Start crash monitor
        manager.start_crash_monitor();
        
        manager
    }

    #[instrument(skip(self, definition))]
    pub async fn start_service(
        &self,
        service: &str,
        definition: &ServiceDefinition,
    ) -> Result<()> {
        info!("Starting service: {}", service);
        
        // Update lifecycle state
        {
            let mut state = self.lifecycle_state.write().await;
            state.total_starts += 1;
        }
        
        // Check if already running
        if self.processes.contains_key(service) {
            return Err(anyhow::anyhow!("Service {} is already running", service));
        }
        
        // Update service status
        self.registry.update_status(service, ServiceStatus::Starting).await?;
        
        // Start the service
        match self.spawn_service_process(service, definition).await {
            Ok(process_info) => {
                let pid = process_info.pid;
                self.processes.insert(service.to_string(), process_info);
                
                // Update registry with PID
                self.registry.update_pid(service, pid).await?;
                self.registry.update_status(service, ServiceStatus::Running).await?;
                
                // Record lifecycle event
                self.record_event(LifecycleEvent {
                    service: service.to_string(),
                    event_type: LifecycleEventType::Start,
                    timestamp: Instant::now(),
                    success: true,
                    message: Some(format!("Started with PID {}", pid)),
                }).await;
                
                info!("Service {} started successfully with PID {}", service, pid);
                Ok(())
            }
            Err(e) => {
                error!("Failed to start service {}: {}", service, e);
                
                // Update lifecycle state
                {
                    let mut state = self.lifecycle_state.write().await;
                    state.failed_starts += 1;
                }
                
                // Update service status
                self.registry.update_status(service, ServiceStatus::Failed).await?;
                
                // Record lifecycle event
                self.record_event(LifecycleEvent {
                    service: service.to_string(),
                    event_type: LifecycleEventType::Start,
                    timestamp: Instant::now(),
                    success: false,
                    message: Some(e.to_string()),
                }).await;
                
                Err(e)
            }
        }
    }

    async fn spawn_service_process(
        &self,
        service: &str,
        definition: &ServiceDefinition,
    ) -> Result<ProcessInfo> {
        debug!("Spawning process for service: {}", service);
        
        let mut cmd = Command::new(&definition.command);
        
        // Add arguments
        cmd.args(&definition.args);
        
        // Set environment variables
        for (key, value) in &definition.env {
            cmd.env(key, value);
        }
        
        // Set working directory
        if let Some(ref working_dir) = definition.working_dir {
            cmd.current_dir(working_dir);
        }
        
        // Configure process I/O
        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());
        
        // Spawn the process
        let mut child = cmd.spawn()
            .with_context(|| format!("Failed to spawn process for {}", service))?;
        
        let pid = child.id()
            .ok_or_else(|| anyhow::anyhow!("Failed to get process ID"))?;
        
        Ok(ProcessInfo {
            pid,
            child: Arc::new(RwLock::new(child)),
            start_time: Instant::now(),
            definition: definition.clone(),
        })
    }

    #[instrument(skip(self))]
    pub async fn stop_service(&self, service: &str, timeout: Duration) -> Result<()> {
        info!("Stopping service: {} with timeout {:?}", service, timeout);
        
        // Update lifecycle state
        {
            let mut state = self.lifecycle_state.write().await;
            state.total_stops += 1;
        }
        
        // Update service status
        self.registry.update_status(service, ServiceStatus::Stopping).await?;
        
        // Get process info
        let process_info = self.processes.remove(service)
            .map(|(_, info)| info)
            .ok_or_else(|| anyhow::anyhow!("Service {} is not running", service))?;
        
        // Stop the process
        match self.stop_process(&process_info, timeout).await {
            Ok(_) => {
                self.registry.update_status(service, ServiceStatus::Stopped).await?;
                
                // Record lifecycle event
                self.record_event(LifecycleEvent {
                    service: service.to_string(),
                    event_type: LifecycleEventType::Stop,
                    timestamp: Instant::now(),
                    success: true,
                    message: None,
                }).await;
                
                info!("Service {} stopped successfully", service);
                Ok(())
            }
            Err(e) => {
                error!("Failed to stop service {}: {}", service, e);
                
                // Update lifecycle state
                {
                    let mut state = self.lifecycle_state.write().await;
                    state.failed_stops += 1;
                }
                
                // Update service status
                self.registry.update_status(service, ServiceStatus::Failed).await?;
                
                // Record lifecycle event
                self.record_event(LifecycleEvent {
                    service: service.to_string(),
                    event_type: LifecycleEventType::Stop,
                    timestamp: Instant::now(),
                    success: false,
                    message: Some(e.to_string()),
                }).await;
                
                Err(e)
            }
        }
    }

    async fn stop_process(&self, process_info: &ProcessInfo, timeout: Duration) -> Result<()> {
        let mut child = process_info.child.write().await;
        
        // Try graceful shutdown first
        #[cfg(unix)]
        {
            use nix::sys::signal::{self, Signal};
            use nix::unistd::Pid;
            
            // SECURITY FIX: Safe PID conversion with validation
            if process_info.pid > i32::MAX as u32 {
                return Err(anyhow::anyhow!("PID {} is too large for i32 conversion", process_info.pid));
            }
            
            let pid_i32 = process_info.pid as i32;
            if pid_i32 <= 0 {
                return Err(anyhow::anyhow!("Invalid PID: {}", pid_i32));
            }
            
            let pid = Pid::from_raw(pid_i32);
            signal::kill(pid, Signal::SIGTERM)
                .context("Failed to send SIGTERM")?;
        }
        
        // Wait for process to exit
        match tokio::time::timeout(timeout, child.wait()).await {
            Ok(Ok(_)) => {
                debug!("Process {} exited gracefully", process_info.pid);
                Ok(())
            }
            Ok(Err(e)) => {
                error!("Process wait error: {}", e);
                Err(anyhow::anyhow!("Process wait failed: {}", e))
            }
            Err(_) => {
                // Timeout reached, force kill
                warn!("Process {} did not exit gracefully, forcing kill", process_info.pid);
                
                child.kill().await
                    .context("Failed to kill process")?;
                
                Ok(())
            }
        }
    }

    pub async fn restart_service(&self, service: &str) -> Result<()> {
        info!("Restarting service: {}", service);
        
        // Update lifecycle state
        {
            let mut state = self.lifecycle_state.write().await;
            state.total_restarts += 1;
        }
        
        // Get process info before stopping
        let definition = self.processes
            .get(service)
            .map(|entry| entry.definition.clone())
            .ok_or_else(|| anyhow::anyhow!("Service {} is not running", service))?;
        
        // Stop the service
        self.stop_service(service, Duration::from_secs(30)).await?;
        
        // Wait for cleanup
        tokio::time::sleep(Duration::from_secs(2)).await;
        
        // Start the service again
        self.start_service(service, &definition).await?;
        
        // Update restart tracker
        self.restart_tracker.insert(
            service.to_string(),
            RestartInfo {
                count: self.get_restart_count(service) + 1,
                last_restart: Instant::now(),
                backoff_seconds: 1,
            },
        );
        
        // Record lifecycle event
        self.record_event(LifecycleEvent {
            service: service.to_string(),
            event_type: LifecycleEventType::Restart,
            timestamp: Instant::now(),
            success: true,
            message: None,
        }).await;
        
        Ok(())
    }

    fn get_restart_count(&self, service: &str) -> u32 {
        self.restart_tracker
            .get(service)
            .map(|entry| entry.count)
            .unwrap_or(0)
    }

    fn start_crash_monitor(&self) {
        let manager = self.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            
            loop {
                interval.tick().await;
                
                // Check all running processes
                let services: Vec<String> = manager.processes
                    .iter()
                    .map(|entry| entry.key().clone())
                    .collect();
                
                for service in services {
                    if let Err(e) = manager.check_process_health(&service).await {
                        error!("Process health check failed for {}: {}", service, e);
                    }
                }
            }
        });
    }

    async fn check_process_health(&self, service: &str) -> Result<()> {
        if let Some(entry) = self.processes.get(service) {
            let mut child = entry.child.write().await;
            
            // Try to get exit status without waiting
            match child.try_wait() {
                Ok(Some(status)) => {
                    // Process has exited
                    warn!("Service {} has crashed with status: {:?}", service, status);
                    drop(child);
                    drop(entry);
                    
                    // Remove from processes map
                    self.processes.remove(service);
                    
                    // Update service status
                    self.registry.update_status(service, ServiceStatus::Failed).await?;
                    
                    // Record crash event
                    self.record_event(LifecycleEvent {
                        service: service.to_string(),
                        event_type: LifecycleEventType::Crash,
                        timestamp: Instant::now(),
                        success: false,
                        message: Some(format!("Process exited with status: {:?}", status)),
                    }).await;
                    
                    // Handle restart policy
                    self.handle_crash_recovery(service).await?;
                }
                Ok(None) => {
                    // Process is still running
                    // Nothing to do
                }
                Err(e) => {
                    error!("Failed to check process status for {}: {}", service, e);
                }
            }
        }
        
        Ok(())
    }

    async fn handle_crash_recovery(&self, service: &str) -> Result<()> {
        // Get service definition from a crashed process
        // This is a simplified version - in production, we'd store this differently
        let service_info = self.registry.get_service_info(service).await?;
        
        // Check restart policy
        let should_restart = match self.get_restart_policy(service).await {
            RestartPolicy::Always => true,
            RestartPolicy::OnFailure { max_retries } => {
                let restart_count = self.get_restart_count(service);
                restart_count < max_retries
            }
            RestartPolicy::Never => false,
        };
        
        if should_restart {
            info!("Attempting to recover crashed service: {}", service);
            
            // Get backoff duration
            let backoff = self.get_restart_backoff(service);
            
            // Wait for backoff
            tokio::time::sleep(backoff).await;
            
            // Attempt restart
            // Note: We'd need to store the ServiceDefinition properly for this to work
            // This is a placeholder
            warn!("Auto-recovery not fully implemented for service: {}", service);
            
            // Record recovery event
            self.record_event(LifecycleEvent {
                service: service.to_string(),
                event_type: LifecycleEventType::Recovery,
                timestamp: Instant::now(),
                success: false,
                message: Some("Auto-recovery not implemented".to_string()),
            }).await;
        }
        
        Ok(())
    }

    async fn get_restart_policy(&self, _service: &str) -> RestartPolicy {
        // In a real implementation, this would fetch from configuration
        RestartPolicy::OnFailure { max_retries: 3 }
    }

    fn get_restart_backoff(&self, service: &str) -> Duration {
        self.restart_tracker
            .get(service)
            .map(|entry| {
                let backoff = entry.backoff_seconds.min(300); // Max 5 minutes
                Duration::from_secs(backoff)
            })
            .unwrap_or(Duration::from_secs(1))
    }

    async fn record_event(&self, event: LifecycleEvent) {
        // In a real implementation, this would persist events
        debug!("Lifecycle event: {:?}", event);
    }

    pub async fn get_lifecycle_stats(&self) -> LifecycleStats {
        let state = self.lifecycle_state.read().await;
        let running_services = self.processes.len();
        
        LifecycleStats {
            total_starts: state.total_starts,
            total_stops: state.total_stops,
            total_restarts: state.total_restarts,
            failed_starts: state.failed_starts,
            failed_stops: state.failed_stops,
            running_services,
            success_rate: if state.total_starts > 0 {
                ((state.total_starts - state.failed_starts) as f64 
                    / state.total_starts as f64) * 100.0
            } else {
                0.0
            },
        }
    }

    pub async fn get_service_uptime(&self, service: &str) -> Option<Duration> {
        self.processes
            .get(service)
            .map(|entry| entry.start_time.elapsed())
    }

    pub async fn list_running_services(&self) -> Vec<String> {
        self.processes
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleStats {
    pub total_starts: u64,
    pub total_stops: u64,
    pub total_restarts: u64,
    pub failed_starts: u64,
    pub failed_stops: u64,
    pub running_services: usize,
    pub success_rate: f64,
}