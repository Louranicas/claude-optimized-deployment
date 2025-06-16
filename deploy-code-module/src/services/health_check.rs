use anyhow::{Result, Context};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::{info, debug, warn, error, instrument};
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use reqwest::Client;

use super::{ServiceRegistry, HealthStatus, HealthCheckConfig};

#[derive(Debug, Clone)]
pub struct HealthChecker {
    registry: Arc<ServiceRegistry>,
    check_tasks: Arc<DashMap<String, JoinHandle<()>>>,
    health_client: Arc<Client>,
    check_results: Arc<DashMap<String, HealthCheckResult>>,
    config: Arc<RwLock<HealthCheckerConfig>>,
}

#[derive(Debug, Clone)]
struct HealthCheckerConfig {
    default_interval: Duration,
    default_timeout: Duration,
    max_retries: u32,
    enable_auto_recovery: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    pub service: String,
    pub status: HealthStatus,
    #[serde(skip, default = "Instant::now")]
    pub last_check: Instant,
    pub consecutive_failures: u32,
    pub response_time_ms: Option<u64>,
    pub error_message: Option<String>,
    pub details: HealthCheckDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckDetails {
    pub check_type: HealthCheckType,
    pub endpoint: Option<String>,
    pub status_code: Option<u16>,
    pub additional_info: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HealthCheckType {
    Http,
    Tcp,
    Command,
    Process,
}

impl Default for HealthCheckerConfig {
    fn default() -> Self {
        Self {
            default_interval: Duration::from_secs(30),
            default_timeout: Duration::from_secs(10),
            max_retries: 3,
            enable_auto_recovery: true,
        }
    }
}

impl HealthChecker {
    pub fn new(registry: Arc<ServiceRegistry>) -> Self {
        let health_client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to create HTTP client");
        
        Self {
            registry,
            check_tasks: Arc::new(DashMap::new()),
            health_client: Arc::new(health_client),
            check_results: Arc::new(DashMap::new()),
            config: Arc::new(RwLock::new(HealthCheckerConfig::default())),
        }
    }

    #[instrument(skip(self))]
    pub async fn start_monitoring(&self, service: &str) -> Result<()> {
        info!("Starting health monitoring for service: {}", service);
        
        // Check if already monitoring
        if self.check_tasks.contains_key(service) {
            warn!("Health monitoring already active for service: {}", service);
            return Ok(());
        }
        
        // Get service info
        let service_info = self.registry.get_service_info(service).await?;
        
        // Create health check configuration
        let check_config = self.create_check_config(&service_info).await?;
        
        // Start monitoring task
        let task = self.spawn_monitoring_task(service.to_string(), check_config);
        
        self.check_tasks.insert(service.to_string(), task);
        
        Ok(())
    }

    async fn create_check_config(&self, service_info: &super::ServiceInfo) -> Result<HealthCheckConfig> {
        let config = self.config.read().await;
        
        // For now, create a simple HTTP health check if port is available
        let check_config = if let Some(port) = service_info.port {
            HealthCheckConfig {
                endpoint: Some(format!("http://localhost:{}/health", port)),
                command: None,
                interval: config.default_interval,
                timeout: config.default_timeout,
                retries: config.max_retries,
                start_period: Duration::from_secs(60),
            }
        } else {
            // Process-based health check
            HealthCheckConfig {
                endpoint: None,
                command: None,
                interval: config.default_interval,
                timeout: config.default_timeout,
                retries: config.max_retries,
                start_period: Duration::from_secs(30),
            }
        };
        
        Ok(check_config)
    }

    fn spawn_monitoring_task(
        &self,
        service: String,
        check_config: HealthCheckConfig,
    ) -> JoinHandle<()> {
        let checker = self.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(check_config.interval);
            let mut consecutive_failures = 0u32;
            let start_time = Instant::now();
            
            // Wait for start period
            tokio::time::sleep(check_config.start_period).await;
            
            loop {
                interval.tick().await;
                
                let check_start = Instant::now();
                let check_result = checker.perform_health_check(&service, &check_config).await;
                let response_time_ms = check_start.elapsed().as_millis() as u64;
                
                match check_result {
                    Ok(status) => {
                        debug!("Health check for {} returned: {:?}", service, status);
                        
                        if status == HealthStatus::Healthy {
                            consecutive_failures = 0;
                        } else {
                            consecutive_failures += 1;
                        }
                        
                        // Update registry
                        if let Err(e) = checker.registry.update_health(&service, status.clone()).await {
                            error!("Failed to update health status for {}: {}", service, e);
                        }
                        
                        // Store result
                        let result = HealthCheckResult {
                            service: service.clone(),
                            status,
                            last_check: Instant::now(),
                            consecutive_failures,
                            response_time_ms: Some(response_time_ms),
                            error_message: None,
                            details: HealthCheckDetails {
                                check_type: if check_config.endpoint.is_some() {
                                    HealthCheckType::Http
                                } else {
                                    HealthCheckType::Process
                                },
                                endpoint: check_config.endpoint.clone(),
                                status_code: None,
                                additional_info: std::collections::HashMap::new(),
                            },
                        };
                        
                        checker.check_results.insert(service.clone(), result);
                    }
                    Err(e) => {
                        error!("Health check failed for {}: {}", service, e);
                        consecutive_failures += 1;
                        
                        // Update health status
                        let status = if consecutive_failures >= check_config.retries {
                            HealthStatus::Unhealthy
                        } else {
                            HealthStatus::Degraded
                        };
                        
                        if let Err(e) = checker.registry.update_health(&service, status.clone()).await {
                            error!("Failed to update health status for {}: {}", service, e);
                        }
                        
                        // Store result
                        let result = HealthCheckResult {
                            service: service.clone(),
                            status,
                            last_check: Instant::now(),
                            consecutive_failures,
                            response_time_ms: Some(response_time_ms),
                            error_message: Some(e.to_string()),
                            details: HealthCheckDetails {
                                check_type: if check_config.endpoint.is_some() {
                                    HealthCheckType::Http
                                } else {
                                    HealthCheckType::Process
                                },
                                endpoint: check_config.endpoint.clone(),
                                status_code: None,
                                additional_info: std::collections::HashMap::new(),
                            },
                        };
                        
                        checker.check_results.insert(service.clone(), result);
                        
                        // Trigger auto-recovery if enabled
                        if consecutive_failures >= check_config.retries {
                            let config = checker.config.read().await;
                            if config.enable_auto_recovery {
                                warn!("Service {} is unhealthy, triggering auto-recovery", service);
                                // TODO: Implement auto-recovery logic
                            }
                        }
                    }
                }
            }
        })
    }

    async fn perform_health_check(
        &self,
        service: &str,
        config: &HealthCheckConfig,
    ) -> Result<HealthStatus> {
        if let Some(endpoint) = &config.endpoint {
            // HTTP health check
            self.perform_http_check(endpoint, config.timeout).await
        } else if let Some(command) = &config.command {
            // Command-based health check
            self.perform_command_check(command, config.timeout).await
        } else {
            // Process-based health check
            self.perform_process_check(service).await
        }
    }

    async fn perform_http_check(&self, endpoint: &str, timeout: Duration) -> Result<HealthStatus> {
        let response = tokio::time::timeout(
            timeout,
            self.health_client.get(endpoint).send()
        ).await
            .context("Health check timeout")?
            .context("HTTP request failed")?;
        
        match response.status().as_u16() {
            200..=299 => Ok(HealthStatus::Healthy),
            503 => Ok(HealthStatus::Degraded),
            _ => Ok(HealthStatus::Unhealthy),
        }
    }

    async fn perform_command_check(&self, command: &[String], timeout: Duration) -> Result<HealthStatus> {
        if command.is_empty() {
            return Err(anyhow::anyhow!("Empty health check command"));
        }
        
        let output = tokio::time::timeout(
            timeout,
            tokio::process::Command::new(&command[0])
                .args(&command[1..])
                .output()
        ).await
            .context("Command timeout")?
            .context("Command execution failed")?;
        
        if output.status.success() {
            Ok(HealthStatus::Healthy)
        } else {
            Ok(HealthStatus::Unhealthy)
        }
    }

    async fn perform_process_check(&self, service: &str) -> Result<HealthStatus> {
        // Check if service is registered and has a PID
        let service_info = self.registry.get_service_info(service).await?;
        
        if let Some(pid) = service_info.pid {
            // Check if process is running
            if self.is_process_running(pid) {
                Ok(HealthStatus::Healthy)
            } else {
                Ok(HealthStatus::Unhealthy)
            }
        } else {
            Ok(HealthStatus::Unknown)
        }
    }

    fn is_process_running(&self, pid: u32) -> bool {
        #[cfg(unix)]
        {
            use nix::unistd::Pid;
            use nix::errno::Errno;
            
            // Check if process exists by trying to get its info
            use std::path::Path;
            Path::new(&format!("/proc/{}", pid)).exists()
        }
        
        #[cfg(not(unix))]
        {
            // On non-Unix systems, assume process is running
            // This would need platform-specific implementation
            true
        }
    }

    #[instrument(skip(self))]
    pub async fn stop_monitoring(&self, service: &str) -> Result<()> {
        info!("Stopping health monitoring for service: {}", service);
        
        if let Some((_, task)) = self.check_tasks.remove(service) {
            task.abort();
            self.check_results.remove(service);
            Ok(())
        } else {
            Err(anyhow::anyhow!("No monitoring task found for service: {}", service))
        }
    }

    pub async fn get_check_result(&self, service: &str) -> Option<HealthCheckResult> {
        self.check_results
            .get(service)
            .map(|entry| entry.value().clone())
    }

    pub async fn get_all_results(&self) -> Vec<HealthCheckResult> {
        self.check_results
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub async fn update_config(&self, new_config: HealthCheckerConfig) -> Result<()> {
        let mut config = self.config.write().await;
        *config = new_config;
        Ok(())
    }

    pub async fn force_check(&self, service: &str) -> Result<HealthStatus> {
        let service_info = self.registry.get_service_info(service).await?;
        let check_config = self.create_check_config(&service_info).await?;
        
        self.perform_health_check(service, &check_config).await
    }
}