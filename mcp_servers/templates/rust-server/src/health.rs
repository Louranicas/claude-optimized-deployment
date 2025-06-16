/*!
 * Health Monitoring System for Rust MCP Server
 */

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tokio::time;
use tracing::{debug, error};

/// Health status enumeration
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Individual health check definition
pub struct HealthCheck {
    pub name: String,
    pub description: String,
    pub check_fn: Box<dyn Fn() -> Pin<Box<dyn Future<Output = Result<(HealthStatus, String)>> + Send>> + Send + Sync>,
    pub interval: Duration,
}

/// Health check result
#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    pub name: String,
    pub status: HealthStatus,
    pub message: String,
    pub last_checked: chrono::DateTime<chrono::Utc>,
    pub duration_ms: u64,
}

/// Overall health status
#[derive(Debug, Clone)]
pub struct OverallHealthStatus {
    pub overall: HealthStatus,
    pub checks: Vec<HealthCheckResult>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Health monitoring system
pub struct HealthMonitor {
    checks: Arc<RwLock<HashMap<String, HealthCheck>>>,
    results: Arc<RwLock<HashMap<String, HealthCheckResult>>>,
    is_running: Arc<Mutex<bool>>,
}

impl HealthMonitor {
    /// Create a new health monitor
    pub fn new() -> Self {
        Self {
            checks: Arc::new(RwLock::new(HashMap::new())),
            results: Arc::new(RwLock::new(HashMap::new())),
            is_running: Arc::new(Mutex::new(false)),
        }
    }
    
    /// Add a health check
    pub async fn add_check(&self, check: HealthCheck) {
        let name = check.name.clone();
        
        // Initialize with unknown status
        {
            let mut results = self.results.write().await;
            results.insert(name.clone(), HealthCheckResult {
                name: name.clone(),
                status: HealthStatus::Unhealthy,
                message: "Not yet checked".to_string(),
                last_checked: chrono::Utc::now(),
                duration_ms: 0,
            });
        }
        
        // Add the check
        {
            let mut checks = self.checks.write().await;
            checks.insert(name, check);
        }
    }
    
    /// Start health monitoring
    pub async fn start(&self) -> Result<()> {
        {
            let mut running = self.is_running.lock().await;
            *running = true;
        }
        
        // Start monitoring tasks for each check
        let checks = self.checks.read().await;
        for (name, check) in checks.iter() {
            self.start_check_task(name.clone(), check.interval).await;
        }
        
        debug!("Health monitoring started with {} checks", checks.len());
        Ok(())
    }
    
    /// Stop health monitoring
    pub async fn stop(&self) {
        let mut running = self.is_running.lock().await;
        *running = false;
        debug!("Health monitoring stopped");
    }
    
    /// Start a monitoring task for a specific check
    async fn start_check_task(&self, check_name: String, interval: Duration) {
        let checks = Arc::clone(&self.checks);
        let results = Arc::clone(&self.results);
        let is_running = Arc::clone(&self.is_running);
        
        tokio::spawn(async move {
            let mut interval_timer = time::interval(interval);
            
            loop {
                interval_timer.tick().await;
                
                // Check if monitoring is still running
                {
                    let running = is_running.lock().await;
                    if !*running {
                        break;
                    }
                }
                
                // Execute the health check
                let check_result = {
                    let checks_guard = checks.read().await;
                    if let Some(check) = checks_guard.get(&check_name) {
                        let start_time = std::time::Instant::now();
                        
                        match (check.check_fn)().await {
                            Ok((status, message)) => {
                                let duration = start_time.elapsed();
                                Some(HealthCheckResult {
                                    name: check_name.clone(),
                                    status,
                                    message,
                                    last_checked: chrono::Utc::now(),
                                    duration_ms: duration.as_millis() as u64,
                                })
                            }
                            Err(e) => {
                                let duration = start_time.elapsed();
                                error!("Health check '{}' failed: {}", check_name, e);
                                Some(HealthCheckResult {
                                    name: check_name.clone(),
                                    status: HealthStatus::Unhealthy,
                                    message: format!("Check failed: {}", e),
                                    last_checked: chrono::Utc::now(),
                                    duration_ms: duration.as_millis() as u64,
                                })
                            }
                        }
                    } else {
                        None
                    }
                };
                
                // Store the result
                if let Some(result) = check_result {
                    let mut results_guard = results.write().await;
                    results_guard.insert(check_name.clone(), result);
                }
            }
        });
    }
    
    /// Get current health status
    pub async fn get_status(&self) -> OverallHealthStatus {
        let results = self.results.read().await;
        let check_results: Vec<HealthCheckResult> = results.values().cloned().collect();
        
        // Determine overall status
        let overall = if check_results.iter().any(|r| r.status == HealthStatus::Unhealthy) {
            HealthStatus::Unhealthy
        } else if check_results.iter().any(|r| r.status == HealthStatus::Degraded) {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };
        
        OverallHealthStatus {
            overall,
            checks: check_results,
            timestamp: chrono::Utc::now(),
        }
    }
    
    /// Get status as JSON
    pub async fn get_status_json(&self) -> Value {
        let status = self.get_status().await;
        
        json!({
            "status": match status.overall {
                HealthStatus::Healthy => "healthy",
                HealthStatus::Degraded => "degraded",
                HealthStatus::Unhealthy => "unhealthy"
            },
            "timestamp": status.timestamp.to_rfc3339(),
            "checks": status.checks.iter().map(|check| {
                json!({
                    "name": check.name,
                    "status": match check.status {
                        HealthStatus::Healthy => "pass",
                        HealthStatus::Degraded => "warn",
                        HealthStatus::Unhealthy => "fail"
                    },
                    "message": check.message,
                    "last_checked": check.last_checked.to_rfc3339(),
                    "duration_ms": check.duration_ms
                })
            }).collect::<Vec<_>>()
        })
    }
    
    /// Remove a health check
    pub async fn remove_check(&self, name: &str) {
        {
            let mut checks = self.checks.write().await;
            checks.remove(name);
        }
        
        {
            let mut results = self.results.write().await;
            results.remove(name);
        }
    }
    
    /// List all check names
    pub async fn list_checks(&self) -> Vec<String> {
        let checks = self.checks.read().await;
        checks.keys().cloned().collect()
    }
}

impl Default for HealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}