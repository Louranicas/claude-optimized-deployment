//! Health monitoring for MCP servers

use crate::mcp_manager::{
    config::HealthCheckConfig,
    errors::Result,
    metrics::MetricsCollector,
    registry::ServerRegistry,
    server::{McpServer, ServerState},
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tokio::time::interval;

/// Health check result
#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    /// Server ID
    pub server_id: String,
    /// Is healthy
    pub healthy: bool,
    /// Response time
    pub response_time: Duration,
    /// Error message if unhealthy
    pub error: Option<String>,
    /// Timestamp
    pub timestamp: Instant,
}

/// Health status summary
#[derive(Debug, Clone)]
pub struct HealthStatus {
    /// Total servers
    pub total_servers: usize,
    /// Healthy servers
    pub healthy_servers: usize,
    /// Degraded servers
    pub degraded_servers: usize,
    /// Unhealthy servers
    pub unhealthy_servers: usize,
    /// Average response time
    pub avg_response_time: Duration,
    /// Last check time
    pub last_check: Instant,
}

/// Health monitor for all MCP servers
pub struct HealthMonitor {
    /// Server registry
    registry: Arc<RwLock<ServerRegistry>>,
    /// Metrics collector
    metrics: Arc<MetricsCollector>,
    /// Health check configuration
    config: HealthCheckConfig,
    /// Health check results
    results: Arc<Mutex<HashMap<String, Vec<HealthCheckResult>>>>,
    /// Running flag
    running: Arc<Mutex<bool>>,
    /// Task handle
    task_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl HealthMonitor {
    /// Create a new health monitor
    pub fn new(
        registry: Arc<RwLock<ServerRegistry>>,
        metrics: Arc<MetricsCollector>,
    ) -> Self {
        Self {
            registry,
            metrics,
            config: HealthCheckConfig {
                interval_ms: 30000,
                timeout_ms: 5000,
                unhealthy_threshold: 3,
                healthy_threshold: 2,
            },
            results: Arc::new(Mutex::new(HashMap::new())),
            running: Arc::new(Mutex::new(false)),
            task_handle: Arc::new(Mutex::new(None)),
        }
    }

    /// Configure health monitor
    pub fn with_config(mut self, config: HealthCheckConfig) -> Self {
        self.config = config;
        self
    }

    /// Start health monitoring
    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.lock().await;
        if *running {
            return Ok(());
        }
        *running = true;
        
        let monitor = self.clone_for_task();
        let handle = tokio::spawn(async move {
            monitor.run_health_checks().await;
        });
        
        *self.task_handle.lock().await = Some(handle);
        Ok(())
    }

    /// Stop health monitoring
    pub async fn stop(&self) -> Result<()> {
        *self.running.lock().await = false;
        
        if let Some(handle) = self.task_handle.lock().await.take() {
            handle.abort();
        }
        
        Ok(())
    }

    /// Get health status summary
    pub async fn status(&self) -> HealthStatus {
        let registry = self.registry.read().await;
        let servers = registry.all();
        
        let mut healthy = 0;
        let mut degraded = 0;
        let mut unhealthy = 0;
        let mut total_response_time = Duration::from_secs(0);
        let mut response_count = 0;
        
        for server in &servers {
            match server.state().await {
                ServerState::Healthy => healthy += 1,
                ServerState::Degraded => degraded += 1,
                ServerState::Unhealthy | ServerState::Stopped => unhealthy += 1,
                _ => {}
            }
            
            // Get latest health check result
            if let Some(results) = self.results.lock().await.get(server.id()) {
                if let Some(latest) = results.last() {
                    if latest.healthy {
                        total_response_time += latest.response_time;
                        response_count += 1;
                    }
                }
            }
        }
        
        let avg_response_time = if response_count > 0 {
            Duration::from_millis(total_response_time.as_millis() as u64 / response_count as u64)
        } else {
            Duration::from_secs(0)
        };
        
        HealthStatus {
            total_servers: servers.len(),
            healthy_servers: healthy,
            degraded_servers: degraded,
            unhealthy_servers: unhealthy,
            avg_response_time,
            last_check: Instant::now(),
        }
    }

    /// Get health history for a server
    pub async fn history(&self, server_id: &str) -> Vec<HealthCheckResult> {
        self.results.lock().await
            .get(server_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Perform immediate health check for a server
    pub async fn check_server(&self, server: &Arc<McpServer>) -> Result<HealthCheckResult> {
        let start = Instant::now();
        
        let result = match tokio::time::timeout(
            Duration::from_millis(self.config.timeout_ms),
            server.health_check()
        ).await {
            Ok(Ok(healthy)) => HealthCheckResult {
                server_id: server.id().to_string(),
                healthy,
                response_time: start.elapsed(),
                error: None,
                timestamp: Instant::now(),
            },
            Ok(Err(e)) => HealthCheckResult {
                server_id: server.id().to_string(),
                healthy: false,
                response_time: start.elapsed(),
                error: Some(e.to_string()),
                timestamp: Instant::now(),
            },
            Err(_) => HealthCheckResult {
                server_id: server.id().to_string(),
                healthy: false,
                response_time: Duration::from_millis(self.config.timeout_ms),
                error: Some("Health check timed out".to_string()),
                timestamp: Instant::now(),
            },
        };
        
        // Store result
        let mut results = self.results.lock().await;
        let history = results.entry(server.id().to_string()).or_insert_with(Vec::new);
        history.push(result.clone());
        
        // Keep only recent history (last 100 checks)
        if history.len() > 100 {
            history.drain(0..history.len() - 100);
        }
        
        // Update server state based on failure threshold
        if !result.healthy {
            let recent_failures = history.iter()
                .rev()
                .take(self.config.unhealthy_threshold as usize)
                .filter(|r| !r.healthy)
                .count();
            
            if recent_failures >= self.config.unhealthy_threshold as usize {
                server.set_state(ServerState::Unhealthy).await;
            }
        }
        
        // Record metrics
        self.metrics.record_health_check(
            server.id(),
            result.healthy,
            result.response_time,
        ).await;
        
        Ok(result)
    }

    /// Run continuous health checks
    async fn run_health_checks(&self) {
        let mut check_interval = interval(Duration::from_millis(self.config.interval_ms));
        
        while *self.running.lock().await {
            check_interval.tick().await;
            
            let registry = self.registry.read().await;
            let servers = registry.all();
            drop(registry);
            
            for server in servers {
                if !*self.running.lock().await {
                    break;
                }
                
                // Skip servers in maintenance or stopped state
                match server.state().await {
                    ServerState::Maintenance | ServerState::Stopped => continue,
                    _ => {}
                }
                
                // Perform health check
                let _ = self.check_server(&server).await;
                
                // TODO: Future enhancement - adaptive health check intervals
            }
        }
    }


    /// Clone monitor for task
    fn clone_for_task(&self) -> Self {
        Self {
            registry: self.registry.clone(),
            metrics: self.metrics.clone(),
            config: self.config.clone(),
            results: self.results.clone(),
            running: self.running.clone(),
            task_handle: self.task_handle.clone(),
        }
    }
}

/// Health aggregator for distributed deployments
pub struct HealthAggregator {
    /// Health monitors by region/zone
    monitors: HashMap<String, Arc<HealthMonitor>>,
}

impl HealthAggregator {
    /// Create a new health aggregator
    pub fn new() -> Self {
        Self {
            monitors: HashMap::new(),
        }
    }

    /// Add a health monitor
    pub fn add_monitor(&mut self, region: String, monitor: Arc<HealthMonitor>) {
        self.monitors.insert(region, monitor);
    }

    /// Get global health status
    pub async fn global_status(&self) -> HashMap<String, HealthStatus> {
        let mut status = HashMap::new();
        
        for (region, monitor) in &self.monitors {
            status.insert(region.clone(), monitor.status().await);
        }
        
        status
    }

    /// Check if system is healthy globally
    pub async fn is_healthy(&self) -> bool {
        for monitor in self.monitors.values() {
            let status = monitor.status().await;
            if status.unhealthy_servers > 0 {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_monitor_creation() {
        let registry = Arc::new(RwLock::new(ServerRegistry::new()));
        let metrics = Arc::new(MetricsCollector::new());
        let monitor = HealthMonitor::new(registry, metrics);
        
        assert_eq!(monitor.config.interval_ms, 30000);
        assert_eq!(monitor.config.unhealthy_threshold, 3);
    }

    #[tokio::test]
    async fn test_health_status() {
        let registry = Arc::new(RwLock::new(ServerRegistry::new()));
        let metrics = Arc::new(MetricsCollector::new());
        let monitor = HealthMonitor::new(registry.clone(), metrics);
        
        let status = monitor.status().await;
        assert_eq!(status.total_servers, 0);
        assert_eq!(status.healthy_servers, 0);
        assert_eq!(status.unhealthy_servers, 0);
    }

    #[tokio::test]
    async fn test_health_aggregator() {
        let mut aggregator = HealthAggregator::new();
        
        let registry1 = Arc::new(RwLock::new(ServerRegistry::new()));
        let metrics1 = Arc::new(MetricsCollector::new());
        let monitor1 = Arc::new(HealthMonitor::new(registry1, metrics1));
        
        aggregator.add_monitor("us-east".to_string(), monitor1);
        
        let global_status = aggregator.global_status().await;
        assert!(global_status.contains_key("us-east"));
        assert!(aggregator.is_healthy().await);
    }
}