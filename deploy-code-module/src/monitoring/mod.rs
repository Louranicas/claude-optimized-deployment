use anyhow::Result;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use tracing::{info, debug};

#[derive(Debug, Clone)]
pub struct MetricsCollector {
    metrics: Arc<DashMap<String, ServiceMetrics>>,
    deployment_metrics: Arc<RwLock<DeploymentMetrics>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceMetrics {
    pub uptime: Duration,
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub request_count: u64,
    pub error_count: u64,
    #[serde(skip, default = "Instant::now")]
    pub last_updated: Instant,
}

#[derive(Debug, Clone)]
struct DeploymentMetrics {
    total_deployments: u64,
    successful_deployments: u64,
    failed_deployments: u64,
    average_deployment_time: Duration,
    last_deployment: Option<Instant>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(DashMap::new()),
            deployment_metrics: Arc::new(RwLock::new(DeploymentMetrics {
                total_deployments: 0,
                successful_deployments: 0,
                failed_deployments: 0,
                average_deployment_time: Duration::default(),
                last_deployment: None,
            })),
        }
    }
    
    pub async fn record_service_start(&self, service: &str) {
        let metrics = ServiceMetrics {
            uptime: Duration::default(),
            cpu_usage: 0.0,
            memory_usage: 0.0,
            request_count: 0,
            error_count: 0,
            last_updated: Instant::now(),
        };
        
        self.metrics.insert(service.to_string(), metrics);
        debug!("Started metrics collection for service: {}", service);
    }
    
    pub async fn update_service_metrics(
        &self,
        service: &str,
        cpu: f64,
        memory: f64,
    ) {
        if let Some(mut metrics) = self.metrics.get_mut(service) {
            let now = Instant::now();
            metrics.uptime = now.duration_since(metrics.last_updated) + metrics.uptime;
            metrics.cpu_usage = cpu;
            metrics.memory_usage = memory;
            metrics.last_updated = now;
        }
    }
    
    pub async fn record_request(&self, service: &str, success: bool) {
        if let Some(mut metrics) = self.metrics.get_mut(service) {
            metrics.request_count += 1;
            if !success {
                metrics.error_count += 1;
            }
        }
    }
    
    pub async fn get_service_metrics(&self, service: &str) -> Option<ServiceMetrics> {
        self.metrics.get(service).map(|m| m.clone())
    }
    
    pub async fn record_deployment_start(&self) {
        let mut metrics = self.deployment_metrics.write().await;
        metrics.total_deployments += 1;
        metrics.last_deployment = Some(Instant::now());
    }
    
    pub async fn record_deployment_success(&self) {
        let mut metrics = self.deployment_metrics.write().await;
        metrics.successful_deployments += 1;
        
        if let Some(start_time) = metrics.last_deployment {
            let duration = start_time.elapsed();
            
            // Update average deployment time
            let total_time = metrics.average_deployment_time.as_secs_f64() 
                * metrics.successful_deployments as f64;
            let new_average = (total_time + duration.as_secs_f64()) 
                / (metrics.successful_deployments + 1) as f64;
            
            metrics.average_deployment_time = Duration::from_secs_f64(new_average);
        }
    }
    
    pub async fn record_deployment_failure(&self) {
        let mut metrics = self.deployment_metrics.write().await;
        metrics.failed_deployments += 1;
    }
    
    pub async fn get_deployment_stats(&self) -> (u64, u64, u64, Duration) {
        let metrics = self.deployment_metrics.read().await;
        (
            metrics.total_deployments,
            metrics.successful_deployments,
            metrics.failed_deployments,
            metrics.average_deployment_time,
        )
    }
    
    pub async fn export_prometheus_metrics(&self) -> String {
        let mut output = String::new();
        
        // Service metrics
        for item in self.metrics.iter() {
            let (service, metrics) = item.pair();
            
            output.push_str(&format!(
                "service_uptime_seconds{{service=\"{}\"}} {}\n",
                service,
                metrics.uptime.as_secs()
            ));
            
            output.push_str(&format!(
                "service_cpu_usage_percent{{service=\"{}\"}} {}\n",
                service,
                metrics.cpu_usage
            ));
            
            output.push_str(&format!(
                "service_memory_usage_percent{{service=\"{}\"}} {}\n",
                service,
                metrics.memory_usage
            ));
            
            output.push_str(&format!(
                "service_request_total{{service=\"{}\"}} {}\n",
                service,
                metrics.request_count
            ));
            
            output.push_str(&format!(
                "service_error_total{{service=\"{}\"}} {}\n",
                service,
                metrics.error_count
            ));
        }
        
        // Deployment metrics
        let deployment_metrics = self.deployment_metrics.read().await;
        
        output.push_str(&format!(
            "deployments_total {}\n",
            deployment_metrics.total_deployments
        ));
        
        output.push_str(&format!(
            "deployments_successful_total {}\n",
            deployment_metrics.successful_deployments
        ));
        
        output.push_str(&format!(
            "deployments_failed_total {}\n",
            deployment_metrics.failed_deployments
        ));
        
        output.push_str(&format!(
            "deployment_duration_seconds {}\n",
            deployment_metrics.average_deployment_time.as_secs_f64()
        ));
        
        output
    }
    
    pub async fn clear_service_metrics(&self, service: &str) {
        self.metrics.remove(service);
        debug!("Cleared metrics for service: {}", service);
    }
}