//! Metrics collection for MCP servers

use crate::mcp_manager::errors::Result;
use prometheus::{
    GaugeVec, HistogramVec, HistogramOpts,
    IntCounterVec, IntGaugeVec,
    Opts, Registry,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

lazy_static::lazy_static! {
    /// Request counter
    static ref REQUEST_COUNTER: IntCounterVec = IntCounterVec::new(
        Opts::new("mcp_requests_total", "Total number of requests"),
        &["server_id", "method", "status"]
    ).unwrap();
    
    /// Response time histogram
    static ref RESPONSE_TIME: HistogramVec = HistogramVec::new(
        HistogramOpts::new("mcp_response_time_seconds", "Response time in seconds"),
        &["server_id", "method"]
    ).unwrap();
    
    /// Active connections gauge
    static ref ACTIVE_CONNECTIONS: IntGaugeVec = IntGaugeVec::new(
        Opts::new("mcp_active_connections", "Number of active connections"),
        &["server_id"]
    ).unwrap();
    
    /// Health check results
    static ref HEALTH_CHECK_RESULTS: IntCounterVec = IntCounterVec::new(
        Opts::new("mcp_health_checks_total", "Total health check results"),
        &["server_id", "result"]
    ).unwrap();
    
    /// Circuit breaker state
    static ref CIRCUIT_BREAKER_STATE: IntGaugeVec = IntGaugeVec::new(
        Opts::new("mcp_circuit_breaker_state", "Circuit breaker state (0=closed, 1=open, 2=half-open)"),
        &["server_id"]
    ).unwrap();
    
    /// Connection pool metrics
    static ref CONNECTION_POOL_SIZE: IntGaugeVec = IntGaugeVec::new(
        Opts::new("mcp_connection_pool_size", "Connection pool size"),
        &["server_id", "state"]
    ).unwrap();
    
    /// Server availability
    static ref SERVER_AVAILABILITY: GaugeVec = GaugeVec::new(
        Opts::new("mcp_server_availability", "Server availability percentage"),
        &["server_id"]
    ).unwrap();
    
    /// Error rate
    static ref ERROR_RATE: GaugeVec = GaugeVec::new(
        Opts::new("mcp_error_rate", "Error rate per minute"),
        &["server_id"]
    ).unwrap();
}

/// Metrics collector for MCP operations
pub struct MetricsCollector {
    /// Prometheus registry
    registry: Registry,
    /// Custom metrics storage
    custom_metrics: Arc<Mutex<HashMap<String, f64>>>,
    /// Running flag
    running: Arc<Mutex<bool>>,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new() -> Self {
        let registry = Registry::new();
        
        // Register metrics
        registry.register(Box::new(REQUEST_COUNTER.clone())).unwrap();
        registry.register(Box::new(RESPONSE_TIME.clone())).unwrap();
        registry.register(Box::new(ACTIVE_CONNECTIONS.clone())).unwrap();
        registry.register(Box::new(HEALTH_CHECK_RESULTS.clone())).unwrap();
        registry.register(Box::new(CIRCUIT_BREAKER_STATE.clone())).unwrap();
        registry.register(Box::new(CONNECTION_POOL_SIZE.clone())).unwrap();
        registry.register(Box::new(SERVER_AVAILABILITY.clone())).unwrap();
        registry.register(Box::new(ERROR_RATE.clone())).unwrap();
        
        Self {
            registry,
            custom_metrics: Arc::new(Mutex::new(HashMap::new())),
            running: Arc::new(Mutex::new(false)),
        }
    }

    /// Start metrics collection
    pub async fn start(&self) -> Result<()> {
        *self.running.lock().await = true;
        
        // Start background tasks for derived metrics
        self.start_availability_calculator();
        self.start_error_rate_calculator();
        
        Ok(())
    }

    /// Stop metrics collection
    pub async fn stop(&self) -> Result<()> {
        *self.running.lock().await = false;
        Ok(())
    }

    /// Record a request
    pub async fn record_request(
        &self,
        server_id: &str,
        method: &str,
        status: &str,
        duration: Duration,
    ) {
        REQUEST_COUNTER
            .with_label_values(&[server_id, method, status])
            .inc();
        
        RESPONSE_TIME
            .with_label_values(&[server_id, method])
            .observe(duration.as_secs_f64());
    }

    /// Record active connections
    pub async fn record_active_connections(&self, server_id: &str, count: i64) {
        ACTIVE_CONNECTIONS
            .with_label_values(&[server_id])
            .set(count);
    }

    /// Record health check result
    pub async fn record_health_check(
        &self,
        server_id: &str,
        healthy: bool,
        _response_time: Duration,
    ) {
        let result = if healthy { "success" } else { "failure" };
        HEALTH_CHECK_RESULTS
            .with_label_values(&[server_id, result])
            .inc();
    }

    /// Record circuit breaker state
    pub async fn record_circuit_breaker_state(&self, server_id: &str, state: CircuitBreakerState) {
        let state_value = match state {
            CircuitBreakerState::Closed => 0,
            CircuitBreakerState::Open => 1,
            CircuitBreakerState::HalfOpen => 2,
        };
        
        CIRCUIT_BREAKER_STATE
            .with_label_values(&[server_id])
            .set(state_value);
    }

    /// Record connection pool metrics
    pub async fn record_connection_pool(
        &self,
        server_id: &str,
        active: i64,
        idle: i64,
    ) {
        CONNECTION_POOL_SIZE
            .with_label_values(&[server_id, "active"])
            .set(active);
        
        CONNECTION_POOL_SIZE
            .with_label_values(&[server_id, "idle"])
            .set(idle);
    }

    /// Get Prometheus metrics
    pub fn prometheus_metrics(&self) -> Vec<prometheus::proto::MetricFamily> {
        self.registry.gather()
    }

    /// Export metrics in Prometheus format
    pub fn export_prometheus(&self) -> String {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    }

    /// Record custom metric
    pub async fn record_custom(&self, name: &str, value: f64) {
        self.custom_metrics.lock().await.insert(name.to_string(), value);
    }

    /// Get custom metric
    pub async fn get_custom(&self, name: &str) -> Option<f64> {
        self.custom_metrics.lock().await.get(name).copied()
    }
    
    /// Get all metrics as a hashmap (compatibility method)
    pub async fn get_all_metrics(&self) -> HashMap<String, f64> {
        let mut metrics = HashMap::new();
        
        // Add custom metrics
        let custom = self.custom_metrics.lock().await;
        for (name, value) in custom.iter() {
            metrics.insert(name.clone(), *value);
        }
        
        // TODO: Add prometheus metrics conversion if needed
        
        metrics
    }

    /// Start availability calculator
    fn start_availability_calculator(&self) {
        let running = self.running.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            
            while *running.lock().await {
                interval.tick().await;
                
                // Calculate availability for each server
                // This is a placeholder - in production, this would:
                // 1. Look at health check history
                // 2. Calculate uptime percentage
                // 3. Update SERVER_AVAILABILITY gauge
            }
        });
    }

    /// Start error rate calculator
    fn start_error_rate_calculator(&self) {
        let running = self.running.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            
            while *running.lock().await {
                interval.tick().await;
                
                // Calculate error rate for each server
                // This is a placeholder - in production, this would:
                // 1. Look at request counters
                // 2. Calculate errors per minute
                // 3. Update ERROR_RATE gauge
            }
        });
    }
}

/// Circuit breaker state for metrics
#[derive(Debug, Clone, Copy)]
pub enum CircuitBreakerState {
    Closed,
    Open,
    HalfOpen,
}

/// Metrics aggregator for multiple collectors
pub struct MetricsAggregator {
    collectors: Vec<Arc<MetricsCollector>>,
}

impl MetricsAggregator {
    /// Create a new metrics aggregator
    pub fn new() -> Self {
        Self {
            collectors: Vec::new(),
        }
    }

    /// Add a metrics collector
    pub fn add_collector(&mut self, collector: Arc<MetricsCollector>) {
        self.collectors.push(collector);
    }

    /// Get aggregated Prometheus metrics
    pub fn aggregate_prometheus(&self) -> String {
        let mut all_metrics = Vec::new();
        
        for collector in &self.collectors {
            all_metrics.extend(collector.prometheus_metrics());
        }
        
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let mut buffer = Vec::new();
        encoder.encode(&all_metrics, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    }
}

/// Metrics dashboard data
#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricsDashboard {
    /// Total requests
    pub total_requests: u64,
    /// Average response time
    pub avg_response_time: f64,
    /// Error rate
    pub error_rate: f64,
    /// Server availability
    pub availability: f64,
    /// Active connections
    pub active_connections: u64,
    /// Health status
    pub health_status: HashMap<String, bool>,
}

impl MetricsCollector {
    /// Generate dashboard data
    pub async fn dashboard_data(&self) -> MetricsDashboard {
        // This is a placeholder - in production, this would aggregate
        // metrics from Prometheus and return formatted dashboard data
        
        MetricsDashboard {
            total_requests: 0,
            avg_response_time: 0.0,
            error_rate: 0.0,
            availability: 100.0,
            active_connections: 0,
            health_status: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_collector_creation() {
        let collector = MetricsCollector::new();
        assert!(collector.start().await.is_ok());
        assert!(collector.stop().await.is_ok());
    }

    #[tokio::test]
    async fn test_record_request() {
        let collector = MetricsCollector::new();
        
        collector.record_request(
            "server-1",
            "execute",
            "success",
            Duration::from_millis(100),
        ).await;
        
        // Verify metric was recorded
        let metrics = collector.export_prometheus();
        assert!(metrics.contains("mcp_requests_total"));
    }

    #[tokio::test]
    async fn test_custom_metrics() {
        let collector = MetricsCollector::new();
        
        collector.record_custom("test_metric", 42.0).await;
        let value = collector.get_custom("test_metric").await;
        assert_eq!(value, Some(42.0));
    }

    #[tokio::test]
    async fn test_metrics_aggregator() {
        let mut aggregator = MetricsAggregator::new();
        
        let collector1 = Arc::new(MetricsCollector::new());
        let collector2 = Arc::new(MetricsCollector::new());
        
        aggregator.add_collector(collector1);
        aggregator.add_collector(collector2);
        
        let aggregated = aggregator.aggregate_prometheus();
        assert!(!aggregated.is_empty());
    }
}