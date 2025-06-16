//! Performance Monitoring Module
//! 
//! Real-time performance metrics with minimal overhead

use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::VecDeque;
use dashmap::DashMap;
use parking_lot::RwLock;
use prometheus::{Counter, Gauge, Histogram, HistogramOpts, Registry};
use metrics::{describe_counter, describe_gauge, describe_histogram, Unit};
use tracing::{debug, info, instrument, warn};

use crate::error::{CoreError, Result};

/// Performance metric types
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MetricType {
    /// Counter metric
    Counter,
    /// Gauge metric
    Gauge,
    /// Histogram metric
    Histogram,
    /// Summary metric
    Summary,
}

/// Metric data point
#[derive(Debug, Clone)]
pub struct DataPoint {
    /// Timestamp
    pub timestamp: Instant,
    /// Value
    pub value: f64,
    /// Labels
    pub labels: Option<Vec<(String, String)>>,
}

/// Time series data
#[derive(Debug)]
pub struct TimeSeries {
    /// Metric name
    name: String,
    /// Data points
    points: RwLock<VecDeque<DataPoint>>,
    /// Maximum retention
    max_retention: Duration,
    /// Maximum points
    max_points: usize,
}

impl TimeSeries {
    fn new(name: String, max_retention: Duration, max_points: usize) -> Self {
        Self {
            name,
            points: RwLock::new(VecDeque::with_capacity(max_points)),
            max_retention,
            max_points,
        }
    }
    
    fn add_point(&self, value: f64, labels: Option<Vec<(String, String)>>) {
        let mut points = self.points.write();
        let now = Instant::now();
        
        // Remove old points
        let cutoff = now - self.max_retention;
        points.retain(|p| p.timestamp > cutoff);
        
        // Add new point
        if points.len() >= self.max_points {
            points.pop_front();
        }
        
        points.push_back(DataPoint {
            timestamp: now,
            value,
            labels,
        });
    }
    
    fn get_points(&self, duration: Duration) -> Vec<DataPoint> {
        let points = self.points.read();
        let cutoff = Instant::now() - duration;
        
        points.iter()
            .filter(|p| p.timestamp > cutoff)
            .cloned()
            .collect()
    }
}

/// Performance monitor configuration
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    /// Enable Prometheus metrics
    pub enable_prometheus: bool,
    /// Prometheus port
    pub prometheus_port: u16,
    /// Metrics retention period
    pub retention_period: Duration,
    /// Maximum points per metric
    pub max_points_per_metric: usize,
    /// Collection interval
    pub collection_interval: Duration,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            enable_prometheus: true,
            prometheus_port: 9090,
            retention_period: Duration::from_secs(3600), // 1 hour
            max_points_per_metric: 10000,
            collection_interval: Duration::from_secs(1),
        }
    }
}

/// Performance monitor
pub struct PerformanceMonitor {
    /// Configuration
    config: MonitorConfig,
    /// Prometheus registry
    registry: Option<Registry>,
    /// Time series data
    time_series: Arc<DashMap<String, Arc<TimeSeries>>>,
    /// Prometheus metrics
    prom_metrics: Arc<DashMap<String, PrometheusMetric>>,
    /// System metrics
    system_metrics: Arc<SystemMetrics>,
    /// Shutdown signal
    shutdown: Arc<tokio::sync::Notify>,
}

/// Prometheus metric wrapper
enum PrometheusMetric {
    Counter(Counter),
    Gauge(Gauge),
    Histogram(Histogram),
}

/// System metrics
struct SystemMetrics {
    /// CPU usage percentage
    cpu_usage: Arc<RwLock<f64>>,
    /// Memory usage in bytes
    memory_usage: Arc<RwLock<u64>>,
    /// Thread count
    thread_count: Arc<RwLock<usize>>,
    /// File descriptor count
    fd_count: Arc<RwLock<usize>>,
}

impl Default for SystemMetrics {
    fn default() -> Self {
        Self {
            cpu_usage: Arc::new(RwLock::new(0.0)),
            memory_usage: Arc::new(RwLock::new(0)),
            thread_count: Arc::new(RwLock::new(0)),
            fd_count: Arc::new(RwLock::new(0)),
        }
    }
}

impl PerformanceMonitor {
    /// Create a new performance monitor
    pub fn new() -> Result<Self> {
        Self::with_config(MonitorConfig::default())
    }
    
    /// Create with custom configuration
    pub fn with_config(config: MonitorConfig) -> Result<Self> {
        let registry = if config.enable_prometheus {
            Some(Registry::new())
        } else {
            None
        };
        
        Ok(Self {
            config,
            registry,
            time_series: Arc::new(DashMap::new()),
            prom_metrics: Arc::new(DashMap::new()),
            system_metrics: Arc::new(SystemMetrics::default()),
            shutdown: Arc::new(tokio::sync::Notify::new()),
        })
    }
    
    /// Start the performance monitor
    #[instrument(skip_all)]
    pub async fn start(&self) -> Result<()> {
        info!("Starting performance monitor");
        
        // Initialize system metrics
        self.init_system_metrics()?;
        
        // Start metrics collection
        self.start_collection_task().await?;
        
        // Start Prometheus endpoint if enabled
        if self.config.enable_prometheus {
            self.start_prometheus_endpoint().await?;
        }
        
        Ok(())
    }
    
    /// Initialize system metrics
    fn init_system_metrics(&self) -> Result<()> {
        // Register core metrics
        self.register_gauge("mcp_core_cpu_usage", "CPU usage percentage")?;
        self.register_gauge("mcp_core_memory_bytes", "Memory usage in bytes")?;
        self.register_gauge("mcp_core_threads", "Number of threads")?;
        self.register_gauge("mcp_core_fd_count", "File descriptor count")?;
        
        // Register performance metrics
        self.register_histogram("mcp_message_latency_us", "Message processing latency in microseconds")?;
        self.register_counter("mcp_messages_total", "Total messages processed")?;
        self.register_counter("mcp_errors_total", "Total errors")?;
        self.register_gauge("mcp_queue_depth", "Current queue depth")?;
        
        Ok(())
    }
    
    /// Register a counter metric
    #[instrument(skip_all, fields(name = %name))]
    pub fn register_counter(&self, name: &str, help: &str) -> Result<()> {
        // describe_counter!(name, help); // Disabled due to lifetime issues
        
        if let Some(ref registry) = self.registry {
            let counter = Counter::new(name, help)
                .map_err(|e| CoreError::monitoring(format!("Failed to create counter: {}", e)))?;
            
            registry.register(Box::new(counter.clone()))
                .map_err(|e| CoreError::monitoring(format!("Failed to register counter: {}", e)))?;
            
            self.prom_metrics.insert(name.to_string(), PrometheusMetric::Counter(counter));
        }
        
        // Create time series
        let ts = Arc::new(TimeSeries::new(
            name.to_string(),
            self.config.retention_period,
            self.config.max_points_per_metric,
        ));
        self.time_series.insert(name.to_string(), ts);
        
        Ok(())
    }
    
    /// Register a gauge metric
    #[instrument(skip_all, fields(name = %name))]
    pub fn register_gauge(&self, name: &str, help: &str) -> Result<()> {
        // describe_gauge!(name, help); // Disabled due to lifetime issues
        
        if let Some(ref registry) = self.registry {
            let gauge = Gauge::new(name, help)
                .map_err(|e| CoreError::monitoring(format!("Failed to create gauge: {}", e)))?;
            
            registry.register(Box::new(gauge.clone()))
                .map_err(|e| CoreError::monitoring(format!("Failed to register gauge: {}", e)))?;
            
            self.prom_metrics.insert(name.to_string(), PrometheusMetric::Gauge(gauge));
        }
        
        // Create time series
        let ts = Arc::new(TimeSeries::new(
            name.to_string(),
            self.config.retention_period,
            self.config.max_points_per_metric,
        ));
        self.time_series.insert(name.to_string(), ts);
        
        Ok(())
    }
    
    /// Register a histogram metric
    #[instrument(skip_all, fields(name = %name))]
    pub fn register_histogram(&self, name: &str, help: &str) -> Result<()> {
        // describe_histogram!(name, help); // Disabled due to lifetime issues
        
        if let Some(ref registry) = self.registry {
            let opts = HistogramOpts::new(name, help);
            let histogram = Histogram::with_opts(opts)
                .map_err(|e| CoreError::monitoring(format!("Failed to create histogram: {}", e)))?;
            
            registry.register(Box::new(histogram.clone()))
                .map_err(|e| CoreError::monitoring(format!("Failed to register histogram: {}", e)))?;
            
            self.prom_metrics.insert(name.to_string(), PrometheusMetric::Histogram(histogram));
        }
        
        // Create time series
        let ts = Arc::new(TimeSeries::new(
            name.to_string(),
            self.config.retention_period,
            self.config.max_points_per_metric,
        ));
        self.time_series.insert(name.to_string(), ts);
        
        Ok(())
    }
    
    /// Record a counter increment
    pub fn increment_counter(&self, name: &str, value: f64) {
        if let Some(metric) = self.prom_metrics.get(name) {
            if let PrometheusMetric::Counter(counter) = metric.value() {
                counter.inc_by(value);
            }
        }
        
        if let Some(ts) = self.time_series.get(name) {
            ts.add_point(value, None);
        }
        
        // metrics::counter!(name).increment(value as u64); // Disabled due to lifetime issues
    }
    
    /// Set a gauge value
    pub fn set_gauge(&self, name: &str, value: f64) {
        if let Some(metric) = self.prom_metrics.get(name) {
            if let PrometheusMetric::Gauge(gauge) = metric.value() {
                gauge.set(value);
            }
        }
        
        if let Some(ts) = self.time_series.get(name) {
            ts.add_point(value, None);
        }
        
        // metrics::gauge!(name).set(value); // Disabled due to lifetime issues
    }
    
    /// Record a histogram observation
    pub fn observe_histogram(&self, name: &str, value: f64) {
        if let Some(metric) = self.prom_metrics.get(name) {
            if let PrometheusMetric::Histogram(histogram) = metric.value() {
                histogram.observe(value);
            }
        }
        
        if let Some(ts) = self.time_series.get(name) {
            ts.add_point(value, None);
        }
        
        // metrics::histogram!(name).record(value); // Disabled due to lifetime issues
    }
    
    /// Start metrics collection task
    async fn start_collection_task(&self) -> Result<()> {
        let system_metrics = self.system_metrics.clone();
        let shutdown = self.shutdown.clone();
        let interval = self.config.collection_interval;
        let monitor = self.clone_for_task();
        
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(interval);
            
            loop {
                tokio::select! {
                    _ = timer.tick() => {
                        // Collect system metrics
                        if let Ok(cpu) = Self::get_cpu_usage() {
                            *system_metrics.cpu_usage.write() = cpu;
                            monitor.set_gauge("mcp_core_cpu_usage", cpu);
                        }
                        
                        if let Ok(mem) = Self::get_memory_usage() {
                            *system_metrics.memory_usage.write() = mem;
                            monitor.set_gauge("mcp_core_memory_bytes", mem as f64);
                        }
                        
                        if let Ok(threads) = Self::get_thread_count() {
                            *system_metrics.thread_count.write() = threads;
                            monitor.set_gauge("mcp_core_threads", threads as f64);
                        }
                    }
                    _ = shutdown.notified() => {
                        info!("Metrics collection task shutting down");
                        break;
                    }
                }
            }
        });
        
        Ok(())
    }
    
    /// Clone monitor for use in tasks
    fn clone_for_task(&self) -> Self {
        Self {
            config: self.config.clone(),
            registry: self.registry.clone(),
            time_series: self.time_series.clone(),
            prom_metrics: self.prom_metrics.clone(),
            system_metrics: self.system_metrics.clone(),
            shutdown: self.shutdown.clone(),
        }
    }
    
    /// Get CPU usage percentage
    fn get_cpu_usage() -> Result<f64> {
        // Simplified CPU usage calculation
        // In production, use proper system metrics libraries
        Ok(0.0)
    }
    
    /// Get memory usage in bytes
    fn get_memory_usage() -> Result<u64> {
        // Simplified memory usage calculation
        // In production, use proper system metrics libraries
        Ok(0)
    }
    
    /// Get thread count
    fn get_thread_count() -> Result<usize> {
        // Simplified thread count
        // In production, use proper system metrics libraries
        Ok(std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1))
    }
    
    /// Start Prometheus endpoint
    async fn start_prometheus_endpoint(&self) -> Result<()> {
        // TODO: Implement Prometheus HTTP endpoint
        info!("Prometheus endpoint would start on port {}", self.config.prometheus_port);
        Ok(())
    }
    
    /// Get time series data for a metric
    pub fn get_time_series(&self, name: &str, duration: Duration) -> Option<Vec<DataPoint>> {
        self.time_series.get(name).map(|ts| ts.get_points(duration))
    }
    
    /// Shutdown the monitor
    #[instrument(skip_all)]
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down performance monitor");
        self.shutdown.notify_waiters();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_monitor_creation() {
        let monitor = PerformanceMonitor::new();
        assert!(monitor.is_ok());
    }
    
    #[tokio::test]
    async fn test_metric_registration() {
        let monitor = PerformanceMonitor::new().unwrap();
        
        assert!(monitor.register_counter("test_counter", "Test counter").is_ok());
        assert!(monitor.register_gauge("test_gauge", "Test gauge").is_ok());
        assert!(monitor.register_histogram("test_histogram", "Test histogram").is_ok());
    }
    
    #[tokio::test]
    async fn test_metric_recording() {
        let monitor = PerformanceMonitor::new().unwrap();
        
        monitor.register_counter("test_counter", "Test counter").unwrap();
        monitor.increment_counter("test_counter", 1.0);
        
        monitor.register_gauge("test_gauge", "Test gauge").unwrap();
        monitor.set_gauge("test_gauge", 42.0);
        
        monitor.register_histogram("test_histogram", "Test histogram").unwrap();
        monitor.observe_histogram("test_histogram", 100.0);
    }
}