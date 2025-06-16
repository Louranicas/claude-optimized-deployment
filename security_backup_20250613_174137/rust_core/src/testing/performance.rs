/*!
Performance Testing Framework

This module provides comprehensive performance testing capabilities including
benchmarking, load testing, memory profiling, and performance regression detection.
*/

use super::{TestContext, TestResult, TestMetadata, TestType, AssertionResult, AdvancedAssertions, ResourceUsage};
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, debug};
use serde::{Serialize, Deserialize};

/// Performance test configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceTestConfig {
    pub warmup_iterations: usize,
    pub measurement_iterations: usize,
    pub concurrent_users: usize,
    pub duration_seconds: u64,
    pub memory_limit_mb: u64,
    pub cpu_limit_percent: f64,
    pub performance_thresholds: HashMap<String, f64>,
}

impl Default for PerformanceTestConfig {
    fn default() -> Self {
        let mut thresholds = HashMap::new();
        thresholds.insert("avg_response_time_ms".to_string(), 100.0);
        thresholds.insert("p95_response_time_ms".to_string(), 200.0);
        thresholds.insert("p99_response_time_ms".to_string(), 500.0);
        thresholds.insert("throughput_ops_per_sec".to_string(), 1000.0);
        thresholds.insert("memory_usage_mb".to_string(), 512.0);
        thresholds.insert("cpu_usage_percent".to_string(), 80.0);

        Self {
            warmup_iterations: 100,
            measurement_iterations: 1000,
            concurrent_users: 10,
            duration_seconds: 60,
            memory_limit_mb: 1024,
            cpu_limit_percent: 90.0,
            performance_thresholds: thresholds,
        }
    }
}

/// Performance metrics collection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub total_operations: u64,
    pub successful_operations: u64,
    pub failed_operations: u64,
    pub total_duration: Duration,
    pub avg_response_time: Duration,
    pub min_response_time: Duration,
    pub max_response_time: Duration,
    pub p50_response_time: Duration,
    pub p95_response_time: Duration,
    pub p99_response_time: Duration,
    pub throughput_ops_per_sec: f64,
    pub memory_usage: MemoryMetrics,
    pub cpu_usage: CpuMetrics,
    pub error_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryMetrics {
    pub peak_usage_mb: f64,
    pub avg_usage_mb: f64,
    pub allocations_per_sec: f64,
    pub gc_collections: u64,
    pub gc_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuMetrics {
    pub peak_usage_percent: f64,
    pub avg_usage_percent: f64,
    pub user_time_ms: u64,
    pub system_time_ms: u64,
    pub context_switches: u64,
}

/// Load testing patterns
#[derive(Debug, Clone, PartialEq)]
pub enum LoadPattern {
    Constant,
    RampUp,
    Spike,
    Step,
    Sine,
}

/// Performance test types
#[derive(Debug, Clone, PartialEq)]
pub enum PerformanceTestType {
    Latency,
    Throughput,
    Stress,
    Volume,
    Endurance,
    Spike,
    Memory,
    CPU,
}

/// Benchmark operation trait
pub trait BenchmarkOperation: Send + Sync {
    fn execute(&self) -> impl std::future::Future<Output = anyhow::Result<Duration>> + Send;
    fn name(&self) -> &str;
    fn description(&self) -> &str;
}

/// Simple function benchmark operation
pub struct FunctionBenchmark<F, Fut>
where
    F: Fn() -> Fut + Send + Sync,
    Fut: std::future::Future<Output = anyhow::Result<()>> + Send,
{
    name: String,
    description: String,
    function: F,
}

impl<F, Fut> FunctionBenchmark<F, Fut>
where
    F: Fn() -> Fut + Send + Sync,
    Fut: std::future::Future<Output = anyhow::Result<()>> + Send,
{
    pub fn new(name: String, description: String, function: F) -> Self {
        Self {
            name,
            description,
            function,
        }
    }
}

impl<F, Fut> BenchmarkOperation for FunctionBenchmark<F, Fut>
where
    F: Fn() -> Fut + Send + Sync,
    Fut: std::future::Future<Output = anyhow::Result<()>> + Send,
{
    async fn execute(&self) -> anyhow::Result<Duration> {
        let start = Instant::now();
        (self.function)().await?;
        Ok(start.elapsed())
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        &self.description
    }
}

/// Performance tester for comprehensive performance evaluation
pub struct PerformanceTester {
    config: PerformanceTestConfig,
    metrics_history: Vec<PerformanceMetrics>,
    baseline_metrics: Option<PerformanceMetrics>,
}

impl PerformanceTester {
    pub fn new(config: PerformanceTestConfig) -> Self {
        Self {
            config,
            metrics_history: Vec::new(),
            baseline_metrics: None,
        }
    }

    /// Run comprehensive performance benchmark
    pub async fn run_benchmark<Op>(&mut self, operation: Arc<Op>) -> anyhow::Result<PerformanceMetrics>
    where
        Op: BenchmarkOperation + 'static,
    {
        info!("Starting performance benchmark for: {}", operation.name());

        // Warmup phase
        info!("Warming up with {} iterations", self.config.warmup_iterations);
        for _ in 0..self.config.warmup_iterations {
            let _ = operation.execute().await;
            tokio::task::yield_now().await;
        }

        // Measurement phase
        info!("Running {} measurement iterations", self.config.measurement_iterations);
        let mut response_times = Vec::with_capacity(self.config.measurement_iterations);
        let mut successful_ops = 0u64;
        let mut failed_ops = 0u64;

        let start_time = Instant::now();
        let memory_monitor = Arc::new(RwLock::new(Vec::new()));
        let cpu_monitor = Arc::new(RwLock::new(Vec::new()));

        // Start resource monitoring
        let memory_monitor_clone = memory_monitor.clone();
        let cpu_monitor_clone = cpu_monitor.clone();
        
        let monitoring_task = tokio::spawn(async move {
            while !memory_monitor_clone.read().await.is_empty() || memory_monitor_clone.read().await.is_empty() {
                // Simulate resource monitoring
                let memory_usage = Self::get_current_memory_usage();
                let cpu_usage = Self::get_current_cpu_usage();
                
                memory_monitor_clone.write().await.push(memory_usage);
                cpu_monitor_clone.write().await.push(cpu_usage);
                
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });

        // Execute benchmark iterations
        for i in 0..self.config.measurement_iterations {
            match operation.execute().await {
                Ok(duration) => {
                    response_times.push(duration);
                    successful_ops += 1;
                }
                Err(e) => {
                    warn!("Benchmark iteration {} failed: {:?}", i, e);
                    failed_ops += 1;
                }
            }

            // Yield control periodically
            if i % 100 == 0 {
                tokio::task::yield_now().await;
            }
        }

        let total_duration = start_time.elapsed();

        // Stop monitoring
        drop(monitoring_task);

        // Calculate statistics
        response_times.sort();
        let total_operations = successful_ops + failed_ops;
        
        let avg_response_time = if !response_times.is_empty() {
            response_times.iter().sum::<Duration>() / response_times.len() as u32
        } else {
            Duration::ZERO
        };

        let min_response_time = response_times.first().copied().unwrap_or(Duration::ZERO);
        let max_response_time = response_times.last().copied().unwrap_or(Duration::ZERO);

        let p50_response_time = Self::percentile(&response_times, 50);
        let p95_response_time = Self::percentile(&response_times, 95);
        let p99_response_time = Self::percentile(&response_times, 99);

        let throughput_ops_per_sec = if total_duration.as_secs_f64() > 0.0 {
            successful_ops as f64 / total_duration.as_secs_f64()
        } else {
            0.0
        };

        let error_rate = if total_operations > 0 {
            failed_ops as f64 / total_operations as f64 * 100.0
        } else {
            0.0
        };

        // Collect resource metrics
        let memory_readings = memory_monitor.read().await;
        let cpu_readings = cpu_monitor.read().await;

        let memory_metrics = MemoryMetrics {
            peak_usage_mb: memory_readings.iter().map(|m| m.memory_mb).fold(0.0, f64::max),
            avg_usage_mb: memory_readings.iter().map(|m| m.memory_mb).sum::<f64>() / memory_readings.len().max(1) as f64,
            allocations_per_sec: successful_ops as f64 / total_duration.as_secs_f64(),
            gc_collections: 0, // Would need actual GC info
            gc_time_ms: 0,
        };

        let cpu_metrics = CpuMetrics {
            peak_usage_percent: cpu_readings.iter().map(|c| c.cpu_percent).fold(0.0, f64::max),
            avg_usage_percent: cpu_readings.iter().map(|c| c.cpu_percent).sum::<f64>() / cpu_readings.len().max(1) as f64,
            user_time_ms: 0, // Would need actual CPU time info
            system_time_ms: 0,
            context_switches: 0,
        };

        let metrics = PerformanceMetrics {
            total_operations,
            successful_operations: successful_ops,
            failed_operations: failed_ops,
            total_duration,
            avg_response_time,
            min_response_time,
            max_response_time,
            p50_response_time,
            p95_response_time,
            p99_response_time,
            throughput_ops_per_sec,
            memory_usage: memory_metrics,
            cpu_usage: cpu_metrics,
            error_rate,
        };

        self.metrics_history.push(metrics.clone());
        info!("Benchmark completed: {} ops/sec, {:.2}ms avg response time", 
              metrics.throughput_ops_per_sec, metrics.avg_response_time.as_millis());

        Ok(metrics)
    }

    /// Run load testing with specified pattern
    pub async fn run_load_test<Op>(
        &mut self,
        operation: Arc<Op>,
        pattern: LoadPattern,
    ) -> anyhow::Result<PerformanceMetrics>
    where
        Op: BenchmarkOperation + 'static,
    {
        info!("Starting load test with pattern: {:?}", pattern);

        let duration = Duration::from_secs(self.config.duration_seconds);
        let start_time = Instant::now();
        let mut all_response_times = Vec::new();
        let mut total_successful = 0u64;
        let mut total_failed = 0u64;

        // Calculate load schedule based on pattern
        let load_schedule = self.calculate_load_schedule(pattern, duration);

        for (time_offset, concurrent_users) in load_schedule {
            if start_time.elapsed() >= duration {
                break;
            }

            // Wait until the scheduled time
            let target_time = start_time + time_offset;
            let now = Instant::now();
            if now < target_time {
                tokio::time::sleep(target_time - now).await;
            }

            // Launch concurrent operations
            let mut tasks = Vec::new();
            for _ in 0..concurrent_users {
                let op = operation.clone();
                let task = tokio::spawn(async move {
                    op.execute().await
                });
                tasks.push(task);
            }

            // Collect results
            for task in tasks {
                match task.await {
                    Ok(Ok(duration)) => {
                        all_response_times.push(duration);
                        total_successful += 1;
                    }
                    Ok(Err(_)) | Err(_) => {
                        total_failed += 1;
                    }
                }
            }
        }

        let total_duration = start_time.elapsed();

        // Calculate metrics similar to benchmark
        all_response_times.sort();
        let metrics = self.calculate_metrics_from_response_times(
            all_response_times,
            total_successful,
            total_failed,
            total_duration,
        ).await;

        self.metrics_history.push(metrics.clone());
        Ok(metrics)
    }

    /// Run stress test to find breaking point
    pub async fn run_stress_test<Op>(&mut self, operation: Arc<Op>) -> anyhow::Result<PerformanceMetrics>
    where
        Op: BenchmarkOperation + 'static,
    {
        info!("Starting stress test to find breaking point");

        let mut current_load = 1;
        let max_load = 1000;
        let step_duration = Duration::from_secs(30);
        let mut best_metrics = None;

        while current_load <= max_load {
            info!("Testing with {} concurrent operations", current_load);

            let mut tasks = Vec::new();
            let start_time = Instant::now();

            // Launch concurrent operations
            for _ in 0..current_load {
                let op = operation.clone();
                let task = tokio::spawn(async move {
                    op.execute().await
                });
                tasks.push(task);
            }

            // Wait for specified duration or all tasks to complete
            let mut response_times = Vec::new();
            let mut successful = 0u64;
            let mut failed = 0u64;

            tokio::time::timeout(step_duration, async {
                for task in tasks {
                    match task.await {
                        Ok(Ok(duration)) => {
                            response_times.push(duration);
                            successful += 1;
                        }
                        Ok(Err(_)) | Err(_) => {
                            failed += 1;
                        }
                    }
                }
            }).await.ok(); // Ignore timeout error

            let step_duration = start_time.elapsed();
            let error_rate = if successful + failed > 0 {
                failed as f64 / (successful + failed) as f64 * 100.0
            } else {
                100.0
            };

            // Check if we've reached the breaking point
            if error_rate > 10.0 || response_times.iter().any(|&d| d > Duration::from_secs(5)) {
                info!("Breaking point reached at {} concurrent operations", current_load);
                break;
            }

            let metrics = self.calculate_metrics_from_response_times(
                response_times,
                successful,
                failed,
                step_duration,
            ).await;

            best_metrics = Some(metrics);
            current_load *= 2; // Exponential increase
        }

        best_metrics.ok_or_else(|| anyhow::anyhow!("No successful stress test iterations"))
    }

    /// Validate performance against thresholds
    pub fn validate_performance_thresholds(&self, metrics: &PerformanceMetrics) -> Vec<AssertionResult> {
        let mut assertions = Vec::new();

        // Check average response time
        if let Some(threshold) = self.config.performance_thresholds.get("avg_response_time_ms") {
            let avg_ms = metrics.avg_response_time.as_millis() as f64;
            assertions.push(AdvancedAssertions::assert_with_context(
                || avg_ms <= *threshold,
                "Average response time",
                &format!("<= {} ms", threshold),
                &format!("{:.2} ms", avg_ms),
                "performance_avg_response_time",
            ));
        }

        // Check P95 response time
        if let Some(threshold) = self.config.performance_thresholds.get("p95_response_time_ms") {
            let p95_ms = metrics.p95_response_time.as_millis() as f64;
            assertions.push(AdvancedAssertions::assert_with_context(
                || p95_ms <= *threshold,
                "P95 response time",
                &format!("<= {} ms", threshold),
                &format!("{:.2} ms", p95_ms),
                "performance_p95_response_time",
            ));
        }

        // Check P99 response time
        if let Some(threshold) = self.config.performance_thresholds.get("p99_response_time_ms") {
            let p99_ms = metrics.p99_response_time.as_millis() as f64;
            assertions.push(AdvancedAssertions::assert_with_context(
                || p99_ms <= *threshold,
                "P99 response time",
                &format!("<= {} ms", threshold),
                &format!("{:.2} ms", p99_ms),
                "performance_p99_response_time",
            ));
        }

        // Check throughput
        if let Some(threshold) = self.config.performance_thresholds.get("throughput_ops_per_sec") {
            assertions.push(AdvancedAssertions::assert_with_context(
                || metrics.throughput_ops_per_sec >= *threshold,
                "Throughput",
                &format!(">= {} ops/sec", threshold),
                &format!("{:.2} ops/sec", metrics.throughput_ops_per_sec),
                "performance_throughput",
            ));
        }

        // Check memory usage
        if let Some(threshold) = self.config.performance_thresholds.get("memory_usage_mb") {
            assertions.push(AdvancedAssertions::assert_with_context(
                || metrics.memory_usage.peak_usage_mb <= *threshold,
                "Memory usage",
                &format!("<= {} MB", threshold),
                &format!("{:.2} MB", metrics.memory_usage.peak_usage_mb),
                "performance_memory_usage",
            ));
        }

        // Check CPU usage
        if let Some(threshold) = self.config.performance_thresholds.get("cpu_usage_percent") {
            assertions.push(AdvancedAssertions::assert_with_context(
                || metrics.cpu_usage.peak_usage_percent <= *threshold,
                "CPU usage",
                &format!("<= {}%", threshold),
                &format!("{:.2}%", metrics.cpu_usage.peak_usage_percent),
                "performance_cpu_usage",
            ));
        }

        // Check error rate (should be low)
        assertions.push(AdvancedAssertions::assert_with_context(
            || metrics.error_rate <= 1.0, // 1% error rate threshold
            "Error rate",
            "<= 1%",
            &format!("{:.2}%", metrics.error_rate),
            "performance_error_rate",
        ));

        assertions
    }

    /// Set baseline metrics for regression detection
    pub fn set_baseline(&mut self, metrics: PerformanceMetrics) {
        self.baseline_metrics = Some(metrics);
    }

    /// Check for performance regression
    pub fn check_regression(&self, current_metrics: &PerformanceMetrics) -> Vec<AssertionResult> {
        let mut assertions = Vec::new();

        if let Some(baseline) = &self.baseline_metrics {
            // Check response time regression (allow 10% degradation)
            let response_time_regression = (current_metrics.avg_response_time.as_millis() as f64 
                - baseline.avg_response_time.as_millis() as f64) 
                / baseline.avg_response_time.as_millis() as f64 * 100.0;

            assertions.push(AdvancedAssertions::assert_with_context(
                || response_time_regression <= 10.0,
                "Response time regression",
                "<= 10% increase",
                &format!("{:.2}% change", response_time_regression),
                "performance_regression_response_time",
            ));

            // Check throughput regression (allow 10% degradation)
            let throughput_regression = (baseline.throughput_ops_per_sec - current_metrics.throughput_ops_per_sec) 
                / baseline.throughput_ops_per_sec * 100.0;

            assertions.push(AdvancedAssertions::assert_with_context(
                || throughput_regression <= 10.0,
                "Throughput regression",
                "<= 10% decrease",
                &format!("{:.2}% change", throughput_regression),
                "performance_regression_throughput",
            ));

            // Check memory usage regression (allow 20% increase)
            let memory_regression = (current_metrics.memory_usage.peak_usage_mb - baseline.memory_usage.peak_usage_mb) 
                / baseline.memory_usage.peak_usage_mb * 100.0;

            assertions.push(AdvancedAssertions::assert_with_context(
                || memory_regression <= 20.0,
                "Memory usage regression",
                "<= 20% increase",
                &format!("{:.2}% change", memory_regression),
                "performance_regression_memory",
            ));
        }

        assertions
    }

    /// Calculate load schedule for different patterns
    fn calculate_load_schedule(&self, pattern: LoadPattern, duration: Duration) -> Vec<(Duration, usize)> {
        let mut schedule = Vec::new();
        let max_users = self.config.concurrent_users;
        let total_seconds = duration.as_secs();
        let step_interval = Duration::from_secs(1);

        match pattern {
            LoadPattern::Constant => {
                for i in 0..total_seconds {
                    schedule.push((Duration::from_secs(i), max_users));
                }
            }
            LoadPattern::RampUp => {
                for i in 0..total_seconds {
                    let users = ((i as f64 / total_seconds as f64) * max_users as f64) as usize;
                    schedule.push((Duration::from_secs(i), users.max(1)));
                }
            }
            LoadPattern::Spike => {
                let spike_start = total_seconds / 3;
                let spike_end = (total_seconds * 2) / 3;
                
                for i in 0..total_seconds {
                    let users = if i >= spike_start && i <= spike_end {
                        max_users
                    } else {
                        max_users / 4
                    };
                    schedule.push((Duration::from_secs(i), users));
                }
            }
            LoadPattern::Step => {
                let step_size = total_seconds / 5;
                for i in 0..total_seconds {
                    let step = i / step_size;
                    let users = ((step + 1) as f64 / 5.0 * max_users as f64) as usize;
                    schedule.push((Duration::from_secs(i), users.max(1)));
                }
            }
            LoadPattern::Sine => {
                for i in 0..total_seconds {
                    let angle = (i as f64 / total_seconds as f64) * 2.0 * std::f64::consts::PI;
                    let users = ((angle.sin() + 1.0) / 2.0 * max_users as f64) as usize;
                    schedule.push((Duration::from_secs(i), users.max(1)));
                }
            }
        }

        schedule
    }

    /// Calculate percentile from sorted response times
    fn percentile(sorted_times: &[Duration], percentile: u8) -> Duration {
        if sorted_times.is_empty() {
            return Duration::ZERO;
        }

        let index = (percentile as f64 / 100.0 * (sorted_times.len() - 1) as f64) as usize;
        sorted_times.get(index).copied().unwrap_or(Duration::ZERO)
    }

    /// Calculate comprehensive metrics from response times
    async fn calculate_metrics_from_response_times(
        &self,
        mut response_times: Vec<Duration>,
        successful: u64,
        failed: u64,
        total_duration: Duration,
    ) -> PerformanceMetrics {
        response_times.sort();

        let avg_response_time = if !response_times.is_empty() {
            response_times.iter().sum::<Duration>() / response_times.len() as u32
        } else {
            Duration::ZERO
        };

        let min_response_time = response_times.first().copied().unwrap_or(Duration::ZERO);
        let max_response_time = response_times.last().copied().unwrap_or(Duration::ZERO);

        let throughput_ops_per_sec = if total_duration.as_secs_f64() > 0.0 {
            successful as f64 / total_duration.as_secs_f64()
        } else {
            0.0
        };

        let error_rate = if successful + failed > 0 {
            failed as f64 / (successful + failed) as f64 * 100.0
        } else {
            0.0
        };

        PerformanceMetrics {
            total_operations: successful + failed,
            successful_operations: successful,
            failed_operations: failed,
            total_duration,
            avg_response_time,
            min_response_time,
            max_response_time,
            p50_response_time: Self::percentile(&response_times, 50),
            p95_response_time: Self::percentile(&response_times, 95),
            p99_response_time: Self::percentile(&response_times, 99),
            throughput_ops_per_sec,
            memory_usage: MemoryMetrics {
                peak_usage_mb: Self::get_current_memory_usage().memory_mb,
                avg_usage_mb: Self::get_current_memory_usage().memory_mb,
                allocations_per_sec: successful as f64 / total_duration.as_secs_f64(),
                gc_collections: 0,
                gc_time_ms: 0,
            },
            cpu_usage: CpuMetrics {
                peak_usage_percent: Self::get_current_cpu_usage().cpu_percent,
                avg_usage_percent: Self::get_current_cpu_usage().cpu_percent,
                user_time_ms: 0,
                system_time_ms: 0,
                context_switches: 0,
            },
            error_rate,
        }
    }

    /// Get current memory usage (mock implementation)
    fn get_current_memory_usage() -> ResourceUsage {
        ResourceUsage {
            memory_mb: 256.0, // Mock value
            cpu_percent: 0.0,
            disk_io_mb: 0.0,
            network_io_mb: 0.0,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Get current CPU usage (mock implementation)
    fn get_current_cpu_usage() -> ResourceUsage {
        ResourceUsage {
            memory_mb: 0.0,
            cpu_percent: 25.0, // Mock value
            disk_io_mb: 0.0,
            network_io_mb: 0.0,
            timestamp: chrono::Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct MockOperation {
        name: String,
        delay: Duration,
        counter: AtomicU64,
    }

    impl MockOperation {
        fn new(name: String, delay: Duration) -> Self {
            Self {
                name,
                delay,
                counter: AtomicU64::new(0),
            }
        }
    }

    impl BenchmarkOperation for MockOperation {
        async fn execute(&self) -> anyhow::Result<Duration> {
            let start = Instant::now();
            tokio::time::sleep(self.delay).await;
            self.counter.fetch_add(1, Ordering::Relaxed);
            Ok(start.elapsed())
        }

        fn name(&self) -> &str {
            &self.name
        }

        fn description(&self) -> &str {
            "Mock operation for testing"
        }
    }

    #[tokio::test]
    async fn test_performance_benchmark() {
        let config = PerformanceTestConfig {
            warmup_iterations: 5,
            measurement_iterations: 10,
            ..Default::default()
        };

        let mut tester = PerformanceTester::new(config);
        let operation = Arc::new(MockOperation::new(
            "test_op".to_string(),
            Duration::from_millis(10),
        ));

        let metrics = tester.run_benchmark(operation.clone()).await.unwrap();

        assert_eq!(metrics.successful_operations, 10);
        assert_eq!(metrics.failed_operations, 0);
        assert!(metrics.avg_response_time >= Duration::from_millis(10));
        assert!(metrics.throughput_ops_per_sec > 0.0);
    }

    #[test]
    fn test_percentile_calculation() {
        let times = vec![
            Duration::from_millis(10),
            Duration::from_millis(20),
            Duration::from_millis(30),
            Duration::from_millis(40),
            Duration::from_millis(50),
        ];

        assert_eq!(PerformanceTester::percentile(&times, 50), Duration::from_millis(30));
        assert_eq!(PerformanceTester::percentile(&times, 95), Duration::from_millis(50));
    }

    #[test]
    fn test_load_schedule_calculation() {
        let config = PerformanceTestConfig {
            concurrent_users: 100,
            ..Default::default()
        };

        let tester = PerformanceTester::new(config);
        let schedule = tester.calculate_load_schedule(
            LoadPattern::RampUp,
            Duration::from_secs(10),
        );

        assert_eq!(schedule.len(), 10);
        assert_eq!(schedule[0].1, 0); // First entry should have 0 users (rounded down)
        assert_eq!(schedule[9].1, 100); // Last entry should have max users
    }

    #[tokio::test]
    async fn test_stress_testing() {
        let config = PerformanceTestConfig {
            warmup_iterations: 1,
            measurement_iterations: 5,
            ..Default::default()
        };

        let mut tester = PerformanceTester::new(config);
        let operation = Arc::new(MockOperation::new(
            "stress_test".to_string(),
            Duration::from_millis(5),
        ));

        let metrics = tester.run_stress_test(operation).await.unwrap();
        assert!(metrics.successful_operations > 0);
    }
}