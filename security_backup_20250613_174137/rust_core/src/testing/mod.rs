/*! 
Comprehensive Rust Testing Framework

This module provides advanced testing capabilities for Rust components including
unit testing, integration testing, property-based testing, and performance benchmarking.
*/

use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::fmt;
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};
use serde::{Serialize, Deserialize};

pub mod unit;
pub mod integration;
pub mod ffi;
pub mod performance;
pub mod property;

/// Test result enumeration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestStatus {
    Pending,
    Running,
    Passed,
    Failed,
    Skipped,
    Error,
}

/// Test type classification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestType {
    Unit,
    Integration,
    Performance,
    Property,
    FFI,
    Security,
}

/// Test metadata for enhanced reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestMetadata {
    pub test_id: String,
    pub test_type: TestType,
    pub category: String,
    pub tags: Vec<String>,
    pub timeout: Duration,
    pub memory_limit_mb: Option<u64>,
    pub cpu_limit_percent: Option<f64>,
}

/// Comprehensive test result structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub metadata: TestMetadata,
    pub status: TestStatus,
    pub duration: Duration,
    pub memory_used_mb: Option<f64>,
    pub cpu_used_percent: Option<f64>,
    pub output: String,
    pub error_message: Option<String>,
    pub assertions: Vec<AssertionResult>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Assertion result for detailed debugging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionResult {
    pub description: String,
    pub passed: bool,
    pub expected: String,
    pub actual: String,
    pub location: String,
}

/// Resource usage tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub memory_mb: f64,
    pub cpu_percent: f64,
    pub disk_io_mb: f64,
    pub network_io_mb: f64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Test execution context
#[derive(Debug)]
pub struct TestContext {
    pub test_data: HashMap<String, serde_json::Value>,
    pub temp_files: Vec<std::path::PathBuf>,
    pub cleanup_tasks: Vec<Box<dyn FnOnce() + Send>>,
    pub resource_monitor: Arc<RwLock<ResourceMonitor>>,
}

impl TestContext {
    pub fn new() -> Self {
        Self {
            test_data: HashMap::new(),
            temp_files: Vec::new(),
            cleanup_tasks: Vec::new(),
            resource_monitor: Arc::new(RwLock::new(ResourceMonitor::new())),
        }
    }

    pub fn set_test_data<T: serde::Serialize>(&mut self, key: &str, value: T) -> anyhow::Result<()> {
        let json_value = serde_json::to_value(value)?;
        self.test_data.insert(key.to_string(), json_value);
        Ok(())
    }

    pub fn get_test_data<T: serde::de::DeserializeOwned>(&self, key: &str) -> anyhow::Result<Option<T>> {
        if let Some(value) = self.test_data.get(key) {
            let deserialized = serde_json::from_value(value.clone())?;
            Ok(Some(deserialized))
        } else {
            Ok(None)
        }
    }

    pub fn add_temp_file(&mut self, path: std::path::PathBuf) {
        self.temp_files.push(path);
    }

    pub fn add_cleanup_task<F>(&mut self, task: F)
    where
        F: FnOnce() + Send + 'static,
    {
        self.cleanup_tasks.push(Box::new(task));
    }

    pub async fn cleanup(&mut self) {
        // Remove temporary files
        for path in &self.temp_files {
            if path.exists() {
                if let Err(e) = std::fs::remove_file(path) {
                    warn!("Failed to remove temp file {:?}: {}", path, e);
                }
            }
        }

        // Execute cleanup tasks
        for task in self.cleanup_tasks.drain(..) {
            task();
        }
    }
}

/// Resource monitoring for test execution
#[derive(Debug)]
pub struct ResourceMonitor {
    start_time: Option<Instant>,
    usage_history: Vec<ResourceUsage>,
}

impl ResourceMonitor {
    pub fn new() -> Self {
        Self {
            start_time: None,
            usage_history: Vec::new(),
        }
    }

    pub fn start(&mut self) {
        self.start_time = Some(Instant::now());
        self.usage_history.clear();
    }

    pub fn record_usage(&mut self, usage: ResourceUsage) {
        self.usage_history.push(usage);
    }

    pub fn get_average_usage(&self) -> Option<ResourceUsage> {
        if self.usage_history.is_empty() {
            return None;
        }

        let count = self.usage_history.len() as f64;
        let avg_memory = self.usage_history.iter().map(|u| u.memory_mb).sum::<f64>() / count;
        let avg_cpu = self.usage_history.iter().map(|u| u.cpu_percent).sum::<f64>() / count;
        let avg_disk = self.usage_history.iter().map(|u| u.disk_io_mb).sum::<f64>() / count;
        let avg_network = self.usage_history.iter().map(|u| u.network_io_mb).sum::<f64>() / count;

        Some(ResourceUsage {
            memory_mb: avg_memory,
            cpu_percent: avg_cpu,
            disk_io_mb: avg_disk,
            network_io_mb: avg_network,
            timestamp: chrono::Utc::now(),
        })
    }

    pub fn get_peak_usage(&self) -> Option<ResourceUsage> {
        self.usage_history.iter()
            .max_by(|a, b| a.memory_mb.partial_cmp(&b.memory_mb).unwrap())
            .cloned()
    }
}

/// Advanced assertion framework
pub struct AdvancedAssertions;

impl AdvancedAssertions {
    /// Assert with custom message and location tracking
    pub fn assert_with_context<T, F>(
        condition: F,
        description: &str,
        expected: &str,
        actual: &str,
        location: &str,
    ) -> AssertionResult
    where
        F: FnOnce() -> bool,
    {
        let passed = condition();
        AssertionResult {
            description: description.to_string(),
            passed,
            expected: expected.to_string(),
            actual: actual.to_string(),
            location: location.to_string(),
        }
    }

    /// Assert performance within bounds
    pub fn assert_performance(
        duration: Duration,
        max_duration: Duration,
        description: &str,
    ) -> AssertionResult {
        let passed = duration <= max_duration;
        Self::assert_with_context(
            || passed,
            description,
            &format!("<= {:?}", max_duration),
            &format!("{:?}", duration),
            "performance_assertion",
        )
    }

    /// Assert memory usage within bounds
    pub fn assert_memory_usage(
        used_mb: f64,
        max_mb: f64,
        description: &str,
    ) -> AssertionResult {
        let passed = used_mb <= max_mb;
        Self::assert_with_context(
            || passed,
            description,
            &format!("<= {} MB", max_mb),
            &format!("{:.2} MB", used_mb),
            "memory_assertion",
        )
    }

    /// Assert approximate equality for floating point numbers
    pub fn assert_approx_eq(
        actual: f64,
        expected: f64,
        tolerance: f64,
        description: &str,
    ) -> AssertionResult {
        let diff = (actual - expected).abs();
        let passed = diff <= tolerance;
        Self::assert_with_context(
            || passed,
            description,
            &format!("{} ± {}", expected, tolerance),
            &format!("{}", actual),
            "approximate_equality",
        )
    }
}

/// Test runner for executing comprehensive test suites
pub struct TestRunner {
    results: Vec<TestResult>,
    resource_monitor: Arc<RwLock<ResourceMonitor>>,
}

impl TestRunner {
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
            resource_monitor: Arc::new(RwLock::new(ResourceMonitor::new())),
        }
    }

    /// Execute a single test with full monitoring
    pub async fn run_test<F, Fut>(&mut self, metadata: TestMetadata, test_func: F) -> TestResult
    where
        F: FnOnce(TestContext) -> Fut + Send,
        Fut: std::future::Future<Output = anyhow::Result<Vec<AssertionResult>>> + Send,
    {
        let start_time = Instant::now();
        let mut context = TestContext::new();
        context.resource_monitor = self.resource_monitor.clone();

        // Start resource monitoring
        {
            let mut monitor = self.resource_monitor.write().await;
            monitor.start();
        }

        let mut result = TestResult {
            metadata: metadata.clone(),
            status: TestStatus::Running,
            duration: Duration::default(),
            memory_used_mb: None,
            cpu_used_percent: None,
            output: String::new(),
            error_message: None,
            assertions: Vec::new(),
            timestamp: chrono::Utc::now(),
        };

        // Execute test with timeout
        let test_result = tokio::time::timeout(
            metadata.timeout,
            test_func(context)
        ).await;

        let duration = start_time.elapsed();
        result.duration = duration;

        match test_result {
            Ok(Ok(assertions)) => {
                result.assertions = assertions;
                result.status = if assertions.iter().all(|a| a.passed) {
                    TestStatus::Passed
                } else {
                    TestStatus::Failed
                };
            }
            Ok(Err(e)) => {
                result.status = TestStatus::Error;
                result.error_message = Some(format!("{:?}", e));
                error!("Test {} failed with error: {:?}", metadata.test_id, e);
            }
            Err(_) => {
                result.status = TestStatus::Failed;
                result.error_message = Some("Test timeout".to_string());
                warn!("Test {} timed out after {:?}", metadata.test_id, metadata.timeout);
            }
        }

        // Get resource usage
        {
            let monitor = self.resource_monitor.read().await;
            if let Some(avg_usage) = monitor.get_average_usage() {
                result.memory_used_mb = Some(avg_usage.memory_mb);
                result.cpu_used_percent = Some(avg_usage.cpu_percent);
            }
        }

        info!("Test {} completed with status {:?} in {:?}", 
              metadata.test_id, result.status, duration);

        self.results.push(result.clone());
        result
    }

    /// Run multiple tests in parallel
    pub async fn run_tests_parallel<F, Fut>(&mut self, tests: Vec<(TestMetadata, F)>) -> Vec<TestResult>
    where
        F: FnOnce(TestContext) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = anyhow::Result<Vec<AssertionResult>>> + Send + 'static,
    {
        let mut tasks = Vec::new();

        for (metadata, test_func) in tests {
            let resource_monitor = self.resource_monitor.clone();
            let task = tokio::spawn(async move {
                let mut runner = TestRunner::new();
                runner.resource_monitor = resource_monitor;
                runner.run_test(metadata, test_func).await
            });
            tasks.push(task);
        }

        let mut results = Vec::new();
        for task in tasks {
            match task.await {
                Ok(result) => {
                    results.push(result.clone());
                    self.results.push(result);
                }
                Err(e) => {
                    error!("Test task failed: {:?}", e);
                }
            }
        }

        results
    }

    /// Generate comprehensive test report
    pub fn generate_report(&self) -> TestReport {
        let total_tests = self.results.len();
        let passed = self.results.iter().filter(|r| r.status == TestStatus::Passed).count();
        let failed = self.results.iter().filter(|r| r.status == TestStatus::Failed).count();
        let errors = self.results.iter().filter(|r| r.status == TestStatus::Error).count();
        let skipped = self.results.iter().filter(|r| r.status == TestStatus::Skipped).count();

        let success_rate = if total_tests > 0 {
            passed as f64 / total_tests as f64
        } else {
            0.0
        };

        let total_duration: Duration = self.results.iter().map(|r| r.duration).sum();

        TestReport {
            summary: TestSummary {
                total_tests,
                passed,
                failed,
                errors,
                skipped,
                success_rate,
                total_duration,
            },
            results: self.results.clone(),
            timestamp: chrono::Utc::now(),
        }
    }

    pub fn clear_results(&mut self) {
        self.results.clear();
    }
}

/// Test report structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestReport {
    pub summary: TestSummary,
    pub results: Vec<TestResult>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSummary {
    pub total_tests: usize,
    pub passed: usize,
    pub failed: usize,
    pub errors: usize,
    pub skipped: usize,
    pub success_rate: f64,
    pub total_duration: Duration,
}

impl fmt::Display for TestReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Test Report ===")?;
        writeln!(f, "Total Tests: {}", self.summary.total_tests)?;
        writeln!(f, "Passed: {}", self.summary.passed)?;
        writeln!(f, "Failed: {}", self.summary.failed)?;
        writeln!(f, "Errors: {}", self.summary.errors)?;
        writeln!(f, "Skipped: {}", self.summary.skipped)?;
        writeln!(f, "Success Rate: {:.2}%", self.summary.success_rate * 100.0)?;
        writeln!(f, "Total Duration: {:?}", self.summary.total_duration)?;
        writeln!(f, "Timestamp: {}", self.timestamp)?;
        
        if !self.results.is_empty() {
            writeln!(f, "\n=== Individual Results ===")?;
            for result in &self.results {
                writeln!(f, "{}: {:?} ({:?})", 
                        result.metadata.test_id, 
                        result.status, 
                        result.duration)?;
            }
        }
        
        Ok(())
    }
}

/// Utility macros for enhanced testing
#[macro_export]
macro_rules! test_metadata {
    ($id:expr, $type:expr, $category:expr) => {
        TestMetadata {
            test_id: $id.to_string(),
            test_type: $type,
            category: $category.to_string(),
            tags: vec![],
            timeout: std::time::Duration::from_secs(30),
            memory_limit_mb: None,
            cpu_limit_percent: None,
        }
    };
    ($id:expr, $type:expr, $category:expr, timeout = $timeout:expr) => {
        TestMetadata {
            test_id: $id.to_string(),
            test_type: $type,
            category: $category.to_string(),
            tags: vec![],
            timeout: $timeout,
            memory_limit_mb: None,
            cpu_limit_percent: None,
        }
    };
}

#[macro_export]
macro_rules! assert_test {
    ($condition:expr, $description:expr) => {
        AdvancedAssertions::assert_with_context(
            || $condition,
            $description,
            "true",
            &format!("{}", $condition),
            &format!("{}:{}", file!(), line!()),
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_runner_basic_functionality() {
        let mut runner = TestRunner::new();
        
        let metadata = test_metadata!("test_basic", TestType::Unit, "basic");
        
        let result = runner.run_test(metadata, |_ctx| async {
            Ok(vec![
                AdvancedAssertions::assert_with_context(
                    || true,
                    "Basic assertion",
                    "true",
                    "true",
                    "test_location"
                )
            ])
        }).await;
        
        assert_eq!(result.status, TestStatus::Passed);
        assert_eq!(result.assertions.len(), 1);
        assert!(result.assertions[0].passed);
    }

    #[tokio::test]
    async fn test_resource_monitoring() {
        let mut monitor = ResourceMonitor::new();
        monitor.start();
        
        let usage = ResourceUsage {
            memory_mb: 100.0,
            cpu_percent: 50.0,
            disk_io_mb: 10.0,
            network_io_mb: 5.0,
            timestamp: chrono::Utc::now(),
        };
        
        monitor.record_usage(usage.clone());
        
        let avg_usage = monitor.get_average_usage().unwrap();
        assert_eq!(avg_usage.memory_mb, 100.0);
        assert_eq!(avg_usage.cpu_percent, 50.0);
    }

    #[test]
    fn test_assertion_framework() {
        let assertion = AdvancedAssertions::assert_performance(
            Duration::from_millis(100),
            Duration::from_millis(200),
            "Performance test"
        );
        
        assert!(assertion.passed);
        assert_eq!(assertion.description, "Performance test");
    }
}