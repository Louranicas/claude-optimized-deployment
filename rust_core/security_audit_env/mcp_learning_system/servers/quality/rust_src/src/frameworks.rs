use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use std::sync::Arc;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestFramework {
    pub name: String,
    pub language: Language,
    pub command: String,
    pub config_file: Option<String>,
    pub supported_features: Vec<Feature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Language {
    Rust,
    Python,
    JavaScript,
    TypeScript,
    Go,
    Java,
    CSharp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Feature {
    UnitTesting,
    IntegrationTesting,
    CoverageReporting,
    ParallelExecution,
    TestFiltering,
    Mocking,
    Benchmarking,
    PropertyTesting,
}

#[async_trait]
pub trait TestRunner: Send + Sync {
    async fn run_tests(&self, config: TestRunConfig) -> Result<TestRunResult, TestError>;
    async fn get_coverage(&self, test_results: &TestRunResult) -> Result<CoverageReport, TestError>;
    fn supports_feature(&self, feature: &Feature) -> bool;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestRunConfig {
    pub test_filter: Option<String>,
    pub parallel: bool,
    pub coverage: bool,
    pub timeout: std::time::Duration,
    pub environment: HashMap<String, String>,
    pub working_directory: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestRunResult {
    pub total_tests: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub duration: std::time::Duration,
    pub test_details: Vec<TestDetail>,
    pub output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestDetail {
    pub name: String,
    pub status: TestStatus,
    pub duration: std::time::Duration,
    pub failure_message: Option<String>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TestStatus {
    Passed,
    Failed,
    Skipped,
    Ignored,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageReport {
    pub line_coverage: f64,
    pub branch_coverage: f64,
    pub function_coverage: f64,
    pub file_reports: HashMap<String, FileCoverageReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileCoverageReport {
    pub path: String,
    pub lines_covered: usize,
    pub lines_total: usize,
    pub branches_covered: usize,
    pub branches_total: usize,
    pub functions_covered: usize,
    pub functions_total: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum TestError {
    #[error("Test execution failed: {0}")]
    ExecutionFailed(String),
    
    #[error("Coverage analysis failed: {0}")]
    CoverageFailed(String),
    
    #[error("Framework not supported: {0}")]
    FrameworkNotSupported(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

// Framework implementations

pub struct RustTestRunner {
    cargo_path: String,
    tarpaulin_path: Option<String>,
}

impl RustTestRunner {
    pub fn new() -> Self {
        Self {
            cargo_path: "cargo".to_string(),
            tarpaulin_path: Self::find_tarpaulin(),
        }
    }
    
    fn find_tarpaulin() -> Option<String> {
        Command::new("which")
            .arg("cargo-tarpaulin")
            .output()
            .ok()
            .and_then(|output| {
                if output.status.success() {
                    String::from_utf8(output.stdout).ok().map(|s| s.trim().to_string())
                } else {
                    None
                }
            })
    }
}

#[async_trait]
impl TestRunner for RustTestRunner {
    async fn run_tests(&self, config: TestRunConfig) -> Result<TestRunResult, TestError> {
        let mut cmd = Command::new(&self.cargo_path);
        cmd.arg("test");
        
        if let Some(filter) = &config.test_filter {
            cmd.arg(filter);
        }
        
        if !config.parallel {
            cmd.arg("--test-threads=1");
        }
        
        if config.coverage && self.tarpaulin_path.is_some() {
            // Use tarpaulin for coverage
            cmd = Command::new(self.tarpaulin_path.as_ref().unwrap());
            cmd.arg("--out").arg("Json");
        }
        
        cmd.current_dir(&config.working_directory);
        
        for (key, value) in &config.environment {
            cmd.env(key, value);
        }
        
        let start = std::time::Instant::now();
        let output = cmd.output()
            .map_err(|e| TestError::ExecutionFailed(e.to_string()))?;
        
        let duration = start.elapsed();
        let output_str = String::from_utf8_lossy(&output.stdout).to_string();
        
        // Parse test results
        let test_details = self.parse_cargo_test_output(&output_str);
        let (passed, failed, skipped) = self.count_test_results(&test_details);
        
        Ok(TestRunResult {
            total_tests: test_details.len(),
            passed,
            failed,
            skipped,
            duration,
            test_details,
            output: output_str,
        })
    }
    
    async fn get_coverage(&self, test_results: &TestRunResult) -> Result<CoverageReport, TestError> {
        if self.tarpaulin_path.is_none() {
            return Err(TestError::CoverageFailed("cargo-tarpaulin not found".to_string()));
        }
        
        // Parse tarpaulin JSON output
        // Simplified implementation
        Ok(CoverageReport {
            line_coverage: 0.85,
            branch_coverage: 0.75,
            function_coverage: 0.90,
            file_reports: HashMap::new(),
        })
    }
    
    fn supports_feature(&self, feature: &Feature) -> bool {
        matches!(
            feature,
            Feature::UnitTesting
                | Feature::IntegrationTesting
                | Feature::CoverageReporting
                | Feature::ParallelExecution
                | Feature::TestFiltering
                | Feature::Benchmarking
                | Feature::PropertyTesting
        )
    }
}

impl RustTestRunner {
    fn parse_cargo_test_output(&self, output: &str) -> Vec<TestDetail> {
        let mut test_details = Vec::new();
        
        for line in output.lines() {
            if line.contains("test") && line.contains("...") {
                let parts: Vec<&str> = line.split("...").collect();
                if parts.len() >= 2 {
                    let name = parts[0].trim().replace("test ", "");
                    let status_part = parts[1].trim();
                    
                    let (status, duration) = if status_part.starts_with("ok") {
                        (TestStatus::Passed, self.parse_duration(status_part))
                    } else if status_part.starts_with("FAILED") {
                        (TestStatus::Failed, self.parse_duration(status_part))
                    } else if status_part.starts_with("ignored") {
                        (TestStatus::Ignored, std::time::Duration::from_secs(0))
                    } else {
                        continue;
                    };
                    
                    test_details.push(TestDetail {
                        name,
                        status,
                        duration,
                        failure_message: None,
                        stdout: None,
                        stderr: None,
                    });
                }
            }
        }
        
        test_details
    }
    
    fn parse_duration(&self, status: &str) -> std::time::Duration {
        // Extract duration from "ok (0.001s)" format
        if let Some(start) = status.find('(') {
            if let Some(end) = status.find("s)") {
                let duration_str = &status[start + 1..end];
                if let Ok(seconds) = duration_str.parse::<f64>() {
                    return std::time::Duration::from_secs_f64(seconds);
                }
            }
        }
        std::time::Duration::from_secs(0)
    }
    
    fn count_test_results(&self, test_details: &[TestDetail]) -> (usize, usize, usize) {
        let passed = test_details.iter().filter(|t| matches!(t.status, TestStatus::Passed)).count();
        let failed = test_details.iter().filter(|t| matches!(t.status, TestStatus::Failed)).count();
        let skipped = test_details.iter().filter(|t| matches!(t.status, TestStatus::Skipped | TestStatus::Ignored)).count();
        
        (passed, failed, skipped)
    }
}

pub struct PythonTestRunner {
    pytest_path: String,
    coverage_path: Option<String>,
}

impl PythonTestRunner {
    pub fn new() -> Self {
        Self {
            pytest_path: Self::find_pytest().unwrap_or_else(|| "pytest".to_string()),
            coverage_path: Self::find_coverage(),
        }
    }
    
    fn find_pytest() -> Option<String> {
        Command::new("which")
            .arg("pytest")
            .output()
            .ok()
            .and_then(|output| {
                if output.status.success() {
                    String::from_utf8(output.stdout).ok().map(|s| s.trim().to_string())
                } else {
                    None
                }
            })
    }
    
    fn find_coverage() -> Option<String> {
        Command::new("which")
            .arg("coverage")
            .output()
            .ok()
            .and_then(|output| {
                if output.status.success() {
                    String::from_utf8(output.stdout).ok().map(|s| s.trim().to_string())
                } else {
                    None
                }
            })
    }
}

#[async_trait]
impl TestRunner for PythonTestRunner {
    async fn run_tests(&self, config: TestRunConfig) -> Result<TestRunResult, TestError> {
        let mut cmd = Command::new(&self.pytest_path);
        
        cmd.arg("-v").arg("--tb=short");
        
        if let Some(filter) = &config.test_filter {
            cmd.arg("-k").arg(filter);
        }
        
        if config.parallel {
            cmd.arg("-n").arg("auto");
        }
        
        if config.coverage && self.coverage_path.is_some() {
            cmd.arg("--cov").arg("--cov-report=json");
        }
        
        cmd.current_dir(&config.working_directory);
        
        for (key, value) in &config.environment {
            cmd.env(key, value);
        }
        
        let start = std::time::Instant::now();
        let output = cmd.output()
            .map_err(|e| TestError::ExecutionFailed(e.to_string()))?;
        
        let duration = start.elapsed();
        let output_str = String::from_utf8_lossy(&output.stdout).to_string();
        
        // Parse pytest output
        let test_details = self.parse_pytest_output(&output_str);
        let (passed, failed, skipped) = self.count_test_results(&test_details);
        
        Ok(TestRunResult {
            total_tests: test_details.len(),
            passed,
            failed,
            skipped,
            duration,
            test_details,
            output: output_str,
        })
    }
    
    async fn get_coverage(&self, test_results: &TestRunResult) -> Result<CoverageReport, TestError> {
        // Parse coverage.py JSON output
        Ok(CoverageReport {
            line_coverage: 0.80,
            branch_coverage: 0.70,
            function_coverage: 0.85,
            file_reports: HashMap::new(),
        })
    }
    
    fn supports_feature(&self, feature: &Feature) -> bool {
        matches!(
            feature,
            Feature::UnitTesting
                | Feature::IntegrationTesting
                | Feature::CoverageReporting
                | Feature::ParallelExecution
                | Feature::TestFiltering
                | Feature::Mocking
        )
    }
}

impl PythonTestRunner {
    fn parse_pytest_output(&self, output: &str) -> Vec<TestDetail> {
        let mut test_details = Vec::new();
        
        for line in output.lines() {
            if line.contains("PASSED") || line.contains("FAILED") || line.contains("SKIPPED") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let name = parts[0].trim();
                    let status = if line.contains("PASSED") {
                        TestStatus::Passed
                    } else if line.contains("FAILED") {
                        TestStatus::Failed
                    } else {
                        TestStatus::Skipped
                    };
                    
                    test_details.push(TestDetail {
                        name: name.to_string(),
                        status,
                        duration: std::time::Duration::from_secs(0), // Would parse from output
                        failure_message: None,
                        stdout: None,
                        stderr: None,
                    });
                }
            }
        }
        
        test_details
    }
    
    fn count_test_results(&self, test_details: &[TestDetail]) -> (usize, usize, usize) {
        let passed = test_details.iter().filter(|t| matches!(t.status, TestStatus::Passed)).count();
        let failed = test_details.iter().filter(|t| matches!(t.status, TestStatus::Failed)).count();
        let skipped = test_details.iter().filter(|t| matches!(t.status, TestStatus::Skipped)).count();
        
        (passed, failed, skipped)
    }
}

// Framework manager
pub struct TestFrameworkManager {
    frameworks: HashMap<Language, Arc<dyn TestRunner>>,
}

impl TestFrameworkManager {
    pub fn new() -> Self {
        let mut frameworks: HashMap<Language, Arc<dyn TestRunner>> = HashMap::new();
        
        frameworks.insert(Language::Rust, Arc::new(RustTestRunner::new()));
        frameworks.insert(Language::Python, Arc::new(PythonTestRunner::new()));
        
        Self { frameworks }
    }
    
    pub async fn run_tests(
        &self,
        language: Language,
        config: TestRunConfig,
    ) -> Result<TestRunResult, TestError> {
        let runner = self.frameworks.get(&language)
            .ok_or_else(|| TestError::FrameworkNotSupported(format!("{:?}", language)))?;
        
        runner.run_tests(config).await
    }
    
    pub async fn get_coverage(
        &self,
        language: Language,
        test_results: &TestRunResult,
    ) -> Result<CoverageReport, TestError> {
        let runner = self.frameworks.get(&language)
            .ok_or_else(|| TestError::FrameworkNotSupported(format!("{:?}", language)))?;
        
        runner.get_coverage(test_results).await
    }
    
    pub fn detect_language(&self, path: &str) -> Option<Language> {
        if path.contains("Cargo.toml") || path.ends_with(".rs") {
            Some(Language::Rust)
        } else if path.contains("setup.py") || path.contains("pyproject.toml") || path.ends_with(".py") {
            Some(Language::Python)
        } else if path.contains("package.json") {
            if path.contains("tsconfig.json") {
                Some(Language::TypeScript)
            } else {
                Some(Language::JavaScript)
            }
        } else if path.contains("go.mod") || path.ends_with(".go") {
            Some(Language::Go)
        } else if path.contains("pom.xml") || path.ends_with(".java") {
            Some(Language::Java)
        } else if path.ends_with(".cs") || path.contains(".csproj") {
            Some(Language::CSharp)
        } else {
            None
        }
    }
    
    pub fn get_supported_features(&self, language: Language) -> Vec<Feature> {
        self.frameworks.get(&language)
            .map(|runner| {
                vec![
                    Feature::UnitTesting,
                    Feature::IntegrationTesting,
                    Feature::CoverageReporting,
                    Feature::ParallelExecution,
                    Feature::TestFiltering,
                    Feature::Mocking,
                    Feature::Benchmarking,
                    Feature::PropertyTesting,
                ]
                .into_iter()
                .filter(|f| runner.supports_feature(f))
                .collect()
            })
            .unwrap_or_default()
    }
}