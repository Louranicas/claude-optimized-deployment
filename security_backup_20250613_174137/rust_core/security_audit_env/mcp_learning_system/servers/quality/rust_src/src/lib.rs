pub mod memory;
pub mod test_analyzer;
pub mod coverage_tracker;
pub mod performance_profiler;
pub mod quality_scorer;
pub mod server;
pub mod learning;
pub mod frameworks;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

pub use server::QualityMCPServer;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeChanges {
    pub files: Vec<FileChange>,
    pub commit_hash: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChange {
    pub path: String,
    pub additions: Vec<String>,
    pub deletions: Vec<String>,
    pub modifications: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSuite {
    pub tests: Vec<Test>,
    pub optimization_strategy: String,
    pub estimated_duration: std::time::Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Test {
    pub name: String,
    pub path: String,
    pub priority: f64,
    pub failure_probability: f64,
    pub coverage_impact: f64,
    pub last_duration: std::time::Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityPrediction {
    pub predictions: Vec<QualityIssue>,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityIssue {
    pub issue_type: IssueType,
    pub severity: Severity,
    pub location: Location,
    pub description: String,
    pub fix_suggestion: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IssueType {
    CodeSmell,
    SecurityVulnerability,
    PerformanceBottleneck,
    TestCoverageGap,
    ComplexityIssue,
    DuplicationIssue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub file: String,
    pub line: usize,
    pub column: usize,
}

#[async_trait]
pub trait QualityAnalyzer: Send + Sync {
    async fn analyze(&self, code: &str) -> Result<QualityAnalysis, anyhow::Error>;
    async fn predict_issues(&self, changes: &CodeChanges) -> Result<Vec<QualityIssue>, anyhow::Error>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityAnalysis {
    pub score: f64,
    pub metrics: QualityMetrics,
    pub issues: Vec<QualityIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityMetrics {
    pub complexity: f64,
    pub maintainability: f64,
    pub test_coverage: f64,
    pub security_score: f64,
    pub performance_score: f64,
}

impl TestSuite {
    pub fn optimized(tests: Vec<Test>) -> Self {
        let estimated_duration = tests
            .iter()
            .map(|t| t.last_duration)
            .sum();
        
        Self {
            tests,
            optimization_strategy: "ML-based impact analysis".to_string(),
            estimated_duration,
        }
    }
}