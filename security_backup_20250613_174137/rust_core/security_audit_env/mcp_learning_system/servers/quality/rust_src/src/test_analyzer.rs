use crate::{CodeChanges, FileChange, Test};
use ahash::AHashMap;
use async_trait::async_trait;
use dashmap::DashMap;
use parking_lot::RwLock;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactAnalysis {
    pub affected_modules: Vec<String>,
    pub impact_score: f64,
    pub test_dependencies: HashMap<String, Vec<String>>,
    pub critical_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestHistory {
    pub test_name: String,
    pub executions: Vec<TestExecution>,
    pub failure_rate: f64,
    pub flakiness_score: f64,
    pub avg_duration: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestExecution {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub duration: Duration,
    pub passed: bool,
    pub coverage: f64,
    pub memory_usage: usize,
}

pub struct TestAnalyzer {
    test_history: Arc<DashMap<String, TestHistory>>,
    dependency_graph: Arc<RwLock<TestDependencyGraph>>,
    impact_cache: Arc<DashMap<String, ImpactAnalysis>>,
    ml_predictor: Arc<TestFailurePredictor>,
}

struct TestDependencyGraph {
    nodes: HashMap<String, TestNode>,
    edges: Vec<TestEdge>,
}

struct TestNode {
    name: String,
    module: String,
    dependencies: HashSet<String>,
    coverage_files: HashSet<PathBuf>,
}

struct TestEdge {
    from: String,
    to: String,
    weight: f64,
}

struct TestFailurePredictor {
    model_weights: Vec<f64>,
    feature_extractors: Vec<Box<dyn FeatureExtractor>>,
}

#[async_trait]
trait FeatureExtractor: Send + Sync {
    async fn extract(&self, changes: &CodeChanges) -> Vec<f64>;
}

impl TestAnalyzer {
    pub fn new() -> Self {
        Self {
            test_history: Arc::new(DashMap::new()),
            dependency_graph: Arc::new(RwLock::new(TestDependencyGraph::new())),
            impact_cache: Arc::new(DashMap::new()),
            ml_predictor: Arc::new(TestFailurePredictor::new()),
        }
    }
    
    pub async fn analyze_impact(&self, changes: &CodeChanges) -> ImpactAnalysis {
        let start = Instant::now();
        
        // Check cache first
        let cache_key = self.generate_cache_key(changes);
        if let Some(cached) = self.impact_cache.get(&cache_key) {
            debug!("Impact analysis cache hit");
            return cached.clone();
        }
        
        // Analyze file changes in parallel
        let affected_modules: Vec<String> = changes
            .files
            .par_iter()
            .flat_map(|file| self.find_affected_modules(&file.path))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        
        // Calculate impact score
        let impact_score = self.calculate_impact_score(changes, &affected_modules).await;
        
        // Find test dependencies
        let test_dependencies = self.find_test_dependencies(&affected_modules).await;
        
        // Identify critical paths
        let critical_paths = self.identify_critical_paths(changes, &test_dependencies).await;
        
        let analysis = ImpactAnalysis {
            affected_modules,
            impact_score,
            test_dependencies,
            critical_paths,
        };
        
        // Cache the result
        self.impact_cache.insert(cache_key, analysis.clone());
        
        info!("Impact analysis completed in {:?}", start.elapsed());
        analysis
    }
    
    pub async fn predict_test_failures(&self, tests: &[Test], changes: &CodeChanges) -> Vec<(String, f64)> {
        let features = self.ml_predictor.extract_features(changes).await;
        
        tests
            .par_iter()
            .map(|test| {
                let test_features = self.extract_test_features(test);
                let combined_features = [features.as_slice(), test_features.as_slice()].concat();
                let failure_prob = self.ml_predictor.predict(&combined_features);
                (test.name.clone(), failure_prob)
            })
            .collect()
    }
    
    pub async fn smart_test_selection(
        &self,
        impact_analysis: &ImpactAnalysis,
        available_time: Duration,
    ) -> Vec<Test> {
        let mut selected_tests = Vec::new();
        let mut total_time = Duration::from_secs(0);
        
        // Get all relevant tests
        let mut candidate_tests: Vec<Test> = impact_analysis
            .test_dependencies
            .values()
            .flatten()
            .map(|name| self.get_test_info(name))
            .collect();
        
        // Sort by priority (failure probability * coverage impact)
        candidate_tests.sort_by(|a, b| {
            let a_priority = a.failure_probability * a.coverage_impact;
            let b_priority = b.failure_probability * b.coverage_impact;
            b_priority.partial_cmp(&a_priority).unwrap()
        });
        
        // Select tests within time budget
        for test in candidate_tests {
            if total_time + test.last_duration <= available_time {
                total_time += test.last_duration;
                selected_tests.push(test);
            }
        }
        
        selected_tests
    }
    
    pub fn update_test_history(&self, test_name: &str, execution: TestExecution) {
        self.test_history
            .entry(test_name.to_string())
            .and_modify(|history| {
                history.executions.push(execution.clone());
                history.update_metrics();
            })
            .or_insert_with(|| TestHistory {
                test_name: test_name.to_string(),
                executions: vec![execution],
                failure_rate: 0.0,
                flakiness_score: 0.0,
                avg_duration: Duration::from_secs(0),
            });
    }
    
    fn find_affected_modules(&self, file_path: &str) -> Vec<String> {
        let graph = self.dependency_graph.read();
        graph
            .nodes
            .iter()
            .filter(|(_, node)| {
                node.coverage_files
                    .iter()
                    .any(|p| p.to_string_lossy().contains(file_path))
            })
            .map(|(name, _)| name.clone())
            .collect()
    }
    
    async fn calculate_impact_score(&self, changes: &CodeChanges, modules: &[String]) -> f64 {
        let file_count = changes.files.len() as f64;
        let module_count = modules.len() as f64;
        let change_size: f64 = changes
            .files
            .iter()
            .map(|f| (f.additions.len() + f.deletions.len() + f.modifications.len()) as f64)
            .sum();
        
        // Weighted impact score
        let score = (file_count * 0.2) + (module_count * 0.3) + (change_size.log2() * 0.5);
        score.min(1.0)
    }
    
    async fn find_test_dependencies(&self, modules: &[String]) -> HashMap<String, Vec<String>> {
        let graph = self.dependency_graph.read();
        let mut dependencies = HashMap::new();
        
        for module in modules {
            let tests: Vec<String> = graph
                .nodes
                .iter()
                .filter(|(_, node)| node.dependencies.contains(module))
                .map(|(name, _)| name.clone())
                .collect();
            
            dependencies.insert(module.clone(), tests);
        }
        
        dependencies
    }
    
    async fn identify_critical_paths(
        &self,
        changes: &CodeChanges,
        dependencies: &HashMap<String, Vec<String>>,
    ) -> Vec<String> {
        // Find paths with high failure impact
        let mut critical_paths = Vec::new();
        
        for (module, tests) in dependencies {
            let test_failure_rates: Vec<f64> = tests
                .iter()
                .filter_map(|test| {
                    self.test_history
                        .get(test)
                        .map(|h| h.failure_rate)
                })
                .collect();
            
            if !test_failure_rates.is_empty() {
                let avg_failure_rate = test_failure_rates.iter().sum::<f64>() / test_failure_rates.len() as f64;
                if avg_failure_rate > 0.1 {
                    critical_paths.push(module.clone());
                }
            }
        }
        
        critical_paths
    }
    
    fn generate_cache_key(&self, changes: &CodeChanges) -> String {
        use std::hash::{Hash, Hasher};
        let mut hasher = ahash::AHasher::default();
        changes.commit_hash.hash(&mut hasher);
        format!("impact_{:x}", hasher.finish())
    }
    
    fn get_test_info(&self, test_name: &str) -> Test {
        let history = self.test_history.get(test_name);
        
        Test {
            name: test_name.to_string(),
            path: format!("tests/{}.rs", test_name),
            priority: 0.5,
            failure_probability: history.as_ref().map(|h| h.failure_rate).unwrap_or(0.1),
            coverage_impact: 0.7,
            last_duration: history.as_ref().map(|h| h.avg_duration).unwrap_or(Duration::from_secs(1)),
        }
    }
    
    fn extract_test_features(&self, test: &Test) -> Vec<f64> {
        vec![
            test.failure_probability,
            test.coverage_impact,
            test.last_duration.as_secs_f64(),
            test.priority,
        ]
    }
}

impl TestDependencyGraph {
    fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
        }
    }
}

impl TestHistory {
    fn update_metrics(&mut self) {
        let total = self.executions.len() as f64;
        let failures = self.executions.iter().filter(|e| !e.passed).count() as f64;
        self.failure_rate = failures / total;
        
        // Calculate flakiness (variance in results)
        let mut flaky_count = 0;
        for window in self.executions.windows(2) {
            if window[0].passed != window[1].passed {
                flaky_count += 1;
            }
        }
        self.flakiness_score = flaky_count as f64 / total.max(1.0);
        
        // Update average duration
        let total_duration: Duration = self.executions.iter().map(|e| e.duration).sum();
        self.avg_duration = total_duration / self.executions.len() as u32;
    }
}

impl TestFailurePredictor {
    fn new() -> Self {
        Self {
            model_weights: vec![0.3, 0.2, 0.1, 0.4], // Example weights
            feature_extractors: vec![
                Box::new(FileCountExtractor),
                Box::new(ChangeSizeExtractor),
                Box::new(ComplexityExtractor),
                Box::new(HistoricalFailureExtractor),
            ],
        }
    }
    
    async fn extract_features(&self, changes: &CodeChanges) -> Vec<f64> {
        let mut features = Vec::new();
        
        for extractor in &self.feature_extractors {
            let extracted = extractor.extract(changes).await;
            features.extend(extracted);
        }
        
        features
    }
    
    fn predict(&self, features: &[f64]) -> f64 {
        // Simple linear model for demonstration
        features
            .iter()
            .zip(&self.model_weights)
            .map(|(f, w)| f * w)
            .sum::<f64>()
            .min(1.0)
            .max(0.0)
    }
}

struct FileCountExtractor;
struct ChangeSizeExtractor;
struct ComplexityExtractor;
struct HistoricalFailureExtractor;

#[async_trait]
impl FeatureExtractor for FileCountExtractor {
    async fn extract(&self, changes: &CodeChanges) -> Vec<f64> {
        vec![changes.files.len() as f64 / 100.0]
    }
}

#[async_trait]
impl FeatureExtractor for ChangeSizeExtractor {
    async fn extract(&self, changes: &CodeChanges) -> Vec<f64> {
        let total_changes: usize = changes
            .files
            .iter()
            .map(|f| f.additions.len() + f.deletions.len() + f.modifications.len())
            .sum();
        
        vec![total_changes as f64 / 1000.0]
    }
}

#[async_trait]
impl FeatureExtractor for ComplexityExtractor {
    async fn extract(&self, changes: &CodeChanges) -> Vec<f64> {
        // Simplified complexity calculation
        let complexity = changes.files.len() as f64 * 0.5;
        vec![complexity / 10.0]
    }
}

#[async_trait]
impl FeatureExtractor for HistoricalFailureExtractor {
    async fn extract(&self, changes: &CodeChanges) -> Vec<f64> {
        // Would look up historical failure rates for changed files
        vec![0.15] // Placeholder
    }
}