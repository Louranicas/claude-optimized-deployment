use std::sync::Arc;
use std::path::PathBuf;
use dashmap::DashMap;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{info, debug};

use crate::{
    MemoryPool,
    CodeAnalyzer,
    ProjectGraph,
    PatternCache,
    code_analyzer::{CodeRequest, CodeResponse, CodePattern},
};

const MEMORY_SIZE: usize = 4_294_967_296; // 4GB

pub struct DevelopmentMCPServer {
    memory_pool: Arc<MemoryPool<MEMORY_SIZE>>,
    code_analyzer: Arc<CodeAnalyzer>,
    project_graph: Arc<RwLock<ProjectGraph>>,
    pattern_cache: Arc<PatternCache>,
    active_sessions: DashMap<String, SessionContext>,
    metrics: Arc<ServerMetrics>,
}

#[derive(Clone)]
struct SessionContext {
    session_id: String,
    project_root: PathBuf,
    last_activity: std::time::Instant,
    patterns_learned: u32,
    requests_processed: u32,
}

#[derive(Default)]
struct ServerMetrics {
    total_requests: std::sync::atomic::AtomicU64,
    successful_responses: std::sync::atomic::AtomicU64,
    pattern_cache_hits: std::sync::atomic::AtomicU64,
    average_response_time: parking_lot::Mutex<MovingAverage>,
}

struct MovingAverage {
    values: Vec<f64>,
    capacity: usize,
    sum: f64,
}

impl MovingAverage {
    fn new(capacity: usize) -> Self {
        Self {
            values: Vec::with_capacity(capacity),
            capacity,
            sum: 0.0,
        }
    }

    fn add(&mut self, value: f64) {
        if self.values.len() >= self.capacity {
            self.sum -= self.values.remove(0);
        }
        self.values.push(value);
        self.sum += value;
    }

    fn average(&self) -> f64 {
        if self.values.is_empty() {
            0.0
        } else {
            self.sum / self.values.len() as f64
        }
    }
}

impl Default for MovingAverage {
    fn default() -> Self {
        Self::new(100)
    }
}

impl DevelopmentMCPServer {
    pub fn new(project_root: PathBuf) -> Self {
        info!("Initializing Development MCP Server with 4GB memory");
        
        Self {
            memory_pool: Arc::new(MemoryPool::new()),
            code_analyzer: Arc::new(CodeAnalyzer::new()),
            project_graph: Arc::new(RwLock::new(ProjectGraph::new(project_root.clone()))),
            pattern_cache: Arc::new(PatternCache::new()),
            active_sessions: DashMap::new(),
            metrics: Arc::new(ServerMetrics::default()),
        }
    }

    pub async fn analyze_code_request(&self, req: CodeRequest) -> CodeResponse {
        let start = std::time::Instant::now();
        self.metrics.total_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        debug!("Processing code request for {}", req.file_path);
        
        // Check pattern cache first
        if let Some(pattern) = self.pattern_cache.get(&req.context) {
            info!("Pattern cache hit for context: {}", req.context);
            self.metrics.pattern_cache_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            
            let response = self.apply_pattern(pattern, req).await;
            self.record_response_time(start.elapsed().as_secs_f64());
            return response;
        }
        
        // Analyze and learn
        let analysis = self.code_analyzer.analyze(&req).await;
        
        // Cache the pattern
        self.pattern_cache.insert(&req.context, analysis.pattern.clone());
        
        // Update project graph
        {
            let mut graph = self.project_graph.write().await;
            graph.add_file(PathBuf::from(&req.file_path), &req.content, &req.language).await;
        }
        
        // Learn from the pattern
        self.learn_pattern(req.context.clone(), analysis.pattern).await;
        
        self.metrics.successful_responses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.record_response_time(start.elapsed().as_secs_f64());
        
        analysis.response
    }

    async fn apply_pattern(&self, pattern: CodePattern, req: CodeRequest) -> CodeResponse {
        // Apply learned pattern to generate response
        CodeResponse {
            suggestion: format!("// Applied pattern: {:?}", pattern.pattern_type),
            confidence: 0.90,
            patterns_used: vec![format!("{:?}", pattern.pattern_type)],
            learning_applied: true,
        }
    }

    async fn learn_pattern(&self, context: String, pattern: CodePattern) {
        debug!("Learning new pattern for context: {}", context);
        
        // Update pattern frequency
        self.pattern_cache.update_frequency(&context, 1);
        
        // TODO: Update neural network embeddings
        // This would involve:
        // 1. Extracting features from the pattern
        // 2. Updating embedding weights
        // 3. Retraining style classifier
    }

    pub async fn create_session(&self, project_root: PathBuf) -> String {
        let session_id = uuid::Uuid::new_v4().to_string();
        
        let context = SessionContext {
            session_id: session_id.clone(),
            project_root,
            last_activity: std::time::Instant::now(),
            patterns_learned: 0,
            requests_processed: 0,
        };
        
        self.active_sessions.insert(session_id.clone(), context);
        info!("Created new session: {}", session_id);
        
        session_id
    }

    pub async fn end_session(&self, session_id: &str) {
        if let Some((_, context)) = self.active_sessions.remove(session_id) {
            info!(
                "Ended session {} - Patterns learned: {}, Requests: {}",
                session_id, context.patterns_learned, context.requests_processed
            );
        }
    }

    pub async fn get_project_insights(&self) -> ProjectInsights {
        let graph = self.project_graph.read().await;
        
        // Get hot patterns
        let hot_patterns = self.pattern_cache.get_hot_patterns(10);
        
        // Get recent patterns
        let recent_patterns = self.pattern_cache.get_recent_patterns(10);
        
        // Get refactoring suggestions
        let refactoring_suggestions = graph.suggest_refactoring(50).await;
        
        ProjectInsights {
            hot_patterns,
            recent_patterns,
            refactoring_suggestions,
            cache_stats: self.pattern_cache.stats(),
            memory_usage: self.get_memory_usage(),
        }
    }

    pub fn get_memory_usage(&self) -> MemoryUsage {
        let pool_used = self.memory_pool.used_memory();
        let pool_available = self.memory_pool.available_memory();
        
        MemoryUsage {
            total: MEMORY_SIZE,
            used: pool_used,
            available: pool_available,
            percentage: (pool_used as f64 / MEMORY_SIZE as f64) * 100.0,
            breakdown: MemoryBreakdown {
                project_graph: pool_used / 2, // Approximate
                pattern_cache: pool_used / 4,
                code_analyzer: pool_used / 8,
                active_requests: pool_used / 8,
            },
        }
    }

    pub fn get_performance_metrics(&self) -> PerformanceMetrics {
        let total = self.metrics.total_requests.load(std::sync::atomic::Ordering::Relaxed);
        let successful = self.metrics.successful_responses.load(std::sync::atomic::Ordering::Relaxed);
        let cache_hits = self.metrics.pattern_cache_hits.load(std::sync::atomic::Ordering::Relaxed);
        
        PerformanceMetrics {
            total_requests: total,
            successful_responses: successful,
            success_rate: if total > 0 { successful as f64 / total as f64 } else { 0.0 },
            pattern_cache_hit_rate: if total > 0 { cache_hits as f64 / total as f64 } else { 0.0 },
            average_response_time_ms: self.metrics.average_response_time.lock().average() * 1000.0,
        }
    }

    fn record_response_time(&self, time_secs: f64) {
        self.metrics.average_response_time.lock().add(time_secs);
    }

    pub async fn persist_patterns(&self, path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        self.pattern_cache.serialize_to_disk(&path)?;
        info!("Persisted patterns to {:?}", path);
        Ok(())
    }

    pub async fn load_patterns(&self, path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        self.pattern_cache.load_from_disk(&path)?;
        info!("Loaded patterns from {:?}", path);
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectInsights {
    pub hot_patterns: Vec<CodePattern>,
    pub recent_patterns: Vec<CodePattern>,
    pub refactoring_suggestions: Vec<crate::project_graph::RefactoringSuggestion>,
    pub cache_stats: crate::pattern_cache::CacheStatistics,
    pub memory_usage: MemoryUsage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryUsage {
    pub total: usize,
    pub used: usize,
    pub available: usize,
    pub percentage: f64,
    pub breakdown: MemoryBreakdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryBreakdown {
    pub project_graph: usize,
    pub pattern_cache: usize,
    pub code_analyzer: usize,
    pub active_requests: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub total_requests: u64,
    pub successful_responses: u64,
    pub success_rate: f64,
    pub pattern_cache_hit_rate: f64,
    pub average_response_time_ms: f64,
}

// Add uuid dependency
use uuid;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_analyzer::CodeIntent;

    #[tokio::test]
    async fn test_server_initialization() {
        let server = DevelopmentMCPServer::new(PathBuf::from("/tmp/test"));
        assert_eq!(server.get_memory_usage().total, MEMORY_SIZE);
    }

    #[tokio::test]
    async fn test_code_request_processing() {
        let server = DevelopmentMCPServer::new(PathBuf::from("/tmp/test"));
        
        let request = CodeRequest {
            file_path: "test.py".to_string(),
            content: "def hello():\n    pass".to_string(),
            context: "function_definition".to_string(),
            language: "python".to_string(),
            intent: CodeIntent::Complete,
        };
        
        let response = server.analyze_code_request(request).await;
        assert!(!response.suggestion.is_empty());
        assert!(response.learning_applied);
    }
}