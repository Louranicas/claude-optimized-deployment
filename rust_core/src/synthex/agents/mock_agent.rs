use crate::synthex::Result;
/// Mock agent implementation for testing

use super::*;
use crate::synthex::query::SubQuery;
use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Mock search agent for testing
pub struct MockAgent {
    name: String,
    total_searches: Arc<AtomicU64>,
    should_fail: bool,
    latency_ms: u64,
}

impl MockAgent {
    /// Create a new mock agent
    pub fn new() -> Self {
        Self {
            name: "mock_agent".to_string(),
            total_searches: Arc::new(AtomicU64::new(0)),
            should_fail: false,
            latency_ms: 10,
        }
    }
    
    /// Create a mock agent with custom name
    pub fn with_name(name: String) -> Self {
        Self {
            name,
            total_searches: Arc::new(AtomicU64::new(0)),
            should_fail: false,
            latency_ms: 10,
        }
    }
    
    /// Configure agent to fail
    pub fn set_should_fail(&mut self, should_fail: bool) {
        self.should_fail = should_fail;
    }
    
    /// Set simulated latency
    pub fn set_latency(&mut self, latency_ms: u64) {
        self.latency_ms = latency_ms;
    }
}

#[async_trait]
impl SearchAgent for MockAgent {
    fn name(&self) -> &str {
        &self.name
    }
    
    fn supported_queries(&self) -> Vec<QueryType> {
        vec![QueryType::FullText, QueryType::Semantic]
    }
    
    async fn search(
        &self,
        query: &str,
        options: SearchOptions,
    ) -> Result<Vec<RawResult>> {
        // Simulate latency
        tokio::time::sleep(tokio::time::Duration::from_millis(self.latency_ms)).await;
        
        self.total_searches.fetch_add(1, Ordering::Relaxed);
        
        if self.should_fail {
            return Err(crate::synthex::SynthexError::SearchError("Mock agent configured to fail".to_string()));
        }
        
        // Return mock results
        Ok(vec![
            RawResult {
                content: format!("Mock Result 1 for: {}", query),
                metadata: HashMap::from([
                    ("mock".to_string(), serde_json::json!(true)),
                    ("query".to_string(), serde_json::json!(query)),
                ]),
                score: 0.95,
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
            },
            RawResult {
                content: format!("Mock Result 2 for: {}", query),
                metadata: HashMap::from([
                    ("mock".to_string(), serde_json::json!(true)),
                    ("index".to_string(), serde_json::json!(2)),
                ]),
                score: 0.85,
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
            },
        ])
    }
    
    async fn health_check(&self) -> Result<HealthStatus> {
        Ok(HealthStatus {
            healthy: !self.should_fail,
            latency_ms: self.latency_ms,
            error_rate: if self.should_fail { 1.0 } else { 0.0 },
            last_check: chrono::Utc::now().timestamp_millis() as u64,
        })
    }
    
    fn get_metrics(&self) -> AgentMetrics {
        AgentMetrics {
            total_searches: self.total_searches.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release,
            successful_searches: if self.should_fail { 0 } else { self.total_searches.load(Ordering::Relaxed)} // TODO: Review memory ordering - consider Acquire/Release,
            failed_searches: if self.should_fail { self.total_searches.load(Ordering::Relaxed)} // TODO: Review memory ordering - consider Acquire/Release else { 0 },
            avg_latency_ms: self.latency_ms,
            cache_hits: 0,
            cache_misses: 0,
        }
    }
}
