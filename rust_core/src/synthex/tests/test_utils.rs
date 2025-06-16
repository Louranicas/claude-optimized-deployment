//! Test utilities for SYNTHEX test suite

use std::sync::Arc;
use tokio::sync::RwLock;
use crate::synthex::{
    config::SynthexConfig,
    engine::SynthexEngine,
    query::{Query, QueryBuilder},
    agents::{Agent, AgentCapabilities},
};

/// Create a test configuration with default values
pub fn test_config() -> SynthexConfig {
    SynthexConfig {
        max_concurrent_agents: 5,
        cache_size: 100,
        timeout_seconds: 10,
        enable_ml_optimization: false,
        enable_gpu_acceleration: false,
        max_retries: 3,
        batch_size: 10,
        memory_limit_mb: 512,
    }
}

/// Create a test engine with mock agents
pub async fn test_engine() -> Arc<RwLock<SynthexEngine>> {
    let config = test_config();
    let engine = SynthexEngine::new(config).await.unwrap();
    Arc::new(RwLock::new(engine))
}

/// Generate test queries
pub fn test_queries() -> Vec<Query> {
    vec![
        QueryBuilder::new("test query 1")
            .with_context("test context")
            .with_max_results(10)
            .build(),
        QueryBuilder::new("complex AND query OR test")
            .with_filters(vec!["type:documentation".to_string()])
            .with_timeout(5)
            .build(),
        QueryBuilder::new("performance test query")
            .with_parallel_execution(true)
            .with_max_results(100)
            .build(),
    ]
}

/// Mock agent for testing
pub struct MockTestAgent {
    id: String,
    response_delay_ms: u64,
    should_fail: bool,
}

impl MockTestAgent {
    pub fn new(id: String) -> Self {
        Self {
            id,
            response_delay_ms: 0,
            should_fail: false,
        }
    }
    
    pub fn with_delay(mut self, delay_ms: u64) -> Self {
        self.response_delay_ms = delay_ms;
        self
    }
    
    pub fn with_failure(mut self) -> Self {
        self.should_fail = true;
        self
    }
}

#[async_trait::async_trait]
impl Agent for MockTestAgent {
    fn id(&self) -> &str {
        &self.id
    }
    
    fn capabilities(&self) -> &AgentCapabilities {
        &AgentCapabilities {
            can_search: true,
            can_analyze: true,
            can_transform: false,
            supported_formats: vec!["text".to_string()],
            max_concurrent_requests: 10,
        }
    }
    
    async fn execute(&self, query: &Query) -> Result<Vec<crate::synthex::SearchResult>, crate::synthex::SynthexError> {
        if self.should_fail {
            return Err(crate::synthex::SynthexError::AgentError(
                format!("Mock agent {} failed as configured", self.id)
            ));
        }
        
        if self.response_delay_ms > 0 {
            tokio::time::sleep(tokio::time::Duration::from_millis(self.response_delay_ms)).await;
        }
        
        Ok(vec![
            crate::synthex::SearchResult {
                content: format!("Mock result from {} for query: {}", self.id, query.text),
                relevance: 0.9,
                source: self.id.clone(),
                metadata: std::collections::HashMap::new(),
            }
        ])
    }
}

/// Performance measurement helper
pub struct PerfMeasure {
    start: std::time::Instant,
    name: String,
}

impl PerfMeasure {
    pub fn new(name: &str) -> Self {
        Self {
            start: std::time::Instant::now(),
            name: name.to_string(),
        }
    }
    
    pub fn elapsed_ms(&self) -> u128 {
        self.start.elapsed().as_millis()
    }
    
    pub fn report(&self) {
        println!("{}: {}ms", self.name, self.elapsed_ms());
    }
}

impl Drop for PerfMeasure {
    fn drop(&mut self) {
        self.report();
    }
}

/// Assert that a future completes within a timeout
pub async fn assert_completes_within<F, T>(
    future: F,
    timeout_ms: u64,
    message: &str,
) -> T
where
    F: std::future::Future<Output = T>,
{
    tokio::time::timeout(
        tokio::time::Duration::from_millis(timeout_ms),
        future
    )
    .await
    .expect(message)
}

/// Generate large dataset for performance testing
pub fn generate_test_dataset(size: usize) -> Vec<String> {
    (0..size)
        .map(|i| format!("Test document {} with content for performance testing", i))
        .collect()
}