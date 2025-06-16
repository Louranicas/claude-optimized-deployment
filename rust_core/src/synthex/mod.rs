// SYNTHEX - Synthetic Experience Search Engine Core
// High-performance search engine designed for AI agents

pub mod query_parser;
pub mod parallel_executor;
pub mod result_aggregator;
pub mod mcp_v2;
pub mod agents;
pub mod knowledge_graph;
pub mod python_bindings;
pub mod performance_optimizer;
pub mod bashgod_optimizer;
pub mod config;
pub mod query;
pub mod engine;
pub mod service;

#[cfg(test)]
mod test_compilation;

#[cfg(test)]
mod tests;

use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

// Re-export key types
pub use config::SynthexConfig;
pub use query::{SearchQuery, QueryOptions};
pub use engine::SynthexEngine;
pub use service::{SynthexServiceImpl, create_synthex_service};
pub use query_parser::{ExecutionPlan, ExecutionStrategy};

/// Result type for SYNTHEX operations
pub type Result<T> = std::result::Result<T, SynthexError>;

/// SYNTHEX-specific errors
#[derive(Error, Debug, Clone)]
pub enum SynthexError {
    #[error("Search error: {0}")]
    SearchError(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("Agent error: {0}")]
    AgentError(String),
    
    #[error("Security error: {0}")]
    SecurityError(String),
    
    #[error("Rate limit exceeded")]
    RateLimitError,
    
    #[error("Timeout error: operation took longer than {0}ms")]
    TimeoutError(u64),
    
    #[error("IO error: {0}")]
    IoError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Python interop error: {0}")]
    PythonError(String),
}

/// Search result returned by SYNTHEX
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub query_id: String,
    pub total_results: usize,
    pub execution_time_ms: u64,
    pub results: Vec<SearchItem>,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Individual search result item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchItem {
    pub id: String,
    pub title: String,
    pub content: String,
    pub url: Option<String>,
    pub score: f32,
    pub source: String,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Agent health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentHealthStatus {
    Healthy,
    Degraded,
    Failed,
    Initializing,
}

/// Agent health information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHealth {
    pub status: AgentHealthStatus,
    pub last_check: DateTime<Utc>,
    pub consecutive_failures: u32,
    pub error_message: Option<String>,
    pub response_time_ms: Option<u64>,
}

/// Main trait for SYNTHEX services
#[async_trait]
pub trait SynthexServiceTrait: Send + Sync {
    async fn initialize(&self) -> Result<()>;
    async fn search(&self, query: SearchQuery) -> Result<SearchResult>;
    async fn register_agent(&self, name: String, agent: Arc<dyn agents::SearchAgent>) -> Result<()>;
    async fn get_agent_status(&self) -> Result<HashMap<String, AgentHealth>>;
    async fn update_knowledge_graph(&self, results: &SearchResult) -> Result<()>;
    async fn shutdown(&self) -> Result<()>;
}

/// Statistics for SYNTHEX operations
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SynthexStats {
    pub total_searches: u64,
    pub successful_searches: u64,
    pub failed_searches: u64,
    pub average_response_time_ms: f64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub active_agents: usize,
}

/// Cache entry for search results
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub result: SearchResult,
    pub timestamp: DateTime<Utc>,
    pub hit_count: u32,
}

/// Utility functions for SYNTHEX
pub mod utils {
    use super::*;
use crate::synthex::query::SubQuery;
    use sha2::{Sha256, Digest};
    
    pub fn generate_query_id(query: &str, options: &query::QueryOptions) -> String {
        let mut hasher = Sha256::new();
        hasher.update(query.as_bytes());
        hasher.update(format!("{:?}", options).as_bytes());
        format!("{:x}", hasher.finalize())
    }
    
    pub fn sanitize_query(query: &str) -> String {
        query
            .chars()
            .filter(|c| c.is_alphanumeric() || c.is_whitespace() || "-_.!?".contains(*c))
            .collect::<String>()
            .trim()
            .to_string()
    }
}

/// Constants for SYNTHEX
pub mod constants {
    pub const DEFAULT_CACHE_SIZE_MB: usize = 4096;
    pub const DEFAULT_QUERY_TIMEOUT_MS: u64 = 5000;
    pub const MAX_CONCURRENT_SEARCHES: usize = 10000;
    pub const CACHE_TTL_SECONDS: i64 = 3600;
    pub const MAX_RESULTS_PER_SEARCH: usize = 1000;
    pub const HEALTH_CHECK_INTERVAL_SECONDS: u64 = 60;
}

// Re-export McpV2Config from config module
pub use config::McpV2Config;

// Legacy types for backwards compatibility
pub use query_parser::QueryParser;
pub use parallel_executor::ParallelExecutor;
pub use result_aggregator::ResultAggregator;

/// Grouped search results (legacy format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultGroup {
    pub category: String,
    pub relevance: f64,
    pub items: Vec<ResultItem>,
}

/// Individual search result (legacy format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultItem {
    pub id: String,
    pub title: String,
    pub snippet: String,
    pub source: String,
    pub score: f64,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Search metadata (legacy format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchMetadata {
    pub sources_searched: Vec<String>,
    pub optimizations_applied: Vec<String>,
    pub cache_hit_rate: f64,
    pub parallel_searches: usize,
}
impl From<&str> for SynthexError {
    fn from(s: &str) -> Self {
        SynthexError::SearchError(s.to_string())
    }
}

impl From<String> for SynthexError {
    fn from(s: String) -> Self {
        SynthexError::SearchError(s)
    }
}

impl From<std::io::Error> for SynthexError {
    fn from(e: std::io::Error) -> Self {
        SynthexError::IoError(e.to_string())
    }
}

impl From<serde_json::Error> for SynthexError {
    fn from(e: serde_json::Error) -> Self {
        SynthexError::SerializationError(e.to_string())
    }
}

impl From<reqwest::Error> for SynthexError {
    fn from(e: reqwest::Error) -> Self {
        SynthexError::SearchError(format!("HTTP error: {}", e))
    }
}

impl From<tokio::sync::AcquireError> for SynthexError {
    fn from(_: tokio::sync::AcquireError) -> Self {
        SynthexError::SearchError("Failed to acquire semaphore".to_string())
    }
}

impl From<walkdir::Error> for SynthexError {
    fn from(e: walkdir::Error) -> Self {
        SynthexError::IoError(format!("Directory walk error: {}", e))
    }
}

impl From<regex::Error> for SynthexError {
    fn from(e: regex::Error) -> Self {
        SynthexError::SearchError(format!("Regex error: {}", e))
    }
}

impl From<grep::regex::Error> for SynthexError {
    fn from(e: grep::regex::Error) -> Self {
        SynthexError::SearchError(format!("Grep error: {}", e))
    }
}

impl From<sqlx::Error> for SynthexError {
    fn from(e: sqlx::Error) -> Self {
        SynthexError::SearchError(format!("Database error: {}", e))
    }
}

impl From<tokio::time::error::Elapsed> for SynthexError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        SynthexError::TimeoutError(5000) // Default timeout
    }
}
