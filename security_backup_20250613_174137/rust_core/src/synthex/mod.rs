// SYNTHEX - Synthetic Experience Search Engine Core
// High-performance search engine designed for AI agents

pub mod query_parser;
pub mod parallel_executor;
pub mod result_aggregator;
pub mod mcp_v2;
pub mod agents;
pub mod knowledge_graph;
pub mod python_bindings;

use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// Core SYNTHEX engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynthexConfig {
    /// Maximum parallel searches
    pub max_parallel_searches: usize,
    /// Connection pool size per domain
    pub connection_pool_size: usize,
    /// Cache size in MB
    pub cache_size_mb: usize,
    /// Query timeout in milliseconds
    pub query_timeout_ms: u64,
    /// Enable query optimization
    pub enable_query_optimization: bool,
    /// MCP v2 protocol settings
    pub mcp_v2_config: McpV2Config,
}

impl Default for SynthexConfig {
    fn default() -> Self {
        Self {
            max_parallel_searches: 10000,
            connection_pool_size: 100,
            cache_size_mb: 4096,
            query_timeout_ms: 5000,
            enable_query_optimization: true,
            mcp_v2_config: McpV2Config::default(),
        }
    }
}

/// MCP v2 Protocol Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpV2Config {
    /// Enable compression
    pub compression: bool,
    /// Max message size
    pub max_message_size: usize,
    /// Connection timeout
    pub connection_timeout_ms: u64,
    /// Enable multiplexing
    pub enable_multiplexing: bool,
}

impl Default for McpV2Config {
    fn default() -> Self {
        Self {
            compression: true,
            max_message_size: 10 * 1024 * 1024, // 10MB
            connection_timeout_ms: 1000,
            enable_multiplexing: true,
        }
    }
}

/// Main SYNTHEX engine
pub struct SynthexEngine {
    config: Arc<SynthexConfig>,
    query_parser: Arc<query_parser::QueryParser>,
    executor: Arc<parallel_executor::ParallelExecutor>,
    aggregator: Arc<result_aggregator::ResultAggregator>,
    knowledge_graph: Arc<RwLock<knowledge_graph::KnowledgeGraph>>,
    search_agents: Arc<RwLock<HashMap<String, Arc<dyn agents::SearchAgent>>>>,
}

impl SynthexEngine {
    /// Create new SYNTHEX engine instance
    pub async fn new(config: SynthexConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let config = Arc::new(config);
        
        Ok(Self {
            config: config.clone(),
            query_parser: Arc::new(query_parser::QueryParser::new(config.clone())?),
            executor: Arc::new(parallel_executor::ParallelExecutor::new(config.clone())?),
            aggregator: Arc::new(result_aggregator::ResultAggregator::new(config.clone())?),
            knowledge_graph: Arc::new(RwLock::new(knowledge_graph::KnowledgeGraph::new())),
            search_agents: Arc::new(RwLock::new(HashMap::new())),
        })
    }
    
    /// Execute a search query
    pub async fn search(&self, query: &str) -> Result<SearchResult, Box<dyn std::error::Error>> {
        // Parse query into optimized execution plan
        let execution_plan = self.query_parser.parse(query).await?;
        
        // Execute searches in parallel
        let raw_results = self.executor.execute(execution_plan).await?;
        
        // Aggregate and rank results
        let aggregated_results = self.aggregator.aggregate(raw_results).await?;
        
        // Update knowledge graph with new information
        self.update_knowledge_graph(&aggregated_results).await?;
        
        Ok(aggregated_results)
    }
    
    /// Register a new search agent
    pub async fn register_agent(&self, name: String, agent: Arc<dyn agents::SearchAgent>) {
        let mut agents = self.search_agents.write().await;
        agents.insert(name, agent);
    }
    
    /// Update knowledge graph with search results
    async fn update_knowledge_graph(&self, results: &SearchResult) -> Result<(), Box<dyn std::error::Error>> {
        let mut graph = self.knowledge_graph.write().await;
        graph.update_from_results(results)?;
        Ok(())
    }
}

/// Search result structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    /// Query ID for tracking
    pub query_id: String,
    /// Total results found
    pub total_results: usize,
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
    /// Grouped results by category
    pub results: Vec<ResultGroup>,
    /// Metadata about the search
    pub metadata: SearchMetadata,
}

/// Grouped search results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultGroup {
    /// Category name
    pub category: String,
    /// Relevance score (0-1)
    pub relevance: f64,
    /// Individual results
    pub items: Vec<ResultItem>,
}

/// Individual search result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultItem {
    /// Unique identifier
    pub id: String,
    /// Result title
    pub title: String,
    /// Content snippet
    pub snippet: String,
    /// Source URL or identifier
    pub source: String,
    /// Relevance score
    pub score: f64,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Search metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchMetadata {
    /// Sources searched
    pub sources_searched: Vec<String>,
    /// Query optimizations applied
    pub optimizations_applied: Vec<String>,
    /// Cache hit rate
    pub cache_hit_rate: f64,
    /// Parallel searches executed
    pub parallel_searches: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_engine_creation() {
        let config = SynthexConfig::default();
        let engine = SynthexEngine::new(config).await.unwrap();
        assert!(engine.search_agents.read().await.is_empty());
    }
}