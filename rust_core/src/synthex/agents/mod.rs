use crate::synthex::Result;
// Search Agents - Specialized agents for different data sources
pub mod web_agent;
pub mod database_agent;
pub mod api_agent;
pub mod file_agent;
pub mod knowledge_base_agent;

#[cfg(test)]
pub mod mock_agent;

use super::*;

use async_trait::async_trait;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};

/// Raw search result from an agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawResult {
    pub content: String,
    pub metadata: HashMap<String, serde_json::Value>,
    pub score: f64,
    pub timestamp: u64,
}

/// Base trait for all search agents
#[async_trait]
pub trait SearchAgent: Send + Sync {
    /// Get agent name
    fn name(&self) -> &str;
    
    /// Get supported query types
    fn supported_queries(&self) -> Vec<QueryType>;
    
    /// Execute search
    async fn search(
        &self,
        query: &str,
        options: SearchOptions,
    ) -> Result<Vec<RawResult>>;
    
    /// Check agent health
    async fn health_check(&self) -> Result<HealthStatus>;
    
    /// Get agent metrics
    fn get_metrics(&self) -> AgentMetrics;
}

/// Query types supported by agents
#[derive(Debug, Clone, PartialEq)]
pub enum QueryType {
    FullText,
    Semantic,
    Structured,
    Regex,
    Fuzzy,
}

/// Search options
#[derive(Debug, Clone)]
pub struct SearchOptions {
    pub max_results: usize,
    pub timeout_ms: u64,
    pub include_metadata: bool,
    pub filters: HashMap<String, String>,
}

impl Default for SearchOptions {
    fn default() -> Self {
        Self {
            max_results: 100,
            timeout_ms: 5000,
            include_metadata: true,
            filters: HashMap::new(),
        }
    }
}

/// Agent health status
#[derive(Debug, Clone)]
pub struct HealthStatus {
    pub healthy: bool,
    pub latency_ms: u64,
    pub error_rate: f64,
    pub last_check: u64,
}

/// Agent performance metrics
#[derive(Debug, Clone, Default)]
pub struct AgentMetrics {
    pub total_searches: u64,
    pub successful_searches: u64,
    pub failed_searches: u64,
    pub avg_latency_ms: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

/// Agent registry for managing search agents
pub struct AgentRegistry {
    agents: Arc<RwLock<HashMap<String, Arc<dyn SearchAgent>>>>,
    config: Arc<SynthexConfig>,
}

impl AgentRegistry {
    pub fn new(config: Arc<SynthexConfig>) -> Self {
        Self {
            agents: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }
    
    /// Register a search agent
    pub async fn register(&self, agent: Arc<dyn SearchAgent>) -> Result<()> {
        let name = agent.name().to_string();
        let mut agents = self.agents.write().await;
        agents.insert(name, agent);
        Ok(())
    }
    
    /// Get agent by name
    pub async fn get(&self, name: &str) -> Option<Arc<dyn SearchAgent>> {
        let agents = self.agents.read().await;
        agents.get(name).cloned()
    }
    
    /// List all registered agents
    pub async fn list(&self) -> Vec<String> {
        let agents = self.agents.read().await;
        agents.keys().cloned().collect()
    }
    
    /// Run health checks on all agents
    pub async fn health_check_all(&self) -> HashMap<String, HealthStatus> {
        let agents = self.agents.read().await;
        let mut health_results = HashMap::new();
        
        for (name, agent) in agents.iter() {
            match agent.health_check().await {
                Ok(status) => {
                    health_results.insert(name.clone(), status);
                }
                Err(e) => {
                    health_results.insert(name.clone(), HealthStatus {
                        healthy: false,
                        latency_ms: 0,
                        error_rate: 1.0,
                        last_check: chrono::Utc::now().timestamp_millis() as u64,
                    });
                    eprintln!("Health check failed for {}: {}", name, e);
                }
            }
        }
        
        health_results
    }
}

// Re-export agent implementations
pub use web_agent::WebSearchAgent;
pub use database_agent::DatabaseSearchAgent;
pub use api_agent::ApiSearchAgent;
pub use file_agent::FileSearchAgent;
pub use knowledge_base_agent::KnowledgeBaseAgent;

#[cfg(test)]
pub use mock_agent::MockAgent;

/// Agent types for categorization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentType {
    WebSearch,
    DatabaseSearch,
    ApiSearch,
    FileSearch,
    KnowledgeBase,
    Custom(u32),
}

/// Agent status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatus {
    pub healthy: bool,
    pub latency_ms: u64,
    pub error_rate: f32,
    pub last_check: String,
    pub metrics: HashMap<String, serde_json::Value>,
}
