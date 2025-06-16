//! SYNTHEX Engine Implementation
//! 
//! Core search engine with agent coordination and result aggregation

use crate::synthex::{
    agents::{SearchAgent},
    config::SynthexConfig,
    query::{SearchQuery},
    Result, SearchResult, AgentHealth, AgentHealthStatus,
    SynthexStats, CacheEntry, utils, constants,
};
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use chrono::{ Utc, Duration};
use uuid::Uuid;
use std::time::Instant;


/// Core SYNTHEX search engine
pub struct SynthexEngine {
    /// Engine configuration
    config: Arc<SynthexConfig>,
    /// Registered search agents
    agents: Arc<RwLock<HashMap<String, Arc<dyn SearchAgent>>>>,
    /// Agent health tracking
    agent_health: Arc<DashMap<String, AgentHealth>>,
    /// Result cache
    cache: Arc<DashMap<String, CacheEntry>>,
    /// Engine statistics
    stats: Arc<RwLock<SynthexStats>>,
    /// Health check task handle
    health_check_handle: Option<tokio::task::JoinHandle<()>>,
}

impl SynthexEngine {
    /// Create a new SYNTHEX engine
    pub async fn new(config: SynthexConfig) -> Result<Self> {
        let engine = Self {
            config: Arc::new(config),
            agents: Arc::new(RwLock::new(HashMap::new())),
            agent_health: Arc::new(DashMap::new()),
            cache: Arc::new(DashMap::new()),
            stats: Arc::new(RwLock::new(SynthexStats::default())),
            health_check_handle: None,
        };
        
        Ok(engine)
    }
    
    /// Initialize the engine and start background tasks
    pub async fn initialize(&mut self) -> Result<()> {
        // Start health check task
        let agents = self.agents.clone();
        let health = self.agent_health.clone();
        let interval = constants::HEALTH_CHECK_INTERVAL_SECONDS;
        
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval));
            loop {
                interval.tick().await;
                Self::check_agent_health(&agents, &health).await;
            }
        });
        
        self.health_check_handle = Some(handle);
        
        Ok(())
    }
    
    /// Register a search agent
    pub async fn register_agent(&self, name: String, agent: Arc<dyn SearchAgent>) -> Result<()> {
        let mut agents = self.agents.write().await;
        
        // Initialize agent health
        self.agent_health.insert(
            name.clone(),
            AgentHealth {
                status: AgentHealthStatus::Initializing,
                last_check: Utc::now(),
                consecutive_failures: 0,
                error_message: None,
                response_time_ms: None,
            },
        );
        
        agents.insert(name, agent);
        Ok(())
    }
    
    /// Perform a search across all registered agents
    pub async fn search(&self, query: SearchQuery) -> Result<SearchResult> {
        let start_time = Instant::now();
        let query_id = Uuid::new_v4().to_string();
        
        // Check cache first
        if query.options.enable_cache {
            let cache_key = utils::generate_query_id(&query.query, &query.options);
            if let Some(mut entry) = self.cache.get_mut(&cache_key) {
                // Check if cache entry is still valid
                let age = Utc::now() - entry.timestamp;
                if age < Duration::seconds(constants::CACHE_TTL_SECONDS) {
                    entry.hit_count += 1;
                    let mut stats = self.stats.write().await;
                    stats.cache_hits += 1;
                    return Ok(entry.result.clone());
                }
            }
        }
        
        // Get healthy agents
        let agents = self.agents.read().await;
        let mut search_tasks = Vec::new();
        
        for (name, agent) in agents.iter() {
            // Check if agent is healthy
            if let Some(health) = self.agent_health.get(name) {
                if health.status == AgentHealthStatus::Failed {
                    continue;
                }
            }
            
            // Check if this agent type is enabled
            if !self.should_use_agent(name, &query.options.sources) {
                continue;
            }
            
            let agent = agent.clone();
            let query_clone = query.clone();
            let name_clone = name.clone();
            
            let task = tokio::spawn(async move {
                let agent_start = Instant::now();
                let result = agent.search(query_clone).await;
                let duration = agent_start.elapsed().as_millis() as u64;
                (name_clone, result, duration)
            });
            
            search_tasks.push(task);
        }
        
        // Execute searches with timeout
        let timeout = tokio::time::Duration::from_millis(query.options.timeout_ms);
        let results = tokio::time::timeout(timeout, futures::future::join_all(search_tasks))
            .await
            .map_err(|_| crate::synthex::SynthexError::TimeoutError(query.options.timeout_ms))?;
        
        // Aggregate results
        let mut all_items = Vec::new();
        let mut sources_searched = Vec::new();
        let mut total_errors = 0;
        
        for result in results {
            match result {
                Ok((agent_name, Ok(items), duration)) => {
                    sources_searched.push(agent_name.clone());
                    all_items.extend(items);
                    
                    // Update agent health
                    if let Some(mut health) = self.agent_health.get_mut(&agent_name) {
                        health.status = AgentHealthStatus::Healthy;
                        health.last_check = Utc::now();
                        health.consecutive_failures = 0;
                        health.response_time_ms = Some(duration);
                    }
                }
                Ok((agent_name, Err(e), _)) => {
                    total_errors += 1;
                    
                    // Update agent health
                    if let Some(mut health) = self.agent_health.get_mut(&agent_name) {
                        health.consecutive_failures += 1;
                        health.error_message = Some(e.to_string());
                        health.last_check = Utc::now();
                        
                        if health.consecutive_failures >= 3 {
                            health.status = AgentHealthStatus::Failed;
                        } else {
                            health.status = AgentHealthStatus::Degraded;
                        }
                    }
                }
                Err(e) => {
                    total_errors += 1;
                    eprintln!("Task join error: {}", e);
                }
            }
        }
        
        // Sort and limit results
        all_items.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        all_items.truncate(query.options.max_results);
        
        let execution_time_ms = start_time.elapsed().as_millis() as u64;
        
        let result = SearchResult {
            query_id,
            total_results: all_items.len(),
            execution_time_ms,
            results: all_items,
            metadata: HashMap::from([
                ("sources_searched".to_string(), serde_json::json!(sources_searched)),
                ("errors".to_string(), serde_json::json!(total_errors)),
                ("cache_hit".to_string(), serde_json::json!(false)),
            ]),
        };
        
        // Update cache
        if query.options.enable_cache {
            let cache_key = utils::generate_query_id(&query.query, &query.options);
            self.cache.insert(
                cache_key,
                CacheEntry {
                    result: result.clone(),
                    timestamp: Utc::now(),
                    hit_count: 0,
                },
            );
            
            // Clean old cache entries
            self.clean_cache().await;
        }
        
        // Update statistics
        let mut stats = self.stats.write().await;
        stats.total_searches += 1;
        if total_errors == 0 {
            stats.successful_searches += 1;
        } else {
            stats.failed_searches += 1;
        }
        stats.cache_misses += 1;
        stats.active_agents = agents.len();
        
        // Update average response time
        let total_time = stats.average_response_time_ms * (stats.total_searches - 1) as f64;
        stats.average_response_time_ms = (total_time + execution_time_ms as f64) / stats.total_searches as f64;
        
        Ok(result)
    }
    
    /// Get the status of all registered agents
    pub async fn get_agent_status(&self) -> Result<HashMap<String, AgentHealth>> {
        let mut status = HashMap::new();
        
        for item in self.agent_health.iter() {
            status.insert(item.key().clone(), item.value().clone());
        }
        
        Ok(status)
    }
    
    /// Get engine statistics
    pub async fn get_stats(&self) -> Result<SynthexStats> {
        Ok(self.stats.read().await.clone())
    }
    
    /// Shutdown the engine
    pub async fn shutdown(&mut self) -> Result<()> {
        // Stop health check task
        if let Some(handle) = self.health_check_handle.take() {
            handle.abort();
        }
        
        // Shutdown all agents
        let agents = self.agents.read().await;
        for (_, agent) in agents.iter() {
            if let Err(e) = agent.shutdown().await {
                eprintln!("Error shutting down agent: {}", e);
            }
        }
        
        Ok(())
    }
    
    /// Check if an agent should be used based on sources filter
    fn should_use_agent(&self, agent_name: &str, sources: &[String]) -> bool {
        if sources.is_empty() || sources.contains(&"all".to_string()) {
            return true;
        }
        
        // Map agent names to source types
        let agent_type = match agent_name {
            name if name.contains("web") => "web",
            name if name.contains("database") => "database",
            name if name.contains("api") => "api",
            name if name.contains("file") => "file",
            name if name.contains("knowledge") => "knowledge",
            _ => return false,
        };
        
        sources.iter().any(|s| s == agent_type)
    }
    
    /// Check health of all agents
    async fn check_agent_health(
        agents: &Arc<RwLock<HashMap<String, Arc<dyn SearchAgent>>>>,
        health: &Arc<DashMap<String, AgentHealth>>
    ) {
        let agents = agents.read().await;
        
        for (name, agent) in agents.iter() {
            match agent.get_status().await {
                Ok(status) => {
                    if let Some(mut health_entry) = health.get_mut(name) {
                        health_entry.status = if status.healthy {
                            AgentHealthStatus::Healthy
                        } else {
                            AgentHealthStatus::Degraded
                        };
                        health_entry.last_check = Utc::now();
                        health_entry.error_message = None;
                    }
                }
                Err(e) => {
                    if let Some(mut health_entry) = health.get_mut(name) {
                        health_entry.consecutive_failures += 1;
                        health_entry.error_message = Some(e.to_string());
                        health_entry.last_check = Utc::now();
                        
                        if health_entry.consecutive_failures >= 3 {
                            health_entry.status = AgentHealthStatus::Failed;
                        }
                    }
                }
            }
        }
    }
    
    /// Clean old cache entries
    async fn clean_cache(&self) {
        let now = Utc::now();
        let ttl = Duration::seconds(constants::CACHE_TTL_SECONDS);
        
        self.cache.retain(|_, entry| {
            now - entry.timestamp < ttl
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
use crate::synthex::query::SubQuery;
    use crate::synthex::agents::MockAgent;
    
    #[tokio::test]
    async fn test_engine_creation() {
        let config = SynthexConfig::default();
        let mut engine = SynthexEngine::new(config).await.unwrap();
        assert!(engine.initialize().await.is_ok());
        assert!(engine.shutdown().await.is_ok());
    }
    
    #[tokio::test]
    async fn test_agent_registration() {
        let config = SynthexConfig::default();
        let engine = SynthexEngine::new(config).await.unwrap();
        
        let mock_agent = Arc::new(MockAgent::new());
        assert!(engine.register_agent("test_agent".to_string(), mock_agent).await.is_ok());
        
        let status = engine.get_agent_status().await.unwrap();
        assert!(status.contains_key("test_agent"));
    }
}