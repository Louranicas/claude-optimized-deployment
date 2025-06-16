//! SYNTHEX Service Layer
//! 
//! Service implementation that bridges the Rust engine with Python API

use crate::synthex::{
    SynthexEngine, SynthexConfig, SearchQuery, SearchResult, 
    AgentHealth, Result, SynthexServiceTrait,
    agents::SearchAgent,
};
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;


/// SYNTHEX service implementation
pub struct SynthexServiceImpl {
    /// Core engine
    engine: Arc<RwLock<SynthexEngine>>,
    /// Service configuration
    config: Arc<SynthexConfig>,
    /// Runtime handle
    runtime: Arc<tokio::runtime::Runtime>,
}

impl SynthexServiceImpl {
    /// Create a new service instance
    pub fn new(config: SynthexConfig) -> Result<Self> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| crate::synthex::SynthexError::IoError(e.to_string()))?;
        
        let engine = runtime.block_on(async {
            SynthexEngine::new(config.clone()).await
        })?;
        
        Ok(Self {
            engine: Arc::new(RwLock::new(engine)),
            config: Arc::new(config),
            runtime: Arc::new(runtime),
        })
    }
    
    /// Get the runtime handle
    pub fn runtime(&self) -> &tokio::runtime::Runtime {
        &self.runtime
    }
}

#[async_trait::async_trait]
impl SynthexServiceTrait for SynthexServiceImpl {
    async fn initialize(&self) -> Result<()> {
        let mut engine = self.engine.write().await;
        engine.initialize().await
    }
    
    async fn search(&self, query: SearchQuery) -> Result<SearchResult> {
        let engine = self.engine.read().await;
        engine.search(query).await
    }
    
    async fn register_agent(&self, name: String, agent: Arc<dyn SearchAgent>) -> Result<()> {
        let engine = self.engine.read().await;
        engine.register_agent(name, agent).await
    }
    
    async fn get_agent_status(&self) -> Result<HashMap<String, AgentHealth>> {
        let engine = self.engine.read().await;
        engine.get_agent_status().await
    }
    
    async fn update_knowledge_graph(&self, _results: &SearchResult) -> Result<()> {
        // TODO: Implement knowledge graph update
        Ok(())
    }
    
    async fn shutdown(&self) -> Result<()> {
        let mut engine = self.engine.write().await;
        engine.shutdown().await
    }
}

/// Factory function to create a SYNTHEX service
pub async fn create_synthex_service(config: SynthexConfig) -> Result<Arc<dyn SynthexServiceTrait>> {
    let service = SynthexServiceImpl::new(config)?;
    service.initialize().await?;
    Ok(Arc::new(service))
}


#[cfg(test)]
mod tests {
    use super::*;
use crate::synthex::query::SubQuery;
    
    #[tokio::test]
    async fn test_service_creation() {
        let config = SynthexConfig::default();
        let service = create_synthex_service(config).await.unwrap();
        let status = service.get_agent_status().await.unwrap();
        assert!(status.is_empty());
    }
}