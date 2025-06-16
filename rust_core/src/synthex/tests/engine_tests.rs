//! Tests for SYNTHEX engine core functionality

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use crate::synthex::{
        engine::SynthexEngine,
        config::SynthexConfig,
        query::QueryBuilder,
        agents::*,
        SynthexError,
    };
    use super::super::test_utils::*;
    
    #[tokio::test]
    async fn test_engine_initialization() {
        let config = test_config();
        let engine = SynthexEngine::new(config).await.unwrap();
        
        assert_eq!(engine.agent_count(), 0); // No agents registered yet
        assert!(engine.is_ready());
    }
    
    #[tokio::test]
    async fn test_engine_agent_registration() {
        let engine = test_engine().await;
        let mut engine_guard = engine.write().await;
        
        let agent1 = Box::new(MockTestAgent::new("agent1".to_string()));
        let agent2 = Box::new(MockTestAgent::new("agent2".to_string()));
        
        engine_guard.register_agent(agent1).await.unwrap();
        engine_guard.register_agent(agent2).await.unwrap();
        
        assert_eq!(engine_guard.agent_count(), 2);
    }
    
    #[tokio::test]
    async fn test_engine_duplicate_agent_rejection() {
        let engine = test_engine().await;
        let mut engine_guard = engine.write().await;
        
        let agent1 = Box::new(MockTestAgent::new("duplicate".to_string()));
        let agent2 = Box::new(MockTestAgent::new("duplicate".to_string()));
        
        engine_guard.register_agent(agent1).await.unwrap();
        let result = engine_guard.register_agent(agent2).await;
        
        assert!(result.is_err());
        match result {
            Err(SynthexError::DuplicateAgent(id)) => {
                assert_eq!(id, "duplicate");
            }
            _ => panic!("Expected DuplicateAgent error"),
        }
    }
    
    #[tokio::test]
    async fn test_engine_search_execution() {
        let engine = test_engine().await;
        let mut engine_guard = engine.write().await;
        
        // Register test agents
        for i in 0..3 {
            let agent = Box::new(MockTestAgent::new(format!("search_agent_{}", i)));
            engine_guard.register_agent(agent).await.unwrap();
        }
        
        drop(engine_guard); // Release write lock
        
        let query = QueryBuilder::new("test search query")
            .with_max_results(10)
            .build();
            
        let engine_guard = engine.read().await;
        let results = engine_guard.search(&query).await.unwrap();
        
        assert_eq!(results.len(), 3); // One result per agent
        for result in &results {
            assert!(result.content.contains("test search query"));
            assert!(result.relevance > 0.0);
        }
    }
    
    #[tokio::test]
    async fn test_engine_parallel_search() {
        let engine = test_engine().await;
        let mut engine_guard = engine.write().await;
        
        // Register agents with different delays
        for i in 0..5 {
            let agent = Box::new(
                MockTestAgent::new(format!("parallel_agent_{}", i))
                    .with_delay(i * 100) // Different delays
            );
            engine_guard.register_agent(agent).await.unwrap();
        }
        
        drop(engine_guard);
        
        let query = QueryBuilder::new("parallel test")
            .with_parallel_execution(true)
            .build();
            
        let start = std::time::Instant::now();
        let engine_guard = engine.read().await;
        let results = engine_guard.search(&query).await.unwrap();
        let elapsed = start.elapsed().as_millis();
        
        assert_eq!(results.len(), 5);
        // Should complete faster than sequential (< 1000ms instead of 1500ms)
        assert!(elapsed < 1000, "Parallel execution too slow: {}ms", elapsed);
    }
    
    #[tokio::test]
    async fn test_engine_caching() {
        let engine = test_engine().await;
        let mut engine_guard = engine.write().await;
        
        let agent = Box::new(MockTestAgent::new("cache_test".to_string()));
        engine_guard.register_agent(agent).await.unwrap();
        
        drop(engine_guard);
        
        let query = QueryBuilder::new("cached query")
            .with_cache_enabled(true)
            .build();
            
        // First search - should hit agent
        let engine_guard = engine.read().await;
        let start1 = std::time::Instant::now();
        let results1 = engine_guard.search(&query).await.unwrap();
        let time1 = start1.elapsed().as_millis();
        
        // Second search - should hit cache
        let start2 = std::time::Instant::now();
        let results2 = engine_guard.search(&query).await.unwrap();
        let time2 = start2.elapsed().as_millis();
        
        assert_eq!(results1.len(), results2.len());
        assert!(time2 < time1 / 2, "Cache not effective: {}ms vs {}ms", time2, time1);
    }
    
    #[tokio::test]
    async fn test_engine_error_aggregation() {
        let engine = test_engine().await;
        let mut engine_guard = engine.write().await;
        
        // Mix of successful and failing agents
        engine_guard.register_agent(
            Box::new(MockTestAgent::new("success1".to_string()))
        ).await.unwrap();
        
        engine_guard.register_agent(
            Box::new(MockTestAgent::new("fail1".to_string()).with_failure())
        ).await.unwrap();
        
        engine_guard.register_agent(
            Box::new(MockTestAgent::new("success2".to_string()))
        ).await.unwrap();
        
        drop(engine_guard);
        
        let query = QueryBuilder::new("error test").build();
        let engine_guard = engine.read().await;
        let results = engine_guard.search(&query).await.unwrap();
        
        // Should get results from successful agents only
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| !r.source.contains("fail")));
    }
    
    #[tokio::test]
    async fn test_engine_resource_management() {
        let mut config = test_config();
        config.max_concurrent_agents = 3;
        
        let engine = SynthexEngine::new(config).await.unwrap();
        let engine = Arc::new(RwLock::new(engine));
        let mut engine_guard = engine.write().await;
        
        // Register more agents than max concurrent
        for i in 0..10 {
            let agent = Box::new(
                MockTestAgent::new(format!("resource_agent_{}", i))
                    .with_delay(100)
            );
            engine_guard.register_agent(agent).await.unwrap();
        }
        
        drop(engine_guard);
        
        let query = QueryBuilder::new("resource test")
            .with_parallel_execution(true)
            .build();
            
        let start = std::time::Instant::now();
        let engine_guard = engine.read().await;
        let results = engine_guard.search(&query).await.unwrap();
        let elapsed = start.elapsed().as_millis();
        
        assert_eq!(results.len(), 10);
        // Should batch process with max 3 concurrent
        assert!(elapsed >= 300, "Too fast, batching not working: {}ms", elapsed);
        assert!(elapsed < 1200, "Too slow, parallelism not working: {}ms", elapsed);
    }
    
    #[tokio::test]
    async fn test_engine_shutdown_cleanup() {
        let engine = test_engine().await;
        let mut engine_guard = engine.write().await;
        
        // Register agents
        for i in 0..5 {
            let agent = Box::new(MockTestAgent::new(format!("shutdown_{}", i)));
            engine_guard.register_agent(agent).await.unwrap();
        }
        
        // Shutdown
        engine_guard.shutdown().await.unwrap();
        
        assert_eq!(engine_guard.agent_count(), 0);
        assert!(!engine_guard.is_ready());
        
        // Further operations should fail
        let query = QueryBuilder::new("after shutdown").build();
        let result = engine_guard.search(&query).await;
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_engine_metrics() {
        let engine = test_engine().await;
        let mut engine_guard = engine.write().await;
        
        let agent = Box::new(MockTestAgent::new("metrics_test".to_string()));
        engine_guard.register_agent(agent).await.unwrap();
        
        drop(engine_guard);
        
        // Perform several searches
        for i in 0..10 {
            let query = QueryBuilder::new(&format!("metrics query {}", i)).build();
            let engine_guard = engine.read().await;
            let _ = engine_guard.search(&query).await;
        }
        
        let engine_guard = engine.read().await;
        let metrics = engine_guard.get_metrics();
        
        assert_eq!(metrics.total_searches, 10);
        assert_eq!(metrics.successful_searches, 10);
        assert_eq!(metrics.failed_searches, 0);
        assert!(metrics.average_latency_ms > 0.0);
        assert_eq!(metrics.cache_hits, 0); // No repeated queries
    }
}