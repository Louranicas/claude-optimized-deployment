//! Integration tests for SYNTHEX components

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use crate::synthex::{
        engine::SynthexEngine,
        config::SynthexConfig,
        query::QueryBuilder,
        agents::*,
        service::SynthexService,
        result_aggregator::ResultAggregator,
        parallel_executor::ParallelExecutor,
    };
    use super::super::test_utils::*;
    
    #[tokio::test]
    async fn test_full_pipeline_integration() {
        // Create complete SYNTHEX setup
        let config = SynthexConfig {
            max_concurrent_agents: 10,
            cache_size: 500,
            timeout_seconds: 30,
            enable_ml_optimization: false,
            enable_gpu_acceleration: false,
            max_retries: 3,
            batch_size: 20,
            memory_limit_mb: 1024,
        };
        
        let service = SynthexService::new(config).await.unwrap();
        
        // Register different agent types
        service.register_agent(
            Box::new(MockTestAgent::new("mock1".to_string()))
        ).await.unwrap();
        
        service.register_agent(
            Box::new(FileAgent::new("files", FileAgentConfig {
                root_path: std::env::temp_dir(),
                allowed_extensions: vec!["txt".to_string(), "md".to_string()],
                max_file_size_mb: 10,
                enable_content_indexing: true,
            }))
        ).await.unwrap();
        
        // Execute complex query
        let query = QueryBuilder::new("integration test")
            .with_context("testing full pipeline")
            .with_max_results(20)
            .with_parallel_execution(true)
            .with_cache_enabled(true)
            .build();
            
        let results = service.search(&query).await.unwrap();
        
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.relevance >= 0.0 && r.relevance <= 1.0));
    }
    
    #[tokio::test]
    async fn test_multi_agent_coordination() {
        let engine = test_engine().await;
        let mut engine_guard = engine.write().await;
        
        // Create agents with different capabilities
        let api_agent = Box::new(MockTestAgent::new("api".to_string()));
        let db_agent = Box::new(MockTestAgent::new("database".to_string()));
        let file_agent = Box::new(MockTestAgent::new("files".to_string()));
        
        engine_guard.register_agent(api_agent).await.unwrap();
        engine_guard.register_agent(db_agent).await.unwrap();
        engine_guard.register_agent(file_agent).await.unwrap();
        
        drop(engine_guard);
        
        // Complex query requiring multiple agents
        let query = QueryBuilder::new("user data from multiple sources")
            .with_filters(vec!["source:api".to_string(), "source:database".to_string()])
            .with_parallel_execution(true)
            .build();
            
        let engine_guard = engine.read().await;
        let results = engine_guard.search(&query).await.unwrap();
        
        // Should have results from multiple agents
        let sources: std::collections::HashSet<_> = results.iter()
            .map(|r| r.source.clone())
            .collect();
            
        assert!(sources.len() >= 2, "Not enough sources: {:?}", sources);
    }
    
    #[tokio::test]
    async fn test_result_aggregation() {
        let aggregator = ResultAggregator::new();
        
        // Create results from different sources
        let results1 = vec![
            crate::synthex::SearchResult {
                content: "Result A".to_string(),
                relevance: 0.9,
                source: "agent1".to_string(),
                metadata: std::collections::HashMap::new(),
            },
            crate::synthex::SearchResult {
                content: "Result B".to_string(),
                relevance: 0.7,
                source: "agent1".to_string(),
                metadata: std::collections::HashMap::new(),
            },
        ];
        
        let results2 = vec![
            crate::synthex::SearchResult {
                content: "Result A".to_string(), // Duplicate
                relevance: 0.85,
                source: "agent2".to_string(),
                metadata: std::collections::HashMap::new(),
            },
            crate::synthex::SearchResult {
                content: "Result C".to_string(),
                relevance: 0.95,
                source: "agent2".to_string(),
                metadata: std::collections::HashMap::new(),
            },
        ];
        
        let aggregated = aggregator.aggregate(vec![results1, results2], 10);
        
        // Should deduplicate and sort by relevance
        assert_eq!(aggregated.len(), 3); // A, B, C (deduplicated)
        assert_eq!(aggregated[0].content, "Result C"); // Highest relevance
        assert!(aggregated[0].relevance > aggregated[1].relevance);
    }
    
    #[tokio::test]
    async fn test_parallel_executor() {
        let executor = ParallelExecutor::new(5); // Max 5 concurrent
        
        let tasks: Vec<_> = (0..20).map(|i| {
            async move {
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                format!("Task {} complete", i)
            }
        }).collect();
        
        let start = std::time::Instant::now();
        let results = executor.execute_all(tasks).await;
        let elapsed = start.elapsed().as_millis();
        
        assert_eq!(results.len(), 20);
        // Should complete in ~200ms (4 batches of 5) not 1000ms (sequential)
        assert!(elapsed < 300, "Parallel execution too slow: {}ms", elapsed);
    }
    
    #[tokio::test]
    async fn test_error_recovery() {
        let engine = test_engine().await;
        let mut engine_guard = engine.write().await;
        
        // Mix of reliable and unreliable agents
        engine_guard.register_agent(
            Box::new(MockTestAgent::new("reliable1".to_string()))
        ).await.unwrap();
        
        engine_guard.register_agent(
            Box::new(MockTestAgent::new("unreliable1".to_string()).with_failure())
        ).await.unwrap();
        
        engine_guard.register_agent(
            Box::new(MockTestAgent::new("reliable2".to_string()))
        ).await.unwrap();
        
        engine_guard.register_agent(
            Box::new(MockTestAgent::new("slow".to_string()).with_delay(5000))
        ).await.unwrap();
        
        drop(engine_guard);
        
        let query = QueryBuilder::new("error recovery test")
            .with_timeout(1) // 1 second timeout
            .build();
            
        let engine_guard = engine.read().await;
        let results = engine_guard.search(&query).await.unwrap();
        
        // Should get results from reliable agents only
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.source.contains("reliable")));
    }
    
    #[tokio::test]
    async fn test_configuration_hot_reload() {
        let initial_config = SynthexConfig {
            max_concurrent_agents: 5,
            cache_size: 100,
            timeout_seconds: 10,
            enable_ml_optimization: false,
            enable_gpu_acceleration: false,
            max_retries: 3,
            batch_size: 10,
            memory_limit_mb: 512,
        };
        
        let service = SynthexService::new(initial_config).await.unwrap();
        
        // Update configuration
        let new_config = SynthexConfig {
            max_concurrent_agents: 10,
            cache_size: 200,
            timeout_seconds: 20,
            enable_ml_optimization: true,
            enable_gpu_acceleration: false,
            max_retries: 5,
            batch_size: 20,
            memory_limit_mb: 1024,
        };
        
        service.update_config(new_config).await.unwrap();
        
        let current_config = service.get_config().await;
        assert_eq!(current_config.max_concurrent_agents, 10);
        assert_eq!(current_config.cache_size, 200);
        assert!(current_config.enable_ml_optimization);
    }
    
    #[tokio::test]
    async fn test_graceful_shutdown() {
        let service = SynthexService::new(test_config()).await.unwrap();
        
        // Register agents
        for i in 0..5 {
            service.register_agent(
                Box::new(MockTestAgent::new(format!("shutdown_test_{}", i)))
            ).await.unwrap();
        }
        
        // Start some background queries
        let service_clone = service.clone();
        let query_handle = tokio::spawn(async move {
            for i in 0..10 {
                let query = QueryBuilder::new(&format!("background query {}", i))
                    .build();
                let _ = service_clone.search(&query).await;
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        });
        
        // Wait a bit then shutdown
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        
        let shutdown_result = service.shutdown().await;
        assert!(shutdown_result.is_ok());
        
        // Verify no more queries can be processed
        let query = QueryBuilder::new("after shutdown").build();
        let result = service.search(&query).await;
        assert!(result.is_err());
        
        // Background queries should have stopped
        assert!(query_handle.is_finished());
    }
    
    #[tokio::test]
    async fn test_distributed_search() {
        // Simulate distributed SYNTHEX deployment
        let node1 = SynthexService::new(test_config()).await.unwrap();
        let node2 = SynthexService::new(test_config()).await.unwrap();
        let node3 = SynthexService::new(test_config()).await.unwrap();
        
        // Each node has different agents
        node1.register_agent(
            Box::new(MockTestAgent::new("node1_agent1".to_string()))
        ).await.unwrap();
        
        node2.register_agent(
            Box::new(MockTestAgent::new("node2_agent1".to_string()))
        ).await.unwrap();
        
        node3.register_agent(
            Box::new(MockTestAgent::new("node3_agent1".to_string()))
        ).await.unwrap();
        
        // Coordinator collects results from all nodes
        let query = QueryBuilder::new("distributed search").build();
        
        let mut all_results = vec![];
        
        let (r1, r2, r3) = tokio::join!(
            node1.search(&query),
            node2.search(&query),
            node3.search(&query)
        );
        
        all_results.extend(r1.unwrap());
        all_results.extend(r2.unwrap());
        all_results.extend(r3.unwrap());
        
        assert_eq!(all_results.len(), 3);
        
        // Verify results from all nodes
        let sources: std::collections::HashSet<_> = all_results.iter()
            .map(|r| r.source.split('_').next().unwrap())
            .collect();
            
        assert!(sources.contains("node1"));
        assert!(sources.contains("node2"));
        assert!(sources.contains("node3"));
    }
    
    #[tokio::test]
    async fn test_circuit_breaker() {
        let service = SynthexService::new(test_config()).await.unwrap();
        
        // Register a consistently failing agent
        service.register_agent(
            Box::new(MockTestAgent::new("failing_agent".to_string()).with_failure())
        ).await.unwrap();
        
        // Make multiple requests
        for i in 0..10 {
            let query = QueryBuilder::new(&format!("circuit test {}", i)).build();
            let _ = service.search(&query).await;
        }
        
        // Circuit breaker should have tripped
        let stats = service.get_agent_stats("failing_agent").await;
        assert!(stats.circuit_open);
        assert_eq!(stats.consecutive_failures, 10);
        
        // Further requests should be rejected immediately
        let start = std::time::Instant::now();
        let query = QueryBuilder::new("after circuit open").build();
        let _ = service.search(&query).await;
        let elapsed = start.elapsed().as_millis();
        
        assert!(elapsed < 10, "Circuit breaker not working: {}ms", elapsed);
    }
}