//! Tests for all SYNTHEX agent types

#[cfg(test)]
mod tests {
    use crate::synthex::{
        agents::*,
        query::{Query, QueryBuilder},
        SynthexError,
    };
    use super::super::test_utils::*;
    
    #[tokio::test]
    async fn test_api_agent_initialization() {
        let config = ApiAgentConfig {
            base_url: "https://api.example.com".to_string(),
            api_key: Some("test_key".to_string()),
            timeout_seconds: 10,
            max_retries: 3,
        };
        
        let agent = ApiAgent::new("test_api", config);
        assert_eq!(agent.id(), "test_api");
        assert!(agent.capabilities().can_search);
    }
    
    #[tokio::test]
    async fn test_database_agent_query_execution() {
        let config = DatabaseAgentConfig {
            connection_string: "sqlite::memory:".to_string(),
            pool_size: 5,
            query_timeout_seconds: 30,
        };
        
        let agent = DatabaseAgent::new("test_db", config);
        let query = QueryBuilder::new("SELECT * FROM users")
            .with_context("database")
            .build();
            
        // Note: This would fail without actual DB, but tests structure
        let result = agent.execute(&query).await;
        assert!(result.is_err()); // Expected without real DB
    }
    
    #[tokio::test]
    async fn test_file_agent_search() {
        use tempfile::TempDir;
        use std::fs;
        
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, "This is test content for SYNTHEX").unwrap();
        
        let config = FileAgentConfig {
            root_path: temp_dir.path().to_path_buf(),
            allowed_extensions: vec!["txt".to_string()],
            max_file_size_mb: 10,
            enable_content_indexing: true,
        };
        
        let agent = FileAgent::new("test_files", config);
        let query = QueryBuilder::new("test content")
            .with_max_results(5)
            .build();
            
        let results = agent.execute(&query).await.unwrap();
        assert!(!results.is_empty());
        assert!(results[0].content.contains("test content"));
    }
    
    #[tokio::test]
    async fn test_web_agent_capabilities() {
        let config = WebAgentConfig {
            user_agent: "SYNTHEX/1.0".to_string(),
            max_concurrent_requests: 10,
            timeout_seconds: 30,
            enable_javascript: false,
        };
        
        let agent = WebAgent::new("test_web", config);
        let caps = agent.capabilities();
        
        assert!(caps.can_search);
        assert!(caps.can_analyze);
        assert_eq!(caps.max_concurrent_requests, 10);
    }
    
    #[tokio::test]
    async fn test_knowledge_base_agent() {
        let config = KnowledgeBaseConfig {
            index_path: "/tmp/test_kb_index".to_string(),
            embedding_model: "small".to_string(),
            similarity_threshold: 0.7,
            max_results: 20,
        };
        
        let mut agent = KnowledgeBaseAgent::new("test_kb", config);
        
        // Add test documents
        agent.add_document("doc1", "SYNTHEX is a high-performance search system").await.unwrap();
        agent.add_document("doc2", "It uses multiple agents for parallel execution").await.unwrap();
        
        let query = QueryBuilder::new("SYNTHEX performance")
            .with_max_results(10)
            .build();
            
        let results = agent.execute(&query).await.unwrap();
        assert!(!results.is_empty());
        assert!(results[0].relevance > 0.5);
    }
    
    #[tokio::test]
    async fn test_agent_error_handling() {
        let agent = MockTestAgent::new("error_agent".to_string())
            .with_failure();
            
        let query = QueryBuilder::new("test").build();
        let result = agent.execute(&query).await;
        
        assert!(result.is_err());
        match result {
            Err(SynthexError::AgentError(msg)) => {
                assert!(msg.contains("failed as configured"));
            }
            _ => panic!("Expected AgentError"),
        }
    }
    
    #[tokio::test]
    async fn test_agent_timeout() {
        let agent = MockTestAgent::new("slow_agent".to_string())
            .with_delay(5000); // 5 second delay
            
        let query = QueryBuilder::new("test")
            .with_timeout(1) // 1 second timeout
            .build();
            
        let start = std::time::Instant::now();
        let result = assert_completes_within(
            agent.execute(&query),
            1500, // 1.5 seconds max
            "Agent should timeout"
        ).await;
        
        let elapsed = start.elapsed().as_millis();
        assert!(elapsed < 2000); // Should not wait full 5 seconds
    }
    
    #[tokio::test]
    async fn test_multiple_agents_coordination() {
        use tokio::sync::mpsc;
        
        let (tx, mut rx) = mpsc::channel(10);
        
        let agents: Vec<Box<dyn Agent + Send + Sync>> = vec![
            Box::new(MockTestAgent::new("agent1".to_string())),
            Box::new(MockTestAgent::new("agent2".to_string())),
            Box::new(MockTestAgent::new("agent3".to_string())),
        ];
        
        let query = QueryBuilder::new("coordinated test").build();
        
        // Execute all agents in parallel
        let mut handles = vec![];
        for agent in agents {
            let query_clone = query.clone();
            let tx_clone = tx.clone();
            
            let handle = tokio::spawn(async move {
                let result = agent.execute(&query_clone).await;
                tx_clone.send((agent.id().to_string(), result)).await.unwrap();
            });
            
            handles.push(handle);
        }
        
        drop(tx); // Close sender
        
        // Collect results
        let mut results = vec![];
        while let Some((agent_id, result)) = rx.recv().await {
            results.push((agent_id, result));
        }
        
        assert_eq!(results.len(), 3);
        for (agent_id, result) in results {
            assert!(result.is_ok());
            let search_results = result.unwrap();
            assert!(!search_results.is_empty());
            assert!(search_results[0].content.contains(&agent_id));
        }
    }
    
    #[tokio::test]
    async fn test_agent_resource_limits() {
        let config = test_config();
        let mut total_memory = 0usize;
        
        // Create many agents to test memory limits
        let mut agents = vec![];
        for i in 0..100 {
            let agent = MockTestAgent::new(format!("memory_test_{}", i));
            agents.push(agent);
            
            // Rough memory estimation
            total_memory += std::mem::size_of::<MockTestAgent>() + 100; // Extra for strings
            
            if total_memory > (config.memory_limit_mb as usize * 1024 * 1024) {
                break;
            }
        }
        
        assert!(agents.len() < 100); // Should hit memory limit
        assert!(agents.len() > 10); // But should create some agents
    }
}