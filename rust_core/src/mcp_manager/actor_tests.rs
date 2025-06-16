//! Comprehensive tests for the actor-based MCP Manager
//! 
//! These tests verify the message-passing architecture works correctly
//! and provides the same functionality as the old shared-state version.

#[cfg(test)]
mod tests {
    use crate::mcp_manager::{
        actor::{McpCommand, McpRuntime, Metrics},
        manager_v2::McpManagerV2,
        config::{McpManagerConfig, ServerConfig, ServerType, RetryPolicy},
        errors::McpError,
    };
    use std::time::Duration;
    use tokio::time::timeout;
    
    /// Helper to create a test server config
    fn create_test_server_config(name: &str) -> ServerConfig {
        ServerConfig {
            name: name.to_string(),
            server_type: ServerType::Docker,
            url: format!("http://localhost:{}", 8000 + name.len()),
            port: (8000 + name.len()) as u16,
            auth: None,
            capabilities: vec!["test.capability".to_string()],
            max_connections: 10,
            timeout_ms: 5000,
            retry_policy: RetryPolicy::default(),
            priority: 5,
            tags: vec!["test".to_string()],
        }
    }
    
    #[tokio::test]
    async fn test_actor_basic_lifecycle() {
        let config = McpManagerConfig::default();
        let runtime = McpRuntime::new(config);
        
        // Deploy a server
        let server_config = create_test_server_config("test1");
        let server_id = runtime.deploy(server_config).await.unwrap();
        assert_eq!(server_id, "test1");
        
        // List servers
        let servers = runtime.list_servers().await.unwrap();
        assert_eq!(servers.len(), 1);
        assert!(servers.contains(&"test1".to_string()));
        
        // Check metrics
        let metrics = runtime.get_metrics(None).await.unwrap();
        assert_eq!(metrics.active_servers, 1);
        assert!(metrics.total_commands > 0);
        assert!(metrics.successful_commands > 0);
        
        // Undeploy
        runtime.undeploy(&server_id).await.unwrap();
        
        // Verify server is gone
        let servers = runtime.list_servers().await.unwrap();
        assert!(servers.is_empty());
        
        // Shutdown
        runtime.shutdown().await.unwrap();
    }
    
    #[tokio::test]
    async fn test_concurrent_deployments() {
        let config = McpManagerConfig::default();
        let runtime = McpRuntime::new(config);
        
        // Deploy multiple servers concurrently
        let mut tasks = vec![];
        for i in 0..10 {
            let runtime_clone = runtime.clone();
            let config = create_test_server_config(&format!("server{}", i));
            
            tasks.push(tokio::spawn(async move {
                runtime_clone.deploy(config).await
            }));
        }
        
        // Wait for all deployments
        let results: Vec<_> = futures::future::join_all(tasks).await;
        
        // Verify all succeeded
        for (i, result) in results.iter().enumerate() {
            let server_id = result.as_ref().unwrap().as_ref().unwrap();
            assert_eq!(server_id, &format!("server{}", i));
        }
        
        // Check server count
        let servers = runtime.list_servers().await.unwrap();
        assert_eq!(servers.len(), 10);
        
        // Check metrics
        let metrics = runtime.get_metrics(None).await.unwrap();
        assert_eq!(metrics.active_servers, 10);
        
        runtime.shutdown().await.unwrap();
    }
    
    #[tokio::test]
    async fn test_duplicate_deployment_error() {
        let config = McpManagerConfig::default();
        let runtime = McpRuntime::new(config);
        
        // Deploy a server
        let server_config = create_test_server_config("duplicate");
        runtime.deploy(server_config.clone()).await.unwrap();
        
        // Try to deploy again with same name
        let result = runtime.deploy(server_config).await;
        assert!(result.is_err());
        
        match result.unwrap_err() {
            McpError::AlreadyExists(msg) => {
                assert!(msg.contains("duplicate"));
            }
            _ => panic!("Expected AlreadyExists error"),
        }
        
        runtime.shutdown().await.unwrap();
    }
    
    #[tokio::test]
    async fn test_undeploy_nonexistent_server() {
        let config = McpManagerConfig::default();
        let runtime = McpRuntime::new(config);
        
        // Try to undeploy non-existent server
        let result = runtime.undeploy("nonexistent").await;
        assert!(result.is_err());
        
        match result.unwrap_err() {
            McpError::NotFound(msg) => {
                assert!(msg.contains("nonexistent"));
            }
            _ => panic!("Expected NotFound error"),
        }
        
        runtime.shutdown().await.unwrap();
    }
    
    #[tokio::test]
    async fn test_backpressure() {
        let config = McpManagerConfig::default();
        let runtime = McpRuntime::new(config);
        
        // Send many commands quickly to test backpressure
        let mut tasks = vec![];
        for i in 0..200 {
            let runtime_clone = runtime.clone();
            
            tasks.push(tokio::spawn(async move {
                runtime_clone.list_servers().await
            }));
        }
        
        // All should complete successfully despite high load
        let results: Vec<_> = futures::future::join_all(tasks).await;
        for result in results {
            assert!(result.is_ok());
            assert!(result.unwrap().is_ok());
        }
        
        runtime.shutdown().await.unwrap();
    }
    
    #[tokio::test]
    async fn test_manager_v2_integration() {
        let mut config = McpManagerConfig::default();
        
        // Add some test servers to config
        config.servers.push(create_test_server_config("config1"));
        config.servers.push(create_test_server_config("config2"));
        
        let manager = McpManagerV2::new(config);
        
        // Initialize should deploy configured servers
        manager.initialize().await.unwrap();
        
        // Verify servers were deployed
        let servers = manager.list_servers().await.unwrap();
        assert_eq!(servers.len(), 2);
        assert!(servers.contains(&"config1".to_string()));
        assert!(servers.contains(&"config2".to_string()));
        
        // Deploy additional server
        let new_server = create_test_server_config("dynamic");
        manager.deploy_server(new_server).await.unwrap();
        
        // Verify total count
        let servers = manager.list_servers().await.unwrap();
        assert_eq!(servers.len(), 3);
        
        // Test execute_tool (would fail without real server)
        let result = manager.execute_tool("config1", "test.tool", serde_json::json!({})).await;
        // We expect this to fail in tests but the structure should work
        assert!(result.is_err());
        
        // Get metrics
        let metrics = manager.get_metrics(None).await.unwrap();
        assert_eq!(metrics.active_servers, 3);
        
        // Shutdown
        manager.shutdown().await.unwrap();
    }
    
    #[tokio::test]
    async fn test_graceful_shutdown() {
        let config = McpManagerConfig::default();
        let runtime = McpRuntime::new(config);
        
        // Deploy some servers
        for i in 0..5 {
            let config = create_test_server_config(&format!("shutdown{}", i));
            runtime.deploy(config).await.unwrap();
        }
        
        // Start a long-running operation
        let runtime_clone = runtime.clone();
        let long_op = tokio::spawn(async move {
            // Simulate a long operation
            tokio::time::sleep(Duration::from_secs(5)).await;
            runtime_clone.list_servers().await
        });
        
        // Shutdown should wait for operations to complete
        runtime.shutdown().await.unwrap();
        
        // The long operation should have been cancelled
        assert!(timeout(Duration::from_millis(100), long_op).await.is_ok());
    }
    
    #[tokio::test]
    async fn test_metrics_accuracy() {
        let config = McpManagerConfig::default();
        let runtime = McpRuntime::new(config);
        
        // Perform various operations
        let server1 = create_test_server_config("metrics1");
        runtime.deploy(server1).await.unwrap();
        
        let server2 = create_test_server_config("metrics2");
        runtime.deploy(server2).await.unwrap();
        
        // Some successful operations
        runtime.list_servers().await.unwrap();
        runtime.health_check("metrics1").await.unwrap();
        
        // Some failed operations
        let _ = runtime.undeploy("nonexistent").await;
        let _ = runtime.health_check("nonexistent").await;
        
        // Check metrics
        let metrics = runtime.get_metrics(None).await.unwrap();
        assert_eq!(metrics.active_servers, 2);
        assert!(metrics.total_commands >= 6); // At least our operations
        assert!(metrics.successful_commands >= 4); // Deploys + list + health
        assert!(metrics.failed_commands >= 2); // Failed undeploy + health
        assert!(metrics.avg_latency_us > 0);
        
        runtime.shutdown().await.unwrap();
    }
    
    #[tokio::test]
    async fn test_error_propagation() {
        let config = McpManagerConfig::default();
        let runtime = McpRuntime::new(config);
        
        // Test various error conditions
        let errors = vec![
            runtime.undeploy("nonexistent").await,
            runtime.execute("nonexistent", serde_json::json!({})).await,
            runtime.health_check("nonexistent").await,
        ];
        
        for error in errors {
            assert!(error.is_err());
            match error.unwrap_err() {
                McpError::NotFound(_) => {}, // Expected
                e => panic!("Unexpected error type: {:?}", e),
            }
        }
        
        runtime.shutdown().await.unwrap();
    }
}