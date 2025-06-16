//! Simple test to verify actor implementation works

#[cfg(test)]
mod test {
    use claude_optimized_deployment_rust::mcp_manager::{
        actor::McpRuntime,
        config::{McpManagerConfig, ServerConfig, ServerType, RetryPolicy},
    };
    
    #[tokio::test]
    async fn test_actor_works() {
        // Create runtime
        let config = McpManagerConfig::default();
        let runtime = McpRuntime::new(config);
        
        // Deploy a test server
        let server_config = ServerConfig {
            name: "test-server".to_string(),
            server_type: ServerType::Docker,
            url: "http://localhost:8001".to_string(),
            port: 8001,
            auth: None,
            capabilities: vec!["test".to_string()],
            max_connections: 10,
            timeout_ms: 5000,
            retry_policy: RetryPolicy::default(),
            priority: 5,
            tags: vec!["test".to_string()],
        };
        
        // Deploy server
        let server_id = runtime.deploy(server_config).await.unwrap();
        println!("✅ Deployed server: {}", server_id);
        
        // List servers
        let servers = runtime.list_servers().await.unwrap();
        println!("✅ Servers: {:?}", servers);
        assert_eq!(servers.len(), 1);
        
        // Get metrics
        let metrics = runtime.get_metrics(None).await.unwrap();
        println!("✅ Metrics: {:?}", metrics);
        assert_eq!(metrics.active_servers, 1);
        
        // Undeploy
        runtime.undeploy(&server_id).await.unwrap();
        println!("✅ Undeployed server");
        
        // Shutdown
        runtime.shutdown().await.unwrap();
        println!("✅ Runtime shutdown complete");
        
        println!("\n🎉 Actor implementation works correctly!");
    }
}

#[tokio::main]
async fn main() {
    println!("Run with: cargo test --test test_actor -- --nocapture");
}