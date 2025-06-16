//! Tests for SYNTHEX MCP v2 integration

#[cfg(test)]
mod tests {
    use crate::synthex::{
        mcp_v2::{McpV2Manager, McpServer, McpTool, McpResource},
        config::SynthexConfig,
        query::QueryBuilder,
    };
    use std::collections::HashMap;
    
    #[tokio::test]
    async fn test_mcp_manager_initialization() {
        let config = SynthexConfig::default();
        let manager = McpV2Manager::new(config).await.unwrap();
        
        assert!(manager.is_ready());
        assert_eq!(manager.server_count(), 0); // No servers registered yet
    }
    
    #[tokio::test]
    async fn test_mcp_server_registration() {
        let manager = McpV2Manager::new(SynthexConfig::default()).await.unwrap();
        
        let server = McpServer {
            id: "test_server".to_string(),
            name: "Test MCP Server".to_string(),
            version: "1.0.0".to_string(),
            capabilities: vec!["search".to_string(), "analyze".to_string()],
            endpoint: "http://localhost:8080".to_string(),
            metadata: HashMap::new(),
        };
        
        manager.register_server(server).await.unwrap();
        assert_eq!(manager.server_count(), 1);
        
        // Duplicate registration should fail
        let duplicate = McpServer {
            id: "test_server".to_string(),
            name: "Duplicate".to_string(),
            version: "1.0.0".to_string(),
            capabilities: vec![],
            endpoint: "http://localhost:8081".to_string(),
            metadata: HashMap::new(),
        };
        
        let result = manager.register_server(duplicate).await;
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_mcp_tool_discovery() {
        let manager = McpV2Manager::new(SynthexConfig::default()).await.unwrap();
        
        // Register server with tools
        let mut server = McpServer {
            id: "tool_server".to_string(),
            name: "Tool Server".to_string(),
            version: "1.0.0".to_string(),
            capabilities: vec!["tools".to_string()],
            endpoint: "http://localhost:8080".to_string(),
            metadata: HashMap::new(),
        };
        
        manager.register_server(server.clone()).await.unwrap();
        
        // Add tools to server
        let tools = vec![
            McpTool {
                name: "search".to_string(),
                description: "Search documents".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"}
                    }
                }),
                server_id: "tool_server".to_string(),
            },
            McpTool {
                name: "analyze".to_string(),
                description: "Analyze content".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "content": {"type": "string"}
                    }
                }),
                server_id: "tool_server".to_string(),
            },
        ];
        
        for tool in tools {
            manager.register_tool(tool).await.unwrap();
        }
        
        // Discover tools
        let discovered_tools = manager.discover_tools("search").await;
        assert_eq!(discovered_tools.len(), 1);
        assert_eq!(discovered_tools[0].name, "search");
        
        let all_tools = manager.list_all_tools().await;
        assert_eq!(all_tools.len(), 2);
    }
    
    #[tokio::test]
    async fn test_mcp_resource_management() {
        let manager = McpV2Manager::new(SynthexConfig::default()).await.unwrap();
        
        // Register server
        let server = McpServer {
            id: "resource_server".to_string(),
            name: "Resource Server".to_string(),
            version: "1.0.0".to_string(),
            capabilities: vec!["resources".to_string()],
            endpoint: "http://localhost:8080".to_string(),
            metadata: HashMap::new(),
        };
        
        manager.register_server(server).await.unwrap();
        
        // Add resources
        let resources = vec![
            McpResource {
                uri: "file:///docs/guide.md".to_string(),
                name: "User Guide".to_string(),
                mime_type: "text/markdown".to_string(),
                server_id: "resource_server".to_string(),
                metadata: HashMap::new(),
            },
            McpResource {
                uri: "http://api.example.com/data".to_string(),
                name: "API Data".to_string(),
                mime_type: "application/json".to_string(),
                server_id: "resource_server".to_string(),
                metadata: HashMap::new(),
            },
        ];
        
        for resource in resources {
            manager.register_resource(resource).await.unwrap();
        }
        
        // Query resources
        let markdown_resources = manager.find_resources_by_type("text/markdown").await;
        assert_eq!(markdown_resources.len(), 1);
        
        let resource = manager.get_resource("file:///docs/guide.md").await.unwrap();
        assert_eq!(resource.name, "User Guide");
    }
    
    #[tokio::test]
    async fn test_mcp_tool_execution() {
        let manager = McpV2Manager::new(SynthexConfig::default()).await.unwrap();
        
        // Setup mock server and tool
        let server = McpServer {
            id: "exec_server".to_string(),
            name: "Execution Server".to_string(),
            version: "1.0.0".to_string(),
            capabilities: vec!["tools".to_string()],
            endpoint: "http://localhost:8080".to_string(),
            metadata: HashMap::new(),
        };
        
        manager.register_server(server).await.unwrap();
        
        let tool = McpTool {
            name: "calculate".to_string(),
            description: "Perform calculation".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "expression": {"type": "string"}
                },
                "required": ["expression"]
            }),
            server_id: "exec_server".to_string(),
        };
        
        manager.register_tool(tool).await.unwrap();
        
        // Execute tool
        let input = serde_json::json!({
            "expression": "2 + 2"
        });
        
        let result = manager.execute_tool("calculate", input).await;
        assert!(result.is_ok());
        
        // Invalid input should fail
        let invalid_input = serde_json::json!({
            "wrong_field": "value"
        });
        
        let result = manager.execute_tool("calculate", invalid_input).await;
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_mcp_server_health_monitoring() {
        let manager = McpV2Manager::new(SynthexConfig::default()).await.unwrap();
        
        // Register multiple servers
        for i in 0..3 {
            let server = McpServer {
                id: format!("health_server_{}", i),
                name: format!("Health Server {}", i),
                version: "1.0.0".to_string(),
                capabilities: vec!["health".to_string()],
                endpoint: format!("http://localhost:808{}", i),
                metadata: HashMap::new(),
            };
            
            manager.register_server(server).await.unwrap();
        }
        
        // Check health status
        let health_report = manager.check_all_servers_health().await;
        
        assert_eq!(health_report.total_servers, 3);
        // In test environment, servers might not be actually running
        assert!(health_report.healthy_servers <= 3);
        
        // Get specific server health
        let server_health = manager.check_server_health("health_server_0").await;
        assert!(server_health.is_ok());
    }
    
    #[tokio::test]
    async fn test_mcp_capability_matching() {
        let manager = McpV2Manager::new(SynthexConfig::default()).await.unwrap();
        
        // Register servers with different capabilities
        let servers = vec![
            ("search_server", vec!["search", "index"]),
            ("analyze_server", vec!["analyze", "nlp"]),
            ("storage_server", vec!["store", "retrieve"]),
        ];
        
        for (id, capabilities) in servers {
            let server = McpServer {
                id: id.to_string(),
                name: format!("{} Server", id),
                version: "1.0.0".to_string(),
                capabilities: capabilities.iter().map(|s| s.to_string()).collect(),
                endpoint: format!("http://{}.local", id),
                metadata: HashMap::new(),
            };
            
            manager.register_server(server).await.unwrap();
        }
        
        // Find servers by capability
        let search_servers = manager.find_servers_by_capability("search").await;
        assert_eq!(search_servers.len(), 1);
        assert_eq!(search_servers[0].id, "search_server");
        
        let nlp_servers = manager.find_servers_by_capability("nlp").await;
        assert_eq!(nlp_servers.len(), 1);
        assert_eq!(nlp_servers[0].id, "analyze_server");
    }
    
    #[tokio::test]
    async fn test_mcp_query_routing() {
        let manager = McpV2Manager::new(SynthexConfig::default()).await.unwrap();
        
        // Setup specialized servers
        setup_specialized_servers(&manager).await;
        
        // Route different query types
        let search_query = QueryBuilder::new("find documents about rust")
            .with_context("search")
            .build();
            
        let routed_servers = manager.route_query(&search_query).await;
        assert!(routed_servers.iter().any(|s| s.capabilities.contains(&"search".to_string())));
        
        let analysis_query = QueryBuilder::new("analyze sentiment")
            .with_context("nlp")
            .build();
            
        let routed_servers = manager.route_query(&analysis_query).await;
        assert!(routed_servers.iter().any(|s| s.capabilities.contains(&"nlp".to_string())));
    }
    
    #[tokio::test]
    async fn test_mcp_load_balancing() {
        let manager = McpV2Manager::new(SynthexConfig::default()).await.unwrap();
        
        // Register multiple identical servers
        for i in 0..3 {
            let server = McpServer {
                id: format!("lb_server_{}", i),
                name: format!("Load Balanced Server {}", i),
                version: "1.0.0".to_string(),
                capabilities: vec!["search".to_string()],
                endpoint: format!("http://lb{}.local", i),
                metadata: HashMap::new(),
            };
            
            manager.register_server(server).await.unwrap();
        }
        
        // Make multiple requests and verify load distribution
        let mut server_hits = HashMap::new();
        
        for _ in 0..30 {
            let selected = manager.select_server_for_capability("search").await.unwrap();
            *server_hits.entry(selected.id.clone()).or_insert(0) += 1;
        }
        
        // Verify relatively even distribution
        for (_, hits) in server_hits {
            assert!(hits >= 8 && hits <= 12, "Uneven load distribution: {} hits", hits);
        }
    }
    
    #[tokio::test]
    async fn test_mcp_error_handling() {
        let manager = McpV2Manager::new(SynthexConfig::default()).await.unwrap();
        
        // Test various error scenarios
        
        // 1. Execute tool on non-existent server
        let result = manager.execute_tool("non_existent_tool", serde_json::json!({})).await;
        assert!(result.is_err());
        
        // 2. Get non-existent resource
        let result = manager.get_resource("fake://resource").await;
        assert!(result.is_err());
        
        // 3. Register server with invalid endpoint
        let invalid_server = McpServer {
            id: "invalid".to_string(),
            name: "Invalid Server".to_string(),
            version: "1.0.0".to_string(),
            capabilities: vec![],
            endpoint: "not-a-valid-url".to_string(),
            metadata: HashMap::new(),
        };
        
        let result = manager.register_server(invalid_server).await;
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_mcp_performance_metrics() {
        let manager = McpV2Manager::new(SynthexConfig::default()).await.unwrap();
        
        // Setup server and execute operations
        let server = McpServer {
            id: "perf_server".to_string(),
            name: "Performance Server".to_string(),
            version: "1.0.0".to_string(),
            capabilities: vec!["metrics".to_string()],
            endpoint: "http://localhost:8080".to_string(),
            metadata: HashMap::new(),
        };
        
        manager.register_server(server).await.unwrap();
        
        // Simulate operations
        for i in 0..10 {
            manager.record_operation_metric("perf_server", "latency", 50.0 + i as f64).await;
            manager.record_operation_metric("perf_server", "throughput", 1000.0 - i as f64 * 10.0).await;
        }
        
        // Get metrics
        let metrics = manager.get_server_metrics("perf_server").await.unwrap();
        
        assert_eq!(metrics.operation_count, 20);
        assert!(metrics.average_latency > 50.0);
        assert!(metrics.average_throughput < 1000.0);
        assert!(metrics.error_rate == 0.0);
    }
}

// Helper function to setup specialized servers
async fn setup_specialized_servers(manager: &McpV2Manager) {
    let servers = vec![
        ("search_specialist", vec!["search", "index", "query"]),
        ("nlp_specialist", vec!["nlp", "sentiment", "analyze"]),
        ("storage_specialist", vec!["store", "retrieve", "cache"]),
        ("compute_specialist", vec!["calculate", "aggregate", "transform"]),
    ];
    
    for (id, capabilities) in servers {
        let server = McpServer {
            id: id.to_string(),
            name: format!("{} Server", id),
            version: "1.0.0".to_string(),
            capabilities: capabilities.iter().map(|s| s.to_string()).collect(),
            endpoint: format!("http://{}.local", id),
            metadata: HashMap::new(),
        };
        
        manager.register_server(server).await.unwrap();
    }
}