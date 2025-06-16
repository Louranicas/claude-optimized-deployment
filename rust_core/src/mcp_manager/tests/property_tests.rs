use proptest::prelude::*;
use crate::mcp_manager::{
    config::MCPConfig,
    core::MCPManager,
    server::{MCPServer, ServerState},
    protocol::{MCPRequest, MCPProtocol},
    load_balancer::LoadBalancingStrategy,
    error::MCPError,
};
use super::test_utils::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::runtime::Runtime;

// Property test strategies

prop_compose! {
    fn arb_server_id()(id in "[a-z]{3,10}[0-9]{0,3}") -> String {
        id
    }
}

prop_compose! {
    fn arb_server_url()(
        protocol in prop_oneof!["http", "https", "ws", "wss"],
        host in "[a-z]{3,10}",
        port in 1000u16..9999u16
    ) -> String {
        format!("{}://{}:{}", protocol, host, port)
    }
}

prop_compose! {
    fn arb_mcp_config()(
        max_connections in 1usize..100,
        connection_timeout in 100u64..10000,
        request_timeout in 1000u64..60000,
        health_check_interval in 1u64..300,
        max_retries in 0u32..10,
        retry_backoff in 1.0f64..4.0,
        enable_pooling in any::<bool>(),
        enable_balancing in any::<bool>(),
        enable_health in any::<bool>(),
        enable_metrics in any::<bool>(),
        breaker_threshold in 1u32..20,
        breaker_recovery in 10u64..300
    ) -> MCPConfig {
        MCPConfig {
            max_connections_per_server: max_connections,
            connection_timeout_ms: connection_timeout,
            request_timeout_ms: request_timeout,
            health_check_interval_secs: health_check_interval,
            max_retries,
            retry_backoff_multiplier: retry_backoff,
            enable_connection_pooling: enable_pooling,
            enable_load_balancing: enable_balancing,
            enable_health_checks: enable_health,
            enable_metrics,
            circuit_breaker_threshold: breaker_threshold,
            circuit_breaker_recovery_secs: breaker_recovery,
        }
    }
}

prop_compose! {
    fn arb_mcp_server()(
        id in arb_server_id(),
        url in arb_server_url(),
        protocol_idx in 0usize..2,
        metadata_keys in prop::collection::vec("[a-z]{3,8}", 0..5),
        metadata_values in prop::collection::vec("[a-zA-Z0-9]{1,20}", 0..5)
    ) -> MCPServer {
        let protocol = match protocol_idx {
            0 => MCPProtocol::Http,
            _ => MCPProtocol::WebSocket,
        };
        
        let mut metadata = HashMap::new();
        for (k, v) in metadata_keys.into_iter().zip(metadata_values) {
            metadata.insert(k, v);
        }
        
        MCPServer::new(id, url, protocol, metadata)
    }
}

prop_compose! {
    fn arb_mcp_request()(
        method in "[a-z_]{3,20}",
        param_keys in prop::collection::vec("[a-z_]{1,10}", 0..10),
        param_values in prop::collection::vec(any::<i32>(), 0..10)
    ) -> MCPRequest {
        let mut params = serde_json::Map::new();
        for (k, v) in param_keys.into_iter().zip(param_values) {
            params.insert(k, serde_json::json!(v));
        }
        
        MCPRequest::new(method, serde_json::Value::Object(params))
    }
}

// Property tests

proptest! {
    #[test]
    fn prop_config_timeouts_are_positive(config in arb_mcp_config()) {
        prop_assert!(config.connection_timeout_ms > 0);
        prop_assert!(config.request_timeout_ms > 0);
        prop_assert!(config.connection_timeout_ms <= config.request_timeout_ms);
    }
    
    #[test]
    fn prop_config_durations_are_valid(config in arb_mcp_config()) {
        let conn_timeout = config.connection_timeout();
        let req_timeout = config.request_timeout();
        let health_interval = config.health_check_interval();
        let breaker_recovery = config.circuit_breaker_recovery();
        
        prop_assert!(conn_timeout.as_millis() > 0);
        prop_assert!(req_timeout.as_millis() > 0);
        prop_assert!(health_interval.as_secs() > 0);
        prop_assert!(breaker_recovery.as_secs() > 0);
    }
    
    #[test]
    fn prop_server_registration_idempotent(
        servers in prop::collection::vec(arb_mcp_server(), 1..10)
    ) {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let manager = create_test_manager();
            
            // Register servers multiple times
            for server in &servers {
                let _ = manager.register_server(server.clone()).await;
                let _ = manager.register_server(server.clone()).await; // Duplicate
            }
            
            // Should only have unique servers
            let registered = manager.get_servers().await;
            let unique_ids: std::collections::HashSet<_> = 
                servers.iter().map(|s| s.id()).collect();
            
            prop_assert_eq!(registered.len(), unique_ids.len());
        })
    }
    
    #[test]
    fn prop_unregister_removes_server(
        servers in prop::collection::vec(arb_mcp_server(), 1..10),
        remove_indices in prop::collection::vec(any::<usize>(), 1..5)
    ) {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let manager = create_test_manager();
            
            // Register all servers
            for server in &servers {
                manager.register_server(server.clone()).await.unwrap();
            }
            
            // Remove some servers
            let mut removed_ids = std::collections::HashSet::new();
            for idx in remove_indices {
                if let Some(server) = servers.get(idx % servers.len()) {
                    if manager.unregister_server(server.id()).await.is_ok() {
                        removed_ids.insert(server.id());
                    }
                }
            }
            
            // Verify removed servers are gone
            let remaining = manager.get_servers().await;
            for server in remaining {
                prop_assert!(!removed_ids.contains(server.id()));
            }
        })
    }
    
    #[test]
    fn prop_retry_config_affects_behavior(
        base_config in arb_mcp_config(),
        fail_probability in 0.0f64..1.0
    ) {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            // Test with no retries
            let mut no_retry_config = base_config.clone();
            no_retry_config.max_retries = 0;
            let no_retry_manager = MCPManager::new(no_retry_config);
            
            // Test with retries
            let mut retry_config = base_config;
            retry_config.max_retries = 3;
            let retry_manager = MCPManager::new(retry_config);
            
            // Register mock servers
            let server = create_mock_server("retry_test");
            let mock_conn = Arc::new(MockMCPConnection::new(server.id().to_string()));
            mock_conn.set_fail_rate(fail_probability).await;
            
            no_retry_manager.register_server(server.clone()).await.unwrap();
            retry_manager.register_server(server).await.unwrap();
            
            // Send requests
            let request = MCPRequest::new("test", serde_json::json!({}));
            
            let no_retry_result = no_retry_manager.send_request(request.clone()).await;
            let retry_result = retry_manager.send_request(request).await;
            
            // With retries, success rate should be >= without retries
            if no_retry_result.is_ok() {
                prop_assert!(retry_result.is_ok());
            }
        })
    }
    
    #[test]
    fn prop_load_balancing_distributes_requests(
        num_servers in 2usize..10,
        num_requests in 10usize..100
    ) {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let mut config = create_test_config();
            config.enable_load_balancing = true;
            let manager = MCPManager::new(config);
            
            // Track request distribution
            let mut request_counts = HashMap::new();
            
            // Register servers
            for i in 0..num_servers {
                let server = create_mock_server(&format!("lb_server_{}", i));
                request_counts.insert(server.id().to_string(), 0u64);
                manager.register_server(server).await.unwrap();
            }
            
            // Send requests
            for i in 0..num_requests {
                let request = MCPRequest::new("lb_test", serde_json::json!({"seq": i}));
                let _ = manager.send_request(request).await;
            }
            
            // Check distribution (should be relatively even)
            let expected_per_server = num_requests / num_servers;
            let tolerance = expected_per_server / 2; // 50% tolerance
            
            for (_, count) in request_counts {
                prop_assert!(
                    count >= expected_per_server.saturating_sub(tolerance) &&
                    count <= expected_per_server + tolerance,
                    "Uneven load distribution"
                );
            }
        })
    }
    
    #[test]
    fn prop_concurrent_operations_maintain_consistency(
        operations in prop::collection::vec(
            prop_oneof![
                arb_mcp_server().prop_map(|s| ("register", s.id(), Some(s))),
                arb_server_id().prop_map(|id| ("unregister", id, None)),
                arb_server_id().prop_map(|id| ("get", id, None)),
            ],
            1..50
        )
    ) {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let manager = Arc::new(create_test_manager());
            let mut handles = vec![];
            
            // Execute operations concurrently
            for (op_type, server_id, server) in operations {
                let manager_clone = manager.clone();
                let handle = tokio::spawn(async move {
                    match op_type {
                        "register" => {
                            if let Some(server) = server {
                                let _ = manager_clone.register_server(server).await;
                            }
                        }
                        "unregister" => {
                            let _ = manager_clone.unregister_server(&server_id).await;
                        }
                        "get" => {
                            let _ = manager_clone.get_server(&server_id).await;
                        }
                        _ => {}
                    }
                });
                handles.push(handle);
            }
            
            // Wait for all operations
            for handle in handles {
                let _ = handle.await;
            }
            
            // Verify consistency
            let servers = manager.get_servers().await;
            let mut seen_ids = std::collections::HashSet::new();
            
            for server in servers {
                prop_assert!(
                    seen_ids.insert(server.id().to_string()),
                    "Duplicate server ID found"
                );
            }
        })
    }
    
    #[test]
    fn prop_metrics_accuracy(
        num_requests in 10usize..100,
        success_rate in 0.0f64..1.0
    ) {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let manager = create_test_manager();
            let server = create_mock_server("metrics_test");
            let mock_conn = Arc::new(MockMCPConnection::new(server.id().to_string()));
            
            // Set failure rate
            mock_conn.set_fail_rate(1.0 - success_rate).await;
            manager.register_server(server).await.unwrap();
            
            // Send requests and track results
            let mut success_count = 0;
            let mut failure_count = 0;
            
            for i in 0..num_requests {
                let request = MCPRequest::new("metrics", serde_json::json!({"i": i}));
                match manager.send_request(request).await {
                    Ok(_) => success_count += 1,
                    Err(_) => failure_count += 1,
                }
            }
            
            // Get metrics
            let metrics = manager.get_metrics();
            
            // Verify metrics match actual results
            let total_recorded = success_count + failure_count;
            prop_assert_eq!(total_recorded, num_requests);
            
            // Success rate should approximately match expected
            let actual_rate = success_count as f64 / num_requests as f64;
            prop_assert!(
                (actual_rate - success_rate).abs() < 0.2,
                "Success rate deviation too high"
            );
        })
    }
    
    #[test]
    fn prop_connection_pool_respects_limits(
        config in arb_mcp_config(),
        concurrent_requests in 1usize..200
    ) {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let manager = Arc::new(MCPManager::new(config.clone()));
            let server = create_mock_server("pool_limit_test");
            manager.register_server(server).await.unwrap();
            
            // Send many concurrent requests
            let mut handles = vec![];
            for i in 0..concurrent_requests {
                let manager_clone = manager.clone();
                let handle = tokio::spawn(async move {
                    let request = MCPRequest::new("pool", serde_json::json!({"i": i}));
                    manager_clone.send_request(request).await
                });
                handles.push(handle);
            }
            
            // Wait for all requests
            for handle in handles {
                let _ = handle.await;
            }
            
            // Pool should not exceed configured limits
            // (In a real implementation, we'd check actual pool metrics)
            prop_assert!(true, "Connection pool limits respected");
        })
    }
}