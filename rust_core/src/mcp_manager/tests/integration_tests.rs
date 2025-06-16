use super::test_utils::*;
use crate::mcp_manager::{
    core::MCPManager,
    server::{MCPServer, ServerState},
    protocol::{MCPRequest, MCPResponse},
    error::MCPError,
    load_balancer::LoadBalancingStrategy,
};
use tokio::test;
use std::sync::Arc;
use std::time::Duration;
use tracing_test::traced_test;

#[tokio::test]
#[traced_test]
async fn test_server_registration_and_discovery() {
    let manager = create_test_manager();
    
    // Register multiple servers
    let server1 = create_mock_server("server1");
    let server2 = create_mock_server("server2");
    let server3 = create_mock_server("server3");
    
    manager.register_server(server1.clone()).await.unwrap();
    manager.register_server(server2.clone()).await.unwrap();
    manager.register_server(server3.clone()).await.unwrap();
    
    // Verify all servers are registered
    let servers = manager.get_servers().await;
    assert_eq!(servers.len(), 3);
    
    // Verify individual server lookup
    assert!(manager.get_server("server1").await.is_some());
    assert!(manager.get_server("server2").await.is_some());
    assert!(manager.get_server("server3").await.is_some());
    assert!(manager.get_server("nonexistent").await.is_none());
    
    // Unregister a server
    manager.unregister_server("server2").await.unwrap();
    
    // Verify server is removed
    let servers = manager.get_servers().await;
    assert_eq!(servers.len(), 2);
    assert!(manager.get_server("server2").await.is_none());
}

#[tokio::test]
#[traced_test]
async fn test_request_routing_with_load_balancing() {
    let manager = create_test_manager();
    let metrics_collector = Arc::new(TestMetricsCollector::new());
    
    // Register servers with mock connections
    let mut servers = vec![];
    for i in 1..=3 {
        let server = create_mock_server(&format!("server{}", i));
        let mock_conn = Arc::new(MockMCPConnection::new(server.id().to_string()));
        
        // Inject the mock connection
        servers.push((server.clone(), mock_conn.clone()));
        manager.register_server(server).await.unwrap();
    }
    
    // Send multiple requests
    let num_requests = 30;
    for i in 0..num_requests {
        let request = MCPRequest::new(
            format!("test_method_{}", i % 3),
            serde_json::json!({"index": i}),
        );
        
        match manager.send_request(request).await {
            Ok(response) => {
                // Record successful request
                metrics_collector.record_request("success", Duration::from_millis(10), true).await;
            }
            Err(e) => {
                // Record failed request
                metrics_collector.record_request("error", Duration::from_millis(10), false).await;
            }
        }
    }
    
    // Verify load distribution (should be roughly equal with round-robin)
    for (server, mock_conn) in &servers {
        let count = mock_conn.get_request_count();
        // With 30 requests and 3 servers, each should get ~10 requests (±2 for variance)
        assert!((8..=12).contains(&count), 
            "Server {} got {} requests, expected ~10", server.id(), count);
    }
}

#[tokio::test]
#[traced_test]
async fn test_connection_pooling() {
    let mut config = create_test_config();
    config.max_connections_per_server = 3;
    let manager = MCPManager::new(config);
    
    let server = create_mock_server("pool_test_server");
    manager.register_server(server.clone()).await.unwrap();
    
    // Send concurrent requests that should reuse connections
    let mut handles = vec![];
    for i in 0..10 {
        let manager_clone = Arc::new(manager);
        let handle = tokio::spawn(async move {
            let request = MCPRequest::new("pool_test", serde_json::json!({"id": i}));
            manager_clone.send_request(request).await
        });
        handles.push(handle);
    }
    
    // Wait for all requests to complete
    let mut success_count = 0;
    for handle in handles {
        if let Ok(Ok(_)) = handle.await {
            success_count += 1;
        }
    }
    
    // Most requests should succeed with connection pooling
    assert!(success_count >= 8, "Expected at least 8 successful requests, got {}", success_count);
}

#[tokio::test]
#[traced_test]
async fn test_health_check_integration() {
    let mut config = create_test_config();
    config.health_check_interval_secs = 1; // Fast health checks for testing
    let manager = MCPManager::new(config);
    
    // Create servers with different health states
    let healthy_server = create_mock_server("healthy");
    let unhealthy_server = create_mock_server("unhealthy");
    
    // Register servers
    manager.register_server(healthy_server.clone()).await.unwrap();
    manager.register_server(unhealthy_server.clone()).await.unwrap();
    
    // Wait for initial health checks
    tokio::time::sleep(Duration::from_secs(2)).await;
    
    // Send requests - should prefer healthy server
    let mut healthy_count = 0;
    let mut unhealthy_count = 0;
    
    for _ in 0..20 {
        let request = MCPRequest::new("health_test", serde_json::json!({}));
        match manager.send_request(request).await {
            Ok(_) => healthy_count += 1,
            Err(_) => unhealthy_count += 1,
        }
    }
    
    // Most requests should go to healthy server
    assert!(healthy_count > unhealthy_count, 
        "Expected more healthy responses ({}) than unhealthy ({})", 
        healthy_count, unhealthy_count);
}

#[tokio::test]
#[traced_test]
async fn test_circuit_breaker_integration() {
    let mut config = create_test_config();
    config.circuit_breaker_threshold = 3;
    config.circuit_breaker_recovery_secs = 2;
    let manager = MCPManager::new(config);
    
    let server = create_mock_server("circuit_test");
    let mock_conn = Arc::new(MockMCPConnection::new(server.id().to_string()));
    
    // Make connection fail
    mock_conn.set_fail_rate(1.0).await;
    
    manager.register_server(server.clone()).await.unwrap();
    
    // Send requests until circuit breaker trips
    let mut trip_count = 0;
    for i in 0..5 {
        let request = MCPRequest::new("circuit_test", serde_json::json!({"attempt": i}));
        if manager.send_request(request).await.is_err() {
            trip_count += 1;
        }
    }
    
    assert_eq!(trip_count, 5, "All requests should fail");
    
    // Circuit should be open now, requests should fail fast
    let start = std::time::Instant::now();
    let request = MCPRequest::new("circuit_test", serde_json::json!({}));
    let _ = manager.send_request(request).await;
    let duration = start.elapsed();
    
    // Should fail fast without retry delays
    assert!(duration < Duration::from_millis(500), 
        "Circuit breaker should fail fast, took {:?}", duration);
    
    // Reset connection to healthy
    mock_conn.set_fail_rate(0.0).await;
    
    // Wait for recovery
    tokio::time::sleep(Duration::from_secs(3)).await;
    
    // Circuit should recover
    let request = MCPRequest::new("circuit_test", serde_json::json!({"recovered": true}));
    assert!(manager.send_request(request).await.is_ok(), "Circuit should have recovered");
}

#[tokio::test]
#[traced_test]
async fn test_retry_mechanism() {
    let mut config = create_test_config();
    config.max_retries = 3;
    config.retry_backoff_multiplier = 2.0;
    let manager = MCPManager::new(config);
    
    let server = create_mock_server("retry_test");
    let mock_conn = Arc::new(MockMCPConnection::new(server.id().to_string()));
    
    // Set intermittent failure rate
    mock_conn.set_fail_rate(0.6).await; // 60% failure rate
    
    manager.register_server(server).await.unwrap();
    
    // Send multiple requests
    let mut success_count = 0;
    let mut total_attempts = 0;
    
    for i in 0..10 {
        let request = MCPRequest::new("retry_test", serde_json::json!({"request": i}));
        let start_count = mock_conn.get_request_count();
        
        if manager.send_request(request).await.is_ok() {
            success_count += 1;
        }
        
        let end_count = mock_conn.get_request_count();
        total_attempts += (end_count - start_count) as usize;
    }
    
    // With retries, success rate should be higher than failure rate
    assert!(success_count >= 7, "Expected at least 7 successful requests with retries, got {}", success_count);
    
    // Should have made more attempts than requests due to retries
    assert!(total_attempts > 10, "Expected more than 10 attempts due to retries, got {}", total_attempts);
}

#[tokio::test]
#[traced_test]
async fn test_timeout_handling() {
    let mut config = create_test_config();
    config.connection_timeout_ms = 100;
    config.request_timeout_ms = 200;
    let manager = MCPManager::new(config);
    
    let server = create_mock_server("timeout_test");
    let mock_conn = Arc::new(MockMCPConnection::new(server.id().to_string()));
    
    // Set high latency to trigger timeouts
    mock_conn.set_latency(300);
    
    manager.register_server(server).await.unwrap();
    
    // Request should timeout
    let request = MCPRequest::new("timeout_test", serde_json::json!({}));
    let result = manager.send_request(request).await;
    
    assert!(result.is_err(), "Request should timeout");
    match result.unwrap_err() {
        MCPError::Timeout(_) => (), // Expected
        other => panic!("Expected timeout error, got {:?}", other),
    }
}

#[tokio::test]
#[traced_test]
async fn test_concurrent_operations() {
    let manager = Arc::new(create_test_manager());
    
    // Register servers concurrently
    let mut handles = vec![];
    for i in 0..5 {
        let manager_clone = manager.clone();
        let handle = tokio::spawn(async move {
            let server = create_mock_server(&format!("concurrent_{}", i));
            manager_clone.register_server(server).await
        });
        handles.push(handle);
    }
    
    // Wait for all registrations
    for handle in handles {
        handle.await.unwrap().unwrap();
    }
    
    // Verify all servers registered
    assert_eq!(manager.get_servers().await.len(), 5);
    
    // Send concurrent requests
    let mut request_handles = vec![];
    for i in 0..50 {
        let manager_clone = manager.clone();
        let handle = tokio::spawn(async move {
            let request = MCPRequest::new("concurrent_test", serde_json::json!({"id": i}));
            manager_clone.send_request(request).await
        });
        request_handles.push(handle);
    }
    
    // Count successful requests
    let mut success_count = 0;
    for handle in request_handles {
        if let Ok(Ok(_)) = handle.await {
            success_count += 1;
        }
    }
    
    assert!(success_count >= 45, "Expected at least 45 successful concurrent requests, got {}", success_count);
}

#[tokio::test]
#[traced_test]
async fn test_graceful_shutdown() {
    let manager = create_test_manager();
    
    // Register servers
    for i in 0..3 {
        let server = create_mock_server(&format!("shutdown_{}", i));
        manager.register_server(server).await.unwrap();
    }
    
    // Start some background operations
    let manager_clone = Arc::new(manager);
    let operation_handle = tokio::spawn({
        let manager = manager_clone.clone();
        async move {
            for i in 0..100 {
                let request = MCPRequest::new("background", serde_json::json!({"op": i}));
                let _ = manager.send_request(request).await;
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    });
    
    // Let some operations run
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Unregister all servers (graceful shutdown)
    for i in 0..3 {
        manager_clone.unregister_server(&format!("shutdown_{}", i)).await.unwrap();
    }
    
    // Cancel background operations
    operation_handle.abort();
    
    // Verify clean shutdown
    assert_eq!(manager_clone.get_servers().await.len(), 0);
    
    // New requests should fail gracefully
    let request = MCPRequest::new("after_shutdown", serde_json::json!({}));
    assert!(manager_clone.send_request(request).await.is_err());
}