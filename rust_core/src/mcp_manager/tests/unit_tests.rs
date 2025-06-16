use crate::mcp_manager::{
    config::MCPConfig,
    error::{MCPError, MCPResult},
    server::{MCPServer, ServerState},
    protocol::{MCPRequest, MCPResponse, MCPProtocol},
    registry::ServerRegistry,
    connection_pool::ConnectionPool,
    load_balancer::{LoadBalancer, LoadBalancingStrategy},
    health_check::{HealthChecker, HealthStatus},
    metrics::MCPMetrics,
};
use std::collections::HashMap;
use std::time::Duration;

#[cfg(test)]
mod config_tests {
    use super::*;
    
    #[test]
    fn test_default_config() {
        let config = MCPConfig::default();
        
        assert_eq!(config.max_connections_per_server, 10);
        assert_eq!(config.connection_timeout_ms, 5000);
        assert_eq!(config.request_timeout_ms, 30000);
        assert_eq!(config.health_check_interval_secs, 30);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_backoff_multiplier, 2.0);
        assert!(config.enable_connection_pooling);
        assert!(config.enable_load_balancing);
        assert!(config.enable_health_checks);
        assert!(config.enable_metrics);
        assert_eq!(config.circuit_breaker_threshold, 5);
        assert_eq!(config.circuit_breaker_recovery_secs, 60);
    }
    
    #[test]
    fn test_config_duration_conversions() {
        let config = MCPConfig {
            connection_timeout_ms: 1500,
            request_timeout_ms: 45000,
            health_check_interval_secs: 120,
            circuit_breaker_recovery_secs: 300,
            ..Default::default()
        };
        
        assert_eq!(config.connection_timeout(), Duration::from_millis(1500));
        assert_eq!(config.request_timeout(), Duration::from_millis(45000));
        assert_eq!(config.health_check_interval(), Duration::from_secs(120));
        assert_eq!(config.circuit_breaker_recovery(), Duration::from_secs(300));
    }
}

#[cfg(test)]
mod error_tests {
    use super::*;
    
    #[test]
    fn test_error_display() {
        let errors = vec![
            MCPError::Connection("Connection refused".to_string()),
            MCPError::Protocol("Invalid protocol".to_string()),
            MCPError::ServerNotFound("server123".to_string()),
            MCPError::Configuration("Invalid config".to_string()),
            MCPError::LoadBalancing("No servers available".to_string()),
            MCPError::HealthCheck("Health check failed".to_string()),
            MCPError::Timeout(5000),
            MCPError::Capacity("Pool exhausted".to_string()),
            MCPError::Authentication("Invalid credentials".to_string()),
            MCPError::Internal("Internal error".to_string()),
        ];
        
        for error in errors {
            let error_string = error.to_string();
            assert!(!error_string.is_empty());
            
            // Test error conversion
            match error {
                MCPError::Timeout(ms) => {
                    assert!(error_string.contains(&ms.to_string()));
                }
                _ => {}
            }
        }
    }
    
    #[test]
    fn test_error_from_io() {
        let io_error = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let mcp_error: MCPError = io_error.into();
        
        match mcp_error {
            MCPError::Connection(msg) => assert!(msg.contains("refused")),
            _ => panic!("Expected Connection error"),
        }
    }
    
    #[test]
    fn test_error_from_timeout() {
        let timeout_error = tokio::time::error::Elapsed::new();
        let mcp_error: MCPError = timeout_error.into();
        
        match mcp_error {
            MCPError::Timeout(ms) => assert_eq!(ms, 5000), // Default timeout
            _ => panic!("Expected Timeout error"),
        }
    }
}

#[cfg(test)]
mod server_tests {
    use super::*;
    
    #[test]
    fn test_server_creation() {
        let mut metadata = HashMap::new();
        metadata.insert("region".to_string(), "us-west".to_string());
        metadata.insert("version".to_string(), "1.0.0".to_string());
        
        let server = MCPServer::new(
            "test_server".to_string(),
            "http://localhost:8080".to_string(),
            MCPProtocol::Http,
            metadata,
        );
        
        assert_eq!(server.id(), "test_server");
        assert_eq!(server.url(), "http://localhost:8080");
        assert_eq!(server.protocol(), &MCPProtocol::Http);
        assert_eq!(server.metadata().get("region"), Some(&"us-west".to_string()));
        assert_eq!(server.metadata().get("version"), Some(&"1.0.0".to_string()));
    }
    
    #[test]
    fn test_server_state_transitions() {
        let server = MCPServer::new(
            "state_test".to_string(),
            "http://localhost:8080".to_string(),
            MCPProtocol::Http,
            HashMap::new(),
        );
        
        // Initial state should be Unknown
        assert_eq!(server.state(), ServerState::Unknown);
        
        // Test state transitions
        server.set_state(ServerState::Healthy);
        assert_eq!(server.state(), ServerState::Healthy);
        
        server.set_state(ServerState::Unhealthy);
        assert_eq!(server.state(), ServerState::Unhealthy);
        
        server.set_state(ServerState::Degraded);
        assert_eq!(server.state(), ServerState::Degraded);
    }
}

#[cfg(test)]
mod protocol_tests {
    use super::*;
    use serde_json::json;
    
    #[test]
    fn test_request_creation() {
        let params = json!({
            "key": "value",
            "number": 42,
            "nested": {
                "field": "data"
            }
        });
        
        let request = MCPRequest::new("test_method", params.clone());
        
        assert_eq!(request.method, "test_method");
        assert_eq!(request.params, params);
        assert!(!request.id.is_empty());
    }
    
    #[test]
    fn test_request_with_id() {
        let request = MCPRequest::with_id(
            "custom_id_123".to_string(),
            "test_method".to_string(),
            json!({"data": "test"}),
        );
        
        assert_eq!(request.id, "custom_id_123");
        assert_eq!(request.method, "test_method");
    }
    
    #[test]
    fn test_response_success() {
        let response = MCPResponse::success(json!({"result": "ok"}));
        
        assert!(response.error.is_none());
        assert_eq!(response.result, Some(json!({"result": "ok"})));
    }
    
    #[test]
    fn test_response_error() {
        let response = MCPResponse::error(-32600, "Invalid request");
        
        assert!(response.result.is_none());
        assert!(response.error.is_some());
        
        let error = response.error.unwrap();
        assert_eq!(error.code, -32600);
        assert_eq!(error.message, "Invalid request");
    }
    
    #[test]
    fn test_protocol_variants() {
        let protocols = vec![
            MCPProtocol::Http,
            MCPProtocol::WebSocket,
            MCPProtocol::Grpc,
            MCPProtocol::Custom("mqtt".to_string()),
        ];
        
        for protocol in protocols {
            match protocol {
                MCPProtocol::Http => assert_eq!(format!("{:?}", protocol), "Http"),
                MCPProtocol::WebSocket => assert_eq!(format!("{:?}", protocol), "WebSocket"),
                MCPProtocol::Grpc => assert_eq!(format!("{:?}", protocol), "Grpc"),
                MCPProtocol::Custom(name) => assert!(format!("{:?}", protocol).contains(&name)),
            }
        }
    }
}

#[cfg(test)]
mod registry_tests {
    use super::*;
    use tokio::test;
    
    #[test]
    fn test_registry_operations() {
        let mut registry = ServerRegistry::new();
        
        // Test empty registry
        assert_eq!(registry.get_all().len(), 0);
        assert!(registry.get("nonexistent").is_none());
        
        // Add servers
        let server1 = MCPServer::new(
            "server1".to_string(),
            "http://localhost:8001".to_string(),
            MCPProtocol::Http,
            HashMap::new(),
        );
        
        let server2 = MCPServer::new(
            "server2".to_string(),
            "http://localhost:8002".to_string(),
            MCPProtocol::Http,
            HashMap::new(),
        );
        
        registry.register(server1.clone()).unwrap();
        registry.register(server2.clone()).unwrap();
        
        // Test retrieval
        assert_eq!(registry.get_all().len(), 2);
        assert!(registry.get("server1").is_some());
        assert!(registry.get("server2").is_some());
        
        // Test duplicate registration
        let result = registry.register(server1.clone());
        assert!(result.is_err());
        
        // Test removal
        registry.unregister("server1").unwrap();
        assert_eq!(registry.get_all().len(), 1);
        assert!(registry.get("server1").is_none());
        
        // Test removing non-existent
        let result = registry.unregister("nonexistent");
        assert!(result.is_err());
    }
    
    #[test]
    fn test_registry_health_filtering() {
        let mut registry = ServerRegistry::new();
        
        // Add servers with different health states
        let healthy = MCPServer::new(
            "healthy".to_string(),
            "http://localhost:8001".to_string(),
            MCPProtocol::Http,
            HashMap::new(),
        );
        healthy.set_state(ServerState::Healthy);
        
        let unhealthy = MCPServer::new(
            "unhealthy".to_string(),
            "http://localhost:8002".to_string(),
            MCPProtocol::Http,
            HashMap::new(),
        );
        unhealthy.set_state(ServerState::Unhealthy);
        
        let degraded = MCPServer::new(
            "degraded".to_string(),
            "http://localhost:8003".to_string(),
            MCPProtocol::Http,
            HashMap::new(),
        );
        degraded.set_state(ServerState::Degraded);
        
        registry.register(healthy).unwrap();
        registry.register(unhealthy).unwrap();
        registry.register(degraded).unwrap();
        
        // Test health filtering
        let healthy_servers = registry.get_healthy_servers();
        assert_eq!(healthy_servers.len(), 1);
        assert_eq!(healthy_servers[0].id(), "healthy");
        
        let available_servers = registry.get_available_servers();
        assert_eq!(available_servers.len(), 2); // healthy + degraded
    }
}

#[cfg(test)]
mod metrics_tests {
    use super::*;
    use std::time::Duration;
    
    #[test]
    fn test_metrics_counters() {
        let metrics = MCPMetrics::new();
        
        // Test initial state
        assert_eq!(metrics.get_server_count(), 0);
        assert_eq!(metrics.get_request_count(), 0);
        assert_eq!(metrics.get_error_count(), 0);
        
        // Test increments
        metrics.increment_server_count();
        metrics.increment_server_count();
        assert_eq!(metrics.get_server_count(), 2);
        
        metrics.increment_request_count();
        metrics.increment_request_count();
        metrics.increment_request_count();
        assert_eq!(metrics.get_request_count(), 3);
        
        metrics.increment_error_count();
        assert_eq!(metrics.get_error_count(), 1);
        
        // Test decrements
        metrics.decrement_server_count();
        assert_eq!(metrics.get_server_count(), 1);
    }
    
    #[test]
    fn test_metrics_latency_tracking() {
        let metrics = MCPMetrics::new();
        
        // Record some latencies
        metrics.record_request_duration(Duration::from_millis(10));
        metrics.record_request_duration(Duration::from_millis(20));
        metrics.record_request_duration(Duration::from_millis(30));
        metrics.record_request_duration(Duration::from_millis(40));
        metrics.record_request_duration(Duration::from_millis(50));
        
        // Test percentiles
        let p50 = metrics.get_latency_percentile(0.50);
        let p95 = metrics.get_latency_percentile(0.95);
        let p99 = metrics.get_latency_percentile(0.99);
        
        assert!(p50.is_some());
        assert!(p95.is_some());
        assert!(p99.is_some());
        
        // p50 should be around 30ms
        assert!(p50.unwrap().as_millis() >= 25 && p50.unwrap().as_millis() <= 35);
        
        // Percentiles should be ordered
        assert!(p50.unwrap() <= p95.unwrap());
        assert!(p95.unwrap() <= p99.unwrap());
    }
    
    #[test]
    fn test_metrics_reset() {
        let metrics = MCPMetrics::new();
        
        // Add some data
        metrics.increment_server_count();
        metrics.increment_request_count();
        metrics.increment_error_count();
        metrics.record_request_duration(Duration::from_millis(100));
        
        // Reset
        metrics.reset();
        
        // Verify reset
        assert_eq!(metrics.get_server_count(), 0);
        assert_eq!(metrics.get_request_count(), 0);
        assert_eq!(metrics.get_error_count(), 0);
        assert!(metrics.get_latency_percentile(0.50).is_none());
    }
}

#[cfg(test)]
mod load_balancer_tests {
    use super::*;
    
    #[test]
    fn test_round_robin_strategy() {
        let strategy = LoadBalancingStrategy::RoundRobin;
        let servers = vec![
            create_test_server("server1"),
            create_test_server("server2"),
            create_test_server("server3"),
        ];
        
        let lb = LoadBalancer::new(strategy);
        
        // Should cycle through servers
        let s1 = lb.select_server_sync(&servers).unwrap();
        let s2 = lb.select_server_sync(&servers).unwrap();
        let s3 = lb.select_server_sync(&servers).unwrap();
        let s4 = lb.select_server_sync(&servers).unwrap();
        
        assert_eq!(s1.id(), "server1");
        assert_eq!(s2.id(), "server2");
        assert_eq!(s3.id(), "server3");
        assert_eq!(s4.id(), "server1"); // Cycles back
    }
    
    #[test]
    fn test_least_connections_strategy() {
        let strategy = LoadBalancingStrategy::LeastConnections;
        let servers = vec![
            create_test_server("server1"),
            create_test_server("server2"),
            create_test_server("server3"),
        ];
        
        // Set connection counts
        servers[0].set_connection_count(5);
        servers[1].set_connection_count(2);
        servers[2].set_connection_count(8);
        
        let lb = LoadBalancer::new(strategy);
        
        // Should select server with least connections
        let selected = lb.select_server_sync(&servers).unwrap();
        assert_eq!(selected.id(), "server2");
    }
    
    #[test]
    fn test_random_strategy() {
        let strategy = LoadBalancingStrategy::Random;
        let servers = vec![
            create_test_server("server1"),
            create_test_server("server2"),
            create_test_server("server3"),
        ];
        
        let lb = LoadBalancer::new(strategy);
        
        // Should select random servers
        let mut selections = HashMap::new();
        for _ in 0..100 {
            let server = lb.select_server_sync(&servers).unwrap();
            *selections.entry(server.id().to_string()).or_insert(0) += 1;
        }
        
        // All servers should be selected at least once
        assert_eq!(selections.len(), 3);
        for (_, count) in selections {
            assert!(count > 0);
        }
    }
    
    #[test]
    fn test_weighted_round_robin_strategy() {
        let strategy = LoadBalancingStrategy::WeightedRoundRobin;
        let servers = vec![
            create_test_server_with_weight("server1", 1),
            create_test_server_with_weight("server2", 2),
            create_test_server_with_weight("server3", 3),
        ];
        
        let lb = LoadBalancer::new(strategy);
        
        // Count selections
        let mut selections = HashMap::new();
        for _ in 0..60 {
            let server = lb.select_server_sync(&servers).unwrap();
            *selections.entry(server.id().to_string()).or_insert(0) += 1;
        }
        
        // Selections should be proportional to weights
        assert!(selections["server1"] < selections["server2"]);
        assert!(selections["server2"] < selections["server3"]);
    }
    
    fn create_test_server(id: &str) -> MCPServer {
        MCPServer::new(
            id.to_string(),
            format!("http://{}:8080", id),
            MCPProtocol::Http,
            HashMap::new(),
        )
    }
    
    fn create_test_server_with_weight(id: &str, weight: u32) -> MCPServer {
        let mut metadata = HashMap::new();
        metadata.insert("weight".to_string(), weight.to_string());
        
        MCPServer::new(
            id.to_string(),
            format!("http://{}:8080", id),
            MCPProtocol::Http,
            metadata,
        )
    }
}

#[cfg(test)]
mod health_check_tests {
    use super::*;
    use tokio::test;
    
    #[tokio::test]
    async fn test_health_checker_basic() {
        let checker = HealthChecker::new(Duration::from_millis(100));
        let server = create_test_server("health_test");
        
        // Start monitoring
        checker.start_monitoring(server.clone()).await;
        
        // Wait for health check
        tokio::time::sleep(Duration::from_millis(200)).await;
        
        // Check status
        let status = checker.get_status(&server.id()).await;
        assert!(status.is_some());
        
        // Stop monitoring
        checker.stop_monitoring(&server.id()).await;
        
        // Status should be removed
        tokio::time::sleep(Duration::from_millis(100)).await;
        let status = checker.get_status(&server.id()).await;
        assert!(status.is_none());
    }
    
    #[test]
    fn test_health_status() {
        let status = HealthStatus::healthy();
        assert!(status.is_healthy);
        assert_eq!(status.consecutive_failures, 0);
        assert!(status.last_error.is_none());
        
        let status = HealthStatus::unhealthy("Connection failed");
        assert!(!status.is_healthy);
        assert_eq!(status.consecutive_failures, 1);
        assert_eq!(status.last_error, Some("Connection failed".to_string()));
    }
    
    fn create_test_server(id: &str) -> MCPServer {
        MCPServer::new(
            id.to_string(),
            format!("http://{}:8080", id),
            MCPProtocol::Http,
            HashMap::new(),
        )
    }
}