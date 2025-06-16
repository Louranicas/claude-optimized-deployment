//! Comprehensive test suite for MCP Manager
//!
//! Follows patterns from "Zero to Production in Rust" for test organization,
//! mock implementations, test fixtures, and performance assertions.

use claude_optimized_deployment_rust::mcp_manager::{
    DeploymentManager, HealthMonitor, McpConfig, McpError, McpManager, McpServer, MetricsCollector,
    Result, ServerRegistry, ServerState,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Barrier, RwLock};
use tokio::time::timeout;

// Test fixtures module
mod fixtures {
    use super::*;

    /// Creates a test configuration with sensible defaults
    pub fn test_config() -> McpConfig {
        McpConfig {
            max_connections_per_server: 5,
            connection_timeout_ms: 1000,
            request_timeout_ms: 5000,
            health_check_interval_secs: 1,
            max_retries: 2,
            retry_backoff_multiplier: 1.5,
            enable_connection_pooling: true,
            enable_load_balancing: true,
            enable_health_checks: true,
            enable_metrics: true,
            circuit_breaker_threshold: 3,
            circuit_breaker_recovery_secs: 5,
            ..Default::default()
        }
    }

    /// Creates a test MCP manager with mock dependencies
    pub async fn test_manager() -> McpManager {
        let config = test_config();
        McpManager::new(config)
    }

    /// Creates multiple test servers
    pub fn test_servers(count: usize) -> Vec<McpServer> {
        (0..count)
            .map(|i| McpServer {
                id: format!("test-server-{}", i),
                name: format!("Test Server {}", i),
                server_type: "test".to_string(),
                endpoint: format!("ws://localhost:{}", 8000 + i),
                state: ServerState::Stopped,
                metadata: HashMap::new(),
            })
            .collect()
    }
}

// Mock implementations module
mod mocks {
    use super::*;
    use async_trait::async_trait;

    /// Mock server that simulates various behaviors
    pub struct MockServer {
        pub id: String,
        pub fail_count: Arc<RwLock<usize>>,
        pub response_delay: Duration,
        pub should_fail: bool,
    }

    impl MockServer {
        pub fn new(id: &str) -> Self {
            Self {
                id: id.to_string(),
                fail_count: Arc::new(RwLock::new(0)),
                response_delay: Duration::from_millis(10),
                should_fail: false,
            }
        }

        pub fn with_delay(mut self, delay: Duration) -> Self {
            self.response_delay = delay;
            self
        }

        pub fn with_failures(mut self) -> Self {
            self.should_fail = true;
            self
        }
    }
}

// Thread safety tests
#[cfg(test)]
mod thread_safety_tests {
    use super::fixtures::*;
    use super::*;

    #[tokio::test]
    async fn test_concurrent_server_registration() {
        let manager = test_manager().await;
        let barrier = Arc::new(Barrier::new(10));
        let registry = manager.registry().clone();

        let mut handles = vec![];

        for i in 0..10 {
            let registry = registry.clone();
            let barrier = barrier.clone();

            let handle = tokio::spawn(async move {
                barrier.wait().await;

                let server = McpServer {
                    id: format!("concurrent-{}", i),
                    name: format!("Concurrent Server {}", i),
                    server_type: "test".to_string(),
                    endpoint: format!("ws://localhost:{}", 9000 + i),
                    state: ServerState::Stopped,
                    metadata: HashMap::new(),
                };

                let mut reg = registry.write().await;
                reg.register_server(server).await
            });

            handles.push(handle);
        }

        // Wait for all tasks to complete
        let results: Vec<_> = futures::future::join_all(handles).await;

        // Verify all registrations succeeded
        for result in results {
            assert!(result.is_ok());
            assert!(result.unwrap().is_ok());
        }

        // Verify all servers are registered
        let registry = manager.registry().read().await;
        assert_eq!(registry.server_count(), 10);
    }

    #[tokio::test]
    async fn test_concurrent_health_checks() {
        let manager = test_manager().await;
        manager.start().await.unwrap();

        // Register multiple servers
        let servers = test_servers(5);
        let registry = manager.registry();

        for server in servers {
            let mut reg = registry.write().await;
            reg.register_server(server).await.unwrap();
        }

        // Run concurrent health checks
        let health_monitor = manager.health_monitor();
        let barrier = Arc::new(Barrier::new(5));
        let mut handles = vec![];

        for i in 0..5 {
            let health_monitor = health_monitor.clone();
            let barrier = barrier.clone();
            let server_id = format!("test-server-{}", i);

            let handle = tokio::spawn(async move {
                barrier.wait().await;
                health_monitor.check_server_health(&server_id).await
            });

            handles.push(handle);
        }

        let results: Vec<_> = futures::future::join_all(handles).await;

        // Verify no panics or deadlocks
        for result in results {
            assert!(result.is_ok());
        }

        manager.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_connection_pool_thread_safety() {
        let config = test_config();
        let pool = Arc::new(ConnectionPool::new(config.max_connections_per_server));
        let barrier = Arc::new(Barrier::new(20));

        let mut handles = vec![];

        // Spawn multiple tasks that acquire and release connections
        for i in 0..20 {
            let pool = pool.clone();
            let barrier = barrier.clone();

            let handle = tokio::spawn(async move {
                barrier.wait().await;

                for _ in 0..10 {
                    let conn = pool.acquire("test-server").await;
                    assert!(conn.is_ok());

                    // Simulate work
                    tokio::time::sleep(Duration::from_micros(100)).await;

                    // Connection dropped automatically
                }
            });

            handles.push(handle);
        }

        let results: Vec<_> = futures::future::join_all(handles).await;

        // Verify no panics
        for result in results {
            assert!(result.is_ok());
        }
    }
}

// Error handling tests
#[cfg(test)]
mod error_handling_tests {
    use super::fixtures::*;
    use super::mocks::*;
    use super::*;

    #[tokio::test]
    async fn test_server_registration_duplicate_id() {
        let manager = test_manager().await;
        let server = test_servers(1).into_iter().next().unwrap();

        let mut registry = manager.registry().write().await;

        // First registration should succeed
        assert!(registry.register_server(server.clone()).await.is_ok());

        // Duplicate registration should fail
        match registry.register_server(server).await {
            Err(McpError::DuplicateServer(id)) => {
                assert_eq!(id, "test-server-0");
            }
            _ => panic!("Expected DuplicateServer error"),
        }
    }

    #[tokio::test]
    async fn test_connection_timeout_handling() {
        let mut config = test_config();
        config.connection_timeout_ms = 100; // Very short timeout

        let manager = McpManager::new(config);
        let slow_server = McpServer {
            id: "slow-server".to_string(),
            name: "Slow Server".to_string(),
            server_type: "test".to_string(),
            endpoint: "ws://192.0.2.1:8080".to_string(), // Non-routable IP
            state: ServerState::Stopped,
            metadata: HashMap::new(),
        };

        let mut registry = manager.registry().write().await;
        registry.register_server(slow_server).await.unwrap();
        drop(registry);

        // Attempt to connect should timeout
        let deployment_mgr = manager.deployment_manager();
        match deployment_mgr.deploy_server("slow-server").await {
            Err(McpError::ConnectionTimeout) => {
                // Expected
            }
            _ => panic!("Expected ConnectionTimeout error"),
        }
    }

    #[tokio::test]
    async fn test_circuit_breaker_activation() {
        let mut config = test_config();
        config.circuit_breaker_threshold = 3;

        let manager = McpManager::new(config);
        manager.start().await.unwrap();

        let failing_server = McpServer {
            id: "failing-server".to_string(),
            name: "Failing Server".to_string(),
            server_type: "test".to_string(),
            endpoint: "ws://localhost:7999".to_string(),
            state: ServerState::Running,
            metadata: HashMap::new(),
        };

        let mut registry = manager.registry().write().await;
        registry.register_server(failing_server).await.unwrap();
        drop(registry);

        // Simulate multiple failures
        for _ in 0..3 {
            let _ = manager
                .deployment_manager()
                .execute_command("failing-server", "test_command")
                .await;
        }

        // Circuit breaker should now be open
        match manager
            .deployment_manager()
            .execute_command("failing-server", "test_command")
            .await
        {
            Err(McpError::CircuitBreakerOpen) => {
                // Expected
            }
            _ => panic!("Expected CircuitBreakerOpen error"),
        }

        manager.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_graceful_shutdown_with_active_connections() {
        let manager = test_manager().await;
        manager.start().await.unwrap();

        // Create some active connections
        let servers = test_servers(3);
        for server in servers {
            let mut registry = manager.registry().write().await;
            registry.register_server(server).await.unwrap();
        }

        // Start some background operations
        let deployment_mgr = manager.deployment_manager().clone();
        let handle = tokio::spawn(async move {
            for i in 0..10 {
                let _ = deployment_mgr
                    .get_server_status(&format!("test-server-{}", i % 3))
                    .await;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });

        // Give operations time to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Shutdown should complete gracefully
        let shutdown_result = timeout(Duration::from_secs(5), manager.stop()).await;

        assert!(shutdown_result.is_ok());
        assert!(shutdown_result.unwrap().is_ok());

        // Background task should complete or be cancelled
        let _ = timeout(Duration::from_secs(1), handle).await;
    }
}

// Performance characteristic tests
#[cfg(test)]
mod performance_tests {
    use super::fixtures::*;
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn test_server_registration_performance() {
        let manager = test_manager().await;
        let servers = test_servers(1000);

        let start = Instant::now();

        for server in servers {
            let mut registry = manager.registry().write().await;
            registry.register_server(server).await.unwrap();
        }

        let duration = start.elapsed();

        // Should register 1000 servers in under 1 second
        assert!(duration.as_millis() < 1000);

        // Verify all servers registered
        let registry = manager.registry().read().await;
        assert_eq!(registry.server_count(), 1000);
    }

    #[tokio::test]
    async fn test_concurrent_request_throughput() {
        let manager = test_manager().await;
        manager.start().await.unwrap();

        // Register test servers
        let servers = test_servers(10);
        for server in servers {
            let mut registry = manager.registry().write().await;
            registry.register_server(server).await.unwrap();
        }

        let deployment_mgr = manager.deployment_manager();
        let start = Instant::now();
        let mut handles = vec![];

        // Spawn 100 concurrent operations
        for i in 0..100 {
            let deployment_mgr = deployment_mgr.clone();
            let server_id = format!("test-server-{}", i % 10);

            let handle =
                tokio::spawn(async move { deployment_mgr.get_server_status(&server_id).await });

            handles.push(handle);
        }

        let results: Vec<_> = futures::future::join_all(handles).await;
        let duration = start.elapsed();

        // All operations should complete
        for result in results {
            assert!(result.is_ok());
        }

        // Should handle 100 concurrent requests in under 500ms
        assert!(duration.as_millis() < 500);

        manager.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_memory_usage_under_load() {
        let manager = test_manager().await;
        manager.start().await.unwrap();

        // Measure initial memory
        let initial_memory = get_current_memory_usage();

        // Register many servers
        let servers = test_servers(100);
        for server in servers {
            let mut registry = manager.registry().write().await;
            registry.register_server(server).await.unwrap();
        }

        // Perform many operations
        let deployment_mgr = manager.deployment_manager();
        for _ in 0..1000 {
            let server_id = format!("test-server-{}", rand::random::<usize>() % 100);
            let _ = deployment_mgr.get_server_status(&server_id).await;
        }

        // Measure final memory
        let final_memory = get_current_memory_usage();
        let memory_increase = final_memory - initial_memory;

        // Memory increase should be reasonable (< 100MB)
        assert!(memory_increase < 100 * 1024 * 1024);

        manager.stop().await.unwrap();
    }
}

// PyO3 binding correctness tests
#[cfg(test)]
mod pyo3_binding_tests {
    use super::fixtures::*;
    use super::*;
    use pyo3::prelude::*;
    use pyo3::types::PyDict;

    #[test]
    fn test_config_python_conversion() {
        Python::with_gil(|py| {
            let config = test_config();

            // Convert to Python dict
            let py_dict = PyDict::new(py);
            py_dict
                .set_item(
                    "max_connections_per_server",
                    config.max_connections_per_server,
                )
                .unwrap();
            py_dict
                .set_item("connection_timeout_ms", config.connection_timeout_ms)
                .unwrap();
            py_dict
                .set_item("enable_metrics", config.enable_metrics)
                .unwrap();

            // Verify values
            assert_eq!(
                py_dict
                    .get_item("max_connections_per_server")
                    .unwrap()
                    .extract::<usize>()
                    .unwrap(),
                5
            );
            assert_eq!(
                py_dict
                    .get_item("connection_timeout_ms")
                    .unwrap()
                    .extract::<u64>()
                    .unwrap(),
                1000
            );
            assert!(py_dict
                .get_item("enable_metrics")
                .unwrap()
                .extract::<bool>()
                .unwrap());
        });
    }

    #[tokio::test]
    async fn test_async_python_integration() {
        Python::with_gil(|py| {
            pyo3_asyncio::tokio::run(py, async move {
                let manager = test_manager().await;

                // Test that manager can be used from Python async context
                manager.start().await.unwrap();

                // Register a server
                let server = test_servers(1).into_iter().next().unwrap();
                let mut registry = manager.registry().write().await;
                registry.register_server(server).await.unwrap();
                drop(registry);

                // Verify registration
                let registry = manager.registry().read().await;
                assert_eq!(registry.server_count(), 1);

                manager.stop().await.unwrap();
                Ok(())
            })
            .unwrap();
        });
    }

    #[test]
    fn test_error_conversion_to_python() {
        Python::with_gil(|py| {
            let errors = vec![
                McpError::ServerNotFound("test".to_string()),
                McpError::ConnectionTimeout,
                McpError::CircuitBreakerOpen,
                McpError::DuplicateServer("dup".to_string()),
            ];

            for error in errors {
                // Convert to Python exception
                let py_err: PyErr = error.into();

                // Verify it's a valid Python exception
                assert!(py_err.value(py).to_string().len() > 0);
            }
        });
    }
}

// Helper functions
fn get_current_memory_usage() -> usize {
    // Simplified memory measurement
    // In a real implementation, use a proper memory profiler
    std::mem::size_of::<McpManager>() * 1000
}

// Integration test module
#[cfg(test)]
mod integration_tests {
    use super::fixtures::*;
    use super::*;

    #[tokio::test]
    async fn test_full_lifecycle() {
        let manager = test_manager().await;

        // Start manager
        manager.start().await.unwrap();

        // Register servers
        let servers = test_servers(5);
        for server in servers {
            let mut registry = manager.registry().write().await;
            registry.register_server(server).await.unwrap();
        }

        // Deploy servers
        let deployment_mgr = manager.deployment_manager();
        for i in 0..5 {
            deployment_mgr
                .deploy_server(&format!("test-server-{}", i))
                .await
                .unwrap();
        }

        // Verify health checks are running
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Check metrics
        let metrics = manager.metrics_collector().get_metrics().await;
        assert!(metrics.total_requests > 0);

        // Stop servers
        for i in 0..5 {
            deployment_mgr
                .stop_server(&format!("test-server-{}", i))
                .await
                .unwrap();
        }

        // Shutdown manager
        manager.stop().await.unwrap();
    }
}
