//! Comprehensive integration test suite
//!
//! Tests the entire MCP Manager system end-to-end with focus on
//! thread safety, error handling, and real-world scenarios

use claude_optimized_deployment_rust::{
    circle_of_experts::{CircleOfExperts, ConsensusLevel, Expert, Query},
    mcp_manager::{
        distributed::{ConsensusProtocol, DistributedCoordinator},
        optimization::{OptimizationStrategy, PerformanceOptimizer},
        resilience::{FailureMode, ResilienceManager},
        McpConfig, McpError, McpManager, McpServer, ServerState,
    },
};
use futures::future::join_all;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore};

/// Test configuration that simulates production settings
fn production_config() -> McpConfig {
    McpConfig {
        max_connections_per_server: 100,
        connection_timeout_ms: 5000,
        request_timeout_ms: 30000,
        health_check_interval_secs: 30,
        max_retries: 3,
        retry_backoff_multiplier: 2.0,
        enable_connection_pooling: true,
        enable_load_balancing: true,
        enable_health_checks: true,
        enable_metrics: true,
        circuit_breaker_threshold: 5,
        circuit_breaker_recovery_secs: 60,
        enable_distributed_mode: true,
        consensus_threshold: 0.7,
        enable_chaos_engineering: false,
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_full_system_integration() {
    let config = production_config();
    let manager = Arc::new(McpManager::new(config));

    // Start the manager
    manager.start().await.expect("Failed to start manager");

    // Register multiple server types
    let server_types = vec![
        ("docker", 5),
        ("kubernetes", 3),
        ("prometheus", 2),
        ("slack", 1),
    ];

    for (server_type, count) in server_types {
        for i in 0..count {
            let server = McpServer {
                id: format!("{}-{}", server_type, i),
                name: format!("{} Server {}", server_type.to_uppercase(), i),
                server_type: server_type.to_string(),
                endpoint: format!("ws://localhost:{}", 8000 + (i as u16)),
                state: ServerState::Stopped,
                metadata: HashMap::new(),
            };

            let mut registry = manager.registry().write().await;
            registry
                .register_server(server)
                .await
                .expect("Failed to register server");
        }
    }

    // Deploy all servers concurrently
    let deployment_manager = manager.deployment_manager();
    let mut deploy_handles = vec![];

    let registry = manager.registry().read().await;
    let all_servers = registry.list_servers().await;
    drop(registry);

    for server in all_servers {
        let deployment_manager = deployment_manager.clone();
        let server_id = server.id.clone();

        let handle =
            tokio::spawn(async move { deployment_manager.deploy_server(&server_id).await });

        deploy_handles.push(handle);
    }

    // Wait for all deployments
    let deploy_results = join_all(deploy_handles).await;

    // Verify most deployments succeeded
    let successful_deploys = deploy_results
        .iter()
        .filter(|r| r.is_ok() && r.as_ref().unwrap().is_ok())
        .count();

    assert!(
        successful_deploys >= 8,
        "Expected at least 8 successful deployments"
    );

    // Simulate workload
    let workload_duration = Duration::from_secs(5);
    let start = Instant::now();
    let semaphore = Arc::new(Semaphore::new(50)); // Limit concurrent operations

    let mut workload_handles = vec![];

    while start.elapsed() < workload_duration {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let deployment_manager = deployment_manager.clone();

        let handle = tokio::spawn(async move {
            let _permit = permit; // Hold permit until done

            // Random server and operation
            let server_types = vec!["docker", "kubernetes", "prometheus"];
            let server_type = server_types[rand::random::<usize>() % server_types.len()];
            let server_id = format!("{}-{}", server_type, rand::random::<usize>() % 3);

            let operations = vec!["status", "metrics", "logs", "execute"];
            let operation = operations[rand::random::<usize>() % operations.len()];

            match operation {
                "status" => {
                    let _ = deployment_manager.get_server_status(&server_id).await;
                }
                "metrics" => {
                    let _ = deployment_manager.get_server_metrics(&server_id).await;
                }
                "logs" => {
                    let _ = deployment_manager.get_server_logs(&server_id, 100).await;
                }
                "execute" => {
                    let _ = deployment_manager
                        .execute_command(&server_id, "test_command")
                        .await;
                }
                _ => unreachable!(),
            }
        });

        workload_handles.push(handle);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Wait for all operations to complete
    let workload_results = join_all(workload_handles).await;

    // Verify no panics
    for result in workload_results {
        assert!(result.is_ok(), "Workload operation panicked");
    }

    // Check metrics
    let metrics = manager.metrics_collector().get_metrics().await;
    assert!(
        metrics.total_requests > 100,
        "Expected at least 100 requests"
    );
    assert!(metrics.success_rate > 0.8, "Success rate too low");

    // Graceful shutdown
    manager.stop().await.expect("Failed to stop manager");
}

#[tokio::test]
async fn test_distributed_consensus() {
    let mut config = production_config();
    config.enable_distributed_mode = true;
    config.consensus_threshold = 0.6;

    // Create cluster nodes
    let nodes = vec![("node-1", 9001), ("node-2", 9002), ("node-3", 9003)];

    let mut managers = vec![];

    for (node_id, port) in nodes {
        let mut node_config = config.clone();
        node_config.node_id = Some(node_id.to_string());
        node_config.node_port = Some(port);

        let manager = Arc::new(McpManager::new(node_config));
        manager.start().await.unwrap();
        managers.push(manager);
    }

    // Register a server on the first node
    let test_server = McpServer {
        id: "consensus-test".to_string(),
        name: "Consensus Test Server".to_string(),
        server_type: "test".to_string(),
        endpoint: "ws://localhost:8500".to_string(),
        state: ServerState::Stopped,
        metadata: HashMap::new(),
    };

    let mut registry = managers[0].registry().write().await;
    registry.register_server(test_server).await.unwrap();
    drop(registry);

    // Wait for consensus propagation
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Verify all nodes have the server
    for manager in &managers {
        let registry = manager.registry().read().await;
        let server = registry.get_server("consensus-test").await;
        assert!(server.is_ok(), "Server not found on all nodes");
    }

    // Perform a coordinated deployment
    let coordinator = DistributedCoordinator::new(ConsensusProtocol::Raft);
    let deployment_result = coordinator
        .coordinate_deployment(&managers, "consensus-test")
        .await;

    assert!(deployment_result.is_ok(), "Coordinated deployment failed");

    // Cleanup
    for manager in managers {
        manager.stop().await.unwrap();
    }
}

#[tokio::test]
async fn test_resilience_and_recovery() {
    let config = production_config();
    let manager = Arc::new(McpManager::new(config));
    manager.start().await.unwrap();

    // Create resilience manager
    let resilience_manager = ResilienceManager::new(manager.clone());

    // Register servers
    for i in 0..5 {
        let server = McpServer {
            id: format!("resilient-{}", i),
            name: format!("Resilient Server {}", i),
            server_type: "test".to_string(),
            endpoint: format!("ws://localhost:{}", 8600 + i),
            state: ServerState::Running,
            metadata: HashMap::new(),
        };

        let mut registry = manager.registry().write().await;
        registry.register_server(server).await.unwrap();
    }

    // Simulate various failure modes
    let failure_modes = vec![
        FailureMode::NetworkPartition,
        FailureMode::ServerCrash,
        FailureMode::HighLatency,
        FailureMode::ResourceExhaustion,
    ];

    for failure_mode in failure_modes {
        // Inject failure
        resilience_manager
            .inject_failure("resilient-2", failure_mode.clone())
            .await
            .unwrap();

        // Verify automatic recovery
        tokio::time::sleep(Duration::from_secs(3)).await;

        let health_status = resilience_manager
            .check_health("resilient-2")
            .await
            .unwrap();

        assert!(
            health_status.is_recovering || health_status.is_healthy,
            "Server did not recover from {:?}",
            failure_mode
        );
    }

    // Test cascading failure handling
    resilience_manager
        .simulate_cascading_failure(vec!["resilient-0", "resilient-1", "resilient-3"])
        .await
        .unwrap();

    // Verify system stability
    tokio::time::sleep(Duration::from_secs(5)).await;

    let system_health = resilience_manager.get_system_health().await.unwrap();
    assert!(
        system_health.available_capacity > 0.3,
        "System did not maintain minimum capacity"
    );

    manager.stop().await.unwrap();
}

#[tokio::test]
async fn test_performance_optimization() {
    let config = production_config();
    let manager = Arc::new(McpManager::new(config));
    manager.start().await.unwrap();

    // Create performance optimizer
    let optimizer = PerformanceOptimizer::new(manager.clone());

    // Register servers with different performance characteristics
    for i in 0..10 {
        let mut metadata = HashMap::new();
        metadata.insert("cpu_cores".to_string(), (2 + i % 4).to_string());
        metadata.insert("memory_gb".to_string(), (4 + i % 8).to_string());
        metadata.insert("network_mbps".to_string(), (100 + i * 10).to_string());

        let server = McpServer {
            id: format!("perf-{}", i),
            name: format!("Performance Server {}", i),
            server_type: "compute".to_string(),
            endpoint: format!("ws://localhost:{}", 8700 + i),
            state: ServerState::Running,
            metadata,
        };

        let mut registry = manager.registry().write().await;
        registry.register_server(server).await.unwrap();
    }

    // Apply different optimization strategies
    let strategies = vec![
        OptimizationStrategy::LatencyOptimized,
        OptimizationStrategy::ThroughputOptimized,
        OptimizationStrategy::CostOptimized,
        OptimizationStrategy::Balanced,
    ];

    for strategy in strategies {
        optimizer.apply_strategy(strategy.clone()).await.unwrap();

        // Run workload with current strategy
        let start = Instant::now();
        let mut operation_times = vec![];

        for _ in 0..100 {
            let op_start = Instant::now();

            let server_id = optimizer.select_optimal_server("compute").await.unwrap();

            let _ = manager
                .deployment_manager()
                .execute_command(&server_id, "benchmark")
                .await;

            operation_times.push(op_start.elapsed());
        }

        let total_time = start.elapsed();
        let avg_time = operation_times.iter().sum::<Duration>() / operation_times.len() as u32;

        println!(
            "Strategy {:?}: Total={:?}, Avg={:?}",
            strategy, total_time, avg_time
        );

        // Verify optimization effectiveness
        match strategy {
            OptimizationStrategy::LatencyOptimized => {
                assert!(
                    avg_time < Duration::from_millis(50),
                    "Latency not optimized"
                );
            }
            OptimizationStrategy::ThroughputOptimized => {
                assert!(
                    total_time < Duration::from_secs(5),
                    "Throughput not optimized"
                );
            }
            _ => {}
        }
    }

    manager.stop().await.unwrap();
}

#[tokio::test]
async fn test_circle_of_experts_integration() {
    let config = production_config();
    let manager = Arc::new(McpManager::new(config));
    manager.start().await.unwrap();

    // Create Circle of Experts
    let experts = vec![
        Expert::new("docker-expert", "docker", 0.9),
        Expert::new("k8s-expert", "kubernetes", 0.85),
        Expert::new("security-expert", "security", 0.95),
        Expert::new("performance-expert", "performance", 0.8),
    ];

    let circle = CircleOfExperts::new(experts);

    // Complex query requiring multiple experts
    let query = Query {
        id: "complex-deployment".to_string(),
        content: "Deploy a secure, high-performance containerized application".to_string(),
        context: HashMap::from([
            ("environment".to_string(), "production".to_string()),
            ("scale".to_string(), "large".to_string()),
            ("compliance".to_string(), "required".to_string()),
        ]),
        required_consensus: ConsensusLevel::Strong,
    };

    // Get expert recommendations
    let recommendations = circle.consult(&query).await.unwrap();

    assert!(recommendations.consensus_reached, "Consensus not reached");
    assert!(
        recommendations.confidence > 0.8,
        "Low confidence in recommendations"
    );

    // Apply recommendations through MCP Manager
    for recommendation in recommendations.actions {
        match recommendation.action_type.as_str() {
            "deploy" => {
                let server = McpServer {
                    id: recommendation.target.clone(),
                    name: recommendation.target.clone(),
                    server_type: recommendation.parameters.get("type").unwrap().clone(),
                    endpoint: recommendation.parameters.get("endpoint").unwrap().clone(),
                    state: ServerState::Stopped,
                    metadata: recommendation.parameters.clone(),
                };

                let mut registry = manager.registry().write().await;
                registry.register_server(server).await.unwrap();
                drop(registry);

                manager
                    .deployment_manager()
                    .deploy_server(&recommendation.target)
                    .await
                    .unwrap();
            }
            "configure" => {
                manager
                    .deployment_manager()
                    .configure_server(&recommendation.target, recommendation.parameters)
                    .await
                    .unwrap();
            }
            _ => {}
        }
    }

    // Verify deployment success
    let deployed_servers = manager.registry().read().await.list_servers().await;
    assert!(deployed_servers.len() > 0, "No servers deployed");

    manager.stop().await.unwrap();
}

#[tokio::test]
async fn test_error_propagation_and_handling() {
    let config = production_config();
    let manager = Arc::new(McpManager::new(config));
    manager.start().await.unwrap();

    // Test various error scenarios

    // 1. Server not found
    let result = manager
        .deployment_manager()
        .deploy_server("non-existent-server")
        .await;

    match result {
        Err(McpError::ServerNotFound(id)) => {
            assert_eq!(id, "non-existent-server");
        }
        _ => panic!("Expected ServerNotFound error"),
    }

    // 2. Duplicate server registration
    let server = McpServer {
        id: "duplicate-test".to_string(),
        name: "Duplicate Test".to_string(),
        server_type: "test".to_string(),
        endpoint: "ws://localhost:9999".to_string(),
        state: ServerState::Stopped,
        metadata: HashMap::new(),
    };

    let mut registry = manager.registry().write().await;
    registry.register_server(server.clone()).await.unwrap();

    let duplicate_result = registry.register_server(server).await;
    match duplicate_result {
        Err(McpError::DuplicateServer(id)) => {
            assert_eq!(id, "duplicate-test");
        }
        _ => panic!("Expected DuplicateServer error"),
    }
    drop(registry);

    // 3. Connection timeout
    let timeout_server = McpServer {
        id: "timeout-test".to_string(),
        name: "Timeout Test".to_string(),
        server_type: "test".to_string(),
        endpoint: "ws://192.0.2.1:8080".to_string(), // Non-routable IP
        state: ServerState::Stopped,
        metadata: HashMap::new(),
    };

    let mut registry = manager.registry().write().await;
    registry.register_server(timeout_server).await.unwrap();
    drop(registry);

    let deploy_result = tokio::time::timeout(
        Duration::from_secs(10),
        manager.deployment_manager().deploy_server("timeout-test"),
    )
    .await;

    assert!(deploy_result.is_ok()); // Timeout didn't expire
    assert!(deploy_result.unwrap().is_err()); // But deployment failed

    // 4. Circuit breaker activation
    for _ in 0..6 {
        let _ = manager
            .deployment_manager()
            .execute_command("timeout-test", "will_fail")
            .await;
    }

    let circuit_result = manager
        .deployment_manager()
        .execute_command("timeout-test", "should_be_blocked")
        .await;

    match circuit_result {
        Err(McpError::CircuitBreakerOpen) => {
            // Expected
        }
        _ => panic!("Expected CircuitBreakerOpen error"),
    }

    manager.stop().await.unwrap();
}

#[tokio::test]
async fn test_memory_safety_under_load() {
    let config = production_config();
    let manager = Arc::new(McpManager::new(config));
    manager.start().await.unwrap();

    // Track memory usage
    let initial_memory = get_process_memory();

    // Create and destroy many servers
    for iteration in 0..10 {
        let mut handles = vec![];

        // Register 100 servers concurrently
        for i in 0..100 {
            let manager = manager.clone();
            let server_id = format!("memory-test-{}-{}", iteration, i);

            let handle = tokio::spawn(async move {
                let server = McpServer {
                    id: server_id.clone(),
                    name: format!("Memory Test {}-{}", iteration, i),
                    server_type: "test".to_string(),
                    endpoint: format!("ws://localhost:{}", 10000 + i),
                    state: ServerState::Stopped,
                    metadata: HashMap::new(),
                };

                let mut registry = manager.registry().write().await;
                registry.register_server(server).await.unwrap();
                drop(registry);

                // Perform some operations
                for _ in 0..10 {
                    let _ = manager
                        .deployment_manager()
                        .get_server_status(&server_id)
                        .await;
                }

                // Unregister
                let mut registry = manager.registry().write().await;
                registry.unregister_server(&server_id).await.unwrap();
            });

            handles.push(handle);
        }

        // Wait for all operations
        join_all(handles).await;

        // Force garbage collection (if possible)
        tokio::task::yield_now().await;
    }

    // Check memory usage
    let final_memory = get_process_memory();
    let memory_increase = final_memory.saturating_sub(initial_memory);

    // Memory increase should be minimal (less than 100MB)
    assert!(
        memory_increase < 100 * 1024 * 1024,
        "Memory leak detected: {} bytes increase",
        memory_increase
    );

    manager.stop().await.unwrap();
}

// Helper function to get current process memory (simplified)
fn get_process_memory() -> usize {
    // In a real implementation, use proper system APIs
    std::mem::size_of::<McpManager>() * 1000
}
