//! Integration tests for the orchestration engine
//!
//! These tests verify the complete orchestration functionality including
//! service deployment, resource management, and reliability patterns.

use claude_optimized_deployment_rust::{
    network::{NetworkAllocator, Protocol},
    orchestrator::{DeploymentState, EngineConfig, OrchestrationEngine},
    reliability::{CircuitBreaker, RecoveryManager, RecoveryStrategy, RetryPolicy},
    resources::{ResourceManager, ResourceRequest},
    services::{HealthCheckConfig, HealthChecker, LifecycleManager, ServiceRegistry},
};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use uuid::Uuid;

#[tokio::test]
async fn test_full_service_lifecycle() {
    // Create engine with test configuration
    let config = EngineConfig {
        max_concurrent_deployments: 10,
        registration_timeout_ms: 50,
        health_check_interval_secs: 1,
        ..Default::default()
    };

    let engine = OrchestrationEngine::new(config).await.unwrap();

    // Deploy a service
    let resources = ResourceRequest {
        cpu_cores: 1.0,
        memory_mb: 512,
        disk_mb: 1024,
    };

    let metadata = engine
        .deploy_service("test-service".to_string(), "1.0.0".to_string(), resources)
        .await
        .unwrap();

    assert_eq!(metadata.name, "test-service");
    assert_eq!(metadata.state, DeploymentState::Pending);

    // Wait for deployment
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Check service status
    let status = engine.get_service_status(metadata.id).await.unwrap();
    assert_ne!(status.state, DeploymentState::Failed);

    // Stop service
    engine.stop_service(metadata.id).await.unwrap();

    // Verify stopped
    let final_status = engine.get_service_status(metadata.id).await.unwrap();
    assert_eq!(final_status.state, DeploymentState::Stopped);
}

#[tokio::test]
async fn test_concurrent_deployments() {
    let config = EngineConfig {
        max_concurrent_deployments: 5,
        ..Default::default()
    };

    let engine = Arc::new(OrchestrationEngine::new(config).await.unwrap());

    // Deploy 10 services concurrently (more than max)
    let mut handles = vec![];

    for i in 0..10 {
        let engine_clone = Arc::clone(&engine);
        let handle = tokio::spawn(async move {
            let resources = ResourceRequest {
                cpu_cores: 0.5,
                memory_mb: 256,
                disk_mb: 512,
            };

            engine_clone
                .deploy_service(
                    format!("concurrent-service-{}", i),
                    "1.0.0".to_string(),
                    resources,
                )
                .await
        });
        handles.push(handle);
    }

    // Collect results
    let mut successes = 0;
    let mut failures = 0;

    for handle in handles {
        match handle.await.unwrap() {
            Ok(_) => successes += 1,
            Err(_) => failures += 1,
        }
    }

    // Should have some successes (up to max concurrent)
    assert!(successes > 0);
    assert!(successes <= 10);
}

#[tokio::test]
async fn test_resource_management() {
    let manager = ResourceManager::new();

    // Allocate resources for multiple services
    let service1 = Uuid::new_v4();
    let service2 = Uuid::new_v4();

    let request1 = ResourceRequest {
        cpu_cores: 2.0,
        memory_mb: 1024,
        disk_mb: 2048,
    };

    let request2 = ResourceRequest {
        cpu_cores: 1.0,
        memory_mb: 512,
        disk_mb: 1024,
    };

    let alloc1 = manager
        .allocate_resources(&service1, request1)
        .await
        .unwrap();
    let alloc2 = manager
        .allocate_resources(&service2, request2)
        .await
        .unwrap();

    assert_eq!(alloc1.cpu.cores, 2.0);
    assert_eq!(alloc2.memory.memory_mb, 512);

    // Check total utilization
    let utilization = manager.get_total_utilization().await.unwrap();
    assert!(utilization > 0.0);

    // Release resources
    manager.release_resources(&service1).await.unwrap();
    manager.release_resources(&service2).await.unwrap();

    // Verify resources freed
    let final_stats = manager.get_stats().await;
    assert_eq!(final_stats.active_allocations, 0);
}

#[tokio::test]
async fn test_network_allocation() {
    let allocator = NetworkAllocator::new();

    // Allocate ports for services
    let service1 = Uuid::new_v4();
    let service2 = Uuid::new_v4();

    let config1 = allocator
        .allocate_port(&service1, Protocol::Http)
        .await
        .unwrap();
    let config2 = allocator
        .allocate_port(&service2, Protocol::Grpc)
        .await
        .unwrap();

    // Ports should be different
    assert_ne!(config1.internal_port, config2.internal_port);

    // Release ports
    allocator.release_port(&service1).await.unwrap();
    allocator.release_port(&service2).await.unwrap();
}

#[tokio::test]
async fn test_circuit_breaker_integration() {
    use claude_optimized_deployment_rust::reliability::{
        with_circuit_breaker, CircuitBreakerConfig,
    };

    let config = CircuitBreakerConfig {
        failure_threshold: 3,
        timeout: Duration::from_millis(100),
        ..Default::default()
    };

    let breaker = CircuitBreaker::new(config);

    // Simulate failures to open circuit
    for _ in 0..3 {
        let _ = with_circuit_breaker(&breaker, async {
            Err::<(), _>(anyhow::anyhow!("simulated failure"))
        })
        .await;
    }

    // Circuit should be open
    assert!(!breaker.can_proceed());

    // Wait for timeout
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Should transition to half-open
    assert!(breaker.can_proceed());
}

#[tokio::test]
async fn test_recovery_manager() {
    use claude_optimized_deployment_rust::reliability::RecoveryConfig;

    let config = RecoveryConfig {
        default_strategy: RecoveryStrategy::Restart,
        max_attempts: 2,
        timeout: Duration::from_secs(5),
        auto_recovery: true,
        ..Default::default()
    };

    let manager = RecoveryManager::new(config);
    manager.start().await.unwrap();

    // Initiate recovery
    let service_id = Uuid::new_v4();
    manager
        .recover_service(
            service_id,
            "failing-service".to_string(),
            Some(RecoveryStrategy::RestartWithBackoff),
        )
        .await
        .unwrap();

    // Check recovery status
    tokio::time::sleep(Duration::from_millis(100)).await;

    let status = manager.get_recovery_status(service_id).await;
    assert!(status.is_some());

    // Stop manager
    manager.stop().await.unwrap();
}

#[tokio::test]
async fn test_health_checking_system() {
    let config = HealthCheckConfig {
        default_interval_secs: 1,
        timeout_secs: 1,
        ..Default::default()
    };

    let checker = HealthChecker::new(config);
    checker.start().await.unwrap();

    // Register services
    let service_id = Uuid::new_v4();
    checker
        .register_service(
            service_id,
            "http://localhost:9999/health".to_string(),
            HealthCheckType::Http,
        )
        .await
        .unwrap();

    // Wait for health check
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Get health status
    let status = checker.get_health_status(service_id).await;
    assert!(status.is_some());

    // Stop checker
    checker.stop().await.unwrap();
}

#[tokio::test]
async fn test_graceful_shutdown() {
    let engine = OrchestrationEngine::new(EngineConfig::default())
        .await
        .unwrap();

    // Deploy some services
    let mut service_ids = vec![];
    for i in 0..3 {
        let resources = ResourceRequest {
            cpu_cores: 0.5,
            memory_mb: 256,
            disk_mb: 512,
        };

        let metadata = engine
            .deploy_service(
                format!("shutdown-test-{}", i),
                "1.0.0".to_string(),
                resources,
            )
            .await
            .unwrap();

        service_ids.push(metadata.id);
    }

    // Perform graceful shutdown
    let shutdown_result = timeout(Duration::from_secs(10), engine.shutdown()).await;

    assert!(shutdown_result.is_ok());
}

#[tokio::test]
async fn test_performance_metrics() {
    let engine = OrchestrationEngine::new(EngineConfig::default())
        .await
        .unwrap();

    // Deploy a service to generate metrics
    let resources = ResourceRequest {
        cpu_cores: 1.0,
        memory_mb: 512,
        disk_mb: 1024,
    };

    let start = std::time::Instant::now();
    let metadata = engine
        .deploy_service("metrics-test".to_string(), "1.0.0".to_string(), resources)
        .await
        .unwrap();
    let deployment_time = start.elapsed();

    // Verify sub-second deployment
    assert!(deployment_time.as_millis() < 1000);

    // Get metrics
    let metrics = engine.get_metrics().await;
    assert!(metrics.total_deployments > 0);
    assert!(metrics.average_deployment_time_ms > 0.0);
}
