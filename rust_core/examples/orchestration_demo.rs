//! Orchestration engine demonstration
//!
//! This example shows how to use the high-performance orchestration engine
//! to deploy and manage services with sub-millisecond registration.

use claude_optimized_deployment_rust::{
    network::Protocol,
    orchestrator::{EngineConfig, OrchestrationEngine},
    reliability::{BackoffStrategy, CircuitBreaker, CircuitBreakerConfig, RetryPolicyBuilder},
    resources::ResourceRequest,
    services::{HealthCheckConfig, HealthCheckType, HealthChecker},
};
use std::time::Duration;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    info!("Starting orchestration engine demo");

    // Configure the orchestration engine
    let config = EngineConfig {
        max_concurrent_deployments: 50,
        registration_timeout_ms: 100, // Sub-millisecond target
        health_check_interval_secs: 5,
        resource_allocation_timeout_ms: 500,
        distributed_locking_enabled: true,
        max_retry_attempts: 3,
        circuit_breaker_threshold: 0.5,
        perf_monitoring_interval_secs: 10,
    };

    // Create orchestration engine
    let engine = OrchestrationEngine::new(config).await?;
    info!("Orchestration engine initialized");

    // Deploy multiple services concurrently
    let mut handles = vec![];

    for i in 0..5 {
        let engine_clone = engine.clone();
        let handle = tokio::spawn(async move {
            let service_name = format!("demo-service-{}", i);
            let resources = ResourceRequest {
                cpu_cores: 0.5,
                memory_mb: 512,
                disk_mb: 1024,
            };

            match engine_clone
                .deploy_service(service_name.clone(), "1.0.0".to_string(), resources)
                .await
            {
                Ok(metadata) => {
                    info!("Service {} deployed with ID {}", service_name, metadata.id);
                    Some(metadata.id)
                }
                Err(e) => {
                    error!("Failed to deploy {}: {}", service_name, e);
                    None
                }
            }
        });
        handles.push(handle);
    }

    // Wait for all deployments
    let mut service_ids = vec![];
    for handle in handles {
        if let Some(id) = handle.await? {
            service_ids.push(id);
        }
    }

    info!("Deployed {} services", service_ids.len());

    // Set up health checking
    let health_config = HealthCheckConfig {
        default_interval_secs: 10,
        timeout_secs: 5,
        failure_threshold: 3,
        success_threshold: 2,
        exponential_backoff: true,
        max_backoff_secs: 60,
        worker_threads: 2,
    };

    let health_checker = HealthChecker::new(health_config);
    health_checker.start().await?;

    // Register services for health checking
    for (i, service_id) in service_ids.iter().enumerate() {
        health_checker
            .register_service(
                *service_id,
                format!("http://localhost:{}/health", 8080 + i),
                HealthCheckType::Http,
            )
            .await?;
    }

    info!("Health checking configured for all services");

    // Demonstrate circuit breaker
    let cb_config = CircuitBreakerConfig {
        failure_threshold: 5,
        success_threshold: 2,
        timeout: Duration::from_secs(30),
        window_size: 100,
        min_requests: 10,
    };

    let circuit_breaker = CircuitBreaker::new(cb_config);

    // Simulate some requests
    for i in 0..10 {
        if circuit_breaker.can_proceed() {
            // Simulate request
            if i % 3 == 0 {
                circuit_breaker.record_failure();
                info!("Request {} failed", i);
            } else {
                circuit_breaker.record_success();
                info!("Request {} succeeded", i);
            }
        } else {
            info!("Circuit breaker open, request {} rejected", i);
        }
    }

    let cb_stats = circuit_breaker.stats();
    info!("Circuit breaker stats: {:?}", cb_stats);

    // Demonstrate retry policy
    let retry_policy = RetryPolicyBuilder::new()
        .max_attempts(3)
        .initial_delay(Duration::from_millis(100))
        .strategy(BackoffStrategy::Exponential)
        .build();

    let mut attempt_count = 0;
    let result: Result<String, Box<dyn std::error::Error>> = retry_policy
        .execute(|| async {
            attempt_count += 1;
            if attempt_count < 3 {
                Err("Simulated transient error".into())
            } else {
                Ok("Success after retries".to_string())
            }
        })
        .await;

    match result {
        Ok(msg) => info!("Retry succeeded: {}", msg),
        Err(e) => error!("Retry failed: {}", e),
    }

    // Get engine metrics
    let metrics = engine.get_metrics().await;
    info!("Engine metrics: {:?}", metrics);

    // List all services
    let services = engine.list_services().await?;
    info!("Active services: {}", services.len());

    // Wait a bit to see health checks in action
    tokio::time::sleep(Duration::from_secs(15)).await;

    // Stop services gracefully
    info!("Stopping services...");
    for service_id in service_ids {
        engine.stop_service(service_id).await?;
    }

    // Shutdown
    health_checker.stop().await?;
    engine.shutdown().await?;

    info!("Orchestration demo complete");
    Ok(())
}
