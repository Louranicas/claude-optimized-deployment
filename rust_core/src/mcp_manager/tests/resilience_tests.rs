// ============================================================================
// Resilience Module Unit Tests
// ============================================================================

use crate::mcp_manager::{
    resilience::{
        bulkhead::{Bulkhead, BulkheadConfig, IsolationMode},
        chaos::{ChaosEngine, ChaosExperiment, FaultType},
        fallback::{FallbackHandler, FallbackStrategy, FallbackChain},
        retry_policy::{RetryPolicy, RetryStrategy, BackoffStrategy},
    },
    protocol::{MCPRequest, MCPResponse},
    error::{MCPError, MCPResult},
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};
use tokio::test;

#[cfg(test)]
mod bulkhead_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_bulkhead_thread_pool_isolation() {
        let config = BulkheadConfig {
            max_concurrent_calls: 5,
            max_wait_duration: Duration::from_millis(100),
            isolation_mode: IsolationMode::ThreadPool,
        };
        
        let bulkhead = Bulkhead::new("test_bulkhead", config);
        let execution_count = Arc::new(AtomicU64::new(0));
        
        // Try to execute more than max concurrent calls
        let mut handles = vec![];
        for i in 0..10 {
            let bulkhead_clone = bulkhead.clone();
            let count_clone = execution_count.clone();
            
            let handle = tokio::spawn(async move {
                bulkhead_clone.execute(async move {
                    count_clone.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    Ok::<_, MCPError>(())
                }).await
            });
            handles.push(handle);
        }
        
        // Wait for all to complete
        let mut success_count = 0;
        let mut rejection_count = 0;
        
        for handle in handles {
            match handle.await.unwrap() {
                Ok(_) => success_count += 1,
                Err(MCPError::Capacity(_)) => rejection_count += 1,
                Err(e) => panic!("Unexpected error: {:?}", e),
            }
        }
        
        // Should have accepted max_concurrent_calls and rejected the rest
        assert_eq!(success_count, 5);
        assert_eq!(rejection_count, 5);
    }
    
    #[tokio::test]
    async fn test_bulkhead_semaphore_isolation() {
        let config = BulkheadConfig {
            max_concurrent_calls: 3,
            max_wait_duration: Duration::from_millis(200),
            isolation_mode: IsolationMode::Semaphore,
        };
        
        let bulkhead = Bulkhead::new("semaphore_test", config);
        let concurrent_executions = Arc::new(AtomicU64::new(0));
        let max_concurrent = Arc::new(AtomicU64::new(0));
        
        let mut handles = vec![];
        for _ in 0..6 {
            let bulkhead_clone = bulkhead.clone();
            let concurrent_clone = concurrent_executions.clone();
            let max_clone = max_concurrent.clone();
            
            let handle = tokio::spawn(async move {
                bulkhead_clone.execute(async move {
                    let current = concurrent_clone.fetch_add(1, Ordering::Relaxed) + 1;
                    
                    // Update max concurrent
                    loop {
                        let max = max_clone.load(Ordering::Relaxed); // TODO: Review memory ordering - consider Acquire/Release
                        if current <= max || max_clone.compare_exchange(max, current, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                            break;
                        }
                    }
                    
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    concurrent_clone.fetch_sub(1, Ordering::Relaxed);
                    Ok::<_, MCPError>(())
                }).await
            });
            handles.push(handle);
        }
        
        for handle in handles {
            let _ = handle.await;
        }
        
        let max_observed = max_concurrent.load(Ordering::Relaxed); // TODO: Review memory ordering - consider Acquire/Release
        assert!(max_observed <= 3, "Max concurrent executions should not exceed 3, was {}", max_observed);
    }
    
    #[tokio::test]
    async fn test_bulkhead_metrics() {
        let config = BulkheadConfig {
            max_concurrent_calls: 2,
            max_wait_duration: Duration::from_millis(50),
            isolation_mode: IsolationMode::Semaphore,
        };
        
        let bulkhead = Bulkhead::new("metrics_test", config);
        
        // Execute some successful calls
        for _ in 0..5 {
            let _ = bulkhead.execute(async {
                Ok::<_, MCPError>(42)
            }).await;
        }
        
        // Execute some failing calls
        for _ in 0..3 {
            let _ = bulkhead.execute(async {
                Err::<i32, MCPError>(MCPError::Internal("test error".to_string()))
            }).await;
        }
        
        // Get metrics
        let metrics = bulkhead.get_metrics().await;
        assert_eq!(metrics.total_calls, 8);
        assert_eq!(metrics.successful_calls, 5);
        assert_eq!(metrics.failed_calls, 3);
        assert!(metrics.rejection_count >= 0);
    }
}

#[cfg(test)]
mod chaos_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_chaos_latency_injection() {
        let chaos_engine = ChaosEngine::new();
        
        let experiment = ChaosExperiment {
            name: "latency_test".to_string(),
            fault_type: FaultType::Latency {
                delay: Duration::from_millis(100),
                jitter: Duration::from_millis(20),
                distribution: "normal".to_string(),
            },
            probability: 1.0, // Always inject
            duration: Duration::from_secs(10),
            targets: vec!["service1".to_string()],
        };
        
        chaos_engine.start_experiment(experiment).await.unwrap();
        
        // Measure execution time
        let start = Instant::now();
        chaos_engine.inject_fault("service1", async {
            // Normal operation
            Ok::<_, MCPError>(())
        }).await.unwrap();
        let elapsed = start.elapsed();
        
        // Should have added latency
        assert!(elapsed >= Duration::from_millis(80), "Should have injected latency");
        assert!(elapsed <= Duration::from_millis(150), "Latency should be within bounds");
    }
    
    #[tokio::test]
    async fn test_chaos_error_injection() {
        let chaos_engine = ChaosEngine::new();
        
        let experiment = ChaosExperiment {
            name: "error_test".to_string(),
            fault_type: FaultType::Error {
                error_type: "NetworkError".to_string(),
                message: "Simulated network failure".to_string(),
            },
            probability: 0.5, // 50% chance
            duration: Duration::from_secs(10),
            targets: vec!["service2".to_string()],
        };
        
        chaos_engine.start_experiment(experiment).await.unwrap();
        
        let mut error_count = 0;
        let mut success_count = 0;
        
        // Run multiple times to test probability
        for _ in 0..100 {
            match chaos_engine.inject_fault("service2", async {
                Ok::<_, MCPError>("success")
            }).await {
                Ok(_) => success_count += 1,
                Err(_) => error_count += 1,
            }
        }
        
        // Should have roughly 50% errors
        assert!((40..=60).contains(&error_count), "Error injection probability should be ~50%, was {}", error_count);
        assert!((40..=60).contains(&success_count), "Success rate should be ~50%, was {}", success_count);
    }
    
    #[tokio::test]
    async fn test_chaos_resource_exhaustion() {
        let chaos_engine = ChaosEngine::new();
        
        let experiment = ChaosExperiment {
            name: "resource_test".to_string(),
            fault_type: FaultType::ResourceExhaustion {
                resource_type: "memory".to_string(),
                consumption_rate: 0.8, // 80% of available
            },
            probability: 1.0,
            duration: Duration::from_millis(500),
            targets: vec!["service3".to_string()],
        };
        
        chaos_engine.start_experiment(experiment).await.unwrap();
        
        // Should simulate resource pressure
        let result = chaos_engine.inject_fault("service3", async {
            // Simulate memory-intensive operation
            let _data: Vec<u8> = vec![0; 1024 * 1024]; // 1MB
            Ok::<_, MCPError>(())
        }).await;
        
        // Operation might fail due to resource exhaustion
        if result.is_err() {
            match result.unwrap_err() {
                MCPError::Capacity(_) => (), // Expected
                e => panic!("Unexpected error type: {:?}", e),
            }
        }
    }
    
    #[tokio::test]
    async fn test_chaos_network_partition() {
        let chaos_engine = ChaosEngine::new();
        
        let experiment = ChaosExperiment {
            name: "partition_test".to_string(),
            fault_type: FaultType::NetworkPartition {
                partitions: vec![
                    vec!["node1".to_string(), "node2".to_string()],
                    vec!["node3".to_string(), "node4".to_string()],
                ],
            },
            probability: 1.0,
            duration: Duration::from_secs(1),
            targets: vec!["node1".to_string(), "node2".to_string(), "node3".to_string(), "node4".to_string()],
        };
        
        chaos_engine.start_experiment(experiment).await.unwrap();
        
        // Communication within partition should work
        let result1 = chaos_engine.can_communicate("node1", "node2").await;
        assert!(result1, "Nodes in same partition should communicate");
        
        // Communication across partitions should fail
        let result2 = chaos_engine.can_communicate("node1", "node3").await;
        assert!(!result2, "Nodes in different partitions should not communicate");
    }
}

#[cfg(test)]
mod fallback_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_fallback_static_value() {
        let fallback = FallbackHandler::new(FallbackStrategy::StaticValue(
            serde_json::json!({"status": "fallback", "data": []})
        ));
        
        // Primary operation fails
        let result = fallback.execute(async {
            Err::<serde_json::Value, MCPError>(MCPError::Connection("Primary failed".to_string()))
        }).await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), serde_json::json!({"status": "fallback", "data": []}));
    }
    
    #[tokio::test]
    async fn test_fallback_cache() {
        let fallback = FallbackHandler::new(FallbackStrategy::Cache {
            ttl: Duration::from_secs(60),
            max_entries: 100,
        });
        
        // First call - populate cache
        let result1 = fallback.execute(async {
            Ok(serde_json::json!({"id": 1, "value": "cached"}))
        }).await.unwrap();
        
        // Second call - primary fails, should use cache
        let result2 = fallback.execute(async {
            Err::<serde_json::Value, MCPError>(MCPError::Connection("Failed".to_string()))
        }).await.unwrap();
        
        assert_eq!(result1, result2);
    }
    
    #[tokio::test]
    async fn test_fallback_chain() {
        let chain = FallbackChain::new()
            .add_fallback(FallbackHandler::new(FallbackStrategy::Custom(Box::new(
                |_error| Box::pin(async { Err(MCPError::Internal("First fallback failed".to_string())) })
            ))))
            .add_fallback(FallbackHandler::new(FallbackStrategy::Custom(Box::new(
                |_error| Box::pin(async { Err(MCPError::Internal("Second fallback failed".to_string())) })
            ))))
            .add_fallback(FallbackHandler::new(FallbackStrategy::StaticValue(
                serde_json::json!("final fallback")
            )));
        
        // All primary and first two fallbacks fail
        let result = chain.execute(async {
            Err::<serde_json::Value, MCPError>(MCPError::Connection("Primary failed".to_string()))
        }).await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), serde_json::json!("final fallback"));
    }
    
    #[tokio::test]
    async fn test_fallback_circuit_breaker_integration() {
        let fallback = FallbackHandler::new(FallbackStrategy::CircuitBreaker {
            failure_threshold: 3,
            recovery_timeout: Duration::from_millis(500),
            half_open_max_calls: 1,
        });
        
        // Fail multiple times to open circuit
        for _ in 0..3 {
            let _ = fallback.execute(async {
                Err::<(), MCPError>(MCPError::Connection("Failed".to_string()))
            }).await;
        }
        
        // Circuit should be open, calls should fail fast
        let start = Instant::now();
        let result = fallback.execute(async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(())
        }).await;
        let elapsed = start.elapsed();
        
        assert!(result.is_err());
        assert!(elapsed < Duration::from_millis(100), "Should fail fast when circuit is open");
        
        // Wait for recovery timeout
        tokio::time::sleep(Duration::from_millis(600)).await;
        
        // Should allow one call through (half-open)
        let result = fallback.execute(async {
            Ok("recovered")
        }).await;
        
        assert!(result.is_ok());
    }
}

#[cfg(test)]
mod retry_policy_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_retry_exponential_backoff() {
        let policy = RetryPolicy::new(
            RetryStrategy::Exponential,
            BackoffStrategy::Exponential {
                initial_delay: Duration::from_millis(10),
                max_delay: Duration::from_millis(100),
                multiplier: 2.0,
            },
            3, // max retries
        );
        
        let attempt_count = Arc::new(AtomicU64::new(0));
        let attempt_clone = attempt_count.clone();
        
        let start = Instant::now();
        let result = policy.execute(move || {
            let count = attempt_clone.clone();
            Box::pin(async move {
                let attempts = count.fetch_add(1, Ordering::Relaxed) + 1;
                if attempts < 3 {
                    Err(MCPError::Connection("Transient error".to_string()))
                } else {
                    Ok("Success after retries")
                }
            })
        }).await;
        
        let elapsed = start.elapsed();
        
        assert!(result.is_ok());
        assert_eq!(attempt_count.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release, 3);
        
        // Should have delays: 10ms + 20ms = 30ms minimum
        assert!(elapsed >= Duration::from_millis(30), "Should have exponential delays");
    }
    
    #[tokio::test]
    async fn test_retry_with_jitter() {
        let policy = RetryPolicy::new(
            RetryStrategy::Linear,
            BackoffStrategy::ExponentialWithJitter {
                initial_delay: Duration::from_millis(50),
                max_delay: Duration::from_millis(200),
                multiplier: 2.0,
                jitter_factor: 0.1,
            },
            5,
        );
        
        let delays = Arc::new(Mutex::new(Vec::new()));
        let delays_clone = delays.clone();
        
        let _ = policy.execute(move || {
            let delays = delays_clone.clone();
            Box::pin(async move {
                let start = Instant::now();
                let result = Err::<(), MCPError>(MCPError::Connection("Always fail".to_string()));
                let delay = start.elapsed();
                delays.lock().await.push(delay);
                result
            })
        }).await;
        
        let recorded_delays = delays.lock().await;
        
        // Verify jitter is applied (delays should vary)
        let mut unique_delays = recorded_delays.clone();
        unique_delays.dedup();
        assert!(unique_delays.len() > 1, "Jitter should cause variation in delays");
    }
    
    #[tokio::test]
    async fn test_retry_conditional() {
        let policy = RetryPolicy::new(
            RetryStrategy::Conditional(Box::new(|error| {
                // Only retry on connection errors
                matches!(error, MCPError::Connection(_))
            })),
            BackoffStrategy::Fixed(Duration::from_millis(10)),
            3,
        );
        
        // Should retry on connection error
        let attempt_count = Arc::new(AtomicU64::new(0));
        let count_clone = attempt_count.clone();
        
        let result = policy.execute(move || {
            let count = count_clone.clone();
            Box::pin(async move {
                count.fetch_add(1, Ordering::Relaxed);
                Err::<(), MCPError>(MCPError::Connection("Retry me".to_string()))
            })
        }).await;
        
        assert_eq!(attempt_count.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release, 4); // 1 initial + 3 retries
        
        // Should not retry on other errors
        let attempt_count2 = Arc::new(AtomicU64::new(0));
        let count_clone2 = attempt_count2.clone();
        
        let result2 = policy.execute(move || {
            let count = count_clone2.clone();
            Box::pin(async move {
                count.fetch_add(1, Ordering::Relaxed);
                Err::<(), MCPError>(MCPError::Authentication("Don't retry".to_string()))
            })
        }).await;
        
        assert_eq!(attempt_count2.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release, 1); // No retries
    }
    
    #[tokio::test]
    async fn test_retry_timeout() {
        let policy = RetryPolicy::new(
            RetryStrategy::Exponential,
            BackoffStrategy::Fixed(Duration::from_millis(100)),
            10, // Many retries
        )
        .with_timeout(Duration::from_millis(250)); // Overall timeout
        
        let start = Instant::now();
        let result = policy.execute(|| {
            Box::pin(async {
                Err::<(), MCPError>(MCPError::Connection("Always fail".to_string()))
            })
        }).await;
        
        let elapsed = start.elapsed();
        
        assert!(result.is_err());
        // Should timeout before all retries complete
        assert!(elapsed < Duration::from_millis(1000), "Should respect overall timeout");
        assert!(elapsed >= Duration::from_millis(250), "Should run until timeout");
    }
}