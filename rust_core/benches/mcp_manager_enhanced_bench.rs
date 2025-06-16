use claude_optimized_deployment_rust::mcp_manager::{
    config::MCPConfig,
    core::MCPManager,
    distributed::{ConsensusManager, FailoverManager, ShardManager},
    optimization::{AdaptiveCache, PrefetchEngine, RequestBatcher},
    protocol::{MCPProtocol, MCPRequest, MCPResponse},
    resilience::{Bulkhead, ChaosEngine, RetryPolicy},
    server::{MCPServer, ServerState},
    server_types::security::SecurityServer,
};
use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;

// ============================================================================
// Distributed Module Benchmarks
// ============================================================================

fn bench_consensus_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("mcp_manager/consensus");

    // Leader election
    group.bench_function("leader_election", |b| {
        b.to_async(&rt).iter_batched(
            || {
                ConsensusManager::new(
                    "bench_node".to_string(),
                    vec!["node1", "node2", "node3", "node4", "node5"],
                    ConsensusProtocol::Raft,
                )
            },
            |consensus| async move {
                consensus.start_election().await.unwrap();
                black_box(consensus.get_leader().await)
            },
            BatchSize::SmallInput,
        )
    });

    // Consensus proposal
    group.bench_function("propose_and_commit", |b| {
        let consensus = rt.block_on(async {
            let c = ConsensusManager::new(
                "leader".to_string(),
                vec!["leader", "follower1", "follower2"],
                ConsensusProtocol::Raft,
            );
            c.become_leader().await.unwrap();
            c
        });

        b.to_async(&rt).iter(|| {
            let consensus = consensus.clone();
            async move {
                let value = serde_json::json!({"op": "update", "key": "test", "value": 42});
                black_box(consensus.propose(value).await.unwrap())
            }
        })
    });

    group.finish();
}

fn bench_sharding_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("mcp_manager/sharding");

    let shard_manager = rt.block_on(async {
        let config = ShardConfig {
            num_shards: 64,
            replication_factor: 3,
            virtual_nodes: 150,
        };
        let mut manager = ShardManager::new(config);

        // Add nodes
        for i in 0..10 {
            manager.add_node(&format!("node{}", i)).await.unwrap();
        }

        Arc::new(manager)
    });

    // Shard lookup
    group.bench_function("shard_lookup", |b| {
        let manager = shard_manager.clone();
        b.to_async(&rt).iter(|| {
            let manager = manager.clone();
            async move {
                let key = format!("key_{}", rand::random::<u64>());
                black_box(manager.get_shard(&key).await)
            }
        })
    });

    // Consistent hashing
    group.throughput(Throughput::Elements(1000));
    group.bench_function("consistent_hash_distribution", |b| {
        let manager = shard_manager.clone();
        b.to_async(&rt).iter(|| {
            let manager = manager.clone();
            async move {
                let mut distribution = HashMap::new();
                for i in 0..1000 {
                    let key = format!("test_key_{}", i);
                    let shard = manager.get_shard(&key).await;
                    *distribution.entry(shard).or_insert(0) += 1;
                }
                black_box(distribution)
            }
        })
    });

    group.finish();
}

// ============================================================================
// Resilience Module Benchmarks
// ============================================================================

fn bench_circuit_breaker_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("mcp_manager/circuit_breaker");

    group.bench_function("healthy_requests", |b| {
        let breaker =
            rt.block_on(async { CircuitBreaker::new("bench_breaker", 5, Duration::from_secs(60)) });

        b.to_async(&rt).iter(|| {
            let breaker = breaker.clone();
            async move { breaker.call(async { Ok::<_, MCPError>("success") }).await }
        })
    });

    group.bench_function("circuit_state_transitions", |b| {
        b.to_async(&rt).iter_batched(
            || CircuitBreaker::new("transition_test", 3, Duration::from_millis(100)),
            |breaker| async move {
                // Trigger circuit open
                for _ in 0..3 {
                    let _ = breaker
                        .call(async {
                            Err::<(), MCPError>(MCPError::Connection("fail".to_string()))
                        })
                        .await;
                }

                // Try when open (should fail fast)
                let open_result = breaker.call(async { Ok(()) }).await;

                // Wait for half-open
                tokio::time::sleep(Duration::from_millis(150)).await;

                // Try when half-open
                let half_open_result = breaker.call(async { Ok(()) }).await;

                black_box((open_result, half_open_result))
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_retry_mechanisms(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("mcp_manager/retry");

    // Exponential backoff
    group.bench_function("exponential_backoff", |b| {
        let policy = RetryPolicy::new(
            RetryStrategy::Exponential,
            BackoffStrategy::Exponential {
                initial_delay: Duration::from_micros(100),
                max_delay: Duration::from_millis(10),
                multiplier: 2.0,
            },
            3,
        );

        b.to_async(&rt).iter(|| {
            let policy = policy.clone();
            async move {
                let mut attempts = 0;
                policy
                    .execute(|| {
                        attempts += 1;
                        Box::pin(async move {
                            if attempts < 2 {
                                Err(MCPError::Connection("retry".to_string()))
                            } else {
                                Ok("success")
                            }
                        })
                    })
                    .await
            }
        })
    });

    // Jittered backoff
    group.bench_function("jittered_backoff", |b| {
        let policy = RetryPolicy::new(
            RetryStrategy::Linear,
            BackoffStrategy::ExponentialWithJitter {
                initial_delay: Duration::from_micros(100),
                max_delay: Duration::from_millis(10),
                multiplier: 1.5,
                jitter_factor: 0.1,
            },
            5,
        );

        b.to_async(&rt).iter(|| {
            let policy = policy.clone();
            async move {
                policy
                    .execute(|| {
                        Box::pin(async {
                            // Always succeed on first try for benchmarking
                            Ok::<_, MCPError>(42)
                        })
                    })
                    .await
            }
        })
    });

    group.finish();
}

// ============================================================================
// Optimization Module Benchmarks
// ============================================================================

fn bench_adaptive_cache(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("mcp_manager/adaptive_cache");

    let cache = rt.block_on(async {
        let cache = AdaptiveCache::new(
            CacheStrategy::Adaptive,
            EvictionPolicy::LRU,
            10000,
            Duration::from_secs(300),
        );

        // Pre-populate cache
        for i in 0..5000 {
            cache
                .put(
                    format!("key_{}", i),
                    serde_json::json!({"id": i, "data": "cached"}),
                )
                .await;
        }

        Arc::new(cache)
    });

    // Cache hits
    group.bench_function("cache_hit", |b| {
        let cache = cache.clone();
        b.to_async(&rt).iter(|| {
            let cache = cache.clone();
            async move {
                let key = format!("key_{}", rand::random::<u32>() % 5000);
                black_box(cache.get(&key).await)
            }
        })
    });

    // Cache misses
    group.bench_function("cache_miss", |b| {
        let cache = cache.clone();
        b.to_async(&rt).iter(|| {
            let cache = cache.clone();
            async move {
                let key = format!("missing_key_{}", rand::random::<u32>());
                black_box(cache.get(&key).await)
            }
        })
    });

    // Mixed workload
    group.bench_function("mixed_workload", |b| {
        let cache = cache.clone();
        b.to_async(&rt).iter(|| {
            let cache = cache.clone();
            async move {
                let r = rand::random::<f32>();
                if r < 0.7 {
                    // 70% reads
                    let key = format!("key_{}", rand::random::<u32>() % 5000);
                    black_box(cache.get(&key).await)
                } else if r < 0.9 {
                    // 20% updates
                    let key = format!("key_{}", rand::random::<u32>() % 5000);
                    cache.put(key, serde_json::json!({"updated": true})).await;
                    black_box(())
                } else {
                    // 10% new inserts
                    let key = format!("new_key_{}", rand::random::<u32>());
                    cache.put(key, serde_json::json!({"new": true})).await;
                    black_box(())
                }
            }
        })
    });

    group.finish();
}

fn bench_request_batching(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("mcp_manager/request_batching");

    for batch_size in [10, 50, 100, 200].iter() {
        group.throughput(Throughput::Elements(*batch_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            batch_size,
            |b, &batch_size| {
                let batcher = rt.block_on(async {
                    let config = BatchConfig {
                        max_batch_size: batch_size,
                        max_wait_time: Duration::from_millis(10),
                        min_batch_size: 1,
                    };

                    let batcher = RequestBatcher::new(BatchingStrategy::Adaptive, config);

                    batcher
                        .set_processor(|batch| {
                            Box::pin(async move {
                                // Simulate batch processing
                                tokio::time::sleep(Duration::from_micros(100 * batch.len() as u64))
                                    .await;
                                Ok(vec![
                                    MCPResponse::success(serde_json::json!({}));
                                    batch.len()
                                ])
                            })
                        })
                        .await;

                    Arc::new(batcher)
                });

                b.to_async(&rt).iter(|| {
                    let batcher = batcher.clone();
                    async move {
                        let mut handles = vec![];
                        for i in 0..batch_size {
                            let batcher = batcher.clone();
                            let handle = tokio::spawn(async move {
                                let request = MCPRequest::new("bench", serde_json::json!({"i": i}));
                                batcher.add_request(request).await
                            });
                            handles.push(handle);
                        }

                        for handle in handles {
                            let _ = handle.await;
                        }
                    }
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Security Module Benchmarks
// ============================================================================

fn bench_security_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("mcp_manager/security");

    let security_server = rt.block_on(async { Arc::new(SecurityServer::new("bench_security")) });

    // Token generation
    group.bench_function("token_generation", |b| {
        let server = security_server.clone();
        b.to_async(&rt).iter(|| {
            let server = server.clone();
            async move {
                black_box(
                    server
                        .generate_token("user123", Duration::from_secs(3600))
                        .await
                        .unwrap(),
                )
            }
        })
    });

    // Token validation
    let token = rt.block_on(async {
        security_server
            .generate_token("bench_user", Duration::from_secs(3600))
            .await
            .unwrap()
    });

    group.bench_function("token_validation", |b| {
        let server = security_server.clone();
        let token = token.clone();
        b.to_async(&rt).iter(|| {
            let server = server.clone();
            let token = token.clone();
            async move { black_box(server.validate_token(&token).await) }
        })
    });

    // Permission checking
    rt.block_on(async {
        security_server
            .create_role("bench_role", vec!["read", "write"])
            .await
            .unwrap();
        security_server
            .assign_role("bench_user", "bench_role")
            .await
            .unwrap();
    });

    group.bench_function("permission_check", |b| {
        let server = security_server.clone();
        b.to_async(&rt).iter(|| {
            let server = server.clone();
            async move { black_box(server.check_permission("bench_user", "read").await.unwrap()) }
        })
    });

    // Encryption/decryption
    let data = serde_json::json!({"sensitive": "data", "field": "value"});

    group.bench_function("data_encryption", |b| {
        let server = security_server.clone();
        let data = data.clone();
        b.to_async(&rt).iter(|| {
            let server = server.clone();
            let data = data.clone();
            async move { black_box(server.encrypt_data(&data).await.unwrap()) }
        })
    });

    let encrypted = rt.block_on(async { security_server.encrypt_data(&data).await.unwrap() });

    group.bench_function("data_decryption", |b| {
        let server = security_server.clone();
        let encrypted = encrypted.clone();
        b.to_async(&rt).iter(|| {
            let server = server.clone();
            let encrypted = encrypted.clone();
            async move { black_box(server.decrypt_data(&encrypted).await.unwrap()) }
        })
    });

    group.finish();
}

// ============================================================================
// End-to-End Scenarios
// ============================================================================

fn bench_real_world_scenarios(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("mcp_manager/real_world");

    // Microservices communication pattern
    group.bench_function("microservices_pattern", |b| {
        b.to_async(&rt).iter_batched(
            || {
                let config = MCPConfig {
                    max_connections_per_server: 50,
                    enable_connection_pooling: true,
                    enable_load_balancing: true,
                    enable_metrics: true,
                    enable_security: true,
                    ..Default::default()
                };

                let manager = Arc::new(MCPManager::new(config));

                // Setup microservices
                rt.block_on(async {
                    for service in ["auth", "users", "orders", "inventory", "notifications"] {
                        for i in 0..3 {
                            let server = MCPServer::new(
                                format!("{}_{}", service, i),
                                format!("http://{}_{}.local:8080", service, i),
                                MCPProtocol::Http,
                                HashMap::new(),
                            );
                            manager.register_server(server).await.unwrap();
                        }
                    }
                });

                manager
            },
            |manager| async move {
                // Simulate microservice request chain
                // 1. Auth check
                let auth_req =
                    MCPRequest::new("authenticate", serde_json::json!({"token": "abc123"}));
                let _ = manager.send_request(auth_req).await;

                // 2. Get user data
                let user_req = MCPRequest::new("get_user", serde_json::json!({"id": "user123"}));
                let _ = manager.send_request(user_req).await;

                // 3. Check inventory
                let inventory_req =
                    MCPRequest::new("check_stock", serde_json::json!({"items": [1, 2, 3]}));
                let _ = manager.send_request(inventory_req).await;

                // 4. Create order
                let order_req = MCPRequest::new(
                    "create_order",
                    serde_json::json!({"user": "user123", "items": [1, 2]}),
                );
                let _ = manager.send_request(order_req).await;

                // 5. Send notification
                let notify_req = MCPRequest::new(
                    "send_notification",
                    serde_json::json!({"type": "order_created"}),
                );
                let _ = manager.send_request(notify_req).await;
            },
            BatchSize::SmallInput,
        )
    });

    // High-frequency trading pattern
    group.bench_function("hft_pattern", |b| {
        let manager = rt.block_on(async {
            let config = MCPConfig {
                max_connections_per_server: 100,
                connection_timeout_ms: 100,
                request_timeout_ms: 500,
                enable_connection_pooling: true,
                enable_metrics: false,  // Reduce overhead
                enable_security: false, // Maximum performance
                ..Default::default()
            };

            let manager = Arc::new(MCPManager::new(config));

            // Setup market data servers
            for exchange in ["NYSE", "NASDAQ", "CME"] {
                for i in 0..5 {
                    let server = MCPServer::new(
                        format!("{}_{}", exchange, i),
                        format!("tcp://{}_{}.exchange:9999", exchange, i),
                        MCPProtocol::Custom("FIX".to_string()),
                        HashMap::new(),
                    );
                    manager.register_server(server).await.unwrap();
                }
            }

            manager
        });

        b.to_async(&rt).iter(|| {
            let manager = manager.clone();
            async move {
                // Simulate market data requests
                let mut handles = vec![];

                for i in 0..10 {
                    let manager = manager.clone();
                    let handle = tokio::spawn(async move {
                        let req = MCPRequest::new(
                            "get_quote",
                            serde_json::json!({
                                "symbol": format!("STOCK{}", i % 5),
                                "timestamp": std::time::SystemTime::now(),
                            }),
                        );
                        manager.send_request(req).await
                    });
                    handles.push(handle);
                }

                for handle in handles {
                    let _ = handle.await;
                }
            }
        })
    });

    group.finish();
}

// ============================================================================
// Python Integration Benchmarks
// ============================================================================

fn bench_python_integration(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("mcp_manager/python_integration");

    // Benchmark PyO3 overhead
    group.bench_function("ffi_call_overhead", |b| {
        b.iter(|| {
            // Simulate FFI boundary crossing
            let data = vec![0u8; 1024];
            let json = serde_json::json!({"data": data});
            let serialized = serde_json::to_string(&json).unwrap();
            let deserialized: serde_json::Value = serde_json::from_str(&serialized).unwrap();
            black_box(deserialized)
        })
    });

    // Large data transfer
    for size in [1024, 10240, 102400].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let data = vec![0u8; size];
            b.iter(|| {
                let json = serde_json::json!({"payload": &data});
                let serialized = serde_json::to_vec(&json).unwrap();
                let deserialized: serde_json::Value = serde_json::from_slice(&serialized).unwrap();
                black_box(deserialized)
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_consensus_operations,
    bench_sharding_operations,
    bench_circuit_breaker_operations,
    bench_retry_mechanisms,
    bench_adaptive_cache,
    bench_request_batching,
    bench_security_operations,
    bench_real_world_scenarios,
    bench_python_integration
);

criterion_main!(benches);
