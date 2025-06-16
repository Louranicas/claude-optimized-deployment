// Rust performance benchmarks for MCP Learning System

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use futures::future::join_all;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;

use mcp_learning_core::{
    LearningServer, Pattern, LearningInteraction, CrossInstanceMessage,
    PatternMatcher, LearningUpdater, KnowledgeSharer
};

/// Benchmark pattern matching performance
fn benchmark_pattern_matching(c: &mut Criterion) {
    let runtime = Runtime::new().unwrap();
    let server = Arc::new(runtime.block_on(LearningServer::new()));
    
    let mut group = c.benchmark_group("pattern_matching");
    
    // Small patterns (100 features)
    let small_pattern = Pattern::new(vec![0.5; 100]);
    group.throughput(Throughput::Elements(1));
    group.bench_function("small_pattern", |b| {
        b.iter(|| {
            runtime.block_on(async {
                server.match_pattern(black_box(&small_pattern)).await
            })
        })
    });
    
    // Medium patterns (1000 features)
    let medium_pattern = Pattern::new(vec![0.5; 1000]);
    group.throughput(Throughput::Elements(1));
    group.bench_function("medium_pattern", |b| {
        b.iter(|| {
            runtime.block_on(async {
                server.match_pattern(black_box(&medium_pattern)).await
            })
        })
    });
    
    // Large patterns (10000 features)
    let large_pattern = Pattern::new(vec![0.5; 10000]);
    group.throughput(Throughput::Elements(1));
    group.bench_function("large_pattern", |b| {
        b.iter(|| {
            runtime.block_on(async {
                server.match_pattern(black_box(&large_pattern)).await
            })
        })
    });
    
    // Batch pattern matching
    let batch_patterns: Vec<Pattern> = (0..100)
        .map(|_| Pattern::new(vec![0.5; 1000]))
        .collect();
    
    group.throughput(Throughput::Elements(100));
    group.bench_function("batch_100_patterns", |b| {
        b.iter(|| {
            runtime.block_on(async {
                server.batch_match_patterns(black_box(&batch_patterns)).await
            })
        })
    });
    
    group.finish();
}

/// Benchmark concurrent learning updates
fn benchmark_learning_updates(c: &mut Criterion) {
    let runtime = Runtime::new().unwrap();
    let server = Arc::new(runtime.block_on(LearningServer::new()));
    
    let mut group = c.benchmark_group("learning_updates");
    group.measurement_time(Duration::from_secs(10));
    
    // Single update
    let interaction = LearningInteraction::new(
        vec![0.5; 100],
        vec![0.7; 10],
        "benchmark".to_string()
    );
    
    group.bench_function("single_update", |b| {
        b.iter(|| {
            runtime.block_on(async {
                server.update_learning(black_box(&interaction)).await
            })
        })
    });
    
    // Concurrent updates (10 threads)
    group.bench_function("concurrent_10", |b| {
        b.iter(|| {
            runtime.block_on(async {
                let handles: Vec<_> = (0..10)
                    .map(|i| {
                        let server = server.clone();
                        let interaction = interaction.clone();
                        tokio::spawn(async move {
                            server.update_learning(black_box(&interaction)).await
                        })
                    })
                    .collect();
                
                join_all(handles).await
            })
        })
    });
    
    // Concurrent updates (100 threads)
    group.bench_function("concurrent_100", |b| {
        b.iter(|| {
            runtime.block_on(async {
                let handles: Vec<_> = (0..100)
                    .map(|i| {
                        let server = server.clone();
                        let interaction = interaction.clone();
                        tokio::spawn(async move {
                            server.update_learning(black_box(&interaction)).await
                        })
                    })
                    .collect();
                
                join_all(handles).await
            })
        })
    });
    
    // High-frequency updates
    group.throughput(Throughput::Elements(1000));
    group.bench_function("high_frequency_1000", |b| {
        b.iter(|| {
            runtime.block_on(async {
                for _ in 0..1000 {
                    server.update_learning(black_box(&interaction)).await.ok();
                }
            })
        })
    });
    
    group.finish();
}

/// Benchmark cross-instance communication
fn benchmark_cross_instance(c: &mut Criterion) {
    let runtime = Runtime::new().unwrap();
    
    // Create multiple server instances
    let servers: Vec<Arc<LearningServer>> = runtime.block_on(async {
        let mut servers = Vec::new();
        for _ in 0..4 {
            servers.push(Arc::new(LearningServer::new().await));
        }
        servers
    });
    
    let mut group = c.benchmark_group("cross_instance");
    
    // Point-to-point message
    let message = CrossInstanceMessage::new(
        "source".to_string(),
        "target".to_string(),
        vec![0.5; 1000]
    );
    
    group.bench_function("point_to_point", |b| {
        b.iter(|| {
            runtime.block_on(async {
                servers[0].send_message(black_box(&message)).await
            })
        })
    });
    
    // Broadcast message
    group.bench_function("broadcast", |b| {
        b.iter(|| {
            runtime.block_on(async {
                servers[0].broadcast_message(black_box(&message)).await
            })
        })
    });
    
    // Knowledge synchronization
    let knowledge_items = 100;
    group.throughput(Throughput::Elements(knowledge_items));
    group.bench_function("knowledge_sync", |b| {
        b.iter(|| {
            runtime.block_on(async {
                servers[0].sync_knowledge_with(&servers[1], knowledge_items as usize).await
            })
        })
    });
    
    group.finish();
}

/// Benchmark memory allocation patterns
fn benchmark_memory_patterns(c: &mut Criterion) {
    let runtime = Runtime::new().unwrap();
    let server = Arc::new(runtime.block_on(LearningServer::new()));
    
    let mut group = c.benchmark_group("memory_patterns");
    
    // Pattern storage
    for size in &[100, 1000, 10000] {
        let pattern = Pattern::new(vec![0.5; *size]);
        
        group.bench_with_input(
            BenchmarkId::new("store_pattern", size),
            size,
            |b, _| {
                b.iter(|| {
                    runtime.block_on(async {
                        server.store_pattern(black_box(&pattern)).await
                    })
                })
            }
        );
    }
    
    // Batch allocation
    let batch_size = 1000;
    group.throughput(Throughput::Elements(batch_size));
    group.bench_function("batch_allocation", |b| {
        b.iter(|| {
            runtime.block_on(async {
                let patterns: Vec<Pattern> = (0..batch_size)
                    .map(|_| Pattern::new(vec![0.5; 100]))
                    .collect();
                
                for pattern in patterns {
                    server.store_pattern(black_box(&pattern)).await.ok();
                }
            })
        })
    });
    
    // Memory pool efficiency
    group.bench_function("memory_pool", |b| {
        b.iter(|| {
            runtime.block_on(async {
                // Allocate and deallocate patterns to test pool efficiency
                for i in 0..100 {
                    let pattern = Pattern::new(vec![0.5; 1000]);
                    let id = server.store_pattern(&pattern).await.unwrap();
                    
                    if i % 2 == 0 {
                        server.remove_pattern(&id).await.ok();
                    }
                }
            })
        })
    });
    
    group.finish();
}

/// Benchmark consensus algorithms
fn benchmark_consensus(c: &mut Criterion) {
    let runtime = Runtime::new().unwrap();
    
    // Create cluster of servers
    let servers: Vec<Arc<LearningServer>> = runtime.block_on(async {
        let mut servers = Vec::new();
        for _ in 0..5 {
            servers.push(Arc::new(LearningServer::new().await));
        }
        servers
    });
    
    let mut group = c.benchmark_group("consensus");
    group.measurement_time(Duration::from_secs(30));
    
    // Simple majority
    let proposal = vec![0.5; 100];
    group.bench_function("simple_majority", |b| {
        b.iter(|| {
            runtime.block_on(async {
                servers[0].propose_consensus(black_box(&proposal), &servers).await
            })
        })
    });
    
    // Byzantine fault tolerant
    group.bench_function("bft_consensus", |b| {
        b.iter(|| {
            runtime.block_on(async {
                servers[0].bft_consensus(black_box(&proposal), &servers, 1).await
            })
        })
    });
    
    // Raft consensus
    group.bench_function("raft_append", |b| {
        b.iter(|| {
            runtime.block_on(async {
                servers[0].raft_append_entry(black_box(&proposal), &servers).await
            })
        })
    });
    
    group.finish();
}

/// Benchmark pattern recognition under load
fn benchmark_pattern_recognition_load(c: &mut Criterion) {
    let runtime = Runtime::new().unwrap();
    let server = Arc::new(runtime.block_on(LearningServer::new()));
    
    // Pre-train with patterns
    runtime.block_on(async {
        for i in 0..1000 {
            let pattern = Pattern::new(vec![i as f32 / 1000.0; 100]);
            server.train_pattern(&pattern).await.ok();
        }
    });
    
    let mut group = c.benchmark_group("pattern_recognition");
    
    // Recognition accuracy under no load
    let test_pattern = Pattern::new(vec![0.5; 100]);
    group.bench_function("no_load", |b| {
        b.iter(|| {
            runtime.block_on(async {
                server.recognize_pattern(black_box(&test_pattern)).await
            })
        })
    });
    
    // Recognition under concurrent load
    group.bench_function("concurrent_load", |b| {
        b.iter(|| {
            runtime.block_on(async {
                let recognition = tokio::spawn({
                    let server = server.clone();
                    let pattern = test_pattern.clone();
                    async move {
                        server.recognize_pattern(black_box(&pattern)).await
                    }
                });
                
                // Generate load
                let load_tasks: Vec<_> = (0..10)
                    .map(|_| {
                        let server = server.clone();
                        tokio::spawn(async move {
                            let pattern = Pattern::new(vec![0.7; 100]);
                            server.match_pattern(&pattern).await.ok();
                        })
                    })
                    .collect();
                
                let result = recognition.await.unwrap();
                join_all(load_tasks).await;
                result
            })
        })
    });
    
    group.finish();
}

/// Benchmark cache performance
fn benchmark_cache_performance(c: &mut Criterion) {
    let runtime = Runtime::new().unwrap();
    let server = Arc::new(runtime.block_on(LearningServer::new()));
    
    // Populate cache
    runtime.block_on(async {
        for i in 0..1000 {
            let pattern = Pattern::new(vec![i as f32 / 1000.0; 100]);
            server.cache_pattern(&pattern).await.ok();
        }
    });
    
    let mut group = c.benchmark_group("cache");
    
    // Cache hit
    let cached_pattern = Pattern::new(vec![0.5; 100]);
    runtime.block_on(async {
        server.cache_pattern(&cached_pattern).await.ok();
    });
    
    group.bench_function("cache_hit", |b| {
        b.iter(|| {
            runtime.block_on(async {
                server.get_cached_pattern(black_box(&cached_pattern.id())).await
            })
        })
    });
    
    // Cache miss
    let uncached_pattern = Pattern::new(vec![0.99; 100]);
    group.bench_function("cache_miss", |b| {
        b.iter(|| {
            runtime.block_on(async {
                server.get_cached_pattern(black_box(&uncached_pattern.id())).await
            })
        })
    });
    
    // Cache eviction
    group.bench_function("cache_eviction", |b| {
        b.iter(|| {
            runtime.block_on(async {
                let pattern = Pattern::new(vec![0.8; 100]);
                server.cache_pattern_with_eviction(black_box(&pattern)).await
            })
        })
    });
    
    group.finish();
}

// Define criterion groups
criterion_group!(
    benches,
    benchmark_pattern_matching,
    benchmark_learning_updates,
    benchmark_cross_instance,
    benchmark_memory_patterns,
    benchmark_consensus,
    benchmark_pattern_recognition_load,
    benchmark_cache_performance
);

criterion_main!(benches);