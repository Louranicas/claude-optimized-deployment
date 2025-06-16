//! SYNTHEX Performance Benchmarks
//!
//! Comprehensive benchmarks for the SYNTHEX search engine measuring:
//! - Search speed and latency
//! - Concurrent operations scalability
//! - Memory usage and efficiency
//! - Cache performance
//! - Agent coordination
//! - Knowledge graph operations

use claude_optimized_deployment_rust::synthex::{
    agents::{MockAgent, SearchAgent},
    constants, create_synthex_service,
    knowledge_graph::KnowledgeGraph,
    parallel_executor::ParallelExecutor,
    result_aggregator::ResultAggregator,
    utils, QueryOptions, SearchItem, SearchQuery, SearchResult, SynthexConfig, SynthexEngine,
};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use futures::future::join_all;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;

/// Generate random search query for benchmarking
fn generate_random_query() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect()
}

/// Generate mock search results
fn generate_mock_results(count: usize) -> Vec<SearchItem> {
    (0..count)
        .map(|i| SearchItem {
            id: format!("item-{}", i),
            title: format!("Result {}", i),
            content: "Lorem ipsum dolor sit amet, consectetur adipiscing elit.".to_string(),
            url: Some(format!("https://example.com/item-{}", i)),
            score: thread_rng().gen_range(0.0..1.0),
            source: "mock".to_string(),
            metadata: Default::default(),
        })
        .collect()
}

/// Benchmark single search operations
fn bench_single_search(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("synthex_single_search");

    // Setup SYNTHEX engine
    let engine = rt.block_on(async {
        let config = SynthexConfig::default();
        let engine = Arc::new(SynthexEngine::new(config).await.unwrap());

        // Register mock agents
        for i in 0..5 {
            let agent = MockAgent::new(format!("mock-agent-{}", i));
            engine
                .register_agent(format!("agent-{}", i), Arc::new(agent))
                .await
                .unwrap();
        }

        engine
    });

    // Benchmark simple query
    group.bench_function("simple_query", |b| {
        let eng = engine.clone();
        b.to_async(&rt).iter(|| async {
            let query = SearchQuery::new("test query");
            let result = eng.search(query).await.unwrap();
            black_box(result)
        });
    });

    // Benchmark complex query with options
    group.bench_function("complex_query", |b| {
        let eng = engine.clone();
        b.to_async(&rt).iter(|| async {
            let mut query = SearchQuery::new("advanced search query with multiple terms");
            query.options = QueryOptions {
                max_results: 100,
                timeout_ms: 5000,
                sources: vec!["web".to_string(), "database".to_string(), "api".to_string()],
                filters: Default::default(),
                sort_by: Some("relevance".to_string()),
                include_metadata: true,
            };

            let result = eng.search(query).await.unwrap();
            black_box(result)
        });
    });

    // Benchmark cached query
    group.bench_function("cached_query", |b| {
        let eng = engine.clone();
        let query = SearchQuery::new("cached test query");

        // Warm up cache
        rt.block_on(async {
            eng.search(query.clone()).await.unwrap();
        });

        b.to_async(&rt).iter(|| async {
            let result = eng.search(query.clone()).await.unwrap();
            black_box(result)
        });
    });

    group.finish();
}

/// Benchmark concurrent search operations
fn bench_concurrent_searches(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("synthex_concurrent_searches");
    group.sample_size(10); // Reduce sample size for heavy concurrent tests

    // Setup SYNTHEX service
    let service = rt.block_on(async {
        let config = SynthexConfig::default();
        let service = create_synthex_service(config).await.unwrap();

        // Register multiple agents
        for i in 0..10 {
            let agent = MockAgent::new(format!("concurrent-agent-{}", i));
            service
                .register_agent(format!("agent-{}", i), Arc::new(agent))
                .await
                .unwrap();
        }

        Arc::new(service)
    });

    // Benchmark different concurrency levels
    for concurrent in [10, 50, 100, 500].iter() {
        group.throughput(Throughput::Elements(*concurrent as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(concurrent),
            concurrent,
            |b, &concurrent| {
                let svc = service.clone();
                b.to_async(&rt).iter(|| async move {
                    let tasks: Vec<_> = (0..concurrent)
                        .map(|i| {
                            let svc_clone = svc.clone();
                            tokio::spawn(async move {
                                let query = SearchQuery::new(&format!("concurrent query {}", i));
                                svc_clone.search(query).await
                            })
                        })
                        .collect();

                    let results = join_all(tasks).await;
                    black_box(results)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark memory usage patterns
fn bench_memory_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("synthex_memory_operations");

    // Setup components
    let knowledge_graph = Arc::new(KnowledgeGraph::new());
    let aggregator = ResultAggregator::new();

    // Benchmark result aggregation with different sizes
    for size in [100, 1000, 10000].iter() {
        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("aggregate_results", size),
            size,
            |b, &size| {
                let results = generate_mock_results(size);
                b.iter(|| {
                    let aggregated = aggregator.aggregate(results.clone());
                    black_box(aggregated)
                });
            },
        );
    }

    // Benchmark knowledge graph operations
    group.bench_function("knowledge_graph_insert", |b| {
        let kg = knowledge_graph.clone();
        b.to_async(&rt).iter(|| async {
            let result = SearchResult {
                query_id: utils::generate_query_id("test", &QueryOptions::default()),
                total_results: 10,
                execution_time_ms: 100,
                results: generate_mock_results(10),
                metadata: Default::default(),
            };

            kg.insert_results(&result).await;
            black_box(())
        });
    });

    group.bench_function("knowledge_graph_query", |b| {
        let kg = knowledge_graph.clone();

        // Populate with test data
        rt.block_on(async {
            for i in 0..100 {
                let result = SearchResult {
                    query_id: format!("query-{}", i),
                    total_results: 10,
                    execution_time_ms: 100,
                    results: generate_mock_results(10),
                    metadata: Default::default(),
                };
                kg.insert_results(&result).await;
            }
        });

        b.to_async(&rt).iter(|| async {
            let related = kg.find_related("test query", 10).await;
            black_box(related)
        });
    });

    group.finish();
}

/// Benchmark parallel execution
fn bench_parallel_execution(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("synthex_parallel_execution");

    let executor = Arc::new(ParallelExecutor::new(num_cpus::get()));

    // Benchmark task distribution
    for task_count in [10, 100, 1000].iter() {
        group.throughput(Throughput::Elements(*task_count as u64));
        group.bench_with_input(
            BenchmarkId::new("distribute_tasks", task_count),
            task_count,
            |b, &task_count| {
                let exec = executor.clone();
                b.to_async(&rt).iter(|| async move {
                    let tasks: Vec<_> = (0..task_count)
                        .map(|i| {
                            let exec_clone = exec.clone();
                            tokio::spawn(async move {
                                exec_clone
                                    .execute_task(async move {
                                        // Simulate work
                                        tokio::time::sleep(Duration::from_micros(10)).await;
                                        i
                                    })
                                    .await
                            })
                        })
                        .collect();

                    let results = join_all(tasks).await;
                    black_box(results)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark cache performance
fn bench_cache_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("synthex_cache");

    let engine = rt.block_on(async {
        let mut config = SynthexConfig::default();
        config.cache_size_mb = 1024; // 1GB cache
        config.cache_ttl_seconds = 3600;

        Arc::new(SynthexEngine::new(config).await.unwrap())
    });

    // Prepare test queries
    let queries: Vec<SearchQuery> = (0..1000)
        .map(|i| SearchQuery::new(&format!("cache test query {}", i)))
        .collect();

    // Benchmark cache miss rate
    group.bench_function("cache_miss", |b| {
        let eng = engine.clone();
        let mut idx = 0;
        b.to_async(&rt).iter(|| async {
            let query = &queries[idx % queries.len()];
            idx += 1;
            let result = eng.search(query.clone()).await.unwrap();
            black_box(result)
        });
    });

    // Warm up cache
    rt.block_on(async {
        for query in &queries[..100] {
            engine.search(query.clone()).await.unwrap();
        }
    });

    // Benchmark cache hit rate
    group.bench_function("cache_hit", |b| {
        let eng = engine.clone();
        let mut idx = 0;
        b.to_async(&rt).iter(|| async {
            let query = &queries[idx % 100]; // Only use cached queries
            idx += 1;
            let result = eng.search(query.clone()).await.unwrap();
            black_box(result)
        });
    });

    group.finish();
}

/// Benchmark query parsing and optimization
fn bench_query_processing(c: &mut Criterion) {
    let mut group = c.benchmark_group("synthex_query_processing");

    use claude_optimized_deployment_rust::synthex::query_parser::QueryParser;

    let parser = QueryParser::new();

    // Simple queries
    group.bench_function("parse_simple", |b| {
        b.iter(|| {
            let parsed = parser.parse("simple search query");
            black_box(parsed)
        });
    });

    // Complex queries with operators
    group.bench_function("parse_complex", |b| {
        b.iter(|| {
            let parsed =
                parser.parse("advanced AND (search OR query) NOT excluded site:example.com");
            black_box(parsed)
        });
    });

    // Query sanitization
    group.bench_function("sanitize_query", |b| {
        let dirty_query = "test <script>alert('xss')</script> query!@#$%^&*()";
        b.iter(|| {
            let sanitized = utils::sanitize_query(dirty_query);
            black_box(sanitized)
        });
    });

    // Query ID generation
    group.bench_function("generate_query_id", |b| {
        let query = "benchmark test query";
        let options = QueryOptions::default();
        b.iter(|| {
            let id = utils::generate_query_id(query, &options);
            black_box(id)
        });
    });

    group.finish();
}

/// Benchmark agent coordination
fn bench_agent_coordination(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("synthex_agent_coordination");

    let service = rt.block_on(async {
        let config = SynthexConfig::default();
        let service = create_synthex_service(config).await.unwrap();

        // Register different types of agents
        for i in 0..20 {
            let agent = MockAgent::new(format!("coordination-agent-{}", i));
            service
                .register_agent(format!("agent-{}", i), Arc::new(agent))
                .await
                .unwrap();
        }

        Arc::new(service)
    });

    // Benchmark agent health checks
    group.bench_function("health_check_all", |b| {
        let svc = service.clone();
        b.to_async(&rt).iter(|| async {
            let status = svc.get_agent_status().await.unwrap();
            black_box(status)
        });
    });

    // Benchmark coordinated search across all agents
    group.bench_function("coordinated_search", |b| {
        let svc = service.clone();
        b.to_async(&rt).iter(|| async {
            let mut query = SearchQuery::new("coordinated search across all agents");
            query.options.sources = (0..20).map(|i| format!("agent-{}", i)).collect();

            let result = svc.search(query).await.unwrap();
            black_box(result)
        });
    });

    group.finish();
}

/// Benchmark result ranking and scoring
fn bench_result_ranking(c: &mut Criterion) {
    let mut group = c.benchmark_group("synthex_result_ranking");

    let aggregator = ResultAggregator::new();

    // Benchmark different result set sizes
    for size in [100, 500, 1000, 5000].iter() {
        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(BenchmarkId::new("rank_results", size), size, |b, &size| {
            let mut results = generate_mock_results(size);
            // Add variety to scores
            for (i, result) in results.iter_mut().enumerate() {
                result.score = (i as f32 / size as f32) * thread_rng().gen_range(0.5..1.0);
            }

            b.iter(|| {
                let ranked = aggregator.rank_results(results.clone());
                black_box(ranked)
            });
        });
    }

    group.finish();
}

/// Benchmark memory allocation patterns
fn bench_memory_allocation(c: &mut Criterion) {
    let mut group = c.benchmark_group("synthex_memory_allocation");

    // Benchmark search result allocation
    group.bench_function("allocate_search_result", |b| {
        b.iter(|| {
            let result = SearchResult {
                query_id: "bench-query".to_string(),
                total_results: 1000,
                execution_time_ms: 100,
                results: Vec::with_capacity(1000),
                metadata: Default::default(),
            };
            black_box(result)
        });
    });

    // Benchmark large result set creation
    group.bench_function("create_large_result_set", |b| {
        b.iter(|| {
            let results = generate_mock_results(10000);
            black_box(results)
        });
    });

    // Benchmark metadata operations
    group.bench_function("metadata_operations", |b| {
        use std::collections::HashMap;
        b.iter(|| {
            let mut metadata = HashMap::new();
            for i in 0..100 {
                metadata.insert(
                    format!("key_{}", i),
                    serde_json::json!({
                        "value": i,
                        "timestamp": chrono::Utc::now(),
                        "tags": vec!["tag1", "tag2", "tag3"]
                    }),
                );
            }
            black_box(metadata)
        });
    });

    group.finish();
}

/// Benchmark end-to-end search pipeline
fn bench_end_to_end_pipeline(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("synthex_end_to_end");
    group.sample_size(10);

    // Create full production configuration
    let service = rt.block_on(async {
        let mut config = SynthexConfig::default();
        config.max_concurrent_searches = 1000;
        config.cache_size_mb = 2048;
        config.enable_ml_optimization = false; // Disabled for benchmarking

        let service = create_synthex_service(config).await.unwrap();

        // Register diverse agents
        for i in 0..10 {
            let agent = MockAgent::new(format!("production-agent-{}", i));
            service
                .register_agent(format!("agent-{}", i), Arc::new(agent))
                .await
                .unwrap();
        }

        Arc::new(service)
    });

    // Benchmark realistic workload
    group.bench_function("realistic_workload", |b| {
        let svc = service.clone();
        b.to_async(&rt).iter(|| async {
            // Simulate mixed workload
            let tasks: Vec<_> = (0..100)
                .map(|i| {
                    let svc_clone = svc.clone();
                    tokio::spawn(async move {
                        let query_type = i % 3;
                        let query = match query_type {
                            0 => SearchQuery::new("simple search"),
                            1 => {
                                let mut q = SearchQuery::new("complex search with filters");
                                q.options.max_results = 50;
                                q.options
                                    .filters
                                    .insert("type".to_string(), "document".to_string());
                                q
                            }
                            _ => {
                                let mut q = SearchQuery::new("advanced multi-source search");
                                q.options.sources =
                                    vec!["agent-0".to_string(), "agent-1".to_string()];
                                q.options.timeout_ms = 3000;
                                q
                            }
                        };

                        svc_clone.search(query).await
                    })
                })
                .collect();

            let results = join_all(tasks).await;
            black_box(results)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_single_search,
    bench_concurrent_searches,
    bench_memory_operations,
    bench_parallel_execution,
    bench_cache_operations,
    bench_query_processing,
    bench_agent_coordination,
    bench_result_ranking,
    bench_memory_allocation,
    bench_end_to_end_pipeline
);

criterion_main!(benches);
