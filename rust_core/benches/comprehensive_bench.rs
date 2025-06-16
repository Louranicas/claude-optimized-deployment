use claude_optimized_deployment_rust::*;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::time::Duration;

fn bench_command_optimization(c: &mut Criterion) {
    let mut group = c.benchmark_group("command_optimization");

    for size in [10, 50, 100, 500, 1000].iter() {
        group.throughput(Throughput::Elements(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let commands: Vec<_> = (0..size)
                .map(|i| Command::new("echo", vec![format!("test_{}", i)]))
                .collect();

            let optimizer = CommandOptimizer::new();

            b.iter(|| {
                let optimized = optimizer.optimize(black_box(&commands)).unwrap();
                black_box(optimized);
            });
        });
    }

    group.finish();
}

fn bench_memory_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_operations");
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Setup memory system
    let memory = rt.block_on(async {
        MemorySystem::new(MemoryConfig {
            max_size_bytes: 1024 * 1024 * 1024, // 1GB
            enable_compression: false,
            gc_interval: Duration::from_secs(3600),
        })
    });

    // Benchmark store operations
    group.bench_function("store_small", |b| {
        b.to_async(&rt).iter(|| async {
            let key = format!("key_{}", rand::random::<u64>());
            let value = vec![0u8; 100];
            memory.store(&key, black_box(value)).await.unwrap();
        });
    });

    group.bench_function("store_medium", |b| {
        b.to_async(&rt).iter(|| async {
            let key = format!("key_{}", rand::random::<u64>());
            let value = vec![0u8; 10_000];
            memory.store(&key, black_box(value)).await.unwrap();
        });
    });

    group.bench_function("store_large", |b| {
        b.to_async(&rt).iter(|| async {
            let key = format!("key_{}", rand::random::<u64>());
            let value = vec![0u8; 1_000_000];
            memory.store(&key, black_box(value)).await.unwrap();
        });
    });

    // Prepare data for retrieval benchmarks
    rt.block_on(async {
        for i in 0..1000 {
            let key = format!("retrieve_key_{}", i);
            let value = vec![i as u8; 1000];
            memory.store(&key, value).await.unwrap();
        }
    });

    group.bench_function("retrieve_existing", |b| {
        b.to_async(&rt).iter(|| async {
            let key = format!("retrieve_key_{}", rand::random::<u32>() % 1000);
            let value = memory.get(black_box(&key)).await.unwrap();
            black_box(value);
        });
    });

    group.bench_function("retrieve_missing", |b| {
        b.to_async(&rt).iter(|| async {
            let key = format!("missing_key_{}", rand::random::<u64>());
            let value = memory.get(black_box(&key)).await.unwrap();
            black_box(value);
        });
    });

    group.finish();
}

fn bench_vector_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("vector_operations");
    let rt = tokio::runtime::Runtime::new().unwrap();

    let vector_db = rt.block_on(async {
        VectorDB::new(128) // 128-dimensional vectors
    });

    // Prepare test vectors
    let vectors: Vec<Vec<f32>> = (0..1000)
        .map(|_| (0..128).map(|_| rand::random::<f32>()).collect())
        .collect();

    // Store vectors
    rt.block_on(async {
        for (i, vec) in vectors.iter().enumerate() {
            vector_db
                .store(&format!("vec_{}", i), vec.clone())
                .await
                .unwrap();
        }
    });

    group.bench_function("vector_store", |b| {
        b.to_async(&rt).iter(|| async {
            let id = format!("bench_{}", rand::random::<u64>());
            let vector: Vec<f32> = (0..128).map(|_| rand::random()).collect();
            vector_db.store(&id, black_box(vector)).await.unwrap();
        });
    });

    group.bench_function("vector_search_top_10", |b| {
        let query_vector: Vec<f32> = (0..128).map(|_| rand::random()).collect();

        b.to_async(&rt).iter(|| async {
            let results = vector_db
                .search_top_k(black_box(&query_vector), 10)
                .await
                .unwrap();
            black_box(results);
        });
    });

    group.bench_function("vector_search_top_100", |b| {
        let query_vector: Vec<f32> = (0..128).map(|_| rand::random()).collect();

        b.to_async(&rt).iter(|| async {
            let results = vector_db
                .search_top_k(black_box(&query_vector), 100)
                .await
                .unwrap();
            black_box(results);
        });
    });

    group.finish();
}

fn bench_learning_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("learning_operations");
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Small dataset
    let small_data: Vec<(Vec<f32>, Vec<f32>)> = (0..100)
        .map(|i| {
            let x = i as f32 / 100.0;
            let y = x * 2.0 + 1.0;
            (vec![x], vec![y])
        })
        .collect();

    // Medium dataset
    let medium_data: Vec<(Vec<f32>, Vec<f32>)> = (0..1000)
        .map(|i| {
            let x = vec![
                (i as f32) / 1000.0,
                ((i * 2) as f32) / 1000.0,
                ((i * 3) as f32) / 1000.0,
            ];
            let y = vec![x[0] * 2.0 + x[1] * 3.0 + x[2] * 4.0];
            (x, y)
        })
        .collect();

    group.bench_function("train_epoch_small", |b| {
        let learner = rt.block_on(async {
            AdaptiveLearner::new(LearnerConfig {
                model_type: ModelType::Linear,
                learning_rate: 0.01,
                batch_size: 32,
                max_epochs: 1,
            })
        });

        b.to_async(&rt).iter(|| async {
            learner.train_epoch(black_box(&small_data)).await.unwrap();
        });
    });

    group.bench_function("train_epoch_medium", |b| {
        let learner = rt.block_on(async {
            AdaptiveLearner::new(LearnerConfig {
                model_type: ModelType::Linear,
                learning_rate: 0.01,
                batch_size: 32,
                max_epochs: 1,
            })
        });

        b.to_async(&rt).iter(|| async {
            learner.train_epoch(black_box(&medium_data)).await.unwrap();
        });
    });

    group.bench_function("predict_single", |b| {
        let learner = rt.block_on(async {
            let l = AdaptiveLearner::new(LearnerConfig {
                model_type: ModelType::Linear,
                learning_rate: 0.01,
                batch_size: 32,
                max_epochs: 10,
            });
            l.train(&small_data).await.unwrap();
            l
        });

        b.to_async(&rt).iter(|| async {
            let input = vec![0.5];
            let output = learner.predict(black_box(&input)).await.unwrap();
            black_box(output);
        });
    });

    group.bench_function("predict_batch", |b| {
        let learner = rt.block_on(async {
            let l = AdaptiveLearner::new(LearnerConfig {
                model_type: ModelType::Linear,
                learning_rate: 0.01,
                batch_size: 32,
                max_epochs: 10,
            });
            l.train(&small_data).await.unwrap();
            l
        });

        let batch: Vec<Vec<f32>> = (0..100).map(|i| vec![i as f32 / 100.0]).collect();

        b.to_async(&rt).iter(|| async {
            let outputs = learner.predict_batch(black_box(&batch)).await.unwrap();
            black_box(outputs);
        });
    });

    group.finish();
}

fn bench_mcp_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("mcp_operations");
    let rt = tokio::runtime::Runtime::new().unwrap();

    let handler = MCPHandler::new();

    group.bench_function("handle_list_tools", |b| {
        let request = r#"{
            "jsonrpc": "2.0",
            "method": "list_tools",
            "id": 1
        }"#;

        b.iter(|| {
            let response = handler.handle_raw_request(black_box(request)).unwrap();
            black_box(response);
        });
    });

    group.bench_function("handle_execute_tool", |b| {
        let request = r#"{
            "jsonrpc": "2.0",
            "method": "execute_tool",
            "params": {
                "tool": "echo",
                "arguments": {
                    "message": "Hello, World!"
                }
            },
            "id": 1
        }"#;

        b.iter(|| {
            let response = handler.handle_raw_request(black_box(request)).unwrap();
            black_box(response);
        });
    });

    group.bench_function("parse_large_request", |b| {
        let large_params = serde_json::json!({
            "data": (0..1000).map(|i| {
                serde_json::json!({
                    "id": i,
                    "value": format!("item_{}", i),
                    "metadata": {
                        "created": "2024-01-01T00:00:00Z",
                        "updated": "2024-01-01T00:00:00Z",
                        "tags": ["tag1", "tag2", "tag3"]
                    }
                })
            }).collect::<Vec<_>>()
        });

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "process_batch",
            "params": large_params,
            "id": 1
        })
        .to_string();

        b.iter(|| {
            let response = handler.handle_raw_request(black_box(&request)).unwrap();
            black_box(response);
        });
    });

    group.finish();
}

fn bench_parallel_execution(c: &mut Criterion) {
    let mut group = c.benchmark_group("parallel_execution");
    let rt = tokio::runtime::Runtime::new().unwrap();

    for num_tasks in [10, 50, 100, 500].iter() {
        group.throughput(Throughput::Elements(*num_tasks as u64));

        group.bench_with_input(
            BenchmarkId::from_parameter(num_tasks),
            num_tasks,
            |b, &num_tasks| {
                let executor = ParallelExecutor::new();
                let tasks: Vec<_> = (0..num_tasks)
                    .map(|i| Task::new(format!("task_{}", i), Duration::from_micros(100)))
                    .collect();

                b.to_async(&rt).iter(|| async {
                    let results = executor.execute_all(black_box(&tasks)).await.unwrap();
                    black_box(results);
                });
            },
        );
    }

    group.finish();
}

fn bench_actor_messaging(c: &mut Criterion) {
    let mut group = c.benchmark_group("actor_messaging");
    let rt = tokio::runtime::Runtime::new().unwrap();

    let system = rt.block_on(async { ActorSystem::new() });

    let actor = rt.block_on(async { system.spawn_actor("bench_actor").await.unwrap() });

    group.bench_function("send_message", |b| {
        b.to_async(&rt).iter(|| async {
            let msg = Message::new("bench", vec![1, 2, 3, 4, 5]);
            actor.send(black_box(msg)).await.unwrap();
        });
    });

    group.bench_function("send_receive_roundtrip", |b| {
        b.to_async(&rt).iter(|| async {
            let msg = Message::new("echo", vec![1, 2, 3, 4, 5]);
            actor.send(black_box(msg)).await.unwrap();
            let response = actor
                .receive_timeout(Duration::from_millis(100))
                .await
                .unwrap();
            black_box(response);
        });
    });

    // Benchmark with multiple actors
    let actors: Vec<_> = rt.block_on(async {
        futures::future::join_all((0..10).map(|i| system.spawn_actor(&format!("actor_{}", i))))
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    });

    group.bench_function("broadcast_to_10_actors", |b| {
        b.to_async(&rt).iter(|| async {
            let msg = Message::new("broadcast", vec![0; 100]);
            for actor in &actors {
                actor.send(black_box(msg.clone())).await.unwrap();
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_command_optimization,
    bench_memory_operations,
    bench_vector_operations,
    bench_learning_operations,
    bench_mcp_operations,
    bench_parallel_execution,
    bench_actor_messaging
);
criterion_main!(benches);
