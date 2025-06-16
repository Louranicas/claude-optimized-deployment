use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use code_rust_core::*;
use std::collections::HashMap;
use std::time::Duration;
use tokio::runtime::Runtime;

// Benchmark infrastructure scanning
fn bench_infrastructure_scanning(c: &mut Criterion) {
    let mut group = c.benchmark_group("infrastructure_scanning");
    
    for size in [100, 500, 1000, 5000].iter() {
        group.bench_with_input(BenchmarkId::new("rust_scan", size), size, |b, &size| {
            b.iter(|| {
                let mut resources = HashMap::new();
                for i in 0..size {
                    resources.insert(format!("resource_{}", i), format!("value_{}", i));
                }
                
                // Simulate processing
                let processed: Vec<_> = resources
                    .iter()
                    .map(|(k, v)| format!("{}:{}", k, v))
                    .collect();
                
                black_box(processed);
            });
        });
    }
    
    group.finish();
}

// Benchmark configuration parsing
fn bench_config_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("config_parsing");
    
    let config_json = r#"
    {
        "services": [
            {"name": "web", "replicas": 3, "cpu": "100m", "memory": "128Mi"},
            {"name": "api", "replicas": 2, "cpu": "200m", "memory": "256Mi"},
            {"name": "db", "replicas": 1, "cpu": "500m", "memory": "1Gi"}
        ],
        "network": {
            "ingress": {"enabled": true, "host": "example.com"},
            "service_mesh": {"enabled": false}
        },
        "storage": {
            "persistent_volumes": [
                {"name": "db-data", "size": "10Gi", "type": "ssd"}
            ]
        }
    }
    "#;
    
    group.bench_function("parse_json_config", |b| {
        b.iter(|| {
            let config: serde_json::Value = serde_json::from_str(black_box(config_json)).unwrap();
            black_box(config);
        });
    });
    
    group.bench_function("serialize_json_config", |b| {
        let config: serde_json::Value = serde_json::from_str(config_json).unwrap();
        b.iter(|| {
            let serialized = serde_json::to_string(black_box(&config)).unwrap();
            black_box(serialized);
        });
    });
    
    group.finish();
}

// Benchmark SIMD operations
fn bench_simd_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("simd_operations");
    
    for size in [1000, 10000, 100000].iter() {
        let data: Vec<f32> = (0..*size).map(|x| x as f32).collect();
        
        group.bench_with_input(BenchmarkId::new("vector_sum", size), &data, |b, data| {
            b.iter(|| {
                let sum: f32 = data.iter().sum();
                black_box(sum);
            });
        });
        
        group.bench_with_input(BenchmarkId::new("vector_dot_product", size), &data, |b, data| {
            b.iter(|| {
                let dot_product: f32 = data.iter().zip(data.iter()).map(|(a, b)| a * b).sum();
                black_box(dot_product);
            });
        });
    }
    
    group.finish();
}

// Benchmark parallel processing
fn bench_parallel_processing(c: &mut Criterion) {
    let mut group = c.benchmark_group("parallel_processing");
    
    for size in [1000, 10000, 100000].iter() {
        let data: Vec<i32> = (0..*size).collect();
        
        group.bench_with_input(BenchmarkId::new("sequential_process", size), &data, |b, data| {
            b.iter(|| {
                let result: Vec<i32> = data.iter().map(|x| x * x + 1).collect();
                black_box(result);
            });
        });
        
        group.bench_with_input(BenchmarkId::new("parallel_process", size), &data, |b, data| {
            use rayon::prelude::*;
            b.iter(|| {
                let result: Vec<i32> = data.par_iter().map(|x| x * x + 1).collect();
                black_box(result);
            });
        });
    }
    
    group.finish();
}

// Benchmark memory-mapped operations
fn bench_memory_mapped_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_mapped");
    
    // Create test data
    let test_data = b"test data ".repeat(10000);
    let temp_file = std::env::temp_dir().join("benchmark_test.dat");
    std::fs::write(&temp_file, &test_data).unwrap();
    
    group.bench_function("file_read_normal", |b| {
        b.iter(|| {
            let data = std::fs::read(black_box(&temp_file)).unwrap();
            black_box(data);
        });
    });
    
    group.bench_function("file_read_mmap", |b| {
        use memmap2::MmapOptions;
        b.iter(|| {
            let file = std::fs::File::open(black_box(&temp_file)).unwrap();
            let mmap = unsafe { MmapOptions::new().map(&file).unwrap() };
            let data = &mmap[..];
            black_box(data);
        });
    });
    
    // Cleanup
    std::fs::remove_file(&temp_file).ok();
    group.finish();
}

// Benchmark lockfree collections
fn bench_lockfree_collections(c: &mut Criterion) {
    let mut group = c.benchmark_group("lockfree_collections");
    
    use dashmap::DashMap;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    
    group.bench_function("dashmap_insert", |b| {
        let map = DashMap::new();
        b.iter(|| {
            for i in 0..1000 {
                map.insert(black_box(i), black_box(i * 2));
            }
            map.clear();
        });
    });
    
    group.bench_function("mutex_hashmap_insert", |b| {
        let map = Arc::new(Mutex::new(HashMap::new()));
        b.iter(|| {
            for i in 0..1000 {
                let mut guard = map.lock().expect("Failed to acquire lock");
                guard.insert(black_box(i), black_box(i * 2));
            }
            map.lock().expect("Failed to acquire lock").clear();
        });
    });
    
    group.finish();
}

// Benchmark async operations
fn bench_async_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("async_operations");
    
    group.bench_function("async_task_spawn", |b| {
        b.to_async(&rt).iter(|| async {
            let tasks: Vec<_> = (0..100)
                .map(|i| {
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_nanos(1)).await;
                        i * 2
                    })
                })
                .collect();
            
            let results: Vec<_> = futures::future::join_all(tasks)
                .await
                .into_iter()
                .map(|r| r.unwrap())
                .collect();
            
            black_box(results);
        });
    });
    
    group.bench_function("async_channel_mpsc", |b| {
        b.to_async(&rt).iter(|| async {
            let (tx, mut rx) = tokio::sync::mpsc::channel(1000);
            
            // Spawn producer
            let producer = tokio::spawn(async move {
                for i in 0..1000 {
                    tx.send(i).await.unwrap();
                }
            });
            
            // Consume messages
            let mut count = 0;
            while let Some(_msg) = rx.recv().await {
                count += 1;
                if count >= 1000 {
                    break;
                }
            }
            
            producer.await.unwrap();
            black_box(count);
        });
    });
    
    group.finish();
}

// Benchmark cryptographic operations
fn bench_crypto_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_operations");
    
    use sha2::{Sha256, Digest};
    use hmac::{Hmac, Mac};
    
    let data = b"benchmark data ".repeat(100);
    let key = b"secret key for hmac operations";
    
    group.bench_function("sha256_hash", |b| {
        b.iter(|| {
            let mut hasher = Sha256::new();
            hasher.update(black_box(&data));
            let result = hasher.finalize();
            black_box(result);
        });
    });
    
    group.bench_function("hmac_sha256", |b| {
        type HmacSha256 = Hmac<Sha256>;
        b.iter(|| {
            let mut mac = HmacSha256::new_from_slice(black_box(key)).unwrap();
            mac.update(black_box(&data));
            let result = mac.finalize();
            black_box(result);
        });
    });
    
    group.finish();
}

// Benchmark network operations
fn bench_network_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("network_operations");
    
    group.bench_function("http_client_creation", |b| {
        b.iter(|| {
            let client = reqwest::Client::new();
            black_box(client);
        });
    });
    
    // Only run actual network tests if we have connectivity
    if std::env::var("BENCH_NETWORK").is_ok() {
        group.bench_function("http_request_httpbin", |b| {
            b.to_async(&rt).iter(|| async {
                let client = reqwest::Client::new();
                let response = client
                    .get("https://httpbin.org/json")
                    .send()
                    .await
                    .unwrap();
                let body = response.text().await.unwrap();
                black_box(body);
            });
        });
    }
    
    group.finish();
}

// Configure criterion
criterion_group!(
    benches,
    bench_infrastructure_scanning,
    bench_config_parsing,
    bench_simd_operations,
    bench_parallel_processing,
    bench_memory_mapped_ops,
    bench_lockfree_collections,
    bench_async_operations,
    bench_crypto_operations,
    bench_network_operations
);

criterion_main!(benches);