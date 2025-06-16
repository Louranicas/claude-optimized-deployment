//! Performance benchmarks for MCP Rust Core
//! 
//! Validates sub-microsecond performance targets.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use mcp_rust_core::{
    server::{HighPerfMCPServer, MCPServer, Request, Response},
    memory::MemoryPool,
    messaging::{MessageQueue, Priority},
    state::StateManager,
};
use serde_json::json;
use std::sync::Arc;
use tokio::runtime::Runtime;

/// Benchmark request processing
fn benchmark_request_processing(c: &mut Criterion) {
    let runtime = Runtime::new().unwrap();
    let server = Arc::new(HighPerfMCPServer::new(1024).unwrap());
    
    // Register a simple handler
    server.register_handler("echo".to_string(), |req| {
        Response {
            id: req.id,
            result: req.params.clone(),
            error: None,
            processing_time_us: 0,
        }
    });
    
    let mut group = c.benchmark_group("request_processing");
    
    // Benchmark different payload sizes
    for size in [10, 100, 1000, 10000].iter() {
        let payload = json!({
            "data": "x".repeat(*size),
            "timestamp": 12345678
        });
        
        let request = Request {
            id: 1,
            method: "echo".to_string(),
            params: payload,
            timestamp: 0,
        };
        
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            size,
            |b, _| {
                b.to_async(&runtime).iter(|| {
                    let server = server.clone();
                    let req = request.clone();
                    async move {
                        black_box(server.process_request(req).await.unwrap())
                    }
                });
            }
        );
    }
    
    group.finish();
}

/// Benchmark memory allocation
fn benchmark_memory_allocation(c: &mut Criterion) {
    let pool = MemoryPool::new(1024).unwrap();
    
    let mut group = c.benchmark_group("memory_allocation");
    
    // Benchmark different allocation sizes
    for size in [64, 256, 1024, 4096, 16384].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            size,
            |b, &size| {
                b.iter(|| {
                    black_box(pool.allocate_working(size))
                });
            }
        );
    }
    
    group.finish();
}

/// Benchmark message passing
fn benchmark_message_passing(c: &mut Criterion) {
    let runtime = Runtime::new().unwrap();
    let queue = Arc::new(MessageQueue::<serde_json::Value>::new());
    
    let mut group = c.benchmark_group("message_passing");
    
    // Benchmark send operation
    group.bench_function("send", |b| {
        b.iter(|| {
            black_box(queue.send(json!({"test": "data"}), Priority::Normal).unwrap())
        });
    });
    
    // Benchmark receive operation
    let queue_filled = Arc::new(MessageQueue::<serde_json::Value>::new());
    for _ in 0..1000 {
        queue_filled.send(json!({"test": "data"}), Priority::Normal).unwrap();
    }
    
    group.bench_function("receive", |b| {
        b.iter(|| {
            black_box(queue_filled.try_receive())
        });
    });
    
    // Benchmark concurrent send/receive
    group.bench_function("concurrent_send_receive", |b| {
        b.to_async(&runtime).iter(|| {
            let q = queue.clone();
            async move {
                let send_handle = tokio::spawn(async move {
                    for _ in 0..100 {
                        q.send(json!({"test": "data"}), Priority::Normal).unwrap();
                    }
                });
                
                let q2 = queue.clone();
                let recv_handle = tokio::spawn(async move {
                    for _ in 0..100 {
                        while q2.try_receive().is_none() {
                            tokio::task::yield_now().await;
                        }
                    }
                });
                
                send_handle.await.unwrap();
                recv_handle.await.unwrap();
            }
        });
    });
    
    group.finish();
}

/// Benchmark state management
fn benchmark_state_management(c: &mut Criterion) {
    let manager = Arc::new(StateManager::new());
    
    let mut group = c.benchmark_group("state_management");
    
    // Pre-populate state
    for i in 0..10000 {
        manager.set(format!("key_{}", i), json!({"value": i})).unwrap();
    }
    
    // Benchmark get operation (cache miss)
    group.bench_function("get_cold", |b| {
        let mut i = 0;
        b.iter(|| {
            let key = format!("key_{}", i % 10000);
            i += 1;
            black_box(manager.get(&key))
        });
    });
    
    // Warm up cache
    for i in 0..100 {
        for _ in 0..20 {
            manager.get(&format!("key_{}", i));
        }
    }
    
    // Benchmark get operation (cache hit)
    group.bench_function("get_hot", |b| {
        let mut i = 0;
        b.iter(|| {
            let key = format!("key_{}", i % 100);
            i += 1;
            black_box(manager.get(&key))
        });
    });
    
    // Benchmark set operation
    group.bench_function("set", |b| {
        let mut i = 10000;
        b.iter(|| {
            let key = format!("new_key_{}", i);
            i += 1;
            black_box(manager.set(key, json!({"value": i})).unwrap())
        });
    });
    
    // Benchmark compare and swap
    let cas_key = "cas_key";
    let version = manager.set(cas_key.to_string(), json!({"v": 0})).unwrap();
    
    group.bench_function("compare_and_swap", |b| {
        let mut v = version;
        let mut i = 1;
        b.iter(|| {
            v = black_box(manager.compare_exchange(cas_key, v, json!({"v": i}, Ordering::Relaxed).is_ok()).unwrap());
            i += 1;
        });
    });
    
    group.finish();
}

/// Benchmark end-to-end integration
fn benchmark_integration(c: &mut Criterion) {
    let runtime = Runtime::new().unwrap();
    
    c.bench_function("end_to_end_request", |b| {
        b.to_async(&runtime).iter(|| async {
            // Create server
            let server = HighPerfMCPServer::new(100).unwrap();
            
            // Register handler that uses state and memory
            let state = Arc::new(StateManager::new());
            let memory = Arc::new(MemoryPool::new(10).unwrap());
            
            let state_clone = state.clone();
            let memory_clone = memory.clone();
            
            server.register_handler("process".to_string(), move |req| {
                // Simulate real processing
                let key = format!("req_{}", req.id);
                state_clone.set(key.clone(), req.params.clone()).unwrap();
                
                if let Some(data) = req.params.as_str() {
                    memory_clone.store_learning(key, data.as_bytes().to_vec()).unwrap();
                }
                
                Response {
                    id: req.id,
                    result: json!({"processed": true}),
                    error: None,
                    processing_time_us: 0,
                }
            });
            
            // Process request
            let request = Request {
                id: 1,
                method: "process".to_string(),
                params: json!("test data"),
                timestamp: 0,
            };
            
            black_box(server.process_request(request).await.unwrap())
        });
    });
}

criterion_group!(
    benches,
    benchmark_request_processing,
    benchmark_memory_allocation,
    benchmark_message_passing,
    benchmark_state_management,
    benchmark_integration
);

criterion_main!(benches);