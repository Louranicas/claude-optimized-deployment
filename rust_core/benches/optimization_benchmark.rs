use code_rust_core::lockfree_collections::{LockFreeQueue, LockFreeStack, MetricsCollector};
use code_rust_core::memory_mapped::{search_files_parallel, MemoryMappedCache};
use code_rust_core::performance::BufferPool;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn bench_lockfree_queue(c: &mut Criterion) {
    let mut group = c.benchmark_group("lockfree_queue");

    for num_threads in [1, 2, 4, 8].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(num_threads),
            num_threads,
            |b, &num_threads| {
                b.iter(|| {
                    let queue = Arc::new(LockFreeQueue::new(None));
                    let mut handles = vec![];

                    for _ in 0..num_threads {
                        let queue_clone = Arc::clone(&queue);
                        let handle = thread::spawn(move || {
                            for i in 0..1000 {
                                queue_clone.push(format!("item-{}", i)).unwrap();
                            }
                        });
                        handles.push(handle);
                    }

                    for handle in handles {
                        handle.join().unwrap();
                    }

                    black_box(queue);
                });
            },
        );
    }

    group.finish();
}

fn bench_metrics_collector(c: &mut Criterion) {
    let mut group = c.benchmark_group("metrics_collector");

    group.bench_function("increment_counter", |b| {
        let collector = MetricsCollector::new();
        b.iter(|| {
            for i in 0..1000 {
                collector
                    .increment(format!("counter-{}", i % 10), Some(1))
                    .unwrap();
            }
        });
    });

    group.bench_function("set_gauge", |b| {
        let collector = MetricsCollector::new();
        b.iter(|| {
            for i in 0..1000 {
                collector.set_gauge(format!("gauge-{}", i % 10), i).unwrap();
            }
        });
    });

    group.finish();
}

fn bench_buffer_pool(c: &mut Criterion) {
    let mut group = c.benchmark_group("buffer_pool");

    group.bench_function("with_pool", |b| {
        let pool = BufferPool::new(1024, 100);
        b.iter(|| {
            let mut buffer = pool.acquire();
            buffer.extend_from_slice(b"Hello, World!");
            black_box(&buffer);
            pool.release(buffer);
        });
    });

    group.bench_function("without_pool", |b| {
        b.iter(|| {
            let mut buffer = Vec::with_capacity(1024);
            buffer.extend_from_slice(b"Hello, World!");
            black_box(&buffer);
        });
    });

    group.finish();
}

fn bench_parallel_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("parallel_operations");

    // Simulate parallel workload
    group.bench_function("rayon_parallel", |b| {
        use rayon::prelude::*;
        let data: Vec<i32> = (0..10000).collect();

        b.iter(|| {
            let sum: i32 = data.par_iter().map(|x| x * x).sum();
            black_box(sum);
        });
    });

    group.bench_function("sequential", |b| {
        let data: Vec<i32> = (0..10000).collect();

        b.iter(|| {
            let sum: i32 = data.iter().map(|x| x * x).sum();
            black_box(sum);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_lockfree_queue,
    bench_metrics_collector,
    bench_buffer_pool,
    bench_parallel_operations
);
criterion_main!(benches);
