use claude_optimized_deployment_rust::synthex::performance_optimizer::*;
use claude_optimized_deployment_rust::synthex::*;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::collections::HashMap;
use std::time::Duration;
use tokio::runtime::Runtime;

// Baseline sequential bash command execution simulator
fn baseline_sequential_execution(commands: &[String]) -> Vec<String> {
    commands
        .iter()
        .map(|cmd| {
            // Simulate command execution time
            std::thread::sleep(Duration::from_micros(100));
            format!("Result: {}", cmd)
        })
        .collect()
}

// Optimized parallel execution with all features
async fn optimized_execution(executor: &OptimizedExecutor, commands: Vec<String>) -> Vec<String> {
    let tasks: Vec<CommandTask> = commands
        .into_iter()
        .enumerate()
        .map(|(i, cmd)| CommandTask {
            id: format!("task_{}", i),
            command: cmd,
            context: HashMap::new(),
            priority: 1,
        })
        .collect();

    let results = executor.execute_optimized(tasks).await;
    results
        .into_iter()
        .map(|r| r.unwrap_or_else(|e| format!("Error: {}", e)))
        .collect()
}

fn bench_command_execution(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Create test commands
    let command_counts = vec![10, 100, 1000, 10000];

    for count in command_counts {
        let commands: Vec<String> = (0..count)
            .map(|i| {
                format!(
                    "find /path -name 'file{}*.txt' | grep pattern{} | sort",
                    i, i
                )
            })
            .collect();

        let mut group = c.benchmark_group("command_execution");
        group.sample_size(10);

        // Benchmark baseline sequential execution
        group.bench_with_input(
            BenchmarkId::new("sequential", count),
            &commands,
            |b, cmds| b.iter(|| baseline_sequential_execution(black_box(cmds))),
        );

        // Benchmark optimized execution
        let config = PerformanceConfig {
            worker_threads: num_cpus::get(),
            queue_size: 100_000,
            l1_cache_size: 10_000,
            l3_cache_path: None,
            patterns: vec![
                ("find".to_string(), 0.9),
                ("grep".to_string(), 0.9),
                ("sort".to_string(), 0.8),
            ],
        };

        let executor = rt.block_on(async { OptimizedExecutor::new(config).unwrap() });

        group.bench_with_input(
            BenchmarkId::new("optimized", count),
            &commands,
            |b, cmds| {
                b.to_async(&rt)
                    .iter(|| optimized_execution(&executor, black_box(cmds.clone())))
            },
        );

        group.finish();
    }
}

fn bench_pattern_matching(c: &mut Criterion) {
    let patterns = vec![
        ("grep -E '(ERROR|WARN)' /var/log/".to_string(), 0.9),
        ("find . -name '*.rs' -type f".to_string(), 0.9),
        ("docker ps -a | grep running".to_string(), 0.8),
        ("ps aux | sort -k3 -nr | head".to_string(), 0.8),
    ];

    let matcher = SimdPatternMatcher::new(patterns);
    let test_texts = vec![
        "grep -E '(ERROR|WARN)' /var/log/syslog | tail -n 100",
        "find . -name '*.rs' -type f -exec grep TODO {} \\;",
        "docker ps -a | grep running | awk '{print $1}'",
        "ps aux | sort -k3 -nr | head -20",
    ];

    let mut group = c.benchmark_group("pattern_matching");

    // Benchmark scalar matching
    group.bench_function("scalar", |b| {
        b.iter(|| {
            for text in &test_texts {
                let _ = matcher.match_scalar(black_box(text.as_bytes()));
            }
        })
    });

    // Benchmark SIMD matching
    #[cfg(feature = "simd")]
    group.bench_function("simd", |b| {
        b.iter(|| {
            for text in &test_texts {
                let _ = matcher.match_simd(black_box(text.as_bytes()));
            }
        })
    });

    group.finish();
}

fn bench_cache_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let cache = rt.block_on(async { TieredCache::new(1000, None).unwrap() });

    let mut group = c.benchmark_group("cache_operations");

    // Pre-populate cache
    for i in 0..500 {
        cache.put(
            format!("key_{}", i),
            bytes::Bytes::from(format!("value_{}", i)),
        );
    }

    // Benchmark cache hits
    group.bench_function("cache_hit", |b| {
        b.iter(|| {
            for i in 0..100 {
                let _ = cache.get(black_box(&format!("key_{}", i)));
            }
        })
    });

    // Benchmark cache misses
    group.bench_function("cache_miss", |b| {
        b.iter(|| {
            for i in 1000..1100 {
                let _ = cache.get(black_box(&format!("key_{}", i)));
            }
        })
    });

    // Benchmark cache puts
    group.bench_function("cache_put", |b| {
        let mut counter = 0;
        b.iter(|| {
            cache.put(
                format!("new_key_{}", counter),
                bytes::Bytes::from(format!("new_value_{}", counter)),
            );
            counter += 1;
        })
    });

    group.finish();
}

fn bench_lock_free_vs_mutex(c: &mut Criterion) {
    use dashmap::DashMap;
    use std::sync::Mutex;

    let mut group = c.benchmark_group("concurrency");
    group.sample_size(10);

    // Lock-free queue
    let lock_free_queue = LockFreeCommandQueue::new(10000);

    // Mutex-based queue for comparison
    let mutex_queue: Arc<Mutex<Vec<CommandTask>>> = Arc::new(Mutex::new(Vec::new()));

    // DashMap (lock-free)
    let dashmap: Arc<DashMap<String, String>> = Arc::new(DashMap::new());

    // Standard HashMap with Mutex
    let mutex_map: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));

    // Benchmark lock-free queue operations
    group.bench_function("lock_free_queue", |b| {
        b.iter(|| {
            let task = CommandTask {
                id: "test".to_string(),
                command: "echo test".to_string(),
                context: HashMap::new(),
                priority: 1,
            };

            for _ in 0..100 {
                let _ = lock_free_queue.push(task.clone());
                let _ = lock_free_queue.pop();
            }
        })
    });

    // Benchmark mutex queue operations
    group.bench_function("mutex_queue", |b| {
        b.iter(|| {
            let task = CommandTask {
                id: "test".to_string(),
                command: "echo test".to_string(),
                context: HashMap::new(),
                priority: 1,
            };

            for _ in 0..100 {
                mutex_queue.lock().expect("Failed to acquire lock").push(task.clone());
                mutex_queue.lock().expect("Failed to acquire lock").pop();
            }
        })
    });

    // Benchmark DashMap operations
    group.bench_function("dashmap", |b| {
        b.iter(|| {
            for i in 0..100 {
                dashmap.insert(format!("key_{}", i), format!("value_{}", i));
                let _ = dashmap.get(&format!("key_{}", i));
            }
        })
    });

    // Benchmark Mutex HashMap operations
    group.bench_function("mutex_hashmap", |b| {
        b.iter(|| {
            for i in 0..100 {
                mutex_map
                    .lock()
                    .unwrap()
                    .insert(format!("key_{}", i), format!("value_{}", i));
                let _ = mutex_map.lock().expect("Failed to acquire lock").get(&format!("key_{}", i));
            }
        })
    });

    group.finish();
}

fn bench_memory_allocation(c: &mut Criterion) {
    let pool_allocator = PoolAllocator::new();

    let mut group = c.benchmark_group("memory_allocation");

    // Benchmark small allocations
    group.bench_function("pool_small", |b| {
        b.iter(|| {
            let buf = pool_allocator.allocate(256);
            pool_allocator.deallocate(black_box(buf));
        })
    });

    group.bench_function("system_small", |b| {
        b.iter(|| {
            let buf = vec![0u8; 256];
            black_box(buf);
        })
    });

    // Benchmark medium allocations
    group.bench_function("pool_medium", |b| {
        b.iter(|| {
            let buf = pool_allocator.allocate(8192);
            pool_allocator.deallocate(black_box(buf));
        })
    });

    group.bench_function("system_medium", |b| {
        b.iter(|| {
            let buf = vec![0u8; 8192];
            black_box(buf);
        })
    });

    group.finish();
}

fn bench_zero_copy_strings(c: &mut Criterion) {
    let string_pool = ZeroCopyStringPool::new();

    let test_strings: Vec<String> = (0..1000)
        .map(|i| format!("test_string_{}_with_some_content", i))
        .collect();

    let mut group = c.benchmark_group("string_operations");

    // Benchmark string interning
    group.bench_function("intern_new", |b| {
        let mut counter = 0;
        b.iter(|| {
            let s = format!("dynamic_string_{}", counter);
            let _ = string_pool.intern(black_box(&s));
            counter += 1;
        })
    });

    // Benchmark string lookup (already interned)
    for s in &test_strings[..10] {
        string_pool.intern(s);
    }

    group.bench_function("intern_existing", |b| {
        b.iter(|| {
            for s in &test_strings[..10] {
                let _ = string_pool.intern(black_box(s));
            }
        })
    });

    group.finish();
}

// Performance improvement calculator
fn calculate_improvement(baseline_ns: f64, optimized_ns: f64) -> f64 {
    ((baseline_ns - optimized_ns) / baseline_ns) * 100.0
}

criterion_group!(
    benches,
    bench_command_execution,
    bench_pattern_matching,
    bench_cache_operations,
    bench_lock_free_vs_mutex,
    bench_memory_allocation,
    bench_zero_copy_strings
);

criterion_main!(benches);
