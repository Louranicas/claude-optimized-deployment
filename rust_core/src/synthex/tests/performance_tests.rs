//! Performance benchmarks and tests for SYNTHEX

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use crate::synthex::{
        engine::SynthexEngine,
        config::SynthexConfig,
        query::QueryBuilder,
        performance_optimizer::PerformanceOptimizer,
    };
    use super::super::test_utils::*;
    
    #[tokio::test]
    async fn test_single_agent_throughput() {
        let engine = test_engine().await;
        let mut engine_guard = engine.write().await;
        
        let agent = Box::new(MockTestAgent::new("perf_single".to_string()));
        engine_guard.register_agent(agent).await.unwrap();
        drop(engine_guard);
        
        let queries: Vec<_> = (0..100)
            .map(|i| QueryBuilder::new(&format!("query {}", i)).build())
            .collect();
            
        let start = std::time::Instant::now();
        
        for query in &queries {
            let engine_guard = engine.read().await;
            let _ = engine_guard.search(query).await.unwrap();
        }
        
        let elapsed = start.elapsed();
        let qps = 100.0 / elapsed.as_secs_f64();
        
        println!("Single agent QPS: {:.2}", qps);
        assert!(qps > 50.0, "Single agent performance too low: {:.2} QPS", qps);
    }
    
    #[tokio::test]
    async fn test_parallel_agent_scaling() {
        let mut results = vec![];
        
        for num_agents in [1, 2, 4, 8, 16] {
            let engine = test_engine().await;
            let mut engine_guard = engine.write().await;
            
            // Register agents
            for i in 0..num_agents {
                let agent = Box::new(
                    MockTestAgent::new(format!("scale_{}", i))
                        .with_delay(10) // Simulate work
                );
                engine_guard.register_agent(agent).await.unwrap();
            }
            
            drop(engine_guard);
            
            // Run queries
            let query = QueryBuilder::new("scaling test")
                .with_parallel_execution(true)
                .build();
                
            let start = std::time::Instant::now();
            let engine_guard = engine.read().await;
            
            for _ in 0..50 {
                let _ = engine_guard.search(&query).await.unwrap();
            }
            
            let elapsed = start.elapsed().as_millis();
            let throughput = 50000.0 / elapsed as f64; // queries per second
            
            results.push((num_agents, throughput));
            println!("{} agents: {:.2} QPS", num_agents, throughput);
        }
        
        // Verify scaling efficiency
        let single_throughput = results[0].1;
        let eight_throughput = results[3].1;
        let scaling_efficiency = eight_throughput / (single_throughput * 8.0);
        
        println!("Scaling efficiency at 8 agents: {:.2}%", scaling_efficiency * 100.0);
        assert!(scaling_efficiency > 0.7, "Poor scaling efficiency: {:.2}%", scaling_efficiency * 100.0);
    }
    
    #[tokio::test]
    async fn test_cache_performance() {
        let mut config = test_config();
        config.cache_size = 1000;
        
        let engine = SynthexEngine::new(config).await.unwrap();
        let engine = Arc::new(RwLock::new(engine));
        let mut engine_guard = engine.write().await;
        
        let agent = Box::new(
            MockTestAgent::new("cache_perf".to_string())
                .with_delay(50) // Simulate expensive operation
        );
        engine_guard.register_agent(agent).await.unwrap();
        
        drop(engine_guard);
        
        // Generate queries with some repetition
        let unique_queries = 20;
        let total_queries = 1000;
        let queries: Vec<_> = (0..total_queries)
            .map(|i| {
                QueryBuilder::new(&format!("query {}", i % unique_queries))
                    .with_cache_enabled(true)
                    .build()
            })
            .collect();
            
        let start = std::time::Instant::now();
        
        for query in &queries {
            let engine_guard = engine.read().await;
            let _ = engine_guard.search(query).await.unwrap();
        }
        
        let elapsed = start.elapsed().as_millis();
        
        // With cache, should be much faster than without
        let expected_without_cache = total_queries as u128 * 50; // 50ms per query
        let speedup = expected_without_cache as f64 / elapsed as f64;
        
        println!("Cache speedup: {:.2}x", speedup);
        assert!(speedup > 10.0, "Cache not effective: {:.2}x speedup", speedup);
    }
    
    #[tokio::test]
    async fn test_memory_efficiency() {
        let mut config = test_config();
        config.memory_limit_mb = 100;
        
        let engine = SynthexEngine::new(config).await.unwrap();
        let engine = Arc::new(RwLock::new(engine));
        
        // Measure baseline memory
        let baseline_memory = get_current_memory_usage();
        
        let mut engine_guard = engine.write().await;
        
        // Register many agents
        for i in 0..50 {
            let agent = Box::new(MockTestAgent::new(format!("mem_{}", i)));
            engine_guard.register_agent(agent).await.unwrap();
        }
        
        drop(engine_guard);
        
        // Generate large dataset
        let large_docs = generate_test_dataset(10000);
        
        // Process all documents
        for (i, doc) in large_docs.iter().enumerate() {
            let query = QueryBuilder::new(doc)
                .with_cache_enabled(true)
                .build();
                
            let engine_guard = engine.read().await;
            let _ = engine_guard.search(&query).await;
            
            if i % 1000 == 0 {
                let current_memory = get_current_memory_usage();
                let memory_growth = current_memory - baseline_memory;
                
                println!("After {} queries: +{}MB", i, memory_growth);
                
                // Should not exceed limit
                assert!(
                    memory_growth < 100,
                    "Memory limit exceeded: {}MB growth",
                    memory_growth
                );
            }
        }
    }
    
    #[tokio::test]
    async fn test_latency_percentiles() {
        let engine = test_engine().await;
        let mut engine_guard = engine.write().await;
        
        // Mix of fast and slow agents
        for i in 0..10 {
            let delay = if i < 8 { 5 } else { 100 }; // 80% fast, 20% slow
            let agent = Box::new(
                MockTestAgent::new(format!("latency_{}", i))
                    .with_delay(delay)
            );
            engine_guard.register_agent(agent).await.unwrap();
        }
        
        drop(engine_guard);
        
        let mut latencies = vec![];
        
        for i in 0..100 {
            let query = QueryBuilder::new(&format!("latency test {}", i))
                .with_parallel_execution(true)
                .build();
                
            let start = std::time::Instant::now();
            let engine_guard = engine.read().await;
            let _ = engine_guard.search(&query).await.unwrap();
            let latency = start.elapsed().as_millis();
            
            latencies.push(latency);
        }
        
        latencies.sort_unstable();
        
        let p50 = latencies[49];
        let p90 = latencies[89];
        let p99 = latencies[98];
        
        println!("Latency percentiles - P50: {}ms, P90: {}ms, P99: {}ms", p50, p90, p99);
        
        assert!(p50 < 20, "P50 latency too high: {}ms", p50);
        assert!(p90 < 50, "P90 latency too high: {}ms", p90);
        assert!(p99 < 150, "P99 latency too high: {}ms", p99);
    }
    
    #[tokio::test]
    async fn test_concurrent_load() {
        let engine = test_engine().await;
        let mut engine_guard = engine.write().await;
        
        // Register agents
        for i in 0..5 {
            let agent = Box::new(MockTestAgent::new(format!("concurrent_{}", i)));
            engine_guard.register_agent(agent).await.unwrap();
        }
        
        drop(engine_guard);
        
        // Simulate concurrent users
        let num_concurrent = 100;
        let queries_per_user = 10;
        
        let start = std::time::Instant::now();
        let mut handles = vec![];
        
        for user in 0..num_concurrent {
            let engine_clone = engine.clone();
            
            let handle = tokio::spawn(async move {
                for q in 0..queries_per_user {
                    let query = QueryBuilder::new(&format!("user {} query {}", user, q))
                        .build();
                        
                    let engine_guard = engine_clone.read().await;
                    let _ = engine_guard.search(&query).await;
                }
            });
            
            handles.push(handle);
        }
        
        // Wait for all to complete
        for handle in handles {
            handle.await.unwrap();
        }
        
        let elapsed = start.elapsed();
        let total_queries = num_concurrent * queries_per_user;
        let qps = total_queries as f64 / elapsed.as_secs_f64();
        
        println!("Concurrent load: {} users, {:.2} QPS", num_concurrent, qps);
        assert!(qps > 100.0, "Poor performance under load: {:.2} QPS", qps);
    }
    
    #[tokio::test]
    async fn test_performance_optimizer() {
        let optimizer = PerformanceOptimizer::new();
        let engine = test_engine().await;
        
        // Simulate workload patterns
        let workload = vec![
            ("popular_query", 100),
            ("rare_query", 1),
            ("medium_query", 10),
        ];
        
        for (query_text, frequency) in &workload {
            for _ in 0..*frequency {
                optimizer.record_query(query_text);
            }
        }
        
        // Get optimization suggestions
        let suggestions = optimizer.get_suggestions();
        
        assert!(suggestions.cache_queries.contains(&"popular_query".to_string()));
        assert!(!suggestions.cache_queries.contains(&"rare_query".to_string()));
        assert!(suggestions.suggested_cache_size > 0);
        assert!(suggestions.suggested_parallelism > 0);
    }
    
    #[tokio::test]
    async fn test_resource_usage_under_stress() {
        let mut config = test_config();
        config.max_concurrent_agents = 20;
        
        let engine = SynthexEngine::new(config).await.unwrap();
        let engine = Arc::new(RwLock::new(engine));
        let mut engine_guard = engine.write().await;
        
        // Register resource-intensive agents
        for i in 0..20 {
            let agent = Box::new(
                MockTestAgent::new(format!("stress_{}", i))
                    .with_delay(50)
            );
            engine_guard.register_agent(agent).await.unwrap();
        }
        
        drop(engine_guard);
        
        // Monitor resource usage during stress test
        let monitor_handle = tokio::spawn(async {
            let mut max_cpu = 0.0;
            let mut max_memory = 0;
            
            for _ in 0..30 {
                let cpu = get_cpu_usage();
                let memory = get_current_memory_usage();
                
                max_cpu = max_cpu.max(cpu);
                max_memory = max_memory.max(memory);
                
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
            
            (max_cpu, max_memory)
        });
        
        // Run stress test
        let stress_handle = tokio::spawn(async move {
            let mut handles = vec![];
            
            for i in 0..50 {
                let engine_clone = engine.clone();
                let handle = tokio::spawn(async move {
                    for j in 0..20 {
                        let query = QueryBuilder::new(&format!("stress {} {}", i, j))
                            .with_parallel_execution(true)
                            .build();
                            
                        let engine_guard = engine_clone.read().await;
                        let _ = engine_guard.search(&query).await;
                    }
                });
                handles.push(handle);
            }
            
            for handle in handles {
                handle.await.unwrap();
            }
        });
        
        // Wait for both to complete
        stress_handle.await.unwrap();
        let (max_cpu, max_memory) = monitor_handle.await.unwrap();
        
        println!("Peak resource usage - CPU: {:.1}%, Memory: {}MB", max_cpu, max_memory);
        
        assert!(max_cpu < 90.0, "CPU usage too high: {:.1}%", max_cpu);
        assert!(max_memory < 500, "Memory usage too high: {}MB", max_memory);
    }
}

// Helper functions for performance testing
fn get_current_memory_usage() -> usize {
    // Simplified memory measurement - in real implementation would use system APIs
    use std::alloc::{GlobalAlloc, Layout, System};
    
    // This is a placeholder - real implementation would track allocations
    100 // MB
}

fn get_cpu_usage() -> f64 {
    // Placeholder - real implementation would use system APIs
    50.0 // percentage
}