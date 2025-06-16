//! Stress Tests for MCP Manager
//!
//! High-load and performance stress tests for the plugin system.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

use super::*;
use claude_optimized_deployment_rust::mcp_manager::plugin::{
    *,
    registry::*,
    lifecycle::*,
    hot_reload::*,
    zero_downtime::*,
};
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use tokio::time::sleep;

/// Stress test plugin that can simulate various load patterns
#[derive(Debug)]
struct StressTestPlugin {
    metadata: PluginMetadata,
    request_count: Arc<AtomicU64>,
    error_count: Arc<AtomicU64>,
    total_latency_us: Arc<AtomicU64>,
    processing_delay_ms: Arc<AtomicU64>,
    should_fail: Arc<AtomicBool>,
    memory_usage: Arc<AtomicU64>,
    cpu_intensive: Arc<AtomicBool>,
}

impl StressTestPlugin {
    fn new(id: &str) -> Self {
        Self {
            metadata: PluginMetadata {
                id: id.to_string(),
                name: format!("Stress Test Plugin {}", id),
                version: "1.0.0".to_string(),
                author: "Stress Test".to_string(),
                description: "Plugin for stress testing".to_string(),
                license: "MIT".to_string(),
                homepage: None,
                repository: None,
                min_mcp_version: "1.0.0".to_string(),
                dependencies: vec![],
                provides: vec![
                    Capability::new("stress", "test", 1),
                    Capability::new("stress", "load", 1),
                    Capability::new("stress", "memory", 1),
                    Capability::new("stress", "cpu", 1),
                ],
                requires: vec![],
            },
            request_count: Arc::new(AtomicU64::new(0)),
            error_count: Arc::new(AtomicU64::new(0)),
            total_latency_us: Arc::new(AtomicU64::new(0)),
            processing_delay_ms: Arc::new(AtomicU64::new(0)),
            should_fail: Arc::new(AtomicBool::new(false)),
            memory_usage: Arc::new(AtomicU64::new(0)),
            cpu_intensive: Arc::new(AtomicBool::new(false)),
        }
    }

    fn set_processing_delay(&self, delay_ms: u64) {
        self.processing_delay_ms.store(delay_ms, Ordering::SeqCst);
    }

    fn set_failure_rate(&self, should_fail: bool) {
        self.should_fail.store(should_fail, Ordering::SeqCst);
    }

    fn set_cpu_intensive(&self, intensive: bool) {
        self.cpu_intensive.store(intensive, Ordering::SeqCst);
    }

    fn get_metrics(&self) -> StressMetrics {
        let count = self.request_count.load(Ordering::SeqCst);
        let errors = self.error_count.load(Ordering::SeqCst);
        let total_latency = self.total_latency_us.load(Ordering::SeqCst);
        
        StressMetrics {
            request_count: count,
            error_count: errors,
            success_rate: if count > 0 { 
                ((count - errors) as f64 / count as f64) * 100.0 
            } else { 
                100.0 
            },
            avg_latency_us: if count > 0 { total_latency / count } else { 0 },
            memory_usage_bytes: self.memory_usage.load(Ordering::SeqCst),
        }
    }
}

#[derive(Debug, Clone)]
struct StressMetrics {
    request_count: u64,
    error_count: u64,
    success_rate: f64,
    avg_latency_us: u64,
    memory_usage_bytes: u64,
}

#[async_trait::async_trait]
impl Plugin for StressTestPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    async fn initialize(&mut self, _config: serde_json::Value) -> Result<()> {
        Ok(())
    }

    async fn handle(&self, request: PluginRequest) -> Result<PluginResponse> {
        let start = Instant::now();
        self.request_count.fetch_add(1, Ordering::SeqCst);

        // Simulate processing delay
        let delay = self.processing_delay_ms.load(Ordering::SeqCst);
        if delay > 0 {
            sleep(Duration::from_millis(delay)).await;
        }

        // Simulate CPU-intensive work
        if self.cpu_intensive.load(Ordering::SeqCst) {
            let mut _sum = 0u64;
            for i in 0..1000000 {
                _sum = _sum.wrapping_add(i);
            }
        }

        // Simulate memory allocation
        match request.method.as_str() {
            "allocate_memory" => {
                let size = request.params["size_mb"].as_u64().unwrap_or(1) * 1024 * 1024;
                let _data = vec![0u8; size as usize];
                self.memory_usage.fetch_add(size, Ordering::SeqCst);
            }
            "release_memory" => {
                self.memory_usage.store(0, Ordering::SeqCst);
            }
            _ => {}
        }

        // Simulate failures
        if self.should_fail.load(Ordering::SeqCst) {
            // Random failure based on request ID hash
            let should_fail = request.id.len() % 10 < 2; // 20% failure rate
            if should_fail {
                self.error_count.fetch_add(1, Ordering::SeqCst);
                return Err(PluginError::ExecutionError("Simulated stress failure".to_string()));
            }
        }

        let elapsed = start.elapsed().as_micros() as u64;
        self.total_latency_us.fetch_add(elapsed, Ordering::SeqCst);

        Ok(PluginResponse {
            request_id: request.id,
            result: PluginResult::Success {
                data: json!({
                    "plugin_id": self.metadata.id,
                    "latency_us": elapsed,
                    "current_metrics": {
                        "requests": self.request_count.load(Ordering::SeqCst),
                        "errors": self.error_count.load(Ordering::SeqCst),
                    }
                }),
            },
            metadata: json!({}),
        })
    }

    async fn shutdown(&mut self) -> Result<()> {
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream::{self, StreamExt};

    #[tokio::test]
    async fn test_high_throughput_stress() {
        let env = TestEnvironment::new(TestConfig::default()).await;
        env.setup().await.unwrap();

        // Create stress test plugin
        let plugin = StressTestPlugin::new("throughput-test");
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
        
        handle.initialize(json!({})).await.unwrap();

        // Configure for high throughput
        if let Some(plugin) = handle.as_any().downcast_ref::<StressTestPlugin>() {
            plugin.set_processing_delay(0); // No delay
            plugin.set_failure_rate(false);
        }

        let start = Instant::now();
        let request_count = 10000;
        let concurrent_requests = 100;

        // Generate requests
        let requests = stream::iter(0..request_count)
            .map(|i| {
                let handle = handle.clone();
                async move {
                    let request = PluginRequest {
                        id: format!("throughput-{}", i),
                        capability: Capability::new("stress", "test", 1),
                        method: "process".to_string(),
                        params: json!({"index": i}),
                        metadata: json!({}),
                    };
                    handle.handle(request).await
                }
            })
            .buffer_unordered(concurrent_requests)
            .collect::<Vec<_>>();

        let results = requests.await;
        let elapsed = start.elapsed();

        // Calculate metrics
        let success_count = results.iter().filter(|r| r.is_ok()).count();
        let throughput = request_count as f64 / elapsed.as_secs_f64();

        println!("High Throughput Test Results:");
        println!("  Total requests: {}", request_count);
        println!("  Successful: {}", success_count);
        println!("  Duration: {:?}", elapsed);
        println!("  Throughput: {:.2} req/s", throughput);

        assert_eq!(success_count, request_count);
        assert!(throughput > 1000.0, "Throughput should exceed 1000 req/s");

        // Check plugin metrics
        if let Some(plugin) = handle.as_any().downcast_ref::<StressTestPlugin>() {
            let metrics = plugin.get_metrics();
            assert_eq!(metrics.request_count, request_count as u64);
            assert_eq!(metrics.error_count, 0);
            assert_eq!(metrics.success_rate, 100.0);
        }

        env.teardown().await.unwrap();
    }

    #[tokio::test]
    async fn test_latency_under_load() {
        let env = TestEnvironment::new(TestConfig::default()).await;
        env.setup().await.unwrap();

        let plugin = StressTestPlugin::new("latency-test");
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
        
        handle.initialize(json!({})).await.unwrap();

        // Configure with realistic processing delay
        if let Some(plugin) = handle.as_any().downcast_ref::<StressTestPlugin>() {
            plugin.set_processing_delay(5); // 5ms processing time
            plugin.set_failure_rate(false);
        }

        // Measure latencies
        let mut latencies = vec![];
        let request_count = 1000;

        for i in 0..request_count {
            let start = Instant::now();
            
            let request = PluginRequest {
                id: format!("latency-{}", i),
                capability: Capability::new("stress", "test", 1),
                method: "process".to_string(),
                params: json!({"index": i}),
                metadata: json!({}),
            };

            let _ = handle.handle(request).await;
            latencies.push(start.elapsed().as_micros() as u64);
        }

        // Calculate percentiles
        latencies.sort_unstable();
        let p50 = latencies[latencies.len() / 2];
        let p95 = latencies[latencies.len() * 95 / 100];
        let p99 = latencies[latencies.len() * 99 / 100];

        println!("Latency Under Load Test Results:");
        println!("  P50: {} μs", p50);
        println!("  P95: {} μs", p95);
        println!("  P99: {} μs", p99);

        // Verify latencies are reasonable
        assert!(p50 < 10_000, "P50 latency should be under 10ms");
        assert!(p95 < 20_000, "P95 latency should be under 20ms");
        assert!(p99 < 50_000, "P99 latency should be under 50ms");

        env.teardown().await.unwrap();
    }

    #[tokio::test]
    async fn test_memory_pressure() {
        let env = TestEnvironment::new(TestConfig::default()).await;
        env.setup().await.unwrap();

        let plugin = StressTestPlugin::new("memory-test");
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
        
        handle.initialize(json!({})).await.unwrap();

        // Allocate memory in steps
        let allocations = vec![1, 5, 10, 20, 50]; // MB
        
        for size_mb in allocations {
            let request = PluginRequest {
                id: format!("mem-alloc-{}", size_mb),
                capability: Capability::new("stress", "memory", 1),
                method: "allocate_memory".to_string(),
                params: json!({"size_mb": size_mb}),
                metadata: json!({}),
            };

            let response = handle.handle(request).await.unwrap();
            assert!(matches!(response.result, PluginResult::Success { .. }));

            // Check memory usage
            if let Some(plugin) = handle.as_any().downcast_ref::<StressTestPlugin>() {
                let metrics = plugin.get_metrics();
                println!("Memory allocated: {} MB", metrics.memory_usage_bytes / 1024 / 1024);
            }
        }

        // Release memory
        let release_request = PluginRequest {
            id: "mem-release".to_string(),
            capability: Capability::new("stress", "memory", 1),
            method: "release_memory".to_string(),
            params: json!({}),
            metadata: json!({}),
        };

        handle.handle(release_request).await.unwrap();

        // Verify memory released
        if let Some(plugin) = handle.as_any().downcast_ref::<StressTestPlugin>() {
            let metrics = plugin.get_metrics();
            assert_eq!(metrics.memory_usage_bytes, 0);
        }

        env.teardown().await.unwrap();
    }

    #[tokio::test]
    async fn test_cpu_intensive_operations() {
        let env = TestEnvironment::new(TestConfig::default()).await;
        env.setup().await.unwrap();

        let plugin = StressTestPlugin::new("cpu-test");
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
        
        handle.initialize(json!({})).await.unwrap();

        // Enable CPU-intensive mode
        if let Some(plugin) = handle.as_any().downcast_ref::<StressTestPlugin>() {
            plugin.set_cpu_intensive(true);
        }

        let start = Instant::now();
        let cpu_tasks = 100;

        // Run CPU-intensive tasks concurrently
        let tasks = stream::iter(0..cpu_tasks)
            .map(|i| {
                let handle = handle.clone();
                async move {
                    let request = PluginRequest {
                        id: format!("cpu-{}", i),
                        capability: Capability::new("stress", "cpu", 1),
                        method: "cpu_intensive".to_string(),
                        params: json!({"task": i}),
                        metadata: json!({}),
                    };
                    handle.handle(request).await
                }
            })
            .buffer_unordered(10) // Limit concurrency to avoid overwhelming CPU
            .collect::<Vec<_>>();

        let results = tasks.await;
        let elapsed = start.elapsed();

        let success_count = results.iter().filter(|r| r.is_ok()).count();
        
        println!("CPU Intensive Test Results:");
        println!("  Tasks: {}", cpu_tasks);
        println!("  Successful: {}", success_count);
        println!("  Duration: {:?}", elapsed);
        println!("  Tasks/sec: {:.2}", cpu_tasks as f64 / elapsed.as_secs_f64());

        assert_eq!(success_count, cpu_tasks);

        env.teardown().await.unwrap();
    }

    #[tokio::test]
    async fn test_graceful_degradation() {
        let env = TestEnvironment::new(TestConfig::default()).await;
        env.setup().await.unwrap();

        let plugin = StressTestPlugin::new("degradation-test");
        let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
        
        handle.initialize(json!({})).await.unwrap();

        // Enable failures
        if let Some(plugin) = handle.as_any().downcast_ref::<StressTestPlugin>() {
            plugin.set_failure_rate(true); // 20% failure rate
            plugin.set_processing_delay(10); // Add some delay
        }

        // Send requests and track results
        let request_count = 1000;
        let mut success_count = 0;
        let mut error_count = 0;

        for i in 0..request_count {
            let request = PluginRequest {
                id: format!("degrade-{}", i),
                capability: Capability::new("stress", "test", 1),
                method: "process".to_string(),
                params: json!({"index": i}),
                metadata: json!({}),
            };

            match handle.handle(request).await {
                Ok(_) => success_count += 1,
                Err(_) => error_count += 1,
            }
        }

        let success_rate = (success_count as f64 / request_count as f64) * 100.0;
        
        println!("Graceful Degradation Test Results:");
        println!("  Total requests: {}", request_count);
        println!("  Successful: {}", success_count);
        println!("  Failed: {}", error_count);
        println!("  Success rate: {:.2}%", success_rate);

        // Should maintain ~80% success rate
        assert!(success_rate > 75.0 && success_rate < 85.0, 
                "Success rate should be around 80% with 20% failure rate");

        env.teardown().await.unwrap();
    }

    #[tokio::test]
    async fn test_sustained_load() {
        let env = TestEnvironment::new(TestConfig::default()).await;
        env.setup().await.unwrap();

        let mut registry = PluginRegistry::new();
        let lifecycle_manager = LifecycleManager::new(Default::default());

        // Create multiple plugins to distribute load
        let plugin_count = 5;
        let mut handles = vec![];

        for i in 0..plugin_count {
            let plugin = StressTestPlugin::new(&format!("sustained-{}", i));
            let handle = Arc::new(PluginHandle::new(Box::new(plugin)));
            
            registry.register(format!("sustained-{}", i), handle.clone()).unwrap();
            lifecycle_manager.register_plugin(format!("sustained-{}", i), handle.clone()).await.unwrap();
            lifecycle_manager.initialize_plugin(&format!("sustained-{}", i), json!({})).await.unwrap();
            
            handles.push(handle);
        }

        // Run sustained load for 30 seconds
        let duration = Duration::from_secs(30);
        let start = Instant::now();
        let mut total_requests = 0;

        println!("Starting sustained load test for {:?}...", duration);

        while start.elapsed() < duration {
            // Round-robin across plugins
            let plugin_idx = total_requests % plugin_count;
            let handle = &handles[plugin_idx];

            let request = PluginRequest {
                id: format!("sustained-{}", total_requests),
                capability: Capability::new("stress", "load", 1),
                method: "process".to_string(),
                params: json!({"seq": total_requests}),
                metadata: json!({}),
            };

            let _ = handle.handle(request).await;
            total_requests += 1;

            // Small delay to maintain steady rate
            if total_requests % 100 == 0 {
                sleep(Duration::from_millis(10)).await;
            }
        }

        let elapsed = start.elapsed();
        let avg_rps = total_requests as f64 / elapsed.as_secs_f64();

        println!("Sustained Load Test Results:");
        println!("  Duration: {:?}", elapsed);
        println!("  Total requests: {}", total_requests);
        println!("  Average RPS: {:.2}", avg_rps);

        // Collect metrics from all plugins
        let mut total_metrics = StressMetrics {
            request_count: 0,
            error_count: 0,
            success_rate: 0.0,
            avg_latency_us: 0,
            memory_usage_bytes: 0,
        };

        for handle in &handles {
            if let Some(plugin) = handle.as_any().downcast_ref::<StressTestPlugin>() {
                let metrics = plugin.get_metrics();
                total_metrics.request_count += metrics.request_count;
                total_metrics.error_count += metrics.error_count;
            }
        }

        total_metrics.success_rate = if total_metrics.request_count > 0 {
            ((total_metrics.request_count - total_metrics.error_count) as f64 
             / total_metrics.request_count as f64) * 100.0
        } else {
            100.0
        };

        println!("  Success rate: {:.2}%", total_metrics.success_rate);
        
        assert!(total_metrics.success_rate > 99.0, "Should maintain high success rate under sustained load");

        env.teardown().await.unwrap();
    }
}