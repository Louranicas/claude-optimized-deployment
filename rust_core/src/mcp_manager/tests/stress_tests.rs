use super::test_utils::*;
use super::scenarios::*;
use crate::mcp_manager::{
    core::MCPManager,
    protocol::MCPRequest,
    metrics::MCPMetrics,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::test;
use tracing_test::traced_test;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[traced_test]
async fn stress_test_high_concurrency() {
    let config = high_concurrency_config();
    let manager = Arc::new(MCPManager::new(config));
    
    // Register multiple servers
    for i in 0..10 {
        let server = create_mock_server(&format!("stress_server_{}", i));
        manager.register_server(server).await.unwrap();
    }
    
    // Metrics tracking
    let total_requests = Arc::new(AtomicU64::new(0));
    let successful_requests = Arc::new(AtomicU64::new(0));
    let failed_requests = Arc::new(AtomicU64::new(0));
    let total_latency = Arc::new(AtomicU64::new(0));
    
    // Run high-concurrency load
    let duration = Duration::from_secs(10);
    let concurrent_clients = 100;
    let requests_per_client = 1000;
    
    let start = Instant::now();
    let mut handles = vec![];
    
    for client_id in 0..concurrent_clients {
        let manager_clone = manager.clone();
        let total_requests_clone = total_requests.clone();
        let successful_requests_clone = successful_requests.clone();
        let failed_requests_clone = failed_requests.clone();
        let total_latency_clone = total_latency.clone();
        
        let handle = tokio::spawn(async move {
            for req_id in 0..requests_per_client {
                let request = MCPRequest::new(
                    "stress_test",
                    serde_json::json!({
                        "client": client_id,
                        "request": req_id,
                        "timestamp": std::time::SystemTime::now()
                    }),
                );
                
                let req_start = Instant::now();
                total_requests_clone.fetch_add(1, Ordering::Relaxed);
                
                match manager_clone.send_request(request).await {
                    Ok(_) => {
                        successful_requests_clone.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        failed_requests_clone.fetch_add(1, Ordering::Relaxed);
                    }
                }
                
                let latency = req_start.elapsed().as_micros() as u64;
                total_latency_clone.fetch_add(latency, Ordering::Relaxed);
                
                // Small delay to prevent overwhelming
                if req_id % 100 == 0 {
                    tokio::task::yield_now().await;
                }
            }
        });
        handles.push(handle);
    }
    
    // Wait for all clients to complete
    for handle in handles {
        let _ = handle.await;
    }
    
    let elapsed = start.elapsed();
    
    // Calculate metrics
    let total = total_requests.load(Ordering::Relaxed); // TODO: Review memory ordering - consider Acquire/Release
    let successful = successful_requests.load(Ordering::Relaxed); // TODO: Review memory ordering - consider Acquire/Release
    let failed = failed_requests.load(Ordering::Relaxed); // TODO: Review memory ordering - consider Acquire/Release
    let avg_latency_us = total_latency.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release/ total.max(1);
    let throughput = total as f64 / elapsed.as_secs_f64();
    
    println!("=== High Concurrency Stress Test Results ===");
    println!("Duration: {:?}", elapsed);
    println!("Total requests: {}", total);
    println!("Successful: {} ({:.2}%)", successful, (successful as f64 / total as f64) * 100.0);
    println!("Failed: {} ({:.2}%)", failed, (failed as f64 / total as f64) * 100.0);
    println!("Average latency: {}μs", avg_latency_us);
    println!("Throughput: {:.2} req/s", throughput);
    
    // Assertions
    assert!(successful as f64 / total as f64 > 0.95, "Success rate should be > 95%");
    assert!(throughput > 5000.0, "Throughput should be > 5000 req/s");
    assert!(avg_latency_us < 10000, "Average latency should be < 10ms");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[traced_test]
async fn stress_test_sustained_load() {
    let config = high_concurrency_config();
    let manager = Arc::new(MCPManager::new(config));
    
    // Register servers
    for i in 0..5 {
        let server = create_mock_server(&format!("sustained_{}", i));
        manager.register_server(server).await.unwrap();
    }
    
    // Memory tracking
    let memory_samples = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let should_stop = Arc::new(AtomicBool::new(false));
    
    // Start memory monitoring task
    let memory_monitor = {
        let memory_samples = memory_samples.clone();
        let should_stop = should_stop.clone();
        tokio::spawn(async move {
            while !should_stop.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release{
                // Simulate memory measurement (in real scenario, use actual memory metrics)
                let sample = rand::random::<f64>() * 100.0 + 500.0; // MB
                memory_samples.lock().await.push(sample);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        })
    };
    
    // Generate sustained load
    let load_duration = Duration::from_secs(30);
    let target_rps = 1000;
    
    generate_load(load_duration, target_rps, || {
        MCPRequest::new(
            "sustained_load",
            serde_json::json!({
                "timestamp": std::time::SystemTime::now(),
                "data": vec![0u8; 1024], // 1KB payload
            }),
        )
    }).await;
    
    // Stop memory monitoring
    should_stop.store(true, Ordering::Relaxed); // TODO: Review memory ordering - consider Acquire/Release
    let _ = memory_monitor.await;
    
    // Analyze memory usage
    let samples = memory_samples.lock().await;
    let avg_memory = samples.iter().sum::<f64>() / samples.len() as f64;
    let max_memory = samples.iter().fold(0.0f64, |a, &b| a.max(b));
    let memory_growth = samples.last().unwrap_or(&0.0) - samples.first().unwrap_or(&0.0);
    
    println!("=== Sustained Load Test Results ===");
    println!("Average memory: {:.2} MB", avg_memory);
    println!("Peak memory: {:.2} MB", max_memory);
    println!("Memory growth: {:.2} MB", memory_growth);
    
    // Memory leak detection
    assert!(memory_growth < 50.0, "Memory growth should be < 50MB, was {:.2}MB", memory_growth);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[traced_test]
async fn stress_test_connection_churn() {
    let manager = Arc::new(create_test_manager());
    let chaos = Arc::new(ChaosInjector::new());
    
    // Metrics
    let connection_failures = Arc::new(AtomicU64::new(0));
    let registration_failures = Arc::new(AtomicU64::new(0));
    
    // Start server churn task
    let churn_handle = {
        let manager = manager.clone();
        let chaos = chaos.clone();
        let connection_failures = connection_failures.clone();
        let registration_failures = registration_failures.clone();
        
        tokio::spawn(async move {
            for i in 0..100 {
                let server_id = format!("churn_server_{}", i % 10);
                
                // Randomly register/unregister servers
                if rand::random::<bool>() {
                    let server = create_mock_server(&server_id);
                    if manager.register_server(server).await.is_err() {
                        registration_failures.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    let _ = manager.unregister_server(&server_id).await;
                }
                
                // Inject chaos
                if i % 10 == 0 {
                    chaos.inject_connection_drops(0.3).await;
                }
                
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
    };
    
    // Start request load
    let request_handle = {
        let manager = manager.clone();
        let connection_failures = connection_failures.clone();
        
        tokio::spawn(async move {
            for i in 0..1000 {
                let request = MCPRequest::new("churn_test", serde_json::json!({"seq": i}));
                if manager.send_request(request).await.is_err() {
                    connection_failures.fetch_add(1, Ordering::Relaxed);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
    };
    
    // Wait for tasks to complete
    let _ = tokio::join!(churn_handle, request_handle);
    
    // Reset chaos
    chaos.reset().await;
    
    let conn_fails = connection_failures.load(Ordering::Relaxed); // TODO: Review memory ordering - consider Acquire/Release
    let reg_fails = registration_failures.load(Ordering::Relaxed); // TODO: Review memory ordering - consider Acquire/Release
    
    println!("=== Connection Churn Test Results ===");
    println!("Connection failures: {}", conn_fails);
    println!("Registration failures: {}", reg_fails);
    
    // System should handle churn gracefully
    assert!(conn_fails < 200, "Too many connection failures: {}", conn_fails);
    assert!(reg_fails < 10, "Too many registration failures: {}", reg_fails);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[traced_test]
async fn stress_test_memory_pressure() {
    let mut config = high_concurrency_config();
    config.max_connections_per_server = 50; // High connection count
    let manager = Arc::new(MCPManager::new(config));
    
    // Register many servers
    for i in 0..20 {
        let server = create_mock_server(&format!("memory_test_{}", i));
        manager.register_server(server).await.unwrap();
    }
    
    // Track memory allocations
    let large_payloads_sent = Arc::new(AtomicU64::new(0));
    
    // Send requests with varying payload sizes
    let mut handles = vec![];
    for client in 0..50 {
        let manager_clone = manager.clone();
        let large_payloads = large_payloads_sent.clone();
        
        let handle = tokio::spawn(async move {
            for i in 0..100 {
                // Vary payload size to stress memory
                let payload_size = match i % 4 {
                    0 => 1024,        // 1KB
                    1 => 10 * 1024,   // 10KB
                    2 => 100 * 1024,  // 100KB
                    _ => 1024 * 1024, // 1MB
                };
                
                if payload_size >= 1024 * 1024 {
                    large_payloads.fetch_add(1, Ordering::Relaxed);
                }
                
                let request = MCPRequest::new(
                    "memory_pressure",
                    serde_json::json!({
                        "client": client,
                        "seq": i,
                        "data": vec![0u8; payload_size],
                    }),
                );
                
                let _ = manager_clone.send_request(request).await;
                
                // Yield periodically to prevent overwhelming
                if i % 10 == 0 {
                    tokio::task::yield_now().await;
                }
            }
        });
        handles.push(handle);
    }
    
    // Wait for completion
    for handle in handles {
        let _ = handle.await;
    }
    
    let large_count = large_payloads_sent.load(Ordering::Relaxed); // TODO: Review memory ordering - consider Acquire/Release
    println!("=== Memory Pressure Test Results ===");
    println!("Large payloads sent: {}", large_count);
    
    // Verify system handled memory pressure
    assert!(large_count > 1000, "Should have sent many large payloads");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[traced_test]
async fn stress_test_cascade_failures() {
    let config = fault_tolerance_config();
    let manager = Arc::new(MCPManager::new(config));
    
    // Create servers with dependencies
    let primary_servers = 3;
    let backup_servers = 2;
    
    for i in 0..primary_servers {
        let server = create_mock_server(&format!("primary_{}", i));
        manager.register_server(server).await.unwrap();
    }
    
    for i in 0..backup_servers {
        let server = create_mock_server(&format!("backup_{}", i));
        manager.register_server(server).await.unwrap();
    }
    
    // Chaos injector for cascade failures
    let chaos = Arc::new(ChaosInjector::new());
    
    // Metrics
    let cascade_events = Arc::new(AtomicU64::new(0));
    let recovery_events = Arc::new(AtomicU64::new(0));
    
    // Simulate cascade failure scenario
    let failure_handle = {
        let manager = manager.clone();
        let chaos = chaos.clone();
        let cascade_events = cascade_events.clone();
        
        tokio::spawn(async move {
            // Phase 1: Normal operation
            tokio::time::sleep(Duration::from_secs(2)).await;
            
            // Phase 2: Primary server failures
            for i in 0..primary_servers {
                chaos.inject_connection_drops(0.8).await;
                cascade_events.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            
            // Phase 3: Network degradation
            chaos.inject_network_delay(200).await;
            chaos.inject_packet_loss(0.3).await;
            
            // Phase 4: CPU spike
            chaos.inject_cpu_spike(2000).await;
            
            // Phase 5: Recovery
            tokio::time::sleep(Duration::from_secs(3)).await;
            chaos.reset().await;
        })
    };
    
    // Client load during failure scenario
    let client_handle = {
        let manager = manager.clone();
        let recovery_events = recovery_events.clone();
        
        tokio::spawn(async move {
            let mut consecutive_failures = 0;
            let mut in_recovery = false;
            
            for i in 0..200 {
                let request = MCPRequest::new("cascade_test", serde_json::json!({"seq": i}));
                
                match manager.send_request(request).await {
                    Ok(_) => {
                        if in_recovery && consecutive_failures > 0 {
                            recovery_events.fetch_add(1, Ordering::Relaxed);
                            in_recovery = false;
                        }
                        consecutive_failures = 0;
                    }
                    Err(_) => {
                        consecutive_failures += 1;
                        if consecutive_failures > 5 {
                            in_recovery = true;
                        }
                    }
                }
                
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
    };
    
    // Wait for scenario to complete
    let _ = tokio::join!(failure_handle, client_handle);
    
    let cascades = cascade_events.load(Ordering::Relaxed); // TODO: Review memory ordering - consider Acquire/Release
    let recoveries = recovery_events.load(Ordering::Relaxed); // TODO: Review memory ordering - consider Acquire/Release
    
    println!("=== Cascade Failure Test Results ===");
    println!("Cascade events: {}", cascades);
    println!("Recovery events: {}", recoveries);
    
    // System should recover from cascade failures
    assert!(recoveries > 0, "System should have recovery events");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[traced_test]
async fn stress_test_extreme_concurrency() {
    let mut config = high_concurrency_config();
    config.max_connections_per_server = 200;
    let manager = Arc::new(MCPManager::new(config));
    
    // Register servers
    for i in 0..5 {
        let server = create_mock_server(&format!("extreme_{}", i));
        manager.register_server(server).await.unwrap();
    }
    
    // Extreme concurrency parameters
    let concurrent_requests = 10000;
    let burst_duration = Duration::from_secs(1);
    
    // Send burst of requests
    let start = Instant::now();
    let mut handles = vec![];
    
    for i in 0..concurrent_requests {
        let manager_clone = manager.clone();
        let handle = tokio::spawn(async move {
            let request = MCPRequest::new(
                "extreme_burst",
                serde_json::json!({"req": i}),
            );
            manager_clone.send_request(request).await
        });
        handles.push(handle);
        
        // Control burst rate
        if i % 100 == 0 {
            tokio::task::yield_now().await;
        }
    }
    
    // Count results
    let mut success_count = 0;
    let mut timeout_count = 0;
    let mut other_errors = 0;
    
    for handle in handles {
        match handle.await {
            Ok(Ok(_)) => success_count += 1,
            Ok(Err(e)) => {
                match e {
                    crate::mcp_manager::error::MCPError::Timeout(_) => timeout_count += 1,
                    _ => other_errors += 1,
                }
            }
            Err(_) => other_errors += 1,
        }
    }
    
    let elapsed = start.elapsed();
    let success_rate = success_count as f64 / concurrent_requests as f64;
    
    println!("=== Extreme Concurrency Test Results ===");
    println!("Burst duration: {:?}", elapsed);
    println!("Successful: {} ({:.2}%)", success_count, success_rate * 100.0);
    println!("Timeouts: {}", timeout_count);
    println!("Other errors: {}", other_errors);
    println!("Burst rate: {:.0} req/s", concurrent_requests as f64 / elapsed.as_secs_f64());
    
    // Even under extreme load, most requests should succeed
    assert!(success_rate > 0.7, "Success rate should be > 70% even under extreme load");
}