// ============================================================================
// Optimization Module Unit Tests
// ============================================================================

use crate::mcp_manager::{
    optimization::{
        cache::{AdaptiveCache, CacheStrategy, EvictionPolicy},
        prefetch::{PrefetchEngine, PrefetchStrategy, PredictionModel},
        request_batching::{RequestBatcher, BatchingStrategy, BatchConfig},
        load_balancer::{OptimizedLoadBalancer, LoadDistributionAlgorithm},
    },
    protocol::{MCPRequest, MCPResponse},
    server::MCPServer,
    error::{MCPError, MCPResult},
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::{Duration, Instant};
use std::collections::HashMap;
use tokio::sync::{RwLock, Mutex};
use tokio::test;

#[cfg(test)]
mod cache_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_adaptive_cache_lru_eviction() {
        let cache = AdaptiveCache::new(
            CacheStrategy::Adaptive,
            EvictionPolicy::LRU,
            100, // max entries
            Duration::from_secs(60), // TTL
        );
        
        // Fill cache beyond capacity
        for i in 0..150 {
            cache.put(
                format!("key_{}", i),
                serde_json::json!({"id": i, "data": "test"}),
            ).await;
        }
        
        // Cache should have evicted oldest entries
        assert_eq!(cache.size().await, 100);
        
        // Oldest entries should be evicted
        assert!(cache.get("key_0").await.is_none());
        assert!(cache.get("key_49").await.is_none());
        
        // Recent entries should still be present
        assert!(cache.get("key_100").await.is_some());
        assert!(cache.get("key_149").await.is_some());
    }
    
    #[tokio::test]
    async fn test_adaptive_cache_lfu_eviction() {
        let cache = AdaptiveCache::new(
            CacheStrategy::Adaptive,
            EvictionPolicy::LFU,
            50,
            Duration::from_secs(60),
        );
        
        // Add entries with different access patterns
        for i in 0..60 {
            cache.put(format!("key_{}", i), serde_json::json!({"id": i})).await;
        }
        
        // Access some entries multiple times
        for _ in 0..10 {
            cache.get("key_10").await;
            cache.get("key_20").await;
            cache.get("key_30").await;
        }
        
        // Force eviction by adding more entries
        for i in 60..70 {
            cache.put(format!("key_{}", i), serde_json::json!({"id": i})).await;
        }
        
        // Frequently accessed entries should remain
        assert!(cache.get("key_10").await.is_some());
        assert!(cache.get("key_20").await.is_some());
        assert!(cache.get("key_30").await.is_some());
        
        // Less frequently accessed entries should be evicted
        assert!(cache.get("key_0").await.is_none());
        assert!(cache.get("key_1").await.is_none());
    }
    
    #[tokio::test]
    async fn test_adaptive_cache_ttl() {
        let cache = AdaptiveCache::new(
            CacheStrategy::TimeBased,
            EvictionPolicy::TTL,
            100,
            Duration::from_millis(100), // Short TTL for testing
        );
        
        cache.put("short_lived", serde_json::json!("data")).await;
        
        // Should exist immediately
        assert!(cache.get("short_lived").await.is_some());
        
        // Wait for TTL to expire
        tokio::time::sleep(Duration::from_millis(150)).await;
        
        // Should be expired
        assert!(cache.get("short_lived").await.is_none());
    }
    
    #[tokio::test]
    async fn test_adaptive_cache_hit_rate() {
        let cache = AdaptiveCache::new(
            CacheStrategy::Adaptive,
            EvictionPolicy::LRU,
            100,
            Duration::from_secs(60),
        );
        
        // Populate cache
        for i in 0..50 {
            cache.put(format!("key_{}", i), serde_json::json!({"id": i})).await;
        }
        
        // Perform lookups
        let mut hits = 0;
        let mut misses = 0;
        
        for i in 0..100 {
            if cache.get(&format!("key_{}", i % 60)).await.is_some() {
                hits += 1;
            } else {
                misses += 1;
            }
        }
        
        let hit_rate = cache.get_hit_rate().await;
        assert!(hit_rate > 0.7, "Cache hit rate should be good for repeated access patterns");
        
        // Verify metrics
        let metrics = cache.get_metrics().await;
        assert_eq!(metrics.total_requests, 100);
        assert_eq!(metrics.hits, hits);
        assert_eq!(metrics.misses, misses);
    }
    
    #[tokio::test]
    async fn test_adaptive_cache_size_adaptation() {
        let cache = AdaptiveCache::new(
            CacheStrategy::Adaptive,
            EvictionPolicy::AdaptiveReplacement,
            100,
            Duration::from_secs(60),
        );
        
        // Simulate varying workload
        // Phase 1: Sequential access pattern
        for i in 0..200 {
            cache.put(format!("seq_{}", i), serde_json::json!({"phase": 1})).await;
            if i > 0 {
                cache.get(&format!("seq_{}", i - 1)).await;
            }
        }
        
        let phase1_metrics = cache.get_metrics().await;
        
        // Phase 2: Random access pattern
        for _ in 0..200 {
            let key = format!("rand_{}", rand::random::<u32>() % 50);
            cache.put(key.clone(), serde_json::json!({"phase": 2})).await;
            cache.get(&key).await;
        }
        
        let phase2_metrics = cache.get_metrics().await;
        
        // Cache should adapt its strategy based on access patterns
        assert_ne!(phase1_metrics.eviction_count, phase2_metrics.eviction_count);
    }
}

#[cfg(test)]
mod prefetch_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_prefetch_sequential_prediction() {
        let prefetch = PrefetchEngine::new(
            PrefetchStrategy::Sequential,
            PredictionModel::default(),
        );
        
        // Train with sequential access pattern
        for i in 0..100 {
            prefetch.record_access(&format!("item_{}", i)).await;
        }
        
        // Predict next accesses
        let predictions = prefetch.predict_next("item_50", 5).await;
        
        assert_eq!(predictions.len(), 5);
        assert_eq!(predictions[0], "item_51");
        assert_eq!(predictions[1], "item_52");
        assert_eq!(predictions[2], "item_53");
        assert_eq!(predictions[3], "item_54");
        assert_eq!(predictions[4], "item_55");
    }
    
    #[tokio::test]
    async fn test_prefetch_pattern_learning() {
        let prefetch = PrefetchEngine::new(
            PrefetchStrategy::MachineLearning,
            PredictionModel::new_neural_network(10, 50, 10),
        );
        
        // Train with repeating pattern
        for cycle in 0..20 {
            for item in ["A", "B", "C", "D", "A", "E", "F"] {
                prefetch.record_access(&format!("{}_{}", item, cycle)).await;
            }
        }
        
        // Should learn the pattern
        prefetch.train_model().await;
        
        // Test predictions
        let after_a = prefetch.predict_next("A_20", 3).await;
        assert!(after_a.contains(&"B_20".to_string()) || after_a.contains(&"E_20".to_string()));
        
        let after_d = prefetch.predict_next("D_20", 2).await;
        assert!(after_d.contains(&"A_20".to_string()));
    }
    
    #[tokio::test]
    async fn test_prefetch_adaptive_strategy() {
        let prefetch = PrefetchEngine::new(
            PrefetchStrategy::Adaptive,
            PredictionModel::default(),
        );
        
        // Mix of sequential and random patterns
        // Sequential burst
        for i in 0..50 {
            prefetch.record_access(&format!("seq_{}", i)).await;
        }
        
        // Random burst
        for _ in 0..50 {
            prefetch.record_access(&format!("rand_{}", rand::random::<u32>() % 20)).await;
        }
        
        // Should adapt strategy
        let seq_predictions = prefetch.predict_next("seq_25", 3).await;
        let rand_predictions = prefetch.predict_next("rand_5", 3).await;
        
        // Sequential predictions should be more accurate
        assert!(seq_predictions.contains(&"seq_26".to_string()));
        
        // Random predictions might be based on frequency
        assert!(!rand_predictions.is_empty());
    }
    
    #[tokio::test]
    async fn test_prefetch_performance_impact() {
        let prefetch = PrefetchEngine::new(
            PrefetchStrategy::CostBased,
            PredictionModel::default(),
        );
        
        // Simulate access with fetch costs
        let access_times = Arc::new(RwLock::new(HashMap::new()));
        
        for i in 0..100 {
            let key = format!("item_{}", i);
            let fetch_time = Duration::from_millis(10 + (i % 5) * 5); // Variable fetch times
            
            access_times.write().await.insert(key.clone(), fetch_time);
            prefetch.record_access_with_metrics(&key, fetch_time, 1024 * (i % 10)).await;
        }
        
        // Get prefetch recommendations considering cost
        let recommendations = prefetch.get_prefetch_recommendations(10).await;
        
        // Should prioritize items with high fetch cost and likelihood
        assert!(!recommendations.is_empty());
        
        // Verify cost-benefit analysis
        let metrics = prefetch.get_metrics().await;
        assert!(metrics.prefetch_hits > 0 || metrics.total_prefetches == 0);
    }
}

#[cfg(test)]
mod request_batching_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_request_batcher_time_window() {
        let config = BatchConfig {
            max_batch_size: 10,
            max_wait_time: Duration::from_millis(50),
            min_batch_size: 2,
        };
        
        let batcher = RequestBatcher::new(
            BatchingStrategy::TimeWindow,
            config,
        );
        
        let batch_count = Arc::new(AtomicU64::new(0));
        let batch_sizes = Arc::new(RwLock::new(Vec::new()));
        
        // Set batch processor
        let count_clone = batch_count.clone();
        let sizes_clone = batch_sizes.clone();
        batcher.set_processor(move |batch| {
            let count = count_clone.clone();
            let sizes = sizes_clone.clone();
            Box::pin(async move {
                count.fetch_add(1, Ordering::Relaxed);
                sizes.write().await.push(batch.len());
                
                // Process batch
                let responses = batch.iter()
                    .map(|_| MCPResponse::success(serde_json::json!({"batched": true})))
                    .collect();
                
                Ok(responses)
            })
        }).await;
        
        // Send requests
        let mut handles = vec![];
        for i in 0..15 {
            let batcher_clone = batcher.clone();
            let handle = tokio::spawn(async move {
                let request = MCPRequest::new("batch_test", serde_json::json!({"id": i}));
                batcher_clone.add_request(request).await
            });
            handles.push(handle);
            
            // Small delay between requests
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        
        // Wait for all requests
        for handle in handles {
            let _ = handle.await.unwrap();
        }
        
        // Should have created multiple batches
        let final_count = batch_count.load(Ordering::Relaxed); // TODO: Review memory ordering - consider Acquire/Release
        assert!(final_count >= 2, "Should have created multiple batches");
        
        let sizes = batch_sizes.read().await;
        for size in sizes.iter() {
            assert!(*size >= 2 && *size <= 10, "Batch size should be within limits");
        }
    }
    
    #[tokio::test]
    async fn test_request_batcher_size_triggered() {
        let config = BatchConfig {
            max_batch_size: 5,
            max_wait_time: Duration::from_secs(10), // Long wait
            min_batch_size: 1,
        };
        
        let batcher = RequestBatcher::new(
            BatchingStrategy::SizeTriggered,
            config,
        );
        
        let processed = Arc::new(AtomicU64::new(0));
        let processed_clone = processed.clone();
        
        batcher.set_processor(move |batch| {
            let processed = processed_clone.clone();
            Box::pin(async move {
                processed.fetch_add(batch.len() as u64, Ordering::Relaxed);
                Ok(vec![MCPResponse::success(serde_json::json!({})); batch.len()])
            })
        }).await;
        
        // Send exactly max_batch_size requests
        let start = Instant::now();
        let mut handles = vec![];
        
        for i in 0..5 {
            let batcher_clone = batcher.clone();
            let handle = tokio::spawn(async move {
                let request = MCPRequest::new("size_test", serde_json::json!({"id": i}));
                batcher_clone.add_request(request).await
            });
            handles.push(handle);
        }
        
        for handle in handles {
            let _ = handle.await.unwrap();
        }
        
        let elapsed = start.elapsed();
        
        // Should process immediately when size is reached
        assert!(elapsed < Duration::from_millis(100), "Should not wait when batch size is reached");
        assert_eq!(processed.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release, 5);
    }
    
    #[tokio::test]
    async fn test_request_batcher_adaptive() {
        let config = BatchConfig {
            max_batch_size: 20,
            max_wait_time: Duration::from_millis(100),
            min_batch_size: 1,
        };
        
        let batcher = RequestBatcher::new(
            BatchingStrategy::Adaptive,
            config,
        );
        
        let batch_info = Arc::new(RwLock::new(Vec::new()));
        let info_clone = batch_info.clone();
        
        batcher.set_processor(move |batch| {
            let info = info_clone.clone();
            let receive_time = Instant::now();
            Box::pin(async move {
                info.write().await.push((batch.len(), receive_time));
                Ok(vec![MCPResponse::success(serde_json::json!({})); batch.len()])
            })
        }).await;
        
        // Phase 1: High rate of requests
        let phase1_start = Instant::now();
        for i in 0..50 {
            let batcher_clone = batcher.clone();
            tokio::spawn(async move {
                let request = MCPRequest::new("adaptive_test", serde_json::json!({"phase": 1, "id": i}));
                let _ = batcher_clone.add_request(request).await;
            });
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        
        tokio::time::sleep(Duration::from_millis(200)).await;
        
        // Phase 2: Low rate of requests
        for i in 0..10 {
            let batcher_clone = batcher.clone();
            tokio::spawn(async move {
                let request = MCPRequest::new("adaptive_test", serde_json::json!({"phase": 2, "id": i}));
                let _ = batcher_clone.add_request(request).await;
            });
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        
        tokio::time::sleep(Duration::from_millis(200)).await;
        
        // Analyze batching behavior
        let info = batch_info.read().await;
        
        // Should have different batching patterns for different request rates
        let phase1_batches: Vec<_> = info.iter()
            .filter(|(_, time)| time.duration_since(phase1_start) < Duration::from_millis(300))
            .map(|(size, _)| *size)
            .collect();
        
        let phase2_batches: Vec<_> = info.iter()
            .filter(|(_, time)| time.duration_since(phase1_start) >= Duration::from_millis(300))
            .map(|(size, _)| *size)
            .collect();
        
        if !phase1_batches.is_empty() && !phase2_batches.is_empty() {
            let avg_phase1 = phase1_batches.iter().sum::<usize>() / phase1_batches.len();
            let avg_phase2 = phase2_batches.iter().sum::<usize>() / phase2_batches.len();
            
            // High-rate phase should have larger batches
            assert!(avg_phase1 > avg_phase2, "Should adapt batch size to request rate");
        }
    }
}

#[cfg(test)]
mod optimized_load_balancer_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_load_balancer_least_response_time() {
        let mut lb = OptimizedLoadBalancer::new(
            LoadDistributionAlgorithm::LeastResponseTime
        );
        
        // Add servers with different response times
        let fast_server = create_test_server("fast");
        let medium_server = create_test_server("medium");
        let slow_server = create_test_server("slow");
        
        lb.add_server(fast_server.clone()).await;
        lb.add_server(medium_server.clone()).await;
        lb.add_server(slow_server.clone()).await;
        
        // Record response times
        lb.record_response_time("fast", Duration::from_millis(10)).await;
        lb.record_response_time("medium", Duration::from_millis(50)).await;
        lb.record_response_time("slow", Duration::from_millis(100)).await;
        
        // Should prefer fast server
        let mut selections = HashMap::new();
        for _ in 0..100 {
            let request = MCPRequest::new("test", serde_json::json!({}));
            let selected = lb.select_server(&request).await.unwrap();
            *selections.entry(selected.id().to_string()).or_insert(0) += 1;
        }
        
        // Fast server should get most requests
        assert!(selections["fast"] > selections["medium"]);
        assert!(selections["medium"] > selections["slow"]);
    }
    
    #[tokio::test]
    async fn test_load_balancer_consistent_hashing() {
        let mut lb = OptimizedLoadBalancer::new(
            LoadDistributionAlgorithm::ConsistentHashing { virtual_nodes: 150 }
        );
        
        // Add servers
        for i in 0..5 {
            lb.add_server(create_test_server(&format!("server{}", i))).await;
        }
        
        // Same key should always go to same server
        let mut key_mapping = HashMap::new();
        
        for key in ["user_123", "session_456", "cache_789"] {
            let request = MCPRequest::with_id(
                key.to_string(),
                "test".to_string(),
                serde_json::json!({}),
            );
            
            for _ in 0..10 {
                let selected = lb.select_server(&request).await.unwrap();
                let entry = key_mapping.entry(key).or_insert(selected.id().to_string());
                assert_eq!(*entry, selected.id(), "Same key should always map to same server");
            }
        }
    }
    
    #[tokio::test]
    async fn test_load_balancer_power_of_two_choices() {
        let mut lb = OptimizedLoadBalancer::new(
            LoadDistributionAlgorithm::PowerOfTwoChoices
        );
        
        // Add servers
        let servers: Vec<_> = (0..10)
            .map(|i| create_test_server(&format!("server{}", i)))
            .collect();
        
        for server in &servers {
            lb.add_server(server.clone()).await;
        }
        
        // Simulate varying loads
        for i in 0..10 {
            let load = match i {
                0..=2 => 80,  // High load
                3..=5 => 50,  // Medium load
                _ => 20,      // Low load
            };
            lb.set_server_load(&format!("server{}", i), load).await;
        }
        
        // Should prefer lower loaded servers
        let mut selections = HashMap::new();
        for _ in 0..1000 {
            let request = MCPRequest::new("test", serde_json::json!({}));
            let selected = lb.select_server(&request).await.unwrap();
            *selections.entry(selected.id().to_string()).or_insert(0) += 1;
        }
        
        // Low load servers should get more requests
        let high_load_avg = (selections.get("server0").unwrap_or(&0) +
                            selections.get("server1").unwrap_or(&0) +
                            selections.get("server2").unwrap_or(&0)) / 3;
        
        let low_load_avg = (selections.get("server6").unwrap_or(&0) +
                           selections.get("server7").unwrap_or(&0) +
                           selections.get("server8").unwrap_or(&0) +
                           selections.get("server9").unwrap_or(&0)) / 4;
        
        assert!(low_load_avg > high_load_avg, "Low load servers should handle more requests");
    }
    
    #[tokio::test]
    async fn test_load_balancer_adaptive_weight() {
        let mut lb = OptimizedLoadBalancer::new(
            LoadDistributionAlgorithm::AdaptiveWeight
        );
        
        // Add servers
        for i in 0..3 {
            lb.add_server(create_test_server(&format!("server{}", i))).await;
        }
        
        // Simulate performance metrics over time
        for iteration in 0..10 {
            // Server0: Consistently fast
            lb.record_response_time("server0", Duration::from_millis(10)).await;
            lb.record_success_rate("server0", 0.99).await;
            
            // Server1: Variable performance
            let response_time = if iteration % 2 == 0 { 20 } else { 100 };
            lb.record_response_time("server1", Duration::from_millis(response_time)).await;
            lb.record_success_rate("server1", 0.90).await;
            
            // Server2: Degrading performance
            lb.record_response_time("server2", Duration::from_millis(50 + iteration * 10)).await;
            lb.record_success_rate("server2", 0.95 - (iteration as f64 * 0.05)).await;
            
            // Update weights based on performance
            lb.adapt_weights().await;
        }
        
        // Test final distribution
        let mut selections = HashMap::new();
        for _ in 0..300 {
            let request = MCPRequest::new("test", serde_json::json!({}));
            let selected = lb.select_server(&request).await.unwrap();
            *selections.entry(selected.id().to_string()).or_insert(0) += 1;
        }
        
        // Server0 should get most traffic due to consistent good performance
        assert!(selections["server0"] > selections["server1"]);
        assert!(selections["server0"] > selections["server2"]);
        
        // Server2 should get least traffic due to degrading performance
        assert!(selections["server2"] < selections["server1"]);
    }
}

// Helper functions
fn create_test_server(id: &str) -> MCPServer {
    MCPServer::new(
        id.to_string(),
        format!("http://{}:8080", id),
        crate::mcp_manager::protocol::MCPProtocol::Http,
        HashMap::new(),
    )
}