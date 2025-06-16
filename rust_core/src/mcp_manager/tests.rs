#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_manager::{
        distributed::*,
        resilience::*,
        optimization::*,
        McpManager,
    };
    use std::collections::{HashMap, HashSet};
    use std::time::Duration;
    use tokio::runtime::Runtime;

    #[test]
    fn test_distributed_coordinator() {
        let rt = Runtime::new().unwrap();
        
        rt.block_on(async {
            let peers = HashSet::from(["node2".to_string(), "node3".to_string()]);
            let coordinator = DistributedCoordinator::new("node1".to_string(), peers);
            
            // Test initial state
            assert_eq!(coordinator.get_state(), RaftState::Follower);
            assert_eq!(coordinator.get_term(), 0);
            
            // Test command submission
            let result = coordinator.submit_command(b"test command".to_vec()).await;
            // Should fail as not leader
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_load_balancer_strategies() {
        let rt = Runtime::new().unwrap();
        
        rt.block_on(async {
            // Test round-robin
            let lb = LoadBalancer::new(LoadBalancingStrategy::RoundRobin);
            
            for i in 1..=3 {
                let server = Server {
                    id: format!("server{}", i),
                    address: format!("192.168.1.{}", i),
                    weight: 1,
                    health: HealthStatus::Healthy,
                    metrics: Default::default(),
                    last_health_check: std::time::Instant::now(),
                };
                lb.add_server(server);
            }
            
            // Should cycle through servers
            let mut selections = Vec::new();
            for _ in 0..6 {
                if let Ok(server) = lb.select_server(None).await {
                    selections.push(server);
                }
            }
            
            assert_eq!(selections.len(), 6);
            
            // Test consistent hash
            let lb_hash = LoadBalancer::new(LoadBalancingStrategy::ConsistentHash);
            
            for i in 1..=3 {
                let server = Server {
                    id: format!("server{}", i),
                    address: format!("192.168.1.{}", i),
                    weight: 1,
                    health: HealthStatus::Healthy,
                    metrics: Default::default(),
                    last_health_check: std::time::Instant::now(),
                };
                lb_hash.add_server(server);
            }
            
            // Same key should always go to same server
            let server1 = lb_hash.select_server(Some("user123")).await.unwrap();
            let server2 = lb_hash.select_server(Some("user123")).await.unwrap();
            assert_eq!(server1, server2);
        });
    }

    #[test]
    fn test_failover_manager() {
        let rt = Runtime::new().unwrap();
        
        rt.block_on(async {
            let manager = FailoverManager::new(FailoverStrategy::ActivePassive);
            
            // Add primary node
            let primary = Node {
                id: "primary".to_string(),
                role: NodeRole::Primary,
                state: NodeState::Active,
                health_score: 1.0,
                last_heartbeat: std::time::Instant::now(),
                priority: 100,
                data_lag: Duration::from_secs(0),
                capacity: 100.0,
                current_load: 50.0,
            };
            
            manager.add_node(primary);
            
            // Add secondary node
            let secondary = Node {
                id: "secondary".to_string(),
                role: NodeRole::Secondary,
                state: NodeState::Active,
                health_score: 0.9,
                last_heartbeat: std::time::Instant::now(),
                priority: 90,
                data_lag: Duration::from_secs(1),
                capacity: 100.0,
                current_load: 30.0,
            };
            
            manager.add_node(secondary);
            
            // Verify primary
            assert_eq!(manager.get_primary(), Some("primary".to_string()));
            
            // Test state snapshot
            let data = b"test state data".to_vec();
            manager.save_snapshot("primary".to_string(), data).await.unwrap();
        });
    }

    #[test]
    fn test_chaos_engineering() {
        let rt = Runtime::new().unwrap();
        
        rt.block_on(async {
            let chaos = ChaosEngineer::new();
            
            // Register mock service
            chaos.register_service_hook("test-service".to_string(), Box::new(MockServiceHook));
            
            // Schedule experiment
            let config = ExperimentConfig {
                experiment_type: ExperimentType::NetworkLatency,
                target: "test-service".to_string(),
                duration: Duration::from_secs(1),
                intensity: 0.5,
                probability: 1.0,
                params: HashMap::new(),
            };
            
            let experiment_id = chaos.schedule_experiment(config).await.unwrap();
            assert!(!experiment_id.is_empty());
            
            // Wait for experiment to complete
            tokio::time::sleep(Duration::from_secs(2)).await;
            
            // Check results
            let result = chaos.get_experiment_results(&experiment_id);
            assert!(result.is_some());
        });
    }

    #[test]
    fn test_bulkhead_pattern() {
        let rt = Runtime::new().unwrap();
        
        rt.block_on(async {
            use crate::mcp_manager::resilience::bulkhead::Bulkhead;
            
            let bulkhead = Bulkhead::new("api".to_string(), 2);
            
            // Test successful execution
            let result = bulkhead.execute(async { Ok::<i32, crate::mcp_manager::errors::McpError>(42) }).await;
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), 42);
            
            // Test available permits
            assert!(bulkhead.available_permits() <= 2);
            assert!(!bulkhead.is_at_capacity());
        });
    }

    #[test]
    fn test_advanced_cache() {
        let rt = Runtime::new().unwrap();
        
        rt.block_on(async {
            let cache = AdvancedCache::new(
                1024 * 1024, // 1MB
                100,         // 100 entries
                EvictionPolicy::LRU,
                Some(Duration::from_secs(60)),
            );
            
            // Test basic operations
            cache.put("key1".to_string(), vec![1, 2, 3], 3).await.unwrap();
            cache.put("key2".to_string(), vec![4, 5, 6], 3).await.unwrap();
            
            // Test get
            let value = cache.get(&"key1".to_string()).await;
            assert_eq!(value, Some(vec![1, 2, 3]));
            
            // Test cache stats
            let stats = cache.get_stats();
            assert_eq!(stats.hits, 1);
            assert_eq!(stats.misses, 0);
            
            // Test hit rate
            let hit_rate = cache.get_hit_rate();
            assert_eq!(hit_rate, 1.0);
        });
    }

    #[test]
    fn test_predictive_prefetcher() {
        let rt = Runtime::new().unwrap();
        
        rt.block_on(async {
            let prefetcher = PredictivePrefetcher::new(PrefetchStrategy::Sequential);
            
            // Record sequential access pattern
            for i in 0..10 {
                let pattern = AccessPattern {
                    key: format!("item_{}", i),
                    timestamp: std::time::Instant::now(),
                    context: HashMap::new(),
                    sequence_id: Some(i as u64),
                };
                prefetcher.record_access(pattern).await;
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            
            // Get prefetch suggestions
            let suggestions = prefetcher.get_prefetch_suggestions(5).await;
            assert!(!suggestions.is_empty());
            
            // Update stats
            prefetcher.update_stats("item_1", true);
            
            let stats = prefetcher.get_stats();
            assert_eq!(stats.successful_predictions, 1);
        });
    }

    #[test]
    fn test_multi_tier_cache() {
        let rt = Runtime::new().unwrap();
        
        rt.block_on(async {
            let mut cache = MultiTierCache::new();
            
            // L1: Small, fast cache
            cache.add_tier(
                1024 * 100,  // 100KB
                10,          // 10 entries
                EvictionPolicy::LRU,
                Some(Duration::from_secs(60)),
            );
            
            // L2: Larger cache
            cache.add_tier(
                1024 * 1024, // 1MB
                100,         // 100 entries
                EvictionPolicy::LFU,
                Some(Duration::from_secs(300)),
            );
            
            // Test operations
            cache.put("key1".to_string(), vec![1, 2, 3], 3).await.unwrap();
            
            let value = cache.get(&"key1".to_string()).await;
            assert_eq!(value, Some(vec![1, 2, 3]));
            
            // Get tier statistics
            let stats = cache.get_stats();
            assert_eq!(stats.len(), 2);
        });
    }

    #[test]
    fn test_mcp_manager_integration() {
        let peers = HashSet::from(["node2".to_string(), "node3".to_string()]);
        let manager = McpManager::new("node1".to_string(), peers);
        
        // Test coordinator
        assert_eq!(manager.coordinator.get_state(), RaftState::Follower);
        
        // Test load balancer
        let server = Server {
            id: "test-server".to_string(),
            address: "127.0.0.1:8080".to_string(),
            weight: 1,
            health: HealthStatus::Healthy,
            metrics: Default::default(),
            last_health_check: std::time::Instant::now(),
        };
        manager.load_balancer.add_server(server);
        
        // Test failover manager
        assert!(manager.failover_manager.get_primary().is_none());
        
        // Test chaos engineer
        assert!(manager.chaos_engineer.get_all_experiments().is_empty());
    }
}