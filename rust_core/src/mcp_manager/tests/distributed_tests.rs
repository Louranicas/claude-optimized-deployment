// ============================================================================
// Distributed Module Unit Tests
// ============================================================================

use crate::mcp_manager::{
    distributed::{
        consensus::{ConsensusManager, ConsensusProtocol, ConsensusState},
        coordinator::{Coordinator, CoordinationMessage, NodeRole},
        failover::{FailoverManager, FailoverStrategy, FailoverEvent},
        load_balancer::{DistributedLoadBalancer, ShardingStrategy},
        shard_manager::{ShardManager, ShardConfig, ShardState},
    },
    server::MCPServer,
    protocol::{MCPRequest, MCPResponse},
    error::{MCPError, MCPResult},
};
use std::sync::Arc;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::{RwLock, Mutex};
use tokio::test;

#[cfg(test)]
mod consensus_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_consensus_leader_election() {
        let node_ids = vec!["node1", "node2", "node3", "node4", "node5"];
        let consensus = ConsensusManager::new(
            "node1".to_string(),
            node_ids.clone(),
            ConsensusProtocol::Raft,
        );
        
        // Start election
        consensus.start_election().await.unwrap();
        
        // Wait for election to complete
        tokio::time::sleep(Duration::from_millis(500)).await;
        
        // Should have a leader
        let leader = consensus.get_leader().await;
        assert!(leader.is_some());
        assert!(node_ids.contains(&leader.unwrap().as_str()));
        
        // Check consensus state
        let state = consensus.get_state().await;
        assert!(matches!(state, ConsensusState::Leader | ConsensusState::Follower));
    }
    
    #[tokio::test]
    async fn test_consensus_propose_and_commit() {
        let consensus = ConsensusManager::new(
            "leader".to_string(),
            vec!["leader", "follower1", "follower2"],
            ConsensusProtocol::Raft,
        );
        
        // Make this node the leader
        consensus.become_leader().await.unwrap();
        
        // Propose a value
        let proposal = serde_json::json!({
            "action": "update_config",
            "key": "max_connections",
            "value": 100
        });
        
        let index = consensus.propose(proposal.clone()).await.unwrap();
        assert!(index > 0);
        
        // Wait for replication
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Check if committed
        let committed = consensus.is_committed(index).await;
        assert!(committed);
        
        // Retrieve committed value
        let value = consensus.get_committed_value(index).await.unwrap();
        assert_eq!(value, proposal);
    }
    
    #[tokio::test]
    async fn test_consensus_Byzantine_fault_tolerance() {
        let consensus = ConsensusManager::new(
            "node1".to_string(),
            vec!["node1", "node2", "node3", "node4", "node5", "node6", "node7"],
            ConsensusProtocol::Pbft, // Practical Byzantine Fault Tolerance
        );
        
        // Simulate Byzantine nodes (up to f = (n-1)/3)
        consensus.simulate_byzantine_node("node5").await;
        consensus.simulate_byzantine_node("node6").await;
        
        // System should still reach consensus
        let proposal = serde_json::json!({"command": "critical_update"});
        let result = consensus.propose(proposal).await;
        
        assert!(result.is_ok(), "Should reach consensus despite Byzantine nodes");
    }
    
    #[tokio::test]
    async fn test_consensus_partition_tolerance() {
        let consensus = ConsensusManager::new(
            "node1".to_string(),
            vec!["node1", "node2", "node3", "node4", "node5"],
            ConsensusProtocol::Raft,
        );
        
        // Simulate network partition
        consensus.simulate_partition(vec!["node1", "node2"], vec!["node3", "node4", "node5"]).await;
        
        // Minority partition should not be able to commit
        let minority_result = consensus.propose(serde_json::json!({"data": "minority"})).await;
        assert!(minority_result.is_err());
        
        // Heal partition
        consensus.heal_partition().await;
        
        // Should be able to commit after healing
        let healed_result = consensus.propose(serde_json::json!({"data": "healed"})).await;
        assert!(healed_result.is_ok());
    }
}

#[cfg(test)]
mod coordinator_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_coordinator_role_assignment() {
        let coordinator = Coordinator::new("coord1".to_string());
        
        // Add nodes
        coordinator.add_node("node1", NodeRole::Worker).await.unwrap();
        coordinator.add_node("node2", NodeRole::Worker).await.unwrap();
        coordinator.add_node("node3", NodeRole::Manager).await.unwrap();
        
        // Assign roles
        coordinator.assign_role("node1", NodeRole::Manager).await.unwrap();
        
        // Verify role assignment
        let role = coordinator.get_node_role("node1").await.unwrap();
        assert_eq!(role, NodeRole::Manager);
        
        // Get nodes by role
        let managers = coordinator.get_nodes_by_role(NodeRole::Manager).await;
        assert_eq!(managers.len(), 2);
        assert!(managers.contains(&"node1".to_string()));
        assert!(managers.contains(&"node3".to_string()));
    }
    
    #[tokio::test]
    async fn test_coordinator_task_distribution() {
        let coordinator = Arc::new(Coordinator::new("coord1".to_string()));
        
        // Add worker nodes
        for i in 0..5 {
            coordinator.add_node(&format!("worker{}", i), NodeRole::Worker).await.unwrap();
        }
        
        // Distribute tasks
        let mut task_distribution = HashMap::new();
        
        for task_id in 0..100 {
            let assigned_node = coordinator.assign_task(&format!("task{}", task_id)).await.unwrap();
            *task_distribution.entry(assigned_node).or_insert(0) += 1;
        }
        
        // Verify even distribution
        for (_, count) in task_distribution {
            assert!((15..=25).contains(&count), "Task distribution should be relatively even");
        }
    }
    
    #[tokio::test]
    async fn test_coordinator_heartbeat_monitoring() {
        let coordinator = Coordinator::new("coord1".to_string());
        
        // Add nodes
        coordinator.add_node("node1", NodeRole::Worker).await.unwrap();
        coordinator.add_node("node2", NodeRole::Worker).await.unwrap();
        
        // Start heartbeat monitoring
        coordinator.start_heartbeat_monitoring(Duration::from_millis(100)).await;
        
        // Send heartbeats
        coordinator.receive_heartbeat("node1").await;
        coordinator.receive_heartbeat("node2").await;
        
        // Wait
        tokio::time::sleep(Duration::from_millis(50)).await;
        
        // Both nodes should be healthy
        assert!(coordinator.is_node_healthy("node1").await);
        assert!(coordinator.is_node_healthy("node2").await);
        
        // Stop heartbeat from node2
        tokio::time::sleep(Duration::from_millis(200)).await;
        
        // Node2 should be marked unhealthy
        coordinator.receive_heartbeat("node1").await;
        assert!(coordinator.is_node_healthy("node1").await);
        assert!(!coordinator.is_node_healthy("node2").await);
    }
    
    #[tokio::test]
    async fn test_coordinator_message_broadcast() {
        let coordinator = Arc::new(Coordinator::new("coord1".to_string()));
        
        // Add nodes with message handlers
        let received_messages = Arc::new(RwLock::new(Vec::new()));
        
        for i in 0..3 {
            let node_id = format!("node{}", i);
            coordinator.add_node(&node_id, NodeRole::Worker).await.unwrap();
            
            let messages_clone = received_messages.clone();
            coordinator.register_message_handler(&node_id, move |msg| {
                let messages = messages_clone.clone();
                Box::pin(async move {
                    messages.write().await.push(msg);
                })
            }).await;
        }
        
        // Broadcast message
        let message = CoordinationMessage::new("test_broadcast", serde_json::json!({"data": "test"}));
        coordinator.broadcast(message).await.unwrap();
        
        // Wait for propagation
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // All nodes should have received the message
        let messages = received_messages.read().await;
        assert_eq!(messages.len(), 3);
    }
}

#[cfg(test)]
mod failover_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_failover_automatic_detection() {
        let mut failover = FailoverManager::new(FailoverStrategy::Automatic);
        
        // Add primary and backup servers
        let primary = create_test_server("primary");
        let backup1 = create_test_server("backup1");
        let backup2 = create_test_server("backup2");
        
        failover.set_primary(primary.clone()).await;
        failover.add_backup(backup1.clone()).await;
        failover.add_backup(backup2.clone()).await;
        
        // Simulate primary failure
        failover.mark_server_failed(&primary.id()).await;
        
        // Should automatically failover
        let new_primary = failover.get_active_server().await.unwrap();
        assert_ne!(new_primary.id(), primary.id());
        assert!(new_primary.id() == backup1.id() || new_primary.id() == backup2.id());
        
        // Check failover event
        let events = failover.get_failover_events().await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].failed_server, primary.id());
        assert_eq!(events[0].new_primary, new_primary.id());
    }
    
    #[tokio::test]
    async fn test_failover_manual_trigger() {
        let mut failover = FailoverManager::new(FailoverStrategy::Manual);
        
        let primary = create_test_server("primary");
        let backup = create_test_server("backup");
        
        failover.set_primary(primary.clone()).await;
        failover.add_backup(backup.clone()).await;
        
        // Manual failover
        failover.trigger_failover().await.unwrap();
        
        // Should switch to backup
        let active = failover.get_active_server().await.unwrap();
        assert_eq!(active.id(), backup.id());
    }
    
    #[tokio::test]
    async fn test_failover_priority_based() {
        let mut failover = FailoverManager::new(FailoverStrategy::PriorityBased);
        
        let primary = create_test_server("primary");
        let high_priority = create_test_server("high_priority");
        let low_priority = create_test_server("low_priority");
        
        failover.set_primary(primary.clone()).await;
        failover.add_backup_with_priority(high_priority.clone(), 10).await;
        failover.add_backup_with_priority(low_priority.clone(), 5).await;
        
        // Trigger failover
        failover.mark_server_failed(&primary.id()).await;
        
        // Should select high priority backup
        let active = failover.get_active_server().await.unwrap();
        assert_eq!(active.id(), high_priority.id());
    }
    
    #[tokio::test]
    async fn test_failover_cascading_failures() {
        let mut failover = FailoverManager::new(FailoverStrategy::Automatic);
        
        // Add multiple backups
        let primary = create_test_server("primary");
        let backups: Vec<_> = (0..5)
            .map(|i| create_test_server(&format!("backup{}", i)))
            .collect();
        
        failover.set_primary(primary.clone()).await;
        for backup in &backups {
            failover.add_backup(backup.clone()).await;
        }
        
        // Simulate cascading failures
        failover.mark_server_failed(&primary.id()).await;
        let first_backup = failover.get_active_server().await.unwrap();
        
        failover.mark_server_failed(&first_backup.id()).await;
        let second_backup = failover.get_active_server().await.unwrap();
        
        // Should have different active servers
        assert_ne!(first_backup.id(), second_backup.id());
        
        // Verify failover history
        let events = failover.get_failover_events().await;
        assert_eq!(events.len(), 2);
    }
    
    #[tokio::test]
    async fn test_failover_recovery() {
        let mut failover = FailoverManager::new(FailoverStrategy::Automatic);
        
        let primary = create_test_server("primary");
        let backup = create_test_server("backup");
        
        failover.set_primary(primary.clone()).await;
        failover.add_backup(backup.clone()).await;
        
        // Fail primary
        failover.mark_server_failed(&primary.id()).await;
        assert_eq!(failover.get_active_server().await.unwrap().id(), backup.id());
        
        // Recover primary
        failover.mark_server_recovered(&primary.id()).await;
        
        // With auto-recovery enabled, should switch back
        failover.enable_auto_recovery(true).await;
        failover.check_recovery().await;
        
        assert_eq!(failover.get_active_server().await.unwrap().id(), primary.id());
    }
}

#[cfg(test)]
mod shard_manager_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_shard_consistent_hashing() {
        let config = ShardConfig {
            num_shards: 16,
            replication_factor: 3,
            virtual_nodes: 150,
        };
        
        let mut shard_manager = ShardManager::new(config);
        
        // Add nodes
        for i in 0..5 {
            shard_manager.add_node(&format!("node{}", i)).await.unwrap();
        }
        
        // Test key distribution
        let mut shard_distribution = HashMap::new();
        
        for i in 0..1000 {
            let key = format!("key_{}", i);
            let shard = shard_manager.get_shard(&key).await;
            *shard_distribution.entry(shard).or_insert(0) += 1;
        }
        
        // Should have relatively even distribution
        for (_, count) in shard_distribution {
            assert!((40..=80).contains(&count), "Shard distribution should be relatively even");
        }
    }
    
    #[tokio::test]
    async fn test_shard_rebalancing() {
        let config = ShardConfig {
            num_shards: 12,
            replication_factor: 2,
            virtual_nodes: 100,
        };
        
        let mut shard_manager = ShardManager::new(config);
        
        // Initial nodes
        for i in 0..3 {
            shard_manager.add_node(&format!("node{}", i)).await.unwrap();
        }
        
        // Get initial distribution
        let initial_assignments = shard_manager.get_shard_assignments().await;
        
        // Add new node
        shard_manager.add_node("node3").await.unwrap();
        
        // Trigger rebalancing
        let migrations = shard_manager.rebalance().await.unwrap();
        
        // Should have migration plans
        assert!(!migrations.is_empty());
        
        // Verify new distribution is more balanced
        let new_assignments = shard_manager.get_shard_assignments().await;
        assert_ne!(initial_assignments, new_assignments);
    }
    
    #[tokio::test]
    async fn test_shard_replication() {
        let config = ShardConfig {
            num_shards: 8,
            replication_factor: 3,
            virtual_nodes: 50,
        };
        
        let mut shard_manager = ShardManager::new(config);
        
        // Add nodes
        for i in 0..5 {
            shard_manager.add_node(&format!("node{}", i)).await.unwrap();
        }
        
        // Check replication
        for shard_id in 0..8 {
            let replicas = shard_manager.get_shard_replicas(shard_id).await.unwrap();
            assert_eq!(replicas.len(), 3, "Each shard should have 3 replicas");
            
            // Replicas should be on different nodes
            let unique_nodes: std::collections::HashSet<_> = replicas.into_iter().collect();
            assert_eq!(unique_nodes.len(), 3, "Replicas should be on different nodes");
        }
    }
    
    #[tokio::test]
    async fn test_shard_failure_handling() {
        let config = ShardConfig {
            num_shards: 10,
            replication_factor: 3,
            virtual_nodes: 100,
        };
        
        let mut shard_manager = ShardManager::new(config);
        
        // Add nodes
        for i in 0..6 {
            shard_manager.add_node(&format!("node{}", i)).await.unwrap();
        }
        
        // Simulate node failure
        shard_manager.mark_node_failed("node2").await.unwrap();
        
        // All shards should still be accessible
        for shard_id in 0..10 {
            let available_replicas = shard_manager.get_available_replicas(shard_id).await.unwrap();
            assert!(available_replicas.len() >= 2, "Should have at least 2 available replicas");
        }
        
        // Should trigger re-replication
        let replication_tasks = shard_manager.get_pending_replications().await;
        assert!(!replication_tasks.is_empty(), "Should have pending replication tasks");
    }
}

#[cfg(test)]
mod distributed_load_balancer_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_distributed_load_balancer_geo_aware() {
        let mut lb = DistributedLoadBalancer::new(ShardingStrategy::GeoAware);
        
        // Add servers in different regions
        let us_east = create_server_with_metadata("us-east-1", "region", "us-east");
        let us_west = create_server_with_metadata("us-west-1", "region", "us-west");
        let eu_west = create_server_with_metadata("eu-west-1", "region", "eu-west");
        
        lb.add_server(us_east.clone()).await;
        lb.add_server(us_west.clone()).await;
        lb.add_server(eu_west.clone()).await;
        
        // Request from us-east client
        let request = create_request_with_metadata("client_region", "us-east");
        let selected = lb.select_server(&request).await.unwrap();
        assert_eq!(selected.id(), "us-east-1");
        
        // Request from eu-west client
        let request = create_request_with_metadata("client_region", "eu-west");
        let selected = lb.select_server(&request).await.unwrap();
        assert_eq!(selected.id(), "eu-west-1");
    }
    
    #[tokio::test]
    async fn test_distributed_load_balancer_affinity() {
        let mut lb = DistributedLoadBalancer::new(ShardingStrategy::SessionAffinity);
        
        // Add servers
        for i in 0..5 {
            lb.add_server(create_test_server(&format!("server{}", i))).await;
        }
        
        // Multiple requests from same session should go to same server
        let session_id = "session123";
        let mut selected_servers = std::collections::HashSet::new();
        
        for _ in 0..10 {
            let request = create_request_with_metadata("session_id", session_id);
            let selected = lb.select_server(&request).await.unwrap();
            selected_servers.insert(selected.id().to_string());
        }
        
        assert_eq!(selected_servers.len(), 1, "All requests from same session should go to same server");
    }
    
    #[tokio::test]
    async fn test_distributed_load_balancer_weighted_sharding() {
        let mut lb = DistributedLoadBalancer::new(ShardingStrategy::WeightedCapacity);
        
        // Add servers with different capacities
        let high_capacity = create_server_with_metadata("high-cap", "capacity", "100");
        let med_capacity = create_server_with_metadata("med-cap", "capacity", "50");
        let low_capacity = create_server_with_metadata("low-cap", "capacity", "25");
        
        lb.add_server(high_capacity.clone()).await;
        lb.add_server(med_capacity.clone()).await;
        lb.add_server(low_capacity.clone()).await;
        
        // Send many requests and count distribution
        let mut distribution = HashMap::new();
        
        for i in 0..1000 {
            let request = MCPRequest::new("test", serde_json::json!({"i": i}));
            let selected = lb.select_server(&request).await.unwrap();
            *distribution.entry(selected.id().to_string()).or_insert(0) += 1;
        }
        
        // High capacity should get approximately 4x more than low capacity
        let high_count = distribution["high-cap"];
        let low_count = distribution["low-cap"];
        assert!(high_count > low_count * 3, "High capacity server should handle more requests");
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

fn create_server_with_metadata(id: &str, key: &str, value: &str) -> MCPServer {
    let mut metadata = HashMap::new();
    metadata.insert(key.to_string(), value.to_string());
    
    MCPServer::new(
        id.to_string(),
        format!("http://{}:8080", id),
        crate::mcp_manager::protocol::MCPProtocol::Http,
        metadata,
    )
}

fn create_request_with_metadata(key: &str, value: &str) -> MCPRequest {
    MCPRequest::new(
        "test",
        serde_json::json!({
            "metadata": {
                key: value
            }
        }),
    )
}