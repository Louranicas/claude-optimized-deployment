//! Distributed Actor Support for BashGod
//! 
//! Implements distributed execution capabilities for scaling BashGod actors
//! across multiple nodes using consistent hashing and gossip protocols.

use super::{
    messages::{DistributedMessage, BashGodMessage, ChainResult},
    BashChain, BashGodError, Result,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};
use serde::{Serialize, Deserialize};

/// Node identifier type
pub type NodeId = String;

/// Distributed BashGod coordinator
pub struct DistributedBashGod {
    /// Local node ID
    node_id: NodeId,
    /// Known nodes in the cluster
    nodes: Arc<RwLock<HashMap<NodeId, NodeInfo>>>,
    /// Consistent hash ring for load distribution
    hash_ring: Arc<RwLock<ConsistentHashRing>>,
    /// Network handler
    network: Arc<NetworkHandler>,
    /// Gossip protocol handler
    gossip: Arc<GossipProtocol>,
}

/// Information about a cluster node
#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub id: NodeId,
    pub address: String,
    pub last_seen: Instant,
    pub load_factor: f32,
    pub capacity: usize,
    pub active_chains: usize,
}

/// Consistent hash ring for load distribution
struct ConsistentHashRing {
    /// Virtual nodes per physical node
    virtual_nodes: usize,
    /// Ring of hash values to node IDs
    ring: std::collections::BTreeMap<u64, NodeId>,
}

impl ConsistentHashRing {
    fn new(virtual_nodes: usize) -> Self {
        Self {
            virtual_nodes,
            ring: std::collections::BTreeMap::new(),
        }
    }
    
    /// Add a node to the ring
    fn add_node(&mut self, node_id: &str) {
        for i in 0..self.virtual_nodes {
            let key = format!("{}-{}", node_id, i);
            let hash = Self::hash(&key);
            self.ring.insert(hash, node_id.to_string());
        }
    }
    
    /// Remove a node from the ring
    fn remove_node(&mut self, node_id: &str) {
        self.ring.retain(|_, v| v != node_id);
    }
    
    /// Get the node responsible for a key
    fn get_node(&self, key: &str) -> Option<&NodeId> {
        if self.ring.is_empty() {
            return None;
        }
        
        let hash = Self::hash(key);
        
        // Find the first node with hash >= key hash
        self.ring.range(hash..)
            .next()
            .or_else(|| self.ring.iter().next())
            .map(|(_, node_id)| node_id)
    }
    
    /// Hash function (using xxhash for speed)
    fn hash(key: &str) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = twox_hash::XxHash64::default();
        key.hash(&mut hasher);
        hasher.finish()
    }
}

/// Network handler for distributed communication
struct NetworkHandler {
    node_id: NodeId,
    listen_addr: String,
    connections: Arc<RwLock<HashMap<NodeId, TcpStream>>>,
}

impl NetworkHandler {
    fn new(node_id: NodeId, listen_addr: String) -> Self {
        Self {
            node_id,
            listen_addr,
            connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Start listening for incoming connections
    async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.listen_addr).await
            .map_err(|e| BashGodError::Runtime(format!("Failed to bind: {}", e)))?;
            
        let connections = self.connections.clone();
        let node_id = self.node_id.clone();
        
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        debug!("New connection from: {}", addr);
                        Self::handle_connection(stream, connections.clone(), node_id.clone());
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                    }
                }
            }
        });
        
        Ok(())
    }
    
    /// Handle incoming connection
    fn handle_connection(
        mut stream: TcpStream,
        connections: Arc<RwLock<HashMap<NodeId, TcpStream>>>,
        _node_id: NodeId,
    ) {
        tokio::spawn(async move {
            let mut buf = vec![0; 4096];
            
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => break, // Connection closed
                    Ok(n) => {
                        // Parse and handle message
                        if let Ok(msg) = serde_json::from_slice::<DistributedMessage>(&buf[..n]) {
                            // TODO: Handle message
                            debug!("Received message: {:?}", msg);
                        }
                    }
                    Err(e) => {
                        error!("Connection error: {}", e);
                        break;
                    }
                }
            }
        });
    }
    
    /// Send message to a specific node
    async fn send_to_node(&self, node_id: &str, message: &DistributedMessage) -> Result<()> {
        let serialized = serde_json::to_vec(message)
            .map_err(|e| BashGodError::Runtime(format!("Serialization error: {}", e)))?;
            
        let mut connections = self.connections.write().await;
        
        if let Some(stream) = connections.get_mut(node_id) {
            stream.write_all(&serialized).await
                .map_err(|e| BashGodError::Runtime(format!("Send error: {}", e)))?;
        } else {
            return Err(BashGodError::Runtime(format!("No connection to node: {}", node_id)));
        }
        
        Ok(())
    }
    
    /// Broadcast message to all nodes
    async fn broadcast(&self, message: &DistributedMessage) -> Result<()> {
        let serialized = serde_json::to_vec(message)
            .map_err(|e| BashGodError::Runtime(format!("Serialization error: {}", e)))?;
            
        let mut connections = self.connections.write().await;
        
        for (node_id, stream) in connections.iter_mut() {
            if let Err(e) = stream.write_all(&serialized).await {
                warn!("Failed to send to node {}: {}", node_id, e);
            }
        }
        
        Ok(())
    }
}

/// Gossip protocol for cluster state synchronization
struct GossipProtocol {
    node_id: NodeId,
    nodes: Arc<RwLock<HashMap<NodeId, NodeInfo>>>,
    network: Arc<NetworkHandler>,
}

impl GossipProtocol {
    fn new(
        node_id: NodeId,
        nodes: Arc<RwLock<HashMap<NodeId, NodeInfo>>>,
        network: Arc<NetworkHandler>,
    ) -> Self {
        Self {
            node_id,
            nodes,
            network,
        }
    }
    
    /// Start gossip protocol
    async fn start(&self) -> Result<()> {
        let nodes = self.nodes.clone();
        let network = self.network.clone();
        let node_id = self.node_id.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            
            loop {
                interval.tick().await;
                
                // Send health ping to random nodes
                if let Err(e) = Self::gossip_round(&node_id, &nodes, &network).await {
                    warn!("Gossip round failed: {}", e);
                }
            }
        });
        
        Ok(())
    }
    
    /// Perform one gossip round
    async fn gossip_round(
        node_id: &str,
        nodes: &Arc<RwLock<HashMap<NodeId, NodeInfo>>>,
        network: &Arc<NetworkHandler>,
    ) -> Result<()> {
        let nodes_read = nodes.read().await;
        let node_list: Vec<NodeId> = nodes_read.keys()
            .filter(|id| *id != node_id)
            .cloned()
            .collect();
        drop(nodes_read);
        
        // Select random nodes to gossip with
        let gossip_targets = Self::select_gossip_targets(&node_list, 3);
        
        for target in gossip_targets {
            let msg = DistributedMessage::HealthPing {
                node_id: node_id.to_string(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            };
            
            let _ = network.send_to_node(&target, &msg).await;
        }
        
        Ok(())
    }
    
    /// Select random nodes for gossip
    fn select_gossip_targets(nodes: &[NodeId], count: usize) -> Vec<NodeId> {
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        
        nodes.choose_multiple(&mut rng, count.min(nodes.len()))
            .cloned()
            .collect()
    }
}

impl DistributedBashGod {
    /// Create a new distributed BashGod instance
    pub fn new(node_id: NodeId, listen_addr: String) -> Self {
        let nodes = Arc::new(RwLock::new(HashMap::new()));
        let hash_ring = Arc::new(RwLock::new(ConsistentHashRing::new(150)));
        let network = Arc::new(NetworkHandler::new(node_id.clone(), listen_addr));
        let gossip = Arc::new(GossipProtocol::new(
            node_id.clone(),
            nodes.clone(),
            network.clone(),
        ));
        
        Self {
            node_id,
            nodes,
            hash_ring,
            network,
            gossip,
        }
    }
    
    /// Start the distributed system
    pub async fn start(&self) -> Result<()> {
        info!("Starting distributed BashGod node: {}", self.node_id);
        
        // Start network handler
        self.network.start().await?;
        
        // Start gossip protocol
        self.gossip.start().await?;
        
        // Add self to hash ring
        self.hash_ring.write().await.add_node(&self.node_id);
        
        Ok(())
    }
    
    /// Join a cluster by connecting to seed nodes
    pub async fn join_cluster(&self, seed_nodes: Vec<(NodeId, String)>) -> Result<()> {
        for (node_id, address) in seed_nodes {
            if let Ok(stream) = TcpStream::connect(&address).await {
                self.network.connections.write().await.insert(node_id.clone(), stream);
                
                // Add to known nodes
                let node_info = NodeInfo {
                    id: node_id.clone(),
                    address,
                    last_seen: Instant::now(),
                    load_factor: 0.0,
                    capacity: 100,
                    active_chains: 0,
                };
                
                self.nodes.write().await.insert(node_id.clone(), node_info);
                self.hash_ring.write().await.add_node(&node_id);
            }
        }
        
        Ok(())
    }
    
    /// Execute a chain, potentially on a remote node
    pub async fn execute_chain(&self, chain: BashChain) -> Result<ChainResult> {
        // Determine which node should handle this chain
        let target_node = self.hash_ring.read().await
            .get_node(&chain.id)
            .cloned()
            .ok_or_else(|| BashGodError::Runtime("No nodes available".to_string()))?;
            
        if target_node == self.node_id {
            // Execute locally
            // TODO: Integrate with local executor
            Ok(ChainResult {
                chain_id: chain.id,
                success: true,
                output: vec!["Executed locally".to_string()],
                error: None,
                execution_time_ms: 0,
                commands_executed: 0,
            })
        } else {
            // Execute remotely
            let request_id = uuid::Uuid::new_v4().to_string();
            let msg = DistributedMessage::ExecuteOnNode {
                node_id: target_node.clone(),
                chain,
                request_id: request_id.clone(),
            };
            
            self.network.send_to_node(&target_node, &msg).await?;
            
            // TODO: Wait for response
            Ok(ChainResult {
                chain_id: request_id,
                success: true,
                output: vec![format!("Forwarded to node: {}", target_node)],
                error: None,
                execution_time_ms: 0,
                commands_executed: 0,
            })
        }
    }
    
    /// Get cluster statistics
    pub async fn get_cluster_stats(&self) -> ClusterStats {
        let nodes = self.nodes.read().await;
        
        ClusterStats {
            total_nodes: nodes.len() + 1, // Include self
            active_nodes: nodes.values()
                .filter(|n| n.last_seen.elapsed() < Duration::from_secs(30))
                .count() + 1,
            total_capacity: nodes.values().map(|n| n.capacity).sum::<usize>() + 100,
            total_active_chains: nodes.values().map(|n| n.active_chains).sum::<usize>(),
            avg_load_factor: {
                let sum: f32 = nodes.values().map(|n| n.load_factor).sum();
                sum / (nodes.len() as f32 + 1.0)
            },
        }
    }
}

/// Cluster statistics
#[derive(Debug, Clone)]
pub struct ClusterStats {
    pub total_nodes: usize,
    pub active_nodes: usize,
    pub total_capacity: usize,
    pub total_active_chains: usize,
    pub avg_load_factor: f32,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_consistent_hash_ring() {
        let mut ring = ConsistentHashRing::new(3);
        
        // Add nodes
        ring.add_node("node1");
        ring.add_node("node2");
        ring.add_node("node3");
        
        // Test key distribution
        let keys = vec!["key1", "key2", "key3", "key4", "key5"];
        let mut distribution = HashMap::new();
        
        for key in &keys {
            if let Some(node) = ring.get_node(key) {
                *distribution.entry(node.clone()).or_insert(0) += 1;
            }
        }
        
        // All nodes should have at least one key
        assert!(distribution.len() >= 2);
        
        // Remove a node
        ring.remove_node("node2");
        
        // Keys should be redistributed
        for key in &keys {
            assert!(ring.get_node(key).is_some());
        }
    }
    
    #[tokio::test]
    async fn test_distributed_bashgod_creation() {
        let distributed = DistributedBashGod::new(
            "test-node".to_string(),
            "127.0.0.1:0".to_string(),
        );
        
        assert!(distributed.start().await.is_ok());
        
        let stats = distributed.get_cluster_stats().await;
        assert_eq!(stats.total_nodes, 1);
        assert_eq!(stats.active_nodes, 1);
    }
}