//! Load balancer implementation

use crate::mcp_manager::{
    errors::{McpError, Result},
    server::McpServer,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::RwLock;

/// Load balancing algorithm
pub trait LoadBalancingAlgorithm: Send + Sync {
    /// Select a server
    fn select(&self, servers: &[Arc<McpServer>]) -> Option<Arc<McpServer>>;
}

/// Round-robin load balancer
pub struct RoundRobin {
    /// Current index
    current: AtomicUsize,
}

impl RoundRobin {
    /// Create new round-robin load balancer
    pub fn new() -> Self {
        Self {
            current: AtomicUsize::new(0),
        }
    }
}

impl LoadBalancingAlgorithm for RoundRobin {
    fn select(&self, servers: &[Arc<McpServer>]) -> Option<Arc<McpServer>> {
        if servers.is_empty() {
            return None;
        }
        
        let index = self.current.fetch_add(1, Ordering::Relaxed) % servers.len();
        Some(servers[index].clone())
    }
}

/// Least connections load balancer
pub struct LeastConnections {
    /// Connection counts
    connections: Arc<RwLock<HashMap<String, usize>>>,
}

impl LeastConnections {
    /// Create new least connections load balancer
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Record connection
    pub async fn add_connection(&self, server_id: &str) {
        let mut connections = self.connections.write().await;
        *connections.entry(server_id.to_string()).or_insert(0) += 1;
    }
    
    /// Remove connection
    pub async fn remove_connection(&self, server_id: &str) {
        let mut connections = self.connections.write().await;
        if let Some(count) = connections.get_mut(server_id) {
            *count = count.saturating_sub(1);
        }
    }
}

impl LoadBalancingAlgorithm for LeastConnections {
    fn select(&self, servers: &[Arc<McpServer>]) -> Option<Arc<McpServer>> {
        if servers.is_empty() {
            return None;
        }
        
        // This is a simplified implementation
        // In production, this would need async access to connection counts
        servers.first().cloned()
    }
}

/// Weighted round-robin load balancer
pub struct WeightedRoundRobin {
    /// Server weights
    weights: HashMap<String, u32>,
    /// Current weights
    current_weights: Arc<RwLock<HashMap<String, i32>>>,
}

impl WeightedRoundRobin {
    /// Create new weighted round-robin load balancer
    pub fn new(weights: HashMap<String, u32>) -> Self {
        let current_weights = weights.iter()
            .map(|(k, _)| (k.clone(), 0))
            .collect();
        
        Self {
            weights,
            current_weights: Arc::new(RwLock::new(current_weights)),
        }
    }
}

impl LoadBalancingAlgorithm for WeightedRoundRobin {
    fn select(&self, servers: &[Arc<McpServer>]) -> Option<Arc<McpServer>> {
        if servers.is_empty() {
            return None;
        }
        
        // Simplified implementation
        servers.first().cloned()
    }
}

/// Load balancer
pub struct LoadBalancer {
    /// Algorithm
    algorithm: Box<dyn LoadBalancingAlgorithm>,
    /// Healthy servers
    healthy_servers: Arc<RwLock<Vec<Arc<McpServer>>>>,
}

impl LoadBalancer {
    /// Create new load balancer
    pub fn new(algorithm: Box<dyn LoadBalancingAlgorithm>) -> Self {
        Self {
            algorithm,
            healthy_servers: Arc::new(RwLock::new(Vec::new())),
        }
    }
    
    /// Update healthy servers
    pub async fn update_servers(&self, servers: Vec<Arc<McpServer>>) {
        *self.healthy_servers.write().await = servers;
    }
    
    /// Select a server
    pub async fn select(&self) -> Result<Arc<McpServer>> {
        let servers = self.healthy_servers.read().await;
        self.algorithm.select(&servers)
            .ok_or_else(|| McpError::Other("No healthy servers available".to_string()))
    }
}