//! Load balancing for distributed MCP servers

use crate::mcp_manager::{
    errors::{McpError, Result},
    server::{McpServer, ServerState},
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Load balancing algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadBalancingAlgorithm {
    /// Round robin
    RoundRobin,
    /// Least connections
    LeastConnections,
    /// Weighted round robin
    WeightedRoundRobin,
    /// Random
    Random,
    /// IP hash
    IpHash,
    /// Least response time
    LeastResponseTime,
}

/// Load balancer for distributing requests across MCP servers
pub struct LoadBalancer {
    /// Algorithm to use
    algorithm: LoadBalancingAlgorithm,
    /// Server pools by type
    pools: Arc<RwLock<HashMap<String, ServerPool>>>,
    /// Current round-robin indices
    rr_indices: Arc<RwLock<HashMap<String, usize>>>,
}

/// Server pool
struct ServerPool {
    /// Servers in the pool
    servers: Vec<Arc<McpServer>>,
    /// Server weights (for weighted algorithms)
    weights: Vec<u32>,
    /// Active connections per server
    connections: Vec<usize>,
    /// Average response times
    response_times: Vec<f64>,
}

impl LoadBalancer {
    /// Create a new load balancer
    pub fn new(algorithm: LoadBalancingAlgorithm) -> Self {
        Self {
            algorithm,
            pools: Arc::new(RwLock::new(HashMap::new())),
            rr_indices: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add server to pool
    pub async fn add_server(&self, pool_name: String, server: Arc<McpServer>, weight: u32) {
        let mut pools = self.pools.write().await;
        let pool = pools.entry(pool_name).or_insert_with(|| ServerPool {
            servers: Vec::new(),
            weights: Vec::new(),
            connections: Vec::new(),
            response_times: Vec::new(),
        });
        
        pool.servers.push(server);
        pool.weights.push(weight);
        pool.connections.push(0);
        pool.response_times.push(0.0);
    }

    /// Remove server from pool
    pub async fn remove_server(&self, pool_name: &str, server_id: &str) -> Result<()> {
        let mut pools = self.pools.write().await;
        
        if let Some(pool) = pools.get_mut(pool_name) {
            if let Some(pos) = pool.servers.iter().position(|s| s.id() == server_id) {
                pool.servers.remove(pos);
                pool.weights.remove(pos);
                pool.connections.remove(pos);
                pool.response_times.remove(pos);
                Ok(())
            } else {
                Err(McpError::ServerNotFound(server_id.to_string()))
            }
        } else {
            Err(McpError::Other(format!("Pool not found: {}", pool_name)))
        }
    }

    /// Select a server from pool
    pub async fn select_server(&self, pool_name: &str, client_ip: Option<&str>) -> Result<Arc<McpServer>> {
        let pools = self.pools.read().await;
        let pool = pools.get(pool_name)
            .ok_or_else(|| McpError::Other(format!("Pool not found: {}", pool_name)))?;
        
        // Filter healthy servers
        let healthy_indices: Vec<usize> = stream::iter(pool.servers.iter().enumerate())
            .filter_map(|(i, server)| async move {
                if server.state().await == ServerState::Healthy {
                    Some(i)
                } else {
                    None
                }
            })
            .collect()
            .await;
        
        if healthy_indices.is_empty() {
            return Err(McpError::Other("No healthy servers in pool".to_string()));
        }
        
        // Select based on algorithm
        let selected_index = match self.algorithm {
            LoadBalancingAlgorithm::RoundRobin => {
                self.round_robin_select(pool_name, &healthy_indices).await
            }
            LoadBalancingAlgorithm::LeastConnections => {
                self.least_connections_select(pool, &healthy_indices)
            }
            LoadBalancingAlgorithm::WeightedRoundRobin => {
                self.weighted_round_robin_select(pool_name, pool, &healthy_indices).await
            }
            LoadBalancingAlgorithm::Random => {
                self.random_select(&healthy_indices)
            }
            LoadBalancingAlgorithm::IpHash => {
                self.ip_hash_select(client_ip, &healthy_indices)
            }
            LoadBalancingAlgorithm::LeastResponseTime => {
                self.least_response_time_select(pool, &healthy_indices)
            }
        };
        
        Ok(pool.servers[selected_index].clone())
    }

    /// Update connection count
    pub async fn update_connections(&self, pool_name: &str, server_id: &str, delta: i32) -> Result<()> {
        let mut pools = self.pools.write().await;
        
        if let Some(pool) = pools.get_mut(pool_name) {
            if let Some(pos) = pool.servers.iter().position(|s| s.id() == server_id) {
                if delta > 0 {
                    pool.connections[pos] += delta as usize;
                } else {
                    pool.connections[pos] = pool.connections[pos].saturating_sub((-delta) as usize);
                }
                Ok(())
            } else {
                Err(McpError::ServerNotFound(server_id.to_string()))
            }
        } else {
            Err(McpError::Other(format!("Pool not found: {}", pool_name)))
        }
    }

    /// Update response time
    pub async fn update_response_time(&self, pool_name: &str, server_id: &str, response_time: f64) -> Result<()> {
        let mut pools = self.pools.write().await;
        
        if let Some(pool) = pools.get_mut(pool_name) {
            if let Some(pos) = pool.servers.iter().position(|s| s.id() == server_id) {
                // Exponential moving average
                let alpha = 0.3;
                pool.response_times[pos] = alpha * response_time + (1.0 - alpha) * pool.response_times[pos];
                Ok(())
            } else {
                Err(McpError::ServerNotFound(server_id.to_string()))
            }
        } else {
            Err(McpError::Other(format!("Pool not found: {}", pool_name)))
        }
    }

    /// Round-robin selection
    async fn round_robin_select(&self, pool_name: &str, healthy_indices: &[usize]) -> usize {
        let mut indices = self.rr_indices.write().await;
        let current = indices.entry(pool_name.to_string()).or_insert(0);
        
        let selected = healthy_indices[*current % healthy_indices.len()];
        *current = (*current + 1) % healthy_indices.len();
        
        selected
    }

    /// Least connections selection
    fn least_connections_select(&self, pool: &ServerPool, healthy_indices: &[usize]) -> usize {
        healthy_indices.iter()
            .min_by_key(|&&i| pool.connections[i])
            .copied()
            .unwrap_or(healthy_indices[0])
    }

    /// Weighted round-robin selection
    async fn weighted_round_robin_select(&self, pool_name: &str, pool: &ServerPool, healthy_indices: &[usize]) -> usize {
        let mut indices = self.rr_indices.write().await;
        let current = indices.entry(pool_name.to_string()).or_insert(0);
        
        // Calculate total weight
        let total_weight: u32 = healthy_indices.iter()
            .map(|&i| pool.weights[i])
            .sum();
        
        // Find server based on weight
        let mut weight_sum = 0;
        let target = *current % total_weight;
        
        for &i in healthy_indices {
            weight_sum += pool.weights[i];
            if target < weight_sum {
                *current = (*current + 1) % total_weight;
                return i;
            }
        }
        
        healthy_indices[0]
    }

    /// Random selection
    fn random_select(&self, healthy_indices: &[usize]) -> usize {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        healthy_indices[rng.gen_range(0..healthy_indices.len())]
    }

    /// IP hash selection
    fn ip_hash_select(&self, client_ip: Option<&str>, healthy_indices: &[usize]) -> usize {
        if let Some(ip) = client_ip {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            
            let mut hasher = DefaultHasher::new();
            ip.hash(&mut hasher);
            let hash = hasher.finish();
            
            healthy_indices[(hash as usize) % healthy_indices.len()]
        } else {
            // Fallback to first healthy server
            healthy_indices[0]
        }
    }

    /// Least response time selection
    fn least_response_time_select(&self, pool: &ServerPool, healthy_indices: &[usize]) -> usize {
        healthy_indices.iter()
            .min_by(|&&a, &&b| {
                pool.response_times[a].partial_cmp(&pool.response_times[b])
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .copied()
            .unwrap_or(healthy_indices[0])
    }

    /// Get pool statistics
    pub async fn pool_stats(&self, pool_name: &str) -> Result<PoolStats> {
        let pools = self.pools.read().await;
        let pool = pools.get(pool_name)
            .ok_or_else(|| McpError::Other(format!("Pool not found: {}", pool_name)))?;
        
        let total_servers = pool.servers.len();
        let healthy_servers = stream::iter(pool.servers.iter())
            .filter(|server| async move {
                server.state().await == ServerState::Healthy
            })
            .count()
            .await;
        
        let total_connections: usize = pool.connections.iter().sum();
        let avg_response_time = if pool.response_times.is_empty() {
            0.0
        } else {
            pool.response_times.iter().sum::<f64>() / pool.response_times.len() as f64
        };
        
        Ok(PoolStats {
            total_servers,
            healthy_servers,
            total_connections,
            avg_response_time,
        })
    }
}

use futures::stream::{self, StreamExt};

/// Pool statistics
#[derive(Debug, Clone)]
pub struct PoolStats {
    /// Total servers in pool
    pub total_servers: usize,
    /// Healthy servers
    pub healthy_servers: usize,
    /// Total active connections
    pub total_connections: usize,
    /// Average response time
    pub avg_response_time: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_manager::config::{ServerConfig, ServerType, AuthConfig};
    use std::time::Duration;

    fn create_test_server(id: &str) -> Arc<McpServer> {
        let config = ServerConfig {
            name: format!("test-{}", id),
            server_type: ServerType::Infrastructure,
            url: "http://localhost:8080".to_string(),
            auth: Some(AuthConfig::ApiKey {
                key: "test-key".to_string(),
            }),
            timeout: Some(Duration::from_secs(30)),
            max_retries: 3,
            priority: 10,
            tags: vec![],
        };
        
        Arc::new(McpServer::new(id.to_string(), config).unwrap())
    }

    #[tokio::test]
    async fn test_round_robin() {
        let lb = LoadBalancer::new(LoadBalancingAlgorithm::RoundRobin);
        
        // Add servers
        for i in 0..3 {
            let server = create_test_server(&format!("server-{}", i));
            lb.add_server("test-pool".to_string(), server, 1).await;
        }
        
        // Test round-robin selection
        let server1 = lb.select_server("test-pool", None).await.unwrap();
        let server2 = lb.select_server("test-pool", None).await.unwrap();
        
        assert_ne!(server1.id(), server2.id());
    }

    #[tokio::test]
    async fn test_least_connections() {
        let lb = LoadBalancer::new(LoadBalancingAlgorithm::LeastConnections);
        
        // Add servers
        for i in 0..3 {
            let server = create_test_server(&format!("server-{}", i));
            lb.add_server("test-pool".to_string(), server, 1).await;
        }
        
        // Update connections
        lb.update_connections("test-pool", "server-0", 5).await.unwrap();
        lb.update_connections("test-pool", "server-1", 2).await.unwrap();
        
        // Should select server-2 (0 connections)
        let server = lb.select_server("test-pool", None).await.unwrap();
        assert_eq!(server.id(), "server-2");
    }

    #[tokio::test]
    async fn test_ip_hash() {
        let lb = LoadBalancer::new(LoadBalancingAlgorithm::IpHash);
        
        // Add servers
        for i in 0..3 {
            let server = create_test_server(&format!("server-{}", i));
            lb.add_server("test-pool".to_string(), server, 1).await;
        }
        
        // Same IP should always get same server
        let server1 = lb.select_server("test-pool", Some("192.168.1.1")).await.unwrap();
        let server2 = lb.select_server("test-pool", Some("192.168.1.1")).await.unwrap();
        
        assert_eq!(server1.id(), server2.id());
    }
}