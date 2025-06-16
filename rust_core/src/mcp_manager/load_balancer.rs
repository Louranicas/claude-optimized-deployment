use crate::mcp_manager::{
    error::{MCPError, MCPResult},
    server::MCPServer,
    protocol::MCPRequest,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use rand::Rng;

/// Load balancing strategies
#[derive(Debug, Clone, PartialEq)]
pub enum LoadBalancingStrategy {
    RoundRobin,
    Random,
    LeastConnections,
    WeightedRoundRobin,
    ResponseTime,
    Hash,
}

/// Load balancer for distributing requests
pub struct LoadBalancer {
    strategy: LoadBalancingStrategy,
    round_robin_counter: AtomicUsize,
}

impl LoadBalancer {
    /// Create a new load balancer
    pub fn new(strategy: LoadBalancingStrategy) -> Self {
        Self {
            strategy,
            round_robin_counter: AtomicUsize::new(0),
        }
    }
    
    /// Select a server based on the configured strategy
    pub async fn select_server(
        &self,
        servers: &[MCPServer],
        request: &MCPRequest,
    ) -> MCPResult<MCPServer> {
        if servers.is_empty() {
            return Err(MCPError::LoadBalancing("No servers available".to_string()));
        }
        
        match self.strategy {
            LoadBalancingStrategy::RoundRobin => self.round_robin(servers),
            LoadBalancingStrategy::Random => self.random(servers),
            LoadBalancingStrategy::LeastConnections => self.least_connections(servers),
            LoadBalancingStrategy::WeightedRoundRobin => self.weighted_round_robin(servers),
            LoadBalancingStrategy::ResponseTime => self.response_time(servers),
            LoadBalancingStrategy::Hash => self.hash_based(servers, request),
        }
    }
    
    /// Synchronous version for testing
    #[cfg(test)]
    pub fn select_server_sync(&self, servers: &[MCPServer]) -> Option<MCPServer> {
        let request = MCPRequest::new("test", serde_json::json!({}));
        futures::executor::block_on(async {
            self.select_server(servers, &request).ok()
        })
    }
    
    /// Round-robin selection
    fn round_robin(&self, servers: &[MCPServer]) -> MCPResult<MCPServer> {
        let index = self.round_robin_counter.fetch_add(1, Ordering::Relaxed) % servers.len();
        Ok(servers[index].clone())
    }
    
    /// Random selection
    fn random(&self, servers: &[MCPServer]) -> MCPResult<MCPServer> {
        let mut rng = rand::thread_rng();
        let index = rng.gen_range(0..servers.len());
        Ok(servers[index].clone())
    }
    
    /// Least connections selection
    fn least_connections(&self, servers: &[MCPServer]) -> MCPResult<MCPServer> {
        servers
            .iter()
            .min_by_key(|s| s.connection_count())
            .cloned()
            .ok_or_else(|| MCPError::LoadBalancing("No servers available".to_string()))
    }
    
    /// Weighted round-robin selection
    fn weighted_round_robin(&self, servers: &[MCPServer]) -> MCPResult<MCPServer> {
        // Calculate total weight
        let total_weight: u32 = servers.iter().map(|s| s.weight()).sum();
        
        if total_weight == 0 {
            return self.round_robin(servers);
        }
        
        // Generate random number in weight range
        let mut rng = rand::thread_rng();
        let mut random_weight = rng.gen_range(0..total_weight);
        
        // Find server based on weight
        for server in servers {
            let weight = server.weight();
            if random_weight < weight {
                return Ok(server.clone());
            }
            random_weight -= weight;
        }
        
        // Fallback to first server
        Ok(servers[0].clone())
    }
    
    /// Response time based selection (selects server with best response time)
    fn response_time(&self, servers: &[MCPServer]) -> MCPResult<MCPServer> {
        // In a real implementation, this would track actual response times
        // For now, use error rate as a proxy
        servers
            .iter()
            .min_by_key(|s| {
                let requests = s.request_count();
                let errors = s.error_count();
                if requests > 0 {
                    (errors * 1000) / requests // Error rate per 1000 requests
                } else {
                    0
                }
            })
            .cloned()
            .ok_or_else(|| MCPError::LoadBalancing("No servers available".to_string()))
    }
    
    /// Hash-based selection (consistent hashing)
    fn hash_based(&self, servers: &[MCPServer], request: &MCPRequest) -> MCPResult<MCPServer> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        request.method.hash(&mut hasher);
        request.id.hash(&mut hasher);
        
        let hash = hasher.finish();
        let index = (hash as usize) % servers.len();
        
        Ok(servers[index].clone())
    }
    
    /// Update strategy
    pub fn set_strategy(&mut self, strategy: LoadBalancingStrategy) {
        self.strategy = strategy;
    }
    
    /// Get current strategy
    pub fn strategy(&self) -> &LoadBalancingStrategy {
        &self.strategy
    }
}