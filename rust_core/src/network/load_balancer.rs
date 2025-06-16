//! Load balancer implementation
//! 
//! Provides various load balancing algorithms with health checking
//! and connection management.

use super::*;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use parking_lot::RwLock as ParkingLotRwLock;
use tracing::{debug, warn, instrument};
use crate::orchestrator::{LoadBalancerConfig, LoadBalancingAlgorithm};
use std::collections::HashMap;

/// Load balancer backend
#[derive(Debug, Clone)]
pub struct LoadBalancerBackend {
    pub id: Uuid,
    pub address: SocketAddr,
    pub weight: u32,
    pub is_healthy: Arc<ParkingLotRwLock<bool>>,
    pub active_connections: Arc<AtomicUsize>,
    pub total_requests: Arc<AtomicU64>,
    pub failed_requests: Arc<AtomicU64>,
    pub last_selected: Arc<ParkingLotRwLock<chrono::DateTime<chrono::Utc>>>,
}

impl LoadBalancerBackend {
    /// Create a new backend
    pub fn new(address: SocketAddr, weight: u32) -> Self {
        Self {
            id: Uuid::new_v4(),
            address,
            weight,
            is_healthy: Arc::new(ParkingLotRwLock::new(true)),
            active_connections: Arc::new(AtomicUsize::new(0)),
            total_requests: Arc::new(AtomicU64::new(0)),
            failed_requests: Arc::new(AtomicU64::new(0)),
            last_selected: Arc::new(ParkingLotRwLock::new(chrono::Utc::now())),
        }
    }
    
    /// Mark backend as healthy/unhealthy
    pub fn set_healthy(&self, healthy: bool) {
        let mut is_healthy = self.is_healthy.write();
        *is_healthy = healthy;
    }
    
    /// Check if backend is healthy
    pub fn is_healthy(&self) -> bool {
        *self.is_healthy.read()
    }
    
    /// Get current connections
    pub fn connections(&self) -> usize {
        self.active_connections.load(Ordering::SeqCst)
    }
    
    /// Increment connection count
    pub fn inc_connections(&self) {
        self.active_connections.fetch_add(1, Ordering::SeqCst);
        self.total_requests.fetch_add(1, Ordering::SeqCst);
    }
    
    /// Decrement connection count
    pub fn dec_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::SeqCst);
    }
    
    /// Record failed request
    pub fn record_failure(&self) {
        self.failed_requests.fetch_add(1, Ordering::SeqCst);
    }
    
    /// Get failure rate
    pub fn failure_rate(&self) -> f64 {
        let total = self.total_requests.load(Ordering::SeqCst);
        let failed = self.failed_requests.load(Ordering::SeqCst);
        
        if total > 0 {
            failed as f64 / total as f64
        } else {
            0.0
        }
    }
}

/// Load balancer state
struct LoadBalancerState {
    round_robin_index: AtomicUsize,
    ip_hash_cache: ParkingLotRwLock<HashMap<IpAddr, Uuid>>,
}

/// Load balancer implementation
pub struct LoadBalancer {
    config: LoadBalancerConfig,
    backends: Arc<ParkingLotRwLock<Vec<LoadBalancerBackend>>>,
    state: Arc<LoadBalancerState>,
    stats: Arc<ParkingLotRwLock<LoadBalancerStats>>,
}

/// Load balancer statistics
#[derive(Debug, Default)]
struct LoadBalancerStats {
    total_requests: u64,
    successful_requests: u64,
    failed_requests: u64,
    average_response_time_ms: f64,
    requests_per_second: f64,
}

impl LoadBalancer {
    /// Create a new load balancer
    pub fn new(config: LoadBalancerConfig) -> Self {
        Self {
            config,
            backends: Arc::new(ParkingLotRwLock::new(Vec::new())),
            state: Arc::new(LoadBalancerState {
                round_robin_index: AtomicUsize::new(0),
                ip_hash_cache: ParkingLotRwLock::new(HashMap::new()),
            }),
            stats: Arc::new(ParkingLotRwLock::new(LoadBalancerStats::default())),
        }
    }
    
    /// Add a backend
    pub fn add_backend(&self, address: SocketAddr, weight: u32) -> Uuid {
        let backend = LoadBalancerBackend::new(address, weight);
        let backend_id = backend.id;
        
        let mut backends = self.backends.write();
        backends.push(backend);
        
        debug!("Added backend {} with weight {}", address, weight);
        
        backend_id
    }
    
    /// Remove a backend
    pub fn remove_backend(&self, backend_id: Uuid) -> bool {
        let mut backends = self.backends.write();
        let initial_len = backends.len();
        backends.retain(|b| b.id != backend_id);
        
        let removed = backends.len() < initial_len;
        if removed {
            debug!("Removed backend {}", backend_id);
        }
        
        removed
    }
    
    /// Select a backend based on the configured algorithm
    #[instrument(skip(self))]
    pub fn select_backend(&self, client_ip: Option<IpAddr>) -> Option<LoadBalancerBackend> {
        let backends = self.backends.read();
        
        // Filter healthy backends
        let healthy_backends: Vec<_> = backends.iter()
            .filter(|b| b.is_healthy())
            .cloned()
            .collect();
        
        if healthy_backends.is_empty() {
            warn!("No healthy backends available");
            return None;
        }
        
        let selected = match self.config.algorithm {
            LoadBalancingAlgorithm::RoundRobin => self.round_robin(&healthy_backends),
            LoadBalancingAlgorithm::LeastConnections => self.least_connections(&healthy_backends),
            LoadBalancingAlgorithm::WeightedRoundRobin => self.weighted_round_robin(&healthy_backends),
            LoadBalancingAlgorithm::Random => self.random(&healthy_backends),
            LoadBalancingAlgorithm::IpHash => {
                if let Some(ip) = client_ip {
                    self.ip_hash(&healthy_backends, ip)
                } else {
                    self.random(&healthy_backends)
                }
            }
        };
        
        if let Some(backend) = &selected {
            backend.inc_connections();
            let mut last_selected = backend.last_selected.write();
            *last_selected = chrono::Utc::now();
            
            let mut stats = self.stats.write();
            stats.total_requests += 1;
        }
        
        selected
    }
    
    /// Round-robin selection
    fn round_robin(&self, backends: &[LoadBalancerBackend]) -> Option<LoadBalancerBackend> {
        if backends.is_empty() {
            return None;
        }
        
        let index = self.state.round_robin_index.fetch_add(1, Ordering::SeqCst) % backends.len();
        Some(backends[index].clone())
    }
    
    /// Least connections selection
    fn least_connections(&self, backends: &[LoadBalancerBackend]) -> Option<LoadBalancerBackend> {
        backends.iter()
            .min_by_key(|b| b.connections())
            .cloned()
    }
    
    /// Weighted round-robin selection
    fn weighted_round_robin(&self, backends: &[LoadBalancerBackend]) -> Option<LoadBalancerBackend> {
        if backends.is_empty() {
            return None;
        }
        
        let total_weight: u32 = backends.iter().map(|b| b.weight).sum();
        if total_weight == 0 {
            return self.round_robin(backends);
        }
        
        let mut rng = rand::thread_rng();
        let mut random_weight = rand::Rng::gen_range(&mut rng, 0..total_weight);
        
        for backend in backends {
            if random_weight < backend.weight {
                return Some(backend.clone());
            }
            random_weight -= backend.weight;
        }
        
        backends.last().cloned()
    }
    
    /// Random selection
    fn random(&self, backends: &[LoadBalancerBackend]) -> Option<LoadBalancerBackend> {
        if backends.is_empty() {
            return None;
        }
        
        let mut rng = rand::thread_rng();
        let index = rand::Rng::gen_range(&mut rng, 0..backends.len());
        Some(backends[index].clone())
    }
    
    /// IP hash selection
    fn ip_hash(&self, backends: &[LoadBalancerBackend], client_ip: IpAddr) -> Option<LoadBalancerBackend> {
        if backends.is_empty() {
            return None;
        }
        
        // Check cache first
        {
            let cache = self.state.ip_hash_cache.read();
            if let Some(backend_id) = cache.get(&client_ip) {
                if let Some(backend) = backends.iter().find(|b| &b.id == backend_id) {
                    if backend.is_healthy() {
                        return Some(backend.clone());
                    }
                }
            }
        }
        
        // Hash IP to select backend
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        client_ip.hash(&mut hasher);
        let hash = hasher.finish();
        let index = (hash % backends.len() as u64) as usize;
        
        let selected = backends[index].clone();
        
        // Update cache
        {
            let mut cache = self.state.ip_hash_cache.write();
            cache.insert(client_ip, selected.id);
            
            // Limit cache size
            if cache.len() > 10000 {
                cache.clear();
            }
        }
        
        Some(selected)
    }
    
    /// Release a connection
    pub fn release_connection(&self, backend_id: Uuid, success: bool) {
        let backends = self.backends.read();
        
        if let Some(backend) = backends.iter().find(|b| b.id == backend_id) {
            backend.dec_connections();
            
            if !success {
                backend.record_failure();
            }
            
            let mut stats = self.stats.write();
            if success {
                stats.successful_requests += 1;
            } else {
                stats.failed_requests += 1;
            }
        }
    }
    
    /// Perform health check on all backends
    pub async fn health_check(&self) {
        let backends = self.backends.read().clone();
        
        for backend in backends {
            let is_healthy = self.check_backend_health(&backend).await;
            backend.set_healthy(is_healthy);
            
            if !is_healthy {
                warn!("Backend {} is unhealthy", backend.address);
            }
        }
    }
    
    /// Check individual backend health
    async fn check_backend_health(&self, backend: &LoadBalancerBackend) -> bool {
        // Simple TCP connection check
        use tokio::net::TcpStream;
        use tokio::time::timeout;
        
        let result = timeout(
            std::time::Duration::from_secs(5),
            TcpStream::connect(backend.address)
        ).await;
        
        match result {
            Ok(Ok(_)) => true,
            _ => false,
        }
    }
    
    /// Get load balancer statistics
    pub fn get_stats(&self) -> LoadBalancerStatsReport {
        let stats = self.stats.read();
        let backends = self.backends.read();
        
        let backend_stats: Vec<_> = backends.iter().map(|b| {
            BackendStats {
                id: b.id,
                address: b.address,
                is_healthy: b.is_healthy(),
                active_connections: b.connections(),
                total_requests: b.total_requests.load(Ordering::SeqCst),
                failure_rate: b.failure_rate(),
            }
        }).collect();
        
        LoadBalancerStatsReport {
            algorithm: self.config.algorithm,
            total_backends: backends.len(),
            healthy_backends: backends.iter().filter(|b| b.is_healthy()).count(),
            total_requests: stats.total_requests,
            successful_requests: stats.successful_requests,
            failed_requests: stats.failed_requests,
            success_rate: if stats.total_requests > 0 {
                stats.successful_requests as f64 / stats.total_requests as f64
            } else {
                0.0
            },
            backends: backend_stats,
        }
    }
}

/// Load balancer statistics report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancerStatsReport {
    pub algorithm: LoadBalancingAlgorithm,
    pub total_backends: usize,
    pub healthy_backends: usize,
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub success_rate: f64,
    pub backends: Vec<BackendStats>,
}

/// Backend statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendStats {
    pub id: Uuid,
    pub address: SocketAddr,
    pub is_healthy: bool,
    pub active_connections: usize,
    pub total_requests: u64,
    pub failure_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    
    #[test]
    fn test_round_robin() {
        let config = LoadBalancerConfig {
            algorithm: LoadBalancingAlgorithm::RoundRobin,
            health_check_interval_secs: 30,
            max_connections: 1000,
            sticky_sessions: false,
        };
        
        let lb = LoadBalancer::new(config);
        
        // Add backends
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 8080);
        
        lb.add_backend(addr1, 100);
        lb.add_backend(addr2, 100);
        
        // Test round-robin selection
        let selections: Vec<_> = (0..4)
            .filter_map(|_| lb.select_backend(None))
            .map(|b| b.address)
            .collect();
        
        assert_eq!(selections.len(), 4);
        assert_eq!(selections[0], addr1);
        assert_eq!(selections[1], addr2);
        assert_eq!(selections[2], addr1);
        assert_eq!(selections[3], addr2);
    }
    
    #[test]
    fn test_least_connections() {
        let config = LoadBalancerConfig {
            algorithm: LoadBalancingAlgorithm::LeastConnections,
            health_check_interval_secs: 30,
            max_connections: 1000,
            sticky_sessions: false,
        };
        
        let lb = LoadBalancer::new(config);
        
        // Add backends
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 8080);
        
        let id1 = lb.add_backend(addr1, 100);
        let id2 = lb.add_backend(addr2, 100);
        
        // Select first backend
        let selected1 = lb.select_backend(None).unwrap();
        assert_eq!(selected1.connections(), 1);
        
        // Next selection should go to the other backend
        let selected2 = lb.select_backend(None).unwrap();
        assert_ne!(selected1.id, selected2.id);
        
        // Release one connection
        lb.release_connection(selected1.id, true);
        
        // Next selection should go to the first backend again
        let selected3 = lb.select_backend(None).unwrap();
        assert_eq!(selected3.id, selected1.id);
    }
    
    #[test]
    fn test_ip_hash() {
        let config = LoadBalancerConfig {
            algorithm: LoadBalancingAlgorithm::IpHash,
            health_check_interval_secs: 30,
            max_connections: 1000,
            sticky_sessions: true,
        };
        
        let lb = LoadBalancer::new(config);
        
        // Add backends
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 8080);
        
        lb.add_backend(addr1, 100);
        lb.add_backend(addr2, 100);
        
        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        
        // Multiple requests from same IP should go to same backend
        let selections: Vec<_> = (0..5)
            .filter_map(|_| lb.select_backend(Some(client_ip)))
            .map(|b| b.id)
            .collect();
        
        assert!(selections.windows(2).all(|w| w[0] == w[1]));
    }
}