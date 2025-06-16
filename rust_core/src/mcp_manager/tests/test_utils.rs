use crate::mcp_manager::{
    config::MCPConfig,
    core::MCPManager,
    server::{MCPServer, ServerState},
    protocol::{MCPConnection, MCPRequest, MCPResponse, MCPProtocol},
    error::{MCPError, MCPResult},
    metrics::MCPMetrics,
};
use async_trait::async_trait;
use std::sync::{Arc, atomic::{AtomicU64, AtomicBool, Ordering}};
use std::collections::HashMap;
use tokio::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

/// Create a test configuration with sensible defaults
pub fn create_test_config() -> MCPConfig {
    MCPConfig {
        max_connections_per_server: 5,
        connection_timeout_ms: 1000,
        request_timeout_ms: 5000,
        health_check_interval_secs: 60,
        max_retries: 2,
        retry_backoff_multiplier: 1.5,
        enable_connection_pooling: true,
        enable_load_balancing: true,
        enable_health_checks: true,
        enable_metrics: true,
        circuit_breaker_threshold: 3,
        circuit_breaker_recovery_secs: 30,
    }
}

/// Create a mock MCP server for testing
pub fn create_mock_server(id: &str) -> MCPServer {
    MCPServer::new(
        id.to_string(),
        format!("mock://{}:8080", id),
        MCPProtocol::Http,
        HashMap::new(),
    )
}

/// Create a test MCP manager instance
pub fn create_test_manager() -> MCPManager {
    MCPManager::new(create_test_config())
}

/// Mock MCP connection for testing
#[derive(Clone)]
pub struct MockMCPConnection {
    pub server_id: String,
    pub latency_ms: Arc<AtomicU64>,
    pub fail_rate: Arc<Mutex<f64>>,
    pub is_connected: Arc<AtomicBool>,
    pub request_count: Arc<AtomicU64>,
    pub response_map: Arc<RwLock<HashMap<String, MCPResponse>>>,
    pub connection_delay_ms: Arc<AtomicU64>,
}

impl MockMCPConnection {
    pub fn new(server_id: String) -> Self {
        let mut response_map = HashMap::new();
        response_map.insert(
            "ping".to_string(),
            MCPResponse::success("pong".to_string()),
        );
        
        Self {
            server_id,
            latency_ms: Arc::new(AtomicU64::new(10)),
            fail_rate: Arc::new(Mutex::new(0.0)),
            is_connected: Arc::new(AtomicBool::new(true)),
            request_count: Arc::new(AtomicU64::new(0)),
            response_map: Arc::new(RwLock::new(response_map)),
            connection_delay_ms: Arc::new(AtomicU64::new(50)),
        }
    }
    
    pub fn set_latency(&self, ms: u64) {
        self.latency_ms.store(ms, Ordering::Relaxed); // TODO: Review memory ordering - consider Acquire/Release
    }
    
    pub async fn set_fail_rate(&self, rate: f64) {
        *self.fail_rate.lock().await = rate.clamp(0.0, 1.0);
    }
    
    pub fn disconnect(&self) {
        self.is_connected.store(false, Ordering::Relaxed); // TODO: Review memory ordering - consider Acquire/Release
    }
    
    pub fn connect(&self) {
        self.is_connected.store(true, Ordering::Relaxed); // TODO: Review memory ordering - consider Acquire/Release
    }
    
    pub async fn add_response(&self, method: &str, response: MCPResponse) {
        self.response_map.write().await.insert(method.to_string(), response);
    }
    
    pub fn get_request_count(&self) -> u64 {
        self.request_count.load(Ordering::Relaxed)} // TODO: Review memory ordering - consider Acquire/Release
}

#[async_trait]
impl MCPConnection for MockMCPConnection {
    async fn connect(&self, _timeout: Duration) -> MCPResult<()> {
        let delay = self.connection_delay_ms.load(Ordering::Relaxed); // TODO: Review memory ordering - consider Acquire/Release
        tokio::time::sleep(Duration::from_millis(delay)).await;
        
        if self.is_connected.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release{
            Ok(())
        } else {
            Err(MCPError::Connection("Mock connection failed".to_string()))
        }
    }
    
    async fn disconnect(&self) -> MCPResult<()> {
        self.is_connected.store(false, Ordering::Relaxed); // TODO: Review memory ordering - consider Acquire/Release
        Ok(())
    }
    
    async fn send_request(&self, request: MCPRequest) -> MCPResult<MCPResponse> {
        self.request_count.fetch_add(1, Ordering::Relaxed);
        
        // Check if connected
        if !self.is_connected.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release{
            return Err(MCPError::Connection("Not connected".to_string()));
        }
        
        // Simulate network latency
        let latency = self.latency_ms.load(Ordering::Relaxed); // TODO: Review memory ordering - consider Acquire/Release
        tokio::time::sleep(Duration::from_millis(latency)).await;
        
        // Simulate failures based on fail rate
        let fail_rate = *self.fail_rate.lock().await;
        if fail_rate > 0.0 && rand::random::<f64>() < fail_rate {
            return Err(MCPError::Connection("Simulated failure".to_string()));
        }
        
        // Return predefined response or default
        let response_map = self.response_map.read().await;
        if let Some(response) = response_map.get(&request.method) {
            Ok(response.clone())
        } else {
            Ok(MCPResponse::success(format!("Mock response for {}", request.method)))
        }
    }
    
    fn is_connected(&self) -> bool {
        self.is_connected.load(Ordering::Relaxed)} // TODO: Review memory ordering - consider Acquire/Release
}

/// Test metrics collector for assertions
pub struct TestMetricsCollector {
    pub request_counts: Arc<RwLock<HashMap<String, u64>>>,
    pub error_counts: Arc<RwLock<HashMap<String, u64>>>,
    pub latencies: Arc<RwLock<Vec<Duration>>>,
    pub server_states: Arc<RwLock<HashMap<String, ServerState>>>,
}

impl TestMetricsCollector {
    pub fn new() -> Self {
        Self {
            request_counts: Arc::new(RwLock::new(HashMap::new())),
            error_counts: Arc::new(RwLock::new(HashMap::new())),
            latencies: Arc::new(RwLock::new(Vec::new())),
            server_states: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    pub async fn record_request(&self, server_id: &str, latency: Duration, success: bool) {
        let mut counts = self.request_counts.write().await;
        *counts.entry(server_id.to_string()).or_insert(0) += 1;
        
        if !success {
            let mut errors = self.error_counts.write().await;
            *errors.entry(server_id.to_string()).or_insert(0) += 1;
        }
        
        self.latencies.write().await.push(latency);
    }
    
    pub async fn get_request_count(&self, server_id: &str) -> u64 {
        self.request_counts.read().await.get(server_id).copied().unwrap_or(0)
    }
    
    pub async fn get_error_count(&self, server_id: &str) -> u64 {
        self.error_counts.read().await.get(server_id).copied().unwrap_or(0)
    }
    
    pub async fn get_average_latency(&self) -> Option<Duration> {
        let latencies = self.latencies.read().await;
        if latencies.is_empty() {
            None
        } else {
            let sum: Duration = latencies.iter().sum();
            Some(sum / latencies.len() as u32)
        }
    }
    
    pub async fn update_server_state(&self, server_id: &str, state: ServerState) {
        self.server_states.write().await.insert(server_id.to_string(), state);
    }
}

/// Generate load for stress testing
pub async fn generate_load<F>(
    duration: Duration,
    requests_per_second: u32,
    request_fn: F,
) where
    F: Fn() -> MCPRequest + Send + Sync + 'static,
{
    let start = Instant::now();
    let interval = Duration::from_millis(1000 / requests_per_second as u64);
    
    while start.elapsed() < duration {
        let request = request_fn();
        tokio::spawn(async move {
            // Request will be handled by the test
            drop(request);
        });
        
        tokio::time::sleep(interval).await;
    }
}

/// Chaos injection for fault tolerance testing
pub struct ChaosInjector {
    pub network_delay: Arc<AtomicU64>,
    pub packet_loss_rate: Arc<Mutex<f64>>,
    pub connection_drop_rate: Arc<Mutex<f64>>,
    pub cpu_spike_duration: Arc<AtomicU64>,
}

impl ChaosInjector {
    pub fn new() -> Self {
        Self {
            network_delay: Arc::new(AtomicU64::new(0)),
            packet_loss_rate: Arc::new(Mutex::new(0.0)),
            connection_drop_rate: Arc::new(Mutex::new(0.0)),
            cpu_spike_duration: Arc::new(AtomicU64::new(0)),
        }
    }
    
    pub async fn inject_network_delay(&self, delay_ms: u64) {
        self.network_delay.store(delay_ms, Ordering::Relaxed); // TODO: Review memory ordering - consider Acquire/Release
    }
    
    pub async fn inject_packet_loss(&self, rate: f64) {
        *self.packet_loss_rate.lock().await = rate.clamp(0.0, 1.0);
    }
    
    pub async fn inject_connection_drops(&self, rate: f64) {
        *self.connection_drop_rate.lock().await = rate.clamp(0.0, 1.0);
    }
    
    pub async fn inject_cpu_spike(&self, duration_ms: u64) {
        self.cpu_spike_duration.store(duration_ms, Ordering::Relaxed); // TODO: Review memory ordering - consider Acquire/Release
        
        // Simulate CPU spike
        tokio::spawn(async move {
            let start = Instant::now();
            while start.elapsed() < Duration::from_millis(duration_ms) {
                // Busy loop to consume CPU
                for _ in 0..1000000 {
                    std::hint::black_box(42);
                }
                tokio::task::yield_now().await;
            }
        });
    }
    
    pub async fn reset(&self) {
        self.network_delay.store(0, Ordering::Relaxed); // TODO: Review memory ordering - consider Acquire/Release
        *self.packet_loss_rate.lock().await = 0.0;
        *self.connection_drop_rate.lock().await = 0.0;
        self.cpu_spike_duration.store(0, Ordering::Relaxed); // TODO: Review memory ordering - consider Acquire/Release
    }
}