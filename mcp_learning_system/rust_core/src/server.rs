//! MCP Server Core Implementation
//! 
//! High-performance async server implementation with sub-microsecond request processing.

use async_trait::async_trait;
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use anyhow::Result;
use tracing::{instrument, trace};

use crate::memory::MemoryPool;
use crate::state::StateManager;
use crate::messaging::MessageQueue;

/// MCP Request structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub id: u64,
    pub method: String,
    pub params: serde_json::Value,
    pub timestamp: u64,
}

/// MCP Response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub id: u64,
    pub result: serde_json::Value,
    pub error: Option<String>,
    pub processing_time_us: u64,
}

/// Server metrics
#[derive(Debug, Clone, Default)]
pub struct Metrics {
    pub total_requests: u64,
    pub total_errors: u64,
    pub avg_latency_us: f64,
    pub p99_latency_us: u64,
    pub memory_usage_mb: f64,
}

/// Core MCP Server trait
#[async_trait]
pub trait MCPServer: Send + Sync {
    /// Process a request with sub-microsecond latency target
    async fn process_request(&self, req: Request) -> Result<Response>;
    
    /// Update server state
    async fn update_state(&self, state: StateUpdate) -> Result<()>;
    
    /// Get current metrics
    fn get_metrics(&self) -> Metrics;
}

/// State update structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateUpdate {
    pub key: String,
    pub value: serde_json::Value,
    pub operation: UpdateOperation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UpdateOperation {
    Set,
    Merge,
    Delete,
}

/// High-performance MCP Server implementation
pub struct HighPerfMCPServer {
    memory_pool: Arc<MemoryPool>,
    state_manager: Arc<StateManager>,
    message_queue: Arc<MessageQueue<Request>>,
    metrics: Arc<RwLock<InternalMetrics>>,
    handlers: Arc<DashMap<String, Handler>>,
}

type Handler = Arc<dyn Fn(Request) -> Response + Send + Sync>;

struct InternalMetrics {
    total_requests: u64,
    total_errors: u64,
    latencies: Vec<u64>,
}

impl HighPerfMCPServer {
    /// Create a new high-performance MCP server
    pub fn new(memory_size_mb: usize) -> Result<Self> {
        let memory_pool = Arc::new(MemoryPool::new(memory_size_mb)?);
        let state_manager = Arc::new(StateManager::new());
        let message_queue = Arc::new(MessageQueue::new());
        
        Ok(Self {
            memory_pool,
            state_manager,
            message_queue,
            metrics: Arc::new(RwLock::new(InternalMetrics {
                total_requests: 0,
                total_errors: 0,
                latencies: Vec::with_capacity(10000),
            })),
            handlers: Arc::new(DashMap::new()),
        })
    }
    
    /// Register a method handler
    pub fn register_handler<F>(&self, method: String, handler: F)
    where
        F: Fn(Request) -> Response + Send + Sync + 'static,
    {
        self.handlers.insert(method, Arc::new(handler));
    }
    
    /// Process request with minimal overhead
    #[inline(always)]
    async fn process_internal(&self, req: Request) -> Response {
        let start = Instant::now();
        let method = req.method.clone();
        
        let result = if let Some(handler) = self.handlers.get(&method) {
            handler.clone()(req.clone())
        } else {
            Response {
                id: req.id,
                result: serde_json::Value::Null,
                error: Some(format!("Unknown method: {}", method)),
                processing_time_us: 0,
            }
        };
        
        let processing_time = start.elapsed().as_micros() as u64;
        
        // Update metrics
        {
            let mut metrics = self.metrics.write();
            metrics.total_requests += 1;
            if result.error.is_some() {
                metrics.total_errors += 1;
            }
            metrics.latencies.push(processing_time);
            
            // Keep only last 10k samples for percentile calculation
            if metrics.latencies.len() > 10000 {
                metrics.latencies.remove(0);
            }
        }
        
        Response {
            processing_time_us: processing_time,
            ..result
        }
    }
}

#[async_trait]
impl MCPServer for HighPerfMCPServer {
    #[instrument(skip(self, req), fields(req.id = req.id))]
    async fn process_request(&self, req: Request) -> Result<Response> {
        trace!("Processing request: {:?}", req);
        Ok(self.process_internal(req).await)
    }
    
    #[instrument(skip(self, state))]
    async fn update_state(&self, state: StateUpdate) -> Result<()> {
        self.state_manager.update(state).await
    }
    
    fn get_metrics(&self) -> Metrics {
        let metrics = self.metrics.read();
        
        let avg_latency = if metrics.total_requests > 0 {
            metrics.latencies.iter().sum::<u64>() as f64 / metrics.latencies.len() as f64
        } else {
            0.0
        };
        
        let p99_latency = if !metrics.latencies.is_empty() {
            let mut sorted = metrics.latencies.clone();
            sorted.sort_unstable();
            let idx = (sorted.len() as f64 * 0.99) as usize;
            sorted.get(idx).copied().unwrap_or(0)
        } else {
            0
        };
        
        Metrics {
            total_requests: metrics.total_requests,
            total_errors: metrics.total_errors,
            avg_latency_us: avg_latency,
            p99_latency_us: p99_latency,
            memory_usage_mb: self.memory_pool.get_usage_mb(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_server_creation() {
        let server = HighPerfMCPServer::new(1024).unwrap();
        let metrics = server.get_metrics();
        assert_eq!(metrics.total_requests, 0);
    }
    
    #[tokio::test]
    async fn test_request_processing() {
        let server = HighPerfMCPServer::new(1024).unwrap();
        
        server.register_handler("test".to_string(), |req| {
            Response {
                id: req.id,
                result: serde_json::json!({"status": "ok"}),
                error: None,
                processing_time_us: 0,
            }
        });
        
        let req = Request {
            id: 1,
            method: "test".to_string(),
            params: serde_json::Value::Null,
            timestamp: 0,
        };
        
        let resp = server.process_request(req).await.unwrap();
        assert!(resp.error.is_none());
        assert!(resp.processing_time_us < 1000); // Should be under 1ms
    }
}