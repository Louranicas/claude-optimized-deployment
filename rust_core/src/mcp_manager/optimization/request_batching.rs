//! Request batching for performance optimization

use crate::mcp_manager::errors::Result;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Notify};
use tokio::time::timeout;

/// Request to be batched
#[derive(Debug, Clone)]
pub struct BatchRequest {
    /// Request ID
    pub id: String,
    /// Request data
    pub data: serde_json::Value,
    /// Timestamp
    pub timestamp: Instant,
}

/// Batch of requests
#[derive(Debug)]
pub struct Batch {
    /// Batch ID
    pub id: String,
    /// Requests in batch
    pub requests: Vec<BatchRequest>,
    /// Created timestamp
    pub created_at: Instant,
}

/// Request batcher
pub struct RequestBatcher {
    /// Maximum batch size
    max_batch_size: usize,
    /// Maximum wait time
    max_wait_time: Duration,
    /// Pending requests
    pending: Arc<Mutex<VecDeque<BatchRequest>>>,
    /// Notify for new requests
    notify: Arc<Notify>,
}

impl RequestBatcher {
    /// Create new request batcher
    pub fn new(max_batch_size: usize, max_wait_time: Duration) -> Self {
        Self {
            max_batch_size,
            max_wait_time,
            pending: Arc::new(Mutex::new(VecDeque::new())),
            notify: Arc::new(Notify::new()),
        }
    }
    
    /// Add request to batch
    pub async fn add_request(&self, request: BatchRequest) {
        self.pending.lock().await.push_back(request);
        self.notify.notify_one();
    }
    
    /// Get next batch
    pub async fn get_batch(&self) -> Option<Batch> {
        let start = Instant::now();
        
        loop {
            let mut pending = self.pending.lock().await;
            
            // Check if we have enough requests or waited too long
            if pending.len() >= self.max_batch_size || 
               (!pending.is_empty() && start.elapsed() >= self.max_wait_time) {
                let batch_size = pending.len().min(self.max_batch_size);
                let requests: Vec<_> = pending.drain(..batch_size).collect();
                
                if !requests.is_empty() {
                    return Some(Batch {
                        id: uuid::Uuid::new_v4().to_string(),
                        requests,
                        created_at: Instant::now(),
                    });
                }
            }
            
            drop(pending);
            
            // Wait for new requests or timeout
            let remaining = self.max_wait_time.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                return None;
            }
            
            match timeout(remaining, self.notify.notified()).await {
                Ok(_) => continue,
                Err(_) => {
                    // Timeout - check one more time
                    let mut pending = self.pending.lock().await;
                    if !pending.is_empty() {
                        let requests: Vec<_> = pending.drain(..).collect();
                        return Some(Batch {
                            id: uuid::Uuid::new_v4().to_string(),
                            requests,
                            created_at: Instant::now(),
                        });
                    }
                    return None;
                }
            }
        }
    }
    
    /// Get pending request count
    pub async fn pending_count(&self) -> usize {
        self.pending.lock().await.len()
    }
}

/// Batch processor
pub trait BatchProcessor: Send + Sync {
    /// Process a batch of requests
    fn process_batch(&self, batch: Batch) -> futures::future::BoxFuture<'_, Result<Vec<serde_json::Value>>>;
}

/// Batch executor
pub struct BatchExecutor<P: BatchProcessor> {
    /// Batcher
    batcher: Arc<RequestBatcher>,
    /// Processor
    processor: Arc<P>,
}

impl<P: BatchProcessor> BatchExecutor<P> {
    /// Create new batch executor
    pub fn new(batcher: Arc<RequestBatcher>, processor: Arc<P>) -> Self {
        Self { batcher, processor }
    }
    
    /// Start processing batches
    pub async fn start(&self) {
        loop {
            if let Some(batch) = self.batcher.get_batch().await {
                let processor = self.processor.clone();
                tokio::spawn(async move {
                    let _ = processor.process_batch(batch).await;
                });
            }
        }
    }
}