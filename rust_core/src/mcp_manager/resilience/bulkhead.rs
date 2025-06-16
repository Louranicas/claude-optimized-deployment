//! Bulkhead pattern implementation

use crate::mcp_manager::errors::{McpError, Result};
use std::sync::Arc;
use tokio::sync::Semaphore;
use futures::future::Future;

/// Bulkhead for isolating resources
pub struct Bulkhead {
    /// Name
    name: String,
    /// Semaphore for limiting concurrent requests
    semaphore: Arc<Semaphore>,
    /// Maximum concurrent requests
    max_concurrent: usize,
}

impl Bulkhead {
    /// Create new bulkhead
    pub fn new(name: String, max_concurrent: usize) -> Self {
        Self {
            name,
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            max_concurrent,
        }
    }
    
    /// Execute with bulkhead protection
    pub async fn execute<F, T>(&self, operation: F) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        let permit = self.semaphore.acquire().await
            .map_err(|_| McpError::Other(format!("Bulkhead {} closed", self.name)))?;
        
        let result = operation.await;
        drop(permit);
        
        result
    }
    
    /// Get available permits
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }
    
    /// Check if bulkhead is at capacity
    pub fn is_at_capacity(&self) -> bool {
        self.available_permits() == 0
    }
}

/// Bulkhead manager for multiple bulkheads
pub struct BulkheadManager {
    /// Bulkheads by name
    bulkheads: std::collections::HashMap<String, Arc<Bulkhead>>,
}

impl BulkheadManager {
    /// Create new bulkhead manager
    pub fn new() -> Self {
        Self {
            bulkheads: std::collections::HashMap::new(),
        }
    }
    
    /// Get or create bulkhead
    pub fn get_or_create(&mut self, name: String, max_concurrent: usize) -> Arc<Bulkhead> {
        self.bulkheads.entry(name.clone())
            .or_insert_with(|| Arc::new(Bulkhead::new(name, max_concurrent)))
            .clone()
    }
    
    /// Get bulkhead
    pub fn get(&self, name: &str) -> Option<Arc<Bulkhead>> {
        self.bulkheads.get(name).cloned()
    }
    
    /// Remove bulkhead
    pub fn remove(&mut self, name: &str) -> Option<Arc<Bulkhead>> {
        self.bulkheads.remove(name)
    }
}