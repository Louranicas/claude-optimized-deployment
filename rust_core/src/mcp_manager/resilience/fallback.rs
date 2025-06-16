//! Fallback mechanism for resilience

use crate::mcp_manager::errors::Result;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Fallback strategy trait
pub trait FallbackStrategy: Send + Sync {
    /// Execute fallback
    fn fallback(&self) -> futures::future::BoxFuture<'_, Result<serde_json::Value>>;
}

/// Static fallback strategy
pub struct StaticFallback {
    /// Fallback value
    value: serde_json::Value,
}

impl StaticFallback {
    /// Create new static fallback
    pub fn new(value: serde_json::Value) -> Self {
        Self { value }
    }
}

impl FallbackStrategy for StaticFallback {
    fn fallback(&self) -> futures::future::BoxFuture<'_, Result<serde_json::Value>> {
        Box::pin(async move {
            Ok(self.value.clone())
        })
    }
}

/// Cache fallback strategy
pub struct CacheFallback {
    /// Cache
    cache: Arc<RwLock<Option<serde_json::Value>>>,
}

impl CacheFallback {
    /// Create new cache fallback
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(None)),
        }
    }
    
    /// Update cache
    pub async fn update(&self, value: serde_json::Value) {
        *self.cache.write().await = Some(value);
    }
}

impl FallbackStrategy for CacheFallback {
    fn fallback(&self) -> futures::future::BoxFuture<'_, Result<serde_json::Value>> {
        Box::pin(async move {
            self.cache.read().await.clone()
                .ok_or_else(|| crate::mcp_manager::errors::McpError::Other("No cached value available".to_string()))
        })
    }
}

/// Fallback executor
pub struct FallbackExecutor<S: FallbackStrategy> {
    strategy: S,
}

impl<S: FallbackStrategy> FallbackExecutor<S> {
    /// Create new fallback executor
    pub fn new(strategy: S) -> Self {
        Self { strategy }
    }
    
    /// Execute with fallback
    pub async fn execute<F, T>(&self, operation: F) -> Result<serde_json::Value>
    where
        F: futures::future::Future<Output = Result<T>>,
        T: Into<serde_json::Value>,
    {
        match operation.await {
            Ok(result) => Ok(result.into()),
            Err(_) => self.strategy.fallback().await,
        }
    }
}