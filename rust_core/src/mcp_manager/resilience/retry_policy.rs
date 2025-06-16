//! Retry policy implementation

use crate::mcp_manager::errors::Result;
use std::time::Duration;
use tokio::time::sleep;

/// Retry policy trait
pub trait RetryPolicy: Send + Sync {
    /// Should retry based on attempt number and error
    fn should_retry(&self, attempt: u32, error: &crate::mcp_manager::errors::McpError) -> bool;
    
    /// Get delay before next retry
    fn get_delay(&self, attempt: u32) -> Duration;
}

/// Exponential backoff retry policy
pub struct ExponentialBackoff {
    /// Maximum retries
    max_retries: u32,
    /// Initial delay
    initial_delay: Duration,
    /// Maximum delay
    max_delay: Duration,
    /// Backoff factor
    factor: f64,
    /// Jitter factor
    jitter: f64,
}

impl ExponentialBackoff {
    /// Create new exponential backoff policy
    pub fn new(
        max_retries: u32,
        initial_delay: Duration,
        max_delay: Duration,
        factor: f64,
        jitter: f64,
    ) -> Self {
        Self {
            max_retries,
            initial_delay,
            max_delay,
            factor,
            jitter,
        }
    }
}

impl Default for ExponentialBackoff {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            factor: 2.0,
            jitter: 0.1,
        }
    }
}

impl RetryPolicy for ExponentialBackoff {
    fn should_retry(&self, attempt: u32, error: &crate::mcp_manager::errors::McpError) -> bool {
        if attempt >= self.max_retries {
            return false;
        }
        
        // Retry on transient errors
        matches!(error, 
            crate::mcp_manager::errors::McpError::ConnectionError(_) |
            crate::mcp_manager::errors::McpError::Timeout(_) |
            crate::mcp_manager::errors::McpError::ResourceExhausted(_)
        )
    }
    
    fn get_delay(&self, attempt: u32) -> Duration {
        let base_delay = self.initial_delay.as_millis() as f64 * self.factor.powi(attempt as i32);
        let jitter_range = base_delay * self.jitter;
        let jitter = (rand::random::<f64>() - 0.5) * 2.0 * jitter_range;
        let delay_ms = (base_delay + jitter).max(0.0) as u64;
        
        Duration::from_millis(delay_ms.min(self.max_delay.as_millis() as u64))
    }
}

/// Retry executor
pub struct RetryExecutor<P: RetryPolicy> {
    policy: P,
}

impl<P: RetryPolicy> RetryExecutor<P> {
    /// Create new retry executor
    pub fn new(policy: P) -> Self {
        Self { policy }
    }
    
    /// Execute with retry
    pub async fn execute<F, T, E>(&self, mut operation: F) -> Result<T>
    where
        F: FnMut() -> futures::future::BoxFuture<'static, std::result::Result<T, E>>,
        E: Into<crate::mcp_manager::errors::McpError>,
    {
        let mut attempt = 0;
        
        loop {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(err) => {
                    let mcp_err = err.into();
                    
                    if !self.policy.should_retry(attempt, &mcp_err) {
                        return Err(mcp_err);
                    }
                    
                    let delay = self.policy.get_delay(attempt);
                    sleep(delay).await;
                    attempt += 1;
                }
            }
        }
    }
}