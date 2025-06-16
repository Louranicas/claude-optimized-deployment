//! Reliability patterns implementation
//! 
//! Provides circuit breakers, retry policies, and recovery mechanisms
//! for building resilient systems.

pub mod circuit_breaker;
pub mod retry_policy;
pub mod recovery;

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};

pub use circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, CircuitState};
pub use retry_policy::{RetryPolicy, RetryConfig, BackoffStrategy};
pub use recovery::{RecoveryManager, RecoveryStrategy};

/// Reliability result type
pub type ReliabilityResult<T> = Result<T, ReliabilityError>;

/// Reliability errors
#[derive(Debug, thiserror::Error)]
pub enum ReliabilityError {
    #[error("Circuit breaker open")]
    CircuitBreakerOpen,
    
    #[error("Max retries exceeded")]
    MaxRetriesExceeded,
    
    #[error("Recovery failed: {0}")]
    RecoveryFailed(String),
    
    #[error("Timeout exceeded")]
    Timeout,
    
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}