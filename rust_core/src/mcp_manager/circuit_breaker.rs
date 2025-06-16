//! Circuit breaker implementation for fault tolerance

use crate::mcp_manager::{
    config::CircuitBreakerConfig,
    errors::{McpError, Result},
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};

/// Circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Circuit is closed, requests flow normally
    Closed,
    /// Circuit is open, all requests fail fast
    Open,
    /// Circuit is half-open, testing if service recovered
    HalfOpen,
}

/// Circuit breaker statistics
#[derive(Debug, Clone)]
pub struct CircuitBreakerStats {
    /// Total requests
    pub total_requests: u64,
    /// Successful requests
    pub successful_requests: u64,
    /// Failed requests
    pub failed_requests: u64,
    /// Times circuit opened
    pub times_opened: u64,
    /// Current consecutive failures
    pub consecutive_failures: u32,
    /// Current consecutive successes
    pub consecutive_successes: u32,
    /// Last state change time
    pub last_state_change: Option<Instant>,
}

/// Circuit breaker for protecting against cascading failures
pub struct CircuitBreaker {
    /// Configuration
    config: CircuitBreakerConfig,
    /// Current state
    state: Arc<RwLock<CircuitState>>,
    /// Statistics
    stats: Arc<Mutex<CircuitBreakerStats>>,
    /// Time when circuit was opened
    opened_at: Arc<Mutex<Option<Instant>>>,
    /// Last test time in half-open state
    last_test: Arc<Mutex<Option<Instant>>>,
}

impl CircuitBreaker {
    /// Create a new circuit breaker
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(CircuitState::Closed)),
            stats: Arc::new(Mutex::new(CircuitBreakerStats {
                total_requests: 0,
                successful_requests: 0,
                failed_requests: 0,
                times_opened: 0,
                consecutive_failures: 0,
                consecutive_successes: 0,
                last_state_change: None,
            })),
            opened_at: Arc::new(Mutex::new(None)),
            last_test: Arc::new(Mutex::new(None)),
        }
    }

    /// Get current state
    pub async fn state(&self) -> CircuitState {
        // Check if we should transition from Open to HalfOpen
        let current_state = *self.state.read().await;
        
        if current_state == CircuitState::Open {
            if let Some(opened_at) = *self.opened_at.lock().await {
                if opened_at.elapsed() >= Duration::from_millis(self.config.timeout_ms) {
                    // Transition to half-open
                    self.transition_to_half_open().await;
                    return CircuitState::HalfOpen;
                }
            }
        }
        
        current_state
    }

    /// Check if circuit allows request
    pub async fn can_execute(&self) -> Result<()> {
        match self.state().await {
            CircuitState::Closed => Ok(()),
            CircuitState::Open => Err(McpError::CircuitBreakerOpen(
                "Circuit breaker is open".to_string()
            )),
            CircuitState::HalfOpen => {
                // Allow one request through for testing
                let mut last_test = self.last_test.lock().await;
                let now = Instant::now();
                
                if let Some(last) = *last_test {
                    if now.duration_since(last) < Duration::from_secs(1) { // Fixed interval for half-open state
                        return Err(McpError::CircuitBreakerOpen(
                            "Circuit breaker is testing".to_string()
                        ));
                    }
                }
                
                *last_test = Some(now);
                Ok(())
            }
        }
    }

    /// Record a successful request
    pub async fn record_success(&self) {
        let mut stats = self.stats.lock().await;
        stats.total_requests += 1;
        stats.successful_requests += 1;
        stats.consecutive_successes += 1;
        stats.consecutive_failures = 0;
        
        let current_state = *self.state.read().await;
        
        match current_state {
            CircuitState::Closed => {
                // Reset consecutive failures on success
            }
            CircuitState::HalfOpen => {
                // Check if we should close the circuit
                if stats.consecutive_successes >= self.config.success_threshold {
                    drop(stats);
                    self.transition_to_closed().await;
                }
            }
            CircuitState::Open => {
                // Shouldn't happen, but handle gracefully
            }
        }
    }

    /// Record a failed request
    pub async fn record_failure(&self) {
        let mut stats = self.stats.lock().await;
        stats.total_requests += 1;
        stats.failed_requests += 1;
        stats.consecutive_failures += 1;
        stats.consecutive_successes = 0;
        
        let current_state = *self.state.read().await;
        
        match current_state {
            CircuitState::Closed => {
                // Check if we should open the circuit
                if stats.consecutive_failures >= self.config.failure_threshold {
                    drop(stats);
                    self.transition_to_open().await;
                }
            }
            CircuitState::HalfOpen => {
                // Single failure in half-open state reopens the circuit
                drop(stats);
                self.transition_to_open().await;
            }
            CircuitState::Open => {
                // Already open, nothing to do
            }
        }
    }

    /// Execute a function with circuit breaker protection
    pub async fn execute<F, T, E>(&self, f: F) -> Result<T>
    where
        F: FnOnce() -> futures::future::BoxFuture<'static, std::result::Result<T, E>>,
        E: Into<McpError>,
    {
        // Check if we can execute
        self.can_execute().await?;
        
        // Execute the function
        match f().await {
            Ok(result) => {
                self.record_success().await;
                Ok(result)
            }
            Err(err) => {
                self.record_failure().await;
                Err(err.into())
            }
        }
    }

    /// Get circuit breaker statistics
    pub async fn stats(&self) -> CircuitBreakerStats {
        self.stats.lock().await.clone()
    }

    /// Reset the circuit breaker
    pub async fn reset(&self) {
        *self.state.write().await = CircuitState::Closed;
        *self.opened_at.lock().await = None;
        *self.last_test.lock().await = None;
        
        let mut stats = self.stats.lock().await;
        stats.consecutive_failures = 0;
        stats.consecutive_successes = 0;
        stats.last_state_change = Some(Instant::now());
    }

    /// Transition to open state
    async fn transition_to_open(&self) {
        *self.state.write().await = CircuitState::Open;
        *self.opened_at.lock().await = Some(Instant::now());
        
        let mut stats = self.stats.lock().await;
        stats.times_opened += 1;
        stats.last_state_change = Some(Instant::now());
    }

    /// Transition to half-open state
    async fn transition_to_half_open(&self) {
        *self.state.write().await = CircuitState::HalfOpen;
        *self.last_test.lock().await = None;
        
        let mut stats = self.stats.lock().await;
        stats.consecutive_failures = 0;
        stats.consecutive_successes = 0;
        stats.last_state_change = Some(Instant::now());
    }

    /// Transition to closed state
    async fn transition_to_closed(&self) {
        *self.state.write().await = CircuitState::Closed;
        *self.opened_at.lock().await = None;
        *self.last_test.lock().await = None;
        
        let mut stats = self.stats.lock().await;
        stats.consecutive_failures = 0;
        stats.last_state_change = Some(Instant::now());
    }
}

/// Circuit breaker manager for multiple services
pub struct CircuitBreakerManager {
    /// Circuit breakers by service ID
    breakers: Arc<RwLock<HashMap<String, Arc<CircuitBreaker>>>>,
    /// Default configuration
    default_config: CircuitBreakerConfig,
}

use std::collections::HashMap;

impl CircuitBreakerManager {
    /// Create a new circuit breaker manager
    pub fn new(default_config: CircuitBreakerConfig) -> Self {
        Self {
            breakers: Arc::new(RwLock::new(HashMap::new())),
            default_config,
        }
    }

    /// Get or create a circuit breaker for a service
    pub async fn get_or_create(&self, service_id: &str) -> Arc<CircuitBreaker> {
        let mut breakers = self.breakers.write().await;
        
        if let Some(breaker) = breakers.get(service_id) {
            return breaker.clone();
        }
        
        let breaker = Arc::new(CircuitBreaker::new(self.default_config.clone()));
        breakers.insert(service_id.to_string(), breaker.clone());
        breaker
    }

    /// Get a circuit breaker if it exists
    pub async fn get(&self, service_id: &str) -> Option<Arc<CircuitBreaker>> {
        self.breakers.read().await.get(service_id).cloned()
    }

    /// Remove a circuit breaker
    pub async fn remove(&self, service_id: &str) -> Option<Arc<CircuitBreaker>> {
        self.breakers.write().await.remove(service_id)
    }

    /// Get all circuit breakers
    pub async fn all(&self) -> Vec<(String, Arc<CircuitBreaker>)> {
        self.breakers.read().await
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Get statistics for all circuit breakers
    pub async fn all_stats(&self) -> HashMap<String, CircuitBreakerStats> {
        let mut stats = HashMap::new();
        let breakers = self.breakers.read().await;
        
        for (id, breaker) in breakers.iter() {
            stats.insert(id.clone(), breaker.stats().await);
        }
        
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            failure_threshold: 3,
            success_threshold: 2,
            timeout: Duration::from_secs(1),
            half_open_interval: Duration::from_millis(100),
        }
    }

    #[tokio::test]
    async fn test_circuit_breaker_closed_to_open() {
        let breaker = CircuitBreaker::new(create_test_config());
        
        assert_eq!(breaker.state().await, CircuitState::Closed);
        
        // Record failures to open the circuit
        for _ in 0..3 {
            breaker.record_failure().await;
        }
        
        assert_eq!(breaker.state().await, CircuitState::Open);
        
        let stats = breaker.stats().await;
        assert_eq!(stats.consecutive_failures, 3);
        assert_eq!(stats.times_opened, 1);
    }

    #[tokio::test]
    async fn test_circuit_breaker_open_to_half_open() {
        let mut config = create_test_config();
        config.timeout = Duration::from_millis(100);
        let breaker = CircuitBreaker::new(config);
        
        // Open the circuit
        for _ in 0..3 {
            breaker.record_failure().await;
        }
        
        assert_eq!(breaker.state().await, CircuitState::Open);
        
        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(150)).await;
        
        assert_eq!(breaker.state().await, CircuitState::HalfOpen);
    }

    #[tokio::test]
    async fn test_circuit_breaker_half_open_to_closed() {
        let breaker = CircuitBreaker::new(create_test_config());
        
        // Manually set to half-open state
        *breaker.state.write().await = CircuitState::HalfOpen;
        
        // Record successes to close the circuit
        for _ in 0..2 {
            breaker.record_success().await;
        }
        
        assert_eq!(breaker.state().await, CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_circuit_breaker_execute() {
        let breaker = CircuitBreaker::new(create_test_config());
        
        // Successful execution
        let result = breaker.execute(|| {
            Box::pin(async { Ok::<_, McpError>(42) })
        }).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        
        // Failed executions to open circuit
        for _ in 0..3 {
            let _ = breaker.execute(|| {
                Box::pin(async { Err::<i32, _>(McpError::Other("test error".to_string())) })
            }).await;
        }
        
        // Circuit should be open now
        let result = breaker.execute(|| {
            Box::pin(async { Ok::<_, McpError>(42) })
        }).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_circuit_breaker_manager() {
        let config = create_test_config();
        let manager = CircuitBreakerManager::new(config);
        
        let breaker1 = manager.get_or_create("service1").await;
        let breaker2 = manager.get_or_create("service2").await;
        
        // Same service should return same breaker
        let breaker1_again = manager.get_or_create("service1").await;
        assert!(Arc::ptr_eq(&breaker1, &breaker1_again));
        
        // Different services should have different breakers
        assert!(!Arc::ptr_eq(&breaker1, &breaker2));
        
        // Test removal
        assert!(manager.remove("service1").await.is_some());
        assert!(manager.get("service1").await.is_none());
    }
}