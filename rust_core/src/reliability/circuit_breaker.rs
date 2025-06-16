//! Circuit breaker pattern implementation
//! 
//! Provides fault tolerance by preventing cascading failures and allowing
//! systems to recover from transient errors.

use super::*;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use parking_lot::RwLock as ParkingLotRwLock;
use tracing::{info, warn};

/// Circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Failure threshold to open circuit
    pub failure_threshold: u32,
    /// Success threshold to close circuit
    pub success_threshold: u32,
    /// Timeout duration for half-open state
    pub timeout: Duration,
    /// Window size for failure rate calculation
    pub window_size: usize,
    /// Minimum number of requests before opening
    pub min_requests: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 2,
            timeout: Duration::from_secs(60),
            window_size: 100,
            min_requests: 10,
        }
    }
}

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitState {
    /// Circuit is closed, requests pass through
    Closed,
    /// Circuit is open, requests are rejected
    Open,
    /// Circuit is half-open, limited requests for testing
    HalfOpen,
}

/// Circuit breaker implementation
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: Arc<ParkingLotRwLock<CircuitState>>,
    consecutive_failures: Arc<AtomicUsize>,
    consecutive_successes: Arc<AtomicUsize>,
    total_requests: Arc<AtomicU64>,
    failed_requests: Arc<AtomicU64>,
    last_failure_time: Arc<ParkingLotRwLock<Option<std::time::Instant>>>,
    request_window: Arc<ParkingLotRwLock<Vec<RequestResult>>>,
}

#[derive(Debug, Clone)]
struct RequestResult {
    timestamp: std::time::Instant,
    success: bool,
}

impl CircuitBreaker {
    /// Create a new circuit breaker
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: Arc::new(ParkingLotRwLock::new(CircuitState::Closed)),
            consecutive_failures: Arc::new(AtomicUsize::new(0)),
            consecutive_successes: Arc::new(AtomicUsize::new(0)),
            total_requests: Arc::new(AtomicU64::new(0)),
            failed_requests: Arc::new(AtomicU64::new(0)),
            last_failure_time: Arc::new(ParkingLotRwLock::new(None)),
            request_window: Arc::new(ParkingLotRwLock::new(Vec::new())),
        }
    }
    
    /// Check if request can proceed
    #[inline]
    pub fn can_proceed(&self) -> bool {
        let state = *self.state.read();
        
        // Optimize for the common case (closed circuit)
        #[cfg(target_arch = "x86_64")]
        if matches!(state, CircuitState::Closed) {
            return true;
        }
        
        match state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if timeout has elapsed
                if let Some(last_failure) = *self.last_failure_time.read() {
                    if last_failure.elapsed() >= self.config.timeout {
                        // Transition to half-open
                        let mut state_write = self.state.write();
                        *state_write = CircuitState::HalfOpen;
                        info!("Circuit breaker transitioned to half-open");
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => {
                // Allow limited requests
                let total = self.total_requests.load(Ordering::SeqCst);
                total % 10 == 0 // Allow 10% of requests
            }
        }
    }
    
    /// Record a successful request
    pub fn record_success(&self) {
        self.total_requests.fetch_add(1, Ordering::SeqCst);
        self.consecutive_failures.store(0, Ordering::SeqCst);
        let successes = self.consecutive_successes.fetch_add(1, Ordering::SeqCst) + 1;
        
        // Add to window
        self.add_to_window(RequestResult {
            timestamp: std::time::Instant::now(),
            success: true,
        });
        
        let state = *self.state.read();
        
        match state {
            CircuitState::HalfOpen => {
                if successes >= self.config.success_threshold as usize {
                    // Close the circuit
                    let mut state_write = self.state.write();
                    *state_write = CircuitState::Closed;
                    self.consecutive_successes.store(0, Ordering::SeqCst);
                    info!("Circuit breaker closed after {} consecutive successes", successes);
                }
            }
            _ => {}
        }
    }
    
    /// Record a failed request
    pub fn record_failure(&self) {
        self.total_requests.fetch_add(1, Ordering::SeqCst);
        self.failed_requests.fetch_add(1, Ordering::SeqCst);
        self.consecutive_successes.store(0, Ordering::SeqCst);
        let failures = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
        
        // Update last failure time
        {
            let mut last_failure = self.last_failure_time.write();
            *last_failure = Some(std::time::Instant::now());
        }
        
        // Add to window
        self.add_to_window(RequestResult {
            timestamp: std::time::Instant::now(),
            success: false,
        });
        
        let state = *self.state.read();
        
        match state {
            CircuitState::Closed => {
                // Check if we should open
                if self.should_open(failures) {
                    let mut state_write = self.state.write();
                    *state_write = CircuitState::Open;
                    warn!("Circuit breaker opened after {} failures", failures);
                }
            }
            CircuitState::HalfOpen => {
                // Immediately open on failure in half-open state
                let mut state_write = self.state.write();
                *state_write = CircuitState::Open;
                warn!("Circuit breaker reopened on failure in half-open state");
            }
            _ => {}
        }
    }
    
    /// Add result to sliding window
    fn add_to_window(&self, result: RequestResult) {
        let mut window = self.request_window.write();
        window.push(result);
        
        // Remove old entries
        let cutoff = std::time::Instant::now() - Duration::from_secs(60);
        window.retain(|r| r.timestamp > cutoff);
        
        // Limit window size
        if window.len() > self.config.window_size {
            let drain_count = window.len() - self.config.window_size;
            window.drain(0..drain_count);
        }
    }
    
    /// Check if circuit should open
    fn should_open(&self, consecutive_failures: usize) -> bool {
        // Check consecutive failures
        if consecutive_failures >= self.config.failure_threshold as usize {
            return true;
        }
        
        // Check failure rate in window
        let window = self.request_window.read();
        if window.len() >= self.config.min_requests as usize {
            let failures = window.iter().filter(|r| !r.success).count();
            let failure_rate = failures as f64 / window.len() as f64;
            
            failure_rate > 0.5 // Open if more than 50% failures
        } else {
            false
        }
    }
    
    /// Get current state
    pub fn state(&self) -> CircuitState {
        *self.state.read()
    }
    
    /// Get circuit breaker statistics
    pub fn stats(&self) -> CircuitBreakerStats {
        let total = self.total_requests.load(Ordering::SeqCst);
        let failed = self.failed_requests.load(Ordering::SeqCst);
        
        CircuitBreakerStats {
            state: self.state(),
            total_requests: total,
            failed_requests: failed,
            success_rate: if total > 0 {
                ((total - failed) as f64 / total as f64) * 100.0
            } else {
                100.0
            },
            consecutive_failures: self.consecutive_failures.load(Ordering::SeqCst),
            consecutive_successes: self.consecutive_successes.load(Ordering::SeqCst),
        }
    }
    
    /// Reset circuit breaker
    pub fn reset(&self) {
        let mut state = self.state.write();
        *state = CircuitState::Closed;
        
        self.consecutive_failures.store(0, Ordering::SeqCst);
        self.consecutive_successes.store(0, Ordering::SeqCst);
        self.total_requests.store(0, Ordering::SeqCst);
        self.failed_requests.store(0, Ordering::SeqCst);
        
        let mut last_failure = self.last_failure_time.write();
        *last_failure = None;
        
        let mut window = self.request_window.write();
        window.clear();
        
        info!("Circuit breaker reset");
    }
}

/// Circuit breaker statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerStats {
    pub state: CircuitState,
    pub total_requests: u64,
    pub failed_requests: u64,
    pub success_rate: f64,
    pub consecutive_failures: usize,
    pub consecutive_successes: usize,
}

/// Execute a function with circuit breaker protection
pub async fn with_circuit_breaker<F, T, E>(
    breaker: &CircuitBreaker,
    f: F,
) -> Result<T, E>
where
    F: std::future::Future<Output = Result<T, E>>,
    E: From<ReliabilityError>,
{
    if !breaker.can_proceed() {
        return Err(ReliabilityError::CircuitBreakerOpen.into());
    }
    
    match f.await {
        Ok(result) => {
            breaker.record_success();
            Ok(result)
        }
        Err(e) => {
            breaker.record_failure();
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_circuit_breaker_opens() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        
        let breaker = CircuitBreaker::new(config);
        
        assert_eq!(breaker.state(), CircuitState::Closed);
        assert!(breaker.can_proceed());
        
        // Record failures
        for _ in 0..3 {
            breaker.record_failure();
        }
        
        assert_eq!(breaker.state(), CircuitState::Open);
        assert!(!breaker.can_proceed());
    }
    
    #[test]
    fn test_circuit_breaker_half_open() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            timeout: Duration::from_millis(100),
            ..Default::default()
        };
        
        let breaker = CircuitBreaker::new(config);
        
        // Open the circuit
        breaker.record_failure();
        breaker.record_failure();
        
        assert_eq!(breaker.state(), CircuitState::Open);
        
        // Wait for timeout
        std::thread::sleep(Duration::from_millis(150));
        
        // Should transition to half-open
        assert!(breaker.can_proceed());
        assert_eq!(breaker.state(), CircuitState::HalfOpen);
    }
    
    #[test]
    fn test_circuit_breaker_closes() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            timeout: Duration::from_millis(100),
            ..Default::default()
        };
        
        let breaker = CircuitBreaker::new(config);
        
        // Open the circuit
        breaker.record_failure();
        breaker.record_failure();
        
        // Wait for timeout
        std::thread::sleep(Duration::from_millis(150));
        
        // Transition to half-open
        assert!(breaker.can_proceed());
        
        // Record successes
        breaker.record_success();
        breaker.record_success();
        
        assert_eq!(breaker.state(), CircuitState::Closed);
    }
    
    #[tokio::test]
    async fn test_with_circuit_breaker() {
        let breaker = CircuitBreaker::new(CircuitBreakerConfig::default());
        
        // Successful operation
        let result: Result<i32, ReliabilityError> = with_circuit_breaker(&breaker, async {
            Ok(42)
        }).await;
        
        assert_eq!(result.unwrap(), 42);
        assert_eq!(breaker.stats().total_requests, 1);
        assert_eq!(breaker.stats().failed_requests, 0);
        
        // Failed operation
        let result: Result<i32, ReliabilityError> = with_circuit_breaker(&breaker, async {
            Err(ReliabilityError::Other(anyhow::anyhow!("test error")))
        }).await;
        
        assert!(result.is_err());
        assert_eq!(breaker.stats().total_requests, 2);
        assert_eq!(breaker.stats().failed_requests, 1);
    }
}