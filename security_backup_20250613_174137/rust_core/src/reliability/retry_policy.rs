//! Retry policy implementation
//! 
//! Provides configurable retry mechanisms with various backoff strategies
//! for handling transient failures.

use super::*;
use std::time::Duration;
use rand::Rng;
use tracing::{debug, warn};

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_attempts: u32,
    /// Initial delay between retries
    pub initial_delay_ms: u64,
    /// Maximum delay between retries
    pub max_delay_ms: u64,
    /// Exponential backoff base
    pub exponential_base: f64,
    /// Enable jitter to prevent thundering herd
    pub jitter: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay_ms: 100,
            max_delay_ms: 10000,
            exponential_base: 2.0,
            jitter: true,
        }
    }
}

/// Backoff strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackoffStrategy {
    /// Fixed delay between retries
    Fixed,
    /// Linear increase in delay
    Linear,
    /// Exponential increase in delay
    Exponential,
    /// Fibonacci sequence delays
    Fibonacci,
}

/// Retry policy
pub struct RetryPolicy {
    config: RetryConfig,
    strategy: BackoffStrategy,
}

impl RetryPolicy {
    /// Create a new retry policy
    pub fn new(config: RetryConfig) -> Self {
        Self {
            config,
            strategy: BackoffStrategy::Exponential,
        }
    }
    
    /// Create retry policy with specific strategy
    pub fn with_strategy(config: RetryConfig, strategy: BackoffStrategy) -> Self {
        Self { config, strategy }
    }
    
    /// Check if retry should be attempted
    pub fn should_retry(&self, attempt: u32) -> bool {
        attempt < self.config.max_attempts
    }
    
    /// Get delay for the given attempt
    pub fn get_delay(&self, attempt: u32) -> Duration {
        let base_delay = match self.strategy {
            BackoffStrategy::Fixed => self.config.initial_delay_ms,
            BackoffStrategy::Linear => self.config.initial_delay_ms * attempt as u64,
            BackoffStrategy::Exponential => {
                let multiplier = self.config.exponential_base.powi(attempt as i32 - 1);
                (self.config.initial_delay_ms as f64 * multiplier) as u64
            }
            BackoffStrategy::Fibonacci => {
                let fib = self.fibonacci(attempt);
                self.config.initial_delay_ms * fib as u64
            }
        };
        
        // Cap at maximum delay
        let delay_ms = base_delay.min(self.config.max_delay_ms);
        
        // Add jitter if enabled
        let final_delay = if self.config.jitter {
            self.add_jitter(delay_ms)
        } else {
            delay_ms
        };
        
        Duration::from_millis(final_delay)
    }
    
    /// Add jitter to delay
    fn add_jitter(&self, delay_ms: u64) -> u64 {
        let mut rng = rand::thread_rng();
        let jitter_range = delay_ms / 4; // 25% jitter
        let jitter = rng.gen_range(0..=jitter_range);
        
        if rng.gen_bool(0.5) {
            delay_ms + jitter
        } else {
            delay_ms.saturating_sub(jitter)
        }
    }
    
    /// Calculate Fibonacci number
    fn fibonacci(&self, n: u32) -> u32 {
        match n {
            0 => 0,
            1 => 1,
            _ => {
                let mut a = 0;
                let mut b = 1;
                for _ in 2..=n {
                    let temp = a + b;
                    a = b;
                    b = temp;
                }
                b
            }
        }
    }
    
    /// Execute a function with retries
    pub async fn execute<F, Fut, T, E>(&self, mut f: F) -> Result<T, E>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
        E: std::fmt::Display + From<ReliabilityError>,
    {
        let mut attempt = 0;
        
        loop {
            attempt += 1;
            
            match f().await {
                Ok(result) => {
                    if attempt > 1 {
                        debug!("Operation succeeded after {} attempts", attempt);
                    }
                    return Ok(result);
                }
                Err(e) => {
                    if !self.should_retry(attempt) {
                        warn!("Operation failed after {} attempts: {}", attempt, e);
                        return Err(ReliabilityError::MaxRetriesExceeded.into());
                    }
                    
                    let delay = self.get_delay(attempt);
                    warn!("Attempt {} failed: {}, retrying in {:?}", attempt, e, delay);
                    
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }
}

/// Retry policy builder
pub struct RetryPolicyBuilder {
    config: RetryConfig,
    strategy: BackoffStrategy,
}

impl RetryPolicyBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            config: RetryConfig::default(),
            strategy: BackoffStrategy::Exponential,
        }
    }
    
    /// Set maximum attempts
    pub fn max_attempts(mut self, attempts: u32) -> Self {
        self.config.max_attempts = attempts;
        self
    }
    
    /// Set initial delay
    pub fn initial_delay(mut self, delay: Duration) -> Self {
        self.config.initial_delay_ms = delay.as_millis() as u64;
        self
    }
    
    /// Set maximum delay
    pub fn max_delay(mut self, delay: Duration) -> Self {
        self.config.max_delay_ms = delay.as_millis() as u64;
        self
    }
    
    /// Set backoff strategy
    pub fn strategy(mut self, strategy: BackoffStrategy) -> Self {
        self.strategy = strategy;
        self
    }
    
    /// Enable or disable jitter
    pub fn jitter(mut self, enabled: bool) -> Self {
        self.config.jitter = enabled;
        self
    }
    
    /// Build the retry policy
    pub fn build(self) -> RetryPolicy {
        RetryPolicy::with_strategy(self.config, self.strategy)
    }
}

/// Execute a function with retries using default policy
pub async fn with_retry<F, Fut, T, E>(f: F) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display + From<ReliabilityError>,
{
    let policy = RetryPolicy::new(RetryConfig::default());
    policy.execute(f).await
}

/// Execute a function with custom retry policy
pub async fn with_custom_retry<F, Fut, T, E>(
    policy: &RetryPolicy,
    f: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display + From<ReliabilityError>,
{
    policy.execute(f).await
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_fixed_backoff() {
        let config = RetryConfig {
            initial_delay_ms: 100,
            jitter: false,
            ..Default::default()
        };
        
        let policy = RetryPolicy::with_strategy(config, BackoffStrategy::Fixed);
        
        assert_eq!(policy.get_delay(1), Duration::from_millis(100));
        assert_eq!(policy.get_delay(2), Duration::from_millis(100));
        assert_eq!(policy.get_delay(3), Duration::from_millis(100));
    }
    
    #[test]
    fn test_linear_backoff() {
        let config = RetryConfig {
            initial_delay_ms: 100,
            jitter: false,
            ..Default::default()
        };
        
        let policy = RetryPolicy::with_strategy(config, BackoffStrategy::Linear);
        
        assert_eq!(policy.get_delay(1), Duration::from_millis(100));
        assert_eq!(policy.get_delay(2), Duration::from_millis(200));
        assert_eq!(policy.get_delay(3), Duration::from_millis(300));
    }
    
    #[test]
    fn test_exponential_backoff() {
        let config = RetryConfig {
            initial_delay_ms: 100,
            exponential_base: 2.0,
            jitter: false,
            ..Default::default()
        };
        
        let policy = RetryPolicy::with_strategy(config, BackoffStrategy::Exponential);
        
        assert_eq!(policy.get_delay(1), Duration::from_millis(100));
        assert_eq!(policy.get_delay(2), Duration::from_millis(200));
        assert_eq!(policy.get_delay(3), Duration::from_millis(400));
        assert_eq!(policy.get_delay(4), Duration::from_millis(800));
    }
    
    #[test]
    fn test_max_delay_cap() {
        let config = RetryConfig {
            initial_delay_ms: 100,
            max_delay_ms: 500,
            exponential_base: 2.0,
            jitter: false,
            ..Default::default()
        };
        
        let policy = RetryPolicy::with_strategy(config, BackoffStrategy::Exponential);
        
        assert_eq!(policy.get_delay(1), Duration::from_millis(100));
        assert_eq!(policy.get_delay(2), Duration::from_millis(200));
        assert_eq!(policy.get_delay(3), Duration::from_millis(400));
        assert_eq!(policy.get_delay(4), Duration::from_millis(500)); // Capped
        assert_eq!(policy.get_delay(5), Duration::from_millis(500)); // Capped
    }
    
    #[tokio::test]
    async fn test_retry_execution() {
        let policy = RetryPolicyBuilder::new()
            .max_attempts(3)
            .initial_delay(Duration::from_millis(10))
            .jitter(false)
            .build();
        
        let mut attempts = 0;
        
        let result: Result<i32, ReliabilityError> = policy.execute(|| async {
            attempts += 1;
            if attempts < 3 {
                Err(ReliabilityError::Other(anyhow::anyhow!("transient error")))
            } else {
                Ok(42)
            }
        }).await;
        
        assert_eq!(result.unwrap(), 42);
        assert_eq!(attempts, 3);
    }
    
    #[tokio::test]
    async fn test_retry_max_attempts() {
        let policy = RetryPolicyBuilder::new()
            .max_attempts(2)
            .initial_delay(Duration::from_millis(10))
            .build();
        
        let mut attempts = 0;
        
        let result: Result<i32, ReliabilityError> = policy.execute(|| async {
            attempts += 1;
            Err(ReliabilityError::Other(anyhow::anyhow!("persistent error")))
        }).await;
        
        assert!(matches!(result, Err(ReliabilityError::MaxRetriesExceeded)));
        assert_eq!(attempts, 2);
    }
}