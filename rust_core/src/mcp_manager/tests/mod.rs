// ============================================================================
// MCP Manager Test Suite - Comprehensive Testing Framework
// ============================================================================

pub mod integration_tests;
pub mod stress_tests;
pub mod property_tests;
mod test_utils;

// Unit tests for individual components
mod unit_tests;

// Unit tests for specific modules
mod distributed_tests;
mod resilience_tests;
mod optimization_tests;
mod security_tests;

// Re-export test utilities for external use
pub use test_utils::{
    create_test_config,
    create_mock_server,
    create_test_manager,
    MockMCPConnection,
    TestMetricsCollector,
};

#[cfg(test)]
mod test_harness {
    use super::*;
    use tracing_test::traced_test;
    
    /// Initialize test environment
    pub fn init_test_env() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_max_level(tracing::Level::DEBUG)
            .try_init();
    }
    
    /// Clean up test environment
    pub fn cleanup_test_env() {
        // Clean up any test artifacts
    }
}

/// Test configuration for various scenarios
#[cfg(test)]
pub mod scenarios {
    use crate::mcp_manager::config::MCPConfig;
    
    /// High-concurrency test configuration
    pub fn high_concurrency_config() -> MCPConfig {
        MCPConfig {
            max_connections_per_server: 100,
            connection_timeout_ms: 1000,
            request_timeout_ms: 5000,
            health_check_interval_secs: 5,
            max_retries: 1,
            retry_backoff_multiplier: 1.5,
            enable_connection_pooling: true,
            enable_load_balancing: true,
            enable_health_checks: true,
            enable_metrics: true,
            circuit_breaker_threshold: 10,
            circuit_breaker_recovery_secs: 30,
        }
    }
    
    /// Low-latency test configuration
    pub fn low_latency_config() -> MCPConfig {
        MCPConfig {
            max_connections_per_server: 20,
            connection_timeout_ms: 500,
            request_timeout_ms: 2000,
            health_check_interval_secs: 10,
            max_retries: 2,
            retry_backoff_multiplier: 1.2,
            enable_connection_pooling: true,
            enable_load_balancing: true,
            enable_health_checks: false, // Disable for lower overhead
            enable_metrics: true,
            circuit_breaker_threshold: 3,
            circuit_breaker_recovery_secs: 15,
        }
    }
    
    /// Fault-tolerance test configuration
    pub fn fault_tolerance_config() -> MCPConfig {
        MCPConfig {
            max_connections_per_server: 50,
            connection_timeout_ms: 3000,
            request_timeout_ms: 10000,
            health_check_interval_secs: 2,
            max_retries: 5,
            retry_backoff_multiplier: 2.0,
            enable_connection_pooling: true,
            enable_load_balancing: true,
            enable_health_checks: true,
            enable_metrics: true,
            circuit_breaker_threshold: 5,
            circuit_breaker_recovery_secs: 60,
        }
    }
}