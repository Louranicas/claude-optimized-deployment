// ============================================================================
// SYNTHEX BASH GOD - Advanced Bash Command Chain Optimizer
// ============================================================================
// This module provides advanced bash command chain optimization with machine
// learning capabilities for automatic pattern recognition and performance tuning.
// ============================================================================

pub mod python_bindings;
pub mod command_chain;
pub mod execution_engine;
pub mod learning_system;
pub mod optimization_engine;
pub mod performance_monitor;
pub mod streaming_interface;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use anyhow::Result;

/// Main SynthexBashGod struct
pub struct SynthexBashGod {
    /// Execution engine for running command chains
    execution_engine: Arc<execution_engine::ExecutionEngine>,
    /// Learning system for pattern recognition
    learning_system: Arc<RwLock<learning_system::LearningSystem>>,
    /// Optimization engine for performance tuning
    optimization_engine: Arc<optimization_engine::OptimizationEngine>,
    /// Performance monitor for tracking metrics
    performance_monitor: Arc<performance_monitor::PerformanceMonitor>,
}

impl SynthexBashGod {
    /// Create a new SynthexBashGod instance
    pub fn new(config: SBGConfig) -> Result<Self> {
        let execution_engine = Arc::new(execution_engine::ExecutionEngine::new(config.execution_config)?);
        let learning_system = Arc::new(RwLock::new(learning_system::LearningSystem::new(config.learning_config)?));
        let optimization_engine = Arc::new(optimization_engine::OptimizationEngine::new(config.optimization_config)?);
        let performance_monitor = Arc::new(performance_monitor::PerformanceMonitor::new(config.monitoring_config)?);

        Ok(Self {
            execution_engine,
            learning_system,
            optimization_engine,
            performance_monitor,
        })
    }

    /// Execute a command chain with optimization
    pub async fn execute_chain(&self, chain: command_chain::CommandChain) -> Result<ExecutionResult> {
        // Start performance monitoring
        let monitor_handle = self.performance_monitor.start_monitoring(&chain.id).await?;

        // Optimize the chain based on learned patterns
        let optimized_chain = self.optimization_engine.optimize(chain, &self.learning_system).await?;

        // Execute the optimized chain
        let result = self.execution_engine.execute(optimized_chain).await?;

        // Stop monitoring and collect metrics
        let metrics = self.performance_monitor.stop_monitoring(monitor_handle).await?;

        // Update learning system with execution results
        self.learning_system.write().await.update_from_execution(&result, &metrics).await?;

        Ok(ExecutionResult {
            output: result.output,
            error: result.error,
            exit_code: result.exit_code,
            metrics,
            optimizations_applied: result.optimizations_applied,
        })
    }

    /// Get learning insights
    pub async fn get_insights(&self) -> Result<LearningInsights> {
        self.learning_system.read().await.get_insights()
    }

    /// Get performance metrics
    pub async fn get_metrics(&self) -> Result<PerformanceMetrics> {
        self.performance_monitor.get_aggregate_metrics().await
    }
}

/// Configuration for SynthexBashGod
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SBGConfig {
    pub execution_config: execution_engine::ExecutionConfig,
    pub learning_config: learning_system::LearningConfig,
    pub optimization_config: optimization_engine::OptimizationConfig,
    pub monitoring_config: performance_monitor::MonitoringConfig,
}

impl Default for SBGConfig {
    fn default() -> Self {
        Self {
            execution_config: execution_engine::ExecutionConfig::default(),
            learning_config: learning_system::LearningConfig::default(),
            optimization_config: optimization_engine::OptimizationConfig::default(),
            monitoring_config: performance_monitor::MonitoringConfig::default(),
        }
    }
}

/// Result of command chain execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub output: String,
    pub error: Option<String>,
    pub exit_code: i32,
    pub metrics: PerformanceMetrics,
    pub optimizations_applied: Vec<String>,
}

/// Performance metrics for execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub total_duration_ms: u64,
    pub cpu_usage_percent: f64,
    pub memory_usage_mb: f64,
    pub io_operations: u64,
    pub network_bytes: u64,
    pub command_timings: HashMap<String, u64>,
}

/// Learning insights from the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningInsights {
    pub common_patterns: Vec<CommandPattern>,
    pub optimization_suggestions: Vec<OptimizationSuggestion>,
    pub performance_trends: HashMap<String, PerformanceTrend>,
    pub failure_patterns: Vec<FailurePattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandPattern {
    pub pattern: String,
    pub frequency: u64,
    pub avg_performance: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationSuggestion {
    pub original: String,
    pub optimized: String,
    pub expected_improvement: f64,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceTrend {
    pub metric: String,
    pub trend: String,
    pub change_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailurePattern {
    pub pattern: String,
    pub failure_rate: f64,
    pub common_errors: Vec<String>,
}

/// Initialize the module
pub fn init() -> Result<()> {
    Ok(())
}

/// Register Python module
pub fn register_module(py: pyo3::Python, m: &pyo3::types::PyModule) -> pyo3::PyResult<()> {
    python_bindings::register_module(py, m)
}