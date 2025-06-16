//! SYNTHEX-BashGod: Revolutionary Bash Command Orchestration
//! 
//! A learning agent that specializes in Bash command chaining, synergy optimization,
//! and seamless integration with MCP servers. Built with top 1% Rust coding standards.
//!
//! By: The Most Distinguished Synthetic Rust Coder in History

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use thiserror::Error;

pub mod actor;
pub mod core;
pub mod memory;
pub mod learning;
pub mod synergy;
pub mod mcp_integration;
pub mod python_bindings;
pub mod service;

#[cfg(test)]
mod tests;

// Re-export main types
pub use actor::{BashGodActor, ActorMessage};
pub use memory::{HybridMemory, MemorySystem, CommandPattern};
pub use learning::{LearningEngine, PatternDetector};
pub use mcp_integration::{MCPEnhancer, MCPIntegration};

/// Result type for SYNTHEX-BashGod operations
pub type Result<T> = std::result::Result<T, SBGError>;

/// Configuration for BashGod service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BashGodConfig {
    /// Size of the channel buffer for actor messages
    pub channel_buffer_size: usize,
    
    /// Number of executor threads in the pool
    pub executor_pool_size: usize,
    
    /// Maximum concurrent operations
    pub max_concurrent_ops: usize,
    
    /// Memory configuration
    pub memory_config: MemoryConfig,
    
    /// Learning configuration
    pub learning_config: LearningConfig,
    
    /// MCP integration settings
    pub mcp_config: MCPConfig,
}

impl Default for BashGodConfig {
    fn default() -> Self {
        Self {
            channel_buffer_size: 1000,
            executor_pool_size: num_cpus::get(),
            max_concurrent_ops: 100,
            memory_config: MemoryConfig::default(),
            learning_config: LearningConfig::default(),
            mcp_config: MCPConfig::default(),
        }
    }
}

/// Memory configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryConfig {
    pub cache_size: usize,
    pub graph_max_nodes: usize,
    pub tensor_dimensions: usize,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            cache_size: 10000,
            graph_max_nodes: 100000,
            tensor_dimensions: 512,
        }
    }
}

/// Learning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningConfig {
    pub pattern_threshold: f32,
    pub optimization_interval: u64,
    pub max_patterns: usize,
}

impl Default for LearningConfig {
    fn default() -> Self {
        Self {
            pattern_threshold: 0.8,
            optimization_interval: 3600,
            max_patterns: 50000,
        }
    }
}

/// MCP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MCPConfig {
    pub server_timeout_ms: u64,
    pub max_retries: u32,
    pub enable_caching: bool,
}

impl Default for MCPConfig {
    fn default() -> Self {
        Self {
            server_timeout_ms: 5000,
            max_retries: 3,
            enable_caching: true,
        }
    }
}

/// SYNTHEX-BashGod errors
#[derive(Error, Debug)]
pub enum SBGError {
    #[error("Actor error: {0}")]
    ActorError(String),
    
    #[error("Memory error: {0}")]
    MemoryError(String),
    
    #[error("Learning error: {0}")]
    LearningError(String),
    
    #[error("MCP integration error: {0}")]
    MCPError(String),
    
    #[error("Command execution error: {0}")]
    ExecutionError(String),
    
    #[error("Optimization error: {0}")]
    OptimizationError(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("Service error: {0}")]
    ServiceError(String),
}

/// Command chain representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandChain {
    /// Unique identifier for the chain
    pub id: String,
    
    /// List of commands in the chain
    pub commands: Vec<BashCommand>,
    
    /// Dependencies between commands
    pub dependencies: HashMap<String, Vec<String>>,
    
    /// Execution strategy
    pub strategy: ExecutionStrategy,
    
    /// Metadata for learning
    pub metadata: ChainMetadata,
}

/// Execution strategy for command chains
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionStrategy {
    /// Execute commands sequentially
    Sequential,
    
    /// Execute independent commands in parallel
    Parallel { max_concurrent: usize },
    
    /// Use dependency graph for optimal execution
    GraphBased,
    
    /// Adaptive strategy based on system load
    Adaptive,
    
    /// Optimized execution based on learned patterns
    Optimized,
    
    /// Predictive execution based on ML models
    Predictive,
}

/// Chain metadata for learning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainMetadata {
    /// Intent of the command chain
    pub intent: String,
    
    /// Tags for categorization
    pub tags: Vec<String>,
    
    /// Expected resource usage
    pub expected_resources: ResourceEstimate,
    
    /// Priority level
    pub priority: Priority,
}

/// Resource estimate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceEstimate {
    pub cpu_cores: Option<f32>,
    pub memory_mb: Option<u64>,
    pub disk_mb: Option<u64>,
    pub disk_io_mbps: Option<f32>,
    pub network_mbps: Option<f32>,
    pub gpu: bool,
}

impl Default for ResourceEstimate {
    fn default() -> Self {
        Self {
            cpu_cores: None,
            memory_mb: None,
            disk_mb: None,
            disk_io_mbps: None,
            network_mbps: None,
            gpu: false,
        }
    }
}

/// Priority levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Low,
    Normal,
    High,
    Critical,
}

/// Individual bash command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BashCommand {
    /// Command ID for dependency tracking
    pub id: String,
    
    /// The actual command string
    pub command: String,
    
    /// Command arguments
    pub args: Vec<String>,
    
    /// Environment variables
    pub env: HashMap<String, String>,
    
    /// Working directory
    pub working_dir: Option<String>,
    
    /// Resource requirements
    pub resources: ResourceEstimate,
    
    /// Timeout in seconds
    pub timeout: Option<u64>,
    
    /// Success criteria
    pub success_criteria: SuccessCriteria,
}

/// Success criteria for command execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessCriteria {
    /// Expected exit codes (default: [0])
    pub exit_codes: Vec<i32>,
    
    /// Output must contain these strings
    pub output_contains: Vec<String>,
    
    /// Output must NOT contain these strings
    pub output_not_contains: Vec<String>,
    
    /// Maximum execution time
    pub max_duration_ms: Option<u64>,
}

impl Default for SuccessCriteria {
    fn default() -> Self {
        Self {
            exit_codes: vec![0],
            output_contains: vec![],
            output_not_contains: vec![],
            max_duration_ms: None,
        }
    }
}

/// Chain execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainResult {
    /// Chain ID
    pub chain_id: String,
    
    /// Overall success
    pub success: bool,
    
    /// Individual command results
    pub command_results: Vec<CommandResult>,
    
    /// Total execution time
    pub total_duration_ms: u64,
    
    /// Resource usage
    pub resource_usage: ResourceUsage,
    
    /// Learning insights generated
    pub insights: Vec<LearningInsight>,
    
    /// Performance metrics
    pub metrics: ExecutionMetrics,
    
    /// Optimization suggestions
    pub suggestions: Vec<String>,
}

/// Individual command result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    /// Command ID
    pub command_id: String,
    
    /// Exit code
    pub exit_code: i32,
    
    /// Standard output
    pub stdout: String,
    
    /// Standard error
    pub stderr: String,
    
    /// Execution time
    pub duration_ms: u64,
    
    /// Resource usage
    pub resource_usage: ResourceUsage,
}

/// Resource usage metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub cpu_percent: f32,
    pub memory_mb: u64,
    pub disk_read_mb: u64,
    pub disk_write_mb: u64,
    pub network_sent_mb: u64,
    pub network_recv_mb: u64,
}

/// Bash command intent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BashIntent {
    /// High-level description
    pub description: String,
    
    /// Category (e.g., "deployment", "monitoring", "security")
    pub category: String,
    
    /// Specific goals
    pub goals: Vec<String>,
    
    /// Constraints
    pub constraints: Vec<String>,
}

/// Learning insight
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningInsight {
    /// Type of insight
    pub insight_type: InsightType,
    
    /// Confidence level (0.0 to 1.0)
    pub confidence: f32,
    
    /// Description
    pub description: String,
    
    /// Recommended action
    pub recommendation: Option<String>,
    
    /// Related patterns
    pub related_patterns: Vec<String>,
}

/// Types of insights
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InsightType {
    /// New synergy discovered
    SynergyDiscovered,
    
    /// Performance optimization
    PerformanceOptimization,
    
    /// Security concern
    SecurityConcern,
    
    /// Resource inefficiency
    ResourceInefficiency,
    
    /// Pattern recognition
    PatternRecognized,
    
    /// Anomaly detected
    AnomalyDetected,
}

// ResourceLimits is re-exported from the core module
pub use self::core::ResourceLimits;

/// Execution metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionMetrics {
    /// Total commands executed
    pub total_commands: u64,
    
    /// Successful commands
    pub successful_commands: u64,
    
    /// Failed commands
    pub failed_commands: u64,
    
    /// Average execution time
    pub avg_execution_time_ms: f64,
    
    /// Peak resource usage
    pub peak_resource_usage: ResourceUsage,
    
    /// Execution time in milliseconds
    pub execution_time_ms: Option<u64>,
    
    /// CPU usage percentage
    pub cpu_usage: Option<f32>,
    
    /// Memory usage in MB
    pub memory_usage: Option<u64>,
}

/// Optimization suggestion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationSuggestion {
    /// Type of optimization
    pub optimization_type: OptimizationType,
    
    /// Description
    pub description: String,
    
    /// Expected improvement
    pub expected_improvement: f32,
    
    /// Risk level
    pub risk_level: RiskLevel,
}

/// Optimization type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OptimizationType {
    Parallelization,
    Caching,
    ResourceReduction,
    CommandSimplification,
    ChainRestructuring,
    Reordering,
}

/// Risk level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Execution time
    pub execution_time_ms: u64,
    
    /// CPU usage
    pub cpu_usage: f32,
    
    /// Memory usage
    pub memory_usage: u64,
    
    /// Throughput
    pub throughput: f64,
}

/// Execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Success status
    pub success: bool,
    
    /// Exit code
    pub exit_code: i32,
    
    /// Output
    pub output: String,
    
    /// Error output
    pub error: Option<String>,
    
    /// Metrics
    pub metrics: ExecutionMetrics,
}

/// Execution insights
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionInsights {
    /// Patterns detected
    pub patterns: Vec<String>,
    
    /// Optimizations applied
    pub optimizations: Vec<OptimizationSuggestion>,
    
    /// Resource efficiency score
    pub efficiency_score: f32,
    
    /// Recommendations
    pub recommendations: Vec<String>,
}

/// Execution status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ExecutionStatus {
    /// Not started
    Pending,
    
    /// Currently running
    Running,
    
    /// Completed successfully
    Completed,
    
    /// Failed with error
    Failed,
    
    /// Cancelled by user
    Cancelled,
    
    /// Timed out
    TimedOut,
}

/// BashGod service trait
#[async_trait]
pub trait BashGodService: Send + Sync {
    /// Execute a command chain
    async fn execute_chain(&self, chain: CommandChain) -> Result<ChainResult>;
    
    /// Analyze bash intent and suggest optimal chain
    async fn analyze_intent(&self, intent: BashIntent) -> Result<CommandChain>;
    
    /// Get learning insights
    async fn get_insights(&self, category: Option<String>) -> Result<Vec<LearningInsight>>;
    
    /// Optimize an existing chain
    async fn optimize_chain(&self, chain: CommandChain) -> Result<CommandChain>;
    
    /// Get service metrics
    async fn get_metrics(&self) -> Result<ExecutionMetrics>;
    
    /// Learn from execution results
    async fn learn_from_execution(&self, result: &ChainResult) -> Result<()>;
    
    /// Generate optimized chain from intent
    async fn generate_chain(&self, intent: BashIntent) -> Result<CommandChain>;
    
    /// Get as any for downcasting
    fn as_any(&self) -> &dyn std::any::Any;
}


/// Resource requirements for a command
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResourceRequirements {
    /// CPU cores needed
    pub cpu_cores: Option<f32>,
    
    /// Memory in MB
    pub memory_mb: Option<u64>,
    
    /// Disk space in MB
    pub disk_mb: Option<u64>,
    
    /// Network bandwidth in Mbps
    pub network_mbps: Option<f32>,
    
    /// GPU requirement
    pub gpu: bool,
}


#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config() {
        let config = BashGodConfig::default();
        assert_eq!(config.max_concurrent_ops, 100);
        assert_eq!(config.memory_config.cache_size, 10000);
        assert!(config.mcp_config.enable_caching);
    }
    
    #[test]
    fn test_command_chain_serialization() {
        let chain = CommandChain {
            id: "test-chain".to_string(),
            commands: vec![],
            dependencies: HashMap::new(),
            strategy: ExecutionStrategy::Sequential,
            metadata: ChainMetadata {
                intent: "test".to_string(),
                tags: vec![],
                expected_resources: ResourceEstimate::default(),
                priority: Priority::Normal,
            },
        };
        
        let serialized = serde_json::to_string(&chain).unwrap();
        let deserialized: CommandChain = serde_json::from_str(&serialized).unwrap();
        assert_eq!(chain.id, deserialized.id);
    }
}

/// Create a new BashGod service instance
pub async fn create_bashgod_service(config: BashGodConfig) -> Result<Arc<dyn BashGodService>> {
    use service::BashGodServiceImpl;
    
    // Create and start the service
    let service = BashGodServiceImpl::new(config).await?;
    Ok(Arc::new(service))
}

/// Factory for creating services (for testing)
pub struct BashGodFactory;

impl BashGodFactory {
    /// Create default service
    pub async fn create_default() -> Result<Arc<dyn BashGodService>> {
        create_bashgod_service(BashGodConfig::default()).await
    }
    
    /// Create service with custom config
    pub async fn create(config: BashGodConfig) -> Result<Arc<dyn BashGodService>> {
        create_bashgod_service(config).await
    }
}