//! Core types and structures for SYNTHEX-BashGod
//!
//! This module defines the fundamental types used throughout the system,
//! including command chains, execution contexts, and configuration.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

/// Main configuration for the BashGod system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BashGodConfig {
    /// Maximum number of concurrent executions
    pub max_concurrent_executions: usize,
    
    /// Directory for storing execution history and learned patterns
    pub data_directory: PathBuf,
    
    /// Whether to enable GPU acceleration
    pub enable_gpu: bool,
    
    /// Number of GPU devices to use
    pub gpu_devices: Vec<u32>,
    
    /// Memory limits for different operations
    pub memory_limits: MemoryLimits,
    
    /// Learning engine configuration
    pub learning: LearningEngineConfig,
    
    /// MCP server configurations
    pub mcp_servers: Vec<MCPServerConfig>,
    
    /// Telemetry and monitoring settings
    pub telemetry: TelemetryConfig,
}

impl Default for BashGodConfig {
    fn default() -> Self {
        Self {
            max_concurrent_executions: 10,
            data_directory: PathBuf::from("./bashgod_data"),
            enable_gpu: false,
            gpu_devices: vec![],
            memory_limits: MemoryLimits::default(),
            learning: LearningEngineConfig::default(),
            mcp_servers: vec![],
            telemetry: TelemetryConfig::default(),
        }
    }
}

/// Memory limits configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryLimits {
    /// Maximum CPU memory usage in bytes
    pub max_cpu_memory: usize,
    
    /// Maximum GPU memory usage per device in bytes
    pub max_gpu_memory_per_device: usize,
    
    /// Maximum size for a single tensor
    pub max_tensor_size: usize,
}

impl Default for MemoryLimits {
    fn default() -> Self {
        Self {
            max_cpu_memory: 8 * 1024 * 1024 * 1024, // 8GB
            max_gpu_memory_per_device: 4 * 1024 * 1024 * 1024, // 4GB
            max_tensor_size: 1024 * 1024 * 1024, // 1GB
        }
    }
}

/// Learning engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningEngineConfig {
    /// Minimum executions before pattern detection
    pub min_executions_for_pattern: usize,
    
    /// Confidence threshold for applying optimizations
    pub optimization_confidence_threshold: f64,
    
    /// Model update frequency
    pub model_update_frequency: Duration,
    
    /// Pattern similarity threshold
    pub pattern_similarity_threshold: f64,
}

impl Default for LearningEngineConfig {
    fn default() -> Self {
        Self {
            min_executions_for_pattern: 5,
            optimization_confidence_threshold: 0.8,
            model_update_frequency: Duration::from_secs(3600), // 1 hour
            pattern_similarity_threshold: 0.85,
        }
    }
}

/// MCP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MCPServerConfig {
    /// Server name
    pub name: String,
    
    /// Server URL
    pub url: String,
    
    /// Authentication token
    pub auth_token: Option<String>,
    
    /// Supported tools
    pub tools: Vec<String>,
    
    /// Performance rating (0.0 to 1.0)
    pub performance_rating: f64,
}

/// Telemetry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// Whether to enable telemetry
    pub enabled: bool,
    
    /// OpenTelemetry endpoint
    pub otlp_endpoint: Option<String>,
    
    /// Metrics export interval
    pub metrics_interval: Duration,
    
    /// Trace sampling rate
    pub trace_sampling_rate: f64,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            otlp_endpoint: None,
            metrics_interval: Duration::from_secs(60),
            trace_sampling_rate: 0.1,
        }
    }
}

/// Represents a chain of bash commands
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandChain {
    /// Unique identifier for the chain
    pub id: String,
    
    /// Original command string
    pub original: String,
    
    /// Parsed individual commands
    pub commands: Vec<Command>,
    
    /// Dependencies between commands
    pub dependencies: Vec<Dependency>,
    
    /// Metadata about the chain
    pub metadata: ChainMetadata,
}

/// Individual command in a chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Command {
    /// Command index in the chain
    pub index: usize,
    
    /// The command string
    pub command: String,
    
    /// Command type
    pub cmd_type: CommandType,
    
    /// Whether this command can be parallelized
    pub parallelizable: bool,
    
    /// Estimated execution time
    pub estimated_duration: Option<Duration>,
    
    /// Resource requirements
    pub resources: ResourceRequirements,
}

/// Type of command
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommandType {
    /// File system operation
    FileSystem,
    
    /// Network operation
    Network,
    
    /// Process management
    Process,
    
    /// Git operation
    Git,
    
    /// Docker operation
    Docker,
    
    /// Kubernetes operation
    Kubernetes,
    
    /// Database operation
    Database,
    
    /// Generic shell command
    Shell,
}

/// Dependency between commands
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    /// Source command index
    pub from: usize,
    
    /// Target command index
    pub to: usize,
    
    /// Type of dependency
    pub dep_type: DependencyType,
}

/// Type of dependency between commands
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DependencyType {
    /// Output of one command is input to another
    DataFlow,
    
    /// Commands must execute in sequence
    Sequential,
    
    /// Commands share a resource
    Resource,
    
    /// Conditional execution
    Conditional,
}

/// Metadata about a command chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainMetadata {
    /// Source of the chain (user, file, etc.)
    pub source: String,
    
    /// Tags for categorization
    pub tags: Vec<String>,
    
    /// Priority level
    pub priority: Priority,
    
    /// Creation timestamp
    pub created_at: u64,
    
    /// Last modification timestamp
    pub modified_at: u64,
}

/// Priority levels for execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Priority {
    Low,
    Normal,
    High,
    Critical,
}

/// Resource requirements for a command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRequirements {
    /// Estimated CPU usage (0.0 to 1.0 per core)
    pub cpu: f64,
    
    /// Estimated memory usage in bytes
    pub memory: usize,
    
    /// Network bandwidth requirement in bytes/sec
    pub network: Option<usize>,
    
    /// Disk I/O requirement in bytes/sec
    pub disk_io: Option<usize>,
    
    /// Whether GPU is required
    pub gpu_required: bool,
}

impl Default for ResourceRequirements {
    fn default() -> Self {
        Self {
            cpu: 0.1,
            memory: 100 * 1024 * 1024, // 100MB
            network: None,
            disk_io: None,
            gpu_required: false,
        }
    }
}

/// Execution context for a command chain
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    /// Unique execution ID
    pub id: String,
    
    /// Command chain being executed
    pub chain: CommandChain,
    
    /// Environment variables
    pub environment: HashMap<String, String>,
    
    /// Working directory
    pub working_directory: PathBuf,
    
    /// Execution constraints
    pub constraints: ExecutionConstraints,
    
    /// Current execution state
    pub state: ExecutionState,
}

/// Constraints for execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionConstraints {
    /// Maximum execution time
    pub timeout: Duration,
    
    /// Maximum retries per command
    pub max_retries: u32,
    
    /// Whether to stop on first error
    pub stop_on_error: bool,
    
    /// Resource limits
    pub resource_limits: ResourceLimits,
}

/// Resource limits for execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum CPU cores
    pub max_cpu_cores: f64,
    
    /// Maximum memory in bytes
    pub max_memory: usize,
    
    /// Maximum disk space in bytes
    pub max_disk_space: Option<usize>,
    
    /// Network rate limit in bytes/sec
    pub network_rate_limit: Option<usize>,
    
    /// Maximum execution time in seconds (compatibility field)
    pub max_time_seconds: u64,
    
    /// Maximum disk I/O in MB/s (compatibility field)
    pub max_disk_io_mbps: f32,
}

impl ResourceLimits {
    /// Convert to ResourceEstimate
    pub fn to_estimate(&self) -> crate::synthex_bashgod::ResourceEstimate {
        crate::synthex_bashgod::ResourceEstimate {
            cpu_cores: Some(self.max_cpu_cores as f32),
            memory_mb: Some((self.max_memory / (1024 * 1024)) as u64),
            disk_mb: self.max_disk_space.map(|s| (s / (1024 * 1024)) as u64),
            disk_io_mbps: Some(self.max_disk_io_mbps),
            network_mbps: self.network_rate_limit.map(|r| (r * 8 / (1024 * 1024)) as f32),
            gpu: false,
        }
    }
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_cpu_cores: 4.0,
            max_memory: 8 * 1024 * 1024 * 1024, // 8GB
            max_disk_space: None,
            network_rate_limit: None,
            max_time_seconds: 3600, // 1 hour
            max_disk_io_mbps: 100.0,
        }
    }
}

/// Current state of execution
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionState {
    /// Not started yet
    Pending,
    
    /// Currently running
    Running,
    
    /// Paused by user or system
    Paused,
    
    /// Completed successfully
    Completed,
    
    /// Failed with error
    Failed,
    
    /// Cancelled by user
    Cancelled,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bashgod_config_default() {
        let config = BashGodConfig::default();
        assert_eq!(config.max_concurrent_executions, 10);
        assert!(!config.enable_gpu);
        assert!(config.gpu_devices.is_empty());
    }

    #[test]
    fn test_command_type() {
        assert_ne!(CommandType::Git, CommandType::Docker);
        assert_eq!(CommandType::Shell, CommandType::Shell);
    }

    #[test]
    fn test_priority_ordering() {
        assert!(Priority::Critical > Priority::High);
        assert!(Priority::High > Priority::Normal);
        assert!(Priority::Normal > Priority::Low);
    }
}