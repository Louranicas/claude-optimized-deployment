// ============================================================================
// Hybrid Tensor-Graph Memory System
// ============================================================================
// This module implements a high-performance hybrid memory system combining:
// - Tensor-based pattern recognition for command execution patterns
// - Graph-based dependency tracking for resource relationships
// - Unified query interface with O(log n) performance
// ============================================================================

pub mod tensor;
pub mod graph;
pub mod hybrid;
pub mod index;
pub mod optimization;

use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Memory system error types
#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("Tensor operation failed: {0}")]
    TensorError(String),
    
    #[error("Graph operation failed: {0}")]
    GraphError(String),
    
    #[error("Index operation failed: {0}")]
    IndexError(String),
    
    #[error("Memory limit exceeded: {current}/{limit} bytes")]
    MemoryLimitExceeded { current: usize, limit: usize },
    
    #[error("Pattern not found: {0}")]
    PatternNotFound(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

pub type MemoryResult<T> = Result<T, MemoryError>;

/// Memory system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryConfig {
    /// Maximum memory size in bytes
    pub max_memory_bytes: usize,
    
    /// Tensor memory allocation ratio (0.0 - 1.0)
    pub tensor_memory_ratio: f32,
    
    /// Graph memory allocation ratio (0.0 - 1.0)
    pub graph_memory_ratio: f32,
    
    /// Enable GPU acceleration for tensor operations
    pub enable_gpu: bool,
    
    /// LRU cache size for frequently accessed patterns
    pub lru_cache_size: usize,
    
    /// Graph pruning threshold (edges older than this are candidates for removal)
    pub graph_pruning_threshold_secs: u64,
    
    /// Memory compaction interval in seconds
    pub compaction_interval_secs: u64,
    
    /// Similarity threshold for pattern matching (0.0 - 1.0)
    pub similarity_threshold: f32,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: 1024 * 1024 * 1024, // 1GB
            tensor_memory_ratio: 0.6,
            graph_memory_ratio: 0.4,
            enable_gpu: false,
            lru_cache_size: 10000,
            graph_pruning_threshold_secs: 86400, // 24 hours
            compaction_interval_secs: 3600, // 1 hour
            similarity_threshold: 0.85,
        }
    }
}

/// Memory usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryStats {
    pub tensor_memory_used: usize,
    pub graph_memory_used: usize,
    pub total_memory_used: usize,
    pub pattern_count: usize,
    pub node_count: usize,
    pub edge_count: usize,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub compactions_performed: u64,
    pub pruning_operations: u64,
}

/// Command execution pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandPattern {
    pub id: String,
    pub command: String,
    pub arguments: Vec<String>,
    pub environment: std::collections::HashMap<String, String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub execution_time_ms: u64,
    pub exit_code: i32,
    pub resource_usage: ResourceUsage,
}

/// Resource usage metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    pub network_recv_bytes: u64,
    pub network_sent_bytes: u64,
}

/// Similarity search result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarityResult {
    pub pattern_id: String,
    pub similarity_score: f32,
    pub pattern: CommandPattern,
}

/// Dependency relationship between commands
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub from_command: String,
    pub to_command: String,
    pub dependency_type: DependencyType,
    pub strength: f32,
}

/// Types of dependencies between commands
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DependencyType {
    /// Output of one command is input to another
    DataFlow,
    /// Commands must execute in sequence
    Sequential,
    /// Commands share resources and may conflict
    ResourceConflict,
    /// One command triggers another
    Trigger,
    /// Commands are alternatives to each other
    Alternative,
}

/// Initialize the memory system
pub fn init() -> MemoryResult<()> {
    tracing::info!("Initializing hybrid memory system");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_memory_config_default() {
        let config = MemoryConfig::default();
        assert_eq!(config.tensor_memory_ratio + config.graph_memory_ratio, 1.0);
        assert!(config.similarity_threshold > 0.0 && config.similarity_threshold <= 1.0);
    }
    
    #[test]
    fn test_command_pattern_creation() {
        let pattern = CommandPattern {
            id: "test-1".to_string(),
            command: "docker".to_string(),
            arguments: vec!["ps".to_string(), "-a".to_string()],
            environment: std::collections::HashMap::new(),
            timestamp: chrono::Utc::now(),
            execution_time_ms: 100,
            exit_code: 0,
            resource_usage: ResourceUsage {
                cpu_percent: 5.0,
                memory_bytes: 1024 * 1024,
                disk_read_bytes: 0,
                disk_write_bytes: 0,
                network_recv_bytes: 1024,
                network_sent_bytes: 512,
            },
        };
        
        assert_eq!(pattern.command, "docker");
        assert_eq!(pattern.arguments.len(), 2);
    }
}