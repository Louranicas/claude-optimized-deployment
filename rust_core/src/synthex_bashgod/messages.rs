//! Message Types for BashGod Actor System
//! 
//! Defines all message types for inter-actor communication with a focus on
//! zero-copy and efficient serialization.

use super::{BashChain, ChainMetadata};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

/// Main message type for BashGod actors
#[derive(Debug)]
pub enum BashGodMessage {
    /// Command messages that require action
    Command(BashGodCommand),
    /// Response messages with results
    Response(BashGodResponse),
}

/// Command messages for BashGod operations
#[derive(Debug)]
pub enum BashGodCommand {
    /// Execute a bash command chain
    ExecuteChain {
        chain: BashChain,
        response: oneshot::Sender<super::Result<ChainResult>>,
    },
    
    /// Optimize a bash command chain using AI
    OptimizeChain {
        chain: BashChain,
        response: oneshot::Sender<super::Result<BashChain>>,
    },
    
    /// Get status of a running chain
    GetStatus {
        chain_id: String,
        response: oneshot::Sender<Option<super::actor::ChainStatus>>,
    },
    
    /// Cancel a running chain
    CancelChain {
        chain_id: String,
        response: oneshot::Sender<super::Result<()>>,
    },
    
    /// Get actor metrics
    GetMetrics {
        response: oneshot::Sender<super::actor::ActorMetricsSnapshot>,
    },
    
    /// Shutdown the actor
    Shutdown {
        response: oneshot::Sender<()>,
    },
}

/// Response messages from BashGod operations
#[derive(Debug)]
pub enum BashGodResponse {
    /// Chain execution completed
    ChainComplete {
        chain_id: String,
        result: ChainResult,
    },
    
    /// Learning data from execution
    LearnFromResult {
        chain_id: String,
        stats: ExecutionStats,
    },
}

/// Result of chain execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainResult {
    pub chain_id: String,
    pub success: bool,
    pub output: Vec<String>,
    pub error: Option<String>,
    pub execution_time_ms: u64,
    pub commands_executed: usize,
}

/// Execution statistics for learning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionStats {
    pub chain_id: String,
    pub total_time_ms: u64,
    pub command_timings: Vec<CommandTiming>,
    pub resource_usage: ResourceUsage,
    pub optimization_opportunities: Vec<OptimizationHint>,
}

/// Timing information for individual commands
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandTiming {
    pub command: String,
    pub duration_ms: u64,
    pub cpu_usage_percent: f32,
    pub memory_usage_mb: u64,
}

/// Resource usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub peak_cpu_percent: f32,
    pub peak_memory_mb: u64,
    pub total_io_bytes: u64,
    pub network_bytes: u64,
}

/// Optimization hints discovered during execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationHint {
    pub hint_type: OptimizationType,
    pub description: String,
    pub estimated_improvement_percent: f32,
    pub affected_commands: Vec<usize>,
}

/// Types of optimizations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OptimizationType {
    Parallelization,
    Caching,
    Deduplication,
    ResourceReduction,
    CommandCombination,
    OrderOptimization,
}

/// Distributed message types for cross-node communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DistributedMessage {
    /// Request to execute chain on a specific node
    ExecuteOnNode {
        node_id: String,
        chain: BashChain,
        request_id: String,
    },
    
    /// Response from node execution
    NodeExecutionResult {
        node_id: String,
        request_id: String,
        result: ChainResult,
    },
    
    /// Health check ping
    HealthPing {
        node_id: String,
        timestamp: u64,
    },
    
    /// Health check pong response
    HealthPong {
        node_id: String,
        timestamp: u64,
        load_factor: f32,
    },
    
    /// Load balancing information
    LoadInfo {
        node_id: String,
        active_chains: usize,
        capacity: usize,
        avg_latency_ms: u64,
    },
    
    /// Chain migration request
    MigrateChain {
        chain_id: String,
        from_node: String,
        to_node: String,
    },
}

/// Inter-actor communication patterns
#[derive(Debug, Clone)]
pub enum CommunicationPattern {
    /// Direct request-response
    RequestResponse,
    /// Fire and forget
    FireAndForget,
    /// Publish-subscribe
    PubSub {
        topic: String,
    },
    /// Streaming
    Stream {
        batch_size: usize,
    },
}

/// Message priority for queue management
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MessagePriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

impl Default for MessagePriority {
    fn default() -> Self {
        Self::Normal
    }
}

/// Message envelope with metadata
#[derive(Debug, Clone)]
pub struct MessageEnvelope<T> {
    pub id: String,
    pub timestamp: u64,
    pub priority: MessagePriority,
    pub sender_id: String,
    pub correlation_id: Option<String>,
    pub payload: T,
}

impl<T> MessageEnvelope<T> {
    /// Create a new message envelope
    pub fn new(sender_id: String, payload: T) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            priority: MessagePriority::default(),
            sender_id,
            correlation_id: None,
            payload,
        }
    }
    
    /// Set message priority
    pub fn with_priority(mut self, priority: MessagePriority) -> Self {
        self.priority = priority;
        self
    }
    
    /// Set correlation ID for request tracking
    pub fn with_correlation_id(mut self, id: String) -> Self {
        self.correlation_id = Some(id);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_message_envelope_creation() {
        let envelope = MessageEnvelope::new(
            "test-actor".to_string(),
            ChainResult {
                chain_id: "test-chain".to_string(),
                success: true,
                output: vec!["test output".to_string()],
                error: None,
                execution_time_ms: 100,
                commands_executed: 1,
            },
        );
        
        assert_eq!(envelope.sender_id, "test-actor");
        assert_eq!(envelope.priority, MessagePriority::Normal);
        assert!(envelope.correlation_id.is_none());
    }
    
    #[test]
    fn test_message_priority_ordering() {
        assert!(MessagePriority::Critical > MessagePriority::High);
        assert!(MessagePriority::High > MessagePriority::Normal);
        assert!(MessagePriority::Normal > MessagePriority::Low);
    }
}