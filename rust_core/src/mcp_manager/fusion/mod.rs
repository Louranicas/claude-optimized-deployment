//! MCP-Bash Fusion Engine
//! 
//! This module provides intelligent enhancement of bash commands with MCP capabilities,
//! creating a powerful hybrid command execution system.

pub mod tool_enhancer;
pub mod command_router;
pub mod cross_tool;
pub mod registry;

use std::sync::Arc;
use tokio::sync::RwLock;
use crate::mcp_manager::{McpManager, Result};

/// Main fusion engine that coordinates MCP-enhanced bash operations
pub struct FusionEngine {
    mcp_manager: Arc<McpManager>,
    tool_registry: Arc<RwLock<registry::ToolRegistry>>,
    command_router: Arc<command_router::CommandRouter>,
    cross_tool_orchestrator: Arc<cross_tool::CrossToolOrchestrator>,
}

impl FusionEngine {
    /// Create a new fusion engine instance
    pub fn new(mcp_manager: Arc<McpManager>) -> Self {
        let tool_registry = Arc::new(RwLock::new(registry::ToolRegistry::new()));
        let command_router = Arc::new(command_router::CommandRouter::new(
            mcp_manager.clone(),
            tool_registry.clone(),
        ));
        let cross_tool_orchestrator = Arc::new(cross_tool::CrossToolOrchestrator::new(
            mcp_manager.clone(),
            tool_registry.clone(),
        ));

        Self {
            mcp_manager,
            tool_registry,
            command_router,
            cross_tool_orchestrator,
        }
    }

    /// Initialize the fusion engine
    pub async fn initialize(&self) -> Result<()> {
        // Load tool capabilities
        self.tool_registry.write().await.load_capabilities().await?;
        
        // Initialize command router
        self.command_router.initialize().await?;
        
        // Start cross-tool orchestrator
        self.cross_tool_orchestrator.start().await?;
        
        Ok(())
    }

    /// Process a bash command and enhance it with MCP capabilities
    pub async fn enhance_command(&self, command: &str) -> Result<EnhancedCommand> {
        tool_enhancer::enhance_bash_command(
            command,
            &self.tool_registry,
            &self.mcp_manager,
        ).await
    }

    /// Execute an enhanced command
    pub async fn execute(&self, command: &EnhancedCommand) -> Result<ExecutionResult> {
        self.command_router.route_and_execute(command).await
    }
}

/// Represents a bash command enhanced with MCP capabilities
#[derive(Debug, Clone)]
pub struct EnhancedCommand {
    pub original: String,
    pub enhancements: Vec<Enhancement>,
    pub strategy: ExecutionStrategy,
}

/// Types of enhancements that can be applied to commands
#[derive(Debug, Clone)]
pub enum Enhancement {
    /// Replace bash command with MCP tool
    Replace {
        tool: String,
        method: String,
        params: serde_json::Value,
    },
    /// Augment bash command with MCP data
    Augment {
        tool: String,
        method: String,
        merge_strategy: MergeStrategy,
    },
    /// Run MCP tool in parallel with bash
    Parallel {
        tool: String,
        method: String,
        correlation_id: String,
    },
    /// Chain multiple MCP tools
    Chain {
        tools: Vec<(String, String)>,
        flow: DataFlow,
    },
}

/// Strategy for merging MCP results with bash output
#[derive(Debug, Clone)]
pub enum MergeStrategy {
    /// Append MCP results
    Append,
    /// Prepend MCP results
    Prepend,
    /// Merge as JSON
    JsonMerge,
    /// Custom merge function
    Custom(String),
}

/// Data flow between chained tools
#[derive(Debug, Clone)]
pub enum DataFlow {
    /// Simple pipeline
    Pipeline,
    /// Conditional flow
    Conditional(Vec<Condition>),
    /// Parallel execution with join
    ParallelJoin,
}

/// Execution strategy for enhanced commands
#[derive(Debug, Clone)]
pub enum ExecutionStrategy {
    /// Run bash first, then MCP
    BashFirst,
    /// Run MCP first, then bash
    McpFirst,
    /// Run both in parallel
    Parallel,
    /// Run only MCP (bash replaced)
    McpOnly,
    /// Smart routing based on conditions
    Smart(SmartRoutingConfig),
}

/// Configuration for smart routing
#[derive(Debug, Clone)]
pub struct SmartRoutingConfig {
    pub prefer_mcp: bool,
    pub fallback_enabled: bool,
    pub performance_threshold_ms: u64,
}

/// Result of executing an enhanced command
#[derive(Debug)]
pub struct ExecutionResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub mcp_results: Vec<McpResult>,
    pub metrics: ExecutionMetrics,
}

/// Individual MCP tool result
#[derive(Debug)]
pub struct McpResult {
    pub tool: String,
    pub method: String,
    pub result: serde_json::Value,
    pub duration_ms: u64,
}

/// Execution metrics
#[derive(Debug)]
pub struct ExecutionMetrics {
    pub total_duration_ms: u64,
    pub bash_duration_ms: Option<u64>,
    pub mcp_duration_ms: Option<u64>,
    pub enhancement_count: usize,
    pub bytes_processed: usize,
}

/// Condition for conditional data flow
#[derive(Debug, Clone)]
pub struct Condition {
    pub field: String,
    pub operator: ComparisonOperator,
    pub value: serde_json::Value,
    pub then_tool: String,
    pub else_tool: Option<String>,
}

/// Comparison operators for conditions
#[derive(Debug, Clone)]
pub enum ComparisonOperator {
    Equals,
    NotEquals,
    GreaterThan,
    LessThan,
    Contains,
    Regex(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_manager::config::McpConfig;

    #[tokio::test]
    async fn test_fusion_engine_creation() {
        let config = McpConfig::default();
        let mcp_manager = Arc::new(McpManager::new(config));
        let fusion_engine = FusionEngine::new(mcp_manager);
        
        assert!(fusion_engine.initialize().await.is_ok());
    }
}