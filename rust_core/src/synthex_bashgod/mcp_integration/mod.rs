//! MCP (Model Context Protocol) Integration for SYNTHEX-BashGod
//! 
//! Enhances bash commands with MCP server capabilities

use crate::synthex_bashgod::{Result, SBGError, BashCommand};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod tool_enhancer;
pub mod server_manager;
pub mod capability_mapper;

pub use tool_enhancer::ToolEnhancer;
pub use server_manager::MCPServerManager;
pub use capability_mapper::CapabilityMapper;

/// MCP integration trait
#[async_trait]
pub trait MCPIntegration: Send + Sync {
    /// Check if command can be enhanced with MCP
    async fn can_enhance(&self, command: &BashCommand) -> bool;
    
    /// Enhance command with MCP tools
    async fn enhance(&self, command: &BashCommand) -> Result<EnhancedCommand>;
    
    /// Execute MCP tool
    async fn execute_tool(&self, tool: &MCPTool) -> Result<ToolResult>;
    
    /// Get available MCP servers
    async fn list_servers(&self) -> Result<Vec<MCPServer>>;
}

/// Enhanced command with MCP integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedCommand {
    /// Original bash command
    pub original: BashCommand,
    
    /// MCP enhancement type
    pub enhancement: EnhancementType,
    
    /// MCP tool to use
    pub mcp_tool: Option<MCPTool>,
    
    /// Execution strategy
    pub strategy: ExecutionStrategy,
    
    /// Performance estimate
    pub performance_estimate: PerformanceEstimate,
}

/// Types of MCP enhancements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnhancementType {
    /// Complete replacement with MCP tool
    FullReplacement,
    
    /// Augment bash with MCP
    Augmentation,
    
    /// Fallback to bash if MCP fails
    WithFallback,
    
    /// Hybrid execution
    Hybrid,
    
    /// No enhancement possible
    None,
}

/// MCP tool representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MCPTool {
    /// Server name
    pub server: String,
    
    /// Tool name
    pub tool: String,
    
    /// Method to call
    pub method: String,
    
    /// Parameters
    pub params: HashMap<String, serde_json::Value>,
    
    /// Required capabilities
    pub required_capabilities: Vec<String>,
}

/// Tool execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    /// Success flag
    pub success: bool,
    
    /// Result data
    pub data: serde_json::Value,
    
    /// Execution time
    pub execution_time_ms: u64,
    
    /// Resource usage
    pub resource_usage: ResourceUsage,
}

/// Resource usage metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// CPU usage percentage
    pub cpu_percent: f32,
    
    /// Memory usage in MB
    pub memory_mb: u64,
    
    /// Network I/O in KB
    pub network_kb: u64,
}

/// Execution strategy for enhanced commands
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionStrategy {
    /// Try MCP first, fall back to bash
    MCPFirst,
    
    /// Try bash first, enhance with MCP
    BashFirst,
    
    /// Execute both and compare
    Parallel,
    
    /// Use MCP only
    MCPOnly,
    
    /// Use bash only
    BashOnly,
}

/// Performance estimate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceEstimate {
    /// Estimated speedup factor
    pub speedup: f32,
    
    /// Resource efficiency
    pub efficiency: f32,
    
    /// Reliability score
    pub reliability: f32,
    
    /// Overall benefit score
    pub benefit_score: f32,
}

/// MCP server information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MCPServer {
    /// Server name
    pub name: String,
    
    /// Server type
    pub server_type: ServerType,
    
    /// Available tools
    pub tools: Vec<ToolInfo>,
    
    /// Server status
    pub status: ServerStatus,
    
    /// Connection info
    pub connection: ConnectionInfo,
}

/// Server types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerType {
    /// Docker MCP server
    Docker,
    
    /// Kubernetes MCP server
    Kubernetes,
    
    /// Git MCP server
    Git,
    
    /// Filesystem MCP server
    Filesystem,
    
    /// Database MCP server
    Database,
    
    /// Cloud provider MCP server
    Cloud(String),
    
    /// Custom MCP server
    Custom(String),
}

/// Tool information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    /// Tool name
    pub name: String,
    
    /// Tool description
    pub description: String,
    
    /// Available methods
    pub methods: Vec<MethodInfo>,
    
    /// Required permissions
    pub permissions: Vec<String>,
}

/// Method information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodInfo {
    /// Method name
    pub name: String,
    
    /// Method description
    pub description: String,
    
    /// Parameters
    pub parameters: Vec<ParameterInfo>,
    
    /// Return type
    pub return_type: String,
}

/// Parameter information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterInfo {
    /// Parameter name
    pub name: String,
    
    /// Parameter type
    pub param_type: String,
    
    /// Required flag
    pub required: bool,
    
    /// Default value
    pub default: Option<serde_json::Value>,
    
    /// Description
    pub description: String,
}

/// Server status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerStatus {
    /// Server is ready
    Ready,
    
    /// Server is starting
    Starting,
    
    /// Server is busy
    Busy,
    
    /// Server is unavailable
    Unavailable,
    
    /// Server error
    Error(String),
}

/// Connection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    /// Connection URL
    pub url: String,
    
    /// Authentication type
    pub auth_type: AuthType,
    
    /// Connection timeout
    pub timeout_ms: u64,
    
    /// Retry policy
    pub retry_policy: RetryPolicy,
}

/// Authentication types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthType {
    /// No authentication
    None,
    
    /// API key authentication
    ApiKey(String),
    
    /// Bearer token
    Bearer(String),
    
    /// Basic auth
    Basic { username: String, password: String },
    
    /// Custom auth
    Custom(HashMap<String, String>),
}

/// Retry policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    /// Maximum retries
    pub max_retries: u32,
    
    /// Initial delay in ms
    pub initial_delay_ms: u64,
    
    /// Backoff multiplier
    pub backoff_multiplier: f32,
    
    /// Maximum delay in ms
    pub max_delay_ms: u64,
}

/// MCP enhancement result
#[derive(Debug, Clone)]
pub struct EnhancementResult {
    /// Enhanced command
    pub command: EnhancedCommand,
    
    /// Confidence score
    pub confidence: f32,
    
    /// Alternative enhancements
    pub alternatives: Vec<EnhancedCommand>,
    
    /// Warnings
    pub warnings: Vec<String>,
}

/// Command mapping for MCP tools
pub struct CommandMapping {
    /// Bash command pattern
    pub bash_pattern: regex::Regex,
    
    /// MCP server
    pub server: String,
    
    /// MCP tool
    pub tool: String,
    
    /// Parameter extraction
    pub param_extractor: Box<dyn ParamExtractor>,
    
    /// Success criteria
    pub success_criteria: SuccessCriteria,
}

/// Parameter extractor trait
pub trait ParamExtractor: Send + Sync {
    /// Extract parameters from bash command
    fn extract(&self, command: &str) -> HashMap<String, serde_json::Value>;
}

/// Success criteria for MCP execution
#[derive(Debug, Clone)]
pub struct SuccessCriteria {
    /// Expected output pattern
    pub output_pattern: Option<regex::Regex>,
    
    /// Maximum execution time
    pub max_time_ms: Option<u64>,
    
    /// Required success fields
    pub required_fields: Vec<String>,
}

/// MCP integration builder
pub struct MCPIntegrationBuilder {
    /// Server configurations
    servers: Vec<MCPServerConfig>,
    
    /// Command mappings
    mappings: Vec<CommandMapping>,
    
    /// Default strategy
    default_strategy: ExecutionStrategy,
    
    /// Performance thresholds
    performance_thresholds: PerformanceThresholds,
}

/// MCP server configuration
#[derive(Debug, Clone)]
pub struct MCPServerConfig {
    /// Server name
    pub name: String,
    
    /// Server type
    pub server_type: ServerType,
    
    /// Connection info
    pub connection: ConnectionInfo,
    
    /// Enabled tools
    pub enabled_tools: Vec<String>,
    
    /// Custom settings
    pub settings: HashMap<String, serde_json::Value>,
}

/// Performance thresholds
#[derive(Debug, Clone)]
pub struct PerformanceThresholds {
    /// Minimum speedup for enhancement
    pub min_speedup: f32,
    
    /// Minimum efficiency gain
    pub min_efficiency: f32,
    
    /// Maximum acceptable latency
    pub max_latency_ms: u64,
}

impl MCPIntegrationBuilder {
    /// Create new builder
    pub fn new() -> Self {
        Self {
            servers: Vec::new(),
            mappings: Vec::new(),
            default_strategy: ExecutionStrategy::MCPFirst,
            performance_thresholds: PerformanceThresholds {
                min_speedup: 1.2,
                min_efficiency: 1.1,
                max_latency_ms: 5000,
            },
        }
    }
    
    /// Add MCP server
    pub fn add_server(mut self, config: MCPServerConfig) -> Self {
        self.servers.push(config);
        self
    }
    
    /// Add command mapping
    pub fn add_mapping(mut self, mapping: CommandMapping) -> Self {
        self.mappings.push(mapping);
        self
    }
    
    /// Set default strategy
    pub fn default_strategy(mut self, strategy: ExecutionStrategy) -> Self {
        self.default_strategy = strategy;
        self
    }
    
    /// Set performance thresholds
    pub fn performance_thresholds(mut self, thresholds: PerformanceThresholds) -> Self {
        self.performance_thresholds = thresholds;
        self
    }
    
    /// Build MCP integration
    pub fn build(self) -> Result<MCPEnhancer> {
        Ok(MCPEnhancer::new(
            self.servers,
            self.mappings,
            self.default_strategy,
            self.performance_thresholds,
        ))
    }
}

impl Default for MCPIntegrationBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// MCP enhancer implementation
pub struct MCPEnhancer {
    /// Server manager
    server_manager: MCPServerManager,
    
    /// Tool enhancer
    tool_enhancer: ToolEnhancer,
    
    /// Capability mapper
    capability_mapper: CapabilityMapper,
    
    /// Configuration
    config: MCPConfig,
}

/// MCP configuration
#[derive(Debug, Clone)]
pub struct MCPConfig {
    /// Default execution strategy
    pub default_strategy: ExecutionStrategy,
    
    /// Performance thresholds
    pub performance_thresholds: PerformanceThresholds,
    
    /// Enable caching
    pub enable_caching: bool,
    
    /// Cache TTL in seconds
    pub cache_ttl: u64,
}

impl MCPEnhancer {
    /// Create new MCP enhancer
    pub fn new(
        servers: Vec<MCPServerConfig>,
        mappings: Vec<CommandMapping>,
        default_strategy: ExecutionStrategy,
        performance_thresholds: PerformanceThresholds,
    ) -> Self {
        let config = MCPConfig {
            default_strategy,
            performance_thresholds,
            enable_caching: true,
            cache_ttl: 300,
        };
        
        Self {
            server_manager: MCPServerManager::new(servers),
            tool_enhancer: ToolEnhancer::new(mappings),
            capability_mapper: CapabilityMapper::new(),
            config,
        }
    }
}

#[async_trait]
impl MCPIntegration for MCPEnhancer {
    async fn can_enhance(&self, command: &BashCommand) -> bool {
        self.tool_enhancer.can_enhance(command).await
    }
    
    async fn enhance(&self, command: &BashCommand) -> Result<EnhancedCommand> {
        self.tool_enhancer.enhance(command, &self.config).await
    }
    
    async fn execute_tool(&self, tool: &MCPTool) -> Result<ToolResult> {
        self.server_manager.execute_tool(tool).await
    }
    
    async fn list_servers(&self) -> Result<Vec<MCPServer>> {
        self.server_manager.list_servers().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mcp_builder() {
        let integration = MCPIntegrationBuilder::new()
            .add_server(MCPServerConfig {
                name: "docker".to_string(),
                server_type: ServerType::Docker,
                connection: ConnectionInfo {
                    url: "http://localhost:8001".to_string(),
                    auth_type: AuthType::None,
                    timeout_ms: 5000,
                    retry_policy: RetryPolicy {
                        max_retries: 3,
                        initial_delay_ms: 100,
                        backoff_multiplier: 2.0,
                        max_delay_ms: 5000,
                    },
                },
                enabled_tools: vec!["containers".to_string()],
                settings: HashMap::new(),
            })
            .default_strategy(ExecutionStrategy::MCPFirst)
            .build();
        
        assert!(integration.is_ok());
    }
    
    #[test]
    fn test_enhancement_types() {
        let enhancement = EnhancedCommand {
            original: BashCommand {
                id: "test".to_string(),
                command: "docker ps".to_string(),
                args: vec![],
                env: HashMap::new(),
                working_dir: None,
                resources: Default::default(),
            },
            enhancement: EnhancementType::FullReplacement,
            mcp_tool: Some(MCPTool {
                server: "docker".to_string(),
                tool: "containers".to_string(),
                method: "list".to_string(),
                params: HashMap::new(),
                required_capabilities: vec![],
            }),
            strategy: ExecutionStrategy::MCPOnly,
            performance_estimate: PerformanceEstimate {
                speedup: 2.0,
                efficiency: 1.5,
                reliability: 0.95,
                benefit_score: 0.8,
            },
        };
        
        assert_eq!(enhancement.performance_estimate.speedup, 2.0);
    }
}