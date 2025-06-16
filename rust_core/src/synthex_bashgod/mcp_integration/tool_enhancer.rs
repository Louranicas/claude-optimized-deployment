//! Tool enhancement for bash commands using MCP
//! 
//! Maps bash commands to appropriate MCP tools for performance gains

use crate::synthex_bashgod::{Result, SBGError, BashCommand};
use crate::synthex_bashgod::mcp_integration::{
    EnhancedCommand, EnhancementType, MCPTool, ExecutionStrategy,
    PerformanceEstimate, CommandMapping, MCPConfig,
};
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Tool enhancer for bash command optimization
pub struct ToolEnhancer {
    /// Command mappings
    mappings: Arc<Vec<CommandMapping>>,
    
    /// Enhancement cache
    cache: Arc<DashMap<String, EnhancedCommand>>,
    
    /// Statistics
    stats: Arc<RwLock<EnhancerStats>>,
}

/// Enhancer statistics
#[derive(Debug, Default)]
struct EnhancerStats {
    /// Total enhancements attempted
    enhancements_attempted: u64,
    
    /// Successful enhancements
    successful_enhancements: u64,
    
    /// Cache hits
    cache_hits: u64,
    
    /// Average speedup achieved
    avg_speedup: f32,
}

impl ToolEnhancer {
    /// Create a new tool enhancer
    pub fn new(mappings: Vec<CommandMapping>) -> Self {
        // Add default mappings
        let mut all_mappings = Self::default_mappings();
        all_mappings.extend(mappings);
        
        Self {
            mappings: Arc::new(all_mappings),
            cache: Arc::new(DashMap::new()),
            stats: Arc::new(RwLock::new(EnhancerStats::default())),
        }
    }
    
    /// Check if command can be enhanced
    pub async fn can_enhance(&self, command: &BashCommand) -> bool {
        // Check cache first
        if self.cache.contains_key(&command.id) {
            return true;
        }
        
        // Check mappings
        for mapping in self.mappings.iter() {
            if mapping.bash_pattern.is_match(&command.command) {
                return true;
            }
        }
        
        false
    }
    
    /// Enhance a bash command
    pub async fn enhance(
        &self,
        command: &BashCommand,
        config: &MCPConfig,
    ) -> Result<EnhancedCommand> {
        // Update stats
        self.stats.write().await.enhancements_attempted += 1;
        
        // Check cache
        if let Some(cached) = self.cache.get(&command.id) {
            self.stats.write().await.cache_hits += 1;
            return Ok(cached.clone());
        }
        
        // Find matching mapping
        let mapping = self.find_mapping(command)?;
        
        // Extract parameters
        let params = mapping.param_extractor.extract(&command.command);
        
        // Create MCP tool
        let mcp_tool = MCPTool {
            server: mapping.server.clone(),
            tool: mapping.tool.clone(),
            method: Self::determine_method(command, &mapping),
            params,
            required_capabilities: Self::determine_capabilities(command),
        };
        
        // Determine enhancement type and strategy
        let (enhancement_type, strategy) = self.determine_enhancement_strategy(
            command,
            &mcp_tool,
            config,
        );
        
        // Estimate performance
        let performance_estimate = self.estimate_performance(command, &mcp_tool);
        
        // Create enhanced command
        let enhanced = EnhancedCommand {
            original: command.clone(),
            enhancement: enhancement_type,
            mcp_tool: Some(mcp_tool),
            strategy,
            performance_estimate,
        };
        
        // Cache result
        self.cache.insert(command.id.clone(), enhanced.clone());
        
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.successful_enhancements += 1;
            
            // Update average speedup
            let n = stats.successful_enhancements as f32;
            stats.avg_speedup = 
                (stats.avg_speedup * (n - 1.0) + enhanced.performance_estimate.speedup) / n;
        }
        
        info!(
            "Enhanced command '{}' with {} speedup",
            command.command,
            enhanced.performance_estimate.speedup
        );
        
        Ok(enhanced)
    }
    
    /// Find matching mapping for command
    fn find_mapping(&self, command: &BashCommand) -> Result<&CommandMapping> {
        for mapping in self.mappings.iter() {
            if mapping.bash_pattern.is_match(&command.command) {
                return Ok(mapping);
            }
        }
        
        Err(SBGError::MCPError("No mapping found for command".to_string()))
    }
    
    /// Determine method based on command
    fn determine_method(command: &BashCommand, mapping: &CommandMapping) -> String {
        // Docker examples
        if mapping.server == "docker" {
            if command.command.contains("ps") {
                return "list_containers".to_string();
            } else if command.command.contains("images") {
                return "list_images".to_string();
            } else if command.command.contains("run") {
                return "run_container".to_string();
            }
        }
        
        // Git examples
        if mapping.server == "git" {
            if command.command.contains("status") {
                return "get_status".to_string();
            } else if command.command.contains("log") {
                return "get_log".to_string();
            } else if command.command.contains("diff") {
                return "get_diff".to_string();
            }
        }
        
        // Default
        "execute".to_string()
    }
    
    /// Determine required capabilities
    fn determine_capabilities(command: &BashCommand) -> Vec<String> {
        let mut capabilities = Vec::new();
        
        // Check for sudo
        if command.command.starts_with("sudo") {
            capabilities.push("elevated_privileges".to_string());
        }
        
        // Check for file system access
        if command.command.contains("/") {
            capabilities.push("filesystem_access".to_string());
        }
        
        // Check for network access
        if command.command.contains("curl") || command.command.contains("wget") {
            capabilities.push("network_access".to_string());
        }
        
        capabilities
    }
    
    /// Determine enhancement strategy
    fn determine_enhancement_strategy(
        &self,
        command: &BashCommand,
        mcp_tool: &MCPTool,
        config: &MCPConfig,
    ) -> (EnhancementType, ExecutionStrategy) {
        // Check if full replacement is possible
        if self.can_fully_replace(command, mcp_tool) {
            return (EnhancementType::FullReplacement, ExecutionStrategy::MCPOnly);
        }
        
        // Check if augmentation is beneficial
        if self.can_augment(command, mcp_tool) {
            return (EnhancementType::Augmentation, ExecutionStrategy::Parallel);
        }
        
        // Use fallback strategy
        (EnhancementType::WithFallback, config.default_strategy.clone())
    }
    
    /// Check if command can be fully replaced
    fn can_fully_replace(&self, command: &BashCommand, mcp_tool: &MCPTool) -> bool {
        // Simple commands that map directly to MCP tools
        let replaceable = vec![
            "docker ps", "docker images", "git status", "git log",
            "kubectl get pods", "kubectl get services",
        ];
        
        replaceable.iter().any(|&cmd| command.command.starts_with(cmd))
    }
    
    /// Check if command can be augmented
    fn can_augment(&self, command: &BashCommand, mcp_tool: &MCPTool) -> bool {
        // Commands that benefit from MCP enhancement
        command.command.contains("|") || command.command.contains("grep")
    }
    
    /// Estimate performance improvement
    fn estimate_performance(&self, command: &BashCommand, mcp_tool: &MCPTool) -> PerformanceEstimate {
        let mut speedup = 1.0;
        let mut efficiency = 1.0;
        let mut reliability = 0.9;
        
        // Docker commands are typically 2-3x faster via MCP
        if mcp_tool.server == "docker" {
            speedup = 2.5;
            efficiency = 2.0;
            reliability = 0.95;
        }
        
        // Git commands benefit from caching
        if mcp_tool.server == "git" {
            speedup = 1.8;
            efficiency = 1.5;
            reliability = 0.98;
        }
        
        // File operations can be much faster
        if mcp_tool.server == "filesystem" {
            speedup = 3.0;
            efficiency = 2.5;
            reliability = 0.99;
        }
        
        // Calculate overall benefit
        let benefit_score = (speedup * 0.4 + efficiency * 0.3 + reliability * 0.3) / 3.0;
        
        PerformanceEstimate {
            speedup,
            efficiency,
            reliability,
            benefit_score,
        }
    }
    
    /// Get default command mappings
    fn default_mappings() -> Vec<CommandMapping> {
        vec![
            // Docker mappings
            Self::create_docker_mapping(r"^docker\s+ps", "list_containers"),
            Self::create_docker_mapping(r"^docker\s+images", "list_images"),
            Self::create_docker_mapping(r"^docker\s+run", "run_container"),
            Self::create_docker_mapping(r"^docker\s+exec", "exec_container"),
            
            // Git mappings
            Self::create_git_mapping(r"^git\s+status", "get_status"),
            Self::create_git_mapping(r"^git\s+log", "get_log"),
            Self::create_git_mapping(r"^git\s+diff", "get_diff"),
            Self::create_git_mapping(r"^git\s+commit", "create_commit"),
            
            // Kubernetes mappings
            Self::create_k8s_mapping(r"^kubectl\s+get\s+pods?", "list_pods"),
            Self::create_k8s_mapping(r"^kubectl\s+get\s+services?", "list_services"),
            Self::create_k8s_mapping(r"^kubectl\s+logs", "get_logs"),
            
            // File system mappings
            Self::create_fs_mapping(r"^find\s+", "search_files"),
            Self::create_fs_mapping(r"^grep\s+-r", "search_content"),
            Self::create_fs_mapping(r"^ls\s+", "list_directory"),
        ]
    }
    
    /// Create Docker command mapping
    fn create_docker_mapping(pattern: &str, tool: &str) -> CommandMapping {
        CommandMapping {
            bash_pattern: regex::Regex::new(pattern).unwrap(),
            server: "docker".to_string(),
            tool: tool.to_string(),
            param_extractor: Box::new(DockerParamExtractor),
            success_criteria: crate::synthex_bashgod::mcp_integration::SuccessCriteria {
                output_pattern: None,
                max_time_ms: Some(5000),
                required_fields: vec![],
            },
        }
    }
    
    /// Create Git command mapping
    fn create_git_mapping(pattern: &str, tool: &str) -> CommandMapping {
        CommandMapping {
            bash_pattern: regex::Regex::new(pattern).unwrap(),
            server: "git".to_string(),
            tool: tool.to_string(),
            param_extractor: Box::new(GitParamExtractor),
            success_criteria: crate::synthex_bashgod::mcp_integration::SuccessCriteria {
                output_pattern: None,
                max_time_ms: Some(3000),
                required_fields: vec![],
            },
        }
    }
    
    /// Create Kubernetes command mapping
    fn create_k8s_mapping(pattern: &str, tool: &str) -> CommandMapping {
        CommandMapping {
            bash_pattern: regex::Regex::new(pattern).unwrap(),
            server: "kubernetes".to_string(),
            tool: tool.to_string(),
            param_extractor: Box::new(K8sParamExtractor),
            success_criteria: crate::synthex_bashgod::mcp_integration::SuccessCriteria {
                output_pattern: None,
                max_time_ms: Some(10000),
                required_fields: vec![],
            },
        }
    }
    
    /// Create file system command mapping
    fn create_fs_mapping(pattern: &str, tool: &str) -> CommandMapping {
        CommandMapping {
            bash_pattern: regex::Regex::new(pattern).unwrap(),
            server: "filesystem".to_string(),
            tool: tool.to_string(),
            param_extractor: Box::new(FsParamExtractor),
            success_criteria: crate::synthex_bashgod::mcp_integration::SuccessCriteria {
                output_pattern: None,
                max_time_ms: Some(30000),
                required_fields: vec![],
            },
        }
    }
    
    /// Get enhancer statistics
    pub async fn get_stats(&self) -> (u64, u64, u64, f32) {
        let stats = self.stats.read().await;
        (
            stats.enhancements_attempted,
            stats.successful_enhancements,
            stats.cache_hits,
            stats.avg_speedup,
        )
    }
}

/// Docker parameter extractor
struct DockerParamExtractor;

impl crate::synthex_bashgod::mcp_integration::ParamExtractor for DockerParamExtractor {
    fn extract(&self, command: &str) -> std::collections::HashMap<String, serde_json::Value> {
        let mut params = std::collections::HashMap::new();
        
        // Extract common Docker flags
        if command.contains("-a") || command.contains("--all") {
            params.insert("all".to_string(), serde_json::Value::Bool(true));
        }
        
        if command.contains("-q") || command.contains("--quiet") {
            params.insert("quiet".to_string(), serde_json::Value::Bool(true));
        }
        
        if let Some(filter) = Self::extract_filter(command) {
            params.insert("filter".to_string(), serde_json::Value::String(filter));
        }
        
        params
    }
}

impl DockerParamExtractor {
    fn extract_filter(command: &str) -> Option<String> {
        if let Some(pos) = command.find("--filter") {
            let rest = &command[pos + 8..].trim();
            if let Some(end) = rest.find(' ') {
                Some(rest[..end].to_string())
            } else {
                Some(rest.to_string())
            }
        } else {
            None
        }
    }
}

/// Git parameter extractor
struct GitParamExtractor;

impl crate::synthex_bashgod::mcp_integration::ParamExtractor for GitParamExtractor {
    fn extract(&self, command: &str) -> std::collections::HashMap<String, serde_json::Value> {
        let mut params = std::collections::HashMap::new();
        
        // Extract common Git options
        if command.contains("--oneline") {
            params.insert("oneline".to_string(), serde_json::Value::Bool(true));
        }
        
        if let Some(n) = Self::extract_number(command, "-n") {
            params.insert("limit".to_string(), serde_json::Value::Number(n.into()));
        }
        
        params
    }
}

impl GitParamExtractor {
    fn extract_number(command: &str, flag: &str) -> Option<u32> {
        if let Some(pos) = command.find(flag) {
            let rest = &command[pos + flag.len()..].trim();
            if let Some(end) = rest.find(' ') {
                rest[..end].parse().ok()
            } else {
                rest.parse().ok()
            }
        } else {
            None
        }
    }
}

/// Kubernetes parameter extractor
struct K8sParamExtractor;

impl crate::synthex_bashgod::mcp_integration::ParamExtractor for K8sParamExtractor {
    fn extract(&self, command: &str) -> std::collections::HashMap<String, serde_json::Value> {
        let mut params = std::collections::HashMap::new();
        
        // Extract namespace
        if let Some(ns) = Self::extract_namespace(command) {
            params.insert("namespace".to_string(), serde_json::Value::String(ns));
        }
        
        // Extract selector
        if let Some(selector) = Self::extract_selector(command) {
            params.insert("selector".to_string(), serde_json::Value::String(selector));
        }
        
        params
    }
}

impl K8sParamExtractor {
    fn extract_namespace(command: &str) -> Option<String> {
        Self::extract_flag_value(command, "-n") 
            .or_else(|| Self::extract_flag_value(command, "--namespace"))
    }
    
    fn extract_selector(command: &str) -> Option<String> {
        Self::extract_flag_value(command, "-l")
            .or_else(|| Self::extract_flag_value(command, "--selector"))
    }
    
    fn extract_flag_value(command: &str, flag: &str) -> Option<String> {
        if let Some(pos) = command.find(flag) {
            let rest = &command[pos + flag.len()..].trim();
            if let Some(end) = rest.find(' ') {
                Some(rest[..end].to_string())
            } else {
                Some(rest.to_string())
            }
        } else {
            None
        }
    }
}

/// File system parameter extractor
struct FsParamExtractor;

impl crate::synthex_bashgod::mcp_integration::ParamExtractor for FsParamExtractor {
    fn extract(&self, command: &str) -> std::collections::HashMap<String, serde_json::Value> {
        let mut params = std::collections::HashMap::new();
        
        // Extract path
        if let Some(path) = Self::extract_path(command) {
            params.insert("path".to_string(), serde_json::Value::String(path));
        }
        
        // Extract pattern for find/grep
        if let Some(pattern) = Self::extract_pattern(command) {
            params.insert("pattern".to_string(), serde_json::Value::String(pattern));
        }
        
        params
    }
}

impl FsParamExtractor {
    fn extract_path(command: &str) -> Option<String> {
        // Simple extraction - first argument that looks like a path
        let parts: Vec<&str> = command.split_whitespace().collect();
        for part in parts.iter().skip(1) {
            if part.starts_with('/') || part.starts_with('.') {
                return Some(part.to_string());
            }
        }
        None
    }
    
    fn extract_pattern(command: &str) -> Option<String> {
        // Extract pattern from find -name or grep pattern
        if command.contains("find") {
            Self::extract_flag_value(command, "-name")
        } else if command.contains("grep") {
            // Simple pattern extraction for grep
            let parts: Vec<&str> = command.split_whitespace().collect();
            if parts.len() > 1 {
                Some(parts[1].to_string())
            } else {
                None
            }
        } else {
            None
        }
    }
    
    fn extract_flag_value(command: &str, flag: &str) -> Option<String> {
        if let Some(pos) = command.find(flag) {
            let rest = &command[pos + flag.len()..].trim();
            if let Some(end) = rest.find(' ') {
                Some(rest[..end].trim_matches('"').trim_matches('\'').to_string())
            } else {
                Some(rest.trim_matches('"').trim_matches('\'').to_string())
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_tool_enhancement() {
        let enhancer = ToolEnhancer::new(vec![]);
        
        let command = BashCommand {
            id: "test-1".to_string(),
            command: "docker ps -a".to_string(),
            args: vec![],
            env: Default::default(),
            working_dir: None,
            resources: Default::default(),
        };
        
        assert!(enhancer.can_enhance(&command).await);
    }
    
    #[test]
    fn test_docker_param_extraction() {
        let extractor = DockerParamExtractor;
        
        let params = extractor.extract("docker ps -a -q --filter status=running");
        
        assert_eq!(params.get("all"), Some(&serde_json::Value::Bool(true)));
        assert_eq!(params.get("quiet"), Some(&serde_json::Value::Bool(true)));
    }
    
    #[test]
    fn test_k8s_param_extraction() {
        let extractor = K8sParamExtractor;
        
        let params = extractor.extract("kubectl get pods -n kube-system -l app=nginx");
        
        assert_eq!(
            params.get("namespace"),
            Some(&serde_json::Value::String("kube-system".to_string()))
        );
        assert_eq!(
            params.get("selector"),
            Some(&serde_json::Value::String("app=nginx".to_string()))
        );
    }
}