//! Tool Enhancer - Analyzes bash commands for MCP enhancement opportunities
//! 
//! This module provides intelligent analysis of bash commands to identify
//! opportunities for enhancement with MCP tools, creating hybrid command strategies.

use std::sync::Arc;
use tokio::sync::RwLock;
use regex::Regex;
use lazy_static::lazy_static;
use serde_json::json;

use crate::mcp_manager::{McpManager, Result, McpError};
use super::{EnhancedCommand, Enhancement, ExecutionStrategy, MergeStrategy, DataFlow, SmartRoutingConfig};
use super::registry::ToolRegistry;

lazy_static! {
    /// Docker command patterns
    static ref DOCKER_PATTERNS: Vec<(Regex, &'static str)> = vec![
        (Regex::new(r"^docker\s+ps").unwrap(), "list_containers"),
        (Regex::new(r"^docker\s+images").unwrap(), "list_images"),
        (Regex::new(r"^docker\s+run").unwrap(), "run_container"),
        (Regex::new(r"^docker\s+build").unwrap(), "build_image"),
        (Regex::new(r"^docker\s+logs").unwrap(), "get_logs"),
        (Regex::new(r"^docker\s+exec").unwrap(), "exec_command"),
        (Regex::new(r"^docker\s+stop").unwrap(), "stop_container"),
        (Regex::new(r"^docker\s+rm").unwrap(), "remove_container"),
        (Regex::new(r"^docker-compose\s+up").unwrap(), "compose_up"),
        (Regex::new(r"^docker-compose\s+down").unwrap(), "compose_down"),
    ];

    /// Git/GitHub command patterns
    static ref GIT_PATTERNS: Vec<(Regex, &'static str)> = vec![
        (Regex::new(r"^git\s+status").unwrap(), "get_status"),
        (Regex::new(r"^git\s+log").unwrap(), "get_commits"),
        (Regex::new(r"^git\s+diff").unwrap(), "get_diff"),
        (Regex::new(r"^git\s+add").unwrap(), "stage_files"),
        (Regex::new(r"^git\s+commit").unwrap(), "create_commit"),
        (Regex::new(r"^git\s+push").unwrap(), "push_changes"),
        (Regex::new(r"^git\s+pull").unwrap(), "pull_changes"),
        (Regex::new(r"^gh\s+pr\s+create").unwrap(), "create_pull_request"),
        (Regex::new(r"^gh\s+issue\s+create").unwrap(), "create_issue"),
        (Regex::new(r"^gh\s+release\s+create").unwrap(), "create_release"),
    ];

    /// File operation patterns
    static ref FILE_PATTERNS: Vec<(Regex, &'static str)> = vec![
        (Regex::new(r"^ls\s+").unwrap(), "list_directory"),
        (Regex::new(r"^cat\s+").unwrap(), "read_file"),
        (Regex::new(r"^grep\s+").unwrap(), "search_files"),
        (Regex::new(r"^find\s+").unwrap(), "find_files"),
        (Regex::new(r"^cp\s+").unwrap(), "copy_file"),
        (Regex::new(r"^mv\s+").unwrap(), "move_file"),
        (Regex::new(r"^rm\s+").unwrap(), "delete_file"),
        (Regex::new(r"^mkdir\s+").unwrap(), "create_directory"),
        (Regex::new(r"^touch\s+").unwrap(), "create_file"),
        (Regex::new(r"^chmod\s+").unwrap(), "change_permissions"),
    ];

    /// Kubernetes command patterns
    static ref K8S_PATTERNS: Vec<(Regex, &'static str)> = vec![
        (Regex::new(r"^kubectl\s+get\s+pods").unwrap(), "list_pods"),
        (Regex::new(r"^kubectl\s+get\s+services").unwrap(), "list_services"),
        (Regex::new(r"^kubectl\s+apply").unwrap(), "apply_manifest"),
        (Regex::new(r"^kubectl\s+delete").unwrap(), "delete_resource"),
        (Regex::new(r"^kubectl\s+logs").unwrap(), "get_pod_logs"),
        (Regex::new(r"^kubectl\s+exec").unwrap(), "exec_in_pod"),
        (Regex::new(r"^kubectl\s+describe").unwrap(), "describe_resource"),
        (Regex::new(r"^kubectl\s+rollout").unwrap(), "manage_rollout"),
        (Regex::new(r"^helm\s+install").unwrap(), "helm_install"),
        (Regex::new(r"^helm\s+upgrade").unwrap(), "helm_upgrade"),
    ];

    /// Monitoring command patterns
    static ref MONITORING_PATTERNS: Vec<(Regex, &'static str)> = vec![
        (Regex::new(r"^curl.*metrics").unwrap(), "get_metrics"),
        (Regex::new(r"^prometheus.*query").unwrap(), "query_prometheus"),
        (Regex::new(r"^grafana.*dashboard").unwrap(), "manage_dashboard"),
        (Regex::new(r"^tail.*log").unwrap(), "tail_logs"),
        (Regex::new(r"^journalctl").unwrap(), "system_logs"),
    ];
}

/// Enhanced command analysis result
#[derive(Debug)]
pub struct AnalysisResult {
    pub command_type: CommandType,
    pub mcp_opportunities: Vec<McpOpportunity>,
    pub recommended_strategy: ExecutionStrategy,
    pub performance_estimate: PerformanceEstimate,
}

/// Type of command being analyzed
#[derive(Debug, Clone, PartialEq)]
pub enum CommandType {
    Docker,
    Git,
    FileOperation,
    Kubernetes,
    Monitoring,
    Pipeline,
    Mixed,
    Unknown,
}

/// MCP enhancement opportunity
#[derive(Debug, Clone)]
pub struct McpOpportunity {
    pub tool: String,
    pub method: String,
    pub confidence: f32,
    pub performance_gain: f32,
    pub parameters: serde_json::Value,
}

/// Performance estimate for command execution
#[derive(Debug)]
pub struct PerformanceEstimate {
    pub bash_only_ms: u64,
    pub mcp_enhanced_ms: u64,
    pub improvement_percent: f32,
}

/// Analyze a bash command and enhance it with MCP capabilities
pub async fn enhance_bash_command(
    command: &str,
    tool_registry: &Arc<RwLock<ToolRegistry>>,
    mcp_manager: &McpManager,
) -> Result<EnhancedCommand> {
    // Analyze the command
    let analysis = analyze_command(command, tool_registry).await?;
    
    // Build enhancements based on analysis
    let enhancements = build_enhancements(&analysis, command)?;
    
    // Determine execution strategy
    let strategy = determine_strategy(&analysis, &enhancements);
    
    Ok(EnhancedCommand {
        original: command.to_string(),
        enhancements,
        strategy,
    })
}

/// Analyze a command to identify enhancement opportunities
async fn analyze_command(
    command: &str,
    tool_registry: &Arc<RwLock<ToolRegistry>>,
) -> Result<AnalysisResult> {
    let command_type = identify_command_type(command);
    let mcp_opportunities = find_mcp_opportunities(command, &command_type, tool_registry).await?;
    let performance_estimate = estimate_performance(command, &mcp_opportunities);
    
    let recommended_strategy = if mcp_opportunities.is_empty() {
        ExecutionStrategy::BashFirst
    } else if mcp_opportunities.iter().all(|o| o.confidence > 0.8) {
        ExecutionStrategy::McpFirst
    } else {
        ExecutionStrategy::Smart(SmartRoutingConfig {
            prefer_mcp: performance_estimate.improvement_percent > 20.0,
            fallback_enabled: true,
            performance_threshold_ms: 1000,
        })
    };
    
    Ok(AnalysisResult {
        command_type,
        mcp_opportunities,
        recommended_strategy,
        performance_estimate,
    })
}

/// Identify the type of command
fn identify_command_type(command: &str) -> CommandType {
    if command.contains('|') || command.contains('&&') || command.contains(';') {
        return CommandType::Pipeline;
    }
    
    if DOCKER_PATTERNS.iter().any(|(re, _)| re.is_match(command)) {
        CommandType::Docker
    } else if GIT_PATTERNS.iter().any(|(re, _)| re.is_match(command)) {
        CommandType::Git
    } else if FILE_PATTERNS.iter().any(|(re, _)| re.is_match(command)) {
        CommandType::FileOperation
    } else if K8S_PATTERNS.iter().any(|(re, _)| re.is_match(command)) {
        CommandType::Kubernetes
    } else if MONITORING_PATTERNS.iter().any(|(re, _)| re.is_match(command)) {
        CommandType::Monitoring
    } else {
        CommandType::Unknown
    }
}

/// Find MCP enhancement opportunities
async fn find_mcp_opportunities(
    command: &str,
    command_type: &CommandType,
    tool_registry: &Arc<RwLock<ToolRegistry>>,
) -> Result<Vec<McpOpportunity>> {
    let mut opportunities = Vec::new();
    let registry = tool_registry.read().await;
    
    match command_type {
        CommandType::Docker => {
            for (pattern, method) in DOCKER_PATTERNS.iter() {
                if pattern.is_match(command) {
                    if registry.has_capability("docker", method) {
                        opportunities.push(McpOpportunity {
                            tool: "docker".to_string(),
                            method: method.to_string(),
                            confidence: 0.9,
                            performance_gain: 2.5,
                            parameters: extract_docker_params(command, method)?,
                        });
                    }
                }
            }
        },
        CommandType::Git => {
            for (pattern, method) in GIT_PATTERNS.iter() {
                if pattern.is_match(command) {
                    if registry.has_capability("github", method) {
                        opportunities.push(McpOpportunity {
                            tool: "github".to_string(),
                            method: method.to_string(),
                            confidence: 0.85,
                            performance_gain: 1.8,
                            parameters: extract_git_params(command, method)?,
                        });
                    }
                }
            }
        },
        CommandType::FileOperation => {
            for (pattern, method) in FILE_PATTERNS.iter() {
                if pattern.is_match(command) {
                    if registry.has_capability("filesystem", method) {
                        opportunities.push(McpOpportunity {
                            tool: "filesystem".to_string(),
                            method: method.to_string(),
                            confidence: 0.95,
                            performance_gain: 3.0,
                            parameters: extract_file_params(command, method)?,
                        });
                    }
                }
            }
        },
        CommandType::Kubernetes => {
            for (pattern, method) in K8S_PATTERNS.iter() {
                if pattern.is_match(command) {
                    if registry.has_capability("kubernetes", method) {
                        opportunities.push(McpOpportunity {
                            tool: "kubernetes".to_string(),
                            method: method.to_string(),
                            confidence: 0.9,
                            performance_gain: 2.0,
                            parameters: extract_k8s_params(command, method)?,
                        });
                    }
                }
            }
        },
        CommandType::Pipeline => {
            // Analyze pipeline components
            let components = split_pipeline(command);
            for component in components {
                let sub_type = identify_command_type(&component);
                let sub_opportunities = find_mcp_opportunities(&component, &sub_type, tool_registry).await?;
                opportunities.extend(sub_opportunities);
            }
        },
        _ => {}
    }
    
    Ok(opportunities)
}

/// Build enhancements from opportunities
fn build_enhancements(
    analysis: &AnalysisResult,
    command: &str,
) -> Result<Vec<Enhancement>> {
    let mut enhancements = Vec::new();
    
    for opportunity in &analysis.mcp_opportunities {
        if opportunity.confidence > 0.7 {
            if opportunity.confidence > 0.9 && opportunity.performance_gain > 2.0 {
                // High confidence and performance - replace
                enhancements.push(Enhancement::Replace {
                    tool: opportunity.tool.clone(),
                    method: opportunity.method.clone(),
                    params: opportunity.parameters.clone(),
                });
            } else if analysis.command_type == CommandType::Pipeline {
                // Pipeline - chain tools
                let tools = analysis.mcp_opportunities.iter()
                    .map(|o| (o.tool.clone(), o.method.clone()))
                    .collect();
                enhancements.push(Enhancement::Chain {
                    tools,
                    flow: DataFlow::Pipeline,
                });
                break; // Only create one chain enhancement
            } else {
                // Medium confidence - augment
                enhancements.push(Enhancement::Augment {
                    tool: opportunity.tool.clone(),
                    method: opportunity.method.clone(),
                    merge_strategy: MergeStrategy::JsonMerge,
                });
            }
        }
    }
    
    // Add parallel enhancements for monitoring
    if analysis.command_type == CommandType::Monitoring {
        for opportunity in &analysis.mcp_opportunities {
            enhancements.push(Enhancement::Parallel {
                tool: opportunity.tool.clone(),
                method: opportunity.method.clone(),
                correlation_id: uuid::Uuid::new_v4().to_string(),
            });
        }
    }
    
    Ok(enhancements)
}

/// Determine execution strategy
fn determine_strategy(
    analysis: &AnalysisResult,
    enhancements: &[Enhancement],
) -> ExecutionStrategy {
    if enhancements.is_empty() {
        return ExecutionStrategy::BashFirst;
    }
    
    let has_replace = enhancements.iter().any(|e| matches!(e, Enhancement::Replace { .. }));
    let has_chain = enhancements.iter().any(|e| matches!(e, Enhancement::Chain { .. }));
    
    if has_replace && enhancements.len() == 1 {
        ExecutionStrategy::McpOnly
    } else if has_chain {
        ExecutionStrategy::McpFirst
    } else if analysis.performance_estimate.improvement_percent > 50.0 {
        ExecutionStrategy::McpFirst
    } else {
        analysis.recommended_strategy.clone()
    }
}

/// Estimate performance improvement
fn estimate_performance(
    command: &str,
    opportunities: &[McpOpportunity],
) -> PerformanceEstimate {
    // Base estimates (milliseconds)
    let bash_only_ms = estimate_bash_duration(command);
    
    let mcp_enhanced_ms = if opportunities.is_empty() {
        bash_only_ms
    } else {
        let avg_gain = opportunities.iter()
            .map(|o| o.performance_gain)
            .sum::<f32>() / opportunities.len() as f32;
        (bash_only_ms as f32 / avg_gain) as u64
    };
    
    let improvement_percent = if bash_only_ms > 0 {
        ((bash_only_ms - mcp_enhanced_ms) as f32 / bash_only_ms as f32) * 100.0
    } else {
        0.0
    };
    
    PerformanceEstimate {
        bash_only_ms,
        mcp_enhanced_ms,
        improvement_percent,
    }
}

/// Estimate bash command duration
fn estimate_bash_duration(command: &str) -> u64 {
    // Simple heuristic based on command type and complexity
    let base = if command.contains("docker") {
        500
    } else if command.contains("kubectl") {
        300
    } else if command.contains("git") {
        200
    } else {
        100
    };
    
    // Add complexity factors
    let pipes = command.matches('|').count() as u64;
    let files = command.matches('/').count() as u64;
    
    base + (pipes * 50) + (files * 10)
}

/// Split pipeline into components
fn split_pipeline(command: &str) -> Vec<String> {
    command.split(|c| c == '|' || c == ';')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Extract Docker parameters from command
fn extract_docker_params(command: &str, method: &str) -> Result<serde_json::Value> {
    let parts: Vec<&str> = command.split_whitespace().collect();
    
    match method {
        "list_containers" => {
            let all = command.contains("-a") || command.contains("--all");
            Ok(json!({ "all": all }))
        },
        "run_container" => {
            let image = parts.get(2).unwrap_or(&"").to_string();
            let detached = command.contains("-d") || command.contains("--detach");
            Ok(json!({ "image": image, "detached": detached }))
        },
        "get_logs" => {
            let container = parts.get(2).unwrap_or(&"").to_string();
            let follow = command.contains("-f") || command.contains("--follow");
            Ok(json!({ "container": container, "follow": follow }))
        },
        _ => Ok(json!({})),
    }
}

/// Extract Git parameters from command
fn extract_git_params(command: &str, method: &str) -> Result<serde_json::Value> {
    let parts: Vec<&str> = command.split_whitespace().collect();
    
    match method {
        "get_commits" => {
            let limit = if let Some(n_pos) = parts.iter().position(|&p| p == "-n") {
                parts.get(n_pos + 1).and_then(|s| s.parse::<u32>().ok()).unwrap_or(10)
            } else {
                10
            };
            Ok(json!({ "limit": limit }))
        },
        "create_commit" => {
            let message = command.split("-m").nth(1)
                .map(|s| s.trim().trim_matches('"'))
                .unwrap_or("");
            Ok(json!({ "message": message }))
        },
        _ => Ok(json!({})),
    }
}

/// Extract file operation parameters
fn extract_file_params(command: &str, method: &str) -> Result<serde_json::Value> {
    let parts: Vec<&str> = command.split_whitespace().collect();
    
    match method {
        "list_directory" => {
            let path = parts.get(1).unwrap_or(&".").to_string();
            let all = command.contains("-a") || command.contains("--all");
            let long = command.contains("-l") || command.contains("--long");
            Ok(json!({ "path": path, "all": all, "long": long }))
        },
        "read_file" => {
            let path = parts.get(1).unwrap_or(&"").to_string();
            Ok(json!({ "path": path }))
        },
        "search_files" => {
            let pattern = parts.get(1).unwrap_or(&"").to_string();
            let path = parts.get(2).unwrap_or(&".").to_string();
            let recursive = command.contains("-r") || command.contains("-R");
            Ok(json!({ "pattern": pattern, "path": path, "recursive": recursive }))
        },
        _ => Ok(json!({})),
    }
}

/// Extract Kubernetes parameters
fn extract_k8s_params(command: &str, method: &str) -> Result<serde_json::Value> {
    let parts: Vec<&str> = command.split_whitespace().collect();
    
    let namespace = if let Some(n_pos) = parts.iter().position(|&p| p == "-n" || p == "--namespace") {
        parts.get(n_pos + 1).map(|s| s.to_string())
    } else {
        None
    };
    
    match method {
        "list_pods" => {
            Ok(json!({ "namespace": namespace }))
        },
        "get_pod_logs" => {
            let pod = parts.get(3).unwrap_or(&"").to_string();
            let follow = command.contains("-f") || command.contains("--follow");
            Ok(json!({ "pod": pod, "namespace": namespace, "follow": follow }))
        },
        "apply_manifest" => {
            let file = parts.iter()
                .position(|&p| p == "-f")
                .and_then(|i| parts.get(i + 1))
                .map(|s| s.to_string());
            Ok(json!({ "file": file, "namespace": namespace }))
        },
        _ => Ok(json!({ "namespace": namespace })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identify_command_type() {
        assert_eq!(identify_command_type("docker ps -a"), CommandType::Docker);
        assert_eq!(identify_command_type("git status"), CommandType::Git);
        assert_eq!(identify_command_type("ls -la"), CommandType::FileOperation);
        assert_eq!(identify_command_type("kubectl get pods"), CommandType::Kubernetes);
        assert_eq!(identify_command_type("docker ps | grep web"), CommandType::Pipeline);
    }

    #[test]
    fn test_estimate_performance() {
        let opportunities = vec![
            McpOpportunity {
                tool: "docker".to_string(),
                method: "list_containers".to_string(),
                confidence: 0.9,
                performance_gain: 2.5,
                parameters: json!({}),
            },
        ];
        
        let estimate = estimate_performance("docker ps", &opportunities);
        assert!(estimate.improvement_percent > 0.0);
        assert!(estimate.mcp_enhanced_ms < estimate.bash_only_ms);
    }

    #[test]
    fn test_extract_docker_params() {
        let params = extract_docker_params("docker ps -a", "list_containers").unwrap();
        assert_eq!(params["all"], true);
        
        let params = extract_docker_params("docker run -d nginx", "run_container").unwrap();
        assert_eq!(params["image"], "nginx");
        assert_eq!(params["detached"], true);
    }
}