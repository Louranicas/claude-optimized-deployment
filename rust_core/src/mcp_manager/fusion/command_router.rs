//! Command Router - Intelligent routing between bash and MCP tools
//! 
//! This module provides smart routing logic to determine the optimal execution path
//! for enhanced commands, with load balancing and fallback mechanisms.

use std::sync::Arc;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex};
use tokio::process::Command;
use futures::future::join_all;
use tracing::{info, warn, error, debug};

use crate::mcp_manager::{McpManager, Result, McpError};
use super::{
    EnhancedCommand, Enhancement, ExecutionStrategy, ExecutionResult,
    McpResult, ExecutionMetrics, MergeStrategy, DataFlow, SmartRoutingConfig
};
use super::registry::ToolRegistry;

/// Load balancing statistics for MCP servers
#[derive(Debug, Default)]
struct LoadStats {
    requests: u64,
    total_duration_ms: u64,
    failures: u64,
    last_failure: Option<Instant>,
}

/// Command router with intelligent routing and load balancing
pub struct CommandRouter {
    mcp_manager: Arc<McpManager>,
    tool_registry: Arc<RwLock<ToolRegistry>>,
    load_stats: Arc<RwLock<HashMap<String, LoadStats>>>,
    circuit_breakers: Arc<RwLock<HashMap<String, CircuitBreaker>>>,
}

/// Simple circuit breaker for fault tolerance
#[derive(Debug)]
struct CircuitBreaker {
    failure_threshold: u32,
    reset_timeout: Duration,
    failure_count: u32,
    last_failure: Option<Instant>,
    state: CircuitState,
}

#[derive(Debug, Clone, PartialEq)]
enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

impl CommandRouter {
    /// Create a new command router
    pub fn new(
        mcp_manager: Arc<McpManager>,
        tool_registry: Arc<RwLock<ToolRegistry>>,
    ) -> Self {
        Self {
            mcp_manager,
            tool_registry,
            load_stats: Arc::new(RwLock::new(HashMap::new())),
            circuit_breakers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Initialize the command router
    pub async fn initialize(&self) -> Result<()> {
        // Initialize circuit breakers for known tools
        let registry = self.tool_registry.read().await;
        let mut breakers = self.circuit_breakers.write().await;
        
        for tool in registry.list_tools() {
            breakers.insert(tool.clone(), CircuitBreaker {
                failure_threshold: 5,
                reset_timeout: Duration::from_secs(30),
                failure_count: 0,
                last_failure: None,
                state: CircuitState::Closed,
            });
        }
        
        Ok(())
    }

    /// Route and execute an enhanced command
    pub async fn route_and_execute(&self, command: &EnhancedCommand) -> Result<ExecutionResult> {
        let start = Instant::now();
        
        match &command.strategy {
            ExecutionStrategy::BashFirst => {
                self.execute_bash_first(command).await
            },
            ExecutionStrategy::McpFirst => {
                self.execute_mcp_first(command).await
            },
            ExecutionStrategy::Parallel => {
                self.execute_parallel(command).await
            },
            ExecutionStrategy::McpOnly => {
                self.execute_mcp_only(command).await
            },
            ExecutionStrategy::Smart(config) => {
                self.execute_smart(command, config).await
            },
        }
    }

    /// Execute bash command first, then enhance with MCP
    async fn execute_bash_first(&self, command: &EnhancedCommand) -> Result<ExecutionResult> {
        let start = Instant::now();
        
        // Execute bash command
        let bash_result = self.execute_bash(&command.original).await?;
        let bash_duration = start.elapsed().as_millis() as u64;
        
        // Execute MCP enhancements
        let mcp_results = self.execute_enhancements(&command.enhancements, Some(&bash_result.stdout)).await?;
        
        // Merge results
        let merged = self.merge_results(bash_result, mcp_results, &command.enhancements)?;
        
        Ok(ExecutionResult {
            stdout: merged.stdout,
            stderr: merged.stderr,
            exit_code: merged.exit_code,
            mcp_results: merged.mcp_results,
            metrics: ExecutionMetrics {
                total_duration_ms: start.elapsed().as_millis() as u64,
                bash_duration_ms: Some(bash_duration),
                mcp_duration_ms: Some(start.elapsed().as_millis() as u64 - bash_duration),
                enhancement_count: command.enhancements.len(),
                bytes_processed: merged.stdout.len() + merged.stderr.len(),
            },
        })
    }

    /// Execute MCP tools first, then bash if needed
    async fn execute_mcp_first(&self, command: &EnhancedCommand) -> Result<ExecutionResult> {
        let start = Instant::now();
        
        // Execute MCP enhancements
        let mcp_results = self.execute_enhancements(&command.enhancements, None).await?;
        let mcp_duration = start.elapsed().as_millis() as u64;
        
        // Check if we need to execute bash
        let needs_bash = !command.enhancements.iter().any(|e| matches!(e, Enhancement::Replace { .. }));
        
        if needs_bash {
            // Execute bash with MCP results as input
            let mcp_output = self.format_mcp_output(&mcp_results);
            let bash_result = self.execute_bash_with_input(&command.original, &mcp_output).await?;
            
            Ok(ExecutionResult {
                stdout: bash_result.stdout,
                stderr: bash_result.stderr,
                exit_code: bash_result.exit_code,
                mcp_results,
                metrics: ExecutionMetrics {
                    total_duration_ms: start.elapsed().as_millis() as u64,
                    bash_duration_ms: Some(start.elapsed().as_millis() as u64 - mcp_duration),
                    mcp_duration_ms: Some(mcp_duration),
                    enhancement_count: command.enhancements.len(),
                    bytes_processed: bash_result.stdout.len() + bash_result.stderr.len(),
                },
            })
        } else {
            // MCP only - format output
            let output = self.format_mcp_output(&mcp_results);
            
            Ok(ExecutionResult {
                stdout: output,
                stderr: String::new(),
                exit_code: 0,
                mcp_results,
                metrics: ExecutionMetrics {
                    total_duration_ms: mcp_duration,
                    bash_duration_ms: None,
                    mcp_duration_ms: Some(mcp_duration),
                    enhancement_count: command.enhancements.len(),
                    bytes_processed: output.len(),
                },
            })
        }
    }

    /// Execute bash and MCP in parallel
    async fn execute_parallel(&self, command: &EnhancedCommand) -> Result<ExecutionResult> {
        let start = Instant::now();
        
        // Spawn parallel tasks
        let bash_future = self.execute_bash(&command.original);
        let mcp_future = self.execute_enhancements(&command.enhancements, None);
        
        // Wait for both to complete
        let (bash_result, mcp_results) = tokio::join!(bash_future, mcp_future);
        
        let bash_result = bash_result?;
        let mcp_results = mcp_results?;
        
        // Merge results
        let merged = self.merge_results(bash_result, mcp_results, &command.enhancements)?;
        
        Ok(ExecutionResult {
            stdout: merged.stdout,
            stderr: merged.stderr,
            exit_code: merged.exit_code,
            mcp_results: merged.mcp_results,
            metrics: ExecutionMetrics {
                total_duration_ms: start.elapsed().as_millis() as u64,
                bash_duration_ms: None, // Parallel execution
                mcp_duration_ms: None,  // Parallel execution
                enhancement_count: command.enhancements.len(),
                bytes_processed: merged.stdout.len() + merged.stderr.len(),
            },
        })
    }

    /// Execute only MCP tools (bash replaced)
    async fn execute_mcp_only(&self, command: &EnhancedCommand) -> Result<ExecutionResult> {
        let start = Instant::now();
        
        let mcp_results = self.execute_enhancements(&command.enhancements, None).await?;
        let output = self.format_mcp_output(&mcp_results);
        
        Ok(ExecutionResult {
            stdout: output,
            stderr: String::new(),
            exit_code: 0,
            mcp_results,
            metrics: ExecutionMetrics {
                total_duration_ms: start.elapsed().as_millis() as u64,
                bash_duration_ms: None,
                mcp_duration_ms: Some(start.elapsed().as_millis() as u64),
                enhancement_count: command.enhancements.len(),
                bytes_processed: output.len(),
            },
        })
    }

    /// Execute with smart routing based on conditions
    async fn execute_smart(&self, command: &EnhancedCommand, config: &SmartRoutingConfig) -> Result<ExecutionResult> {
        let start = Instant::now();
        
        // Check tool availability and load
        let best_tool = self.select_best_tool(&command.enhancements).await?;
        
        if let Some(tool) = best_tool {
            // Check circuit breaker
            let breakers = self.circuit_breakers.read().await;
            if let Some(breaker) = breakers.get(&tool) {
                match breaker.state {
                    CircuitState::Open => {
                        if config.fallback_enabled {
                            info!("Circuit breaker open for {}, falling back to bash", tool);
                            return self.execute_bash_first(command).await;
                        } else {
                            return Err(McpError::ServiceUnavailable(format!("Tool {} is unavailable", tool)));
                        }
                    },
                    CircuitState::HalfOpen => {
                        // Try with caution
                        debug!("Circuit breaker half-open for {}, attempting execution", tool);
                    },
                    CircuitState::Closed => {
                        // Normal execution
                    }
                }
            }
        }
        
        // Execute based on preference and performance
        if config.prefer_mcp {
            match self.execute_mcp_first(command).await {
                Ok(result) => {
                    // Update success stats
                    if let Some(tool) = best_tool {
                        self.update_success_stats(&tool).await;
                    }
                    Ok(result)
                },
                Err(e) => {
                    if config.fallback_enabled {
                        warn!("MCP execution failed, falling back to bash: {}", e);
                        if let Some(tool) = best_tool {
                            self.update_failure_stats(&tool).await;
                        }
                        self.execute_bash_first(command).await
                    } else {
                        Err(e)
                    }
                }
            }
        } else {
            self.execute_bash_first(command).await
        }
    }

    /// Select the best tool based on load and availability
    async fn select_best_tool(&self, enhancements: &[Enhancement]) -> Result<Option<String>> {
        let stats = self.load_stats.read().await;
        let mut best_tool = None;
        let mut best_score = f64::MAX;
        
        for enhancement in enhancements {
            let tool = match enhancement {
                Enhancement::Replace { tool, .. } |
                Enhancement::Augment { tool, .. } |
                Enhancement::Parallel { tool, .. } => tool,
                Enhancement::Chain { tools, .. } => &tools[0].0,
            };
            
            let score = if let Some(stat) = stats.get(tool) {
                // Calculate score based on average response time and failure rate
                let avg_response = if stat.requests > 0 {
                    stat.total_duration_ms as f64 / stat.requests as f64
                } else {
                    100.0 // Default estimate
                };
                
                let failure_rate = if stat.requests > 0 {
                    stat.failures as f64 / stat.requests as f64
                } else {
                    0.0
                };
                
                // Score combines response time and failure rate
                avg_response * (1.0 + failure_rate * 10.0)
            } else {
                100.0 // Default score for new tools
            };
            
            if score < best_score {
                best_score = score;
                best_tool = Some(tool.clone());
            }
        }
        
        Ok(best_tool)
    }

    /// Execute bash command
    async fn execute_bash(&self, command: &str) -> Result<BashResult> {
        let output = Command::new("bash")
            .arg("-c")
            .arg(command)
            .output()
            .await
            .map_err(|e| McpError::ExecutionError(format!("Bash execution failed: {}", e)))?;
        
        Ok(BashResult {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code().unwrap_or(-1),
        })
    }

    /// Execute bash command with input
    async fn execute_bash_with_input(&self, command: &str, input: &str) -> Result<BashResult> {
        use tokio::io::AsyncWriteExt;
        
        let mut child = Command::new("bash")
            .arg("-c")
            .arg(command)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| McpError::ExecutionError(format!("Bash spawn failed: {}", e)))?;
        
        // Write input
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(input.as_bytes()).await
                .map_err(|e| McpError::ExecutionError(format!("Failed to write stdin: {}", e)))?;
        }
        
        let output = child.wait_with_output().await
            .map_err(|e| McpError::ExecutionError(format!("Bash execution failed: {}", e)))?;
        
        Ok(BashResult {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code().unwrap_or(-1),
        })
    }

    /// Execute MCP enhancements
    async fn execute_enhancements(
        &self,
        enhancements: &[Enhancement],
        bash_output: Option<&str>,
    ) -> Result<Vec<McpResult>> {
        let mut results = Vec::new();
        
        for enhancement in enhancements {
            match enhancement {
                Enhancement::Replace { tool, method, params } => {
                    let start = Instant::now();
                    let result = self.execute_mcp_tool(tool, method, params).await?;
                    results.push(McpResult {
                        tool: tool.clone(),
                        method: method.clone(),
                        result,
                        duration_ms: start.elapsed().as_millis() as u64,
                    });
                },
                Enhancement::Augment { tool, method, .. } => {
                    let start = Instant::now();
                    let mut params = serde_json::json!({});
                    if let Some(output) = bash_output {
                        params["bash_output"] = serde_json::Value::String(output.to_string());
                    }
                    let result = self.execute_mcp_tool(tool, method, &params).await?;
                    results.push(McpResult {
                        tool: tool.clone(),
                        method: method.clone(),
                        result,
                        duration_ms: start.elapsed().as_millis() as u64,
                    });
                },
                Enhancement::Parallel { tool, method, correlation_id } => {
                    let start = Instant::now();
                    let params = serde_json::json!({ "correlation_id": correlation_id });
                    let result = self.execute_mcp_tool(tool, method, &params).await?;
                    results.push(McpResult {
                        tool: tool.clone(),
                        method: method.clone(),
                        result,
                        duration_ms: start.elapsed().as_millis() as u64,
                    });
                },
                Enhancement::Chain { tools, flow } => {
                    let chain_results = self.execute_chain(tools, flow, bash_output).await?;
                    results.extend(chain_results);
                },
            }
        }
        
        Ok(results)
    }

    /// Execute a chain of MCP tools
    async fn execute_chain(
        &self,
        tools: &[(String, String)],
        flow: &DataFlow,
        initial_input: Option<&str>,
    ) -> Result<Vec<McpResult>> {
        let mut results = Vec::new();
        let mut previous_output = initial_input.map(|s| serde_json::Value::String(s.to_string()));
        
        match flow {
            DataFlow::Pipeline => {
                for (tool, method) in tools {
                    let start = Instant::now();
                    let params = if let Some(output) = previous_output {
                        serde_json::json!({ "input": output })
                    } else {
                        serde_json::json!({})
                    };
                    
                    let result = self.execute_mcp_tool(tool, method, &params).await?;
                    previous_output = Some(result.clone());
                    
                    results.push(McpResult {
                        tool: tool.clone(),
                        method: method.clone(),
                        result,
                        duration_ms: start.elapsed().as_millis() as u64,
                    });
                }
            },
            DataFlow::ParallelJoin => {
                let futures: Vec<_> = tools.iter().map(|(tool, method)| {
                    let params = if let Some(output) = &previous_output {
                        serde_json::json!({ "input": output })
                    } else {
                        serde_json::json!({})
                    };
                    self.execute_mcp_tool(tool, method, &params)
                }).collect();
                
                let parallel_results = join_all(futures).await;
                
                for ((tool, method), result) in tools.iter().zip(parallel_results) {
                    results.push(McpResult {
                        tool: tool.clone(),
                        method: method.clone(),
                        result: result?,
                        duration_ms: 0, // TODO: Track individual durations
                    });
                }
            },
            DataFlow::Conditional(_conditions) => {
                // TODO: Implement conditional flow
                return Err(McpError::NotImplemented("Conditional flow not yet implemented".to_string()));
            },
        }
        
        Ok(results)
    }

    /// Execute a single MCP tool
    async fn execute_mcp_tool(
        &self,
        tool: &str,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        // Get server registry and find the appropriate server
        let registry = self.mcp_manager.registry().read().await;
        let server = registry.get_server_by_type(tool)
            .ok_or_else(|| McpError::ServerNotFound(tool.to_string()))?;
        
        // Execute the tool method
        server.execute_tool(method, params).await
    }

    /// Merge bash and MCP results
    fn merge_results(
        &self,
        bash_result: BashResult,
        mcp_results: Vec<McpResult>,
        enhancements: &[Enhancement],
    ) -> Result<ExecutionResult> {
        let mut stdout = bash_result.stdout;
        let stderr = bash_result.stderr;
        let exit_code = bash_result.exit_code;
        
        // Apply merge strategies
        for (enhancement, mcp_result) in enhancements.iter().zip(&mcp_results) {
            if let Enhancement::Augment { merge_strategy, .. } = enhancement {
                match merge_strategy {
                    MergeStrategy::Append => {
                        stdout.push_str("\n--- MCP Enhancement ---\n");
                        stdout.push_str(&serde_json::to_string_pretty(&mcp_result.result).unwrap_or_default());
                    },
                    MergeStrategy::Prepend => {
                        let mut new_stdout = String::new();
                        new_stdout.push_str("--- MCP Enhancement ---\n");
                        new_stdout.push_str(&serde_json::to_string_pretty(&mcp_result.result).unwrap_or_default());
                        new_stdout.push_str("\n--- Original Output ---\n");
                        new_stdout.push_str(&stdout);
                        stdout = new_stdout;
                    },
                    MergeStrategy::JsonMerge => {
                        // Try to merge as JSON
                        if let Ok(bash_json) = serde_json::from_str::<serde_json::Value>(&stdout) {
                            if let Ok(merged) = self.merge_json(bash_json, mcp_result.result.clone()) {
                                stdout = serde_json::to_string_pretty(&merged).unwrap_or(stdout);
                            }
                        }
                    },
                    MergeStrategy::Custom(func) => {
                        // TODO: Implement custom merge functions
                        warn!("Custom merge function {} not implemented", func);
                    },
                }
            }
        }
        
        Ok(ExecutionResult {
            stdout,
            stderr,
            exit_code,
            mcp_results,
            metrics: ExecutionMetrics::default(),
        })
    }

    /// Merge two JSON values
    fn merge_json(&self, mut base: serde_json::Value, enhancement: serde_json::Value) -> Result<serde_json::Value> {
        use serde_json::Value;
        
        match (&mut base, enhancement) {
            (Value::Object(base_map), Value::Object(enh_map)) => {
                for (k, v) in enh_map {
                    base_map.insert(k, v);
                }
                Ok(base)
            },
            (Value::Array(base_arr), Value::Array(enh_arr)) => {
                base_arr.extend(enh_arr);
                Ok(base)
            },
            _ => Ok(base), // Return base unchanged for incompatible types
        }
    }

    /// Format MCP output for display
    fn format_mcp_output(&self, results: &[McpResult]) -> String {
        let mut output = String::new();
        
        for (i, result) in results.iter().enumerate() {
            if i > 0 {
                output.push_str("\n---\n");
            }
            
            output.push_str(&format!("Tool: {} | Method: {} | Duration: {}ms\n",
                result.tool, result.method, result.duration_ms));
            
            if let Ok(formatted) = serde_json::to_string_pretty(&result.result) {
                output.push_str(&formatted);
            } else {
                output.push_str(&format!("{:?}", result.result));
            }
        }
        
        output
    }

    /// Update success statistics
    async fn update_success_stats(&self, tool: &str) {
        let mut stats = self.load_stats.write().await;
        let stat = stats.entry(tool.to_string()).or_default();
        stat.requests += 1;
        
        // Update circuit breaker
        let mut breakers = self.circuit_breakers.write().await;
        if let Some(breaker) = breakers.get_mut(tool) {
            breaker.failure_count = 0;
            breaker.state = CircuitState::Closed;
        }
    }

    /// Update failure statistics
    async fn update_failure_stats(&self, tool: &str) {
        let mut stats = self.load_stats.write().await;
        let stat = stats.entry(tool.to_string()).or_default();
        stat.requests += 1;
        stat.failures += 1;
        stat.last_failure = Some(Instant::now());
        
        // Update circuit breaker
        let mut breakers = self.circuit_breakers.write().await;
        if let Some(breaker) = breakers.get_mut(tool) {
            breaker.failure_count += 1;
            breaker.last_failure = Some(Instant::now());
            
            if breaker.failure_count >= breaker.failure_threshold {
                breaker.state = CircuitState::Open;
                error!("Circuit breaker opened for tool: {}", tool);
            }
        }
    }
}

/// Result from bash execution
#[derive(Debug)]
struct BashResult {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_manager::config::McpConfig;

    #[tokio::test]
    async fn test_command_router_creation() {
        let config = McpConfig::default();
        let mcp_manager = Arc::new(McpManager::new(config));
        let tool_registry = Arc::new(RwLock::new(ToolRegistry::new()));
        let router = CommandRouter::new(mcp_manager, tool_registry);
        
        assert!(router.initialize().await.is_ok());
    }

    #[tokio::test]
    async fn test_bash_execution() {
        let config = McpConfig::default();
        let mcp_manager = Arc::new(McpManager::new(config));
        let tool_registry = Arc::new(RwLock::new(ToolRegistry::new()));
        let router = CommandRouter::new(mcp_manager, tool_registry);
        
        let result = router.execute_bash("echo 'Hello, World!'").await.unwrap();
        assert_eq!(result.stdout.trim(), "Hello, World!");
        assert_eq!(result.exit_code, 0);
    }
}