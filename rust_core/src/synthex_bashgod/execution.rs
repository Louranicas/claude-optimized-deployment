//! Command chain execution engine
//!
//! This module implements the core execution logic for bash command chains,
//! including parallelization, resource management, and error handling.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tokio::sync::{Semaphore, RwLock};
use tokio::time::timeout;
use tracing::{debug, error, info, warn, instrument};

use crate::synthex_bashgod::{
    BashGodError, CommandChain, ExecutionConfig, ExecutionContext,
    ExecutionState, Command as ChainCommand, CommandType,
};

/// Result of executing a command chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Unique execution ID
    pub id: String,
    
    /// Whether the execution was successful
    pub success: bool,
    
    /// Combined output from all commands
    pub output: String,
    
    /// Error message if execution failed
    pub error: Option<String>,
    
    /// Total execution time
    pub execution_time: Duration,
    
    /// Individual command timings
    pub command_timings: Vec<CommandTiming>,
    
    /// Performance metrics collected during execution
    pub metrics: HashMap<String, f64>,
    
    /// Optimizations that were applied
    pub optimizations_applied: Vec<String>,
}

/// Timing information for an individual command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandTiming {
    pub command: String,
    pub duration: Duration,
    pub success: bool,
}

/// Command chain executor
pub struct ChainExecutor {
    /// Semaphore for limiting concurrent executions
    concurrency_limiter: Arc<Semaphore>,
    
    /// Execution history for learning
    history: Arc<RwLock<Vec<ExecutionResult>>>,
    
    /// Resource monitor
    resource_monitor: Arc<ResourceMonitor>,
}

impl ChainExecutor {
    /// Create a new chain executor
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            concurrency_limiter: Arc::new(Semaphore::new(max_concurrent)),
            history: Arc::new(RwLock::new(Vec::new())),
            resource_monitor: Arc::new(ResourceMonitor::new()),
        }
    }
    
    /// Execute a command chain
    #[instrument(skip(self, context))]
    pub async fn execute(
        &self,
        context: ExecutionContext,
        config: ExecutionConfig,
    ) -> Result<ExecutionResult, BashGodError> {
        let start_time = Instant::now();
        let execution_id = uuid::Uuid::new_v4().to_string();
        
        info!("Starting execution {}", execution_id);
        
        // Acquire execution permit
        let _permit = self.concurrency_limiter.acquire().await
            .map_err(|e| BashGodError::Execution(format!("Failed to acquire permit: {}", e)))?;
        
        // Initialize result
        let mut result = ExecutionResult {
            id: execution_id.clone(),
            success: true,
            output: String::new(),
            error: None,
            execution_time: Duration::default(),
            command_timings: Vec::new(),
            metrics: HashMap::new(),
            optimizations_applied: Vec::new(),
        };
        
        // Check resource availability
        if !self.resource_monitor.check_availability(&context.chain).await {
            return Err(BashGodError::Execution("Insufficient resources".to_string()));
        }
        
        // Execute commands based on parallelization settings
        if config.parallel_execution {
            self.execute_parallel(&context, &config, &mut result).await?;
        } else {
            self.execute_sequential(&context, &config, &mut result).await?;
        }
        
        // Record total execution time
        result.execution_time = start_time.elapsed();
        
        // Collect final metrics
        if config.collect_metrics {
            result.metrics = self.resource_monitor.collect_metrics().await;
        }
        
        // Store in history
        self.history.write().await.push(result.clone());
        
        info!("Completed execution {} in {:?}", execution_id, result.execution_time);
        
        Ok(result)
    }
    
    /// Execute commands sequentially
    async fn execute_sequential(
        &self,
        context: &ExecutionContext,
        config: &ExecutionConfig,
        result: &mut ExecutionResult,
    ) -> Result<(), BashGodError> {
        for (idx, cmd) in context.chain.commands.iter().enumerate() {
            debug!("Executing command {}: {}", idx, cmd.command);
            
            let timing = self.execute_single_command(
                cmd,
                &context.environment,
                &context.working_directory,
                config.timeout,
            ).await?;
            
            result.output.push_str(&timing.output);
            result.output.push('\n');
            
            result.command_timings.push(CommandTiming {
                command: cmd.command.clone(),
                duration: timing.duration,
                success: timing.success,
            });
            
            if !timing.success && context.constraints.stop_on_error {
                result.success = false;
                result.error = Some(format!("Command failed: {}", cmd.command));
                break;
            }
        }
        
        Ok(())
    }
    
    /// Execute commands in parallel where possible
    async fn execute_parallel(
        &self,
        context: &ExecutionContext,
        config: &ExecutionConfig,
        result: &mut ExecutionResult,
    ) -> Result<(), BashGodError> {
        use petgraph::graph::{DiGraph, NodeIndex};
        use petgraph::algo::toposort;
        
        // Build dependency graph
        let mut graph = DiGraph::<usize, ()>::new();
        let mut node_map = HashMap::new();
        
        // Add nodes
        for (idx, _cmd) in context.chain.commands.iter().enumerate() {
            let node = graph.add_node(idx);
            node_map.insert(idx, node);
        }
        
        // Add edges for dependencies
        for dep in &context.chain.dependencies {
            if let (Some(&from_node), Some(&to_node)) = 
                (node_map.get(&dep.from), node_map.get(&dep.to)) {
                graph.add_edge(from_node, to_node, ());
            }
        }
        
        // Get execution order
        let order = toposort(&graph, None)
            .map_err(|_| BashGodError::Execution("Circular dependency detected".to_string()))?;
        
        // Group commands by level (can be executed in parallel)
        let mut levels = Vec::new();
        let mut visited = std::collections::HashSet::new();
        
        for node in order {
            if visited.contains(&node) {
                continue;
            }
            
            let mut level = vec![node];
            visited.insert(node);
            
            // Find all nodes at the same level (no dependencies between them)
            for &other in &order {
                if visited.contains(&other) {
                    continue;
                }
                
                let mut can_parallel = true;
                for &n in &level {
                    if graph.contains_edge(n, other) || graph.contains_edge(other, n) {
                        can_parallel = false;
                        break;
                    }
                }
                
                if can_parallel {
                    level.push(other);
                    visited.insert(other);
                }
            }
            
            levels.push(level);
        }
        
        // Execute levels
        for level in levels {
            let mut handles = Vec::new();
            
            for node in level {
                let idx = graph[node];
                let cmd = &context.chain.commands[idx];
                
                let cmd_clone = cmd.clone();
                let env_clone = context.environment.clone();
                let dir_clone = context.working_directory.clone();
                let timeout_duration = config.timeout;
                
                let handle = tokio::spawn(async move {
                    self.execute_single_command(
                        &cmd_clone,
                        &env_clone,
                        &dir_clone,
                        timeout_duration,
                    ).await
                });
                
                handles.push((idx, handle));
            }
            
            // Wait for all commands in this level
            for (idx, handle) in handles {
                match handle.await {
                    Ok(Ok(timing)) => {
                        result.output.push_str(&format!("[{}] {}\n", idx, timing.output));
                        
                        result.command_timings.push(CommandTiming {
                            command: context.chain.commands[idx].command.clone(),
                            duration: timing.duration,
                            success: timing.success,
                        });
                        
                        if !timing.success && context.constraints.stop_on_error {
                            result.success = false;
                            result.error = Some(format!("Command failed: {}", 
                                context.chain.commands[idx].command));
                            return Ok(());
                        }
                    }
                    Ok(Err(e)) => {
                        return Err(e);
                    }
                    Err(e) => {
                        return Err(BashGodError::Execution(
                            format!("Task panicked: {}", e)
                        ));
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Execute a single command
    async fn execute_single_command(
        &self,
        cmd: &ChainCommand,
        env: &HashMap<String, String>,
        working_dir: &std::path::Path,
        timeout_duration: Duration,
    ) -> Result<SingleCommandResult, BashGodError> {
        let start = Instant::now();
        
        // Parse command
        let parts = shell_words::split(&cmd.command)
            .map_err(|e| BashGodError::Execution(format!("Failed to parse command: {}", e)))?;
        
        if parts.is_empty() {
            return Err(BashGodError::Execution("Empty command".to_string()));
        }
        
        // Build command
        let mut command = Command::new(&parts[0]);
        
        if parts.len() > 1 {
            command.args(&parts[1..]);
        }
        
        command
            .current_dir(working_dir)
            .envs(env)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        
        // Execute with timeout
        let output = timeout(timeout_duration, command.output()).await
            .map_err(|_| BashGodError::Execution(format!("Command timed out: {}", cmd.command)))?
            .map_err(|e| BashGodError::Execution(format!("Failed to execute command: {}", e)))?;
        
        let duration = start.elapsed();
        
        Ok(SingleCommandResult {
            output: String::from_utf8_lossy(&output.stdout).to_string(),
            error: String::from_utf8_lossy(&output.stderr).to_string(),
            success: output.status.success(),
            duration,
        })
    }
}

/// Result from executing a single command
struct SingleCommandResult {
    output: String,
    error: String,
    success: bool,
    duration: Duration,
}

/// Resource monitor for tracking system resources
struct ResourceMonitor {
    metrics: Arc<RwLock<HashMap<String, f64>>>,
}

impl ResourceMonitor {
    fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Check if resources are available for execution
    async fn check_availability(&self, _chain: &CommandChain) -> bool {
        // TODO: Implement actual resource checking
        // For now, always return true
        true
    }
    
    /// Collect current metrics
    async fn collect_metrics(&self) -> HashMap<String, f64> {
        let mut metrics = HashMap::new();
        
        // CPU usage
        if let Ok(cpu_info) = procfs::CpuInfo::new() {
            metrics.insert("cpu_count".to_string(), cpu_info.num_cores() as f64);
        }
        
        // Memory usage
        if let Ok(meminfo) = procfs::Meminfo::new() {
            let total = meminfo.mem_total as f64;
            let available = meminfo.mem_available.unwrap_or(0) as f64;
            let used = total - available;
            metrics.insert("memory_used_gb".to_string(), used / 1024.0 / 1024.0 / 1024.0);
            metrics.insert("memory_total_gb".to_string(), total / 1024.0 / 1024.0 / 1024.0);
            metrics.insert("memory_usage_percent".to_string(), (used / total) * 100.0);
        }
        
        // Load average
        if let Ok(loadavg) = procfs::LoadAverage::new() {
            metrics.insert("load_1min".to_string(), loadavg.one);
            metrics.insert("load_5min".to_string(), loadavg.five);
            metrics.insert("load_15min".to_string(), loadavg.fifteen);
        }
        
        // Store metrics
        *self.metrics.write().await = metrics.clone();
        
        metrics
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synthex_bashgod::core::{CommandType, Priority};
    
    #[tokio::test]
    async fn test_simple_execution() {
        let executor = ChainExecutor::new(4);
        
        let chain = CommandChain {
            id: "test".to_string(),
            original: "echo hello".to_string(),
            commands: vec![
                ChainCommand {
                    index: 0,
                    command: "echo hello".to_string(),
                    cmd_type: CommandType::Shell,
                    parallelizable: false,
                    estimated_duration: None,
                    resources: Default::default(),
                }
            ],
            dependencies: vec![],
            metadata: crate::synthex_bashgod::core::ChainMetadata {
                source: "test".to_string(),
                tags: vec![],
                priority: Priority::Normal,
                created_at: 0,
                modified_at: 0,
            },
        };
        
        let context = ExecutionContext {
            id: "test-exec".to_string(),
            chain,
            environment: HashMap::new(),
            working_directory: std::env::current_dir().unwrap(),
            constraints: crate::synthex_bashgod::core::ExecutionConstraints {
                timeout: Duration::from_secs(30),
                max_retries: 3,
                stop_on_error: true,
                resource_limits: crate::synthex_bashgod::core::ResourceLimits {
                    max_cpu_cores: 4.0,
                    max_memory: 1024 * 1024 * 1024,
                    max_disk_space: None,
                    network_rate_limit: None,
                    max_time_seconds: 30,
                    max_disk_io_mbps: 100.0,
                },
            },
            state: ExecutionState::Pending,
        };
        
        let result = executor.execute(context, ExecutionConfig::default()).await.unwrap();
        assert!(result.success);
        assert!(result.output.contains("hello"));
    }
}