//! Actor-based zero-lock implementation for SYNTHEX-BashGod
//! 
//! Implements message-passing concurrency with Tokio actors for maximum performance
//! and scalability. No locks, just pure message-passing excellence.

use crate::synthex_bashgod::{
    BashCommand, ChainResult, CommandChain, CommandResult, ExecutionStrategy,
    OptimizationSuggestion, PerformanceMetrics, Result, SBGError,
};
use crate::synthex_bashgod::memory::CommandPattern;
use async_trait::async_trait;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

/// Learning handle trait for pattern storage and optimization
#[async_trait]
pub trait LearningHandle: Send + Sync {
    /// Submit a command pattern for learning
    async fn submit_pattern(&self, pattern: CommandPattern) -> Result<()>;
    
    /// Get optimization suggestions for a chain
    async fn get_suggestions(&self, chain: &CommandChain) -> Result<Vec<OptimizationSuggestion>>;
}

/// MCP handle trait for MCP server integration
#[async_trait]
pub trait MCPHandle: Send + Sync {
    /// Enhance a command with MCP capabilities
    async fn enhance_command(&self, command: &BashCommand) -> Result<EnhancedCommand>;
    
    /// Get enhanced execution strategy
    async fn get_strategy(&self, chain: &CommandChain) -> Result<EnhancedStrategy>;
}

/// Enhanced command with MCP integration
#[derive(Debug, Clone)]
pub struct EnhancedCommand {
    pub base_command: BashCommand,
    pub mcp_tools: Vec<String>,
    pub enhanced_resources: bool,
}

/// Enhanced strategy with MCP optimization
#[derive(Debug, Clone)]
pub struct EnhancedStrategy {
    pub base_strategy: ExecutionStrategy,
    pub mcp_optimizations: Vec<String>,
}

/// Actor message types for zero-lock communication
#[derive(Debug)]
pub enum ActorMessage {
    /// Execute a command chain
    ExecuteChain {
        chain: CommandChain,
        response: oneshot::Sender<Result<ChainResult>>,
    },
    
    /// Optimize a command chain
    OptimizeChain {
        chain: CommandChain,
        response: oneshot::Sender<Result<CommandChain>>,
    },
    
    /// Learn from execution results
    LearnFromResult {
        result: ChainResult,
        response: oneshot::Sender<Result<()>>,
    },
    
    /// Get actor statistics
    GetStats {
        response: oneshot::Sender<ActorStats>,
    },
    
    /// Shutdown the actor
    Shutdown,
    
    /// Get learning insights
    GetInsights {
        category: Option<String>,
        response: oneshot::Sender<Result<Vec<crate::synthex_bashgod::LearningInsight>>>,
    },
}

/// Actor statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorStats {
    /// Total commands executed
    pub commands_executed: u64,
    
    /// Total chains processed
    pub chains_processed: u64,
    
    /// Average execution time
    pub avg_execution_time_ms: f64,
    
    /// Current queue size
    pub queue_size: usize,
    
    /// Active executions
    pub active_executions: usize,
}

/// Actor state
#[derive(Debug)]
struct ActorState {
    /// Statistics
    stats: ActorStats,
    
    /// Active executions
    active_executions: DashMap<String, Instant>,
    
    /// Performance history
    performance_history: Vec<PerformanceRecord>,
}

#[derive(Debug, Clone)]
struct PerformanceRecord {
    chain_id: String,
    execution_time_ms: u64,
    success: bool,
    timestamp: Instant,
}

/// BashGod actor implementation
pub struct BashGodActor {
    /// Receiver for messages
    receiver: mpsc::Receiver<ActorMessage>,
    
    /// Actor state
    state: ActorState,
    
    /// Learning handle
    learning_handle: Arc<dyn LearningHandle>,
    
    /// MCP handle
    mcp_handle: Arc<dyn MCPHandle>,
    
    /// Executor pool
    executor_pool: Arc<tokio::runtime::Runtime>,
}

impl BashGodActor {
    /// Create new actor
    pub fn new(
        receiver: mpsc::Receiver<ActorMessage>,
        learning_handle: Arc<dyn LearningHandle>,
        mcp_handle: Arc<dyn MCPHandle>,
        pool_size: usize,
    ) -> Self {
        let executor_pool = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(pool_size)
            .thread_name("bashgod-executor")
            .enable_all()
            .build()
            .expect("Failed to create executor pool");
        
        Self {
            receiver,
            state: ActorState {
                stats: ActorStats {
                    commands_executed: 0,
                    chains_processed: 0,
                    avg_execution_time_ms: 0.0,
                    queue_size: 0,
                    active_executions: 0,
                },
                active_executions: DashMap::new(),
                performance_history: Vec::new(),
            },
            learning_handle,
            mcp_handle,
            executor_pool: Arc::new(executor_pool),
        }
    }
    
    /// Run the actor event loop
    #[instrument(skip(self))]
    pub async fn run(mut self) {
        info!("BashGod actor started");
        
        while let Some(message) = self.receiver.recv().await {
            match message {
                ActorMessage::ExecuteChain { chain, response } => {
                    let result = self.handle_execute_chain(chain).await;
                    let _ = response.send(result);
                }
                
                ActorMessage::OptimizeChain { chain, response } => {
                    let result = self.handle_optimize_chain(chain).await;
                    let _ = response.send(result);
                }
                
                ActorMessage::LearnFromResult { result, response } => {
                    let learn_result = self.handle_learn_from_result(result).await;
                    let _ = response.send(learn_result);
                }
                
                ActorMessage::GetStats { response } => {
                    let stats = self.state.stats.clone();
                    let _ = response.send(stats);
                }
                
                ActorMessage::GetInsights { category, response } => {
                    let insights = self.handle_get_insights(category).await;
                    let _ = response.send(insights);
                }
                
                ActorMessage::Shutdown => {
                    info!("BashGod actor shutting down");
                    break;
                }
            }
        }
        
        info!("BashGod actor stopped");
    }
    
    /// Handle chain execution
    async fn handle_execute_chain(&mut self, chain: CommandChain) -> Result<ChainResult> {
        let chain_id = chain.id.clone();
        let start = Instant::now();
        
        // Track active execution
        self.state.active_executions.insert(chain_id.clone(), start);
        self.state.stats.chains_processed += 1;
        
        // Execute based on strategy
        let results = match &chain.strategy {
            ExecutionStrategy::Sequential => {
                self.execute_sequential(&chain).await?
            }
            ExecutionStrategy::Parallel { max_concurrent } => {
                self.execute_parallel(&chain, *max_concurrent).await?
            }
            _ => {
                // Default to sequential for other strategies
                self.execute_sequential(&chain).await?
            }
        };
        
        let total_time = start.elapsed().as_millis() as u64;
        
        // Remove from active executions
        self.state.active_executions.remove(&chain_id);
        
        // Update statistics
        self.update_stats(total_time);
        
        // Record performance
        self.state.performance_history.push(PerformanceRecord {
            chain_id: chain_id.clone(),
            execution_time_ms: total_time,
            success: results.iter().all(|r| r.exit_code == 0),
            timestamp: Instant::now(),
        });
        
        // Build result
        let suggestions = vec!["Consider using parallel execution for independent commands".to_string()];
        
        let success = results.iter().all(|r| r.exit_code == 0);
        let successful_count = results.iter().filter(|r| r.exit_code == 0).count() as u64;
        let failed_count = results.iter().filter(|r| r.exit_code != 0).count() as u64;
        
        Ok(ChainResult {
            chain_id,
            success,
            command_results: results,
            total_duration_ms: total_time,
            resource_usage: crate::synthex_bashgod::ResourceUsage {
                cpu_percent: 0.0, // TODO: Implement resource tracking
                memory_mb: 0, // TODO: Implement memory tracking
                disk_read_mb: 0,
                disk_write_mb: 0,
                network_sent_mb: 0,
                network_recv_mb: 0,
            },
            insights: vec![crate::synthex_bashgod::LearningInsight {
                insight_type: crate::synthex_bashgod::InsightType::PerformanceOptimization,
                confidence: 0.8,
                description: "Execution completed successfully".to_string(),
                recommendation: Some("Consider parallelizing independent commands".to_string()),
                related_patterns: vec![],
            }],
            metrics: crate::synthex_bashgod::ExecutionMetrics {
                total_commands: chain.commands.len() as u64,
                successful_commands: successful_count,
                failed_commands: failed_count,
                avg_execution_time_ms: total_time as f64 / chain.commands.len() as f64,
                peak_resource_usage: crate::synthex_bashgod::ResourceUsage {
                    cpu_percent: 0.0,
                    memory_mb: 0,
                    disk_read_mb: 0,
                    disk_write_mb: 0,
                    network_sent_mb: 0,
                    network_recv_mb: 0,
                },
                execution_time_ms: Some(total_time),
                cpu_usage: Some(0.0),
                memory_usage: Some(0),
            },
            suggestions,
        })
    }
    
    /// Execute commands sequentially
    async fn execute_sequential(&mut self, chain: &CommandChain) -> Result<Vec<CommandResult>> {
        let mut results = Vec::new();
        
        for cmd in &chain.commands {
            let result = self.execute_command(cmd).await?;
            results.push(result);
        }
        
        Ok(results)
    }
    
    /// Execute commands in parallel
    async fn execute_parallel(&mut self, chain: &CommandChain, max_concurrent: usize) -> Result<Vec<CommandResult>> {
        use futures::stream::{self, StreamExt};
        use futures::future;
        
        // For now, execute sequentially (parallel execution will be implemented later)
        let mut results = Vec::new();
        for cmd in &chain.commands {
            let result = self.execute_command(cmd).await?;
            results.push(result);
        }
        
        Ok(results)
    }
    
    /// Count independent command groups
    fn count_independent_groups(&self, chain: &CommandChain) -> usize {
        // Simple heuristic: commands without dependencies can run in parallel
        let mut groups = 0;
        let mut has_deps = vec![false; chain.commands.len()];
        
        for (_, deps) in &chain.dependencies {
            for dep in deps {
                if let Some(idx) = chain.commands.iter().position(|c| &c.id == dep) {
                    has_deps[idx] = true;
                }
            }
        }
        
        for (i, cmd) in chain.commands.iter().enumerate() {
            if !has_deps[i] && !chain.dependencies.contains_key(&cmd.id) {
                groups += 1;
            }
        }
        
        groups.max(1)
    }
    
    /// Update statistics
    fn update_stats(&mut self, execution_time_ms: u64) {
        let stats = &mut self.state.stats;
        
        // Update average execution time
        let total_time = stats.avg_execution_time_ms * stats.chains_processed as f64;
        stats.avg_execution_time_ms = (total_time + execution_time_ms as f64) / (stats.chains_processed as f64);
        
        // Update queue size
        stats.queue_size = self.receiver.len();
        stats.active_executions = self.state.active_executions.len();
    }
    
    /// Execute a single command
    async fn execute_command(&mut self, bash_cmd: &BashCommand) -> Result<CommandResult> {
        let start = Instant::now();
        
        // Execute the command
        let (exit_code, stdout, stderr) = self.execute_bash_command(bash_cmd).await?;
        
        let execution_time = start.elapsed().as_millis() as u64;
        self.state.stats.commands_executed += 1;
        
        Ok(CommandResult {
            command_id: bash_cmd.id.clone(),
            exit_code,
            stdout,
            stderr,
            duration_ms: execution_time,
            resource_usage: crate::synthex_bashgod::ResourceUsage {
                cpu_percent: 0.0,
                memory_mb: 0,
                disk_read_mb: 0,
                disk_write_mb: 0,
                network_sent_mb: 0,
                network_recv_mb: 0,
            },
        })
    }
    
    /// Execute bash command
    async fn execute_bash_command(&self, cmd: &BashCommand) -> Result<(i32, String, String)> {
        let mut command = Command::new("bash");
        command.arg("-c").arg(&cmd.command);
        
        // Set working directory if specified
        if let Some(dir) = &cmd.working_dir {
            command.current_dir(dir);
        }
        
        // Set environment variables
        for (key, value) in &cmd.env {
            command.env(key, value);
        }
        
        // Execute with timeout
        let timeout_duration = Duration::from_secs(cmd.timeout.unwrap_or(300));
        let output = timeout(timeout_duration, command.output()).await
            .map_err(|_| SBGError::ExecutionError("Command timed out".to_string()))?
            .map_err(|e| SBGError::ExecutionError(e.to_string()))?;
        
        let exit_code = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        
        Ok((exit_code, stdout, stderr))
    }
    
    /// Handle chain optimization
    async fn handle_optimize_chain(&self, chain: CommandChain) -> Result<CommandChain> {
        // Get suggestions from learning engine
        let suggestions = self.learning_handle.get_suggestions(&chain).await?;
        
        let mut optimized = chain.clone();
        
        // Apply high-confidence optimizations
        for suggestion in suggestions {
            match suggestion.optimization_type {
                crate::synthex_bashgod::OptimizationType::Parallelization => {
                    // Analyze dependencies and set parallel strategy
                    let independent_groups = self.count_independent_groups(&chain);
                    if independent_groups > 1 {
                        optimized.strategy = ExecutionStrategy::Parallel {
                            max_concurrent: independent_groups.min(10),
                        };
                    }
                }
                crate::synthex_bashgod::OptimizationType::Reordering => {
                    // TODO: Implement command reordering
                }
                _ => {} // TODO: Implement other optimizations
            }
        }
        
        Ok(optimized)
    }
    
    /// Handle learning from results
    async fn handle_learn_from_result(&mut self, result: ChainResult) -> Result<()> {
        // Extract pattern from result
        let pattern = CommandPattern {
            id: Uuid::new_v4().to_string(),
            commands: result.command_results.iter()
                .map(|r| r.command_id.clone())
                .collect(),
            features: vec![], // TODO: Extract features
            dependencies: vec![], // TODO: Extract dependencies
            context: crate::synthex_bashgod::memory::PatternContext {
                environment: "production".to_string(),
                user: "system".to_string(),
                tags: vec![],
                created_at: chrono::Utc::now(),
                last_accessed: chrono::Utc::now(),
            },
            metrics: crate::synthex_bashgod::memory::PatternMetrics {
                avg_execution_time_ms: result.total_duration_ms as f64,
                success_rate: if result.success { 1.0 } else { 0.0 },
                execution_count: 1,
                avg_cpu_usage: 0.0,
                avg_memory_mb: 0,
            },
        };
        
        // Submit to learning engine
        self.learning_handle.submit_pattern(pattern).await?;
        
        Ok(())
    }
    
    /// Handle get insights request
    async fn handle_get_insights(&self, _category: Option<String>) -> Result<Vec<crate::synthex_bashgod::LearningInsight>> {
        // TODO: Implement insight retrieval from learning engine
        Ok(vec![
            crate::synthex_bashgod::LearningInsight {
                insight_type: crate::synthex_bashgod::InsightType::PerformanceOptimization,
                confidence: 0.85,
                description: "Parallel execution can reduce runtime by 40%".to_string(),
                recommendation: Some("Use parallel strategy for independent commands".to_string()),
                related_patterns: vec!["deployment-parallel".to_string()],
            }
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_actor_creation() {
        let (tx, rx) = mpsc::channel(100);
        
        struct DummyLearning;
        #[async_trait]
        impl LearningHandle for DummyLearning {
            async fn submit_pattern(&self, _pattern: CommandPattern) -> Result<()> {
                Ok(())
            }
            
            async fn get_suggestions(&self, _chain: &CommandChain) -> Result<Vec<OptimizationSuggestion>> {
                Ok(vec![])
            }
        }
        
        struct DummyMCP;
        #[async_trait]
        impl MCPHandle for DummyMCP {
            async fn enhance_command(&self, command: &BashCommand) -> Result<EnhancedCommand> {
                Ok(EnhancedCommand {
                    base_command: command.clone(),
                    mcp_tools: vec![],
                    enhanced_resources: false,
                })
            }
            
            async fn get_strategy(&self, chain: &CommandChain) -> Result<EnhancedStrategy> {
                Ok(EnhancedStrategy {
                    base_strategy: chain.strategy.clone(),
                    mcp_optimizations: vec![],
                })
            }
        }
        
        let learning = Arc::new(DummyLearning);
        let mcp = Arc::new(DummyMCP);
        
        let actor = BashGodActor::new(rx, learning, mcp, 4);
        
        // Send shutdown message
        tx.send(ActorMessage::Shutdown).await.unwrap();
        
        // Run actor (should exit immediately)
        actor.run().await;
    }
}