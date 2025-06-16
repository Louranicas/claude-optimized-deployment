// ============================================================================
// Execution Engine - High-Performance Command Execution
// ============================================================================

use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use tokio::process::{Command, Child};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};
use std::collections::HashMap;
use std::sync::Arc;
use std::process::Stdio;
use futures::future::join_all;
use tracing::{info, debug, warn, error};

use super::command_chain::{CommandChain, ChainElement, RedirectType};

/// Execution engine for running command chains
pub struct ExecutionEngine {
    config: ExecutionConfig,
    executor_pool: Arc<tokio::sync::Semaphore>,
}

/// Configuration for the execution engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionConfig {
    pub max_parallel: usize,
    pub timeout_seconds: u64,
    pub retry_attempts: u32,
    pub retry_delay_ms: u64,
    pub shell: String,
    pub shell_args: Vec<String>,
    pub capture_output: bool,
    pub stream_output: bool,
    pub env_inherit: bool,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            max_parallel: 10,
            timeout_seconds: 300,
            retry_attempts: 3,
            retry_delay_ms: 1000,
            shell: "bash".to_string(),
            shell_args: vec!["-c".to_string()],
            capture_output: true,
            stream_output: false,
            env_inherit: true,
        }
    }
}

/// Result from executing a command chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionOutput {
    pub output: String,
    pub error: Option<String>,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub retries: u32,
    pub optimizations_applied: Vec<String>,
}

impl ExecutionEngine {
    /// Create a new execution engine
    pub fn new(config: ExecutionConfig) -> Result<Self> {
        let executor_pool = Arc::new(tokio::sync::Semaphore::new(config.max_parallel));
        
        Ok(Self {
            config,
            executor_pool,
        })
    }

    /// Execute a command chain
    pub async fn execute(&self, chain: CommandChain) -> Result<ExecutionOutput> {
        let start = std::time::Instant::now();
        
        // Validate the chain before execution
        chain.validate()?;
        
        // Build the full command string
        let command_string = chain.to_string();
        
        info!("Executing command chain: {}", chain.id);
        debug!("Command: {}", command_string);
        
        // Execute with retry logic
        let mut retries = 0;
        let mut last_error = None;
        
        while retries <= self.config.retry_attempts {
            match self.execute_single(&chain, &command_string).await {
                Ok(mut output) => {
                    output.duration_ms = start.elapsed().as_millis() as u64;
                    output.retries = retries;
                    return Ok(output);
                }
                Err(e) => {
                    warn!("Execution attempt {} failed: {}", retries + 1, e);
                    last_error = Some(e);
                    
                    if retries < self.config.retry_attempts {
                        tokio::time::sleep(Duration::from_millis(
                            self.config.retry_delay_ms * (retries + 1) as u64
                        )).await;
                    }
                    
                    retries += 1;
                }
            }
        }
        
        Err(last_error.unwrap_or_else(|| anyhow!("Execution failed after {} attempts", retries)))
    }

    /// Execute a single command chain without retries
    async fn execute_single(&self, chain: &CommandChain, command_string: &str) -> Result<ExecutionOutput> {
        // Acquire semaphore permit
        let _permit = self.executor_pool.acquire().await?;
        
        // Create command
        let mut cmd = Command::new(&self.config.shell);
        
        // Add shell arguments
        for arg in &self.config.shell_args {
            cmd.arg(arg);
        }
        
        // Add the command string
        cmd.arg(command_string);
        
        // Set environment variables
        for (key, value) in &chain.env_vars {
            cmd.env(key, value);
        }
        
        // Set working directory
        if let Some(cwd) = &chain.working_dir {
            cmd.current_dir(cwd);
        }
        
        // Configure stdio
        if self.config.capture_output {
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());
        }
        
        // Inherit environment if configured
        if self.config.env_inherit {
            cmd.env_clear();
            for (key, value) in std::env::vars() {
                cmd.env(key, value);
            }
        }
        
        // Spawn the process
        let mut child = cmd.spawn()?;
        
        // Handle output capture
        let output = if self.config.capture_output {
            self.capture_output(&mut child).await?
        } else {
            // Wait for completion without capturing
            let status = timeout(
                Duration::from_secs(self.config.timeout_seconds),
                child.wait()
            ).await??;
            
            ExecutionOutput {
                output: String::new(),
                error: None,
                exit_code: status.code().unwrap_or(-1),
                duration_ms: 0,
                retries: 0,
                optimizations_applied: Vec::new(),
            }
        };
        
        Ok(output)
    }

    /// Capture output from a running process
    async fn capture_output(&self, child: &mut Child) -> Result<ExecutionOutput> {
        let stdout = child.stdout.take().ok_or_else(|| anyhow!("Failed to capture stdout"))?;
        let stderr = child.stderr.take().ok_or_else(|| anyhow!("Failed to capture stderr"))?;
        
        // Read output concurrently
        let (stdout_result, stderr_result, status_result) = tokio::join!(
            Self::read_stream(stdout),
            Self::read_stream(stderr),
            timeout(Duration::from_secs(self.config.timeout_seconds), child.wait())
        );
        
        let stdout_data = stdout_result?;
        let stderr_data = stderr_result?;
        let status = status_result??;
        
        let error = if stderr_data.is_empty() {
            None
        } else {
            Some(stderr_data)
        };
        
        Ok(ExecutionOutput {
            output: stdout_data,
            error,
            exit_code: status.code().unwrap_or(-1),
            duration_ms: 0,
            retries: 0,
            optimizations_applied: Vec::new(),
        })
    }

    /// Read a stream to string
    async fn read_stream<R: AsyncReadExt + Unpin>(mut reader: R) -> Result<String> {
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).await?;
        Ok(String::from_utf8_lossy(&buffer).to_string())
    }

    /// Execute multiple chains in parallel
    pub async fn execute_parallel(&self, chains: Vec<CommandChain>) -> Result<Vec<ExecutionOutput>> {
        let futures = chains.into_iter().map(|chain| {
            let engine = self.clone();
            async move {
                engine.execute(chain).await
            }
        });
        
        let results = join_all(futures).await;
        
        // Collect results, propagating first error
        let mut outputs = Vec::new();
        for result in results {
            outputs.push(result?);
        }
        
        Ok(outputs)
    }

    /// Execute chains with dependencies
    pub async fn execute_graph(&self, graph: ExecutionGraph) -> Result<HashMap<String, ExecutionOutput>> {
        let mut results = HashMap::new();
        let mut completed = std::collections::HashSet::new();
        
        while completed.len() < graph.nodes.len() {
            // Find nodes that can be executed
            let ready_nodes: Vec<_> = graph.nodes.iter()
                .filter(|node| {
                    !completed.contains(&node.id) &&
                    node.dependencies.iter().all(|dep| completed.contains(dep))
                })
                .collect();
            
            if ready_nodes.is_empty() {
                return Err(anyhow!("Circular dependency detected in execution graph"));
            }
            
            // Execute ready nodes in parallel
            let chains: Vec<_> = ready_nodes.iter()
                .map(|node| node.chain.clone())
                .collect();
            
            let outputs = self.execute_parallel(chains).await?;
            
            // Store results
            for (node, output) in ready_nodes.iter().zip(outputs.iter()) {
                results.insert(node.id.clone(), output.clone());
                completed.insert(node.id.clone());
            }
        }
        
        Ok(results)
    }
}

impl Clone for ExecutionEngine {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            executor_pool: self.executor_pool.clone(),
        }
    }
}

/// Execution graph for dependency-based execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionGraph {
    pub nodes: Vec<ExecutionNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionNode {
    pub id: String,
    pub chain: CommandChain,
    pub dependencies: Vec<String>,
}

/// Advanced execution strategies
pub mod strategies {
    use super::*;
    
    /// Pipeline execution strategy
    pub struct PipelineStrategy {
        buffer_size: usize,
    }
    
    impl PipelineStrategy {
        pub fn new(buffer_size: usize) -> Self {
            Self { buffer_size }
        }
        
        pub async fn execute(&self, engine: &ExecutionEngine, chains: Vec<CommandChain>) -> Result<Vec<ExecutionOutput>> {
            let (tx, mut rx) = tokio::sync::mpsc::channel(self.buffer_size);
            
            // Producer task
            let producer = tokio::spawn(async move {
                for chain in chains {
                    if tx.send(chain).await.is_err() {
                        break;
                    }
                }
            });
            
            // Consumer tasks
            let mut outputs = Vec::new();
            while let Some(chain) = rx.recv().await {
                let output = engine.execute(chain).await?;
                outputs.push(output);
            }
            
            producer.await?;
            Ok(outputs)
        }
    }
    
    /// Map-reduce execution strategy
    pub struct MapReduceStrategy<M, R> {
        mapper: M,
        reducer: R,
    }
    
    impl<M, R> MapReduceStrategy<M, R>
    where
        M: Fn(CommandChain) -> Vec<CommandChain> + Send + Sync,
        R: Fn(Vec<ExecutionOutput>) -> ExecutionOutput + Send + Sync,
    {
        pub fn new(mapper: M, reducer: R) -> Self {
            Self { mapper, reducer }
        }
        
        pub async fn execute(&self, engine: &ExecutionEngine, chain: CommandChain) -> Result<ExecutionOutput> {
            // Map phase
            let mapped_chains = (self.mapper)(chain);
            
            // Execute mapped chains in parallel
            let outputs = engine.execute_parallel(mapped_chains).await?;
            
            // Reduce phase
            let result = (self.reducer)(outputs);
            
            Ok(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_simple_execution() {
        let config = ExecutionConfig::default();
        let engine = ExecutionEngine::new(config).unwrap();
        
        let mut chain = CommandChain::new();
        chain.add_command("echo 'Hello, World!'".to_string());
        
        let result = engine.execute(chain).await.unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(result.output.contains("Hello, World!"));
    }

    #[tokio::test]
    async fn test_parallel_execution() {
        let config = ExecutionConfig::default();
        let engine = ExecutionEngine::new(config).unwrap();
        
        let chains: Vec<_> = (0..5).map(|i| {
            let mut chain = CommandChain::new();
            chain.add_command(format!("echo 'Task {}'", i));
            chain
        }).collect();
        
        let results = engine.execute_parallel(chains).await.unwrap();
        assert_eq!(results.len(), 5);
        
        for (i, result) in results.iter().enumerate() {
            assert_eq!(result.exit_code, 0);
            assert!(result.output.contains(&format!("Task {}", i)));
        }
    }
}