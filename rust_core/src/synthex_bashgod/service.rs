//! BashGodService implementation wrapper
//!
//! Provides the public interface to SYNTHEX-BashGod

use crate::synthex_bashgod::{
    BashGodService, BashGodConfig, CommandChain, ChainResult, BashIntent,
    LearningInsight, Result, SBGError, ExecutionStrategy, ChainMetadata,
    ResourceEstimate, Priority, ExecutionMetrics,
};
use crate::synthex_bashgod::actor::{BashGodActor, ActorMessage, LearningHandle, MCPHandle, EnhancedCommand, EnhancedStrategy};
use crate::synthex_bashgod::BashCommand;
use async_trait::async_trait;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::{mpsc, oneshot};
use tracing::info;

/// BashGod service implementation
pub struct BashGodServiceImpl {
    /// Message sender to actor
    sender: mpsc::Sender<ActorMessage>,
    
    /// Actor handle
    actor_handle: Option<tokio::task::JoinHandle<()>>,
}

impl BashGodServiceImpl {
    /// Create new service
    pub async fn new(config: BashGodConfig) -> Result<Self> {
        let (sender, receiver) = mpsc::channel(config.channel_buffer_size);
        
        // Create dummy handles for now
        let learning_handle = Arc::new(DummyLearningHandle);
        let mcp_handle = Arc::new(DummyMCPHandle);
        
        // Create and start actor
        let actor = BashGodActor::new(
            receiver,
            learning_handle,
            mcp_handle,
            config.executor_pool_size,
        );
        
        let actor_handle = tokio::spawn(async move {
            actor.run().await;
        });
        
        info!("BashGodService started with config: {:?}", config);
        
        Ok(Self {
            sender,
            actor_handle: Some(actor_handle),
        })
    }
    
    /// Get statistics
    pub async fn get_stats(&self) -> Result<(u64, u64, u64, u64, u64)> {
        let (tx, rx) = oneshot::channel();
        
        self.sender
            .send(ActorMessage::GetStats { response: tx })
            .await
            .map_err(|_| SBGError::ActorError("Failed to send stats request".to_string()))?;
        
        let stats = rx.await
            .map_err(|_| SBGError::ActorError("Failed to receive stats".to_string()))?;
        
        Ok((
            stats.commands_executed,
            stats.chains_processed,
            stats.avg_execution_time_ms as u64,
            0, // patterns_learned - TODO
            0, // chains_optimized - TODO
        ))
    }
}

#[async_trait]
impl BashGodService for BashGodServiceImpl {
    async fn execute_chain(&self, chain: CommandChain) -> Result<ChainResult> {
        let (tx, rx) = oneshot::channel();
        
        self.sender
            .send(ActorMessage::ExecuteChain { chain, response: tx })
            .await
            .map_err(|_| SBGError::ActorError("Failed to send execute request".to_string()))?;
        
        rx.await
            .map_err(|_| SBGError::ActorError("Failed to receive execute response".to_string()))?
    }
    
    async fn optimize_chain(&self, chain: CommandChain) -> Result<CommandChain> {
        let (tx, rx) = oneshot::channel();
        
        self.sender
            .send(ActorMessage::OptimizeChain { 
                chain, 
                response: tx 
            })
            .await
            .map_err(|_| SBGError::ActorError("Failed to send optimize request".to_string()))?;
        
        rx.await
            .map_err(|_| SBGError::ActorError("Failed to receive optimize response".to_string()))?
    }
    
    async fn learn_from_execution(&self, result: &ChainResult) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        
        self.sender
            .send(ActorMessage::LearnFromResult { 
                result: result.clone(), 
                response: tx 
            })
            .await
            .map_err(|_| SBGError::ActorError("Failed to send learn request".to_string()))?;
        
        rx.await
            .map_err(|_| SBGError::ActorError("Failed to receive learn response".to_string()))?
    }
    
    async fn generate_chain(&self, _intent: BashIntent) -> Result<CommandChain> {
        // TODO: Implement chain generation
        Err(SBGError::ExecutionError("Chain generation not yet implemented".to_string()))
    }
    
    async fn get_insights(&self, category: Option<String>) -> Result<Vec<LearningInsight>> {
        let (tx, rx) = oneshot::channel();
        
        self.sender
            .send(ActorMessage::GetInsights { category, response: tx })
            .await
            .map_err(|_| SBGError::ActorError("Failed to send insights request".to_string()))?;
        
        rx.await
            .map_err(|_| SBGError::ActorError("Failed to receive insights response".to_string()))?
    }
    
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    
    async fn analyze_intent(&self, intent: BashIntent) -> Result<CommandChain> {
        // For now, convert intent to a simple command chain
        Ok(CommandChain {
            id: uuid::Uuid::new_v4().to_string(),
            commands: vec![],
            dependencies: HashMap::new(),
            strategy: ExecutionStrategy::Sequential,
            metadata: ChainMetadata {
                intent: intent.description,
                tags: vec![intent.category],
                expected_resources: ResourceEstimate::default(),
                priority: Priority::Normal,
            },
        })
    }
    
    async fn get_metrics(&self) -> Result<ExecutionMetrics> {
        let (tx, rx) = oneshot::channel();
        self.sender.send(ActorMessage::GetStats {
            response: tx,
        }).await
            .map_err(|_| SBGError::ServiceError("Failed to send message".to_string()))?;
        
        let stats = rx.await
            .map_err(|_| SBGError::ServiceError("Failed to receive response".to_string()))?;
        
        Ok(ExecutionMetrics {
            total_commands: stats.chains_processed,
            successful_commands: stats.chains_processed, // Simplified
            failed_commands: 0,
            avg_execution_time_ms: stats.avg_execution_time_ms,
            peak_resource_usage: crate::synthex_bashgod::ResourceUsage {
                cpu_percent: 0.0,
                memory_mb: 0,
                disk_read_mb: 0,
                disk_write_mb: 0,
                network_sent_mb: 0,
                network_recv_mb: 0,
            },
            execution_time_ms: Some(stats.avg_execution_time_ms as u64),
            cpu_usage: Some(0.0),
            memory_usage: Some(0),
        })
    }
}

impl Drop for BashGodServiceImpl {
    fn drop(&mut self) {
        // Send shutdown message
        let sender = self.sender.clone();
        tokio::spawn(async move {
            let _ = sender.send(ActorMessage::Shutdown).await;
        });
        
        // Wait for actor to finish
        if let Some(handle) = self.actor_handle.take() {
            tokio::spawn(async move {
                let _ = handle.await;
            });
        }
    }
}

// Dummy implementations for testing

// Import needed types
use crate::synthex_bashgod::memory::CommandPattern;
use crate::synthex_bashgod::OptimizationSuggestion;

struct DummyLearningHandle;

#[async_trait]
impl LearningHandle for DummyLearningHandle {
    async fn submit_pattern(&self, _pattern: CommandPattern) -> Result<()> {
        Ok(())
    }
    
    async fn get_suggestions(&self, _chain: &CommandChain) -> Result<Vec<OptimizationSuggestion>> {
        Ok(Vec::new())
    }
}

struct DummyMCPHandle;

#[async_trait]
impl MCPHandle for DummyMCPHandle {
    async fn enhance_command(&self, command: &BashCommand) -> Result<EnhancedCommand> {
        Ok(EnhancedCommand {
            base_command: command.clone(),
            mcp_tools: Vec::new(),
            enhanced_resources: false,
        })
    }
    
    async fn get_strategy(&self, _chain: &CommandChain) -> Result<EnhancedStrategy> {
        Ok(EnhancedStrategy {
            base_strategy: ExecutionStrategy::Sequential,
            mcp_optimizations: Vec::new(),
        })
    }
}