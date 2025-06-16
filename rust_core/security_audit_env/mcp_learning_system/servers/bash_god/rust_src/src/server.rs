use anyhow::{Result, anyhow};
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use serde_json;
use tokio::sync::RwLock as TokioRwLock;
use std::collections::HashMap;

use crate::memory::{MemoryPool, CommandPattern};
use crate::command_engine::{CommandEngine, CommandRequest, CommandResponse};
use crate::system_state::{SystemStateManager, SystemContext, ResourceRequirements};
use crate::safety::{SafetyValidator, CommandExecution};
use crate::optimization::{PatternOptimizer, OptimizationRequest, LearningPattern};

pub struct BashGodMCPServer {
    memory_pool: Arc<MemoryPool>,
    command_engine: Arc<CommandEngine>,
    system_state: Arc<SystemStateManager>,
    safety_validator: Arc<SafetyValidator>,
    pattern_optimizer: Arc<PatternOptimizer>,
    learning_enabled: Arc<TokioRwLock<bool>>,
    execution_history: Arc<TokioRwLock<Vec<ExecutionRecord>>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ExecutionRecord {
    timestamp: i64,
    command: String,
    success: bool,
    duration_ms: u64,
    context: HashMap<String, String>,
}

impl BashGodMCPServer {
    pub async fn new() -> Result<Self> {
        let memory_pool = Arc::new(MemoryPool::new()?);
        let command_engine = Arc::new(CommandEngine::new(memory_pool.clone()));
        let system_state = Arc::new(SystemStateManager::new(memory_pool.clone())?);
        let safety_validator = Arc::new(SafetyValidator::new(memory_pool.clone())?);
        let pattern_optimizer = Arc::new(PatternOptimizer::new(memory_pool.clone()));
        
        Ok(Self {
            memory_pool,
            command_engine,
            system_state,
            safety_validator,
            pattern_optimizer,
            learning_enabled: Arc::new(TokioRwLock::new(true)),
            execution_history: Arc::new(TokioRwLock::new(Vec::new())),
        })
    }
    
    pub async fn generate_command(&self, request: CommandRequest) -> Result<CommandResponse> {
        // Get current system context
        let context = self.system_state.get_context().await?;
        
        // Generate base command
        let mut response = self.command_engine.generate(&request, &context).await?;
        
        // Validate safety
        let validation = self.safety_validator.validate(&response.command).await?;
        
        if !validation.is_safe {
            response.warnings.extend(validation.warnings);
            response.safety_level = validation.risk_level;
            
            if let Some(suggested) = validation.suggested_command {
                response.alternatives.insert(0, format!("Safer alternative: {}", suggested));
            }
        }
        
        // Apply optimizations
        let optimized = self.pattern_optimizer.optimize(response.command.clone()).await?;
        if optimized != response.command {
            response.alternatives.push(format!("Optimized: {}", optimized));
            response.command = optimized;
        }
        
        Ok(response)
    }
    
    pub async fn generate_command_from_json(&self, request_json: &str) -> Result<String> {
        let request: CommandRequest = serde_json::from_str(request_json)?;
        let response = self.generate_command(request).await?;
        Ok(serde_json::to_string(&response)?)
    }
    
    pub async fn learn_from_execution(&self, task: String, command: String, success: bool, duration_ms: u64) -> Result<()> {
        if !*self.learning_enabled.read().await {
            return Ok(());
        }
        
        // Record execution
        let record = ExecutionRecord {
            timestamp: chrono::Utc::now().timestamp(),
            command: command.clone(),
            success,
            duration_ms,
            context: HashMap::new(),
        };
        
        self.execution_history.write().await.push(record.clone());
        
        // Learn command pattern
        self.command_engine.learn_from_execution(task, command, success, duration_ms)?;
        
        // Learn optimization patterns
        if success && duration_ms > 1000 {
            // Look for optimization opportunities in slow commands
            let suggestions = self.pattern_optimizer.suggest_improvements(&command);
            if !suggestions.is_empty() {
                // Store as learning opportunity
                let pattern = LearningPattern {
                    original: command.clone(),
                    optimized: command, // Would be replaced with actual optimized version
                    measured_improvement: 1.0,
                    conditions: vec![format!("Duration: {}ms", duration_ms)],
                };
                self.pattern_optimizer.learn(pattern)?;
            }
        }
        
        Ok(())
    }
    
    pub async fn learn_from_execution_json(&self, execution_json: &str) -> Result<()> {
        #[derive(Deserialize)]
        struct ExecutionData {
            task: String,
            command: String,
            success: bool,
            duration_ms: u64,
        }
        
        let data: ExecutionData = serde_json::from_str(execution_json)?;
        self.learn_from_execution(data.task, data.command, data.success, data.duration_ms).await
    }
    
    pub async fn validate_command(&self, command: &str) -> Result<String> {
        let result = self.safety_validator.validate(command).await?;
        Ok(serde_json::to_string(&result)?)
    }
    
    pub async fn validate_command_json(&self, command: &str) -> Result<String> {
        self.validate_command(command).await
    }
    
    pub async fn get_system_info(&self) -> Result<SystemInfo> {
        let context = self.system_state.get_context().await?;
        let snapshot = self.system_state.capture_snapshot().await?;
        let memory_stats = self.memory_pool.get_memory_stats();
        let environment = self.system_state.detect_environment();
        
        Ok(SystemInfo {
            context,
            current_state: snapshot,
            memory_usage: memory_stats,
            environment,
            capabilities: self.get_capabilities(),
        })
    }
    
    pub async fn get_system_info_json(&self) -> Result<String> {
        let info = self.get_system_info().await?;
        Ok(serde_json::to_string(&info)?)
    }
    
    pub async fn check_resources(&self, requirements: ResourceRequirements) -> Result<String> {
        let result = self.system_state.check_resource_availability(&requirements)?;
        Ok(serde_json::to_string(&result)?)
    }
    
    pub async fn optimize_command(&self, request_json: &str) -> Result<String> {
        let request: OptimizationRequest = serde_json::from_str(request_json)?;
        let result = self.pattern_optimizer.optimize_with_context(request).await?;
        Ok(serde_json::to_string(&result)?)
    }
    
    pub async fn get_command_history(&self) -> Result<Vec<HistoryEntry>> {
        let history = self.execution_history.read().await;
        let entries: Vec<HistoryEntry> = history.iter()
            .rev()
            .take(100)
            .map(|record| HistoryEntry {
                timestamp: record.timestamp,
                command: record.command.clone(),
                success: record.success,
                duration_ms: record.duration_ms,
            })
            .collect();
        
        Ok(entries)
    }
    
    pub async fn get_memory_usage(&self) -> Result<String> {
        let stats = self.memory_pool.get_memory_stats();
        Ok(serde_json::to_string(&stats)?)
    }
    
    pub async fn garbage_collect(&self) -> Result<String> {
        let freed = self.memory_pool.garbage_collect()?;
        Ok(format!("Freed {} bytes of memory", freed))
    }
    
    pub async fn enable_learning(&self, enabled: bool) {
        *self.learning_enabled.write().await = enabled;
    }
    
    pub async fn export_learned_patterns(&self) -> Result<LearnedPatterns> {
        let command_patterns: Vec<CommandPattern> = self.memory_pool
            .command_patterns
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        
        let safety_rules = self.memory_pool.get_safety_rules();
        let optimization_hints = self.memory_pool
            .optimization_hints
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        
        Ok(LearnedPatterns {
            command_patterns,
            safety_rules,
            optimization_hints,
            total_patterns: command_patterns.len() + safety_rules.len() + optimization_hints.len(),
        })
    }
    
    pub async fn import_learned_patterns(&self, patterns_json: &str) -> Result<()> {
        let patterns: LearnedPatterns = serde_json::from_str(patterns_json)?;
        
        // Import command patterns
        for pattern in patterns.command_patterns {
            let key = pattern.contexts.first()
                .cloned()
                .unwrap_or_else(|| "imported".to_string());
            self.memory_pool.store_command_pattern(key, pattern)?;
        }
        
        // Import safety rules
        for rule in patterns.safety_rules {
            self.memory_pool.store_safety_rule(rule)?;
        }
        
        // Import optimization hints
        for hint in patterns.optimization_hints {
            self.memory_pool.store_optimization_hint(hint)?;
        }
        
        Ok(())
    }
    
    fn get_capabilities(&self) -> Vec<String> {
        vec![
            "command_generation".to_string(),
            "pattern_learning".to_string(),
            "safety_validation".to_string(),
            "performance_optimization".to_string(),
            "system_monitoring".to_string(),
            "resource_checking".to_string(),
            "parallel_execution".to_string(),
            "command_history".to_string(),
        ]
    }
}

#[derive(Serialize, Deserialize)]
pub struct SystemInfo {
    pub context: SystemContext,
    pub current_state: crate::memory::SystemStateSnapshot,
    pub memory_usage: crate::memory::MemoryStats,
    pub environment: crate::system_state::EnvironmentInfo,
    pub capabilities: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct HistoryEntry {
    pub timestamp: i64,
    pub command: String,
    pub success: bool,
    pub duration_ms: u64,
}

#[derive(Serialize, Deserialize)]
pub struct LearnedPatterns {
    pub command_patterns: Vec<CommandPattern>,
    pub safety_rules: Vec<crate::memory::SafetyRule>,
    pub optimization_hints: Vec<crate::memory::OptimizationHint>,
    pub total_patterns: usize,
}