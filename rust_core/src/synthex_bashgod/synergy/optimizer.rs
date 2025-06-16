//! Synergy optimization implementation
//! 
//! Applies detected synergies to optimize command chains

use crate::synthex_bashgod::{Result, SBGError};
use crate::synthex_bashgod::synergy::{
    CommandSynergy, SynergyImplementation, SynergyChange, SynergyChangeType,
    ImplementationStrategy, SynergyContext,
};
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Synergy optimizer for applying optimizations
pub struct SynergyOptimizer {
    /// Optimization strategies
    strategies: Arc<OptimizationStrategies>,
    
    /// Optimization history
    history: Arc<DashMap<String, OptimizationResult>>,
    
    /// Configuration
    config: OptimizerConfig,
    
    /// Statistics
    stats: Arc<RwLock<OptimizerStats>>,
}

/// Optimization strategies implementation
struct OptimizationStrategies {
    /// Pipeline optimization
    pipeline_optimizer: PipelineOptimizer,
    
    /// Resource sharing optimizer
    resource_optimizer: ResourceOptimizer,
    
    /// Parallel execution optimizer
    parallel_optimizer: ParallelOptimizer,
    
    /// Cache optimization
    cache_optimizer: CacheOptimizer,
}

/// Optimizer configuration
#[derive(Debug, Clone)]
pub struct OptimizerConfig {
    /// Enable aggressive optimizations
    pub aggressive_mode: bool,
    
    /// Maximum command chain length
    pub max_chain_length: usize,
    
    /// Enable experimental features
    pub experimental: bool,
    
    /// Optimization timeout
    pub timeout_ms: u64,
}

impl Default for OptimizerConfig {
    fn default() -> Self {
        Self {
            aggressive_mode: false,
            max_chain_length: 100,
            experimental: false,
            timeout_ms: 5000,
        }
    }
}

/// Optimization result
#[derive(Debug, Clone)]
pub struct OptimizationResult {
    /// Original commands
    pub original: Vec<String>,
    
    /// Optimized commands
    pub optimized: Vec<String>,
    
    /// Applied synergies
    pub applied_synergies: Vec<String>,
    
    /// Performance metrics
    pub metrics: OptimizationMetrics,
    
    /// Success flag
    pub success: bool,
}

/// Optimization metrics
#[derive(Debug, Clone)]
pub struct OptimizationMetrics {
    /// Command count reduction
    pub command_reduction: i32,
    
    /// Estimated time savings
    pub time_savings_percent: f32,
    
    /// Resource savings
    pub resource_savings_percent: f32,
    
    /// Complexity score (lower is better)
    pub complexity_score: f32,
}

/// Optimizer statistics
#[derive(Debug, Default)]
struct OptimizerStats {
    /// Total optimizations performed
    optimizations_performed: u64,
    
    /// Successful optimizations
    successful_optimizations: u64,
    
    /// Failed optimizations
    failed_optimizations: u64,
    
    /// Average time savings
    avg_time_savings: f32,
}

impl SynergyOptimizer {
    /// Create a new synergy optimizer
    pub fn new(config: OptimizerConfig) -> Self {
        Self {
            strategies: Arc::new(OptimizationStrategies::new()),
            history: Arc::new(DashMap::new()),
            config,
            stats: Arc::new(RwLock::new(OptimizerStats::default())),
        }
    }
    
    /// Apply synergy optimization
    pub async fn optimize(
        &self,
        commands: Vec<String>,
        synergies: Vec<CommandSynergy>,
        context: &SynergyContext,
    ) -> Result<OptimizationResult> {
        info!("Applying {} synergies to {} commands", synergies.len(), commands.len());
        
        let mut optimized = commands.clone();
        let mut applied_synergies = Vec::new();
        
        // Sort synergies by score (highest first)
        let mut sorted_synergies = synergies;
        sorted_synergies.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        
        // Apply synergies
        for synergy in sorted_synergies {
            match self.apply_synergy(&mut optimized, &synergy, context).await {
                Ok(applied) => {
                    if applied {
                        applied_synergies.push(synergy.id.clone());
                        debug!("Applied synergy: {}", synergy.id);
                    }
                }
                Err(e) => {
                    warn!("Failed to apply synergy {}: {}", synergy.id, e);
                }
            }
        }
        
        // Calculate metrics
        let metrics = self.calculate_metrics(&commands, &optimized);
        
        let success = !applied_synergies.is_empty();
        let result = OptimizationResult {
            original: commands,
            optimized,
            applied_synergies,
            metrics,
            success,
        };
        
        // Update history
        self.history.insert(
            format!("opt-{}", uuid::Uuid::new_v4()),
            result.clone(),
        );
        
        // Update stats
        self.update_stats(&result).await;
        
        Ok(result)
    }
    
    /// Apply a single synergy
    async fn apply_synergy(
        &self,
        commands: &mut Vec<String>,
        synergy: &CommandSynergy,
        context: &SynergyContext,
    ) -> Result<bool> {
        match synergy.implementation.strategy {
            ImplementationStrategy::PipelineMerge => {
                self.strategies.pipeline_optimizer.apply(commands, synergy)
            }
            ImplementationStrategy::ProcessSubstitution => {
                self.strategies.resource_optimizer.apply_process_substitution(commands, synergy)
            }
            ImplementationStrategy::SharedMemory => {
                self.strategies.resource_optimizer.apply_shared_memory(commands, synergy, context)
            }
            ImplementationStrategy::NamedPipes => {
                self.strategies.resource_optimizer.apply_named_pipes(commands, synergy)
            }
            ImplementationStrategy::TempFileElimination => {
                self.strategies.pipeline_optimizer.eliminate_temp_files(commands, synergy)
            }
            ImplementationStrategy::CombinedTool => {
                self.strategies.pipeline_optimizer.combine_tools(commands, synergy)
            }
        }
    }
    
    /// Calculate optimization metrics
    fn calculate_metrics(
        &self,
        original: &[String],
        optimized: &[String],
    ) -> OptimizationMetrics {
        let command_reduction = original.len() as i32 - optimized.len() as i32;
        
        // Estimate time savings based on command reduction and parallelization
        let time_savings_percent = if command_reduction > 0 {
            (command_reduction as f32 / original.len() as f32) * 100.0
        } else {
            // Check for parallelization
            if optimized.iter().any(|cmd| cmd.contains(" & ") || cmd.contains("parallel")) {
                30.0 // Estimate 30% savings from parallelization
            } else {
                0.0
            }
        };
        
        // Estimate resource savings
        let resource_savings_percent = if optimized.iter().any(|cmd| cmd.contains("tee") || cmd.contains("<(")) {
            20.0 // Process substitution saves resources
        } else {
            command_reduction as f32 * 5.0 // Each eliminated command saves ~5% resources
        };
        
        // Calculate complexity score
        let complexity_score = self.calculate_complexity_score(optimized);
        
        OptimizationMetrics {
            command_reduction,
            time_savings_percent,
            resource_savings_percent,
            complexity_score,
        }
    }
    
    /// Calculate complexity score
    fn calculate_complexity_score(&self, commands: &[String]) -> f32 {
        let mut score = 0.0;
        
        for cmd in commands {
            // Base complexity
            score += 1.0;
            
            // Pipe complexity
            score += cmd.matches('|').count() as f32 * 0.5;
            
            // Process substitution complexity
            score += cmd.matches("<(").count() as f32 * 1.5;
            
            // Background job complexity
            score += cmd.matches(" & ").count() as f32 * 1.0;
            
            // Nested command complexity
            score += cmd.matches('$').count() as f32 * 0.8;
        }
        
        score / commands.len() as f32
    }
    
    /// Update statistics
    async fn update_stats(&self, result: &OptimizationResult) {
        let mut stats = self.stats.write().await;
        
        stats.optimizations_performed += 1;
        
        if result.success {
            stats.successful_optimizations += 1;
            
            // Update average time savings
            let n = stats.successful_optimizations as f32;
            stats.avg_time_savings = 
                (stats.avg_time_savings * (n - 1.0) + result.metrics.time_savings_percent) / n;
        } else {
            stats.failed_optimizations += 1;
        }
    }
    
    /// Get optimizer statistics
    pub async fn get_stats(&self) -> (u64, u64, u64, f32) {
        let stats = self.stats.read().await;
        (
            stats.optimizations_performed,
            stats.successful_optimizations,
            stats.failed_optimizations,
            stats.avg_time_savings,
        )
    }
}

/// Pipeline optimizer
struct PipelineOptimizer;

impl PipelineOptimizer {
    /// Apply pipeline merge optimization
    fn apply(&self, commands: &mut Vec<String>, synergy: &CommandSynergy) -> Result<bool> {
        let indices = &synergy.commands;
        
        if indices.len() < 2 {
            return Ok(false);
        }
        
        // Extract commands to merge
        let mut pipeline_parts = Vec::new();
        for &idx in indices {
            if idx < commands.len() {
                pipeline_parts.push(commands[idx].clone());
            }
        }
        
        // Create merged pipeline
        let merged = pipeline_parts.join(" | ");
        
        // Replace commands with merged version
        commands[indices[0]] = merged;
        
        // Remove other commands (in reverse order to maintain indices)
        for &idx in indices.iter().skip(1).rev() {
            if idx < commands.len() {
                commands.remove(idx);
            }
        }
        
        Ok(true)
    }
    
    /// Eliminate temporary files
    fn eliminate_temp_files(&self, commands: &mut Vec<String>, synergy: &CommandSynergy) -> Result<bool> {
        // Look for patterns like: cmd1 > temp.txt && cmd2 < temp.txt
        let indices = &synergy.commands;
        
        if indices.len() != 2 {
            return Ok(false);
        }
        
        let cmd1 = &commands[indices[0]];
        let cmd2 = &commands[indices[1]];
        
        // Check for temp file pattern
        if let Some(temp_file) = self.extract_temp_file(cmd1, cmd2) {
            // Replace with pipe
            let piped = format!("{} | {}", 
                cmd1.replace(&format!(" > {}", temp_file), ""),
                cmd2.replace(&format!(" < {}", temp_file), ""),
            );
            
            commands[indices[0]] = piped;
            commands.remove(indices[1]);
            
            return Ok(true);
        }
        
        Ok(false)
    }
    
    /// Combine tools
    fn combine_tools(&self, commands: &mut Vec<String>, synergy: &CommandSynergy) -> Result<bool> {
        // Apply tool-specific combinations
        for change in &synergy.implementation.changes {
            if let SynergyChangeType::MergeCommands = change.change_type {
                if let Some(combined) = change.config.get("combined_command").and_then(|v| v.as_str()) {
                    // Replace first command with combined version
                    if !change.targets.is_empty() && change.targets[0] < commands.len() {
                        commands[change.targets[0]] = combined.to_string();
                        
                        // Remove other commands
                        for &idx in change.targets.iter().skip(1).rev() {
                            if idx < commands.len() {
                                commands.remove(idx);
                            }
                        }
                        
                        return Ok(true);
                    }
                }
            }
        }
        
        Ok(false)
    }
    
    /// Extract temp file from commands
    fn extract_temp_file(&self, cmd1: &str, cmd2: &str) -> Option<String> {
        // Look for > file in cmd1 and < file in cmd2
        if let Some(output_file) = self.extract_output_file(cmd1) {
            if let Some(input_file) = self.extract_input_file(cmd2) {
                if output_file == input_file {
                    return Some(output_file);
                }
            }
        }
        
        None
    }
    
    fn extract_output_file(&self, cmd: &str) -> Option<String> {
        if let Some(pos) = cmd.find(" > ") {
            let file = cmd[pos + 3..].trim().split_whitespace().next()?;
            Some(file.to_string())
        } else {
            None
        }
    }
    
    fn extract_input_file(&self, cmd: &str) -> Option<String> {
        if let Some(pos) = cmd.find(" < ") {
            let file = cmd[pos + 3..].trim().split_whitespace().next()?;
            Some(file.to_string())
        } else {
            None
        }
    }
}

/// Resource sharing optimizer
struct ResourceOptimizer;

impl ResourceOptimizer {
    /// Apply process substitution
    fn apply_process_substitution(
        &self,
        commands: &mut Vec<String>,
        synergy: &CommandSynergy,
    ) -> Result<bool> {
        let indices = &synergy.commands;
        
        if indices.len() < 2 {
            return Ok(false);
        }
        
        // Create process substitution command
        let mut substitutions = Vec::new();
        for &idx in indices.iter().skip(1) {
            if idx < commands.len() {
                substitutions.push(format!("<({})", commands[idx]));
            }
        }
        
        if !substitutions.is_empty() && indices[0] < commands.len() {
            let base_cmd = &commands[indices[0]];
            let enhanced = format!("{} {}", base_cmd, substitutions.join(" "));
            
            commands[indices[0]] = enhanced;
            
            // Remove substituted commands
            for &idx in indices.iter().skip(1).rev() {
                if idx < commands.len() {
                    commands.remove(idx);
                }
            }
            
            return Ok(true);
        }
        
        Ok(false)
    }
    
    /// Apply shared memory optimization
    fn apply_shared_memory(
        &self,
        commands: &mut Vec<String>,
        synergy: &CommandSynergy,
        context: &SynergyContext,
    ) -> Result<bool> {
        if !context.resources.has_shm {
            return Ok(false);
        }
        
        // Create shared memory setup
        let shm_path = "/dev/shm/bashgod_tmp";
        let indices = &synergy.commands;
        
        if indices.len() >= 2 && indices[0] < commands.len() {
            // First command writes to shared memory
            commands[indices[0]] = format!("{} > {}", commands[indices[0]], shm_path);
            
            // Other commands read from shared memory
            for &idx in indices.iter().skip(1) {
                if idx < commands.len() {
                    commands[idx] = format!("{} < {}", commands[idx], shm_path);
                }
            }
            
            // Add cleanup
            commands.push(format!("rm -f {}", shm_path));
            
            return Ok(true);
        }
        
        Ok(false)
    }
    
    /// Apply named pipes
    fn apply_named_pipes(
        &self,
        commands: &mut Vec<String>,
        synergy: &CommandSynergy,
    ) -> Result<bool> {
        let indices = &synergy.commands;
        
        if indices.len() < 2 {
            return Ok(false);
        }
        
        let fifo_path = "/tmp/bashgod_fifo_$$";
        
        // Create FIFO
        let setup = format!("mkfifo {}", fifo_path);
        
        // Modify commands to use FIFO
        if indices[0] < commands.len() && indices[1] < commands.len() {
            let writer = format!("{} > {} &", commands[indices[0]], fifo_path);
            let reader = format!("{} < {}", commands[indices[1]], fifo_path);
            
            // Replace with FIFO-based commands
            commands[indices[0]] = format!("{} && {} && {} && rm -f {}", 
                setup, writer, reader, fifo_path);
            
            // Remove reader command
            commands.remove(indices[1]);
            
            return Ok(true);
        }
        
        Ok(false)
    }
}

/// Parallel execution optimizer
struct ParallelOptimizer;

impl ParallelOptimizer {
    /// Apply parallel execution
    fn apply(&self, commands: &mut Vec<String>, synergy: &CommandSynergy) -> Result<bool> {
        let indices = &synergy.commands;
        
        if indices.len() < 2 {
            return Ok(false);
        }
        
        // Extract parallelizable commands
        let mut parallel_cmds = Vec::new();
        for &idx in indices {
            if idx < commands.len() {
                parallel_cmds.push(commands[idx].clone());
            }
        }
        
        // Create GNU parallel command
        let parallel_cmd = format!(
            "parallel -j {} ::: {}",
            indices.len(),
            parallel_cmds.iter()
                .map(|cmd| format!("\"{}\"", cmd))
                .collect::<Vec<_>>()
                .join(" ")
        );
        
        // Replace with parallel execution
        if !indices.is_empty() && indices[0] < commands.len() {
            commands[indices[0]] = parallel_cmd;
            
            // Remove other commands
            for &idx in indices.iter().skip(1).rev() {
                if idx < commands.len() {
                    commands.remove(idx);
                }
            }
            
            return Ok(true);
        }
        
        Ok(false)
    }
}

/// Cache optimizer
struct CacheOptimizer;

impl CacheOptimizer {
    /// Apply caching optimization
    fn apply(&self, commands: &mut Vec<String>, synergy: &CommandSynergy) -> Result<bool> {
        // Add caching wrapper around expensive commands
        for &idx in &synergy.commands {
            if idx < commands.len() {
                let cache_key = self.generate_cache_key(&commands[idx]);
                let cache_file = format!("/tmp/bashgod_cache_{}", cache_key);
                
                // Wrap with cache check
                let cached_cmd = format!(
                    "if [ -f {} ] && [ -z \"$(find {} -mmin +60)\" ]; then cat {}; else {} | tee {}; fi",
                    cache_file, cache_file, cache_file, commands[idx], cache_file
                );
                
                commands[idx] = cached_cmd;
            }
        }
        
        Ok(!synergy.commands.is_empty())
    }
    
    /// Generate cache key
    fn generate_cache_key(&self, command: &str) -> String {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        
        let mut hasher = DefaultHasher::new();
        command.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}

impl OptimizationStrategies {
    fn new() -> Self {
        Self {
            pipeline_optimizer: PipelineOptimizer,
            resource_optimizer: ResourceOptimizer,
            parallel_optimizer: ParallelOptimizer,
            cache_optimizer: CacheOptimizer,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synthex_bashgod::synergy::{
        SynergyBenefits, SystemResources, PerformanceConstraints,
    };
    
    #[tokio::test]
    async fn test_pipeline_optimization() {
        let optimizer = SynergyOptimizer::new(OptimizerConfig::default());
        
        let commands = vec![
            "find . -name '*.log'".to_string(),
            "grep ERROR".to_string(),
            "sort".to_string(),
        ];
        
        let synergy = CommandSynergy {
            id: "test-pipeline".to_string(),
            commands: vec![0, 1, 2],
            synergy_type: crate::synthex_bashgod::synergy::SynergyType::DataPipeline,
            score: 0.8,
            description: "Pipeline optimization".to_string(),
            benefits: SynergyBenefits {
                performance_gain: 0.4,
                resource_savings: 0.3,
                complexity_reduction: 0.2,
                reliability_gain: 0.1,
            },
            implementation: SynergyImplementation {
                strategy: ImplementationStrategy::PipelineMerge,
                changes: vec![],
                prerequisites: vec![],
                example: None,
            },
        };
        
        let context = SynergyContext {
            resources: SystemResources {
                cpu_cores: 4,
                memory_mb: 8192,
                has_shm: true,
                has_fifo: true,
            },
            available_tools: vec!["find".to_string(), "grep".to_string()],
            constraints: PerformanceConstraints {
                max_time_ms: None,
                max_memory_mb: None,
                atomic_required: false,
            },
        };
        
        let result = optimizer.optimize(commands, vec![synergy], &context).await.unwrap();
        
        assert!(result.success);
        assert_eq!(result.optimized.len(), 1);
        assert!(result.optimized[0].contains("|"));
    }
    
    #[test]
    fn test_complexity_scoring() {
        let optimizer = SynergyOptimizer::new(OptimizerConfig::default());
        
        let simple = vec!["echo hello".to_string()];
        let complex = vec!["find . | grep test | awk '{print $1}' | sort | uniq".to_string()];
        
        let simple_score = optimizer.calculate_complexity_score(&simple);
        let complex_score = optimizer.calculate_complexity_score(&complex);
        
        assert!(complex_score > simple_score);
    }
}