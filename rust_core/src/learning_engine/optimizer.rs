use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use anyhow::{Result, Context};
use rayon::prelude::*;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::algo::toposort;
use chrono::{DateTime, Utc};

use crate::learning_engine::pattern_detector::{
    CommandPattern, OptimizedChain, ResourceAllocation, ResourceUsage
};

/// Chain optimization algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OptimizationStrategy {
    Parallel,
    Sequential,
    Hybrid,
    ResourceAware,
    CostOptimized,
}

/// Optimization result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationResult {
    pub original_chain: Vec<String>,
    pub optimized_chain: OptimizedCommandChain,
    pub strategy_used: OptimizationStrategy,
    pub estimated_improvement: f64,
    pub confidence_score: f64,
    pub resource_savings: ResourceSavings,
}

/// Optimized command chain with execution plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizedCommandChain {
    pub stages: Vec<ExecutionStage>,
    pub total_estimated_time_ms: u64,
    pub resource_requirements: ResourceRequirements,
    pub dependency_graph: DependencyGraph,
}

/// Execution stage with parallel commands
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionStage {
    pub stage_id: usize,
    pub commands: Vec<CommandNode>,
    pub can_parallelize: bool,
    pub estimated_duration_ms: u64,
    pub resource_allocation: ResourceAllocation,
}

/// Command node in execution graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandNode {
    pub id: usize,
    pub command: String,
    pub dependencies: Vec<usize>,
    pub estimated_time_ms: u64,
    pub resource_estimate: ResourceUsage,
    pub priority: i32,
}

/// Resource requirements for chain execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRequirements {
    pub min_cpu_cores: u32,
    pub max_cpu_cores: u32,
    pub min_memory_mb: u64,
    pub max_memory_mb: u64,
    pub peak_io_ops: u64,
    pub network_bandwidth_mbps: f64,
}

/// Resource savings from optimization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSavings {
    pub time_saved_percent: f64,
    pub cpu_saved_percent: f64,
    pub memory_saved_percent: f64,
    pub cost_saved_percent: f64,
}

/// Dependency graph representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyGraph {
    pub nodes: Vec<String>,
    pub edges: Vec<(usize, usize)>,
    pub critical_path: Vec<usize>,
}

/// Command chain optimizer
pub struct ChainOptimizer {
    optimization_cache: Arc<RwLock<HashMap<String, OptimizationResult>>>,
    performance_history: Arc<RwLock<VecDeque<PerformanceMetric>>>,
    resource_predictor: ResourcePredictor,
    config: OptimizerConfig,
}

/// Optimizer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizerConfig {
    pub max_parallel_commands: usize,
    pub resource_oversubscription_factor: f64,
    pub optimization_aggressiveness: f64,
    pub cache_ttl_seconds: u64,
    pub min_parallelization_benefit: f64,
}

impl Default for OptimizerConfig {
    fn default() -> Self {
        Self {
            max_parallel_commands: 8,
            resource_oversubscription_factor: 1.2,
            optimization_aggressiveness: 0.7,
            cache_ttl_seconds: 3600,
            min_parallelization_benefit: 0.1, // 10% improvement threshold
        }
    }
}

/// Performance metric for historical analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PerformanceMetric {
    pub chain_hash: String,
    pub actual_time_ms: u64,
    pub predicted_time_ms: u64,
    pub resource_usage: ResourceUsage,
    pub timestamp: DateTime<Utc>,
}

/// Resource usage predictor
struct ResourcePredictor {
    command_profiles: HashMap<String, CommandProfile>,
}

/// Command execution profile
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CommandProfile {
    pub avg_cpu_percent: f32,
    pub avg_memory_mb: u64,
    pub avg_duration_ms: u64,
    pub io_intensity: f64,
    pub network_intensity: f64,
}

impl ChainOptimizer {
    pub fn new(config: OptimizerConfig) -> Result<Self> {
        Ok(Self {
            optimization_cache: Arc::new(RwLock::new(HashMap::new())),
            performance_history: Arc::new(RwLock::new(VecDeque::with_capacity(10000))),
            resource_predictor: ResourcePredictor::new(),
            config,
        })
    }

    /// Optimize a command chain
    pub fn optimize_chain(&self, commands: &[String]) -> Result<OptimizationResult> {
        // Check cache first
        let chain_hash = self.hash_chain(commands);
        if let Some(cached) = self.get_cached_optimization(&chain_hash) {
            return Ok(cached);
        }

        // Analyze command dependencies
        let dependency_graph = self.build_dependency_graph(commands)?;
        
        // Try different optimization strategies
        let strategies = vec![
            OptimizationStrategy::Parallel,
            OptimizationStrategy::ResourceAware,
            OptimizationStrategy::Hybrid,
        ];
        
        let mut best_result = None;
        let mut best_improvement = 0.0;
        
        for strategy in strategies {
            let result = self.apply_strategy(commands, &dependency_graph, &strategy)?;
            let improvement = self.calculate_improvement(&result);
            
            if improvement > best_improvement {
                best_improvement = improvement;
                best_result = Some(result);
            }
        }
        
        let result = best_result.context("No optimization strategy produced valid results")?;
        
        // Cache the result
        self.cache_optimization(&chain_hash, &result);
        
        Ok(result)
    }

    /// Build dependency graph for commands
    fn build_dependency_graph(&self, commands: &[String]) -> Result<DiGraph<CommandNode, ()>> {
        let mut graph = DiGraph::new();
        let mut node_indices = Vec::new();
        
        // Create nodes
        for (i, cmd) in commands.iter().enumerate() {
            let node = CommandNode {
                id: i,
                command: cmd.clone(),
                dependencies: Vec::new(),
                estimated_time_ms: self.estimate_command_time(cmd),
                resource_estimate: self.estimate_command_resources(cmd),
                priority: 0,
            };
            
            let idx = graph.add_node(node);
            node_indices.push(idx);
        }
        
        // Analyze dependencies
        for i in 0..commands.len() {
            for j in (i + 1)..commands.len() {
                if self.has_dependency(&commands[i], &commands[j]) {
                    graph.add_edge(node_indices[i], node_indices[j], ());
                }
            }
        }
        
        Ok(graph)
    }

    /// Apply optimization strategy
    fn apply_strategy(
        &self,
        commands: &[String],
        graph: &DiGraph<CommandNode, ()>,
        strategy: &OptimizationStrategy,
    ) -> Result<OptimizationResult> {
        let optimized_chain = match strategy {
            OptimizationStrategy::Parallel => self.optimize_parallel(commands, graph)?,
            OptimizationStrategy::ResourceAware => self.optimize_resource_aware(commands, graph)?,
            OptimizationStrategy::Hybrid => self.optimize_hybrid(commands, graph)?,
            _ => self.optimize_parallel(commands, graph)?, // Default to parallel
        };
        
        let estimated_improvement = self.estimate_improvement(&optimized_chain, commands);
        let resource_savings = self.calculate_resource_savings(&optimized_chain, commands);
        
        Ok(OptimizationResult {
            original_chain: commands.to_vec(),
            optimized_chain,
            strategy_used: strategy.clone(),
            estimated_improvement,
            confidence_score: self.calculate_confidence_score(commands),
            resource_savings,
        })
    }

    /// Parallel optimization strategy
    fn optimize_parallel(
        &self,
        commands: &[String],
        graph: &DiGraph<CommandNode, ()>,
    ) -> Result<OptimizedCommandChain> {
        // Topological sort to identify execution stages
        let sorted_nodes = toposort(graph, None)
            .map_err(|_| anyhow::anyhow!("Cyclic dependencies detected"))?;
        
        // Group into parallel stages
        let mut stages = Vec::new();
        let mut current_stage = Vec::new();
        let mut stage_dependencies = HashSet::new();
        
        for node_idx in sorted_nodes {
            let node = &graph[node_idx];
            
            // Check if this command depends on any in current stage
            let depends_on_current = graph.edges_directed(node_idx, petgraph::Direction::Incoming)
                .any(|edge| current_stage.iter().any(|n: &CommandNode| n.id == graph[edge.source()].id));
            
            if depends_on_current || current_stage.len() >= self.config.max_parallel_commands {
                // Start new stage
                if !current_stage.is_empty() {
                    stages.push(self.create_execution_stage(stages.len(), current_stage, true));
                    current_stage = Vec::new();
                }
            }
            
            current_stage.push(node.clone());
        }
        
        // Add final stage
        if !current_stage.is_empty() {
            stages.push(self.create_execution_stage(stages.len(), current_stage, true));
        }
        
        let total_time = stages.iter().map(|s| s.estimated_duration_ms).sum();
        let resource_requirements = self.calculate_resource_requirements(&stages);
        let dependency_graph = self.create_dependency_graph_representation(commands, graph);
        
        Ok(OptimizedCommandChain {
            stages,
            total_estimated_time_ms: total_time,
            resource_requirements,
            dependency_graph,
        })
    }

    /// Resource-aware optimization strategy
    fn optimize_resource_aware(
        &self,
        commands: &[String],
        graph: &DiGraph<CommandNode, ()>,
    ) -> Result<OptimizedCommandChain> {
        // Sort commands by resource intensity
        let mut nodes: Vec<_> = graph.node_indices().collect();
        nodes.sort_by_key(|&idx| {
            let node = &graph[idx];
            let intensity = node.resource_estimate.cpu_percent as u64 
                + node.resource_estimate.memory_mb;
            std::cmp::Reverse(intensity)
        });
        
        // Bin packing algorithm for resource allocation
        let mut stages = Vec::new();
        let mut current_stage = Vec::new();
        let mut current_resources = ResourceUsage {
            cpu_percent: 0.0,
            memory_mb: 0,
            io_reads: 0,
            io_writes: 0,
            network_bytes: 0,
        };
        
        let max_cpu = 100.0 * self.config.resource_oversubscription_factor;
        let max_memory = 8192; // 8GB default limit
        
        for &node_idx in &nodes {
            let node = &graph[node_idx];
            
            // Check if adding this command would exceed resource limits
            let new_cpu = current_resources.cpu_percent + node.resource_estimate.cpu_percent;
            let new_memory = current_resources.memory_mb + node.resource_estimate.memory_mb;
            
            if new_cpu > max_cpu as f32 || new_memory > max_memory {
                // Start new stage
                if !current_stage.is_empty() {
                    stages.push(self.create_execution_stage(stages.len(), current_stage, true));
                    current_stage = Vec::new();
                    current_resources = ResourceUsage {
                        cpu_percent: 0.0,
                        memory_mb: 0,
                        io_reads: 0,
                        io_writes: 0,
                        network_bytes: 0,
                    };
                }
            }
            
            current_stage.push(node.clone());
            current_resources.cpu_percent += node.resource_estimate.cpu_percent;
            current_resources.memory_mb += node.resource_estimate.memory_mb;
        }
        
        // Add final stage
        if !current_stage.is_empty() {
            stages.push(self.create_execution_stage(stages.len(), current_stage, true));
        }
        
        let total_time = stages.iter().map(|s| s.estimated_duration_ms).sum();
        let resource_requirements = self.calculate_resource_requirements(&stages);
        let dependency_graph = self.create_dependency_graph_representation(commands, graph);
        
        Ok(OptimizedCommandChain {
            stages,
            total_estimated_time_ms: total_time,
            resource_requirements,
            dependency_graph,
        })
    }

    /// Hybrid optimization strategy
    fn optimize_hybrid(
        &self,
        commands: &[String],
        graph: &DiGraph<CommandNode, ()>,
    ) -> Result<OptimizedCommandChain> {
        // Combine parallel and resource-aware strategies
        let parallel_result = self.optimize_parallel(commands, graph)?;
        let resource_result = self.optimize_resource_aware(commands, graph)?;
        
        // Choose better result based on estimated time and resource efficiency
        let parallel_score = 1.0 / parallel_result.total_estimated_time_ms as f64;
        let resource_score = 1.0 / resource_result.total_estimated_time_ms as f64
            * self.calculate_resource_efficiency(&resource_result);
        
        if parallel_score > resource_score {
            Ok(parallel_result)
        } else {
            Ok(resource_result)
        }
    }

    /// Create execution stage
    fn create_execution_stage(
        &self,
        stage_id: usize,
        commands: Vec<CommandNode>,
        can_parallelize: bool,
    ) -> ExecutionStage {
        let estimated_duration = if can_parallelize {
            commands.iter().map(|c| c.estimated_time_ms).max().unwrap_or(0)
        } else {
            commands.iter().map(|c| c.estimated_time_ms).sum()
        };
        
        let total_cpu = commands.iter().map(|c| c.resource_estimate.cpu_percent).sum::<f32>();
        let total_memory = commands.iter().map(|c| c.resource_estimate.memory_mb).sum::<u64>();
        
        ExecutionStage {
            stage_id,
            commands,
            can_parallelize,
            estimated_duration_ms: estimated_duration,
            resource_allocation: ResourceAllocation {
                cpu_cores: (total_cpu / 100.0).ceil() as u32,
                memory_limit_mb: total_memory,
                priority: 0,
            },
        }
    }

    /// Check if two commands have dependencies
    fn has_dependency(&self, cmd1: &str, cmd2: &str) -> bool {
        // Extract file paths and resources
        let resources1 = self.extract_resources(cmd1);
        let resources2 = self.extract_resources(cmd2);
        
        // Check for shared resources
        for r1 in &resources1 {
            for r2 in &resources2 {
                if r1 == r2 {
                    return true;
                }
            }
        }
        
        // Check for specific command patterns
        self.check_command_patterns(cmd1, cmd2)
    }

    /// Extract resources from command
    fn extract_resources(&self, command: &str) -> Vec<String> {
        let mut resources = Vec::new();
        let tokens: Vec<&str> = command.split_whitespace().collect();
        
        for token in tokens {
            // File paths
            if token.contains('/') || token.contains('.') {
                resources.push(token.to_string());
            }
            
            // Environment variables
            if token.starts_with('$') {
                resources.push(token.to_string());
            }
            
            // Ports
            if token.contains(':') && token.chars().any(|c| c.is_numeric()) {
                resources.push(token.to_string());
            }
        }
        
        resources
    }

    /// Check command patterns for dependencies
    fn check_command_patterns(&self, cmd1: &str, cmd2: &str) -> bool {
        // Build -> Test dependency
        if cmd1.contains("build") && cmd2.contains("test") {
            return true;
        }
        
        // Install -> Use dependency
        if cmd1.contains("install") && !cmd2.contains("install") {
            return true;
        }
        
        // Database operations
        if cmd1.contains("migrate") && cmd2.contains("seed") {
            return true;
        }
        
        false
    }

    /// Estimate command execution time
    fn estimate_command_time(&self, command: &str) -> u64 {
        // Use historical data if available
        if let Some(profile) = self.resource_predictor.get_command_profile(command) {
            return profile.avg_duration_ms;
        }
        
        // Heuristic estimates
        if command.contains("build") || command.contains("compile") {
            5000 // 5 seconds
        } else if command.contains("test") {
            3000 // 3 seconds
        } else if command.contains("install") {
            2000 // 2 seconds
        } else if command.contains("deploy") {
            10000 // 10 seconds
        } else {
            1000 // 1 second default
        }
    }

    /// Estimate command resource usage
    fn estimate_command_resources(&self, command: &str) -> ResourceUsage {
        // Use historical data if available
        if let Some(profile) = self.resource_predictor.get_command_profile(command) {
            return ResourceUsage {
                cpu_percent: profile.avg_cpu_percent,
                memory_mb: profile.avg_memory_mb,
                io_reads: (profile.io_intensity * 1000.0) as u64,
                io_writes: (profile.io_intensity * 500.0) as u64,
                network_bytes: (profile.network_intensity * 1000000.0) as u64,
            };
        }
        
        // Heuristic estimates
        if command.contains("build") || command.contains("compile") {
            ResourceUsage {
                cpu_percent: 80.0,
                memory_mb: 1024,
                io_reads: 10000,
                io_writes: 5000,
                network_bytes: 0,
            }
        } else if command.contains("test") {
            ResourceUsage {
                cpu_percent: 60.0,
                memory_mb: 512,
                io_reads: 5000,
                io_writes: 1000,
                network_bytes: 0,
            }
        } else {
            ResourceUsage {
                cpu_percent: 20.0,
                memory_mb: 256,
                io_reads: 1000,
                io_writes: 500,
                network_bytes: 100000,
            }
        }
    }

    /// Calculate improvement from optimization
    fn calculate_improvement(&self, result: &OptimizationResult) -> f64 {
        result.estimated_improvement
    }

    /// Estimate improvement percentage
    fn estimate_improvement(
        &self,
        optimized: &OptimizedCommandChain,
        original: &[String],
    ) -> f64 {
        let original_time = original.len() as u64 * 1000; // Assume 1s per command
        let optimized_time = optimized.total_estimated_time_ms;
        
        if original_time > 0 {
            (original_time as f64 - optimized_time as f64) / original_time as f64
        } else {
            0.0
        }
    }

    /// Calculate resource savings
    fn calculate_resource_savings(
        &self,
        optimized: &OptimizedCommandChain,
        original: &[String],
    ) -> ResourceSavings {
        let time_saved = self.estimate_improvement(optimized, original);
        
        ResourceSavings {
            time_saved_percent: time_saved * 100.0,
            cpu_saved_percent: time_saved * 50.0, // Assume CPU scales with time
            memory_saved_percent: 20.0, // Conservative memory saving
            cost_saved_percent: time_saved * 80.0, // Cost roughly follows time
        }
    }

    /// Calculate confidence score
    fn calculate_confidence_score(&self, commands: &[String]) -> f64 {
        // Base confidence on historical data availability
        let mut known_commands = 0;
        
        for cmd in commands {
            if self.resource_predictor.get_command_profile(cmd).is_some() {
                known_commands += 1;
            }
        }
        
        let data_confidence = known_commands as f64 / commands.len() as f64;
        
        // Adjust for chain complexity
        let complexity_factor = 1.0 / (1.0 + (commands.len() as f64 / 10.0));
        
        data_confidence * complexity_factor
    }

    /// Calculate resource efficiency
    fn calculate_resource_efficiency(&self, chain: &OptimizedCommandChain) -> f64 {
        let total_cpu = chain.stages.iter()
            .map(|s| s.resource_allocation.cpu_cores)
            .sum::<u32>() as f64;
        
        let total_memory = chain.stages.iter()
            .map(|s| s.resource_allocation.memory_limit_mb)
            .sum::<u64>() as f64;
        
        // Efficiency = 1 / (normalized CPU + normalized memory)
        let cpu_factor = total_cpu / (num_cpus::get() as f64 * chain.stages.len() as f64);
        let memory_factor = total_memory / (8192.0 * chain.stages.len() as f64);
        
        1.0 / (1.0 + cpu_factor + memory_factor)
    }

    /// Calculate resource requirements
    fn calculate_resource_requirements(&self, stages: &[ExecutionStage]) -> ResourceRequirements {
        let min_cpu = stages.iter()
            .map(|s| s.resource_allocation.cpu_cores)
            .min()
            .unwrap_or(1);
        
        let max_cpu = stages.iter()
            .map(|s| s.resource_allocation.cpu_cores)
            .max()
            .unwrap_or(1);
        
        let min_memory = stages.iter()
            .map(|s| s.resource_allocation.memory_limit_mb)
            .min()
            .unwrap_or(128);
        
        let max_memory = stages.iter()
            .map(|s| s.resource_allocation.memory_limit_mb)
            .max()
            .unwrap_or(256);
        
        ResourceRequirements {
            min_cpu_cores: min_cpu,
            max_cpu_cores: max_cpu,
            min_memory_mb: min_memory,
            max_memory_mb: max_memory,
            peak_io_ops: 10000, // Placeholder
            network_bandwidth_mbps: 100.0, // Placeholder
        }
    }

    /// Create dependency graph representation
    fn create_dependency_graph_representation(
        &self,
        commands: &[String],
        graph: &DiGraph<CommandNode, ()>,
    ) -> DependencyGraph {
        let edges: Vec<(usize, usize)> = graph.edge_indices()
            .map(|e| {
                let (src, dst) = graph.edge_endpoints(e).unwrap();
                (graph[src].id, graph[dst].id)
            })
            .collect();
        
        // Find critical path (longest path in DAG)
        let critical_path = self.find_critical_path(graph);
        
        DependencyGraph {
            nodes: commands.to_vec(),
            edges,
            critical_path,
        }
    }

    /// Find critical path in dependency graph
    fn find_critical_path(&self, graph: &DiGraph<CommandNode, ()>) -> Vec<usize> {
        // Simple implementation: return sequential order for now
        // TODO: Implement proper critical path algorithm
        graph.node_indices()
            .map(|idx| graph[idx].id)
            .collect()
    }

    /// Hash command chain for caching
    fn hash_chain(&self, commands: &[String]) -> String {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        for cmd in commands {
            hasher.update(cmd.as_bytes());
            hasher.update(b"|");
        }
        
        format!("{:x}", hasher.finalize())
    }

    /// Get cached optimization result
    fn get_cached_optimization(&self, hash: &str) -> Option<OptimizationResult> {
        let cache = self.optimization_cache.read();
        cache.get(hash).cloned()
    }

    /// Cache optimization result
    fn cache_optimization(&self, hash: &str, result: &OptimizationResult) {
        let mut cache = self.optimization_cache.write();
        cache.insert(hash.to_string(), result.clone());
    }
}

impl ResourcePredictor {
    fn new() -> Self {
        Self {
            command_profiles: HashMap::new(),
        }
    }

    fn get_command_profile(&self, command: &str) -> Option<&CommandProfile> {
        // Simplified lookup - in practice would use more sophisticated matching
        self.command_profiles.get(command)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_optimization() {
        let config = OptimizerConfig::default();
        let optimizer = ChainOptimizer::new(config).unwrap();
        
        let commands = vec![
            "npm install".to_string(),
            "npm run build".to_string(),
            "npm test".to_string(),
        ];
        
        let result = optimizer.optimize_chain(&commands).unwrap();
        
        assert!(result.estimated_improvement >= 0.0);
        assert!(!result.optimized_chain.stages.is_empty());
    }

    #[test]
    fn test_parallel_optimization() {
        let config = OptimizerConfig::default();
        let optimizer = ChainOptimizer::new(config).unwrap();
        
        let commands = vec![
            "curl -o file1.txt https://example.com/1".to_string(),
            "curl -o file2.txt https://example.com/2".to_string(),
            "curl -o file3.txt https://example.com/3".to_string(),
        ];
        
        let result = optimizer.optimize_chain(&commands).unwrap();
        
        // These commands should be parallelized
        assert_eq!(result.optimized_chain.stages.len(), 1);
        assert_eq!(result.optimized_chain.stages[0].commands.len(), 3);
        assert!(result.optimized_chain.stages[0].can_parallelize);
    }
}