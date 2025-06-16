use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};
use anyhow::Result;
use candle_core::{Device, Tensor, DType};
use candle_nn::{Module, VarBuilder, VarMap};

/// Command execution pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandPattern {
    pub commands: Vec<String>,
    pub execution_time_ms: u64,
    pub success_rate: f64,
    pub resource_usage: ResourceUsage,
    pub timestamp: DateTime<Utc>,
    pub context: ExecutionContext,
}

/// Resource usage metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub cpu_percent: f32,
    pub memory_mb: u64,
    pub io_reads: u64,
    pub io_writes: u64,
    pub network_bytes: u64,
}

/// Execution context for pattern learning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContext {
    pub environment: String,
    pub user_id: String,
    pub task_type: String,
    pub tags: Vec<String>,
}

/// Pattern detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedPattern {
    pub pattern_id: String,
    pub frequency: u32,
    pub avg_execution_time_ms: u64,
    pub optimization_potential: f64,
    pub similar_patterns: Vec<String>,
    pub recommended_chain: Option<OptimizedChain>,
}

/// Optimized command chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizedChain {
    pub commands: Vec<String>,
    pub parallel_groups: Vec<Vec<usize>>,
    pub estimated_speedup: f64,
    pub resource_allocation: ResourceAllocation,
}

/// Resource allocation strategy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAllocation {
    pub cpu_cores: u32,
    pub memory_limit_mb: u64,
    pub priority: i8,
}

/// Pattern detector with ML capabilities
pub struct PatternDetector {
    patterns: Arc<RwLock<HashMap<String, CommandPattern>>>,
    pattern_history: Arc<RwLock<VecDeque<CommandPattern>>>,
    detection_model: Option<PatternDetectionModel>,
    device: Device,
    config: PatternDetectorConfig,
}

/// Configuration for pattern detector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternDetectorConfig {
    pub history_size: usize,
    pub min_pattern_frequency: u32,
    pub similarity_threshold: f64,
    pub optimization_threshold: f64,
    pub model_update_interval: Duration,
}

impl Default for PatternDetectorConfig {
    fn default() -> Self {
        Self {
            history_size: 10000,
            min_pattern_frequency: 3,
            similarity_threshold: 0.85,
            optimization_threshold: 0.2, // 20% improvement threshold
            model_update_interval: Duration::hours(1),
        }
    }
}

/// Neural network model for pattern detection
struct PatternDetectionModel {
    embedding_layer: candle_nn::Linear,
    lstm_layer: candle_nn::LSTM,
    attention_layer: candle_nn::Linear,
    output_layer: candle_nn::Linear,
    var_map: VarMap,
}

impl PatternDetector {
    pub fn new(config: PatternDetectorConfig) -> Result<Self> {
        let device = Device::cuda_if_available(0)?;
        
        Ok(Self {
            patterns: Arc::new(RwLock::new(HashMap::new())),
            pattern_history: Arc::new(RwLock::new(VecDeque::with_capacity(config.history_size))),
            detection_model: None,
            device,
            config,
        })
    }

    /// Initialize the ML model
    pub fn initialize_model(&mut self) -> Result<()> {
        let var_map = VarMap::new();
        let vb = VarBuilder::from_varmap(&var_map, DType::F32, &self.device);
        
        // Build pattern detection neural network
        let embedding_dim = 128;
        let hidden_dim = 256;
        let num_layers = 2;
        
        let embedding_layer = candle_nn::linear(1000, embedding_dim, vb.pp("embedding"))?;
        let lstm_layer = candle_nn::lstm(embedding_dim, hidden_dim, num_layers, vb.pp("lstm"))?;
        let attention_layer = candle_nn::linear(hidden_dim, hidden_dim, vb.pp("attention"))?;
        let output_layer = candle_nn::linear(hidden_dim, 64, vb.pp("output"))?;
        
        self.detection_model = Some(PatternDetectionModel {
            embedding_layer,
            lstm_layer,
            attention_layer,
            output_layer,
            var_map,
        });
        
        Ok(())
    }

    /// Record a command execution pattern
    pub fn record_pattern(&self, pattern: CommandPattern) -> Result<()> {
        let pattern_key = self.generate_pattern_key(&pattern);
        
        // Update pattern history
        {
            let mut history = self.pattern_history.write();
            if history.len() >= self.config.history_size {
                history.pop_front();
            }
            history.push_back(pattern.clone());
        }
        
        // Update pattern database
        {
            let mut patterns = self.patterns.write();
            patterns.insert(pattern_key, pattern);
        }
        
        Ok(())
    }

    /// Detect patterns in command sequences
    pub fn detect_patterns(&self, commands: &[String]) -> Result<Vec<DetectedPattern>> {
        let mut detected = Vec::new();
        
        // Analyze command sequences
        let sequences = self.extract_sequences(commands);
        
        for sequence in sequences {
            if let Some(pattern) = self.analyze_sequence(&sequence)? {
                detected.push(pattern);
            }
        }
        
        // Sort by optimization potential
        detected.sort_by(|a, b| {
            b.optimization_potential.partial_cmp(&a.optimization_potential)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        
        Ok(detected)
    }

    /// Identify optimization opportunities
    pub fn identify_optimizations(&self) -> Result<Vec<OptimizedChain>> {
        let patterns = self.patterns.read();
        let mut optimizations = Vec::new();
        
        for (_, pattern) in patterns.iter() {
            if let Some(optimized) = self.optimize_pattern(pattern)? {
                if optimized.estimated_speedup > 1.0 + self.config.optimization_threshold {
                    optimizations.push(optimized);
                }
            }
        }
        
        // Rank by estimated speedup
        optimizations.sort_by(|a, b| {
            b.estimated_speedup.partial_cmp(&a.estimated_speedup)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        
        Ok(optimizations)
    }

    /// Extract execution patterns from historical data
    pub fn extract_execution_patterns(&self) -> Result<Vec<CommandPattern>> {
        let history = self.pattern_history.read();
        let mut patterns = Vec::new();
        
        // Group similar command sequences
        let grouped = self.group_similar_sequences(&history);
        
        for group in grouped {
            if group.len() >= self.config.min_pattern_frequency as usize {
                if let Some(pattern) = self.merge_pattern_group(&group) {
                    patterns.push(pattern);
                }
            }
        }
        
        Ok(patterns)
    }

    /// Generate a key for pattern identification
    fn generate_pattern_key(&self, pattern: &CommandPattern) -> String {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        for cmd in &pattern.commands {
            hasher.update(cmd.as_bytes());
        }
        
        format!("{:x}", hasher.finalize())
    }

    /// Extract command sequences from a list
    fn extract_sequences(&self, commands: &[String]) -> Vec<Vec<String>> {
        let mut sequences = Vec::new();
        let window_sizes = vec![2, 3, 5, 8]; // Different sequence lengths
        
        for window_size in window_sizes {
            if commands.len() >= window_size {
                for window in commands.windows(window_size) {
                    sequences.push(window.to_vec());
                }
            }
        }
        
        sequences
    }

    /// Analyze a command sequence for patterns
    fn analyze_sequence(&self, sequence: &[String]) -> Result<Option<DetectedPattern>> {
        let patterns = self.patterns.read();
        let mut best_match: Option<(String, f64)> = None;
        
        // Find similar patterns
        for (pattern_id, pattern) in patterns.iter() {
            let similarity = self.calculate_similarity(sequence, &pattern.commands)?;
            
            if similarity > self.config.similarity_threshold {
                if best_match.is_none() || similarity > best_match.as_ref().unwrap().1 {
                    best_match = Some((pattern_id.clone(), similarity));
                }
            }
        }
        
        if let Some((pattern_id, _)) = best_match {
            if let Some(pattern) = patterns.get(&pattern_id) {
                let optimization_potential = self.calculate_optimization_potential(pattern)?;
                
                Ok(Some(DetectedPattern {
                    pattern_id: pattern_id.clone(),
                    frequency: 1, // Will be updated by aggregation
                    avg_execution_time_ms: pattern.execution_time_ms,
                    optimization_potential,
                    similar_patterns: vec![],
                    recommended_chain: None,
                }))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Calculate similarity between command sequences
    fn calculate_similarity(&self, seq1: &[String], seq2: &[String]) -> Result<f64> {
        // Use Levenshtein distance normalized by length
        let distance = self.levenshtein_distance(seq1, seq2);
        let max_len = seq1.len().max(seq2.len()) as f64;
        
        Ok(1.0 - (distance as f64 / max_len))
    }

    /// Calculate Levenshtein distance
    fn levenshtein_distance(&self, s1: &[String], s2: &[String]) -> usize {
        let len1 = s1.len();
        let len2 = s2.len();
        let mut matrix = vec![vec![0; len2 + 1]; len1 + 1];
        
        for i in 0..=len1 {
            matrix[i][0] = i;
        }
        
        for j in 0..=len2 {
            matrix[0][j] = j;
        }
        
        for i in 1..=len1 {
            for j in 1..=len2 {
                let cost = if s1[i - 1] == s2[j - 1] { 0 } else { 1 };
                matrix[i][j] = (matrix[i - 1][j] + 1)
                    .min(matrix[i][j - 1] + 1)
                    .min(matrix[i - 1][j - 1] + cost);
            }
        }
        
        matrix[len1][len2]
    }

    /// Calculate optimization potential
    fn calculate_optimization_potential(&self, pattern: &CommandPattern) -> Result<f64> {
        // Factors: execution time, resource usage, parallelization opportunities
        let base_score = 1.0;
        
        // Time optimization potential
        let time_factor = if pattern.execution_time_ms > 1000 {
            (pattern.execution_time_ms as f64 / 1000.0).ln()
        } else {
            0.0
        };
        
        // Resource optimization potential
        let resource_factor = (pattern.resource_usage.cpu_percent / 100.0) +
            (pattern.resource_usage.memory_mb as f64 / 1024.0).min(1.0);
        
        // Parallelization potential (analyze command dependencies)
        let parallel_factor = self.estimate_parallelization_potential(&pattern.commands)?;
        
        Ok(base_score * (1.0 + time_factor + resource_factor + parallel_factor) / 4.0)
    }

    /// Estimate parallelization potential
    fn estimate_parallelization_potential(&self, commands: &[String]) -> Result<f64> {
        // Simple heuristic: look for independent commands
        let mut dependency_graph = vec![vec![false; commands.len()]; commands.len()];
        
        // Build dependency graph
        for (i, cmd1) in commands.iter().enumerate() {
            for (j, cmd2) in commands.iter().enumerate().skip(i + 1) {
                if self.commands_have_dependency(cmd1, cmd2) {
                    dependency_graph[i][j] = true;
                    dependency_graph[j][i] = true;
                }
            }
        }
        
        // Count independent command groups
        let independent_groups = self.count_independent_groups(&dependency_graph);
        
        Ok(independent_groups as f64 / commands.len() as f64)
    }

    /// Check if two commands have dependencies
    fn commands_have_dependency(&self, cmd1: &str, cmd2: &str) -> bool {
        // Simple heuristic: check for shared files/resources
        let tokens1: Vec<&str> = cmd1.split_whitespace().collect();
        let tokens2: Vec<&str> = cmd2.split_whitespace().collect();
        
        // Check for common file operations
        for t1 in &tokens1 {
            for t2 in &tokens2 {
                if t1.contains('/') && t2.contains('/') && t1 == t2 {
                    return true;
                }
            }
        }
        
        false
    }

    /// Count independent command groups
    fn count_independent_groups(&self, dependency_graph: &[Vec<bool>]) -> usize {
        let n = dependency_graph.len();
        let mut visited = vec![false; n];
        let mut groups = 0;
        
        for i in 0..n {
            if !visited[i] {
                self.dfs(i, &dependency_graph, &mut visited);
                groups += 1;
            }
        }
        
        groups
    }

    /// Depth-first search for connected components
    fn dfs(&self, node: usize, graph: &[Vec<bool>], visited: &mut [bool]) {
        visited[node] = true;
        
        for (neighbor, &connected) in graph[node].iter().enumerate() {
            if connected && !visited[neighbor] {
                self.dfs(neighbor, graph, visited);
            }
        }
    }

    /// Optimize a command pattern
    fn optimize_pattern(&self, pattern: &CommandPattern) -> Result<Option<OptimizedChain>> {
        // Analyze parallelization opportunities
        let parallel_groups = self.identify_parallel_groups(&pattern.commands)?;
        
        // Estimate speedup
        let estimated_speedup = self.estimate_speedup(&pattern.commands, &parallel_groups)?;
        
        // Determine resource allocation
        let resource_allocation = self.calculate_optimal_resources(pattern)?;
        
        Ok(Some(OptimizedChain {
            commands: pattern.commands.clone(),
            parallel_groups,
            estimated_speedup,
            resource_allocation,
        }))
    }

    /// Identify groups of commands that can run in parallel
    fn identify_parallel_groups(&self, commands: &[String]) -> Result<Vec<Vec<usize>>> {
        let mut groups = Vec::new();
        let mut dependency_graph = vec![vec![false; commands.len()]; commands.len()];
        
        // Build dependency graph
        for (i, cmd1) in commands.iter().enumerate() {
            for (j, cmd2) in commands.iter().enumerate().skip(i + 1) {
                if self.commands_have_dependency(cmd1, cmd2) {
                    dependency_graph[i][j] = true;
                }
            }
        }
        
        // Topological sort to identify parallel groups
        let mut in_degree = vec![0; commands.len()];
        for i in 0..commands.len() {
            for j in 0..commands.len() {
                if dependency_graph[j][i] {
                    in_degree[i] += 1;
                }
            }
        }
        
        let mut queue = VecDeque::new();
        for (i, &degree) in in_degree.iter().enumerate() {
            if degree == 0 {
                queue.push_back(i);
            }
        }
        
        while !queue.is_empty() {
            let mut current_group = Vec::new();
            let group_size = queue.len();
            
            for _ in 0..group_size {
                if let Some(node) = queue.pop_front() {
                    current_group.push(node);
                    
                    for j in 0..commands.len() {
                        if dependency_graph[node][j] {
                            in_degree[j] -= 1;
                            if in_degree[j] == 0 {
                                queue.push_back(j);
                            }
                        }
                    }
                }
            }
            
            if !current_group.is_empty() {
                groups.push(current_group);
            }
        }
        
        Ok(groups)
    }

    /// Estimate speedup from parallelization
    fn estimate_speedup(&self, commands: &[String], parallel_groups: &[Vec<usize>]) -> Result<f64> {
        if parallel_groups.is_empty() {
            return Ok(1.0);
        }
        
        // Simple model: speedup = sequential_time / parallel_time
        let sequential_time = commands.len() as f64;
        let parallel_time = parallel_groups.len() as f64;
        
        // Account for parallelization overhead
        let overhead_factor = 0.1; // 10% overhead
        let effective_speedup = sequential_time / (parallel_time * (1.0 + overhead_factor));
        
        Ok(effective_speedup.max(1.0))
    }

    /// Calculate optimal resource allocation
    fn calculate_optimal_resources(&self, pattern: &CommandPattern) -> Result<ResourceAllocation> {
        // Base allocation on pattern characteristics
        let cpu_cores = (pattern.resource_usage.cpu_percent / 25.0).ceil() as u32;
        let memory_limit_mb = (pattern.resource_usage.memory_mb as f64 * 1.5) as u64;
        
        // Priority based on execution frequency and time
        let priority = if pattern.execution_time_ms > 5000 {
            1 // High priority for long-running tasks
        } else if pattern.execution_time_ms > 1000 {
            0 // Normal priority
        } else {
            -1 // Low priority for quick tasks
        };
        
        Ok(ResourceAllocation {
            cpu_cores: cpu_cores.max(1).min(num_cpus::get() as u32),
            memory_limit_mb: memory_limit_mb.max(128),
            priority,
        })
    }

    /// Group similar command sequences
    fn group_similar_sequences(&self, history: &VecDeque<CommandPattern>) -> Vec<Vec<CommandPattern>> {
        let mut groups: Vec<Vec<CommandPattern>> = Vec::new();
        
        for pattern in history.iter() {
            let mut added = false;
            
            for group in &mut groups {
                if let Some(first) = group.first() {
                    if let Ok(similarity) = self.calculate_similarity(&pattern.commands, &first.commands) {
                        if similarity > self.config.similarity_threshold {
                            group.push(pattern.clone());
                            added = true;
                            break;
                        }
                    }
                }
            }
            
            if !added {
                groups.push(vec![pattern.clone()]);
            }
        }
        
        groups
    }

    /// Merge a group of similar patterns
    fn merge_pattern_group(&self, group: &[CommandPattern]) -> Option<CommandPattern> {
        if group.is_empty() {
            return None;
        }
        
        // Calculate average metrics
        let avg_execution_time = group.iter()
            .map(|p| p.execution_time_ms)
            .sum::<u64>() / group.len() as u64;
        
        let avg_success_rate = group.iter()
            .map(|p| p.success_rate)
            .sum::<f64>() / group.len() as f64;
        
        let avg_cpu = group.iter()
            .map(|p| p.resource_usage.cpu_percent)
            .sum::<f32>() / group.len() as f32;
        
        let avg_memory = group.iter()
            .map(|p| p.resource_usage.memory_mb)
            .sum::<u64>() / group.len() as u64;
        
        Some(CommandPattern {
            commands: group[0].commands.clone(),
            execution_time_ms: avg_execution_time,
            success_rate: avg_success_rate,
            resource_usage: ResourceUsage {
                cpu_percent: avg_cpu,
                memory_mb: avg_memory,
                io_reads: 0,
                io_writes: 0,
                network_bytes: 0,
            },
            timestamp: group[0].timestamp,
            context: group[0].context.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_detection() {
        let config = PatternDetectorConfig::default();
        let detector = PatternDetector::new(config).unwrap();
        
        let pattern = CommandPattern {
            commands: vec!["make build".to_string(), "make test".to_string()],
            execution_time_ms: 5000,
            success_rate: 0.95,
            resource_usage: ResourceUsage {
                cpu_percent: 80.0,
                memory_mb: 512,
                io_reads: 1000,
                io_writes: 500,
                network_bytes: 0,
            },
            timestamp: Utc::now(),
            context: ExecutionContext {
                environment: "development".to_string(),
                user_id: "test_user".to_string(),
                task_type: "build".to_string(),
                tags: vec!["ci".to_string()],
            },
        };
        
        detector.record_pattern(pattern).unwrap();
        
        let commands = vec!["make build".to_string(), "make test".to_string()];
        let detected = detector.detect_patterns(&commands).unwrap();
        
        assert!(!detected.is_empty());
    }

    #[test]
    fn test_parallelization_detection() {
        let config = PatternDetectorConfig::default();
        let detector = PatternDetector::new(config).unwrap();
        
        let commands = vec![
            "npm install".to_string(),
            "pip install -r requirements.txt".to_string(),
            "cargo build".to_string(),
        ];
        
        let groups = detector.identify_parallel_groups(&commands).unwrap();
        assert_eq!(groups.len(), 1); // All can run in parallel
        assert_eq!(groups[0].len(), 3);
    }
}