//! Synergy detection implementation
//! 
//! Identifies synergistic patterns between commands for optimization

use crate::synthex_bashgod::{Result, SBGError};
use crate::synthex_bashgod::synergy::{
    CommandSynergy, SynergyType, SynergyBenefits, SynergyImplementation,
    SynergyContext, SynergyAnalyzer, SynergyPatterns, PipelinePattern,
    ResourcePattern, ResourceStrategy, ImplementationStrategy,
    SynergyChange, SynergyChangeType, SynergyDetectionResult,
    SynergyRecommendation, ImplementationDifficulty,
};
use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Synergy detector implementation
pub struct SynergyDetector {
    /// Pattern matchers
    pattern_matchers: Arc<PatternMatchers>,
    
    /// Synergy scoring engine
    scoring_engine: Arc<ScoringEngine>,
    
    /// Detection cache
    detection_cache: Arc<DashMap<String, SynergyDetectionResult>>,
    
    /// Statistics
    stats: Arc<RwLock<DetectorStats>>,
}

/// Pattern matching engines
struct PatternMatchers {
    /// Pipeline patterns
    pipeline_patterns: Vec<PipelinePattern>,
    
    /// Resource patterns
    resource_patterns: Vec<ResourcePattern>,
    
    /// Custom matchers
    custom_matchers: Vec<Box<dyn CustomMatcher>>,
}

/// Custom pattern matcher trait
trait CustomMatcher: Send + Sync {
    /// Check if pattern matches
    fn matches(&self, commands: &[String]) -> Option<MatchResult>;
    
    /// Get synergy type
    fn synergy_type(&self) -> SynergyType;
}

/// Pattern match result
#[derive(Debug, Clone)]
struct MatchResult {
    /// Matched command indices
    indices: Vec<usize>,
    
    /// Match confidence
    confidence: f32,
    
    /// Match metadata
    metadata: MatchMetadata,
}

/// Match metadata
#[derive(Debug, Clone)]
struct MatchMetadata {
    /// Pattern name
    pattern_name: String,
    
    /// Optimization hint
    optimization_hint: String,
    
    /// Estimated benefit
    estimated_benefit: f32,
}

/// Synergy scoring engine
struct ScoringEngine {
    /// Scoring weights
    weights: ScoringWeights,
    
    /// Historical scores
    score_history: DashMap<String, f32>,
}

/// Scoring weights configuration
#[derive(Debug, Clone)]
struct ScoringWeights {
    /// Weight for performance improvement
    performance_weight: f32,
    
    /// Weight for resource savings
    resource_weight: f32,
    
    /// Weight for complexity reduction
    complexity_weight: f32,
    
    /// Weight for reliability
    reliability_weight: f32,
}

impl Default for ScoringWeights {
    fn default() -> Self {
        Self {
            performance_weight: 0.4,
            resource_weight: 0.3,
            complexity_weight: 0.2,
            reliability_weight: 0.1,
        }
    }
}

/// Detector statistics
#[derive(Debug, Default)]
struct DetectorStats {
    /// Total detections
    total_detections: u64,
    
    /// Synergies found
    synergies_found: u64,
    
    /// Average synergy score
    avg_synergy_score: f32,
    
    /// Cache hits
    cache_hits: u64,
}

impl SynergyDetector {
    /// Create a new synergy detector
    pub fn new() -> Self {
        let pattern_matchers = Arc::new(PatternMatchers::new());
        let scoring_engine = Arc::new(ScoringEngine::new());
        
        Self {
            pattern_matchers,
            scoring_engine,
            detection_cache: Arc::new(DashMap::new()),
            stats: Arc::new(RwLock::new(DetectorStats::default())),
        }
    }
    
    /// Detect synergies in command chain
    pub async fn detect(
        &self,
        commands: &[String],
        context: &SynergyContext,
    ) -> Result<SynergyDetectionResult> {
        // Generate cache key
        let cache_key = self.generate_cache_key(commands);
        
        // Check cache
        if let Some(cached) = self.detection_cache.get(&cache_key) {
            self.stats.write().await.cache_hits += 1;
            return Ok(cached.clone());
        }
        
        // Detect synergies
        let mut synergies = Vec::new();
        
        // Check pipeline patterns
        synergies.extend(self.detect_pipeline_synergies(commands, context).await?);
        
        // Check resource sharing opportunities
        synergies.extend(self.detect_resource_synergies(commands, context).await?);
        
        // Check data flow synergies
        synergies.extend(self.detect_dataflow_synergies(commands, context).await?);
        
        // Check tool combination synergies
        synergies.extend(self.detect_tool_synergies(commands, context).await?);
        
        // Calculate overall score
        let overall_score = self.calculate_overall_score(&synergies);
        
        // Generate recommendations
        let recommendations = self.generate_recommendations(&synergies, context);
        
        let result = SynergyDetectionResult {
            synergies,
            overall_score,
            recommendations,
        };
        
        // Update cache
        self.detection_cache.insert(cache_key, result.clone());
        
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_detections += 1;
            stats.synergies_found += result.synergies.len() as u64;
            stats.avg_synergy_score = 
                (stats.avg_synergy_score * (stats.total_detections - 1) as f32 + overall_score) 
                / stats.total_detections as f32;
        }
        
        info!("Detected {} synergies with overall score {:.2}", 
              result.synergies.len(), overall_score);
        
        Ok(result)
    }
    
    /// Detect pipeline synergies
    async fn detect_pipeline_synergies(
        &self,
        commands: &[String],
        context: &SynergyContext,
    ) -> Result<Vec<CommandSynergy>> {
        let mut synergies = Vec::new();
        
        // Check for sequential data processing
        for window in commands.windows(3) {
            if self.is_pipeline_candidate(&window) {
                let synergy = CommandSynergy {
                    id: format!("pipeline-{}", uuid::Uuid::new_v4()),
                    commands: vec![0, 1, 2], // Simplified
                    synergy_type: SynergyType::DataPipeline,
                    score: 0.8,
                    description: "Commands can be combined into efficient pipeline".to_string(),
                    benefits: SynergyBenefits {
                        performance_gain: 0.4,
                        resource_savings: 0.3,
                        complexity_reduction: 0.2,
                        reliability_gain: 0.1,
                    },
                    implementation: SynergyImplementation {
                        strategy: ImplementationStrategy::PipelineMerge,
                        changes: vec![
                            SynergyChange {
                                change_type: SynergyChangeType::AddPipe,
                                targets: vec![0, 1],
                                config: serde_json::json!({
                                    "pipe_type": "|"
                                }),
                            },
                        ],
                        prerequisites: vec![],
                        example: Some("cmd1 | cmd2 | cmd3".to_string()),
                    },
                };
                
                synergies.push(synergy);
            }
        }
        
        Ok(synergies)
    }
    
    /// Detect resource sharing synergies
    async fn detect_resource_synergies(
        &self,
        commands: &[String],
        context: &SynergyContext,
    ) -> Result<Vec<CommandSynergy>> {
        let mut synergies = Vec::new();
        
        // Find commands accessing same resources
        let resource_map = self.build_resource_map(commands);
        
        for (resource, accessors) in resource_map {
            if accessors.len() > 1 {
                let synergy = CommandSynergy {
                    id: format!("resource-{}", uuid::Uuid::new_v4()),
                    commands: accessors.clone(),
                    synergy_type: SynergyType::ResourceSharing,
                    score: 0.7,
                    description: format!("Multiple commands access '{}'", resource),
                    benefits: SynergyBenefits {
                        performance_gain: 0.3,
                        resource_savings: 0.5,
                        complexity_reduction: 0.1,
                        reliability_gain: 0.1,
                    },
                    implementation: SynergyImplementation {
                        strategy: ImplementationStrategy::ProcessSubstitution,
                        changes: vec![
                            SynergyChange {
                                change_type: SynergyChangeType::UseProcessSubstitution,
                                targets: accessors,
                                config: serde_json::json!({
                                    "resource": resource,
                                    "method": "tee"
                                }),
                            },
                        ],
                        prerequisites: vec!["Process substitution support".to_string()],
                        example: Some(format!("tee <({}) <({})", "cmd1", "cmd2")),
                    },
                };
                
                synergies.push(synergy);
            }
        }
        
        Ok(synergies)
    }
    
    /// Detect data flow synergies
    async fn detect_dataflow_synergies(
        &self,
        commands: &[String],
        context: &SynergyContext,
    ) -> Result<Vec<CommandSynergy>> {
        let mut synergies = Vec::new();
        
        // Analyze input/output relationships
        for i in 0..commands.len() - 1 {
            let output_type = self.infer_output_type(&commands[i]);
            let input_type = self.infer_input_type(&commands[i + 1]);
            
            if output_type == input_type && !output_type.is_empty() {
                let synergy = CommandSynergy {
                    id: format!("dataflow-{}", uuid::Uuid::new_v4()),
                    commands: vec![i, i + 1],
                    synergy_type: SynergyType::OutputInputMatch,
                    score: 0.85,
                    description: format!("Output of command {} matches input of command {}", i, i + 1),
                    benefits: SynergyBenefits {
                        performance_gain: 0.5,
                        resource_savings: 0.3,
                        complexity_reduction: 0.15,
                        reliability_gain: 0.05,
                    },
                    implementation: SynergyImplementation {
                        strategy: ImplementationStrategy::TempFileElimination,
                        changes: vec![
                            SynergyChange {
                                change_type: SynergyChangeType::EliminateIntermediate,
                                targets: vec![i, i + 1],
                                config: serde_json::json!({
                                    "method": "direct_pipe"
                                }),
                            },
                        ],
                        prerequisites: vec![],
                        example: Some(format!("{} | {}", commands[i], commands[i + 1])),
                    },
                };
                
                synergies.push(synergy);
            }
        }
        
        Ok(synergies)
    }
    
    /// Detect tool combination synergies
    async fn detect_tool_synergies(
        &self,
        commands: &[String],
        context: &SynergyContext,
    ) -> Result<Vec<CommandSynergy>> {
        let mut synergies = Vec::new();
        
        // Check for tools that work well together
        let tool_combinations = vec![
            ("find", "grep", "find -exec grep"),
            ("tar", "gzip", "tar -czf"),
            ("sort", "uniq", "sort -u"),
            ("ps", "grep", "pgrep"),
        ];
        
        for (tool1, tool2, combined) in tool_combinations {
            let mut indices = Vec::new();
            
            for (i, cmd) in commands.iter().enumerate() {
                if cmd.contains(tool1) || cmd.contains(tool2) {
                    indices.push(i);
                }
            }
            
            if indices.len() >= 2 {
                let synergy = CommandSynergy {
                    id: format!("tool-combo-{}", uuid::Uuid::new_v4()),
                    commands: indices.clone(),
                    synergy_type: SynergyType::ToolCombination,
                    score: 0.75,
                    description: format!("'{}' and '{}' can be combined", tool1, tool2),
                    benefits: SynergyBenefits {
                        performance_gain: 0.35,
                        resource_savings: 0.25,
                        complexity_reduction: 0.3,
                        reliability_gain: 0.1,
                    },
                    implementation: SynergyImplementation {
                        strategy: ImplementationStrategy::CombinedTool,
                        changes: vec![
                            SynergyChange {
                                change_type: SynergyChangeType::MergeCommands,
                                targets: indices,
                                config: serde_json::json!({
                                    "combined_command": combined
                                }),
                            },
                        ],
                        prerequisites: vec![],
                        example: Some(combined.to_string()),
                    },
                };
                
                synergies.push(synergy);
            }
        }
        
        Ok(synergies)
    }
    
    /// Check if commands form a pipeline candidate
    fn is_pipeline_candidate(&self, commands: &[String]) -> bool {
        // Simple heuristic: commands that process text data
        let pipeline_commands = vec!["grep", "sed", "awk", "sort", "uniq", "cut", "tr"];
        
        commands.iter().all(|cmd| {
            pipeline_commands.iter().any(|pc| cmd.contains(pc))
        })
    }
    
    /// Build resource access map
    fn build_resource_map(&self, commands: &[String]) -> std::collections::HashMap<String, Vec<usize>> {
        let mut resource_map = std::collections::HashMap::new();
        
        for (i, cmd) in commands.iter().enumerate() {
            // Extract file paths and resources
            let resources = self.extract_resources(cmd);
            
            for resource in resources {
                resource_map.entry(resource)
                    .or_insert_with(Vec::new)
                    .push(i);
            }
        }
        
        resource_map
    }
    
    /// Extract resources from command
    fn extract_resources(&self, command: &str) -> Vec<String> {
        let mut resources = Vec::new();
        
        // Simple extraction of file paths
        let parts: Vec<&str> = command.split_whitespace().collect();
        for part in parts {
            if part.starts_with('/') || part.contains('.') {
                if !part.starts_with('-') {
                    resources.push(part.to_string());
                }
            }
        }
        
        resources
    }
    
    /// Infer output type of command
    fn infer_output_type(&self, command: &str) -> String {
        if command.contains("find") {
            "file_list".to_string()
        } else if command.contains("grep") {
            "text_lines".to_string()
        } else if command.contains("ls") {
            "file_list".to_string()
        } else if command.contains("cat") {
            "text_content".to_string()
        } else {
            "".to_string()
        }
    }
    
    /// Infer input type of command
    fn infer_input_type(&self, command: &str) -> String {
        if command.contains("xargs") {
            "file_list".to_string()
        } else if command.contains("grep") && !command.contains("-r") {
            "text_content".to_string()
        } else if command.contains("sort") || command.contains("uniq") {
            "text_lines".to_string()
        } else {
            "".to_string()
        }
    }
    
    /// Calculate overall synergy score
    fn calculate_overall_score(&self, synergies: &[CommandSynergy]) -> f32 {
        if synergies.is_empty() {
            return 0.0;
        }
        
        let total_score: f32 = synergies.iter()
            .map(|s| s.score)
            .sum();
        
        (total_score / synergies.len() as f32).min(1.0)
    }
    
    /// Generate recommendations
    fn generate_recommendations(
        &self,
        synergies: &[CommandSynergy],
        context: &SynergyContext,
    ) -> Vec<SynergyRecommendation> {
        let mut recommendations = Vec::new();
        
        // Sort synergies by score
        let mut sorted_synergies = synergies.to_vec();
        sorted_synergies.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        
        for (i, synergy) in sorted_synergies.iter().enumerate().take(5) {
            let priority = (10 - i as u8).max(1);
            
            let difficulty = match synergy.implementation.strategy {
                ImplementationStrategy::PipelineMerge => ImplementationDifficulty::Trivial,
                ImplementationStrategy::ProcessSubstitution => ImplementationDifficulty::Moderate,
                ImplementationStrategy::SharedMemory => ImplementationDifficulty::Complex,
                _ => ImplementationDifficulty::Easy,
            };
            
            recommendations.push(SynergyRecommendation {
                id: format!("rec-{}", synergy.id),
                priority,
                description: synergy.description.clone(),
                expected_improvement: synergy.benefits.performance_gain,
                difficulty,
            });
        }
        
        recommendations
    }
    
    /// Generate cache key
    fn generate_cache_key(&self, commands: &[String]) -> String {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        
        let mut hasher = DefaultHasher::new();
        commands.hash(&mut hasher);
        format!("synergy-{:x}", hasher.finish())
    }
}

#[async_trait]
impl SynergyAnalyzer for SynergyDetector {
    async fn analyze(&self, commands: &[String], context: &SynergyContext) -> Result<Vec<CommandSynergy>> {
        let result = self.detect(commands, context).await?;
        Ok(result.synergies)
    }
    
    async fn score_synergy(&self, synergy: &CommandSynergy) -> Result<f32> {
        self.scoring_engine.score(synergy)
    }
    
    async fn generate_implementation(&self, synergy: &CommandSynergy) -> Result<SynergyImplementation> {
        Ok(synergy.implementation.clone())
    }
}

impl PatternMatchers {
    fn new() -> Self {
        Self {
            pipeline_patterns: SynergyPatterns::pipeline_patterns(),
            resource_patterns: SynergyPatterns::resource_patterns(),
            custom_matchers: vec![
                Box::new(ParallelizableMatcher),
                Box::new(CacheableMatcher),
            ],
        }
    }
}

impl ScoringEngine {
    fn new() -> Self {
        Self {
            weights: ScoringWeights::default(),
            score_history: DashMap::new(),
        }
    }
    
    fn score(&self, synergy: &CommandSynergy) -> Result<f32> {
        let benefits = &synergy.benefits;
        
        let weighted_score = 
            benefits.performance_gain * self.weights.performance_weight +
            benefits.resource_savings * self.weights.resource_weight +
            benefits.complexity_reduction * self.weights.complexity_weight +
            benefits.reliability_gain * self.weights.reliability_weight;
        
        Ok(weighted_score.min(1.0))
    }
}

/// Matcher for parallelizable commands
struct ParallelizableMatcher;

impl CustomMatcher for ParallelizableMatcher {
    fn matches(&self, commands: &[String]) -> Option<MatchResult> {
        // Check for independent file operations
        let file_ops = vec!["cp", "mv", "chmod", "chown"];
        let mut indices = Vec::new();
        
        for (i, cmd) in commands.iter().enumerate() {
            if file_ops.iter().any(|op| cmd.starts_with(op)) {
                indices.push(i);
            }
        }
        
        if indices.len() > 1 {
            Some(MatchResult {
                indices,
                confidence: 0.9,
                metadata: MatchMetadata {
                    pattern_name: "Parallelizable file operations".to_string(),
                    optimization_hint: "Use GNU parallel or xargs -P".to_string(),
                    estimated_benefit: 0.6,
                },
            })
        } else {
            None
        }
    }
    
    fn synergy_type(&self) -> SynergyType {
        SynergyType::ParallelOpportunity
    }
}

/// Matcher for cacheable operations
struct CacheableMatcher;

impl CustomMatcher for CacheableMatcher {
    fn matches(&self, commands: &[String]) -> Option<MatchResult> {
        // Check for expensive operations that could be cached
        let expensive_ops = vec!["find /", "docker images", "npm list", "pip list"];
        let mut indices = Vec::new();
        
        for (i, cmd) in commands.iter().enumerate() {
            if expensive_ops.iter().any(|op| cmd.contains(op)) {
                indices.push(i);
            }
        }
        
        if !indices.is_empty() {
            Some(MatchResult {
                indices,
                confidence: 0.7,
                metadata: MatchMetadata {
                    pattern_name: "Cacheable expensive operations".to_string(),
                    optimization_hint: "Cache results for reuse".to_string(),
                    estimated_benefit: 0.5,
                },
            })
        } else {
            None
        }
    }
    
    fn synergy_type(&self) -> SynergyType {
        SynergyType::CacheReuse
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_synergy_detection() {
        let detector = SynergyDetector::new();
        
        let commands = vec![
            "find . -name '*.log'".to_string(),
            "xargs grep ERROR".to_string(),
            "sort | uniq -c".to_string(),
        ];
        
        let context = SynergyContext {
            resources: crate::synthex_bashgod::synergy::SystemResources {
                cpu_cores: 4,
                memory_mb: 8192,
                has_shm: true,
                has_fifo: true,
            },
            available_tools: vec!["find".to_string(), "grep".to_string()],
            constraints: crate::synthex_bashgod::synergy::PerformanceConstraints {
                max_time_ms: None,
                max_memory_mb: None,
                atomic_required: false,
            },
        };
        
        let result = detector.detect(&commands, &context).await.unwrap();
        
        assert!(!result.synergies.is_empty());
        assert!(result.overall_score > 0.0);
    }
}