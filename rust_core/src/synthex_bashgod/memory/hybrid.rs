//! Hybrid memory system combining tensor and graph memory
//! 
//! Provides the best of both worlds: fast similarity matching with tensors
//! and relationship tracking with graphs.

use crate::synthex_bashgod::{Result, SBGError};
use crate::synthex_bashgod::memory::{
    CommandPattern, ExecutionResult, MemoryStats, MemorySystem,
    OptimizationResult, SimilarPattern, TensorMemory, GraphMemory,
};
use crate::synthex_bashgod::memory::tensor::TensorMemoryConfig;
use crate::synthex_bashgod::memory::graph::GraphMemoryConfig;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Hybrid memory system configuration
#[derive(Debug, Clone)]
pub struct HybridMemoryConfig {
    /// Tensor memory configuration
    pub tensor_config: TensorMemoryConfig,
    
    /// Graph memory configuration
    pub graph_config: GraphMemoryConfig,
    
    /// Weight for tensor similarity (0.0 to 1.0)
    pub tensor_weight: f32,
    
    /// Weight for graph similarity (0.0 to 1.0)
    pub graph_weight: f32,
    
    /// Enable cross-memory optimization
    pub enable_cross_optimization: bool,
}

impl Default for HybridMemoryConfig {
    fn default() -> Self {
        Self {
            tensor_config: TensorMemoryConfig::default(),
            graph_config: GraphMemoryConfig::default(),
            tensor_weight: 0.6,
            graph_weight: 0.4,
            enable_cross_optimization: true,
        }
    }
}

/// Hybrid memory system implementation
pub struct HybridMemory {
    /// Tensor memory for pattern matching
    tensor_memory: Arc<TensorMemory>,
    
    /// Graph memory for relationship tracking
    graph_memory: Arc<GraphMemory>,
    
    /// Configuration
    config: HybridMemoryConfig,
    
    /// Statistics
    stats: Arc<RwLock<HybridStats>>,
}

#[derive(Debug, Default)]
struct HybridStats {
    /// Total patterns stored
    pattern_count: u64,
    
    /// Tensor hits
    tensor_hits: u64,
    
    /// Graph hits
    graph_hits: u64,
    
    /// Combined hits
    combined_hits: u64,
}

impl HybridMemory {
    /// Create a new hybrid memory system
    pub fn new(config: HybridMemoryConfig) -> Result<Self> {
        let tensor_memory = Arc::new(TensorMemory::new(config.tensor_config.clone())?);
        let graph_memory = Arc::new(GraphMemory::new(config.graph_config.clone()));
        
        Ok(Self {
            tensor_memory,
            graph_memory,
            config,
            stats: Arc::new(RwLock::new(HybridStats::default())),
        })
    }
    
    /// Find similar patterns using both tensor and graph methods
    pub async fn find_similar_hybrid(
        &self,
        query: &CommandPattern,
        threshold: f32,
    ) -> Result<Vec<SimilarPattern>> {
        // Get tensor-based similarities
        let tensor_results = self.tensor_memory
            .find_similar(&query.features, threshold)
            .await?;
        
        // Get graph-based related patterns
        let graph_results = self.graph_memory
            .find_related(&query.id, 3)
            .await?;
        
        // Check if we have results before combining
        let has_tensor_results = !tensor_results.is_empty();
        let has_graph_results = !graph_results.is_empty();
        
        // Combine results
        let combined = self.combine_results(tensor_results, graph_results).await?;
        
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            if has_tensor_results {
                stats.tensor_hits += 1;
            }
            if has_graph_results {
                stats.graph_hits += 1;
            }
            if !combined.is_empty() {
                stats.combined_hits += 1;
            }
        }
        
        Ok(combined)
    }
    
    /// Combine tensor and graph results
    async fn combine_results(
        &self,
        tensor_results: Vec<SimilarPattern>,
        graph_results: Vec<(String, f32)>,
    ) -> Result<Vec<SimilarPattern>> {
        let mut combined_scores: std::collections::HashMap<String, (f32, String)> = 
            std::collections::HashMap::new();
        
        // Add tensor results
        for result in tensor_results {
            let score = result.similarity * self.config.tensor_weight;
            combined_scores.insert(
                result.pattern.id.clone(),
                (score, result.explanation),
            );
        }
        
        // Add/update with graph results
        for (pattern_id, graph_score) in graph_results {
            let weighted_score = graph_score * self.config.graph_weight;
            
            combined_scores.entry(pattern_id.clone())
                .and_modify(|(score, explanation)| {
                    *score += weighted_score;
                    *explanation = format!(
                        "{} + Graph relationship: {:.2}%",
                        explanation,
                        graph_score * 100.0
                    );
                })
                .or_insert((
                    weighted_score,
                    format!("Graph relationship: {:.2}%", graph_score * 100.0),
                ));
        }
        
        // Convert to SimilarPattern and sort
        let mut results: Vec<SimilarPattern> = Vec::new();
        
        for (pattern_id, (score, explanation)) in combined_scores {
            // Retrieve pattern from tensor memory
            if let Ok(patterns) = self.tensor_memory.find_similar(&[], 0.0).await {
                if let Some(pattern) = patterns.into_iter()
                    .find(|p| p.pattern.id == pattern_id) {
                    results.push(SimilarPattern {
                        pattern: pattern.pattern,
                        similarity: score / (self.config.tensor_weight + self.config.graph_weight),
                        explanation,
                    });
                }
            }
        }
        
        results.sort_by(|a, b| b.similarity.partial_cmp(&a.similarity).unwrap_or(std::cmp::Ordering::Equal));
        
        Ok(results)
    }
    
    /// Optimize both memory systems
    pub async fn optimize_all(&self) -> Result<OptimizationResult> {
        let tensor_result = self.tensor_memory.optimize().await?;
        let graph_result = self.graph_memory.optimize().await?;
        
        // Cross-optimization: remove patterns from tensor that have no graph connections
        let cross_optimized = if self.config.enable_cross_optimization {
            self.cross_optimize().await?
        } else {
            0
        };
        
        Ok(OptimizationResult {
            memory_freed_mb: tensor_result.memory_freed_mb + graph_result.memory_freed_mb,
            patterns_evicted: tensor_result.patterns_evicted + cross_optimized,
            nodes_pruned: graph_result.nodes_pruned,
            optimization_time_ms: tensor_result.optimization_time_ms + graph_result.optimization_time_ms,
        })
    }
    
    /// Cross-optimize between tensor and graph memory
    async fn cross_optimize(&self) -> Result<u64> {
        // This would identify patterns that exist in tensor memory
        // but have no meaningful connections in graph memory
        // For now, return 0 as placeholder
        Ok(0)
    }
    
    /// Get combined memory statistics
    pub async fn get_combined_stats(&self) -> MemoryStats {
        let tensor_stats = self.tensor_memory.get_stats().await;
        let (patterns, nodes, edges) = self.graph_memory.get_stats().await;
        
        let stats = self.stats.read().await;
        let total_queries = stats.tensor_hits + stats.graph_hits;
        let cache_hit_rate = if total_queries > 0 {
            stats.combined_hits as f32 / total_queries as f32
        } else {
            0.0
        };
        
        MemoryStats {
            tensor_memory_mb: tensor_stats.tensor_memory_mb,
            graph_memory_mb: (nodes * 100 + edges * 50) / (1024 * 1024), // Rough estimate
            pattern_count: patterns,
            graph_nodes: nodes,
            graph_edges: edges,
            cache_hit_rate,
        }
    }
}

#[async_trait]
impl MemorySystem for HybridMemory {
    async fn store_pattern(&self, pattern: CommandPattern) -> Result<()> {
        // Store in both systems
        self.tensor_memory.store(pattern.clone()).await?;
        self.graph_memory.add_pattern(&pattern).await?;
        
        // Update stats
        self.stats.write().await.pattern_count += 1;
        
        debug!("Stored pattern {} in hybrid memory", pattern.id);
        
        Ok(())
    }
    
    async fn find_similar(
        &self,
        query: &CommandPattern,
        threshold: f32,
    ) -> Result<Vec<SimilarPattern>> {
        self.find_similar_hybrid(query, threshold).await
    }
    
    async fn update_stats(
        &self,
        pattern_id: &str,
        execution_result: &ExecutionResult,
    ) -> Result<()> {
        // Update in tensor memory
        self.tensor_memory.update_stats(pattern_id, execution_result).await?;
        
        // Update graph edges if we have command sequence info
        // This is simplified - in practice we'd track actual command transitions
        
        Ok(())
    }
    
    async fn get_memory_stats(&self) -> Result<MemoryStats> {
        Ok(self.get_combined_stats().await)
    }
    
    async fn optimize_memory(&self) -> Result<OptimizationResult> {
        self.optimize_all().await
    }
}

/// Builder for hybrid memory system
pub struct HybridMemoryBuilder {
    config: HybridMemoryConfig,
}

impl HybridMemoryBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            config: HybridMemoryConfig::default(),
        }
    }
    
    /// Set tensor weight
    pub fn tensor_weight(mut self, weight: f32) -> Self {
        self.config.tensor_weight = weight.clamp(0.0, 1.0);
        self
    }
    
    /// Set graph weight
    pub fn graph_weight(mut self, weight: f32) -> Self {
        self.config.graph_weight = weight.clamp(0.0, 1.0);
        self
    }
    
    /// Set max patterns
    pub fn max_patterns(mut self, max: usize) -> Self {
        self.config.tensor_config.max_patterns = max;
        self
    }
    
    /// Set max graph nodes
    pub fn max_graph_nodes(mut self, max: usize) -> Self {
        self.config.graph_config.max_nodes = max;
        self
    }
    
    /// Enable GPU acceleration
    pub fn use_gpu(mut self, use_gpu: bool) -> Self {
        self.config.tensor_config.use_gpu = use_gpu;
        self
    }
    
    /// Enable cross-optimization
    pub fn enable_cross_optimization(mut self, enable: bool) -> Self {
        self.config.enable_cross_optimization = enable;
        self
    }
    
    /// Build the hybrid memory system
    pub fn build(self) -> Result<HybridMemory> {
        // Normalize weights
        let total_weight = self.config.tensor_weight + self.config.graph_weight;
        if total_weight > 0.0 {
            let mut config = self.config;
            config.tensor_weight /= total_weight;
            config.graph_weight /= total_weight;
            HybridMemory::new(config)
        } else {
            Err(SBGError::MemoryError("Weights must sum to > 0".to_string()))
        }
    }
}

impl Default for HybridMemoryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synthex_bashgod::memory::{PatternContext, PatternMetrics};
    
    #[tokio::test]
    async fn test_hybrid_memory_storage() {
        let memory = HybridMemoryBuilder::new()
            .tensor_weight(0.5)
            .graph_weight(0.5)
            .use_gpu(false)
            .build()
            .unwrap();
        
        let pattern = CommandPattern {
            id: "hybrid-test".to_string(),
            commands: vec!["echo hybrid".to_string()],
            features: vec![0.5; 128],
            dependencies: vec![],
            context: PatternContext {
                environment: "test".to_string(),
                user: "test".to_string(),
                tags: vec!["hybrid".to_string()],
                created_at: chrono::Utc::now(),
                last_accessed: chrono::Utc::now(),
            },
            metrics: PatternMetrics {
                avg_execution_time_ms: 50.0,
                success_rate: 1.0,
                execution_count: 1,
                avg_cpu_usage: 0.05,
                avg_memory_mb: 5,
            },
        };
        
        // Store pattern
        memory.store_pattern(pattern.clone()).await.unwrap();
        
        // Find similar
        let results = memory.find_similar(&pattern, 0.8).await.unwrap();
        
        assert!(!results.is_empty());
        assert_eq!(results[0].pattern.id, "hybrid-test");
    }
    
    #[tokio::test]
    async fn test_hybrid_memory_stats() {
        let memory = HybridMemoryBuilder::new()
            .max_patterns(1000)
            .max_graph_nodes(5000)
            .build()
            .unwrap();
        
        // Add some patterns
        for i in 0..5 {
            let pattern = CommandPattern {
                id: format!("pattern-{}", i),
                commands: vec![format!("echo {}", i)],
                features: vec![i as f32 / 10.0; 128],
                dependencies: vec![],
                context: PatternContext {
                    environment: "test".to_string(),
                    user: "test".to_string(),
                    tags: vec![],
                    created_at: chrono::Utc::now(),
                    last_accessed: chrono::Utc::now(),
                },
                metrics: PatternMetrics::default(),
            };
            
            memory.store_pattern(pattern).await.unwrap();
        }
        
        // Get stats
        let stats = memory.get_memory_stats().await.unwrap();
        
        assert_eq!(stats.pattern_count, 5);
        assert!(stats.graph_nodes >= 5); // At least one node per pattern
    }
    
    #[tokio::test]
    async fn test_memory_optimization() {
        let memory = HybridMemoryBuilder::new()
            .enable_cross_optimization(true)
            .build()
            .unwrap();
        
        // Add patterns
        for i in 0..10 {
            let pattern = CommandPattern {
                id: format!("opt-pattern-{}", i),
                commands: vec![format!("echo {}", i)],
                features: vec![0.1 * i as f32; 128],
                dependencies: vec![],
                context: PatternContext {
                    environment: "test".to_string(),
                    user: "test".to_string(),
                    tags: vec![],
                    created_at: chrono::Utc::now() - chrono::Duration::days(i as i64),
                    last_accessed: chrono::Utc::now() - chrono::Duration::days(i as i64),
                },
                metrics: PatternMetrics {
                    execution_count: (10 - i) as u64,
                    ..Default::default()
                },
            };
            
            memory.store_pattern(pattern).await.unwrap();
        }
        
        // Optimize
        let result = memory.optimize_memory().await.unwrap();
        
        // Should have freed some memory
        assert!(result.memory_freed_mb > 0 || result.patterns_evicted > 0 || result.nodes_pruned > 0);
    }
}