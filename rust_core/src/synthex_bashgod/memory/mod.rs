//! Hybrid Memory System for SYNTHEX-BashGod
//! 
//! Combines tensor-based pattern memory with graph-based dependency tracking
//! for optimal command chain learning and optimization.

use std::sync::Arc;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub mod tensor;
pub mod graph;
pub mod hybrid;

pub use tensor::TensorMemory;
pub use graph::GraphMemory;
pub use hybrid::HybridMemory;

use crate::synthex_bashgod::{Result, SBGError};

/// Memory system trait for SYNTHEX-BashGod
#[async_trait]
pub trait MemorySystem: Send + Sync {
    /// Store a command pattern
    async fn store_pattern(&self, pattern: CommandPattern) -> Result<()>;
    
    /// Retrieve similar patterns
    async fn find_similar(&self, query: &CommandPattern, threshold: f32) -> Result<Vec<SimilarPattern>>;
    
    /// Update pattern statistics
    async fn update_stats(&self, pattern_id: &str, execution_result: &ExecutionResult) -> Result<()>;
    
    /// Get memory usage statistics
    async fn get_memory_stats(&self) -> Result<MemoryStats>;
    
    /// Perform memory optimization
    async fn optimize_memory(&self) -> Result<OptimizationResult>;
}

/// Command pattern for memory storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandPattern {
    /// Unique pattern ID
    pub id: String,
    
    /// Command sequence
    pub commands: Vec<String>,
    
    /// Feature vector for similarity matching
    pub features: Vec<f32>,
    
    /// Dependencies between commands
    pub dependencies: Vec<(usize, usize)>,
    
    /// Execution context
    pub context: PatternContext,
    
    /// Performance metrics
    pub metrics: PatternMetrics,
}

/// Pattern context information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternContext {
    /// Environment where pattern was executed
    pub environment: String,
    
    /// User who created the pattern
    pub user: String,
    
    /// Tags for categorization
    pub tags: Vec<String>,
    
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    
    /// Last accessed timestamp
    pub last_accessed: chrono::DateTime<chrono::Utc>,
}

/// Pattern performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMetrics {
    /// Average execution time
    pub avg_execution_time_ms: f64,
    
    /// Success rate
    pub success_rate: f32,
    
    /// Number of executions
    pub execution_count: u64,
    
    /// Resource usage
    pub avg_cpu_usage: f32,
    pub avg_memory_mb: u64,
}

/// Similar pattern match
#[derive(Debug, Clone)]
pub struct SimilarPattern {
    /// The pattern
    pub pattern: CommandPattern,
    
    /// Similarity score (0.0 to 1.0)
    pub similarity: f32,
    
    /// Match explanation
    pub explanation: String,
}

/// Execution result for pattern update
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Whether execution succeeded
    pub success: bool,
    
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
    
    /// Resource usage
    pub cpu_usage: f32,
    pub memory_mb: u64,
    
    /// Any errors encountered
    pub errors: Vec<String>,
}

/// Memory statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryStats {
    /// Tensor memory usage
    pub tensor_memory_mb: u64,
    
    /// Graph memory usage
    pub graph_memory_mb: u64,
    
    /// Total patterns stored
    pub pattern_count: u64,
    
    /// Total nodes in graph
    pub graph_nodes: u64,
    
    /// Total edges in graph
    pub graph_edges: u64,
    
    /// Cache hit rate
    pub cache_hit_rate: f32,
}

/// Memory optimization result
#[derive(Debug, Clone)]
pub struct OptimizationResult {
    /// Memory freed in MB
    pub memory_freed_mb: u64,
    
    /// Patterns evicted
    pub patterns_evicted: u64,
    
    /// Nodes pruned
    pub nodes_pruned: u64,
    
    /// Time taken for optimization
    pub optimization_time_ms: u64,
}

/// Feature extractor for command patterns
pub struct FeatureExtractor {
    /// Vocabulary for command tokens
    vocabulary: Vec<String>,
    
    /// IDF weights for terms
    idf_weights: Vec<f32>,
}

impl FeatureExtractor {
    /// Create a new feature extractor
    pub fn new() -> Self {
        // Initialize with common bash command vocabulary
        let vocabulary: Vec<String> = vec![
            "ls", "cd", "grep", "find", "cat", "echo", "sed", "awk",
            "docker", "kubectl", "git", "make", "npm", "cargo", "python",
            "curl", "wget", "tar", "gzip", "chmod", "chown", "sudo",
            "|", "&&", "||", ">", ">>", "<", "2>", "2>&1",
        ].into_iter().map(String::from).collect();
        
        let idf_weights = vec![1.0; vocabulary.len()]; // Simplified
        
        Self {
            vocabulary,
            idf_weights,
        }
    }
    
    /// Extract features from command sequence
    pub fn extract_features(&self, commands: &[String]) -> Vec<f32> {
        let mut features = vec![0.0; self.vocabulary.len()];
        
        for command in commands {
            for (i, term) in self.vocabulary.iter().enumerate() {
                if command.contains(term) {
                    features[i] += self.idf_weights[i];
                }
            }
        }
        
        // Normalize features
        let norm = features.iter().map(|f| f * f).sum::<f32>().sqrt();
        if norm > 0.0 {
            for f in &mut features {
                *f /= norm;
            }
        }
        
        features
    }
    
    /// Calculate similarity between two feature vectors
    pub fn calculate_similarity(features1: &[f32], features2: &[f32]) -> f32 {
        if features1.len() != features2.len() {
            return 0.0;
        }
        
        // Cosine similarity
        let dot_product: f32 = features1.iter()
            .zip(features2.iter())
            .map(|(a, b)| a * b)
            .sum();
        
        let norm1: f32 = features1.iter().map(|f| f * f).sum::<f32>().sqrt();
        let norm2: f32 = features2.iter().map(|f| f * f).sum::<f32>().sqrt();
        
        if norm1 > 0.0 && norm2 > 0.0 {
            dot_product / (norm1 * norm2)
        } else {
            0.0
        }
    }
}

/// Memory cache for fast lookups
pub struct MemoryCache {
    /// LRU cache for recent patterns
    lru_cache: lru::LruCache<String, Arc<CommandPattern>>,
    
    /// Feature index for similarity search
    feature_index: dashmap::DashMap<String, Vec<f32>>,
}

impl MemoryCache {
    /// Create a new memory cache
    pub fn new(capacity: usize) -> Self {
        Self {
            lru_cache: lru::LruCache::new(capacity.try_into().unwrap()),
            feature_index: dashmap::DashMap::new(),
        }
    }
    
    /// Add pattern to cache
    pub fn insert(&mut self, pattern: CommandPattern) {
        let id = pattern.id.clone();
        let features = pattern.features.clone();
        
        self.lru_cache.put(id.clone(), Arc::new(pattern));
        self.feature_index.insert(id, features);
    }
    
    /// Get pattern from cache
    pub fn get(&mut self, id: &str) -> Option<Arc<CommandPattern>> {
        self.lru_cache.get(id).cloned()
    }
    
    /// Find similar patterns in cache
    pub fn find_similar(&self, query_features: &[f32], threshold: f32) -> Vec<(String, f32)> {
        let mut results = Vec::new();
        
        for entry in self.feature_index.iter() {
            let similarity = FeatureExtractor::calculate_similarity(query_features, entry.value());
            if similarity >= threshold {
                results.push((entry.key().clone(), similarity));
            }
        }
        
        // Sort by similarity descending
        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        
        results
    }
    
    /// Clear cache
    pub fn clear(&mut self) {
        self.lru_cache.clear();
        self.feature_index.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_feature_extraction() {
        let extractor = FeatureExtractor::new();
        
        let commands = vec![
            "ls -la".to_string(),
            "grep error /var/log/syslog".to_string(),
            "docker ps -a".to_string(),
        ];
        
        let features = extractor.extract_features(&commands);
        
        // Should have non-zero features for ls, grep, docker
        assert!(features.iter().any(|&f| f > 0.0));
        
        // Features should be normalized
        let norm: f32 = features.iter().map(|f| f * f).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 0.001);
    }
    
    #[test]
    fn test_similarity_calculation() {
        let features1 = vec![0.5, 0.5, 0.5, 0.5];
        let features2 = vec![0.5, 0.5, 0.5, 0.5];
        let features3 = vec![1.0, 0.0, 0.0, 0.0];
        
        // Identical vectors should have similarity 1.0
        let sim1 = FeatureExtractor::calculate_similarity(&features1, &features2);
        assert!((sim1 - 1.0).abs() < 0.001);
        
        // Orthogonal vectors should have similarity close to 0
        let sim2 = FeatureExtractor::calculate_similarity(&features2, &features3);
        assert!(sim2 < 0.6);
    }
    
    #[test]
    fn test_memory_cache() {
        let mut cache = MemoryCache::new(10);
        
        let pattern = CommandPattern {
            id: "test-pattern".to_string(),
            commands: vec!["echo test".to_string()],
            features: vec![0.5, 0.5, 0.0, 0.0],
            dependencies: vec![],
            context: PatternContext {
                environment: "test".to_string(),
                user: "test".to_string(),
                tags: vec![],
                created_at: chrono::Utc::now(),
                last_accessed: chrono::Utc::now(),
            },
            metrics: PatternMetrics {
                avg_execution_time_ms: 100.0,
                success_rate: 1.0,
                execution_count: 1,
                avg_cpu_usage: 0.1,
                avg_memory_mb: 10,
            },
        };
        
        cache.insert(pattern.clone());
        
        // Should be able to retrieve pattern
        assert!(cache.get("test-pattern").is_some());
        
        // Should find similar patterns
        let similar = cache.find_similar(&vec![0.6, 0.4, 0.0, 0.0], 0.8);
        assert_eq!(similar.len(), 1);
        assert_eq!(similar[0].0, "test-pattern");
    }
}