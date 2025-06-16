//! Tensor-based memory for pattern storage and similarity matching
//! 
//! Uses Candle for GPU-accelerated tensor operations when available

use crate::synthex_bashgod::{Result, SBGError};
use crate::synthex_bashgod::memory::{
    CommandPattern, ExecutionResult, FeatureExtractor, MemoryCache,
    MemoryStats, OptimizationResult, PatternMetrics, SimilarPattern,
};
// ML dependencies are optional - using stub implementation
// To enable ML features, uncomment candle dependencies in Cargo.toml

#[cfg(feature = "ml")]
use candle_core::{Device, Tensor, DType};

#[cfg(not(feature = "ml"))]
use self::tensor_stub::{Device, Tensor, DType};
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// Stub implementations for when ML is disabled
#[cfg(not(feature = "ml"))]
mod tensor_stub {
    use serde::{Deserialize, Serialize};
    
    #[derive(Debug, Clone)]
    pub struct Device;
    
    impl Device {
        pub fn cpu() -> Self { Device }
        pub fn cuda_if_available() -> Self { Device }
    }
    
    #[derive(Debug, Clone, Copy)]
    pub enum DType {
        F32,
        F64,
        I32,
        I64,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Tensor {
        pub data: Vec<f32>,
        pub shape: Vec<usize>,
    }
    
    impl Tensor {
        pub fn zeros(shape: &[usize], _dtype: DType, _device: &Device) -> Result<Self, String> {
            let size = shape.iter().product();
            Ok(Self {
                data: vec![0.0; size],
                shape: shape.to_vec(),
            })
        }
        
        pub fn from_slice(data: &[f32], shape: &[usize], _device: &Device) -> Result<Self, String> {
            Ok(Self {
                data: data.to_vec(),
                shape: shape.to_vec(),
            })
        }
        
        pub fn to_vec1<T>(&self) -> Result<Vec<f32>, String> {
            Ok(self.data.clone())
        }
        
        pub fn cat(tensors: &[&Self], dim: usize) -> Result<Self, String> {
            if tensors.is_empty() {
                return Err("Cannot concatenate empty list".into());
            }
            
            // For simplicity, just concatenate data
            let mut all_data = Vec::new();
            for t in tensors {
                all_data.extend(&t.data);
            }
            
            // Update shape
            let mut shape = tensors[0].shape.clone();
            shape[dim] = tensors.iter().map(|t| t.shape[dim]).sum();
            
            Ok(Self {
                data: all_data,
                shape,
            })
        }
        
        pub fn t(&self) -> Result<Self, String> {
            if self.shape.len() != 2 {
                return Err("Transpose only supported for 2D tensors".into());
            }
            
            let rows = self.shape[0];
            let cols = self.shape[1];
            let mut transposed = vec![0.0; self.data.len()];
            
            for i in 0..rows {
                for j in 0..cols {
                    transposed[j * rows + i] = self.data[i * cols + j];
                }
            }
            
            Ok(Self {
                data: transposed,
                shape: vec![cols, rows],
            })
        }
        
        pub fn squeeze(&self, dim: usize) -> Result<Self, String> {
            let mut new_shape = self.shape.clone();
            if new_shape[dim] == 1 {
                new_shape.remove(dim);
            }
            
            Ok(Self {
                data: self.data.clone(),
                shape: new_shape,
            })
        }
        
        pub fn matmul(&self, other: &Self) -> Result<Self, String> {
            // Simplified matmul for 2D tensors
            if self.shape.len() != 2 || other.shape.len() != 2 {
                return Err("Only 2D matmul supported in stub".into());
            }
            
            let m = self.shape[0];
            let k = self.shape[1];
            let n = other.shape[1];
            
            if k != other.shape[0] {
                return Err("Dimension mismatch".into());
            }
            
            let mut result = vec![0.0; m * n];
            
            for i in 0..m {
                for j in 0..n {
                    for ki in 0..k {
                        result[i * n + j] += self.data[i * k + ki] * other.data[ki * n + j];
                    }
                }
            }
            
            Ok(Self {
                data: result,
                shape: vec![m, n],
            })
        }
        
        pub fn add(&self, other: &Self) -> Result<Self, String> {
            if self.shape != other.shape {
                return Err("Shape mismatch".into());
            }
            
            let data: Vec<f32> = self.data.iter()
                .zip(other.data.iter())
                .map(|(a, b)| a + b)
                .collect();
            
            Ok(Self {
                data,
                shape: self.shape.clone(),
            })
        }
        
        pub fn transpose(&self, dim0: usize, dim1: usize) -> Result<Self, String> {
            if self.shape.len() != 2 || dim0 >= 2 || dim1 >= 2 {
                return Err("Only 2D transpose supported".into());
            }
            
            let rows = self.shape[0];
            let cols = self.shape[1];
            let mut data = vec![0.0; rows * cols];
            
            for i in 0..rows {
                for j in 0..cols {
                    data[j * rows + i] = self.data[i * cols + j];
                }
            }
            
            Ok(Self {
                data,
                shape: vec![cols, rows],
            })
        }
        
        pub fn sqr(&self) -> Result<Self, String> {
            let data: Vec<f32> = self.data.iter()
                .map(|x| x * x)
                .collect();
            
            Ok(Self {
                data,
                shape: self.shape.clone(),
            })
        }
        
        pub fn sum_keepdim(&self, dim: usize) -> Result<Self, String> {
            if self.shape.len() != 2 || dim >= 2 {
                return Err("Only 2D sum_keepdim supported".into());
            }
            
            if dim == 0 {
                // Sum across rows
                let mut result = vec![0.0; self.shape[1]];
                for i in 0..self.shape[0] {
                    for j in 0..self.shape[1] {
                        result[j] += self.data[i * self.shape[1] + j];
                    }
                }
                Ok(Self {
                    data: result,
                    shape: vec![1, self.shape[1]],
                })
            } else {
                // Sum across columns
                let mut result = vec![0.0; self.shape[0]];
                for i in 0..self.shape[0] {
                    for j in 0..self.shape[1] {
                        result[i] += self.data[i * self.shape[1] + j];
                    }
                }
                Ok(Self {
                    data: result,
                    shape: vec![self.shape[0], 1],
                })
            }
        }
        
        pub fn sqrt(&self) -> Result<Self, String> {
            let data: Vec<f32> = self.data.iter()
                .map(|x| x.sqrt())
                .collect();
            
            Ok(Self {
                data,
                shape: self.shape.clone(),
            })
        }
        
        pub fn broadcast_div(&self, other: &Self) -> Result<Self, String> {
            // Simple broadcast for normalization
            if self.shape.len() != 2 || other.shape.len() != 2 {
                return Err("Only 2D broadcast_div supported".into());
            }
            
            let mut result = self.data.clone();
            
            if other.shape[0] == 1 && other.shape[1] == self.shape[1] {
                // Broadcast across rows
                for i in 0..self.shape[0] {
                    for j in 0..self.shape[1] {
                        let idx = i * self.shape[1] + j;
                        result[idx] /= other.data[j];
                    }
                }
            } else if other.shape[1] == 1 && other.shape[0] == self.shape[0] {
                // Broadcast across columns
                for i in 0..self.shape[0] {
                    for j in 0..self.shape[1] {
                        let idx = i * self.shape[1] + j;
                        result[idx] /= other.data[i];
                    }
                }
            } else {
                return Err("Unsupported broadcast shape".into());
            }
            
            Ok(Self {
                data: result,
                shape: self.shape.clone(),
            })
        }
    }
}
use tracing::{debug, info, warn};

/// Tensor-based memory storage
pub struct TensorMemory {
    /// Pattern storage
    patterns: Arc<DashMap<String, Arc<CommandPattern>>>,
    
    /// Feature tensor for all patterns
    feature_tensor: Arc<RwLock<Option<Tensor>>>,
    
    /// Pattern ID index
    pattern_index: Arc<RwLock<Vec<String>>>,
    
    /// Feature extractor
    feature_extractor: Arc<FeatureExtractor>,
    
    /// Memory cache
    cache: Arc<RwLock<MemoryCache>>,
    
    /// Device for tensor operations
    device: Device,
    
    /// Configuration
    config: TensorMemoryConfig,
}

/// Tensor memory configuration
#[derive(Debug, Clone)]
pub struct TensorMemoryConfig {
    /// Maximum patterns to store
    pub max_patterns: usize,
    
    /// Feature vector dimension
    pub feature_dim: usize,
    
    /// Cache size
    pub cache_size: usize,
    
    /// Use GPU if available
    pub use_gpu: bool,
    
    /// Similarity threshold for matches
    pub similarity_threshold: f32,
}

impl Default for TensorMemoryConfig {
    fn default() -> Self {
        Self {
            max_patterns: 100_000,
            feature_dim: 128,
            cache_size: 10_000,
            use_gpu: true,
            similarity_threshold: 0.7,
        }
    }
}

impl TensorMemory {
    /// Create a new tensor memory
    pub fn new(config: TensorMemoryConfig) -> Result<Self> {
        // Select device
        let device = if config.use_gpu {
            Device::cuda_if_available()
        } else {
            Device::cpu()
        };
        
        info!("TensorMemory initialized with device: {:?}", device);
        
        Ok(Self {
            patterns: Arc::new(DashMap::new()),
            feature_tensor: Arc::new(RwLock::new(None)),
            pattern_index: Arc::new(RwLock::new(Vec::new())),
            feature_extractor: Arc::new(FeatureExtractor::new()),
            cache: Arc::new(RwLock::new(MemoryCache::new(config.cache_size))),
            device,
            config,
        })
    }
    
    /// Store a pattern in tensor memory
    pub async fn store(&self, pattern: CommandPattern) -> Result<()> {
        let pattern_id = pattern.id.clone();
        
        // Check capacity
        if self.patterns.len() >= self.config.max_patterns {
            // Evict oldest pattern
            self.evict_oldest().await?;
        }
        
        // Store pattern
        self.patterns.insert(pattern_id.clone(), Arc::new(pattern.clone()));
        
        // Update feature tensor
        self.update_feature_tensor(pattern_id.clone(), &pattern.features).await?;
        
        // Update cache
        self.cache.write().await.insert(pattern);
        
        debug!("Stored pattern: {}", pattern_id);
        
        Ok(())
    }
    
    /// Find similar patterns using tensor operations
    pub async fn find_similar(
        &self,
        query_features: &[f32],
        threshold: f32,
    ) -> Result<Vec<SimilarPattern>> {
        // First check cache
        let cache_results = self.cache.read().await.find_similar(query_features, threshold);
        
        if !cache_results.is_empty() {
            // Convert cache results to SimilarPattern
            let mut results = Vec::new();
            for (id, similarity) in cache_results {
                if let Some(pattern) = self.patterns.get(&id) {
                    results.push(SimilarPattern {
                        pattern: pattern.as_ref().clone(),
                        similarity,
                        explanation: format!("Cache hit with {:.2}% similarity", similarity * 100.0),
                    });
                }
            }
            return Ok(results);
        }
        
        // Use tensor operations for similarity search
        let results = self.tensor_similarity_search(query_features, threshold).await?;
        
        Ok(results)
    }
    
    /// Update pattern statistics
    pub async fn update_stats(
        &self,
        pattern_id: &str,
        execution_result: &ExecutionResult,
    ) -> Result<()> {
        if let Some(mut entry) = self.patterns.get_mut(pattern_id) {
            // Get mutable reference to pattern
            let pattern = Arc::make_mut(&mut entry);
            
            // Update metrics
            let metrics = &mut pattern.metrics;
            let n = metrics.execution_count as f64;
            
            // Update moving averages
            metrics.avg_execution_time_ms = 
                (metrics.avg_execution_time_ms * n + execution_result.execution_time_ms as f64) / (n + 1.0);
            
            metrics.avg_cpu_usage = 
                ((metrics.avg_cpu_usage * n as f32) + execution_result.cpu_usage) / (n + 1.0) as f32;
            
            metrics.avg_memory_mb = 
                (((metrics.avg_memory_mb as f64 * n as f64) + execution_result.memory_mb as f64) / (n as f64 + 1.0)) as u64;
            
            // Update success rate
            let successes = (metrics.success_rate * n as f32) as u64;
            let new_successes = if execution_result.success { successes + 1 } else { successes };
            metrics.success_rate = new_successes as f32 / (n + 1.0) as f32;
            
            metrics.execution_count += 1;
            
            // Update last accessed time
            let pattern = Arc::make_mut(&mut entry);
            pattern.context.last_accessed = chrono::Utc::now();
        }
        
        Ok(())
    }
    
    /// Get memory statistics
    pub async fn get_stats(&self) -> MemoryStats {
        let tensor_memory_mb = self.estimate_memory_usage().await;
        
        MemoryStats {
            tensor_memory_mb,
            graph_memory_mb: 0, // Not used in tensor memory
            pattern_count: self.patterns.len() as u64,
            graph_nodes: 0,
            graph_edges: 0,
            cache_hit_rate: 0.0, // TODO: Track cache hits
        }
    }
    
    /// Optimize memory by evicting low-value patterns
    pub async fn optimize(&self) -> Result<OptimizationResult> {
        let start = std::time::Instant::now();
        let initial_count = self.patterns.len();
        
        // Calculate pattern scores
        let mut pattern_scores: Vec<(String, f64)> = Vec::new();
        
        for entry in self.patterns.iter() {
            let pattern = entry.value();
            let score = self.calculate_pattern_value(pattern);
            pattern_scores.push((entry.key().clone(), score));
        }
        
        // Sort by score (lowest first for eviction)
        pattern_scores.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        
        // Evict bottom 10% of patterns
        let evict_count = (initial_count / 10).max(1);
        let mut evicted = 0;
        
        for (pattern_id, _) in pattern_scores.iter().take(evict_count) {
            self.patterns.remove(pattern_id);
            evicted += 1;
        }
        
        // Rebuild feature tensor
        self.rebuild_feature_tensor().await?;
        
        // Clear cache to force refresh
        self.cache.write().await.clear();
        
        let memory_freed_mb = (evicted * 1024) as u64; // Rough estimate
        
        Ok(OptimizationResult {
            memory_freed_mb,
            patterns_evicted: evicted as u64,
            nodes_pruned: 0,
            optimization_time_ms: start.elapsed().as_millis() as u64,
        })
    }
    
    /// Update feature tensor with new pattern
    async fn update_feature_tensor(
        &self,
        pattern_id: String,
        features: &[f32],
    ) -> Result<()> {
        let mut tensor_guard = self.feature_tensor.write().await;
        let mut index_guard = self.pattern_index.write().await;
        
        // Add to index
        index_guard.push(pattern_id);
        
        // Create feature tensor from slice
        let new_features = Tensor::from_slice(
            features,
            &[1, features.len()],
            &self.device,
        ).map_err(|e| SBGError::MemoryError(e.to_string()))?;
        
        // Update or create tensor
        *tensor_guard = match tensor_guard.take() {
            Some(existing) => {
                // Concatenate with existing tensor
                Some(Tensor::cat(&[&existing, &new_features], 0)
                    .map_err(|e| SBGError::MemoryError(e.to_string()))?)
            }
            None => Some(new_features),
        };
        
        Ok(())
    }
    
    /// Perform tensor-based similarity search
    async fn tensor_similarity_search(
        &self,
        query_features: &[f32],
        threshold: f32,
    ) -> Result<Vec<SimilarPattern>> {
        let tensor_guard = self.feature_tensor.read().await;
        let index_guard = self.pattern_index.read().await;
        
        let feature_tensor = match tensor_guard.as_ref() {
            Some(t) => t,
            None => return Ok(Vec::new()),
        };
        
        // Create query tensor
        let query_tensor = Tensor::from_slice(
            query_features,
            &[1, query_features.len()],
            &self.device,
        ).map_err(|e| SBGError::MemoryError(e.to_string()))?;
        
        // Compute cosine similarities
        let similarities = self.compute_cosine_similarity(&query_tensor, feature_tensor)?;
        
        // Convert to Vec for processing
        let sim_vec: Vec<f32> = similarities.to_vec1::<Vec<f32>>()
            .map_err(|e| SBGError::MemoryError(e.to_string()))?;
        
        // Find patterns above threshold
        let mut results = Vec::new();
        
        for (idx, &similarity) in sim_vec.iter().enumerate() {
            if similarity >= threshold {
                if let Some(pattern_id) = index_guard.get(idx) {
                    if let Some(pattern) = self.patterns.get(pattern_id) {
                        results.push(SimilarPattern {
                            pattern: pattern.as_ref().clone(),
                            similarity,
                            explanation: format!(
                                "Tensor similarity: {:.2}% match",
                                similarity * 100.0
                            ),
                        });
                    }
                }
            }
        }
        
        // Sort by similarity descending
        results.sort_by(|a, b| b.similarity.partial_cmp(&a.similarity).unwrap_or(std::cmp::Ordering::Equal));
        
        Ok(results)
    }
    
    /// Compute cosine similarity between query and all patterns
    fn compute_cosine_similarity(
        &self,
        query: &Tensor,
        patterns: &Tensor,
    ) -> Result<Tensor> {
        // Normalize query
        let query_norm = query.sqr()
            .map_err(|e| SBGError::MemoryError(e.to_string()))?
            .sum_keepdim(1)
            .map_err(|e| SBGError::MemoryError(e.to_string()))?
            .sqrt()
            .map_err(|e| SBGError::MemoryError(e.to_string()))?;
        
        let query_normalized = query.broadcast_div(&query_norm)
            .map_err(|e| SBGError::MemoryError(e.to_string()))?;
        
        // Normalize patterns
        let patterns_norm = patterns.sqr()
            .map_err(|e| SBGError::MemoryError(e.to_string()))?
            .sum_keepdim(1)
            .map_err(|e| SBGError::MemoryError(e.to_string()))?
            .sqrt()
            .map_err(|e| SBGError::MemoryError(e.to_string()))?;
        
        let patterns_normalized = patterns.broadcast_div(&patterns_norm)
            .map_err(|e| SBGError::MemoryError(e.to_string()))?;
        
        // Compute dot product
        let similarities = patterns_normalized
            .matmul(&query_normalized.t().map_err(|e| SBGError::MemoryError(e.to_string()))?)
            .map_err(|e| SBGError::MemoryError(e.to_string()))?
            .squeeze(1)
            .map_err(|e| SBGError::MemoryError(e.to_string()))?;
        
        Ok(similarities)
    }
    
    /// Calculate pattern value for eviction decisions
    fn calculate_pattern_value(&self, pattern: &CommandPattern) -> f64 {
        let metrics = &pattern.metrics;
        let age_days = (chrono::Utc::now() - pattern.context.last_accessed).num_days() as f64;
        
        // Value = success_rate * log(execution_count + 1) / (age_days + 1)
        let frequency_score = (metrics.execution_count as f64 + 1.0).ln();
        let recency_score = 1.0 / (age_days + 1.0);
        let quality_score = metrics.success_rate as f64;
        
        quality_score * frequency_score * recency_score
    }
    
    /// Evict oldest pattern
    async fn evict_oldest(&self) -> Result<()> {
        let mut oldest_id = None;
        let mut oldest_time = chrono::Utc::now();
        
        for entry in self.patterns.iter() {
            if entry.value().context.last_accessed < oldest_time {
                oldest_time = entry.value().context.last_accessed;
                oldest_id = Some(entry.key().clone());
            }
        }
        
        if let Some(id) = oldest_id {
            self.patterns.remove(&id);
            
            // Remove from index
            let mut index_guard = self.pattern_index.write().await;
            index_guard.retain(|pattern_id| pattern_id != &id);
            
            // Rebuild tensor
            self.rebuild_feature_tensor().await?;
        }
        
        Ok(())
    }
    
    /// Rebuild feature tensor from scratch
    async fn rebuild_feature_tensor(&self) -> Result<()> {
        let mut tensor_guard = self.feature_tensor.write().await;
        let mut index_guard = self.pattern_index.write().await;
        
        // Clear current state
        *tensor_guard = None;
        index_guard.clear();
        
        // Rebuild from patterns
        let mut all_features = Vec::new();
        
        for entry in self.patterns.iter() {
            let pattern = entry.value();
            index_guard.push(pattern.id.clone());
            all_features.extend_from_slice(&pattern.features);
        }
        
        if !all_features.is_empty() {
            let num_patterns = index_guard.len();
            let feature_dim = self.config.feature_dim;
            
            *tensor_guard = Some(Tensor::from_slice(
                &all_features,
                &[num_patterns, feature_dim],
                &self.device,
            ).map_err(|e| SBGError::MemoryError(e.to_string()))?);
        }
        
        Ok(())
    }
    
    /// Estimate memory usage in MB
    async fn estimate_memory_usage(&self) -> u64 {
        let pattern_count = self.patterns.len() as u64;
        let feature_size = (self.config.feature_dim * 4) as u64; // f32 = 4 bytes
        let pattern_overhead = 1024; // Rough estimate for metadata
        
        (pattern_count * (feature_size + pattern_overhead)) / (1024 * 1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synthex_bashgod::memory::PatternContext;
    
    #[tokio::test]
    async fn test_tensor_memory_store_and_retrieve() {
        let config = TensorMemoryConfig {
            use_gpu: false, // Use CPU for tests
            ..Default::default()
        };
        
        let memory = TensorMemory::new(config).unwrap();
        
        // Create test pattern
        let pattern = CommandPattern {
            id: "test-1".to_string(),
            commands: vec!["ls -la".to_string()],
            features: vec![0.5; 128],
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
        
        // Store pattern
        memory.store(pattern.clone()).await.unwrap();
        
        // Find similar patterns
        let results = memory.find_similar(&vec![0.5; 128], 0.9).await.unwrap();
        
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pattern.id, "test-1");
        assert!(results[0].similarity > 0.99);
    }
    
    #[tokio::test]
    async fn test_pattern_statistics_update() {
        let config = TensorMemoryConfig {
            use_gpu: false,
            ..Default::default()
        };
        
        let memory = TensorMemory::new(config).unwrap();
        
        // Store initial pattern
        let pattern = CommandPattern {
            id: "stats-test".to_string(),
            commands: vec!["echo test".to_string()],
            features: vec![0.3; 128],
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
        
        memory.store(pattern).await.unwrap();
        
        // Update statistics
        let execution_result = ExecutionResult {
            success: true,
            execution_time_ms: 200,
            cpu_usage: 0.2,
            memory_mb: 20,
            errors: vec![],
        };
        
        memory.update_stats("stats-test", &execution_result).await.unwrap();
        
        // Verify update
        let updated = memory.patterns.get("stats-test").unwrap();
        assert_eq!(updated.metrics.execution_count, 2);
        assert_eq!(updated.metrics.avg_execution_time_ms, 150.0);
    }
}