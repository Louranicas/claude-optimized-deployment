// ============================================================================
// Tensor-based Pattern Recognition Memory
// ============================================================================
// Stores command execution patterns as feature vectors and implements
// similarity search using cosine distance for efficient pattern matching.
// ============================================================================

use super::*;
use nalgebra::{DMatrix, DVector};
use std::collections::HashMap;
use parking_lot::RwLock;
use lru::LruCache;
use std::num::NonZeroUsize;

/// Feature extraction configuration
#[derive(Debug, Clone)]
pub struct FeatureConfig {
    /// Dimensionality of command embeddings
    pub command_embedding_dim: usize,
    /// Dimensionality of argument embeddings
    pub arg_embedding_dim: usize,
    /// Dimensionality of environment embeddings
    pub env_embedding_dim: usize,
    /// Total feature vector dimension
    pub total_dimensions: usize,
}

impl Default for FeatureConfig {
    fn default() -> Self {
        Self {
            command_embedding_dim: 64,
            arg_embedding_dim: 32,
            env_embedding_dim: 16,
            total_dimensions: 128, // Includes resource usage features
        }
    }
}

/// Tensor memory for pattern storage and retrieval
pub struct TensorMemory {
    /// Feature configuration
    config: FeatureConfig,
    
    /// Pattern storage (pattern_id -> feature vector)
    patterns: Arc<RwLock<HashMap<String, DVector<f32>>>>,
    
    /// Pattern metadata storage
    metadata: Arc<RwLock<HashMap<String, CommandPattern>>>,
    
    /// LRU cache for frequently accessed patterns
    cache: Arc<RwLock<LruCache<String, (DVector<f32>, CommandPattern)>>>,
    
    /// Feature matrix for batch operations
    feature_matrix: Arc<RwLock<Option<DMatrix<f32>>>>,
    
    /// Pattern ID to matrix index mapping
    id_to_index: Arc<RwLock<HashMap<String, usize>>>,
    
    /// Memory usage in bytes
    memory_used: Arc<RwLock<usize>>,
}

impl TensorMemory {
    /// Create a new tensor memory instance
    pub fn new(cache_size: usize) -> Self {
        let cache_size = NonZeroUsize::new(cache_size).unwrap_or(NonZeroUsize::new(1000).unwrap());
        
        Self {
            config: FeatureConfig::default(),
            patterns: Arc::new(RwLock::new(HashMap::new())),
            metadata: Arc::new(RwLock::new(HashMap::new())),
            cache: Arc::new(RwLock::new(LruCache::new(cache_size))),
            feature_matrix: Arc::new(RwLock::new(None)),
            id_to_index: Arc::new(RwLock::new(HashMap::new())),
            memory_used: Arc::new(RwLock::new(0)),
        }
    }
    
    /// Extract features from a command pattern
    pub fn extract_features(&self, pattern: &CommandPattern) -> DVector<f32> {
        let mut features = DVector::zeros(self.config.total_dimensions);
        let mut offset = 0;
        
        // Command embedding (simple hash-based for now)
        let command_hash = self.hash_string(&pattern.command);
        for i in 0..self.config.command_embedding_dim {
            features[offset + i] = ((command_hash >> i) & 1) as f32;
        }
        offset += self.config.command_embedding_dim;
        
        // Argument embeddings
        for (i, arg) in pattern.arguments.iter().enumerate() {
            if i >= self.config.arg_embedding_dim / 8 {
                break;
            }
            let arg_hash = self.hash_string(arg);
            for j in 0..8 {
                let idx = offset + i * 8 + j;
                if idx < offset + self.config.arg_embedding_dim {
                    features[idx] = ((arg_hash >> j) & 1) as f32;
                }
            }
        }
        offset += self.config.arg_embedding_dim;
        
        // Environment embeddings
        for (i, (key, value)) in pattern.environment.iter().enumerate() {
            if i >= self.config.env_embedding_dim / 2 {
                break;
            }
            let env_hash = self.hash_string(&format!("{}={}", key, value));
            features[offset + i * 2] = ((env_hash >> 0) & 0xFF) as f32 / 255.0;
            features[offset + i * 2 + 1] = ((env_hash >> 8) & 0xFF) as f32 / 255.0;
        }
        offset += self.config.env_embedding_dim;
        
        // Resource usage features (normalized)
        features[offset] = (pattern.execution_time_ms as f32).ln() / 10.0;
        features[offset + 1] = pattern.resource_usage.cpu_percent / 100.0;
        features[offset + 2] = (pattern.resource_usage.memory_bytes as f32).ln() / 20.0;
        features[offset + 3] = (pattern.resource_usage.disk_read_bytes as f32).ln() / 20.0;
        features[offset + 4] = (pattern.resource_usage.disk_write_bytes as f32).ln() / 20.0;
        features[offset + 5] = (pattern.resource_usage.network_recv_bytes as f32).ln() / 20.0;
        features[offset + 6] = (pattern.resource_usage.network_sent_bytes as f32).ln() / 20.0;
        features[offset + 7] = pattern.exit_code as f32 / 255.0;
        
        // Normalize the feature vector
        let norm = features.norm();
        if norm > 0.0 {
            features /= norm;
        }
        
        features
    }
    
    /// Simple string hashing function
    fn hash_string(&self, s: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        s.hash(&mut hasher);
        hasher.finish()
    }
    
    /// Store a pattern in memory
    pub fn store_pattern(&self, pattern: CommandPattern) -> MemoryResult<()> {
        let pattern_id = pattern.id.clone();
        let features = self.extract_features(&pattern);
        
        // Update memory usage
        let feature_size = features.len() * std::mem::size_of::<f32>();
        let pattern_size = std::mem::size_of_val(&pattern) + 
            pattern.command.len() + 
            pattern.arguments.iter().map(|s| s.len()).sum::<usize>();
        
        {
            let mut memory = self.memory_used.write();
            *memory += feature_size + pattern_size;
        }
        
        // Store in main storage
        {
            let mut patterns = self.patterns.write();
            let mut metadata = self.metadata.write();
            
            patterns.insert(pattern_id.clone(), features.clone());
            metadata.insert(pattern_id.clone(), pattern.clone());
        }
        
        // Update cache
        {
            let mut cache = self.cache.write();
            cache.put(pattern_id.clone(), (features, pattern));
        }
        
        // Mark feature matrix as needing rebuild
        {
            let mut matrix = self.feature_matrix.write();
            *matrix = None;
        }
        
        Ok(())
    }
    
    /// Find similar patterns using cosine similarity
    pub fn find_similar(
        &self, 
        query: &CommandPattern, 
        threshold: f32, 
        limit: usize
    ) -> MemoryResult<Vec<SimilarityResult>> {
        let query_features = self.extract_features(query);
        
        // Check cache first
        if let Some((cached_features, cached_pattern)) = self.cache.write().get(&query.id) {
            if cached_features == &query_features {
                return Ok(vec![SimilarityResult {
                    pattern_id: query.id.clone(),
                    similarity_score: 1.0,
                    pattern: cached_pattern.clone(),
                }]);
            }
        }
        
        // Rebuild feature matrix if needed
        self.rebuild_feature_matrix()?;
        
        let mut results = Vec::new();
        
        {
            let patterns = self.patterns.read();
            let metadata = self.metadata.read();
            let matrix = self.feature_matrix.read();
            let id_to_index = self.id_to_index.read();
            
            if let Some(ref feature_matrix) = *matrix {
                // Compute similarities using matrix operations
                let similarities = feature_matrix.transpose() * &query_features;
                
                // Collect results above threshold
                for (pattern_id, &index) in id_to_index.iter() {
                    let similarity = similarities[index];
                    
                    if similarity >= threshold {
                        if let Some(pattern) = metadata.get(pattern_id) {
                            results.push(SimilarityResult {
                                pattern_id: pattern_id.clone(),
                                similarity_score: similarity,
                                pattern: pattern.clone(),
                            });
                        }
                    }
                }
            }
        }
        
        // Sort by similarity score (descending)
        results.sort_by(|a, b| b.similarity_score.partial_cmp(&a.similarity_score).unwrap());
        
        // Limit results
        results.truncate(limit);
        
        Ok(results)
    }
    
    /// Rebuild the feature matrix for efficient batch operations
    fn rebuild_feature_matrix(&self) -> MemoryResult<()> {
        let mut matrix = self.feature_matrix.write();
        
        if matrix.is_some() {
            return Ok(());
        }
        
        let patterns = self.patterns.read();
        let pattern_count = patterns.len();
        
        if pattern_count == 0 {
            return Ok(());
        }
        
        let mut feature_matrix = DMatrix::zeros(self.config.total_dimensions, pattern_count);
        let mut id_to_index_map = HashMap::new();
        
        for (idx, (pattern_id, features)) in patterns.iter().enumerate() {
            for (i, &value) in features.iter().enumerate() {
                feature_matrix[(i, idx)] = value;
            }
            id_to_index_map.insert(pattern_id.clone(), idx);
        }
        
        *matrix = Some(feature_matrix);
        
        let mut id_to_index = self.id_to_index.write();
        *id_to_index = id_to_index_map;
        
        Ok(())
    }
    
    /// Get memory usage statistics
    pub fn get_stats(&self) -> (usize, usize) {
        let pattern_count = self.patterns.read().len();
        let memory_used = *self.memory_used.read();
        (pattern_count, memory_used)
    }
    
    /// Clear all patterns from memory
    pub fn clear(&self) {
        self.patterns.write().clear();
        self.metadata.write().clear();
        self.cache.write().clear();
        self.feature_matrix.write().take();
        self.id_to_index.write().clear();
        *self.memory_used.write() = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    
    fn create_test_pattern(id: &str, command: &str) -> CommandPattern {
        CommandPattern {
            id: id.to_string(),
            command: command.to_string(),
            arguments: vec!["arg1".to_string(), "arg2".to_string()],
            environment: HashMap::new(),
            timestamp: Utc::now(),
            execution_time_ms: 100,
            exit_code: 0,
            resource_usage: ResourceUsage {
                cpu_percent: 10.0,
                memory_bytes: 1024 * 1024,
                disk_read_bytes: 0,
                disk_write_bytes: 0,
                network_recv_bytes: 1024,
                network_sent_bytes: 512,
            },
        }
    }
    
    #[test]
    fn test_pattern_storage_and_retrieval() {
        let memory = TensorMemory::new(100);
        
        let pattern = create_test_pattern("test-1", "docker");
        memory.store_pattern(pattern.clone()).unwrap();
        
        let results = memory.find_similar(&pattern, 0.9, 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pattern_id, "test-1");
        assert!(results[0].similarity_score >= 0.99);
    }
    
    #[test]
    fn test_similarity_search() {
        let memory = TensorMemory::new(100);
        
        // Store multiple patterns
        memory.store_pattern(create_test_pattern("docker-1", "docker")).unwrap();
        memory.store_pattern(create_test_pattern("docker-2", "docker")).unwrap();
        memory.store_pattern(create_test_pattern("kubectl-1", "kubectl")).unwrap();
        
        // Search for similar docker commands
        let query = create_test_pattern("query", "docker");
        let results = memory.find_similar(&query, 0.7, 10).unwrap();
        
        // Should find the docker commands as most similar
        assert!(results.len() >= 2);
        assert!(results[0].pattern.command == "docker");
        assert!(results[1].pattern.command == "docker");
    }
    
    #[test]
    fn test_feature_extraction() {
        let memory = TensorMemory::new(100);
        let pattern = create_test_pattern("test", "docker");
        
        let features = memory.extract_features(&pattern);
        assert_eq!(features.len(), memory.config.total_dimensions);
        
        // Features should be normalized
        let norm = features.norm();
        assert!((norm - 1.0).abs() < 0.001);
    }
}