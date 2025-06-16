// ============================================================================
// Hybrid Memory System - Unified Tensor-Graph Interface
// ============================================================================
// Provides a unified interface for pattern recognition and dependency tracking
// with cross-memory correlation and efficient query performance.
// ============================================================================

use super::*;
use crate::memory::tensor::TensorMemory;
use crate::memory::graph::GraphMemory;
use crate::memory::index::MemoryIndex;
use crate::memory::optimization::MemoryOptimizer;
use std::sync::Arc;
use parking_lot::RwLock;
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::{interval, Duration as TokioDuration};
use std::collections::{HashMap, HashSet};

/// Unified query for hybrid memory system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridQuery {
    /// Pattern to search for similar commands
    pub pattern: Option<CommandPattern>,
    
    /// Command IDs to find dependencies for
    pub command_ids: Option<Vec<String>>,
    
    /// Similarity threshold for pattern matching
    pub similarity_threshold: f32,
    
    /// Maximum number of results
    pub limit: usize,
    
    /// Include dependency information in results
    pub include_dependencies: bool,
    
    /// Include resource conflict analysis
    pub include_conflicts: bool,
}

/// Result from hybrid memory query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridResult {
    /// Similar patterns found
    pub similar_patterns: Vec<SimilarityResult>,
    
    /// Dependencies found
    pub dependencies: HashMap<String, Vec<Dependency>>,
    
    /// Suggested execution order
    pub execution_order: Option<Vec<String>>,
    
    /// Resource conflicts detected
    pub conflicts: Vec<(String, String, Vec<String>)>,
    
    /// Cross-memory correlations
    pub correlations: Vec<Correlation>,
}

/// Cross-memory correlation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Correlation {
    pub pattern_id: String,
    pub correlation_type: CorrelationType,
    pub confidence: f32,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CorrelationType {
    /// Pattern frequently appears in dependency chains
    FrequentInChain,
    /// Pattern is a common predecessor
    CommonPredecessor,
    /// Pattern is a common successor
    CommonSuccessor,
    /// Pattern shares resources with dependencies
    ResourceOverlap,
}

/// Hybrid memory system combining tensor and graph memories
pub struct HybridMemory {
    /// Configuration
    config: Arc<MemoryConfig>,
    
    /// Tensor memory for pattern recognition
    tensor_memory: Arc<TensorMemory>,
    
    /// Graph memory for dependency tracking
    graph_memory: Arc<GraphMemory>,
    
    /// Memory index for fast lookups
    index: Arc<MemoryIndex>,
    
    /// Memory optimizer
    optimizer: Arc<MemoryOptimizer>,
    
    /// Statistics
    stats: Arc<RwLock<MemoryStats>>,
    
    /// Background tasks handle
    background_handle: Arc<AsyncMutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl HybridMemory {
    /// Create a new hybrid memory system
    pub fn new(config: MemoryConfig) -> Self {
        let tensor_memory = Arc::new(TensorMemory::new(config.lru_cache_size));
        let graph_memory = Arc::new(GraphMemory::new(config.graph_pruning_threshold_secs));
        let index = Arc::new(MemoryIndex::new());
        let optimizer = Arc::new(MemoryOptimizer::new(
            config.max_memory_bytes,
            config.tensor_memory_ratio,
            config.graph_memory_ratio,
        ));
        
        Self {
            config: Arc::new(config),
            tensor_memory,
            graph_memory,
            index,
            optimizer,
            stats: Arc::new(RwLock::new(MemoryStats {
                tensor_memory_used: 0,
                graph_memory_used: 0,
                total_memory_used: 0,
                pattern_count: 0,
                node_count: 0,
                edge_count: 0,
                cache_hits: 0,
                cache_misses: 0,
                compactions_performed: 0,
                pruning_operations: 0,
            })),
            background_handle: Arc::new(AsyncMutex::new(None)),
        }
    }
    
    /// Start background maintenance tasks
    pub async fn start_background_tasks(&self) {
        let mut handle = self.background_handle.lock().await;
        if handle.is_some() {
            return;
        }
        
        let memory = self.clone();
        let task = tokio::spawn(async move {
            let mut interval = interval(TokioDuration::from_secs(memory.config.compaction_interval_secs));
            
            loop {
                interval.tick().await;
                
                // Perform memory optimization
                if let Err(e) = memory.optimize_memory().await {
                    tracing::error!("Memory optimization failed: {}", e);
                }
                
                // Update statistics
                memory.update_stats();
            }
        });
        
        *handle = Some(task);
    }
    
    /// Store a command pattern with its dependencies
    pub async fn store(
        &self,
        pattern: CommandPattern,
        resources: HashSet<String>,
        dependencies: Vec<(String, DependencyType, f32)>,
    ) -> MemoryResult<()> {
        // Store in tensor memory
        self.tensor_memory.store_pattern(pattern.clone())?;
        
        // Store in graph memory
        let node_idx = self.graph_memory.add_node(pattern.clone(), resources)?;
        
        // Add dependencies
        for (dep_id, dep_type, strength) in dependencies {
            self.graph_memory.add_dependency(&dep_id, &pattern.id, dep_type, strength)?;
        }
        
        // Update index
        self.index.add_entry(&pattern.id, node_idx)?;
        
        // Update stats
        self.update_stats();
        
        Ok(())
    }
    
    /// Execute a hybrid query
    pub async fn query(&self, query: HybridQuery) -> MemoryResult<HybridResult> {
        let mut result = HybridResult {
            similar_patterns: Vec::new(),
            dependencies: HashMap::new(),
            execution_order: None,
            conflicts: Vec::new(),
            correlations: Vec::new(),
        };
        
        // Pattern similarity search
        if let Some(pattern) = &query.pattern {
            result.similar_patterns = self.tensor_memory.find_similar(
                pattern,
                query.similarity_threshold,
                query.limit,
            )?;
            
            self.stats.write().cache_hits += result.similar_patterns.len() as u64;
        }
        
        // Dependency analysis
        if query.include_dependencies {
            if let Some(command_ids) = &query.command_ids {
                for command_id in command_ids {
                    let deps = self.graph_memory.find_dependencies(command_id)?;
                    let dep_list: Vec<Dependency> = deps.into_iter()
                        .map(|(_, dep)| dep)
                        .collect();
                    result.dependencies.insert(command_id.clone(), dep_list);
                }
                
                // Find execution order
                result.execution_order = Some(
                    self.graph_memory.find_execution_order(command_ids)?
                );
            }
        }
        
        // Conflict detection
        if query.include_conflicts {
            if let Some(command_ids) = &query.command_ids {
                result.conflicts = self.graph_memory.detect_conflicts(command_ids)?;
            }
        }
        
        // Cross-memory correlation
        result.correlations = self.find_correlations(&result).await?;
        
        Ok(result)
    }
    
    /// Find correlations between pattern and graph memories
    async fn find_correlations(&self, result: &HybridResult) -> MemoryResult<Vec<Correlation>> {
        let mut correlations = Vec::new();
        
        // Analyze patterns that frequently appear in dependency chains
        for similar in &result.similar_patterns {
            let dependents = self.graph_memory.find_dependents(&similar.pattern_id)?;
            let dependencies = self.graph_memory.find_dependencies(&similar.pattern_id)?;
            
            if dependents.len() + dependencies.len() > 5 {
                correlations.push(Correlation {
                    pattern_id: similar.pattern_id.clone(),
                    correlation_type: CorrelationType::FrequentInChain,
                    confidence: 0.8 + (0.2 * similar.similarity_score),
                    details: format!(
                        "Pattern appears in {} dependency relationships",
                        dependents.len() + dependencies.len()
                    ),
                });
            }
            
            // Check for common predecessors/successors
            if dependents.len() > 3 {
                correlations.push(Correlation {
                    pattern_id: similar.pattern_id.clone(),
                    correlation_type: CorrelationType::CommonPredecessor,
                    confidence: 0.7 + (0.3 * similar.similarity_score),
                    details: format!("Pattern has {} dependent commands", dependents.len()),
                });
            }
            
            if dependencies.len() > 3 {
                correlations.push(Correlation {
                    pattern_id: similar.pattern_id.clone(),
                    correlation_type: CorrelationType::CommonSuccessor,
                    confidence: 0.7 + (0.3 * similar.similarity_score),
                    details: format!("Pattern depends on {} commands", dependencies.len()),
                });
            }
        }
        
        Ok(correlations)
    }
    
    /// Optimize memory usage
    async fn optimize_memory(&self) -> MemoryResult<()> {
        // Get current memory usage
        let (tensor_patterns, tensor_bytes) = self.tensor_memory.get_stats();
        let (graph_nodes, graph_edges, graph_bytes) = self.graph_memory.get_stats();
        
        let total_bytes = tensor_bytes + graph_bytes;
        
        // Check if we need to free memory
        if total_bytes > self.config.max_memory_bytes {
            tracing::warn!(
                "Memory limit exceeded: {}/{} bytes",
                total_bytes,
                self.config.max_memory_bytes
            );
            
            // Trigger memory optimization
            let freed = self.optimizer.optimize(
                &self.tensor_memory,
                &self.graph_memory,
                total_bytes - self.config.max_memory_bytes,
            ).await?;
            
            tracing::info!("Freed {} bytes of memory", freed);
            
            self.stats.write().compactions_performed += 1;
        }
        
        // Prune old graph entries
        let pruned = self.graph_memory.prune_old_entries()?;
        if pruned > 0 {
            tracing::info!("Pruned {} old graph entries", pruned);
            self.stats.write().pruning_operations += 1;
        }
        
        Ok(())
    }
    
    /// Update memory statistics
    fn update_stats(&self) {
        let (tensor_patterns, tensor_bytes) = self.tensor_memory.get_stats();
        let (graph_nodes, graph_edges, graph_bytes) = self.graph_memory.get_stats();
        
        let mut stats = self.stats.write();
        stats.tensor_memory_used = tensor_bytes;
        stats.graph_memory_used = graph_bytes;
        stats.total_memory_used = tensor_bytes + graph_bytes;
        stats.pattern_count = tensor_patterns;
        stats.node_count = graph_nodes;
        stats.edge_count = graph_edges;
    }
    
    /// Get current memory statistics
    pub fn get_stats(&self) -> MemoryStats {
        self.stats.read().clone()
    }
    
    /// Clear all memory
    pub fn clear(&self) {
        self.tensor_memory.clear();
        self.graph_memory.clear();
        self.index.clear();
        self.update_stats();
    }
}

impl Clone for HybridMemory {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            tensor_memory: Arc::clone(&self.tensor_memory),
            graph_memory: Arc::clone(&self.graph_memory),
            index: Arc::clone(&self.index),
            optimizer: Arc::clone(&self.optimizer),
            stats: Arc::clone(&self.stats),
            background_handle: Arc::new(AsyncMutex::new(None)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;
    
    fn create_test_pattern(id: &str, command: &str) -> CommandPattern {
        CommandPattern {
            id: id.to_string(),
            command: command.to_string(),
            arguments: vec![],
            environment: HashMap::new(),
            timestamp: chrono::Utc::now(),
            execution_time_ms: 100,
            exit_code: 0,
            resource_usage: ResourceUsage {
                cpu_percent: 10.0,
                memory_bytes: 1024,
                disk_read_bytes: 0,
                disk_write_bytes: 0,
                network_recv_bytes: 0,
                network_sent_bytes: 0,
            },
        }
    }
    
    #[tokio::test]
    async fn test_hybrid_storage_and_query() {
        let config = MemoryConfig::default();
        let memory = HybridMemory::new(config);
        
        // Store patterns with dependencies
        let build_pattern = create_test_pattern("build", "docker build");
        let test_pattern = create_test_pattern("test", "pytest");
        let deploy_pattern = create_test_pattern("deploy", "kubectl apply");
        
        memory.store(
            build_pattern.clone(),
            HashSet::from(["docker.sock".to_string()]),
            vec![],
        ).await.unwrap();
        
        memory.store(
            test_pattern.clone(),
            HashSet::new(),
            vec![("build".to_string(), DependencyType::Sequential, 1.0)],
        ).await.unwrap();
        
        memory.store(
            deploy_pattern.clone(),
            HashSet::from(["kubeconfig".to_string()]),
            vec![("test".to_string(), DependencyType::Sequential, 1.0)],
        ).await.unwrap();
        
        // Query for similar patterns and dependencies
        let query = HybridQuery {
            pattern: Some(create_test_pattern("query", "docker")),
            command_ids: Some(vec!["build".to_string(), "test".to_string(), "deploy".to_string()]),
            similarity_threshold: 0.5,
            limit: 10,
            include_dependencies: true,
            include_conflicts: true,
        };
        
        let result = memory.query(query).await.unwrap();
        
        // Check results
        assert!(!result.similar_patterns.is_empty());
        assert_eq!(result.execution_order, Some(vec!["build".to_string(), "test".to_string(), "deploy".to_string()]));
        assert!(!result.correlations.is_empty());
    }
    
    #[tokio::test]
    async fn test_resource_conflict_detection() {
        let config = MemoryConfig::default();
        let memory = HybridMemory::new(config);
        
        // Store patterns with conflicting resources
        let app1 = create_test_pattern("app1", "docker run app1");
        let app2 = create_test_pattern("app2", "docker run app2");
        
        memory.store(
            app1,
            HashSet::from(["port:8080".to_string()]),
            vec![],
        ).await.unwrap();
        
        memory.store(
            app2,
            HashSet::from(["port:8080".to_string()]),
            vec![],
        ).await.unwrap();
        
        // Query for conflicts
        let query = HybridQuery {
            pattern: None,
            command_ids: Some(vec!["app1".to_string(), "app2".to_string()]),
            similarity_threshold: 0.8,
            limit: 10,
            include_dependencies: false,
            include_conflicts: true,
        };
        
        let result = memory.query(query).await.unwrap();
        assert_eq!(result.conflicts.len(), 1);
        assert_eq!(result.conflicts[0].2, vec!["port:8080"]);
    }
}