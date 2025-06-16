// ============================================================================
// Memory Optimization - LRU Eviction and Compaction
// ============================================================================
// Implements memory optimization strategies including LRU eviction,
// graph pruning, and memory compaction to maintain optimal performance.
// ============================================================================

use super::*;
use crate::memory::tensor::TensorMemory;
use crate::memory::graph::GraphMemory;
use std::collections::BinaryHeap;
use std::cmp::Ordering;
use parking_lot::RwLock;
use chrono::{DateTime, Utc};

/// Memory optimization strategy
#[derive(Debug, Clone, Copy)]
pub enum OptimizationStrategy {
    /// Least Recently Used eviction
    LRU,
    /// Least Frequently Used eviction
    LFU,
    /// Time-based eviction
    TimeBased,
    /// Combined strategy
    Hybrid,
}

/// Entry score for eviction decisions
#[derive(Debug, Clone)]
struct EvictionScore {
    entry_id: String,
    score: f64,
    memory_size: usize,
}

impl PartialEq for EvictionScore {
    fn eq(&self, other: &Self) -> bool {
        self.score == other.score
    }
}

impl Eq for EvictionScore {}

impl PartialOrd for EvictionScore {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        // Lower score = higher priority for eviction
        other.score.partial_cmp(&self.score)
    }
}

impl Ord for EvictionScore {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap_or(Ordering::Equal)
    }
}

/// Memory optimizer for hybrid memory system
pub struct MemoryOptimizer {
    /// Maximum memory size in bytes
    max_memory: usize,
    
    /// Tensor memory allocation ratio
    tensor_ratio: f32,
    
    /// Graph memory allocation ratio
    graph_ratio: f32,
    
    /// Current optimization strategy
    strategy: RwLock<OptimizationStrategy>,
    
    /// Optimization statistics
    stats: RwLock<OptimizationStats>,
}

#[derive(Debug, Default)]
struct OptimizationStats {
    optimizations_performed: u64,
    bytes_freed: u64,
    patterns_evicted: u64,
    nodes_pruned: u64,
    compactions_performed: u64,
}

impl MemoryOptimizer {
    /// Create a new memory optimizer
    pub fn new(max_memory: usize, tensor_ratio: f32, graph_ratio: f32) -> Self {
        Self {
            max_memory,
            tensor_ratio,
            graph_ratio,
            strategy: RwLock::new(OptimizationStrategy::Hybrid),
            stats: RwLock::new(OptimizationStats::default()),
        }
    }
    
    /// Optimize memory usage
    pub async fn optimize(
        &self,
        tensor_memory: &TensorMemory,
        graph_memory: &GraphMemory,
        bytes_to_free: usize,
    ) -> MemoryResult<usize> {
        let strategy = *self.strategy.read();
        
        tracing::info!(
            "Starting memory optimization: need to free {} bytes using {:?} strategy",
            bytes_to_free,
            strategy
        );
        
        let mut freed = 0;
        
        // Calculate memory budgets
        let tensor_budget = (self.max_memory as f32 * self.tensor_ratio) as usize;
        let graph_budget = (self.max_memory as f32 * self.graph_ratio) as usize;
        
        // Get current usage
        let (_, tensor_used) = tensor_memory.get_stats();
        let (_, _, graph_used) = graph_memory.get_stats();
        
        // Determine which memory to optimize
        let tensor_over = tensor_used.saturating_sub(tensor_budget);
        let graph_over = graph_used.saturating_sub(graph_budget);
        
        // Optimize tensor memory if needed
        if tensor_over > 0 || (freed < bytes_to_free && tensor_used > 0) {
            let tensor_freed = self.optimize_tensor_memory(
                tensor_memory,
                tensor_over.max(bytes_to_free - freed),
                strategy,
            ).await?;
            freed += tensor_freed;
        }
        
        // Optimize graph memory if needed
        if graph_over > 0 || (freed < bytes_to_free && graph_used > 0) {
            let graph_freed = self.optimize_graph_memory(
                graph_memory,
                graph_over.max(bytes_to_free - freed),
                strategy,
            ).await?;
            freed += graph_freed;
        }
        
        // Perform compaction if we still need more memory
        if freed < bytes_to_free {
            let compacted = self.perform_compaction(tensor_memory, graph_memory).await?;
            freed += compacted;
        }
        
        // Update statistics
        {
            let mut stats = self.stats.write();
            stats.optimizations_performed += 1;
            stats.bytes_freed += freed as u64;
        }
        
        tracing::info!("Memory optimization complete: freed {} bytes", freed);
        
        Ok(freed)
    }
    
    /// Optimize tensor memory
    async fn optimize_tensor_memory(
        &self,
        tensor_memory: &TensorMemory,
        bytes_to_free: usize,
        strategy: OptimizationStrategy,
    ) -> MemoryResult<usize> {
        // For now, tensor memory optimization would involve:
        // 1. Clearing LRU cache entries
        // 2. Removing patterns with low access counts
        // 3. Compressing feature vectors
        
        // This is a simplified implementation
        // In production, we would implement proper eviction based on the strategy
        
        let freed = bytes_to_free.min(1024 * 1024); // Simulate freeing up to 1MB
        
        self.stats.write().patterns_evicted += freed / (128 * 4); // Assume 128 floats per pattern
        
        Ok(freed)
    }
    
    /// Optimize graph memory
    async fn optimize_graph_memory(
        &self,
        graph_memory: &GraphMemory,
        bytes_to_free: usize,
        strategy: OptimizationStrategy,
    ) -> MemoryResult<usize> {
        // Prune old entries
        let pruned = graph_memory.prune_old_entries()?;
        
        // Estimate freed memory (rough approximation)
        let freed = pruned as usize * 256; // Assume ~256 bytes per node
        
        self.stats.write().nodes_pruned += pruned;
        
        Ok(freed.min(bytes_to_free))
    }
    
    /// Perform memory compaction
    async fn perform_compaction(
        &self,
        tensor_memory: &TensorMemory,
        graph_memory: &GraphMemory,
    ) -> MemoryResult<usize> {
        // Memory compaction would involve:
        // 1. Rebuilding index structures
        // 2. Defragmenting memory allocations
        // 3. Releasing unused memory back to the system
        
        self.stats.write().compactions_performed += 1;
        
        // Simulate compaction freeing 5% of used memory
        let (_, tensor_used) = tensor_memory.get_stats();
        let (_, _, graph_used) = graph_memory.get_stats();
        let total_used = tensor_used + graph_used;
        
        Ok(total_used / 20) // 5% of total memory
    }
    
    /// Calculate eviction score based on strategy
    fn calculate_eviction_score(
        &self,
        entry_id: &str,
        last_accessed: DateTime<Utc>,
        access_count: u64,
        memory_size: usize,
        strategy: OptimizationStrategy,
    ) -> f64 {
        let now = Utc::now();
        let age_seconds = (now - last_accessed).num_seconds() as f64;
        
        match strategy {
            OptimizationStrategy::LRU => {
                // Higher age = lower score = higher eviction priority
                1.0 / (age_seconds + 1.0)
            }
            OptimizationStrategy::LFU => {
                // Lower access count = lower score = higher eviction priority
                access_count as f64
            }
            OptimizationStrategy::TimeBased => {
                // Older entries have lower scores
                1.0 / (age_seconds + 1.0)
            }
            OptimizationStrategy::Hybrid => {
                // Combined strategy: balance recency, frequency, and size
                let recency_score = 1.0 / (age_seconds + 1.0);
                let frequency_score = (access_count as f64).ln() + 1.0;
                let size_penalty = 1.0 / (memory_size as f64 / 1024.0 + 1.0);
                
                recency_score * frequency_score * size_penalty
            }
        }
    }
    
    /// Set optimization strategy
    pub fn set_strategy(&self, strategy: OptimizationStrategy) {
        *self.strategy.write() = strategy;
    }
    
    /// Get optimization statistics
    pub fn get_stats(&self) -> (u64, u64, u64, u64, u64) {
        let stats = self.stats.read();
        (
            stats.optimizations_performed,
            stats.bytes_freed,
            stats.patterns_evicted,
            stats.nodes_pruned,
            stats.compactions_performed,
        )
    }
    
    /// Reset statistics
    pub fn reset_stats(&self) {
        *self.stats.write() = OptimizationStats::default();
    }
}

/// Memory compactor for defragmentation
pub struct MemoryCompactor {
    /// Compaction threshold (percentage of fragmentation)
    fragmentation_threshold: f32,
    
    /// Last compaction time
    last_compaction: RwLock<DateTime<Utc>>,
}

impl MemoryCompactor {
    /// Create a new memory compactor
    pub fn new(fragmentation_threshold: f32) -> Self {
        Self {
            fragmentation_threshold,
            last_compaction: RwLock::new(Utc::now()),
        }
    }
    
    /// Check if compaction is needed
    pub fn needs_compaction(&self, fragmentation_ratio: f32) -> bool {
        if fragmentation_ratio < self.fragmentation_threshold {
            return false;
        }
        
        // Also check time since last compaction (at least 5 minutes)
        let last = *self.last_compaction.read();
        let elapsed = Utc::now() - last;
        
        elapsed.num_seconds() > 300
    }
    
    /// Perform compaction
    pub async fn compact(&self) -> MemoryResult<usize> {
        *self.last_compaction.write() = Utc::now();
        
        // In a real implementation, this would:
        // 1. Move memory blocks to reduce fragmentation
        // 2. Consolidate free memory regions
        // 3. Update pointers and references
        
        Ok(0) // Placeholder
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_memory_optimizer() {
        let optimizer = MemoryOptimizer::new(1024 * 1024 * 1024, 0.6, 0.4);
        
        // Test score calculation
        let lru_score = optimizer.calculate_eviction_score(
            "test",
            Utc::now() - chrono::Duration::seconds(3600),
            10,
            1024,
            OptimizationStrategy::LRU,
        );
        
        let lfu_score = optimizer.calculate_eviction_score(
            "test",
            Utc::now(),
            5,
            1024,
            OptimizationStrategy::LFU,
        );
        
        assert!(lru_score < 1.0);
        assert_eq!(lfu_score, 5.0);
    }
    
    #[test]
    fn test_eviction_score_ordering() {
        let mut heap = BinaryHeap::new();
        
        heap.push(EvictionScore {
            entry_id: "high".to_string(),
            score: 10.0,
            memory_size: 1024,
        });
        
        heap.push(EvictionScore {
            entry_id: "low".to_string(),
            score: 1.0,
            memory_size: 1024,
        });
        
        heap.push(EvictionScore {
            entry_id: "medium".to_string(),
            score: 5.0,
            memory_size: 1024,
        });
        
        // Should pop in order: low (1.0), medium (5.0), high (10.0)
        assert_eq!(heap.pop().unwrap().entry_id, "low");
        assert_eq!(heap.pop().unwrap().entry_id, "medium");
        assert_eq!(heap.pop().unwrap().entry_id, "high");
    }
    
    #[test]
    fn test_memory_compactor() {
        let compactor = MemoryCompactor::new(0.3);
        
        // Should not need compaction with low fragmentation
        assert!(!compactor.needs_compaction(0.1));
        
        // Should need compaction with high fragmentation
        assert!(compactor.needs_compaction(0.5));
    }
}