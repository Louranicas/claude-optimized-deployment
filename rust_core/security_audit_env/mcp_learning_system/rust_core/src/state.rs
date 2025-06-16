//! State Management Module
//! 
//! Concurrent state management with minimal contention using DashMap and RwLock.

use std::sync::Arc;
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use anyhow::{Result, anyhow};
use arc_swap::ArcSwap;
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{instrument, trace, warn};

use crate::server::StateUpdate;

/// State entry with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateEntry {
    pub key: String,
    pub value: Value,
    pub version: u64,
    pub created_at: u64,
    pub updated_at: u64,
    pub access_count: u64,
    pub metadata: Option<Value>,
}

/// State manager for concurrent access
pub struct StateManager {
    /// Primary state storage using DashMap for concurrent access
    state: Arc<DashMap<String, Arc<StateEntry>>>,
    
    /// Hot data cache with ArcSwap for lock-free reads
    hot_cache: Arc<DashMap<String, Arc<ArcSwap<StateEntry>>>>,
    
    /// Global configuration with RwLock
    config: Arc<RwLock<StateConfig>>,
    
    /// State statistics
    stats: Arc<StateStats>,
    
    /// Version counter
    version_counter: AtomicU64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateConfig {
    pub max_entries: usize,
    pub hot_cache_size: usize,
    pub ttl_seconds: Option<u64>,
    pub compression_enabled: bool,
}

impl Default for StateConfig {
    fn default() -> Self {
        Self {
            max_entries: 1_000_000,
            hot_cache_size: 10_000,
            ttl_seconds: None,
            compression_enabled: false,
        }
    }
}

struct StateStats {
    reads: AtomicU64,
    writes: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    version_conflicts: AtomicU64,
}

impl StateManager {
    /// Create a new state manager
    pub fn new() -> Self {
        Self {
            state: Arc::new(DashMap::with_capacity(100_000)),
            hot_cache: Arc::new(DashMap::with_capacity(10_000)),
            config: Arc::new(RwLock::new(StateConfig::default())),
            stats: Arc::new(StateStats {
                reads: AtomicU64::new(0),
                writes: AtomicU64::new(0),
                cache_hits: AtomicU64::new(0),
                cache_misses: AtomicU64::new(0),
                version_conflicts: AtomicU64::new(0),
            }),
            version_counter: AtomicU64::new(0),
        }
    }
    
    /// Get state value with minimal contention
    #[instrument(skip(self), fields(key))]
    #[inline(always)]
    pub fn get(&self, key: &str) -> Option<Arc<StateEntry>> {
        let start = Instant::now();
        self.stats.reads.fetch_add(1, Ordering::Relaxed);
        
        // Check hot cache first (lock-free read)
        if let Some(cached) = self.hot_cache.get(key) {
            self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
            let entry = cached.load_full();
            
            // Update access count
            let mut updated = (**entry).clone();
            updated.access_count += 1;
            cached.store(Arc::new(updated.clone()));
            
            trace!("Cache hit for key: {}, latency: {:?}", key, start.elapsed());
            return Some(Arc::new(updated));
        }
        
        self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
        
        // Fallback to main state
        if let Some(entry) = self.state.get(key) {
            let mut updated = (**entry).clone();
            updated.access_count += 1;
            
            // Promote to hot cache if accessed frequently
            if updated.access_count > 10 {
                self.promote_to_hot_cache(key, Arc::new(updated.clone()));
            }
            
            trace!("State hit for key: {}, latency: {:?}", key, start.elapsed());
            Some(Arc::new(updated))
        } else {
            None
        }
    }
    
    /// Set state value
    #[instrument(skip(self, value), fields(key))]
    pub fn set(&self, key: String, value: Value) -> Result<u64> {
        self.stats.writes.fetch_add(1, Ordering::Relaxed);
        
        let version = self.version_counter.fetch_add(1, Ordering::SeqCst);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let entry = Arc::new(StateEntry {
            key: key.clone(),
            value,
            version,
            created_at: now,
            updated_at: now,
            access_count: 0,
            metadata: None,
        });
        
        // Check capacity
        let config = self.config.read();
        if self.state.len() >= config.max_entries {
            self.evict_lru()?;
        }
        drop(config);
        
        // Update state
        self.state.insert(key.clone(), entry.clone());
        
        // Update hot cache if present
        if let Some(cached) = self.hot_cache.get(&key) {
            cached.store(entry);
        }
        
        trace!("Set key: {} with version: {}", key, version);
        Ok(version)
    }
    
    /// Update state with conflict detection
    #[instrument(skip(self, update), fields(key = %update.key))]
    pub async fn update(&self, update: StateUpdate) -> Result<()> {
        match update.operation {
            crate::server::UpdateOperation::Set => {
                self.set(update.key, update.value)?;
            }
            crate::server::UpdateOperation::Merge => {
                if let Some(existing) = self.get(&update.key) {
                    let merged = self.merge_values(&existing.value, &update.value)?;
                    self.set(update.key, merged)?;
                } else {
                    self.set(update.key, update.value)?;
                }
            }
            crate::server::UpdateOperation::Delete => {
                self.delete(&update.key);
            }
        }
        Ok(())
    }
    
    /// Delete state entry
    #[instrument(skip(self), fields(key))]
    pub fn delete(&self, key: &str) -> bool {
        self.hot_cache.remove(key);
        self.state.remove(key).is_some()
    }
    
    /// Check and set atomically
    #[instrument(skip(self, value), fields(key))]
    pub fn compare_and_swap(&self, key: &str, expected_version: u64, value: Value) -> Result<u64> {
        if let Some(entry) = self.state.get(key) {
            if entry.version != expected_version {
                self.stats.version_conflicts.fetch_add(1, Ordering::Relaxed);
                return Err(anyhow!("Version conflict: expected {}, got {}", expected_version, entry.version));
            }
        }
        
        self.set(key.to_string(), value)
    }
    
    /// Promote entry to hot cache
    fn promote_to_hot_cache(&self, key: &str, entry: Arc<StateEntry>) {
        let config = self.config.read();
        if self.hot_cache.len() >= config.hot_cache_size {
            // Evict least recently used from hot cache
            self.evict_from_hot_cache();
        }
        drop(config);
        
        self.hot_cache.insert(key.to_string(), Arc::new(ArcSwap::from(entry)));
    }
    
    /// Evict from hot cache
    fn evict_from_hot_cache(&self) {
        // Simple eviction: remove first entry
        // In production, use proper LRU
        if let Some(entry) = self.hot_cache.iter().next() {
            self.hot_cache.remove(entry.key());
        }
    }
    
    /// Evict least recently used entries
    fn evict_lru(&self) -> Result<()> {
        // Simple eviction: remove 10% of entries
        // In production, use proper LRU tracking
        let to_remove = self.state.len() / 10;
        let mut removed = 0;
        
        for entry in self.state.iter() {
            if removed >= to_remove {
                break;
            }
            self.state.remove(entry.key());
            removed += 1;
        }
        
        Ok(())
    }
    
    /// Merge JSON values
    fn merge_values(&self, base: &Value, update: &Value) -> Result<Value> {
        match (base, update) {
            (Value::Object(base_map), Value::Object(update_map)) => {
                let mut merged = base_map.clone();
                for (k, v) in update_map {
                    merged.insert(k.clone(), v.clone());
                }
                Ok(Value::Object(merged))
            }
            _ => Ok(update.clone()),
        }
    }
    
    /// Get state statistics
    pub fn get_stats(&self) -> StateManagerStats {
        let reads = self.stats.reads.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release;
        let cache_hits = self.stats.cache_hits.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release;
        
        StateManagerStats {
            total_entries: self.state.len(),
            hot_cache_entries: self.hot_cache.len(),
            reads,
            writes: self.stats.writes.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release,
            cache_hits,
            cache_misses: self.stats.cache_misses.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release,
            cache_hit_rate: if reads > 0 {
                (cache_hits as f64) / (reads as f64)
            } else {
                0.0
            },
            version_conflicts: self.stats.version_conflicts.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release,
        }
    }
    
    /// Clear all state
    pub fn clear(&self) {
        self.hot_cache.clear();
        self.state.clear();
        self.version_counter.store(0, Ordering::SeqCst);
    }
}

#[derive(Debug, Clone)]
pub struct StateManagerStats {
    pub total_entries: usize,
    pub hot_cache_entries: usize,
    pub reads: u64,
    pub writes: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_hit_rate: f64,
    pub version_conflicts: u64,
}

/// Thread-safe state snapshot
pub struct StateSnapshot {
    entries: Vec<StateEntry>,
    timestamp: u64,
}

impl StateSnapshot {
    /// Create a snapshot of current state
    pub fn create(state_manager: &StateManager) -> Self {
        let entries: Vec<StateEntry> = state_manager.state
            .iter()
            .map(|entry| (*entry.value()).clone())
            .collect();
        
        Self {
            entries,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
    
    /// Get snapshot entries
    pub fn entries(&self) -> &[StateEntry] {
        &self.entries
    }
    
    /// Get snapshot timestamp
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    
    #[test]
    fn test_state_operations() {
        let manager = StateManager::new();
        
        // Test set and get
        let version = manager.set("key1".to_string(), json!({"value": 42})).unwrap();
        assert_eq!(version, 0);
        
        let entry = manager.get("key1").unwrap();
        assert_eq!(entry.key, "key1");
        assert_eq!(entry.value, json!({"value": 42}));
        
        // Test update
        let version2 = manager.set("key1".to_string(), json!({"value": 43})).unwrap();
        assert_eq!(version2, 1);
        
        // Test delete
        assert!(manager.delete("key1"));
        assert!(manager.get("key1").is_none());
    }
    
    #[test]
    fn test_compare_and_swap() {
        let manager = StateManager::new();
        
        let v1 = manager.set("key1".to_string(), json!({"v": 1})).unwrap();
        
        // Successful CAS
        let v2 = manager.compare_exchange("key1", v1, json!({"v": 2}, Ordering::Relaxed).is_ok()).unwrap();
        assert_eq!(v2, v1 + 1);
        
        // Failed CAS (wrong version)
        assert!(manager.compare_exchange("key1", v1, json!({"v": 3}, Ordering::Relaxed).is_ok()).is_err());
    }
    
    #[tokio::test]
    async fn test_concurrent_access() {
        let manager = Arc::new(StateManager::new());
        
        // Spawn multiple tasks
        let mut handles = vec![];
        
        for i in 0..10 {
            let mgr = manager.clone();
            let handle = tokio::spawn(async move {
                for j in 0..100 {
                    mgr.set(format!("key_{}", j), json!({"thread": i, "value": j})).unwrap();
                }
            });
            handles.push(handle);
        }
        
        // Wait for all tasks
        for handle in handles {
            handle.await.unwrap();
        }
        
        // Verify state
        let stats = manager.get_stats();
        assert_eq!(stats.writes, 1000);
        assert!(stats.total_entries <= 100); // Due to overwrites
    }
    
    #[test]
    fn test_hot_cache() {
        let manager = StateManager::new();
        
        // Set value
        manager.set("hot_key".to_string(), json!({"hot": true})).unwrap();
        
        // Access multiple times to promote to hot cache
        for _ in 0..15 {
            manager.get("hot_key");
        }
        
        // Should now be in hot cache
        let stats = manager.get_stats();
        assert!(stats.cache_hits > 0);
    }
}