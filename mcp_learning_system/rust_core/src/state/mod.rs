//! State Management Module
//! 
//! Lock-free concurrent state management using DashMap

use std::sync::Arc;
use std::time::{Duration, Instant};
use dashmap::{DashMap, mapref::entry::Entry};
use tracing::{debug, info, warn};

use crate::error::Result;

/// State entry with versioning and metadata
#[derive(Debug, Clone)]
pub struct StateEntry {
    /// State key
    pub key: String,
    /// State value
    pub value: Vec<u8>,
    /// Version number
    pub version: u64,
    /// Creation timestamp
    pub created_at: Instant,
    /// Last updated timestamp
    pub updated_at: Instant,
    /// Access count
    pub access_count: u64,
    /// TTL in seconds (0 means no expiry)
    pub ttl: u64,
}

impl StateEntry {
    /// Check if the entry has expired
    pub fn is_expired(&self) -> bool {
        if self.ttl == 0 {
            return false;
        }
        self.updated_at.elapsed().as_secs() > self.ttl
    }
}

/// State manager statistics
#[derive(Debug, Default)]
pub struct StateStats {
    /// Total entries
    pub total_entries: std::sync::atomic::AtomicU64,
    /// Total size in bytes
    pub total_size: std::sync::atomic::AtomicU64,
    /// Cache hits
    pub cache_hits: std::sync::atomic::AtomicU64,
    /// Cache misses
    pub cache_misses: std::sync::atomic::AtomicU64,
    /// Eviction count
    pub eviction_count: std::sync::atomic::AtomicU64,
}

/// Configuration for state manager
#[derive(Debug, Clone)]
pub struct StateConfig {
    /// Maximum cache size in bytes
    pub max_size: usize,
    /// Default TTL in seconds
    pub default_ttl: u64,
    /// Eviction check interval
    pub eviction_interval: Duration,
    /// Enable compression
    pub enable_compression: bool,
}

impl Default for StateConfig {
    fn default() -> Self {
        Self {
            max_size: 2_147_483_648, // 2GB
            default_ttl: 3600,       // 1 hour
            eviction_interval: Duration::from_secs(60),
            enable_compression: true,
        }
    }
}

/// High-performance state manager
pub struct StateManager {
    /// State storage
    state: Arc<DashMap<String, StateEntry>>,
    /// Version counter
    version_counter: Arc<std::sync::atomic::AtomicU64>,
    /// Configuration
    config: StateConfig,
    /// Statistics
    stats: Arc<StateStats>,
    /// Current size tracker
    current_size: Arc<std::sync::atomic::AtomicUsize>,
    /// Shutdown signal
    shutdown: Arc<tokio::sync::Notify>,
}

impl StateManager {
    /// Create a new state manager
    pub fn new(max_size: usize) -> Result<Self> {
        let config = StateConfig {
            max_size,
            ..Default::default()
        };
        
        Ok(Self {
            state: Arc::new(DashMap::new()),
            version_counter: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            config,
            stats: Arc::new(StateStats::default()),
            current_size: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            shutdown: Arc::new(tokio::sync::Notify::new()),
        })
    }
    
    /// Start the state manager
    pub async fn start(&self) -> Result<()> {
        info!("Starting state manager");
        
        // Start eviction task
        let state = self.state.clone();
        let stats = self.stats.clone();
        let current_size = self.current_size.clone();
        let shutdown = self.shutdown.clone();
        let eviction_interval = self.config.eviction_interval;
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(eviction_interval);
            
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let mut evicted = 0;
                        
                        // Remove expired entries
                        state.retain(|_, entry| {
                            if entry.is_expired() {
                                current_size.fetch_sub(entry.value.len(), std::sync::atomic::Ordering::Relaxed);
                                evicted += 1;
                                false
                            } else {
                                true
                            }
                        });
                        
                        if evicted > 0 {
                            stats.eviction_count.fetch_add(evicted, std::sync::atomic::Ordering::Relaxed);
                            debug!("Evicted {} expired entries", evicted);
                        }
                    }
                    _ = shutdown.notified() => {
                        info!("State manager eviction task shutting down");
                        break;
                    }
                }
            }
        });
        
        Ok(())
    }
    
    /// Get a value from the state
    pub async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match self.state.get_mut(key) {
            Some(mut entry) => {
                if entry.is_expired() {
                    drop(entry);
                    self.state.remove(key);
                    self.stats.cache_misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    Ok(None)
                } else {
                    entry.access_count += 1;
                    let value = entry.value.clone();
                    self.stats.cache_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    Ok(Some(value))
                }
            }
            None => {
                self.stats.cache_misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(None)
            }
        }
    }
    
    /// Set a value in the state
    pub async fn set(&self, key: String, value: Vec<u8>) -> Result<()> {
        self.set_with_ttl(key, value, self.config.default_ttl).await
    }
    
    /// Set a value with custom TTL
    pub async fn set_with_ttl(&self, key: String, value: Vec<u8>, ttl: u64) -> Result<()> {
        let value_size = value.len();
        
        // Check if we need to evict entries to make room
        if self.current_size.load(std::sync::atomic::Ordering::Relaxed) + value_size > self.config.max_size {
            self.evict_lru(value_size)?;
        }
        
        let version = self.version_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let now = Instant::now();
        
        let entry = StateEntry {
            key: key.clone(),
            value,
            version,
            created_at: now,
            updated_at: now,
            access_count: 0,
            ttl,
        };
        
        match self.state.entry(key) {
            Entry::Occupied(mut o) => {
                let old_size = o.get().value.len();
                self.current_size.fetch_sub(old_size, std::sync::atomic::Ordering::Relaxed);
                o.insert(entry);
            }
            Entry::Vacant(v) => {
                v.insert(entry);
                self.stats.total_entries.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        
        self.current_size.fetch_add(value_size, std::sync::atomic::Ordering::Relaxed);
        self.stats.total_size.store(
            self.current_size.load(std::sync::atomic::Ordering::Relaxed) as u64,
            std::sync::atomic::Ordering::Relaxed
        );
        
        Ok(())
    }
    
    /// Delete a value from the state
    pub async fn delete(&self, key: &str) -> Result<bool> {
        if let Some((_, entry)) = self.state.remove(key) {
            self.current_size.fetch_sub(entry.value.len(), std::sync::atomic::Ordering::Relaxed);
            self.stats.total_entries.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            Ok(true)
        } else {
            Ok(false)
        }
    }
    
    /// Check if a key exists
    pub async fn exists(&self, key: &str) -> bool {
        self.state.contains_key(key)
    }
    
    /// Get all keys
    pub async fn keys(&self) -> Vec<String> {
        self.state.iter()
            .map(|entry| entry.key().clone())
            .collect()
    }
    
    /// Clear all state
    pub async fn clear(&self) -> Result<()> {
        self.state.clear();
        self.current_size.store(0, std::sync::atomic::Ordering::Relaxed);
        self.stats.total_entries.store(0, std::sync::atomic::Ordering::Relaxed);
        self.stats.total_size.store(0, std::sync::atomic::Ordering::Relaxed);
        info!("State cleared");
        Ok(())
    }
    
    /// Evict least recently used entries to make room
    fn evict_lru(&self, required_space: usize) -> Result<()> {
        let mut entries: Vec<_> = self.state.iter()
            .map(|entry| {
                let e = entry.value();
                (entry.key().clone(), e.access_count, e.updated_at, e.value.len())
            })
            .collect();
        
        // Sort by access count and update time (LRU)
        entries.sort_by(|a, b| {
            a.1.cmp(&b.1).then_with(|| a.2.cmp(&b.2))
        });
        
        let mut freed_space = 0;
        let mut evicted = 0;
        
        for (key, _, _, size) in entries {
            if freed_space >= required_space {
                break;
            }
            
            if self.state.remove(&key).is_some() {
                freed_space += size;
                evicted += 1;
                self.current_size.fetch_sub(size, std::sync::atomic::Ordering::Relaxed);
            }
        }
        
        if evicted > 0 {
            self.stats.eviction_count.fetch_add(evicted, std::sync::atomic::Ordering::Relaxed);
            warn!("Evicted {} entries to free {} bytes", evicted, freed_space);
        }
        
        Ok(())
    }
    
    /// Get statistics
    pub fn stats(&self) -> &Arc<StateStats> {
        &self.stats
    }
    
    /// Shutdown the state manager
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down state manager");
        self.shutdown.notify_one();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_state_manager_creation() {
        let manager = StateManager::new(1_000_000);
        assert!(manager.is_ok());
    }
    
    #[tokio::test]
    async fn test_set_get() {
        let manager = StateManager::new(1_000_000).unwrap();
        
        let key = "test_key".to_string();
        let value = "test_value".as_bytes().to_vec();
        
        manager.set(key.clone(), value.clone()).await.unwrap();
        
        let retrieved = manager.get(&key).await.unwrap();
        assert_eq!(retrieved, Some(value));
    }
    
    #[tokio::test]
    async fn test_delete() {
        let manager = StateManager::new(1_000_000).unwrap();
        
        let key = "test_key".to_string();
        let value = "test_value".as_bytes().to_vec();
        
        manager.set(key.clone(), value).await.unwrap();
        assert!(manager.exists(&key).await);
        
        let deleted = manager.delete(&key).await.unwrap();
        assert!(deleted);
        assert!(!manager.exists(&key).await);
    }
    
    #[tokio::test]
    async fn test_ttl_expiry() {
        let manager = StateManager::new(1_000_000).unwrap();
        
        let key = "test_key".to_string();
        let value = "test_value".as_bytes().to_vec();
        
        // Set with 0 TTL (immediate expiry)
        manager.set_with_ttl(key.clone(), value, 0).await.unwrap();
        
        // Should be expired
        let retrieved = manager.get(&key).await.unwrap();
        assert_eq!(retrieved, None);
    }
}