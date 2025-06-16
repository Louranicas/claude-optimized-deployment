use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use tokio::sync::Mutex;
use tokio::time::interval;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

/// Cache eviction policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictionPolicy {
    LRU,    // Least Recently Used
    LFU,    // Least Frequently Used
    FIFO,   // First In First Out
    Random, // Random eviction
    TTL,    // Time To Live based
}

/// Cache entry with metadata
#[derive(Debug, Clone)]
pub struct CacheEntry<V> {
    pub value: V,
    pub created_at: Instant,
    pub last_accessed: Instant,
    pub access_count: usize,
    pub ttl: Option<Duration>,
    pub size: usize,
}

/// Cache statistics
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub hits: usize,
    pub misses: usize,
    pub evictions: usize,
    pub expirations: usize,
    pub total_size: usize,
    pub entry_count: usize,
}

/// Advanced cache implementation
pub struct AdvancedCache<K, V> 
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    /// Cache storage
    storage: Arc<RwLock<HashMap<K, CacheEntry<V>>>>,
    
    /// Access order for LRU
    lru_queue: Arc<Mutex<VecDeque<K>>>,
    
    /// Frequency map for LFU
    frequency_map: Arc<RwLock<HashMap<K, usize>>>,
    
    /// FIFO queue
    fifo_queue: Arc<Mutex<VecDeque<K>>>,
    
    /// Cache configuration
    max_size: usize,
    max_entries: usize,
    default_ttl: Option<Duration>,
    eviction_policy: EvictionPolicy,
    
    /// Cache statistics
    stats: Arc<RwLock<CacheStats>>,
    
    /// TTL cleanup interval
    cleanup_interval: Duration,
}

impl<K, V> AdvancedCache<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Create a new cache
    pub fn new(
        max_size: usize,
        max_entries: usize,
        eviction_policy: EvictionPolicy,
        default_ttl: Option<Duration>,
    ) -> Self {
        let cache = Self {
            storage: Arc::new(RwLock::new(HashMap::new())),
            lru_queue: Arc::new(Mutex::new(VecDeque::new())),
            frequency_map: Arc::new(RwLock::new(HashMap::new())),
            fifo_queue: Arc::new(Mutex::new(VecDeque::new())),
            max_size,
            max_entries,
            default_ttl,
            eviction_policy,
            stats: Arc::new(RwLock::new(CacheStats::default())),
            cleanup_interval: Duration::from_secs(60),
        };
        
        // Start TTL cleanup task
        cache.start_ttl_cleanup();
        
        cache
    }
    
    /// Get a value from the cache
    pub async fn get(&self, key: &K) -> Option<V> {
        let mut storage = self.storage.write().unwrap();
        
        if let Some(entry) = storage.get_mut(key) {
            // Check TTL
            if let Some(ttl) = entry.ttl {
                if entry.created_at.elapsed() > ttl {
                    // Entry expired
                    storage.remove(key);
                    self.remove_from_tracking(key).await;
                    self.stats.write().unwrap().expirations += 1;
                    self.stats.write().unwrap().misses += 1;
                    return None;
                }
            }
            
            // Update access metadata
            entry.last_accessed = Instant::now();
            entry.access_count += 1;
            
            // Update eviction tracking
            self.update_access_tracking(key.clone()).await;
            
            self.stats.write().unwrap().hits += 1;
            Some(entry.value.clone())
        } else {
            self.stats.write().unwrap().misses += 1;
            None
        }
    }
    
    /// Put a value in the cache
    pub async fn put(&self, key: K, value: V, size: usize) -> Result<()> {
        self.put_with_ttl(key, value, size, self.default_ttl).await
    }
    
    /// Put a value with specific TTL
    pub async fn put_with_ttl(
        &self,
        key: K,
        value: V,
        size: usize,
        ttl: Option<Duration>,
    ) -> Result<()> {
        // Check if we need to evict
        while self.needs_eviction(size).await {
            self.evict_one().await?;
        }
        
        let entry = CacheEntry {
            value,
            created_at: Instant::now(),
            last_accessed: Instant::now(),
            access_count: 1,
            ttl,
            size,
        };
        
        // Update storage
        let mut storage = self.storage.write().unwrap();
        let old_entry = storage.insert(key.clone(), entry);
        
        // Update stats
        let mut stats = self.stats.write().unwrap();
        stats.entry_count = storage.len();
        stats.total_size += size;
        if let Some(old) = old_entry {
            stats.total_size -= old.size;
        }
        drop(stats);
        drop(storage);
        
        // Update eviction tracking
        self.add_to_tracking(key).await;
        
        Ok(())
    }
    
    /// Remove a value from the cache
    pub async fn remove(&self, key: &K) -> Option<V> {
        let mut storage = self.storage.write().unwrap();
        
        if let Some(entry) = storage.remove(key) {
            self.stats.write().unwrap().total_size -= entry.size;
            self.stats.write().unwrap().entry_count -= 1;
            
            drop(storage);
            self.remove_from_tracking(key).await;
            
            Some(entry.value)
        } else {
            None
        }
    }
    
    /// Clear the cache
    pub async fn clear(&self) {
        self.storage.write().unwrap().clear();
        self.lru_queue.lock().await.clear();
        self.frequency_map.write().unwrap().clear();
        self.fifo_queue.lock().await.clear();
        
        let mut stats = self.stats.write().unwrap();
        stats.total_size = 0;
        stats.entry_count = 0;
    }
    
    /// Check if eviction is needed
    async fn needs_eviction(&self, additional_size: usize) -> bool {
        let stats = self.stats.read().unwrap();
        
        stats.entry_count >= self.max_entries ||
        stats.total_size + additional_size > self.max_size
    }
    
    /// Evict one entry based on policy
    async fn evict_one(&self) -> Result<()> {
        let key_to_evict = match self.eviction_policy {
            EvictionPolicy::LRU => self.evict_lru().await?,
            EvictionPolicy::LFU => self.evict_lfu().await?,
            EvictionPolicy::FIFO => self.evict_fifo().await?,
            EvictionPolicy::Random => self.evict_random().await?,
            EvictionPolicy::TTL => self.evict_oldest().await?,
        };
        
        if let Some(key) = key_to_evict {
            self.remove(&key).await;
            self.stats.write().unwrap().evictions += 1;
        }
        
        Ok(())
    }
    
    /// Evict using LRU policy
    async fn evict_lru(&self) -> Result<Option<K>> {
        let mut queue = self.lru_queue.lock().await;
        Ok(queue.pop_front())
    }
    
    /// Evict using LFU policy
    async fn evict_lfu(&self) -> Result<Option<K>> {
        let frequency_map = self.frequency_map.read().unwrap();
        
        frequency_map.iter()
            .min_by_key(|(_, &freq)| freq)
            .map(|(k, _)| k.clone())
            .ok_or_else(|| anyhow!("No entries to evict"))
            .map(Some)
    }
    
    /// Evict using FIFO policy
    async fn evict_fifo(&self) -> Result<Option<K>> {
        let mut queue = self.fifo_queue.lock().await;
        Ok(queue.pop_front())
    }
    
    /// Evict random entry
    async fn evict_random(&self) -> Result<Option<K>> {
        let storage = self.storage.read().unwrap();
        let keys: Vec<_> = storage.keys().cloned().collect();
        
        if keys.is_empty() {
            return Ok(None);
        }
        
        use rand::Rng;
        let idx = rand::thread_rng().gen_range(0..keys.len());
        Ok(Some(keys[idx].clone()))
    }
    
    /// Evict oldest entry
    async fn evict_oldest(&self) -> Result<Option<K>> {
        let storage = self.storage.read().unwrap();
        
        storage.iter()
            .min_by_key(|(_, entry)| entry.created_at)
            .map(|(k, _)| k.clone())
            .ok_or_else(|| anyhow!("No entries to evict"))
            .map(Some)
    }
    
    /// Update access tracking for eviction policies
    async fn update_access_tracking(&self, key: K) {
        match self.eviction_policy {
            EvictionPolicy::LRU => {
                let mut queue = self.lru_queue.lock().await;
                queue.retain(|k| k != &key);
                queue.push_back(key);
            }
            EvictionPolicy::LFU => {
                let mut freq_map = self.frequency_map.write().unwrap();
                *freq_map.entry(key).or_insert(0) += 1;
            }
            _ => {}
        }
    }
    
    /// Add to tracking structures
    async fn add_to_tracking(&self, key: K) {
        match self.eviction_policy {
            EvictionPolicy::LRU => {
                self.lru_queue.lock().await.push_back(key);
            }
            EvictionPolicy::LFU => {
                self.frequency_map.write().unwrap().insert(key, 1);
            }
            EvictionPolicy::FIFO => {
                self.fifo_queue.lock().await.push_back(key);
            }
            _ => {}
        }
    }
    
    /// Remove from tracking structures
    async fn remove_from_tracking(&self, key: &K) {
        match self.eviction_policy {
            EvictionPolicy::LRU => {
                self.lru_queue.lock().await.retain(|k| k != key);
            }
            EvictionPolicy::LFU => {
                self.frequency_map.write().unwrap().remove(key);
            }
            EvictionPolicy::FIFO => {
                self.fifo_queue.lock().await.retain(|k| k != key);
            }
            _ => {}
        }
    }
    
    /// Start TTL cleanup task
    fn start_ttl_cleanup(&self) {
        let storage = self.storage.clone();
        let stats = self.stats.clone();
        let interval_duration = self.cleanup_interval;
        
        tokio::spawn(async move {
            let mut interval = interval(interval_duration);
            
            loop {
                interval.tick().await;
                
                let mut expired_keys = Vec::new();
                
                {
                    let storage_map = storage.read().unwrap();
                    for (key, entry) in storage_map.iter() {
                        if let Some(ttl) = entry.ttl {
                            if entry.created_at.elapsed() > ttl {
                                expired_keys.push(key.clone());
                            }
                        }
                    }
                }
                
                if !expired_keys.is_empty() {
                    let mut storage_map = storage.write().unwrap();
                    let mut stats_mut = stats.write().unwrap();
                    
                    for key in expired_keys {
                        if let Some(entry) = storage_map.remove(&key) {
                            stats_mut.expirations += 1;
                            stats_mut.total_size -= entry.size;
                            stats_mut.entry_count -= 1;
                        }
                    }
                }
            }
        });
    }
    
    /// Get cache statistics
    pub fn get_stats(&self) -> CacheStats {
        self.stats.read().unwrap().clone()
    }
    
    /// Get cache hit rate
    pub fn get_hit_rate(&self) -> f64 {
        let stats = self.stats.read().unwrap();
        let total = stats.hits + stats.misses;
        
        if total == 0 {
            0.0
        } else {
            stats.hits as f64 / total as f64
        }
    }
    
    /// Get current size
    pub fn get_size(&self) -> usize {
        self.stats.read().unwrap().total_size
    }
    
    /// Get entry count
    pub fn get_entry_count(&self) -> usize {
        self.stats.read().unwrap().entry_count
    }
}

/// Multi-tier cache with different policies per tier
pub struct MultiTierCache<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    tiers: Vec<Arc<AdvancedCache<K, V>>>,
}

impl<K, V> MultiTierCache<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Create a new multi-tier cache
    pub fn new() -> Self {
        Self {
            tiers: Vec::new(),
        }
    }
    
    /// Add a cache tier
    pub fn add_tier(
        &mut self,
        max_size: usize,
        max_entries: usize,
        eviction_policy: EvictionPolicy,
        default_ttl: Option<Duration>,
    ) {
        let cache = Arc::new(AdvancedCache::new(
            max_size,
            max_entries,
            eviction_policy,
            default_ttl,
        ));
        
        self.tiers.push(cache);
    }
    
    /// Get from multi-tier cache
    pub async fn get(&self, key: &K) -> Option<V> {
        for (tier_idx, tier) in self.tiers.iter().enumerate() {
            if let Some(value) = tier.get(key).await {
                // Promote to higher tiers
                for i in 0..tier_idx {
                    let _ = self.tiers[i].put(key.clone(), value.clone(), 1).await;
                }
                
                return Some(value);
            }
        }
        
        None
    }
    
    /// Put to multi-tier cache
    pub async fn put(&self, key: K, value: V, size: usize) -> Result<()> {
        // Put in first tier
        if let Some(tier) = self.tiers.first() {
            tier.put(key, value, size).await
        } else {
            Err(anyhow!("No cache tiers configured"))
        }
    }
    
    /// Get aggregated statistics
    pub fn get_stats(&self) -> Vec<CacheStats> {
        self.tiers.iter()
            .map(|tier| tier.get_stats())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_lru_cache() {
        let cache = AdvancedCache::new(100, 3, EvictionPolicy::LRU, None);
        
        // Add entries
        cache.put("a".to_string(), 1, 10).await.unwrap();
        cache.put("b".to_string(), 2, 10).await.unwrap();
        cache.put("c".to_string(), 3, 10).await.unwrap();
        
        // Access 'a' to make it recently used
        assert_eq!(cache.get(&"a".to_string()).await, Some(1));
        
        // Add 'd' which should evict 'b' (least recently used)
        cache.put("d".to_string(), 4, 10).await.unwrap();
        
        assert_eq!(cache.get(&"a".to_string()).await, Some(1));
        assert_eq!(cache.get(&"b".to_string()).await, None); // Evicted
        assert_eq!(cache.get(&"c".to_string()).await, Some(3));
        assert_eq!(cache.get(&"d".to_string()).await, Some(4));
    }
    
    #[tokio::test]
    async fn test_ttl_expiration() {
        let cache = AdvancedCache::new(100, 10, EvictionPolicy::LRU, None);
        
        // Add entry with short TTL
        cache.put_with_ttl(
            "temp".to_string(),
            42,
            10,
            Some(Duration::from_millis(100))
        ).await.unwrap();
        
        // Should exist immediately
        assert_eq!(cache.get(&"temp".to_string()).await, Some(42));
        
        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(150)).await;
        
        // Should be expired
        assert_eq!(cache.get(&"temp".to_string()).await, None);
        
        let stats = cache.get_stats();
        assert_eq!(stats.expirations, 1);
    }
    
    #[tokio::test]
    async fn test_cache_stats() {
        let cache = AdvancedCache::new(100, 10, EvictionPolicy::LRU, None);
        
        cache.put("hit".to_string(), 1, 10).await.unwrap();
        
        // Generate hits
        cache.get(&"hit".to_string()).await;
        cache.get(&"hit".to_string()).await;
        
        // Generate misses
        cache.get(&"miss".to_string()).await;
        cache.get(&"miss".to_string()).await;
        
        let stats = cache.get_stats();
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 2);
        
        let hit_rate = cache.get_hit_rate();
        assert_eq!(hit_rate, 0.5);
    }
    
    #[tokio::test]
    async fn test_multi_tier_cache() {
        let mut multi_cache = MultiTierCache::new();
        
        // L1: Small, fast cache
        multi_cache.add_tier(50, 5, EvictionPolicy::LRU, Some(Duration::from_secs(60)));
        
        // L2: Larger, slower cache
        multi_cache.add_tier(200, 20, EvictionPolicy::LFU, Some(Duration::from_secs(300)));
        
        // Put in L1
        multi_cache.put("key".to_string(), "value", 10).await.unwrap();
        
        // Get should find in L1
        assert_eq!(multi_cache.get(&"key".to_string()).await, Some("value"));
        
        let stats = multi_cache.get_stats();
        assert_eq!(stats.len(), 2);
    }
}