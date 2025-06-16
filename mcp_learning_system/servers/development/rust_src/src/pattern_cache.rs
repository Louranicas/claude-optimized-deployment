use dashmap::DashMap;
use lru::LruCache;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::{Duration, Instant};
use blake3::Hasher;
use bincode;
use crate::code_analyzer::CodePattern;

const CACHE_SIZE: usize = 10_000;
const PATTERN_TTL: Duration = Duration::from_secs(3600); // 1 hour

#[derive(Clone)]
pub struct PatternCache {
    patterns: Arc<DashMap<String, CachedPattern>>,
    lru: Arc<Mutex<LruCache<String, ()>>>,
    stats: Arc<CacheStats>,
}

#[derive(Debug, Clone)]
struct CachedPattern {
    pattern: CodePattern,
    created_at: Instant,
    access_count: u32,
    last_accessed: Instant,
}

#[derive(Debug, Default)]
struct CacheStats {
    hits: std::sync::atomic::AtomicU64,
    misses: std::sync::atomic::AtomicU64,
    evictions: std::sync::atomic::AtomicU64,
}

impl PatternCache {
    pub fn new() -> Self {
        Self {
            patterns: Arc::new(DashMap::new()),
            lru: Arc::new(Mutex::new(LruCache::new(CACHE_SIZE.try_into().unwrap()))),
            stats: Arc::new(CacheStats::default()),
        }
    }

    pub fn get(&self, context: &str) -> Option<CodePattern> {
        let key = self.hash_context(context);
        
        if let Some(mut entry) = self.patterns.get_mut(&key) {
            let now = Instant::now();
            
            // Check TTL
            if now.duration_since(entry.created_at) > PATTERN_TTL {
                drop(entry);
                self.patterns.remove(&key);
                self.stats.misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return None;
            }
            
            // Update access info
            entry.access_count += 1;
            entry.last_accessed = now;
            
            // Update LRU
            self.lru.lock().get(&key);
            
            self.stats.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Some(entry.pattern.clone())
        } else {
            self.stats.misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            None
        }
    }

    pub fn insert(&self, context: &str, pattern: CodePattern) {
        let key = self.hash_context(context);
        let now = Instant::now();
        
        // Check if we need to evict
        if self.patterns.len() >= CACHE_SIZE {
            self.evict_lru();
        }
        
        let cached = CachedPattern {
            pattern,
            created_at: now,
            access_count: 1,
            last_accessed: now,
        };
        
        self.patterns.insert(key.clone(), cached);
        self.lru.lock().put(key, ());
    }

    pub fn update_frequency(&self, context: &str, increment: u32) {
        let key = self.hash_context(context);
        
        if let Some(mut entry) = self.patterns.get_mut(&key) {
            entry.pattern.frequency += increment;
            entry.last_accessed = Instant::now();
        }
    }

    pub fn get_hot_patterns(&self, limit: usize) -> Vec<CodePattern> {
        let mut patterns: Vec<_> = self.patterns.iter()
            .map(|entry| (entry.value().clone(), entry.value().access_count))
            .collect();
        
        patterns.sort_by(|a, b| b.1.cmp(&a.1));
        
        patterns.into_iter()
            .take(limit)
            .map(|(cached, _)| cached.pattern)
            .collect()
    }

    pub fn get_recent_patterns(&self, limit: usize) -> Vec<CodePattern> {
        let mut patterns: Vec<_> = self.patterns.iter()
            .map(|entry| (entry.value().clone(), entry.value().last_accessed))
            .collect();
        
        patterns.sort_by(|a, b| b.1.cmp(&a.1));
        
        patterns.into_iter()
            .take(limit)
            .map(|(cached, _)| cached.pattern)
            .collect()
    }

    pub fn serialize_to_disk(&self, path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
        let patterns: Vec<(String, CodePattern)> = self.patterns.iter()
            .map(|entry| (entry.key().clone(), entry.value().pattern.clone()))
            .collect();
        
        let serialized = bincode::serialize(&patterns)?;
        std::fs::write(path, serialized)?;
        Ok(())
    }

    pub fn load_from_disk(&self, path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
        let data = std::fs::read(path)?;
        let patterns: Vec<(String, CodePattern)> = bincode::deserialize(&data)?;
        
        let now = Instant::now();
        for (key, pattern) in patterns {
            let cached = CachedPattern {
                pattern,
                created_at: now,
                access_count: 0,
                last_accessed: now,
            };
            self.patterns.insert(key, cached);
        }
        
        Ok(())
    }

    pub fn clear(&self) {
        self.patterns.clear();
        self.lru.lock().clear();
    }

    pub fn stats(&self) -> CacheStatistics {
        CacheStatistics {
            total_patterns: self.patterns.len(),
            cache_hits: self.stats.hits.load(std::sync::atomic::Ordering::Relaxed),
            cache_misses: self.stats.misses.load(std::sync::atomic::Ordering::Relaxed),
            evictions: self.stats.evictions.load(std::sync::atomic::Ordering::Relaxed),
            hit_rate: self.calculate_hit_rate(),
        }
    }

    fn hash_context(&self, context: &str) -> String {
        let mut hasher = Hasher::new();
        hasher.update(context.as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    fn evict_lru(&self) {
        let mut lru = self.lru.lock();
        
        // Evict least recently used entries
        let to_evict = CACHE_SIZE / 10; // Evict 10% when full
        
        for _ in 0..to_evict {
            if let Some((key, _)) = lru.pop_lru() {
                self.patterns.remove(&key);
                self.stats.evictions.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    fn calculate_hit_rate(&self) -> f64 {
        let hits = self.stats.hits.load(std::sync::atomic::Ordering::Relaxed);
        let misses = self.stats.misses.load(std::sync::atomic::Ordering::Relaxed);
        let total = hits + misses;
        
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CacheStatistics {
    pub total_patterns: usize,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub evictions: u64,
    pub hit_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_analyzer::{PatternType, StyleFeatures, NamingConvention};

    #[test]
    fn test_pattern_cache_basic() {
        let cache = PatternCache::new();
        
        let pattern = CodePattern {
            pattern_id: "test-123".to_string(),
            pattern_type: PatternType::FunctionSignature,
            frequency: 1,
            context_hash: "hash123".to_string(),
            ast_signature: vec![1, 2, 3],
            style_features: StyleFeatures {
                indentation: "spaces".to_string(),
                quote_style: "double".to_string(),
                semicolons: true,
                trailing_commas: false,
                bracket_spacing: true,
                naming_convention: NamingConvention::CamelCase,
            },
        };
        
        cache.insert("test context", pattern.clone());
        
        let retrieved = cache.get("test context").unwrap();
        assert_eq!(retrieved.pattern_id, pattern.pattern_id);
        
        let stats = cache.stats();
        assert_eq!(stats.cache_hits, 1);
        assert_eq!(stats.cache_misses, 0);
    }

    #[test]
    fn test_pattern_cache_eviction() {
        let cache = PatternCache::new();
        
        // Fill cache beyond capacity
        for i in 0..CACHE_SIZE + 100 {
            let pattern = CodePattern {
                pattern_id: format!("pattern-{}", i),
                pattern_type: PatternType::ImportStyle,
                frequency: 1,
                context_hash: format!("hash-{}", i),
                ast_signature: vec![i as u8],
                style_features: StyleFeatures {
                    indentation: "spaces".to_string(),
                    quote_style: "single".to_string(),
                    semicolons: false,
                    trailing_commas: true,
                    bracket_spacing: true,
                    naming_convention: NamingConvention::SnakeCase,
                },
            };
            
            cache.insert(&format!("context-{}", i), pattern);
        }
        
        // Should have evicted some patterns
        assert!(cache.patterns.len() <= CACHE_SIZE);
        assert!(cache.stats().evictions > 0);
    }
}