//! Memory Management Module
//! 
//! Custom memory pool allocator with arena allocation for O(1) performance.

use std::sync::Arc;
use parking_lot::{RwLock, Mutex};
use dashmap::DashMap;
use bytes::{Bytes, BytesMut};
use anyhow::{Result, anyhow};
use std::alloc::{Layout, GlobalAlloc};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Memory arena for fast allocation
pub struct Arena {
    buffer: Vec<u8>,
    offset: AtomicUsize,
    size: usize,
}

impl Arena {
    /// Create a new arena with specified size in MB
    pub fn new(size_mb: usize) -> Result<Self> {
        let size = size_mb * 1024 * 1024;
        let mut buffer = Vec::with_capacity(size);
        buffer.resize(size, 0);
        
        Ok(Self {
            buffer,
            offset: AtomicUsize::new(0),
            size,
        })
    }
    
    /// Allocate memory from the arena - O(1) operation
    #[inline(always)]
    pub fn allocate(&self, size: usize, align: usize) -> Option<NonNull<u8>> {
        let aligned_size = (size + align - 1) & !(align - 1);
        
        loop {
            let current = self.offset.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release;
            let aligned_offset = (current + align - 1) & !(align - 1);
            let new_offset = aligned_offset + aligned_size;
            
            if new_offset > self.size {
                return None; // Arena full
            }
            
            if self.offset.compare_exchange(
                current,
                new_offset,
                Ordering::Release,
                Ordering::Relaxed
            ).is_ok() {
                let ptr = unsafe {
                    self.buffer.as_ptr().add(aligned_offset) as *mut u8
                };
                return NonNull::new(ptr);
            }
        }
    }
    
    /// Reset the arena for reuse
    pub fn reset(&self) {
        self.offset.store(0, Ordering::Release);
    }
    
    /// Get current usage
    pub fn usage(&self) -> usize {
        self.offset.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release
    }
}

/// Memory pool with working memory and learning storage
pub struct MemoryPool {
    /// Fast working memory using arena allocation
    working_memory: Arc<RwLock<Arena>>,
    
    /// Persistent learning storage
    learning_storage: Arc<DashMap<String, Bytes>>,
    
    /// Memory statistics
    stats: Arc<MemoryStats>,
    
    /// Total pool size
    total_size_mb: usize,
}

struct MemoryStats {
    allocations: AtomicUsize,
    deallocations: AtomicUsize,
    working_memory_usage: AtomicUsize,
    learning_storage_usage: AtomicUsize,
}

impl MemoryPool {
    /// Create a new memory pool
    pub fn new(total_size_mb: usize) -> Result<Self> {
        // Split memory: 80% working, 20% learning storage
        let working_size_mb = (total_size_mb * 8) / 10;
        
        let working_memory = Arc::new(RwLock::new(Arena::new(working_size_mb)?));
        let learning_storage = Arc::new(DashMap::new());
        
        Ok(Self {
            working_memory,
            learning_storage,
            stats: Arc::new(MemoryStats {
                allocations: AtomicUsize::new(0),
                deallocations: AtomicUsize::new(0),
                working_memory_usage: AtomicUsize::new(0),
                learning_storage_usage: AtomicUsize::new(0),
            }),
            total_size_mb,
        })
    }
    
    /// Allocate from working memory - O(1)
    #[inline(always)]
    pub fn allocate_working(&self, size: usize) -> Option<NonNull<u8>> {
        let arena = self.working_memory.read();
        let result = arena.allocate(size, 8);
        
        if result.is_some() {
            self.stats.allocations.fetch_add(1, Ordering::Relaxed);
            self.stats.working_memory_usage.fetch_add(size, Ordering::Relaxed);
        }
        
        result
    }
    
    /// Store in learning storage
    pub fn store_learning(&self, key: String, data: Vec<u8>) -> Result<()> {
        let bytes = Bytes::from(data);
        let size = bytes.len();
        
        self.learning_storage.insert(key, bytes);
        self.stats.learning_storage_usage.fetch_add(size, Ordering::Relaxed);
        
        Ok(())
    }
    
    /// Retrieve from learning storage
    pub fn get_learning(&self, key: &str) -> Option<Bytes> {
        self.learning_storage.get(key).map(|v| v.clone())
    }
    
    /// Reset working memory
    pub fn reset_working(&self) {
        let mut arena = self.working_memory.write();
        arena.reset();
        self.stats.working_memory_usage.store(0, Ordering::Release);
    }
    
    /// Get memory usage in MB
    pub fn get_usage_mb(&self) -> f64 {
        let working = self.stats.working_memory_usage.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release;
        let learning = self.stats.learning_storage_usage.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release;
        (working + learning) as f64 / (1024.0 * 1024.0)
    }
    
    /// Get detailed statistics
    pub fn get_stats(&self) -> MemoryPoolStats {
        MemoryPoolStats {
            allocations: self.stats.allocations.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release,
            deallocations: self.stats.deallocations.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release,
            working_memory_mb: self.stats.working_memory_usage.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release as f64 / (1024.0 * 1024.0),
            learning_storage_mb: self.stats.learning_storage_usage.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release as f64 / (1024.0 * 1024.0),
            total_size_mb: self.total_size_mb,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MemoryPoolStats {
    pub allocations: usize,
    pub deallocations: usize,
    pub working_memory_mb: f64,
    pub learning_storage_mb: f64,
    pub total_size_mb: usize,
}

/// Fast buffer pool for temporary allocations
pub struct BufferPool {
    small_buffers: Arc<Mutex<Vec<BytesMut>>>,  // <= 4KB
    medium_buffers: Arc<Mutex<Vec<BytesMut>>>, // <= 64KB
    large_buffers: Arc<Mutex<Vec<BytesMut>>>,  // <= 1MB
}

impl BufferPool {
    pub fn new() -> Self {
        Self {
            small_buffers: Arc::new(Mutex::new(Vec::with_capacity(100))),
            medium_buffers: Arc::new(Mutex::new(Vec::with_capacity(50))),
            large_buffers: Arc::new(Mutex::new(Vec::with_capacity(10))),
        }
    }
    
    /// Get a buffer of at least the specified size
    #[inline(always)]
    pub fn get(&self, size: usize) -> BytesMut {
        if size <= 4096 {
            if let Some(buf) = self.small_buffers.lock().pop() {
                return buf;
            }
            BytesMut::with_capacity(4096)
        } else if size <= 65536 {
            if let Some(buf) = self.medium_buffers.lock().pop() {
                return buf;
            }
            BytesMut::with_capacity(65536)
        } else if size <= 1048576 {
            if let Some(buf) = self.large_buffers.lock().pop() {
                return buf;
            }
            BytesMut::with_capacity(1048576)
        } else {
            BytesMut::with_capacity(size)
        }
    }
    
    /// Return a buffer to the pool
    #[inline(always)]
    pub fn put(&self, mut buf: BytesMut) {
        buf.clear();
        let capacity = buf.capacity();
        
        if capacity <= 4096 {
            let mut pool = self.small_buffers.lock();
            if pool.len() < 100 {
                pool.push(buf);
            }
        } else if capacity <= 65536 {
            let mut pool = self.medium_buffers.lock();
            if pool.len() < 50 {
                pool.push(buf);
            }
        } else if capacity <= 1048576 {
            let mut pool = self.large_buffers.lock();
            if pool.len() < 10 {
                pool.push(buf);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_arena_allocation() {
        let arena = Arena::new(1).unwrap();
        
        // Test allocation
        let ptr1 = arena.allocate(100, 8).unwrap();
        let ptr2 = arena.allocate(200, 8).unwrap();
        
        assert_ne!(ptr1.as_ptr(), ptr2.as_ptr());
        assert!(arena.usage() >= 300);
    }
    
    #[test]
    fn test_memory_pool() {
        let pool = MemoryPool::new(10).unwrap();
        
        // Test working memory allocation
        let ptr = pool.allocate_working(1024).unwrap();
        assert!(!ptr.as_ptr().is_null());
        
        // Test learning storage
        pool.store_learning("test".to_string(), vec![1, 2, 3, 4]).unwrap();
        let data = pool.get_learning("test").unwrap();
        assert_eq!(data.as_ref(), &[1, 2, 3, 4]);
        
        // Check stats
        let stats = pool.get_stats();
        assert!(stats.allocations > 0);
        assert!(stats.working_memory_mb > 0.0);
    }
    
    #[test]
    fn test_buffer_pool() {
        let pool = BufferPool::new();
        
        let buf1 = pool.get(100);
        assert!(buf1.capacity() >= 100);
        
        pool.put(buf1);
        
        let buf2 = pool.get(100);
        assert!(buf2.capacity() >= 100);
    }
}