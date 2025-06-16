use parking_lot::{Mutex, RwLock};
use std::alloc::{alloc, dealloc, Layout};
use std::collections::HashMap;
use std::ptr::NonNull;
use std::sync::Arc;
use thiserror::Error;

const GB: usize = 1024 * 1024 * 1024;
const QUALITY_MEMORY_SIZE: usize = 2 * GB; // 2GB for quality server

#[derive(Error, Debug)]
pub enum MemoryError {
    #[error("Out of memory: requested {requested}, available {available}")]
    OutOfMemory { requested: usize, available: usize },
    
    #[error("Invalid allocation size: {0}")]
    InvalidSize(usize),
    
    #[error("Memory already allocated at key: {0}")]
    AlreadyAllocated(String),
}

pub struct MemoryPool<const SIZE: usize> {
    memory: NonNull<u8>,
    layout: Layout,
    allocations: Arc<RwLock<HashMap<String, MemoryRegion>>>,
    free_list: Arc<Mutex<Vec<MemoryRegion>>>,
    used: Arc<RwLock<usize>>,
}

#[derive(Clone, Debug)]
struct MemoryRegion {
    offset: usize,
    size: usize,
}

impl<const SIZE: usize> MemoryPool<SIZE> {
    pub fn new() -> Result<Self, MemoryError> {
        let layout = Layout::from_size_align(SIZE, 64)
            .map_err(|_| MemoryError::InvalidSize(SIZE))?;
        
        let memory = unsafe {
            let ptr = alloc(layout);
            NonNull::new(ptr).ok_or(MemoryError::OutOfMemory {
                requested: SIZE,
                available: 0,
            })?
        };
        
        // Initialize with one large free region
        let mut free_list = vec![MemoryRegion { offset: 0, size: SIZE }];
        
        Ok(Self {
            memory,
            layout,
            allocations: Arc::new(RwLock::new(HashMap::new())),
            free_list: Arc::new(Mutex::new(free_list)),
            used: Arc::new(RwLock::new(0)),
        })
    }
    
    pub fn allocate(&self, key: String, size: usize) -> Result<*mut u8, MemoryError> {
        if size == 0 || size > SIZE {
            return Err(MemoryError::InvalidSize(size));
        }
        
        // Check if already allocated
        if self.allocations.read().contains_key(&key) {
            return Err(MemoryError::AlreadyAllocated(key));
        }
        
        // Find suitable free region
        let mut free_list = self.free_list.lock();
        let region_idx = free_list
            .iter()
            .position(|r| r.size >= size)
            .ok_or(MemoryError::OutOfMemory {
                requested: size,
                available: self.available(),
            })?;
        
        let mut region = free_list.remove(region_idx);
        
        // Split region if necessary
        if region.size > size {
            free_list.push(MemoryRegion {
                offset: region.offset + size,
                size: region.size - size,
            });
            region.size = size;
        }
        
        // Record allocation
        self.allocations.write().insert(key, region.clone());
        *self.used.write() += size;
        
        // Return pointer to allocated region
        unsafe {
            Ok(self.memory.as_ptr().add(region.offset))
        }
    }
    
    pub fn deallocate(&self, key: &str) -> Result<(), MemoryError> {
        let region = self.allocations.write().remove(key)
            .ok_or(MemoryError::InvalidSize(0))?;
        
        *self.used.write() -= region.size;
        
        // Add back to free list and coalesce
        let mut free_list = self.free_list.lock();
        free_list.push(region);
        free_list.sort_by_key(|r| r.offset);
        
        // Coalesce adjacent free regions
        let mut i = 0;
        while i < free_list.len() - 1 {
            if free_list[i].offset + free_list[i].size == free_list[i + 1].offset {
                free_list[i].size += free_list[i + 1].size;
                free_list.remove(i + 1);
            } else {
                i += 1;
            }
        }
        
        Ok(())
    }
    
    pub fn used(&self) -> usize {
        *self.used.read()
    }
    
    pub fn available(&self) -> usize {
        SIZE - self.used()
    }
    
    pub fn utilization(&self) -> f64 {
        self.used() as f64 / SIZE as f64
    }
}

impl<const SIZE: usize> Drop for MemoryPool<SIZE> {
    fn drop(&mut self) {
        unsafe {
            dealloc(self.memory.as_ptr(), self.layout);
        }
    }
}

// Quality-specific memory allocations
pub struct QualityMemoryAllocator {
    pool: Arc<MemoryPool<QUALITY_MEMORY_SIZE>>,
}

impl QualityMemoryAllocator {
    pub fn new() -> Result<Self, MemoryError> {
        Ok(Self {
            pool: Arc::new(MemoryPool::new()?),
        })
    }
    
    pub fn allocate_test_history(&self, size: usize) -> Result<*mut u8, MemoryError> {
        self.pool.allocate("test_history".to_string(), size)
    }
    
    pub fn allocate_coverage_data(&self, size: usize) -> Result<*mut u8, MemoryError> {
        self.pool.allocate("coverage_data".to_string(), size)
    }
    
    pub fn allocate_performance_profiles(&self, size: usize) -> Result<*mut u8, MemoryError> {
        self.pool.allocate("performance_profiles".to_string(), size)
    }
    
    pub fn allocate_quality_metrics(&self, size: usize) -> Result<*mut u8, MemoryError> {
        self.pool.allocate("quality_metrics".to_string(), size)
    }
    
    pub fn memory_stats(&self) -> MemoryStats {
        MemoryStats {
            total: QUALITY_MEMORY_SIZE,
            used: self.pool.used(),
            available: self.pool.available(),
            utilization: self.pool.utilization(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MemoryStats {
    pub total: usize,
    pub used: usize,
    pub available: usize,
    pub utilization: f64,
}

unsafe impl<const SIZE: usize> Send for MemoryPool<SIZE> {}
unsafe impl<const SIZE: usize> Sync for MemoryPool<SIZE> {}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_memory_allocation() {
        let pool = MemoryPool::<1024>::new().unwrap();
        
        let ptr1 = pool.allocate("test1".to_string(), 256).unwrap();
        assert_eq!(pool.used(), 256);
        
        let ptr2 = pool.allocate("test2".to_string(), 512).unwrap();
        assert_eq!(pool.used(), 768);
        
        pool.deallocate("test1").unwrap();
        assert_eq!(pool.used(), 512);
    }
}