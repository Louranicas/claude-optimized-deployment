use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use parking_lot::{RwLock, Mutex};
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow};

const PAGE_SIZE: usize = 4096; // 4KB pages
const INITIAL_POOL_SIZE: usize = 1024 * 1024 * 512; // 512MB initial allocation

#[derive(Debug)]
pub struct MemoryPool<const SIZE: usize> {
    allocated: AtomicUsize,
    pages: Arc<RwLock<Vec<Page>>>,
    free_pages: Arc<Mutex<Vec<PageId>>>,
    allocations: Arc<DashMap<AllocationId, Allocation>>,
    next_allocation_id: AtomicUsize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PageId(usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AllocationId(usize);

#[derive(Debug)]
struct Page {
    id: PageId,
    data: Vec<u8>,
    in_use: bool,
}

#[derive(Debug, Clone)]
struct Allocation {
    id: AllocationId,
    pages: Vec<PageId>,
    size: usize,
}

impl<const SIZE: usize> MemoryPool<SIZE> {
    pub fn new() -> Self {
        let initial_pages = INITIAL_POOL_SIZE / PAGE_SIZE;
        let mut pages = Vec::with_capacity(initial_pages);
        let mut free_pages = Vec::with_capacity(initial_pages);
        
        for i in 0..initial_pages {
            let page_id = PageId(i);
            pages.push(Page {
                id: page_id,
                data: vec![0u8; PAGE_SIZE],
                in_use: false,
            });
            free_pages.push(page_id);
        }
        
        Self {
            allocated: AtomicUsize::new(0),
            pages: Arc::new(RwLock::new(pages)),
            free_pages: Arc::new(Mutex::new(free_pages)),
            allocations: Arc::new(DashMap::new()),
            next_allocation_id: AtomicUsize::new(0),
        }
    }
    
    pub fn allocate(&self, size: usize) -> Result<AllocationId> {
        let pages_needed = (size + PAGE_SIZE - 1) / PAGE_SIZE;
        let current_allocated = self.allocated.load(Ordering::Acquire);
        
        if current_allocated + size > SIZE {
            return Err(anyhow!("Memory pool exhausted: requested {} bytes, {} available", 
                size, SIZE - current_allocated));
        }
        
        let mut free_pages = self.free_pages.lock();
        if free_pages.len() < pages_needed {
            drop(free_pages);
            self.expand_pool(pages_needed)?;
            free_pages = self.free_pages.lock();
        }
        
        let mut allocated_pages = Vec::with_capacity(pages_needed);
        for _ in 0..pages_needed {
            if let Some(page_id) = free_pages.pop() {
                allocated_pages.push(page_id);
            } else {
                // Return pages if allocation fails
                for page_id in allocated_pages {
                    free_pages.push(page_id);
                }
                return Err(anyhow!("Failed to allocate {} pages", pages_needed));
            }
        }
        
        drop(free_pages);
        
        // Mark pages as in use
        let mut pages = self.pages.write();
        for &page_id in &allocated_pages {
            pages[page_id.0].in_use = true;
        }
        drop(pages);
        
        let allocation_id = AllocationId(self.next_allocation_id.fetch_add(1, Ordering::SeqCst));
        let allocation = Allocation {
            id: allocation_id,
            pages: allocated_pages,
            size,
        };
        
        self.allocations.insert(allocation_id, allocation);
        self.allocated.fetch_add(size, Ordering::Release);
        
        Ok(allocation_id)
    }
    
    pub fn deallocate(&self, allocation_id: AllocationId) -> Result<()> {
        if let Some((_, allocation)) = self.allocations.remove(&allocation_id) {
            let mut pages = self.pages.write();
            let mut free_pages = self.free_pages.lock();
            
            for page_id in allocation.pages {
                pages[page_id.0].in_use = false;
                pages[page_id.0].data.fill(0); // Clear data
                free_pages.push(page_id);
            }
            
            self.allocated.fetch_sub(allocation.size, Ordering::Release);
            Ok(())
        } else {
            Err(anyhow!("Invalid allocation ID: {:?}", allocation_id))
        }
    }
    
    pub fn read(&self, allocation_id: AllocationId) -> Result<Vec<u8>> {
        if let Some(allocation) = self.allocations.get(&allocation_id) {
            let pages = self.pages.read();
            let mut data = Vec::with_capacity(allocation.size);
            
            for &page_id in &allocation.pages {
                data.extend_from_slice(&pages[page_id.0].data);
            }
            
            data.truncate(allocation.size);
            Ok(data)
        } else {
            Err(anyhow!("Invalid allocation ID: {:?}", allocation_id))
        }
    }
    
    pub fn write(&self, allocation_id: AllocationId, data: &[u8]) -> Result<()> {
        if let Some(allocation) = self.allocations.get(&allocation_id) {
            if data.len() > allocation.size {
                return Err(anyhow!("Data size {} exceeds allocation size {}", 
                    data.len(), allocation.size));
            }
            
            let mut pages = self.pages.write();
            let mut offset = 0;
            
            for &page_id in &allocation.pages {
                let page_data_len = std::cmp::min(PAGE_SIZE, data.len() - offset);
                if page_data_len > 0 {
                    pages[page_id.0].data[..page_data_len]
                        .copy_from_slice(&data[offset..offset + page_data_len]);
                    offset += page_data_len;
                }
                
                if offset >= data.len() {
                    break;
                }
            }
            
            Ok(())
        } else {
            Err(anyhow!("Invalid allocation ID: {:?}", allocation_id))
        }
    }
    
    fn expand_pool(&self, pages_needed: usize) -> Result<()> {
        let mut pages = self.pages.write();
        let mut free_pages = self.free_pages.lock();
        
        let current_pages = pages.len();
        let new_pages = std::cmp::max(pages_needed, current_pages / 4); // Grow by at least 25%
        
        for i in 0..new_pages {
            let page_id = PageId(current_pages + i);
            pages.push(Page {
                id: page_id,
                data: vec![0u8; PAGE_SIZE],
                in_use: false,
            });
            free_pages.push(page_id);
        }
        
        Ok(())
    }
    
    pub fn get_usage(&self) -> MemoryUsage {
        let allocated = self.allocated.load(Ordering::Acquire);
        let pages = self.pages.read();
        let total_pages = pages.len();
        let used_pages = pages.iter().filter(|p| p.in_use).count();
        
        MemoryUsage {
            allocated_bytes: allocated,
            total_bytes: SIZE,
            used_pages,
            total_pages,
            usage_percentage: (allocated as f64 / SIZE as f64) * 100.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryUsage {
    pub allocated_bytes: usize,
    pub total_bytes: usize,
    pub used_pages: usize,
    pub total_pages: usize,
    pub usage_percentage: f64,
}

// Memory-mapped structures for efficient access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedDeployment {
    pub id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub service: String,
    pub version: String,
    pub environment: String,
    pub success: bool,
    pub duration: std::time::Duration,
    pub metrics: DeploymentMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentMetrics {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub error_rate: f64,
    pub response_time: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_memory_allocation() {
        let pool: MemoryPool<1024 * 1024> = MemoryPool::new(); // 1MB pool
        
        // Allocate some memory
        let alloc1 = pool.allocate(1024).unwrap();
        let usage = pool.get_usage();
        assert_eq!(usage.allocated_bytes, 1024);
        
        // Write and read data
        let data = vec![42u8; 1024];
        pool.write(alloc1, &data).unwrap();
        let read_data = pool.read(alloc1).unwrap();
        assert_eq!(read_data, data);
        
        // Deallocate
        pool.deallocate(alloc1).unwrap();
        let usage = pool.get_usage();
        assert_eq!(usage.allocated_bytes, 0);
    }
}