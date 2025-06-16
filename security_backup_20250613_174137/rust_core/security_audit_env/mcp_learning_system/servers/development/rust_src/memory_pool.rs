use std::alloc::{Allocator, Layout, AllocError};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering};
use parking_lot::Mutex;
use crossbeam::queue::ArrayQueue;

const CHUNK_SIZE: usize = 1024 * 1024; // 1MB chunks
const MAX_CACHED_CHUNKS: usize = 100;

pub struct MemoryPool<const SIZE: usize> {
    total_allocated: AtomicUsize,
    free_chunks: ArrayQueue<Box<[u8; CHUNK_SIZE]>>,
    allocator: Mutex<BuddyAllocator>,
}

impl<const SIZE: usize> MemoryPool<SIZE> {
    pub fn new() -> Self {
        Self {
            total_allocated: AtomicUsize::new(0),
            free_chunks: ArrayQueue::new(MAX_CACHED_CHUNKS),
            allocator: Mutex::new(BuddyAllocator::new(SIZE)),
        }
    }

    pub fn allocate(&self, size: usize) -> Option<NonNull<u8>> {
        if size <= CHUNK_SIZE {
            // Try to get from cache
            if let Some(chunk) = self.free_chunks.pop() {
                let ptr = Box::into_raw(chunk) as *mut u8;
                self.total_allocated.fetch_add(CHUNK_SIZE, Ordering::Relaxed);
                return NonNull::new(ptr);
            }
        }

        // Allocate new memory
        let current = self.total_allocated.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release;
        if current + size > SIZE {
            return None;
        }

        let mut allocator = self.allocator.lock();
        allocator.allocate(size).map(|ptr| {
            self.total_allocated.fetch_add(size, Ordering::Relaxed);
            ptr
        })
    }

    pub fn deallocate(&self, ptr: NonNull<u8>, size: usize) {
        if size == CHUNK_SIZE {
            // Try to cache the chunk
            let chunk = unsafe { Box::from_raw(ptr.as_ptr() as *mut [u8; CHUNK_SIZE]) };
            if self.free_chunks.push(chunk).is_err() {
                // Cache is full, actually deallocate
                drop(chunk);
            }
            self.total_allocated.fetch_sub(CHUNK_SIZE, Ordering::Relaxed);
            return;
        }

        let mut allocator = self.allocator.lock();
        allocator.deallocate(ptr, size);
        self.total_allocated.fetch_sub(size, Ordering::Relaxed);
    }

    pub fn used_memory(&self) -> usize {
        self.total_allocated.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release
    }

    pub fn available_memory(&self) -> usize {
        SIZE - self.used_memory()
    }
}

struct BuddyAllocator {
    base: NonNull<u8>,
    size: usize,
    free_lists: Vec<Vec<usize>>,
}

impl BuddyAllocator {
    fn new(size: usize) -> Self {
        let layout = Layout::from_size_align(size, 16).unwrap();
        let base = unsafe {
            let ptr = std::alloc::alloc(layout);
            NonNull::new(ptr).expect("Failed to allocate memory pool")
        };

        let levels = (size.trailing_zeros() + 1) as usize;
        let mut free_lists = vec![Vec::new(); levels];
        free_lists[levels - 1].push(0);

        Self {
            base,
            size,
            free_lists,
        }
    }

    fn allocate(&mut self, size: usize) -> Option<NonNull<u8>> {
        let level = self.size_to_level(size)?;
        let block_offset = self.find_free_block(level)?;
        
        unsafe {
            Some(NonNull::new_unchecked(
                self.base.as_ptr().add(block_offset)
            ))
        }
    }

    fn deallocate(&mut self, ptr: NonNull<u8>, size: usize) {
        let offset = unsafe { ptr.as_ptr().offset_from(self.base.as_ptr()) } as usize;
        let level = self.size_to_level(size).unwrap();
        self.free_lists[level].push(offset);
    }

    fn size_to_level(&self, size: usize) -> Option<usize> {
        let min_level = size.next_power_of_two().trailing_zeros() as usize;
        if min_level < self.free_lists.len() {
            Some(min_level)
        } else {
            None
        }
    }

    fn find_free_block(&mut self, level: usize) -> Option<usize> {
        // Check if we have a free block at this level
        if let Some(offset) = self.free_lists[level].pop() {
            return Some(offset);
        }

        // Try to split a larger block
        for higher_level in (level + 1)..self.free_lists.len() {
            if let Some(offset) = self.free_lists[higher_level].pop() {
                // Split the block
                let buddy_offset = offset + (1 << level);
                self.free_lists[level].push(buddy_offset);
                return Some(offset);
            }
        }

        None
    }
}

unsafe impl<const SIZE: usize> Send for MemoryPool<SIZE> {}
unsafe impl<const SIZE: usize> Sync for MemoryPool<SIZE> {}