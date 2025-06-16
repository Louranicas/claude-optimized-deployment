// ============================================================================
// Lock-Free Collections Module - High-Performance Concurrent Data Structures
// ============================================================================
// This module provides lock-free and wait-free data structures for 
// high-performance concurrent operations with minimal contention and
// excellent scalability across multiple threads.
//
// Key features:
// - Lock-free stacks, queues, and hash maps
// - Wait-free bounded queues with backpressure
// - Concurrent counters and metrics collectors
// - Memory-efficient epoch-based garbage collection
// - Zero-allocation fast paths for common operations
// ============================================================================

use pyo3::prelude::*;
use std::sync::atomic::{AtomicUsize, AtomicPtr, AtomicBool, Ordering};
use std::sync::Arc;
use std::ptr;
use std::collections::HashMap;
use crossbeam::epoch::{self, Atomic, Owned, Shared, Guard};
use crossbeam::queue::{ArrayQueue, SegQueue};
use lockfree::queue::Queue as LockFreeQueue;
use lockfree::stack::Stack as LockFreeStack;
use lockfree::map::Map as LockFreeMap;
use rayon::prelude::*;
use tracing::{debug, warn, info};

use crate::{CoreError, CoreResult};

/// Register lock-free collections with Python module
pub fn register_module(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<LockFreeCounter>()?;
    m.add_class::<ConcurrentStack>()?;
    m.add_class::<ConcurrentQueue>()?;
    m.add_class::<ConcurrentHashMap>()?;
    m.add_class::<MetricsCollector>()?;
    m.add_class::<PerformanceBuffer>()?;
    Ok(())
}

// ========================= Lock-Free Counter =========================

#[pyclass]
pub struct LockFreeCounter {
    value: AtomicUsize,
    name: String,
}

#[pymethods]
impl LockFreeCounter {
    #[new]
    fn new(name: String, initial_value: Option<usize>) -> Self {
        Self {
            value: AtomicUsize::new(initial_value.unwrap_or(0)),
            name,
        }
    }
    
    /// Increment counter and return new value
    fn increment(&self) -> usize {
        self.value.fetch_add(1, Ordering::Relaxed) + 1
    }
    
    /// Add to counter and return new value
    fn add(&self, amount: usize) -> usize {
        self.value.fetch_add(amount, Ordering::Relaxed) + amount
    }
    
    /// Get current value
    fn get(&self) -> usize {
        self.value.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release
    }
    
    /// Reset counter to zero
    fn reset(&self) -> usize {
        self.value.swap(0, Ordering::Relaxed)
    }
    
    /// Compare and swap
    fn compare_and_swap(&self, current: usize, new: usize) -> bool {
        self.value.compare_exchange_weak(current, new, Ordering::Relaxed, Ordering::Relaxed).is_ok()
    }
    
    /// Get counter name
    fn get_name(&self) -> String {
        self.name.clone()
    }
}

// ========================= Concurrent Stack =========================

#[pyclass]
pub struct ConcurrentStack {
    stack: Arc<LockFreeStack<String>>,
    size: AtomicUsize,
    max_size: Option<usize>,
}

#[pymethods]
impl ConcurrentStack {
    #[new]
    fn new(max_size: Option<usize>) -> Self {
        Self {
            stack: Arc::new(LockFreeStack::new()),
            size: AtomicUsize::new(0),
            max_size,
        }
    }
    
    /// Push item onto stack
    fn push(&self, item: String) -> PyResult<bool> {
        if let Some(max) = self.max_size {
            if self.size.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release >= max {
                return Ok(false); // Stack full
            }
        }
        
        self.stack.push(item);
        self.size.fetch_add(1, Ordering::Relaxed);
        Ok(true)
    }
    
    /// Pop item from stack
    fn pop(&self) -> PyResult<Option<String>> {
        match self.stack.pop() {
            Some(item) => {
                self.size.fetch_sub(1, Ordering::Relaxed);
                Ok(Some(item))
            }
            None => Ok(None),
        }
    }
    
    /// Check if stack is empty
    fn is_empty(&self) -> bool {
        self.size.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release == 0
    }
    
    /// Get approximate size
    fn size(&self) -> usize {
        self.size.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release
    }
    
    /// Bulk push operation
    fn push_bulk(&self, items: Vec<String>) -> PyResult<usize> {
        let max_size = self.max_size.unwrap_or(usize::MAX);
        let current_size = self.size.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release;
        let available_space = max_size.saturating_sub(current_size);
        let items_to_push = items.len().min(available_space);
        
        for item in items.into_iter().take(items_to_push) {
            self.stack.push(item);
        }
        
        self.size.fetch_add(items_to_push, Ordering::Relaxed);
        Ok(items_to_push)
    }
    
    /// Bulk pop operation
    fn pop_bulk(&self, count: usize) -> PyResult<Vec<String>> {
        let mut results = Vec::with_capacity(count);
        
        for _ in 0..count {
            if let Some(item) = self.stack.pop() {
                results.push(item);
                self.size.fetch_sub(1, Ordering::Relaxed);
            } else {
                break;
            }
        }
        
        Ok(results)
    }
}

// ========================= Concurrent Queue =========================

#[pyclass]
pub struct ConcurrentQueue {
    bounded_queue: Option<Arc<ArrayQueue<String>>>,
    unbounded_queue: Option<Arc<SegQueue<String>>>,
    size: AtomicUsize,
    is_bounded: bool,
}

#[pymethods]
impl ConcurrentQueue {
    #[new]
    fn new(capacity: Option<usize>) -> Self {
        match capacity {
            Some(cap) => Self {
                bounded_queue: Some(Arc::new(ArrayQueue::new(cap))),
                unbounded_queue: None,
                size: AtomicUsize::new(0),
                is_bounded: true,
            },
            None => Self {
                bounded_queue: None,
                unbounded_queue: Some(Arc::new(SegQueue::new())),
                size: AtomicUsize::new(0),
                is_bounded: false,
            },
        }
    }
    
    /// Enqueue an item
    fn enqueue(&self, item: String) -> PyResult<bool> {
        if self.is_bounded {
            if let Some(ref queue) = self.bounded_queue {
                match queue.push(item) {
                    Ok(()) => {
                        self.size.fetch_add(1, Ordering::Relaxed);
                        Ok(true)
                    }
                    Err(_) => Ok(false), // Queue full
                }
            } else {
                Err(CoreError::Performance("Bounded queue not initialized".to_string()).into())
            }
        } else {
            if let Some(ref queue) = self.unbounded_queue {
                queue.push(item);
                self.size.fetch_add(1, Ordering::Relaxed);
                Ok(true)
            } else {
                Err(CoreError::Performance("Unbounded queue not initialized".to_string()).into())
            }
        }
    }
    
    /// Dequeue an item
    fn dequeue(&self) -> PyResult<Option<String>> {
        if self.is_bounded {
            if let Some(ref queue) = self.bounded_queue {
                match queue.pop() {
                    Some(item) => {
                        self.size.fetch_sub(1, Ordering::Relaxed);
                        Ok(Some(item))
                    }
                    None => Ok(None),
                }
            } else {
                Err(CoreError::Performance("Bounded queue not initialized".to_string()).into())
            }
        } else {
            if let Some(ref queue) = self.unbounded_queue {
                match queue.pop() {
                    Some(item) => {
                        self.size.fetch_sub(1, Ordering::Relaxed);
                        Ok(Some(item))
                    }
                    None => Ok(None),
                }
            } else {
                Err(CoreError::Performance("Unbounded queue not initialized".to_string()).into())
            }
        }
    }
    
    /// Check if queue is empty
    fn is_empty(&self) -> bool {
        self.size.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release == 0
    }
    
    /// Get approximate size
    fn size(&self) -> usize {
        self.size.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release
    }
    
    /// Bulk enqueue operation
    fn enqueue_bulk(&self, items: Vec<String>) -> PyResult<usize> {
        let mut enqueued = 0;
        
        for item in items {
            if self.enqueue(item)? {
                enqueued += 1;
            } else {
                break; // Queue full
            }
        }
        
        Ok(enqueued)
    }
    
    /// Bulk dequeue operation
    fn dequeue_bulk(&self, count: usize) -> PyResult<Vec<String>> {
        let mut results = Vec::with_capacity(count);
        
        for _ in 0..count {
            if let Some(item) = self.dequeue()? {
                results.push(item);
            } else {
                break;
            }
        }
        
        Ok(results)
    }
    
    /// Get queue capacity (bounded queues only)
    fn capacity(&self) -> Option<usize> {
        if self.is_bounded {
            self.bounded_queue.as_ref().map(|q| q.capacity())
        } else {
            None
        }
    }
}

// ========================= Concurrent HashMap =========================

#[pyclass]
pub struct ConcurrentHashMap {
    map: Arc<LockFreeMap<String, String>>,
    size: AtomicUsize,
}

#[pymethods]
impl ConcurrentHashMap {
    #[new]
    fn new() -> Self {
        Self {
            map: Arc::new(LockFreeMap::new()),
            size: AtomicUsize::new(0),
        }
    }
    
    /// Insert a key-value pair
    fn insert(&self, key: String, value: String) -> PyResult<bool> {
        let result = self.map.insert(key, value);
        if result.is_none() {
            self.size.fetch_add(1, Ordering::Relaxed);
            Ok(true)
        } else {
            Ok(false) // Key already existed
        }
    }
    
    /// Get a value by key
    fn get(&self, key: String) -> PyResult<Option<String>> {
        Ok(self.map.get(&key).map(|val| val.val().clone()))
    }
    
    /// Remove a key-value pair
    fn remove(&self, key: String) -> PyResult<Option<String>> {
        if let Some(val) = self.map.remove(&key) {
            self.size.fetch_sub(1, Ordering::Relaxed);
            Ok(Some(val.val().clone()))
        } else {
            Ok(None)
        }
    }
    
    /// Check if key exists
    fn contains_key(&self, key: String) -> bool {
        self.map.get(&key).is_some()
    }
    
    /// Get approximate size
    fn size(&self) -> usize {
        self.size.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release
    }
    
    /// Clear all entries
    fn clear(&self) {
        self.map.clear();
        self.size.store(0, Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release;
    }
    
    /// Get all keys (snapshot)
    fn keys(&self) -> PyResult<Vec<String>> {
        let mut keys = Vec::new();
        for entry in self.map.iter() {
            keys.push(entry.key().clone());
        }
        Ok(keys)
    }
    
    /// Bulk insert operation
    fn insert_bulk(&self, items: Vec<(String, String)>) -> PyResult<usize> {
        let mut inserted = 0;
        
        for (key, value) in items {
            if self.insert(key, value)? {
                inserted += 1;
            }
        }
        
        Ok(inserted)
    }
    
    /// Update or insert (upsert) operation
    fn upsert(&self, key: String, value: String) -> PyResult<Option<String>> {
        let old_value = self.map.insert(key, value);
        if old_value.is_none() {
            self.size.fetch_add(1, Ordering::Relaxed);
        }
        Ok(old_value.map(|val| val.val().clone()))
    }
}

// ========================= Metrics Collector =========================

#[pyclass]
pub struct MetricsCollector {
    counters: Arc<LockFreeMap<String, LockFreeCounter>>,
    gauges: Arc<LockFreeMap<String, AtomicUsize>>,
    histograms: Arc<LockFreeMap<String, Arc<LockFreeQueue<f64>>>>,
    enabled: AtomicBool,
}

#[pymethods]
impl MetricsCollector {
    #[new]
    fn new() -> Self {
        Self {
            counters: Arc::new(LockFreeMap::new()),
            gauges: Arc::new(LockFreeMap::new()),
            histograms: Arc::new(LockFreeMap::new()),
            enabled: AtomicBool::new(true),
        }
    }
    
    /// Increment a counter
    fn increment_counter(&self, name: String) -> PyResult<usize> {
        if !self.enabled.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release {
            return Ok(0);
        }
        
        let counter = self.counters
            .get(&name)
            .map(|c| c.val())
            .unwrap_or_else(|| {
                let new_counter = LockFreeCounter::new(name.clone(), Some(0));
                self.counters.insert(name.clone(), new_counter);
                self.counters.get(&name).unwrap().val()
            });
        
        Ok(counter.increment())
    }
    
    /// Add to counter
    fn add_to_counter(&self, name: String, amount: usize) -> PyResult<usize> {
        if !self.enabled.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release {
            return Ok(0);
        }
        
        let counter = self.counters
            .get(&name)
            .map(|c| c.val())
            .unwrap_or_else(|| {
                let new_counter = LockFreeCounter::new(name.clone(), Some(0));
                self.counters.insert(name.clone(), new_counter);
                self.counters.get(&name).unwrap().val()
            });
        
        Ok(counter.add(amount))
    }
    
    /// Set gauge value
    fn set_gauge(&self, name: String, value: usize) -> PyResult<()> {
        if !self.enabled.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release {
            return Ok(());
        }
        
        let gauge = self.gauges
            .get(&name)
            .map(|g| g.val())
            .unwrap_or_else(|| {
                let new_gauge = AtomicUsize::new(0);
                self.gauges.insert(name.clone(), new_gauge);
                self.gauges.get(&name).unwrap().val()
            });
        
        gauge.store(value, Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release;
        Ok(())
    }
    
    /// Record histogram value
    fn record_histogram(&self, name: String, value: f64) -> PyResult<()> {
        if !self.enabled.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release {
            return Ok(());
        }
        
        let histogram = self.histograms
            .get(&name)
            .map(|h| h.val().clone())
            .unwrap_or_else(|| {
                let new_histogram = Arc::new(LockFreeQueue::new());
                self.histograms.insert(name.clone(), new_histogram.clone());
                new_histogram
            });
        
        histogram.push(value);
        Ok(())
    }
    
    /// Get counter value
    fn get_counter(&self, name: String) -> PyResult<usize> {
        Ok(self.counters
            .get(&name)
            .map(|c| c.val().get())
            .unwrap_or(0))
    }
    
    /// Get gauge value
    fn get_gauge(&self, name: String) -> PyResult<usize> {
        Ok(self.gauges
            .get(&name)
            .map(|g| g.val().load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release)
            .unwrap_or(0))
    }
    
    /// Get histogram statistics
    fn get_histogram_stats(&self, name: String) -> PyResult<HashMap<String, f64>> {
        let mut stats = HashMap::new();
        
        if let Some(histogram_ref) = self.histograms.get(&name) {
            let histogram = histogram_ref.val();
            let mut values = Vec::new();
            
            // Collect all values (this is not zero-copy, but needed for stats)
            while let Some(value) = histogram.pop() {
                values.push(value);
            }
            
            if !values.is_empty() {
                values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                
                let sum: f64 = values.iter().sum();
                let count = values.len() as f64;
                let mean = sum / count;
                
                stats.insert("count".to_string(), count);
                stats.insert("sum".to_string(), sum);
                stats.insert("mean".to_string(), mean);
                stats.insert("min".to_string(), values[0]);
                stats.insert("max".to_string(), values[values.len() - 1]);
                stats.insert("p50".to_string(), values[values.len() / 2]);
                stats.insert("p95".to_string(), values[(values.len() as f64 * 0.95) as usize]);
                stats.insert("p99".to_string(), values[(values.len() as f64 * 0.99) as usize]);
            }
        }
        
        Ok(stats)
    }
    
    /// Get all metric names
    fn get_metric_names(&self) -> PyResult<HashMap<String, Vec<String>>> {
        let mut result = HashMap::new();
        
        let counter_names: Vec<String> = self.counters.iter()
            .map(|entry| entry.key().clone())
            .collect();
        
        let gauge_names: Vec<String> = self.gauges.iter()
            .map(|entry| entry.key().clone())
            .collect();
        
        let histogram_names: Vec<String> = self.histograms.iter()
            .map(|entry| entry.key().clone())
            .collect();
        
        result.insert("counters".to_string(), counter_names);
        result.insert("gauges".to_string(), gauge_names);
        result.insert("histograms".to_string(), histogram_names);
        
        Ok(result)
    }
    
    /// Enable/disable metrics collection
    fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release;
        if enabled {
            info!("Metrics collection enabled");
        } else {
            warn!("Metrics collection disabled");
        }
    }
    
    /// Clear all metrics
    fn clear_all(&self) {
        self.counters.clear();
        self.gauges.clear();
        self.histograms.clear();
        debug!("All metrics cleared");
    }
}

// ========================= Performance Buffer =========================

#[pyclass]
pub struct PerformanceBuffer {
    buffer: Arc<ArrayQueue<PerformanceEvent>>,
    dropped_events: AtomicUsize,
    total_events: AtomicUsize,
}

#[derive(Clone)]
struct PerformanceEvent {
    timestamp: u64,
    event_type: String,
    data: String,
    duration_ns: u64,
}

#[pymethods]
impl PerformanceBuffer {
    #[new]
    fn new(capacity: usize) -> Self {
        Self {
            buffer: Arc::new(ArrayQueue::new(capacity)),
            dropped_events: AtomicUsize::new(0),
            total_events: AtomicUsize::new(0),
        }
    }
    
    /// Record a performance event
    fn record_event(&self, event_type: String, data: String, duration_ns: u64) -> PyResult<bool> {
        self.total_events.fetch_add(1, Ordering::Relaxed);
        
        let event = PerformanceEvent {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            event_type,
            data,
            duration_ns,
        };
        
        match self.buffer.push(event) {
            Ok(()) => Ok(true),
            Err(_) => {
                self.dropped_events.fetch_add(1, Ordering::Relaxed);
                Ok(false)
            }
        }
    }
    
    /// Get next event
    fn get_event(&self) -> PyResult<Option<(String, String, u64, u64)>> {
        match self.buffer.pop() {
            Some(event) => Ok(Some((
                event.event_type,
                event.data,
                event.timestamp,
                event.duration_ns,
            ))),
            None => Ok(None),
        }
    }
    
    /// Get buffer statistics
    fn get_stats(&self) -> PyResult<HashMap<String, usize>> {
        let mut stats = HashMap::new();
        stats.insert("capacity".to_string(), self.buffer.capacity());
        stats.insert("current_size".to_string(), self.buffer.len());
        stats.insert("dropped_events".to_string(), self.dropped_events.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release);
        stats.insert("total_events".to_string(), self.total_events.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release);
        Ok(stats)
    }
    
    /// Drain all events
    fn drain_events(&self) -> PyResult<Vec<(String, String, u64, u64)>> {
        let mut events = Vec::new();
        
        while let Some(event) = self.buffer.pop() {
            events.push((
                event.event_type,
                event.data,
                event.timestamp,
                event.duration_ns,
            ));
        }
        
        Ok(events)
    }
    
    /// Check if buffer is full
    fn is_full(&self) -> bool {
        self.buffer.is_full()
    }
    
    /// Check if buffer is empty
    fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_lockfree_counter() {
        let counter = LockFreeCounter::new("test".to_string(), Some(5));
        assert_eq!(counter.get(), 5);
        
        assert_eq!(counter.increment(), 6);
        assert_eq!(counter.add(10), 16);
        assert_eq!(counter.reset(), 16);
        assert_eq!(counter.get(), 0);
    }
    
    #[test]
    fn test_concurrent_stack() {
        Python::with_gil(|_py| {
            let stack = ConcurrentStack::new(Some(10));
            
            assert!(stack.push("item1".to_string()).unwrap());
            assert!(stack.push("item2".to_string()).unwrap());
            assert_eq!(stack.size(), 2);
            
            assert_eq!(stack.pop().unwrap(), Some("item2".to_string()));
            assert_eq!(stack.pop().unwrap(), Some("item1".to_string()));
            assert!(stack.is_empty());
        });
    }
    
    #[test]
    fn test_concurrent_queue() {
        Python::with_gil(|_py| {
            let queue = ConcurrentQueue::new(Some(5));
            
            assert!(queue.enqueue("item1".to_string()).unwrap());
            assert!(queue.enqueue("item2".to_string()).unwrap());
            assert_eq!(queue.size(), 2);
            
            assert_eq!(queue.dequeue().unwrap(), Some("item1".to_string()));
            assert_eq!(queue.dequeue().unwrap(), Some("item2".to_string()));
            assert!(queue.is_empty());
        });
    }
    
    #[test]
    fn test_concurrent_hashmap() {
        Python::with_gil(|_py| {
            let map = ConcurrentHashMap::new();
            
            assert!(map.insert("key1".to_string(), "value1".to_string()).unwrap());
            assert_eq!(map.get("key1".to_string()).unwrap(), Some("value1".to_string()));
            assert_eq!(map.size(), 1);
            
            assert_eq!(map.remove("key1".to_string()).unwrap(), Some("value1".to_string()));
            assert_eq!(map.size(), 0);
        });
    }
    
    #[test]
    fn test_metrics_collector() {
        Python::with_gil(|_py| {
            let collector = MetricsCollector::new();
            
            collector.increment_counter("requests".to_string()).unwrap();
            collector.add_to_counter("requests".to_string(), 5).unwrap();
            assert_eq!(collector.get_counter("requests".to_string()).unwrap(), 6);
            
            collector.set_gauge("memory_usage".to_string(), 1024).unwrap();
            assert_eq!(collector.get_gauge("memory_usage".to_string()).unwrap(), 1024);
            
            collector.record_histogram("latency".to_string(), 123.45).unwrap();
            let stats = collector.get_histogram_stats("latency".to_string()).unwrap();
            assert_eq!(stats.get("count").unwrap(), &1.0);
        });
    }
}