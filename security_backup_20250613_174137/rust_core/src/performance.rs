// ============================================================================
// Performance Module - High-Performance Operations and Optimizations
// ============================================================================

use pyo3::prelude::*;
use rayon::prelude::*;
use std::sync::Arc;
use std::time::{Duration, Instant};
use crossbeam::channel;
use parking_lot::RwLock;
use dashmap::DashMap;
use tracing::{info, debug, warn};

use crate::{CoreError, CoreResult};

/// Register performance functions with Python module
pub fn register_module(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(benchmark_operation_py, m)?)?;
    m.add_function(wrap_pyfunction!(parallel_execute_py, m)?)?;
    m.add_class::<TaskExecutor>()?;
    m.add_class::<PerformanceMonitor>()?;
    m.add_class::<ResourcePool>()?;
    Ok(())
}

// ========================= Task Executor =========================

#[derive(Clone, Debug)]
pub enum TaskType {
    IoBlocking,
    CpuIntensive,
    Mixed,
    Async,
}

#[pyclass]
pub struct TaskExecutor {
    thread_pool_size: usize,
    async_pool_size: usize,
    task_queue: Arc<RwLock<Vec<TaskInfo>>>,
    results_cache: Arc<DashMap<String, TaskResult>>,
}

#[derive(Clone)]
struct TaskInfo {
    id: String,
    task_type: TaskType,
    priority: u8,
}

#[derive(Clone)]
struct TaskResult {
    duration: Duration,
    success: bool,
    output: Option<String>,
}

#[pymethods]
impl TaskExecutor {
    #[new]
    fn new(thread_pool_size: Option<usize>, async_pool_size: Option<usize>) -> Self {
        Self {
            thread_pool_size: thread_pool_size.unwrap_or(20),
            async_pool_size: async_pool_size.unwrap_or(50),
            task_queue: Arc::new(RwLock::new(Vec::new())),
            results_cache: Arc::new(DashMap::new()),
        }
    }
    
    /// Execute tasks in parallel based on their type
    fn execute_batch(&self, py: Python, tasks: Vec<(String, String)>) -> PyResult<Vec<(String, f64)>> {
        info!("Executing batch of {} tasks", tasks.len());
        
        // Parse task info
        let task_infos: Vec<TaskInfo> = tasks
            .iter()
            .map(|(id, task_type)| {
                let task_type = match task_type.as_str() {
                    "io" => TaskType::IoBlocking,
                    "cpu" => TaskType::CpuIntensive,
                    "mixed" => TaskType::Mixed,
                    _ => TaskType::Async,
                };
                TaskInfo {
                    id: id.clone(),
                    task_type,
                    priority: 5,
                }
            })
            .collect();
        
        // Group tasks by type
        let mut io_tasks = Vec::new();
        let mut cpu_tasks = Vec::new();
        let mut async_tasks = Vec::new();
        
        for task in task_infos {
            match task.task_type {
                TaskType::IoBlocking => io_tasks.push(task),
                TaskType::CpuIntensive => cpu_tasks.push(task),
                TaskType::Mixed => cpu_tasks.push(task), // Treat as CPU-bound
                TaskType::Async => async_tasks.push(task),
            }
        }
        
        // Execute each group with appropriate strategy
        let (tx, rx) = channel::unbounded();
        
        // I/O tasks - use thread pool
        if !io_tasks.is_empty() {
            let tx_io = tx.clone();
            std::thread::spawn(move || {
                io_tasks.par_iter().for_each(|task| {
                    let start = Instant::now();
                    // Simulate I/O operation
                    std::thread::sleep(Duration::from_millis(10));
                    let duration = start.elapsed();
                    tx_io.send((task.id.clone(), duration.as_secs_f64())).unwrap();
                });
            });
        }
        
        // CPU tasks - use compute pool
        if !cpu_tasks.is_empty() {
            let tx_cpu = tx.clone();
            std::thread::spawn(move || {
                cpu_tasks.par_iter().for_each(|task| {
                    let start = Instant::now();
                    // Simulate CPU work
                    let mut sum = 0u64;
                    for i in 0..1_000_000 {
                        sum = sum.wrapping_add(i);
                    }
                    let duration = start.elapsed();
                    tx_cpu.send((task.id.clone(), duration.as_secs_f64())).unwrap();
                });
            });
        }
        
        // Async tasks - use tokio runtime
        if !async_tasks.is_empty() {
            py.allow_threads(|| {
                let runtime = tokio::runtime::Runtime::new().unwrap();
                runtime.block_on(async {
                    for task in async_tasks {
                        let tx_async = tx.clone();
                        tokio::spawn(async move {
                            let start = Instant::now();
                            tokio::time::sleep(Duration::from_millis(5)).await;
                            let duration = start.elapsed();
                            tx_async.send((task.id.clone(), duration.as_secs_f64())).unwrap();
                        });
                    }
                });
            });
        }
        
        // Collect results
        drop(tx); // Close sender
        let results: Vec<(String, f64)> = rx.iter().collect();
        
        debug!("Batch execution complete: {} tasks processed", results.len());
        Ok(results)
    }
    
    /// Get execution statistics
    fn get_stats(&self) -> PyResult<HashMap<String, f64>> {
        let mut stats = HashMap::new();
        stats.insert("queue_size".to_string(), self.task_queue.read().len() as f64);
        stats.insert("cache_size".to_string(), self.results_cache.len() as f64);
        Ok(stats)
    }
}

// ========================= Performance Monitor =========================

#[pyclass]
pub struct PerformanceMonitor {
    metrics: Arc<DashMap<String, Vec<f64>>>,
    start_times: Arc<DashMap<String, Instant>>,
}

#[pymethods]
impl PerformanceMonitor {
    #[new]
    fn new() -> Self {
        Self {
            metrics: Arc::new(DashMap::new()),
            start_times: Arc::new(DashMap::new()),
        }
    }
    
    /// Start timing an operation
    fn start_operation(&self, operation_name: String) {
        self.start_times.insert(operation_name, Instant::now());
    }
    
    /// End timing and record the metric
    fn end_operation(&self, operation_name: String) -> PyResult<f64> {
        if let Some((_, start_time)) = self.start_times.remove(&operation_name) {
            let duration = start_time.elapsed().as_secs_f64();
            
            self.metrics
                .entry(operation_name)
                .or_insert_with(Vec::new)
                .push(duration);
            
            Ok(duration)
        } else {
            Err(CoreError::Performance(format!("Operation {} not started", operation_name)).into())
        }
    }
    
    /// Get statistics for an operation
    fn get_operation_stats(&self, operation_name: &str) -> PyResult<HashMap<String, f64>> {
        let mut stats = HashMap::new();
        
        if let Some(metrics) = self.metrics.get(operation_name) {
            let values = metrics.value();
            if !values.is_empty() {
                let sum: f64 = values.iter().sum();
                let count = values.len() as f64;
                let mean = sum / count;
                
                let mut sorted = values.clone();
                sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
                
                stats.insert("count".to_string(), count);
                stats.insert("mean".to_string(), mean);
                stats.insert("min".to_string(), *sorted.first().unwrap());
                stats.insert("max".to_string(), *sorted.last().unwrap());
                stats.insert("p50".to_string(), sorted[sorted.len() / 2]);
                stats.insert("p95".to_string(), sorted[(sorted.len() as f64 * 0.95) as usize]);
                stats.insert("p99".to_string(), sorted[(sorted.len() as f64 * 0.99) as usize]);
            }
        }
        
        Ok(stats)
    }
    
    /// Clear all metrics
    fn clear(&self) {
        self.metrics.clear();
        self.start_times.clear();
        info!("Performance metrics cleared");
    }
}

// ========================= Resource Pool =========================

#[pyclass]
pub struct ResourcePool {
    max_size: usize,
    available: Arc<RwLock<Vec<String>>>,
    in_use: Arc<DashMap<String, Instant>>,
}

#[pymethods]
impl ResourcePool {
    #[new]
    fn new(max_size: usize) -> Self {
        let mut available = Vec::with_capacity(max_size);
        for i in 0..max_size {
            available.push(format!("resource_{}", i));
        }
        
        Self {
            max_size,
            available: Arc::new(RwLock::new(available)),
            in_use: Arc::new(DashMap::new()),
        }
    }
    
    /// Acquire a resource from the pool
    fn acquire(&self) -> PyResult<Option<String>> {
        let mut available = self.available.write();
        
        if let Some(resource) = available.pop() {
            self.in_use.insert(resource.clone(), Instant::now());
            Ok(Some(resource))
        } else if self.in_use.len() < self.max_size {
            // All resources in use
            Ok(None)
        } else {
            Err(CoreError::Performance("Resource pool exhausted".to_string()).into())
        }
    }
    
    /// Release a resource back to the pool
    fn release(&self, resource: String) -> PyResult<()> {
        if self.in_use.remove(&resource).is_some() {
            self.available.write().push(resource);
            Ok(())
        } else {
            Err(CoreError::Performance("Resource not in use".to_string()).into())
        }
    }
    
    /// Get pool statistics
    fn get_stats(&self) -> PyResult<HashMap<String, usize>> {
        let mut stats = HashMap::new();
        stats.insert("max_size".to_string(), self.max_size);
        stats.insert("available".to_string(), self.available.read().len());
        stats.insert("in_use".to_string(), self.in_use.len());
        Ok(stats)
    }
    
    /// Clean up stale resources (held for too long)
    fn cleanup_stale(&self, max_hold_seconds: f64) -> PyResult<usize> {
        let max_duration = Duration::from_secs_f64(max_hold_seconds);
        let mut released = 0;
        
        let stale_resources: Vec<String> = self.in_use
            .iter()
            .filter(|entry| entry.value().elapsed() > max_duration)
            .map(|entry| entry.key().clone())
            .collect();
        
        for resource in stale_resources {
            if self.in_use.remove(&resource).is_some() {
                self.available.write().push(resource);
                released += 1;
            }
        }
        
        if released > 0 {
            warn!("Released {} stale resources", released);
        }
        
        Ok(released)
    }
}

// ========================= Utility Functions =========================

/// Benchmark an operation
#[pyfunction]
fn benchmark_operation_py(py: Python, iterations: usize) -> PyResult<HashMap<String, f64>> {
    let monitor = PerformanceMonitor::new();
    
    // Benchmark different operations
    let operations = vec!["parse", "compute", "serialize"];
    
    for op in &operations {
        for _ in 0..iterations {
            monitor.start_operation(op.to_string());
            
            // Simulate work based on operation type
            match op.as_ref() {
                "parse" => {
                    let _data: Vec<i32> = (0..1000).collect();
                }
                "compute" => {
                    let _sum: i64 = (0..10000).sum();
                }
                "serialize" => {
                    let _json = serde_json::to_string(&vec![1, 2, 3, 4, 5]).unwrap();
                }
                _ => {}
            }
            
            monitor.end_operation(op.to_string())?;
        }
    }
    
    // Collect results
    let mut results = HashMap::new();
    for op in operations {
        if let Ok(stats) = monitor.get_operation_stats(&op) {
            results.insert(format!("{}_mean_ms", op), stats.get("mean").unwrap_or(&0.0) * 1000.0);
        }
    }
    
    Ok(results)
}

/// Execute functions in parallel
#[pyfunction]
fn parallel_execute_py(py: Python, count: usize) -> PyResult<Vec<f64>> {
    let start = Instant::now();
    
    let results: Vec<f64> = py.allow_threads(|| {
        (0..count)
            .into_par_iter()
            .map(|i| {
                // Simulate work
                let mut sum = 0.0;
                for j in 0..1000 {
                    sum += (i * j) as f64;
                }
                sum
            })
            .collect()
    });
    
    let duration = start.elapsed().as_secs_f64();
    info!("Parallel execution of {} tasks took {:.3}s", count, duration);
    
    Ok(results)
}

use std::collections::HashMap;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_task_executor() {
        Python::with_gil(|py| {
            let executor = TaskExecutor::new(Some(4), Some(10));
            let tasks = vec![
                ("task1".to_string(), "io".to_string()),
                ("task2".to_string(), "cpu".to_string()),
                ("task3".to_string(), "async".to_string()),
            ];
            
            let results = executor.execute_batch(py, tasks).unwrap();
            assert_eq!(results.len(), 3);
        });
    }
    
    #[test]
    fn test_performance_monitor() {
        let monitor = PerformanceMonitor::new();
        
        monitor.start_operation("test_op".to_string());
        std::thread::sleep(Duration::from_millis(10));
        let duration = monitor.end_operation("test_op".to_string()).unwrap();
        
        assert!(duration > 0.01);
        
        let stats = monitor.get_operation_stats("test_op").unwrap();
        assert_eq!(stats["count"], 1.0);
    }
    
    #[test]
    fn test_resource_pool() {
        let pool = ResourcePool::new(3);
        
        // Acquire resources
        let r1 = pool.acquire().unwrap().unwrap();
        let r2 = pool.acquire().unwrap().unwrap();
        let r3 = pool.acquire().unwrap().unwrap();
        
        // Pool should be exhausted
        assert!(pool.acquire().unwrap().is_none());
        
        // Release one
        pool.release(r1).unwrap();
        
        // Should be able to acquire again
        let r4 = pool.acquire().unwrap().unwrap();
        assert!(!r4.is_empty());
    }
}
