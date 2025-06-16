//! FFI Bindings for Python Integration
//! 
//! PyO3-based bindings with minimal overhead for Python interoperability.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3::exceptions::PyRuntimeError;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::runtime::Handle;
use anyhow::Result;

use crate::{
    server::{HighPerfMCPServer, MCPServer, Request, Response, Metrics},
    memory::{MemoryPool, MemoryPoolStats},
    messaging::{MessageQueue, Message, Priority},
    state::{StateManager, StateManagerStats},
};

/// Python-accessible MCP server wrapper
#[pyclass(name = "MCPRustCore")]
pub struct PyMCPServer {
    server: Arc<HighPerfMCPServer>,
    runtime_handle: Handle,
}

#[pymethods]
impl PyMCPServer {
    /// Create a new MCP server with specified memory size in MB
    #[new]
    #[pyo3(signature = (memory_size_mb=1024))]
    fn new(memory_size_mb: Option<usize>) -> PyResult<Self> {
        let memory_size = memory_size_mb.unwrap_or(1024);
        
        let server = HighPerfMCPServer::new(memory_size)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to create server: {}", e)))?;
        
        let runtime_handle = crate::RUNTIME.handle().clone();
        
        Ok(Self {
            server: Arc::new(server),
            runtime_handle,
        })
    }
    
    /// Process a request
    #[pyo3(signature = (method, params=None, request_id=None))]
    fn process_request(
        &self,
        py: Python,
        method: String,
        params: Option<&PyDict>,
        request_id: Option<u64>,
    ) -> PyResult<PyObject> {
        let params_value = if let Some(p) = params {
            pythonize::depythonize(p)?
        } else {
            serde_json::Value::Null
        };
        
        let request = Request {
            id: request_id.unwrap_or_else(rand::random),
            method,
            params: params_value,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        let server = self.server.clone();
        
        // Run async operation
        let response = py.allow_threads(|| {
            self.runtime_handle.block_on(async move {
                server.process_request(request).await
            })
        }).map_err(|e| PyRuntimeError::new_err(format!("Request failed: {}", e)))?;
        
        // Convert response to Python dict
        let dict = PyDict::new(py);
        dict.set_item("id", response.id)?;
        dict.set_item("result", pythonize::pythonize(py, &response.result)?)?;
        dict.set_item("error", response.error)?;
        dict.set_item("processing_time_us", response.processing_time_us)?;
        
        Ok(dict.into())
    }
    
    /// Get server metrics
    fn get_metrics(&self, py: Python) -> PyResult<PyObject> {
        let metrics = self.server.get_metrics();
        
        let dict = PyDict::new(py);
        dict.set_item("total_requests", metrics.total_requests)?;
        dict.set_item("total_errors", metrics.total_errors)?;
        dict.set_item("avg_latency_us", metrics.avg_latency_us)?;
        dict.set_item("p99_latency_us", metrics.p99_latency_us)?;
        dict.set_item("memory_usage_mb", metrics.memory_usage_mb)?;
        
        Ok(dict.into())
    }
    
    /// Register a Python handler for a method
    #[pyo3(signature = (method, handler))]
    fn register_handler(&self, method: String, handler: PyObject) -> PyResult<()> {
        let server = self.server.clone();
        
        Python::with_gil(|py| {
            server.register_handler(method, move |req| {
                Python::with_gil(|py| {
                    // Convert request to Python dict
                    let py_req = PyDict::new(py);
                    py_req.set_item("id", req.id).unwrap();
                    py_req.set_item("method", &req.method).unwrap();
                    py_req.set_item("params", pythonize::pythonize(py, &req.params).unwrap()).unwrap();
                    
                    // Call Python handler
                    let result = handler.call1(py, (py_req,));
                    
                    match result {
                        Ok(py_resp) => {
                            if let Ok(resp_dict) = py_resp.downcast::<PyDict>(py) {
                                Response {
                                    id: req.id,
                                    result: pythonize::depythonize(resp_dict.get_item("result").unwrap()).unwrap_or(serde_json::Value::Null),
                                    error: resp_dict.get_item("error").and_then(|e| e.extract().ok()),
                                    processing_time_us: 0,
                                }
                            } else {
                                Response {
                                    id: req.id,
                                    result: serde_json::Value::Null,
                                    error: Some("Invalid response format".to_string()),
                                    processing_time_us: 0,
                                }
                            }
                        }
                        Err(e) => Response {
                            id: req.id,
                            result: serde_json::Value::Null,
                            error: Some(format!("Handler error: {}", e)),
                            processing_time_us: 0,
                        }
                    }
                })
            });
            Ok(())
        })
    }
}

/// Python-accessible memory pool wrapper
#[pyclass(name = "MemoryPool")]
pub struct PyMemoryPool {
    pool: Arc<MemoryPool>,
}

#[pymethods]
impl PyMemoryPool {
    #[new]
    #[pyo3(signature = (size_mb=1024))]
    fn new(size_mb: Option<usize>) -> PyResult<Self> {
        let size = size_mb.unwrap_or(1024);
        let pool = MemoryPool::new(size)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to create memory pool: {}", e)))?;
        
        Ok(Self {
            pool: Arc::new(pool),
        })
    }
    
    /// Store data in learning storage
    fn store_learning(&self, key: String, data: &[u8]) -> PyResult<()> {
        self.pool.store_learning(key, data.to_vec())
            .map_err(|e| PyRuntimeError::new_err(format!("Store failed: {}", e)))
    }
    
    /// Retrieve data from learning storage
    fn get_learning(&self, key: &str) -> PyResult<Option<Vec<u8>>> {
        Ok(self.pool.get_learning(key).map(|b| b.to_vec()))
    }
    
    /// Reset working memory
    fn reset_working(&self) {
        self.pool.reset_working();
    }
    
    /// Get memory statistics
    fn get_stats(&self, py: Python) -> PyResult<PyObject> {
        let stats = self.pool.get_stats();
        
        let dict = PyDict::new(py);
        dict.set_item("allocations", stats.allocations)?;
        dict.set_item("deallocations", stats.deallocations)?;
        dict.set_item("working_memory_mb", stats.working_memory_mb)?;
        dict.set_item("learning_storage_mb", stats.learning_storage_mb)?;
        dict.set_item("total_size_mb", stats.total_size_mb)?;
        
        Ok(dict.into())
    }
}

/// Python-accessible message queue wrapper
#[pyclass(name = "MessageQueue")]
pub struct PyMessageQueue {
    queue: Arc<MessageQueue<serde_json::Value>>,
    runtime_handle: Handle,
}

#[pymethods]
impl PyMessageQueue {
    #[new]
    fn new() -> PyResult<Self> {
        Ok(Self {
            queue: Arc::new(MessageQueue::new()),
            runtime_handle: crate::RUNTIME.handle().clone(),
        })
    }
    
    /// Send a message
    #[pyo3(signature = (payload, priority=None))]
    fn send(&self, py: Python, payload: &PyAny, priority: Option<u8>) -> PyResult<u64> {
        let json_payload: serde_json::Value = pythonize::depythonize(payload)?;
        let prio = match priority {
            Some(0) => Priority::Low,
            Some(1) => Priority::Normal,
            Some(2) => Priority::High,
            Some(3) => Priority::Critical,
            _ => Priority::Normal,
        };
        
        self.queue.send(json_payload, prio)
            .map_err(|e| PyRuntimeError::new_err(format!("Send failed: {}", e)))
    }
    
    /// Try to receive a message (non-blocking)
    fn try_receive(&self, py: Python) -> PyResult<Option<PyObject>> {
        if let Some(msg) = self.queue.try_receive() {
            let dict = PyDict::new(py);
            dict.set_item("id", msg.id)?;
            dict.set_item("payload", pythonize::pythonize(py, &msg.payload)?)?;
            dict.set_item("timestamp", msg.timestamp)?;
            dict.set_item("priority", msg.priority as u8)?;
            Ok(Some(dict.into()))
        } else {
            Ok(None)
        }
    }
    
    /// Receive with timeout (in seconds)
    #[pyo3(signature = (timeout_secs=1.0))]
    fn receive_timeout(&self, py: Python, timeout_secs: Option<f64>) -> PyResult<Option<PyObject>> {
        let timeout = std::time::Duration::from_secs_f64(timeout_secs.unwrap_or(1.0));
        
        let msg = py.allow_threads(|| {
            self.runtime_handle.block_on(async {
                self.queue.receive_timeout(timeout).await
            })
        });
        
        if let Some(msg) = msg {
            let dict = PyDict::new(py);
            dict.set_item("id", msg.id)?;
            dict.set_item("payload", pythonize::pythonize(py, &msg.payload)?)?;
            dict.set_item("timestamp", msg.timestamp)?;
            dict.set_item("priority", msg.priority as u8)?;
            Ok(Some(dict.into()))
        } else {
            Ok(None)
        }
    }
    
    /// Get queue statistics
    fn get_stats(&self, py: Python) -> PyResult<PyObject> {
        let stats = self.queue.get_stats();
        
        let dict = PyDict::new(py);
        dict.set_item("messages_sent", stats.messages_sent)?;
        dict.set_item("messages_received", stats.messages_received)?;
        dict.set_item("messages_dropped", stats.messages_dropped)?;
        dict.set_item("avg_latency_ns", stats.avg_latency_ns)?;
        
        let queue_sizes = PyList::new(py, &stats.queue_sizes);
        dict.set_item("queue_sizes", queue_sizes)?;
        
        Ok(dict.into())
    }
}

/// Python-accessible state manager wrapper
#[pyclass(name = "StateManager")]
pub struct PyStateManager {
    manager: Arc<StateManager>,
}

#[pymethods]
impl PyStateManager {
    #[new]
    fn new() -> PyResult<Self> {
        Ok(Self {
            manager: Arc::new(StateManager::new()),
        })
    }
    
    /// Get state value
    fn get(&self, py: Python, key: &str) -> PyResult<Option<PyObject>> {
        if let Some(entry) = self.manager.get(key) {
            let dict = PyDict::new(py);
            dict.set_item("key", &entry.key)?;
            dict.set_item("value", pythonize::pythonize(py, &entry.value)?)?;
            dict.set_item("version", entry.version)?;
            dict.set_item("created_at", entry.created_at)?;
            dict.set_item("updated_at", entry.updated_at)?;
            dict.set_item("access_count", entry.access_count)?;
            Ok(Some(dict.into()))
        } else {
            Ok(None)
        }
    }
    
    /// Set state value
    fn set(&self, key: String, value: &PyAny) -> PyResult<u64> {
        let json_value: serde_json::Value = pythonize::depythonize(value)?;
        self.manager.set(key, json_value)
            .map_err(|e| PyRuntimeError::new_err(format!("Set failed: {}", e)))
    }
    
    /// Delete state entry
    fn delete(&self, key: &str) -> bool {
        self.manager.delete(key)
    }
    
    /// Compare and swap
    fn compare_and_swap(&self, key: &str, expected_version: u64, value: &PyAny) -> PyResult<u64> {
        let json_value: serde_json::Value = pythonize::depythonize(value)?;
        self.manager.compare_exchange(key, expected_version, json_value, Ordering::Relaxed).is_ok()
            .map_err(|e| PyRuntimeError::new_err(format!("CAS failed: {}", e)))
    }
    
    /// Get state statistics
    fn get_stats(&self, py: Python) -> PyResult<PyObject> {
        let stats = self.manager.get_stats();
        
        let dict = PyDict::new(py);
        dict.set_item("total_entries", stats.total_entries)?;
        dict.set_item("hot_cache_entries", stats.hot_cache_entries)?;
        dict.set_item("reads", stats.reads)?;
        dict.set_item("writes", stats.writes)?;
        dict.set_item("cache_hits", stats.cache_hits)?;
        dict.set_item("cache_misses", stats.cache_misses)?;
        dict.set_item("cache_hit_rate", stats.cache_hit_rate)?;
        dict.set_item("version_conflicts", stats.version_conflicts)?;
        
        Ok(dict.into())
    }
    
    /// Clear all state
    fn clear(&self) {
        self.manager.clear();
    }
}

/// Initialize the Rust core system
#[pyfunction]
fn initialize() -> PyResult<()> {
    crate::initialize()
        .map_err(|e| PyRuntimeError::new_err(format!("Initialization failed: {}", e)))
}

/// Python module definition
#[pymodule]
fn mcp_rust_core(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(initialize, m)?)?;
    m.add_class::<PyMCPServer>()?;
    m.add_class::<PyMemoryPool>()?;
    m.add_class::<PyMessageQueue>()?;
    m.add_class::<PyStateManager>()?;
    Ok(())
}