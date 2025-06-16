//! Python FFI bindings for MCP Learning Core

use pyo3::prelude::*;
use crate::CoreConfig;

/// Python wrapper for CoreConfig
#[pyclass]
pub struct PyMCPConfig {
    #[pyo3(get, set)]
    pub max_connections: usize,
    #[pyo3(get, set)]
    pub message_buffer_size: usize,
    #[pyo3(get, set)]
    pub state_cache_size: usize,
    #[pyo3(get, set)]
    pub shared_memory_size: usize,
    #[pyo3(get, set)]
    pub ring_buffer_size: usize,
    #[pyo3(get, set)]
    pub max_message_size: usize,
}

#[pymethods]
impl PyMCPConfig {
    #[new]
    fn new() -> Self {
        let config = CoreConfig::default();
        Self {
            max_connections: config.max_connections,
            message_buffer_size: config.message_buffer_size,
            state_cache_size: config.state_cache_size,
            shared_memory_size: config.shared_memory_size,
            ring_buffer_size: config.ring_buffer_size,
            max_message_size: config.max_message_size,
        }
    }

}

/// Python wrapper for MCPLearningCore
#[pyclass]
pub struct PyMCPCore {
    #[pyo3(get)]
    pub initialized: bool,
}

#[pymethods]
impl PyMCPCore {
    #[new]
    fn new() -> Self {
        Self {
            initialized: false,
        }
    }

    fn initialize(&mut self, config: &PyMCPConfig) -> PyResult<()> {
        // TODO: Implement async initialization
        self.initialized = true;
        Ok(())
    }

    fn is_initialized(&self) -> bool {
        self.initialized
    }

    fn get_stats(&self) -> PyResult<String> {
        Ok("Stats: placeholder".to_string())
    }
}

/// Initialize the Python module
#[pymodule]
fn mcp_rust_core(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyMCPConfig>()?;
    m.add_class::<PyMCPCore>()?;
    
    m.add_function(wrap_pyfunction!(get_version, m)?)?;
    
    Ok(())
}

#[pyfunction]
fn get_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}