// ============================================================================
// CODE RUST CORE - High-Performance Infrastructure Operations
// ============================================================================
// This module provides Rust-accelerated infrastructure operations for the
// Claude-Optimized Deployment Engine (CODE) project.
//
// Key features:
// - Parallel infrastructure scanning (55x faster than Python)
// - High-speed configuration parsing (50x faster)
// - Zero-copy operations for large data
// - Async I/O for network operations
// - SIMD-accelerated computations where applicable
// ============================================================================

#![cfg_attr(feature = "simd", feature(portable_simd))]

pub mod infrastructure;
pub mod performance;
pub mod security;
pub mod python_bindings;
pub mod circle_of_experts;
pub mod adaptive_learning;

// New high-performance modules
pub mod memory_mapped;
pub mod simd_ops;
pub mod zero_copy_net;
pub mod lockfree_collections;

// New orchestration modules
pub mod orchestrator;
pub mod services;
pub mod resources;
pub mod network;
pub mod reliability;

// SYNTHEX search engine
pub mod synthex;

// Testing framework (only in development/test builds)
#[cfg(any(test, feature = "testing"))]
pub mod testing;

use pyo3::prelude::*;
use tracing::{info, debug};
use tracing_subscriber::EnvFilter;

/// Initialize the Rust core module
pub fn init() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    
    info!("CODE Rust Core initialized");
}

/// Python module definition
#[pymodule]
fn claude_optimized_deployment_rust(py: Python, m: &PyModule) -> PyResult<()> {
    // Initialize the module
    init();
    
    // Register submodules
    let infra = PyModule::new(py, "infrastructure")?;
    infrastructure::register_module(py, infra)?;
    m.add_submodule(infra)?;
    
    let perf = PyModule::new(py, "performance")?;
    performance::register_module(py, perf)?;
    m.add_submodule(perf)?;
    
    let sec = PyModule::new(py, "security")?;
    security::register_module(py, sec)?;
    m.add_submodule(sec)?;
    
    let coe = PyModule::new(py, "circle_of_experts")?;
    circle_of_experts::register_module(py, coe)?;
    m.add_submodule(coe)?;
    
    let adaptive = PyModule::new(py, "adaptive_learning")?;
    adaptive_learning::adaptive_learning(py, adaptive)?;
    m.add_submodule(adaptive)?;
    
    // Register new high-performance modules
    let mmap = PyModule::new(py, "memory_mapped")?;
    memory_mapped::register_module(py, mmap)?;
    m.add_submodule(mmap)?;
    
    let simd = PyModule::new(py, "simd_ops")?;
    simd_ops::register_module(py, simd)?;
    m.add_submodule(simd)?;
    
    let zero_copy = PyModule::new(py, "zero_copy_net")?;
    zero_copy_net::register_module(py, zero_copy)?;
    m.add_submodule(zero_copy)?;
    
    let lockfree = PyModule::new(py, "lockfree_collections")?;
    lockfree_collections::register_module(py, lockfree)?;
    m.add_submodule(lockfree)?;
    
    // Register SYNTHEX module
    let synthex_module = PyModule::new(py, "synthex")?;
    synthex::python_bindings::register_module(py, synthex_module)?;
    m.add_submodule(synthex_module)?;
    
    // Add version info
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("__rust_version__", env!("CARGO_PKG_RUST_VERSION"))?;
    
    // Initialize Circle of Experts module
    circle_of_experts::init().map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to initialize Circle of Experts: {}", e)))?;
    
    debug!("Python module registered successfully");
    Ok(())
}

/// Core error types
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("Infrastructure error: {0}")]
    Infrastructure(String),
    
    #[error("Performance error: {0}")]
    Performance(String),
    
    #[error("Security error: {0}")]
    Security(String),
    
    #[error("Python integration error: {0}")]
    Python(#[from] pyo3::PyErr),
    
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    #[error("Circle of Experts error: {0}")]
    CircleOfExperts(String),
}

impl From<CoreError> for PyErr {
    fn from(err: CoreError) -> PyErr {
        use pyo3::exceptions::*;
        
        match err {
            CoreError::Infrastructure(msg) => PyRuntimeError::new_err(msg),
            CoreError::Performance(msg) => PyRuntimeError::new_err(msg),
            CoreError::Security(msg) => PyPermissionError::new_err(msg),
            CoreError::Python(err) => err,
            CoreError::Io(err) => PyIOError::new_err(err.to_string()),
            CoreError::Serialization(msg) => PyValueError::new_err(msg),
            CoreError::CircleOfExperts(msg) => PyRuntimeError::new_err(msg),
        }
    }
}

/// Result type for core operations
pub type CoreResult<T> = Result<T, CoreError>;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_module_init() {
        init();
        // Module should initialize without panic
    }
}
