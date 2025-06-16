// Minimal lib.rs for testing PyO3 bindings
use pyo3::prelude::*;

pub mod test_bindings;

/// Python module definition - minimal version for testing
#[pymodule]
fn claude_optimized_deployment_rust(py: Python, m: &PyModule) -> PyResult<()> {
    // Register test bindings module
    let test_module = PyModule::new(py, "test_bindings")?;
    test_bindings::register_test_module(py, test_module)?;
    m.add_submodule(test_module)?;
    
    // Add version info
    m.add("__version__", "0.1.0-test")?;
    
    Ok(())
}