// Minimal PyO3 test module for binding verification
use pyo3::prelude::*;
use pyo3::exceptions::{PyValueError, PyIOError, PyRuntimeError};
use pyo3::types::PyType;
use std::collections::HashMap;

/// Test function for basic type conversions
#[pyfunction]
fn test_type_conversion(
    s: String,
    i: i64,
    f: f64,
    b: bool,
    list: Vec<i32>,
    dict: HashMap<String, String>,
) -> PyResult<String> {
    Ok(format!(
        "Received: string='{}', int={}, float={}, bool={}, list={:?}, dict={:?}",
        s, i, f, b, list, dict
    ))
}

/// Test function that returns various Python types
#[pyfunction]
fn test_return_types() -> PyResult<(String, i64, f64, bool, Vec<i32>, HashMap<String, String>)> {
    let mut dict = HashMap::new();
    dict.insert("key".to_string(), "value".to_string());
    dict.insert("rust".to_string(), "python".to_string());
    
    Ok((
        "Hello from Rust".to_string(),
        42,
        3.14159,
        true,
        vec![1, 2, 3, 4, 5],
        dict,
    ))
}

/// Test exception propagation
#[pyfunction]
fn test_raise_value_error() -> PyResult<()> {
    Err(PyValueError::new_err("This is a test ValueError from Rust"))
}

#[pyfunction]
fn test_raise_io_error() -> PyResult<()> {
    Err(PyIOError::new_err("This is a test IOError from Rust"))
}

#[pyfunction]
fn test_raise_runtime_error() -> PyResult<()> {
    Err(PyRuntimeError::new_err("This is a test RuntimeError from Rust"))
}

/// Test GIL handling with CPU-intensive operation
#[pyfunction]
fn test_gil_release(iterations: usize) -> PyResult<u64> {
    Python::with_gil(|py| {
        // Release the GIL for CPU-intensive work
        py.allow_threads(|| {
            let mut sum = 0u64;
            for i in 0..iterations {
                sum += i as u64;
            }
            sum
        })
    })
}

/// Test memory allocation and cleanup
#[pyfunction]
fn test_memory_allocation(size: usize) -> PyResult<Vec<u8>> {
    // Allocate memory that should be properly cleaned up
    Ok(vec![0u8; size])
}

/// Test async function (requires pyo3-asyncio)
#[pyfunction]
fn test_async_function() -> PyResult<String> {
    // For now, just return a placeholder
    Ok("Async support requires pyo3-asyncio feature".to_string())
}

/// Test class with PyO3
#[pyclass]
struct TestClass {
    #[pyo3(get, set)]
    value: i32,
    internal: String,
}

#[pymethods]
impl TestClass {
    #[new]
    fn new(value: i32) -> Self {
        TestClass {
            value,
            internal: format!("Internal value: {}", value),
        }
    }
    
    fn increment(&mut self) -> PyResult<i32> {
        self.value += 1;
        Ok(self.value)
    }
    
    fn get_internal(&self) -> PyResult<String> {
        Ok(self.internal.clone())
    }
    
    #[staticmethod]
    fn static_method() -> PyResult<String> {
        Ok("Called static method".to_string())
    }
    
    #[classmethod]
    fn class_method(_cls: &PyType) -> PyResult<String> {
        Ok("Called class method".to_string())
    }
}

/// Register the test module
pub fn register_test_module(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(test_type_conversion, m)?)?;
    m.add_function(wrap_pyfunction!(test_return_types, m)?)?;
    m.add_function(wrap_pyfunction!(test_raise_value_error, m)?)?;
    m.add_function(wrap_pyfunction!(test_raise_io_error, m)?)?;
    m.add_function(wrap_pyfunction!(test_raise_runtime_error, m)?)?;
    m.add_function(wrap_pyfunction!(test_gil_release, m)?)?;
    m.add_function(wrap_pyfunction!(test_memory_allocation, m)?)?;
    m.add_function(wrap_pyfunction!(test_async_function, m)?)?;
    m.add_class::<TestClass>()?;
    Ok(())
}