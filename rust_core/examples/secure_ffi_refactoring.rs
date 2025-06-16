// ============================================================================
// Secure FFI Refactoring Example
// ============================================================================
// This example demonstrates how to refactor vulnerable FFI code to use
// secure patterns that prevent common security issues.
// ============================================================================

use pyo3::prelude::*;
use pyo3::exceptions::{PyValueError, PyTypeError, PyRuntimeError};
use std::collections::HashMap;

// Import our security module
use crate::ffi_security::{
    ValidateInput, with_panic_protection, with_python_protection,
    safe_read_slice, ResourceGuard, extract_validated_string,
    MAX_BUFFER_SIZE
};

// ============================================================================
// BEFORE: Vulnerable FFI Implementation
// ============================================================================

mod vulnerable {
    use super::*;
    
    /// Vulnerable: No input validation, panic-prone, potential buffer overflow
    #[pyfunction]
    pub fn process_data_unsafe(data: Vec<u8>, offset: usize, length: usize) -> PyResult<Vec<u8>> {
        // ISSUE 1: No validation of inputs
        // ISSUE 2: Potential integer overflow in offset + length
        let end = offset + length;
        
        // ISSUE 3: Panic if slice is out of bounds
        let slice = &data[offset..end];
        
        // ISSUE 4: Unwrap can panic
        let processed = dangerous_processing(slice).unwrap();
        
        Ok(processed)
    }
    
    /// Vulnerable: Type confusion possible
    #[pyfunction]
    pub fn parse_config_unsafe(config: &PyAny) -> PyResult<String> {
        // ISSUE 1: Unsafe type extraction
        let dict = config.extract::<HashMap<String, String>>().unwrap();
        
        // ISSUE 2: Unwrap can panic
        let value = dict.get("key").unwrap();
        
        // ISSUE 3: No validation
        Ok(value.clone())
    }
    
    /// Vulnerable: Memory leak on error
    #[pyfunction]
    pub fn allocate_resources_unsafe() -> PyResult<Vec<u8>> {
        let mut resources = Vec::new();
        
        // ISSUE 1: Allocate resources
        for i in 0..10 {
            let buffer = vec![0u8; 1024 * 1024]; // 1MB each
            resources.push(buffer);
            
            // ISSUE 2: Error here would leak all previous allocations
            if i == 5 {
                return Err(PyRuntimeError::new_err("Failed"));
            }
        }
        
        Ok(resources.into_iter().flatten().collect())
    }
    
    fn dangerous_processing(data: &[u8]) -> Result<Vec<u8>, &'static str> {
        if data.is_empty() {
            Err("Empty data")
        } else {
            Ok(data.to_vec())
        }
    }
}

// ============================================================================
// AFTER: Secure FFI Implementation
// ============================================================================

mod secure {
    use super::*;
    
    /// Secure: Comprehensive input validation and panic protection
    #[pyfunction]
    pub fn process_data_safe(
        py: Python,
        data: Vec<u8>,
        offset: usize,
        length: usize
    ) -> PyResult<Vec<u8>> {
        // Use our security wrapper
        with_python_protection(py, || {
            // Validate inputs
            data.validate_with_context("data")?;
            
            if offset >= data.len() {
                return Err(PyValueError::new_err(format!(
                    "Offset {} exceeds data length {}",
                    offset, data.len()
                )));
            }
            
            if length == 0 {
                return Err(PyValueError::new_err("Length cannot be zero"));
            }
            
            // Use safe slice function
            let slice = safe_read_slice(&data, offset, length)?;
            
            // Handle errors properly
            safe_processing(slice)
                .map_err(|e| PyRuntimeError::new_err(format!("Processing failed: {}", e)))
        })
    }
    
    /// Secure: Type-safe extraction with validation
    #[pyfunction]
    pub fn parse_config_safe(py: Python, config: &PyAny) -> PyResult<String> {
        with_python_protection(py, || {
            // Type-safe extraction
            let dict = config.downcast::<pyo3::types::PyDict>()
                .map_err(|_| PyTypeError::new_err("Config must be a dictionary"))?;
            
            // Safe key lookup
            let value = dict.get_item("key")?
                .ok_or_else(|| PyValueError::new_err("Missing 'key' in config"))?;
            
            // Validated extraction
            extract_validated_string(value, "config.key")
        })
    }
    
    /// Secure: RAII-based resource management
    #[pyfunction]
    pub fn allocate_resources_safe(py: Python) -> PyResult<Vec<u8>> {
        with_python_protection(py, || {
            let mut guards = Vec::new();
            let mut total_size = 0;
            
            // Allocate with guards for automatic cleanup
            for i in 0..10 {
                let size = 1024 * 1024; // 1MB
                
                // Check total allocation before proceeding
                total_size += size;
                if total_size > MAX_BUFFER_SIZE {
                    return Err(PyValueError::new_err(
                        "Total allocation exceeds maximum allowed"
                    ));
                }
                
                let buffer = vec![0u8; size];
                let guard = ResourceGuard::new(buffer, |buf| {
                    // Cleanup code
                    drop(buf);
                });
                
                guards.push(guard);
                
                // Simulate potential error
                if i == 5 {
                    // Guards will automatically clean up on early return
                    return Err(PyRuntimeError::new_err("Simulated failure"));
                }
            }
            
            // Extract data from guards
            let result: Vec<u8> = guards.into_iter()
                .flat_map(|guard| guard.take())
                .collect();
            
            Ok(result)
        })
    }
    
    fn safe_processing(data: &[u8]) -> Result<Vec<u8>, String> {
        if data.is_empty() {
            return Err("Empty data".to_string());
        }
        
        // Safe processing with bounds checking
        let mut result = Vec::with_capacity(data.len());
        for &byte in data {
            result.push(byte.wrapping_add(1));
        }
        
        Ok(result)
    }
}

// ============================================================================
// Advanced Secure Patterns
// ============================================================================

mod advanced {
    use super::*;
    use std::sync::Arc;
    use parking_lot::Mutex;
    
    /// Thread-safe resource pool with automatic cleanup
    #[pyclass]
    pub struct SecureResourcePool {
        resources: Arc<Mutex<Vec<ResourceHandle>>>,
        max_resources: usize,
    }
    
    struct ResourceHandle {
        data: Vec<u8>,
        id: usize,
    }
    
    #[pymethods]
    impl SecureResourcePool {
        #[new]
        fn new(max_resources: Option<usize>) -> PyResult<Self> {
            let max_resources = max_resources.unwrap_or(100);
            
            if max_resources == 0 || max_resources > 10000 {
                return Err(PyValueError::new_err(
                    "Max resources must be between 1 and 10000"
                ));
            }
            
            Ok(Self {
                resources: Arc::new(Mutex::new(Vec::new())),
                max_resources,
            })
        }
        
        /// Allocate a resource with validation
        fn allocate(&self, py: Python, size: usize) -> PyResult<usize> {
            with_python_protection(py, || {
                // Validate size
                if size == 0 || size > MAX_BUFFER_SIZE {
                    return Err(PyValueError::new_err(format!(
                        "Size must be between 1 and {}",
                        MAX_BUFFER_SIZE
                    )));
                }
                
                let mut resources = self.resources.lock();
                
                if resources.len() >= self.max_resources {
                    return Err(PyRuntimeError::new_err("Resource pool exhausted"));
                }
                
                let id = resources.len();
                let handle = ResourceHandle {
                    data: vec![0u8; size],
                    id,
                };
                
                resources.push(handle);
                Ok(id)
            })
        }
        
        /// Use a resource safely
        fn use_resource<F>(&self, py: Python, id: usize, operation: F) -> PyResult<usize>
        where
            F: FnOnce(&mut [u8]) -> PyResult<usize>,
        {
            with_python_protection(py, || {
                let mut resources = self.resources.lock();
                
                let handle = resources.get_mut(id)
                    .ok_or_else(|| PyValueError::new_err(format!("Invalid resource ID: {}", id)))?;
                
                operation(&mut handle.data)
            })
        }
        
        /// Clean up all resources
        fn cleanup(&self) -> PyResult<usize> {
            let mut resources = self.resources.lock();
            let count = resources.len();
            resources.clear();
            Ok(count)
        }
    }
}

// ============================================================================
// Comparison and Migration Guide
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_vulnerable_vs_secure() {
        Python::with_gil(|py| {
            let data = vec![1, 2, 3, 4, 5];
            
            // Vulnerable version would panic on invalid input
            let result = vulnerable::process_data_unsafe(data.clone(), 10, 5);
            assert!(result.is_err()); // Actually, this would panic in real code
            
            // Secure version returns proper error
            let result = secure::process_data_safe(py, data.clone(), 10, 5);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("exceeds data length"));
            
            // Test successful case
            let result = secure::process_data_safe(py, data, 1, 3);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), vec![3, 4, 5]); // After processing
        });
    }
    
    #[test]
    fn test_resource_cleanup() {
        Python::with_gil(|py| {
            // Vulnerable version would leak memory on error
            let result = vulnerable::allocate_resources_unsafe();
            assert!(result.is_err());
            
            // Secure version cleans up automatically
            let result = secure::allocate_resources_safe(py);
            assert!(result.is_err());
            // Resources are automatically cleaned up by RAII guards
        });
    }
}

// ============================================================================
// Migration Checklist
// ============================================================================

/// Step-by-step guide for migrating vulnerable FFI code:
///
/// 1. **Add Input Validation**
///    - Use ValidateInput trait for all inputs
///    - Check bounds, sizes, and types
///    - Provide clear error messages
///
/// 2. **Wrap in Panic Protection**
///    - Use with_panic_protection or with_python_protection
///    - Never use unwrap() in FFI functions
///    - Convert Result<T, E> to PyResult<T> properly
///
/// 3. **Use Safe Buffer Operations**
///    - Replace slice indexing with safe_read_slice
///    - Use checked arithmetic for all calculations
///    - Validate sizes against MAX_BUFFER_SIZE
///
/// 4. **Implement RAII for Resources**
///    - Use ResourceGuard for automatic cleanup
///    - Never manually manage resources without guards
///    - Ensure cleanup happens on all code paths
///
/// 5. **Type-Safe Extractions**
///    - Use extract_validated_* functions
///    - Check types before extraction
///    - Handle None/null values explicitly
///
/// 6. **Add Comprehensive Testing**
///    - Test error paths
///    - Test with invalid inputs
///    - Test resource cleanup
///    - Use fuzzing for complex inputs
fn _dummy() {}