// ============================================================================
// FFI Security Test Suite
// ============================================================================
// Comprehensive tests for FFI security vulnerabilities including:
// - Buffer overflow detection
// - Type confusion prevention
// - Panic isolation
// - Memory leak detection
// - Signal safety
// - Resource cleanup verification
// ============================================================================

use claude_optimized_deployment_rust::ffi_security::*;
use pyo3::exceptions::{PyRuntimeError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

// ============================================================================
// Buffer Overflow Tests
// ============================================================================

#[test]
fn test_buffer_overflow_protection() {
    // Test integer overflow in size calculation
    let buffer = vec![0u8; 100];

    // This should fail due to integer overflow
    let result = safe_read_slice(&buffer, usize::MAX - 10, 20);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Integer overflow"));

    // This should fail due to out of bounds
    let result = safe_read_slice(&buffer, 90, 20);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("beyond buffer boundary"));

    // This should succeed
    let result = safe_read_slice(&buffer, 10, 20);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 20);
}

#[test]
fn test_safe_copy_buffer_limits() {
    // Test with default limit
    let large_buffer = vec![0u8; MAX_BUFFER_SIZE + 1];
    let result = safe_copy_buffer(&large_buffer, None);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("exceeds maximum allowed"));

    // Test with custom limit
    let buffer = vec![0u8; 1000];
    let result = safe_copy_buffer(&buffer, Some(500));
    assert!(result.is_err());

    // Test successful copy
    let result = safe_copy_buffer(&buffer, Some(2000));
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 1000);
}

// ============================================================================
// Type Confusion Tests
// ============================================================================

#[test]
fn test_string_validation() {
    Python::with_gil(|py| {
        // Test empty string
        let empty = "".to_string();
        assert!(empty.validate().is_err());

        // Test null bytes
        let with_null = "hello\0world".to_string();
        assert!(with_null.validate().is_err());

        // Test oversized string
        let huge = "x".repeat(MAX_STRING_LENGTH + 1);
        assert!(huge.validate().is_err());

        // Test valid string
        let valid = "Hello, world!".to_string();
        assert!(valid.validate().is_ok());
    });
}

#[test]
fn test_collection_validation() {
    // Test empty collection
    let empty: Vec<String> = vec![];
    assert!(empty.validate().is_err());

    // Test oversized collection
    let huge: Vec<usize> = vec![1; MAX_COLLECTION_SIZE + 1];
    assert!(huge.validate().is_err());

    // Test collection with invalid elements
    let with_invalid = vec![
        "valid".to_string(),
        "".to_string(),
        "also valid".to_string(),
    ];
    let result = with_invalid.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Item at index 1"));
}

// ============================================================================
// Panic Safety Tests
// ============================================================================

#[test]
fn test_panic_protection() {
    // Test panic is caught and converted to error
    let result = with_panic_protection(|| -> PyResult<()> {
        panic!("Test panic");
    });

    assert!(result.is_err());
    let err_str = result.unwrap_err().to_string();
    assert!(err_str.contains("Internal error occurred in Rust code"));
}

#[test]
fn test_panic_with_different_types() {
    // Test with string panic
    let result = with_panic_protection(|| -> PyResult<i32> {
        panic!("String panic");
    });
    assert!(result.is_err());

    // Test with String panic
    let result = with_panic_protection(|| -> PyResult<i32> {
        panic!("{}", String::from("String panic"));
    });
    assert!(result.is_err());

    // Test with other panic type
    let result = with_panic_protection(|| -> PyResult<i32> {
        panic!(42);
    });
    assert!(result.is_err());
}

#[test]
fn test_python_protection() {
    Python::with_gil(|py| {
        // Test normal operation
        let result = with_python_protection(py, || Ok(42));
        assert_eq!(result.unwrap(), 42);

        // Test with panic
        let result = with_python_protection(py, || -> PyResult<i32> {
            panic!("Test panic in Python context");
        });
        assert!(result.is_err());
    });
}

// ============================================================================
// Memory Management Tests
// ============================================================================

#[test]
fn test_resource_guard_cleanup() {
    let cleanup_called = Arc::new(AtomicUsize::new(0));
    let cleanup_called_clone = cleanup_called.clone();

    {
        let _guard = ResourceGuard::new(vec![1, 2, 3, 4, 5], move |_v| {
            cleanup_called_clone.fetch_add(1, Ordering::Relaxed);
        });
        // Guard should call cleanup on drop
    }

    assert_eq!(cleanup_called.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release, 1);
}

#[test]
fn test_resource_guard_take() {
    let cleanup_called = Arc::new(AtomicUsize::new(0));
    let cleanup_called_clone = cleanup_called.clone();

    let guard = ResourceGuard::new(vec![1, 2, 3], move |_v| {
        cleanup_called_clone.fetch_add(1, Ordering::Relaxed);
    });

    // Take ownership - cleanup should not be called
    let data = guard.take();
    assert_eq!(data, vec![1, 2, 3]);
    assert_eq!(cleanup_called.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release, 0);
}

#[test]
fn test_resource_guard_panic_safety() {
    let cleanup_called = Arc::new(AtomicUsize::new(0));
    let cleanup_called_clone = cleanup_called.clone();

    let result = std::panic::catch_unwind(|| {
        let _guard = ResourceGuard::new(vec![1, 2, 3], {
            let cleanup_called = cleanup_called_clone.clone();
            move |_v| {
                cleanup_called.fetch_add(1, Ordering::Relaxed);
            }
        });
        panic!("Test panic");
    });

    assert!(result.is_err());
    // Cleanup should still be called despite panic
    assert_eq!(cleanup_called.load(Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release, 1);
}

// ============================================================================
// Signal Safety Tests
// ============================================================================

#[test]
fn test_interruption_check() {
    // Reset shutdown flag
    SHUTDOWN_REQUESTED.store(false, Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release;

    // Normal operation
    let result = with_interruption_check(|| Ok(42));
    assert_eq!(result.unwrap(), 42);

    // Request shutdown
    request_shutdown();

    // Should fail now
    let result = with_interruption_check(|| Ok(42));
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("interrupted by shutdown"));

    // Reset for other tests
    SHUTDOWN_REQUESTED.store(false, Ordering::Relaxed) // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release // TODO: Review memory ordering - consider Acquire/Release;
}

// ============================================================================
// Input Extraction Tests
// ============================================================================

#[test]
fn test_extract_validated_string() {
    Python::with_gil(|py| {
        // Valid string
        let py_str = pyo3::types::PyString::new(py, "Hello, world!");
        let result = extract_validated_string(py_str.as_ref(), "test_field");
        assert_eq!(result.unwrap(), "Hello, world!");

        // Empty string
        let py_str = pyo3::types::PyString::new(py, "");
        let result = extract_validated_string(py_str.as_ref(), "test_field");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("test_field"));

        // Wrong type
        let py_int = pyo3::types::PyInt::new(py, 42);
        let result = extract_validated_string(py_int.as_ref(), "test_field");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be a string"));
    });
}

#[test]
fn test_extract_validated_buffer() {
    Python::with_gil(|py| {
        // Valid buffer
        let py_bytes = pyo3::types::PyBytes::new(py, &[1, 2, 3, 4, 5]);
        let result = extract_validated_buffer(py_bytes.as_ref(), "test_buffer");
        assert_eq!(result.unwrap(), vec![1, 2, 3, 4, 5]);

        // Empty buffer
        let py_bytes = pyo3::types::PyBytes::new(py, &[]);
        let result = extract_validated_buffer(py_bytes.as_ref(), "test_buffer");
        assert!(result.is_err());

        // Wrong type
        let py_str = pyo3::types::PyString::new(py, "not bytes");
        let result = extract_validated_buffer(py_str.as_ref(), "test_buffer");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must be a bytes object"));
    });
}

#[test]
fn test_extract_validated_usize() {
    Python::with_gil(|py| {
        // Valid range
        let py_int = pyo3::types::PyInt::new(py, 50);
        let result = extract_validated_usize(py_int.as_ref(), "test_int", 1, 100);
        assert_eq!(result.unwrap(), 50);

        // Below minimum
        let py_int = pyo3::types::PyInt::new(py, 0);
        let result = extract_validated_usize(py_int.as_ref(), "test_int", 1, 100);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must be between 1 and 100"));

        // Above maximum
        let py_int = pyo3::types::PyInt::new(py, 200);
        let result = extract_validated_usize(py_int.as_ref(), "test_int", 1, 100);
        assert!(result.is_err());

        // Wrong type
        let py_str = pyo3::types::PyString::new(py, "not a number");
        let result = extract_validated_usize(py_str.as_ref(), "test_int", 1, 100);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must be an integer"));
    });
}

// ============================================================================
// Error Context Tests
// ============================================================================

#[test]
fn test_error_context() {
    let result: Result<(), PyErr> = Err(PyValueError::new_err("Original error"));
    let contextualized = result.context("Additional context");

    assert!(contextualized.is_err());
    let err_str = contextualized.unwrap_err().to_string();
    assert!(err_str.contains("Additional context"));
    assert!(err_str.contains("Original error"));
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_secure_ffi_function_macro() {
    Python::with_gil(|py| {
        fn example_function(data: Vec<u8>, count: usize) -> PyResult<usize> {
            Ok(data.len() * count)
        }

        // This would use the macro in real code:
        // let result = secure_ffi_function!(example_function, py, data: Vec<u8>, count: usize);

        // For now, test the equivalent
        let data = vec![1, 2, 3];
        let count = 5;

        let result = with_python_protection(py, || {
            data.validate_with_context("data")?;
            count.validate_with_context("count")?;
            example_function(data, count)
        });

        assert_eq!(result.unwrap(), 15);
    });
}

// ============================================================================
// Fuzzing Helpers (for use with cargo-fuzz)
// ============================================================================

#[cfg(fuzzing)]
pub fn fuzz_safe_read_slice(data: &[u8]) {
    if data.len() < 16 {
        return;
    }

    let buffer_size = u64::from_le_bytes(data[0..8].try_into().unwrap()) as usize;
    let start = u64::from_le_bytes(data[8..16].try_into().unwrap()) as usize;
    let length = if data.len() > 24 {
        u64::from_le_bytes(data[16..24].try_into().unwrap()) as usize
    } else {
        10
    };

    let buffer = vec![0u8; buffer_size.min(1024 * 1024)]; // Cap at 1MB for fuzzing
    let _ = safe_read_slice(&buffer, start, length);
}

#[cfg(fuzzing)]
pub fn fuzz_string_validation(data: &[u8]) {
    if let Ok(s) = String::from_utf8(data.to_vec()) {
        let _ = s.validate();
    }
}
