//! FFI Security Module - Comprehensive Protection for Python-Rust Boundary
//! 
//! Provides security patterns and utilities to prevent undefined behavior,
//! memory corruption, and other vulnerabilities at the FFI boundary.
//!
//! By: The Greatest Synthetic Distinguished Cybersecurity Synthetic Being in History

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString, PyList, PyDict};
use pyo3::exceptions::{PyValueError, PyTypeError, PyRuntimeError};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;
use parking_lot::Mutex;
use thiserror::Error;

/// Maximum allowed buffer size (100MB) to prevent DoS
pub const MAX_BUFFER_SIZE: usize = 100 * 1024 * 1024;

/// Maximum string length (10MB) to prevent memory exhaustion
pub const MAX_STRING_LENGTH: usize = 10 * 1024 * 1024;

/// Maximum collection size to prevent algorithmic complexity attacks
pub const MAX_COLLECTION_SIZE: usize = 1_000_000;

#[derive(Error, Debug)]
pub enum FFISecurityError {
    #[error("Buffer size exceeds maximum allowed: {size} > {max}")]
    BufferTooLarge { size: usize, max: usize },
    
    #[error("String length exceeds maximum allowed: {len} > {max}")]
    StringTooLong { len: usize, max: usize },
    
    #[error("Collection size exceeds maximum allowed: {size} > {max}")]
    CollectionTooLarge { size: usize, max: usize },
    
    #[error("Invalid UTF-8 in string data")]
    InvalidUtf8,
    
    #[error("Type mismatch: expected {expected}, got {actual}")]
    TypeMismatch { expected: String, actual: String },
    
    #[error("Null pointer encountered")]
    NullPointer,
    
    #[error("Integer overflow in size calculation")]
    IntegerOverflow,
    
    #[error("Panic caught at FFI boundary: {message}")]
    PanicCaught { message: String },
}

/// Trait for validating inputs at the FFI boundary
pub trait InputValidator {
    fn validate(&self) -> Result<(), FFISecurityError>;
}

/// Safe buffer operations with comprehensive validation
pub struct SafeBuffer {
    data: Vec<u8>,
    validated: bool,
}

impl SafeBuffer {
    /// Create a new SafeBuffer from PyBytes with validation
    pub fn from_pybytes(py: Python, bytes: &PyBytes) -> PyResult<Self> {
        // Get buffer info safely
        let buffer = bytes.as_bytes();
        let size = buffer.len();
        
        // Validate size
        if size > MAX_BUFFER_SIZE {
            return Err(FFISecurityError::BufferTooLarge {
                size,
                max: MAX_BUFFER_SIZE,
            }.into());
        }
        
        // Check for potential integer overflow
        if size.checked_add(1).is_none() {
            return Err(FFISecurityError::IntegerOverflow.into());
        }
        
        // Create safe copy
        let data = buffer.to_vec();
        
        Ok(Self {
            data,
            validated: true,
        })
    }
    
    /// Get validated data
    pub fn data(&self) -> &[u8] {
        assert!(self.validated, "Attempting to use unvalidated buffer");
        &self.data
    }
    
    /// Get mutable validated data
    pub fn data_mut(&mut self) -> &mut [u8] {
        assert!(self.validated, "Attempting to use unvalidated buffer");
        &mut self.data
    }
    
    /// Validate and get a slice with bounds checking
    pub fn get_slice(&self, start: usize, end: usize) -> Result<&[u8], FFISecurityError> {
        if start > end {
            return Err(FFISecurityError::InvalidUtf8); // Better error needed
        }
        
        if end > self.data.len() {
            return Err(FFISecurityError::IntegerOverflow);
        }
        
        Ok(&self.data[start..end])
    }
}

/// Safe string operations with validation
pub struct SafeString {
    data: String,
    validated: bool,
}

impl SafeString {
    /// Create from PyString with validation
    pub fn from_pystring(py: Python, string: &PyString) -> PyResult<Self> {
        let rust_string = string.to_str()?;
        let len = rust_string.len();
        
        // Validate length
        if len > MAX_STRING_LENGTH {
            return Err(FFISecurityError::StringTooLong {
                len,
                max: MAX_STRING_LENGTH,
            }.into());
        }
        
        // Check for null bytes (can cause issues in C APIs)
        if rust_string.contains('\0') {
            return Err(PyValueError::new_err("String contains null bytes"));
        }
        
        Ok(Self {
            data: rust_string.to_string(),
            validated: true,
        })
    }
    
    /// Get validated string
    pub fn as_str(&self) -> &str {
        assert!(self.validated, "Attempting to use unvalidated string");
        &self.data
    }
}

/// Panic protection wrapper for FFI functions
pub fn safe_ffi_wrapper<F, R>(f: F) -> PyResult<R>
where
    F: FnOnce() -> PyResult<R> + std::panic::UnwindSafe,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(result) => result,
        Err(panic) => {
            let message = if let Some(s) = panic.downcast_ref::<String>() {
                s.clone()
            } else if let Some(s) = panic.downcast_ref::<&str>() {
                s.to_string()
            } else {
                "Unknown panic".to_string()
            };
            
            Err(FFISecurityError::PanicCaught { message }.into())
        }
    }
}

/// Resource guard for automatic cleanup
pub struct ResourceGuard<T: Send> {
    resource: Option<Arc<Mutex<T>>>,
    cleanup: Option<Box<dyn FnOnce(T) + Send>>,
}

impl<T: Send + 'static> ResourceGuard<T> {
    pub fn new(resource: T, cleanup: impl FnOnce(T) + Send + 'static) -> Self {
        Self {
            resource: Some(Arc::new(Mutex::new(resource))),
            cleanup: Some(Box::new(cleanup)),
        }
    }
    
    pub fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        let resource = self.resource.as_ref().expect("Resource already consumed");
        let mut guard = resource.lock();
        f(&mut *guard)
    }
}

impl<T: Send> Drop for ResourceGuard<T> {
    fn drop(&mut self) {
        if let (Some(resource), Some(cleanup)) = (self.resource.take(), self.cleanup.take()) {
            if let Ok(inner) = Arc::try_unwrap(resource) {
                let value = inner.into_inner();
                cleanup(value);
            }
        }
    }
}

/// Type-safe extraction with validation
pub trait SafeExtract: Sized {
    fn safe_extract(ob: &PyAny) -> PyResult<Self>;
}

impl SafeExtract for Vec<u8> {
    fn safe_extract(ob: &PyAny) -> PyResult<Self> {
        let bytes: &PyBytes = ob.downcast()?;
        let buffer = SafeBuffer::from_pybytes(ob.py(), bytes)?;
        Ok(buffer.data)
    }
}

impl SafeExtract for String {
    fn safe_extract(ob: &PyAny) -> PyResult<Self> {
        let string: &PyString = ob.downcast()?;
        let safe_string = SafeString::from_pystring(ob.py(), string)?;
        Ok(safe_string.data)
    }
}

/// Collection size validator
pub fn validate_collection_size(size: usize) -> PyResult<()> {
    if size > MAX_COLLECTION_SIZE {
        return Err(FFISecurityError::CollectionTooLarge {
            size,
            max: MAX_COLLECTION_SIZE,
        }.into());
    }
    Ok(())
}

/// Safe list extraction with size limits
pub fn safe_extract_list<'py, T: FromPyObject<'py>>(list: &'py PyList) -> PyResult<Vec<T>> {
    let size = list.len();
    validate_collection_size(size)?;
    
    let mut result = Vec::with_capacity(size);
    for item in list.iter() {
        result.push(item.extract()?);
    }
    
    Ok(result)
}

/// Safe dict extraction with size limits
pub fn safe_extract_dict(dict: &PyDict) -> PyResult<std::collections::HashMap<String, PyObject>> {
    let size = dict.len();
    validate_collection_size(size)?;
    
    let mut result = std::collections::HashMap::with_capacity(size);
    for (key, value) in dict.iter() {
        let key_str: String = key.extract()?;
        
        // Validate key
        if key_str.len() > MAX_STRING_LENGTH {
            return Err(FFISecurityError::StringTooLong {
                len: key_str.len(),
                max: MAX_STRING_LENGTH,
            }.into());
        }
        
        result.insert(key_str, value.to_object(dict.py()));
    }
    
    Ok(result)
}

/// Macro for creating safe FFI functions
#[macro_export]
macro_rules! safe_pyfunction {
    ($name:ident, $body:expr) => {
        #[pyfunction]
        pub fn $name(py: Python) -> PyResult<PyObject> {
            $crate::ffi_security::safe_ffi_wrapper(|| {
                $body(py)
            })
        }
    };
}

/// Example secure vault implementation fixing the static nonce vulnerability
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key
};
use rand::RngCore;

#[pyclass]
pub struct SecureVault {
    cipher: Aes256Gcm,
}

#[pymethods]
impl SecureVault {
    #[new]
    fn new(key: &PyBytes) -> PyResult<Self> {
        let key_data = SafeBuffer::from_pybytes(key.py(), key)?;
        
        if key_data.data().len() != 32 {
            return Err(PyValueError::new_err("Key must be exactly 32 bytes"));
        }
        
        let key = Key::<Aes256Gcm>::from_slice(key_data.data());
        let cipher = Aes256Gcm::new(key);
        
        Ok(Self { cipher })
    }
    
    fn encrypt(&self, py: Python, plaintext: &PyBytes) -> PyResult<PyObject> {
        {
            let input = SafeBuffer::from_pybytes(py, plaintext)?;
            
            // Generate unique nonce for each encryption
            let mut nonce = [0u8; 12];
            OsRng.fill_bytes(&mut nonce);
            let nonce_obj = Nonce::from_slice(&nonce);
            
            // Encrypt
            let ciphertext = self.cipher
                .encrypt(nonce_obj, input.data())
                .map_err(|_| PyRuntimeError::new_err("Encryption failed"))?;
            
            // Return nonce + ciphertext
            let mut result = nonce.to_vec();
            result.extend_from_slice(&ciphertext);
            
            Ok(PyBytes::new(py, &result).into())
        }
    }
    
    fn decrypt(&self, py: Python, data: &PyBytes) -> PyResult<PyObject> {
        {
            let input = SafeBuffer::from_pybytes(py, data)?;
            
            if input.data().len() < 12 {
                return Err(PyValueError::new_err("Invalid ciphertext"));
            }
            
            // Extract nonce and ciphertext
            let (nonce_bytes, ciphertext) = input.data().split_at(12);
            let nonce = Nonce::from_slice(nonce_bytes);
            
            // Decrypt
            let plaintext = self.cipher
                .decrypt(nonce, ciphertext)
                .map_err(|_| PyRuntimeError::new_err("Decryption failed"))?;
            
            Ok(PyBytes::new(py, &plaintext).into())
        }
    }
}

/// Signal safety utilities
pub mod signal_safety {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    
    /// Interruptible operation guard
    pub struct InterruptGuard {
        should_stop: Arc<AtomicBool>,
    }
    
    impl InterruptGuard {
        pub fn new() -> Self {
            Self {
                should_stop: Arc::new(AtomicBool::new(false)),
            }
        }
        
        pub fn should_stop(&self) -> bool {
            self.should_stop.load(Ordering::Relaxed)} // TODO: Review memory ordering - consider Acquire/Release
        
        pub fn stop_handle(&self) -> Arc<AtomicBool> {
            self.should_stop.clone()
        }
    }
}

/// FFI error conversion
impl From<FFISecurityError> for PyErr {
    fn from(err: FFISecurityError) -> PyErr {
        match err {
            FFISecurityError::BufferTooLarge { .. } |
            FFISecurityError::StringTooLong { .. } |
            FFISecurityError::CollectionTooLarge { .. } => {
                PyValueError::new_err(err.to_string())
            }
            FFISecurityError::InvalidUtf8 |
            FFISecurityError::TypeMismatch { .. } => {
                PyTypeError::new_err(err.to_string())
            }
            _ => PyRuntimeError::new_err(err.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_buffer_validation() {
        // Test size limits
        let large_buffer = vec![0u8; MAX_BUFFER_SIZE + 1];
        assert!(SafeBuffer::from_pybytes(py, &PyBytes::new(py, &large_buffer)).is_err());
        
        // Test normal buffer
        let normal_buffer = vec![1, 2, 3, 4];
        let safe = SafeBuffer::from_pybytes(py, &PyBytes::new(py, &normal_buffer)).unwrap();
        assert_eq!(safe.data(), &[1, 2, 3, 4]);
    }
    
    #[test]
    fn test_panic_protection() {
        let result = safe_ffi_wrapper(|| {
            panic!("Test panic");
            #[allow(unreachable_code)]
            Ok(42)
        });
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Test panic"));
    }
}