// ============================================================================
// Async Helpers Module - Best Practices for Async/Future in PyO3
// ============================================================================

use pyo3::prelude::*;
use pyo3::exceptions::PyRuntimeError;
use std::future::Future;
use std::pin::Pin;


use futures::FutureExt;
use tokio::runtime::{Runtime, Handle};

/// Helper trait for converting async functions to PyO3-compatible results
pub trait IntoPyFuture<T> {
    fn into_py_future(self, py: Python) -> PyResult<T>
    where
        Self: Future<Output = PyResult<T>> + Send + 'static,
        T: Send + 'static;
}

/// Extension trait for async operations in PyO3 context
pub trait PyAsyncExt {
    /// Run an async operation in a Python context with proper runtime handling
    fn run_async<F, Fut, T>(&self, py: Python, f: F) -> PyResult<T>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = PyResult<T>> + Send + 'static,
        T: Send + 'static;
}

/// Helper for creating async-safe closures
pub struct AsyncClosure<T> {
    inner: Pin<Box<dyn Future<Output = T> + Send + 'static>>,
}

impl<T> AsyncClosure<T> {
    pub fn new<F>(future: F) -> Self
    where
        F: Future<Output = T> + Send + 'static,
    {
        Self {
            inner: Box::pin(future),
        }
    }
}

/// Safely run async code in PyO3 context
pub fn py_run_async<F, T>(py: Python, f: F) -> PyResult<T>
where
    F: Future<Output = PyResult<T>> + Send + 'static,
    T: Send + 'static,
{
    py.allow_threads(|| {
        // Try to use existing runtime or create new one
        if let Ok(handle) = Handle::try_current() {
            // We're already in a tokio runtime
            tokio::task::block_in_place(|| {
                handle.block_on(f)
            })
        } else {
            // Create a new runtime
            let rt = Runtime::new()
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to create runtime: {}", e)))?;
            rt.block_on(f)
        }
    })
}

/// Helper for converting sync operations to async
pub fn sync_to_async<T, F>(f: F) -> impl Future<Output = T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f).map(|result| result.expect("Task panicked"))
}

/// Wrapper for async trait methods that need to return BoxFuture
#[macro_export]
macro_rules! async_trait_method {
    ($vis:vis fn $name:ident(&$self:ident $(, $arg:ident: $arg_ty:ty)*) -> $ret:ty $body:block) => {
        $vis fn $name(&$self $(, $arg: $arg_ty)*) -> futures::future::BoxFuture<'_, $ret> {
            Box::pin(async move $body)
        }
    };
}

/// Helper for PyO3 async methods
#[macro_export]
macro_rules! py_async_method {
    ($self:ident, $py:ident, $body:expr) => {{
        use $crate::async_helpers::py_run_async;
        py_run_async($py, async move { $body })
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_async_closure() {
        let closure = AsyncClosure::new(async {
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            42
        });
        
        let result = closure.inner.await;
        assert_eq!(result, 42);
    }
    
    #[test]
    fn test_py_run_async() {
        Python::with_gil(|py| {
            let result = py_run_async(py, async {
                Ok::<i32, PyErr>(42)
            }).unwrap();
            assert_eq!(result, 42);
        });
    }
}