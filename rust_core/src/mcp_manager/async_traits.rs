// ============================================================================
// MCP Manager Async Traits - Proper async trait patterns for Rust 1.75+
// ============================================================================

use std::future::Future;

use async_trait::async_trait;
use futures::future::BoxFuture;
use crate::CoreResult;

/// Trait for async operations that need dynamic dispatch
/// Uses async-trait for compatibility
#[async_trait]
pub trait AsyncOperation: Send + Sync {
    async fn execute(&self) -> CoreResult<()>;
    async fn validate(&self) -> CoreResult<bool>;
}

/// Trait for operations that return BoxFuture (manual implementation)
pub trait BoxFutureOperation: Send + Sync {
    fn execute(&self) -> BoxFuture<'_, CoreResult<()>>;
    fn validate(&self) -> BoxFuture<'_, CoreResult<bool>>;
}

/// Example implementation using async-trait
pub struct AsyncOperationImpl;

#[async_trait]
impl AsyncOperation for AsyncOperationImpl {
    async fn execute(&self) -> CoreResult<()> {
        // Async implementation
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        Ok(())
    }
    
    async fn validate(&self) -> CoreResult<bool> {
        // Async validation
        Ok(true)
    }
}

/// Example implementation using BoxFuture
pub struct BoxFutureOperationImpl;

impl BoxFutureOperation for BoxFutureOperationImpl {
    fn execute(&self) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async move {
            // Async implementation
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            Ok(())
        })
    }
    
    fn validate(&self) -> BoxFuture<'_, CoreResult<bool>> {
        Box::pin(async move {
            // Async validation
            Ok(true)
        })
    }
}

/// Helper macro for implementing async traits with BoxFuture
#[macro_export]
macro_rules! impl_box_future_trait {
    (
        impl $trait:ident for $type:ty {
            $(
                fn $method:ident(&$self:ident $(, $arg:ident: $arg_ty:ty)*) -> BoxFuture<'_, $ret:ty> $body:block
            )*
        }
    ) => {
        impl $trait for $type {
            $(
                fn $method(&$self $(, $arg: $arg_ty)*) -> BoxFuture<'_, $ret> {
                    Box::pin(async move $body)
                }
            )*
        }
    };
}

/// Extension trait for converting between async patterns
pub trait AsyncPatternExt: Future {
    /// Convert a standard Future to BoxFuture
    fn boxed<'a>(self) -> BoxFuture<'a, Self::Output>
    where
        Self: Send + 'a,
        Self::Output: 'a;
}

impl<F> AsyncPatternExt for F
where
    F: Future + Send,
{
    fn boxed<'a>(self) -> BoxFuture<'a, F::Output>
    where
        Self: 'a,
        F::Output: 'a,
    {
        Box::pin(self)
    }
}

/// Helper for async closures that need to be Send
pub struct SendAsyncClosure<T> {
    inner: Box<dyn Fn() -> BoxFuture<'static, T> + Send + Sync>,
}

impl<T> SendAsyncClosure<T> {
    pub fn new<F, Fut>(f: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = T> + Send + 'static,
    {
        Self {
            inner: Box::new(move || Box::pin(f())),
        }
    }
    
    pub async fn call(&self) -> T {
        (self.inner)().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_async_operation() {
        let op = AsyncOperationImpl;
        assert!(op.execute().await.is_ok());
        assert!(op.validate().await.unwrap());
    }
    
    #[tokio::test]
    async fn test_box_future_operation() {
        let op = BoxFutureOperationImpl;
        assert!(op.execute().await.is_ok());
        assert!(op.validate().await.unwrap());
    }
    
    #[tokio::test]
    async fn test_send_async_closure() {
        let closure = SendAsyncClosure::new(|| async {
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            42
        });
        
        let result = closure.call().await;
        assert_eq!(result, 42);
    }
}