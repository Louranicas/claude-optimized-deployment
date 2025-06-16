//! Service management modules
//! 
//! Provides service registry, health checking, and lifecycle management
//! with concurrent access and high performance.

pub mod registry;
pub mod health_check;
pub mod lifecycle;

pub use registry::{ServiceRegistry, RegistryConfig};
pub use health_check::{HealthChecker, HealthCheckConfig};
pub use lifecycle::{LifecycleManager, LifecycleConfig};

use serde::{Deserialize, Serialize};

/// Service management result type
pub type ServiceResult<T> = Result<T, ServiceError>;

/// Service management errors
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("Service not found: {0}")]
    NotFound(String),
    
    #[error("Service already exists: {0}")]
    AlreadyExists(String),
    
    #[error("Invalid state transition: {0}")]
    InvalidStateTransition(String),
    
    #[error("Health check failed: {0}")]
    HealthCheckFailed(String),
    
    #[error("Registry error: {0}")]
    RegistryError(String),
    
    #[error("Lifecycle error: {0}")]
    LifecycleError(String),
    
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}