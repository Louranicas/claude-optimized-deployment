//! Service lifecycle management
//! 
//! Handles service state transitions, startup/shutdown sequences,
//! and dependency management.

use super::*;
use crate::orchestrator::{DeploymentState, ServiceMetadata};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use uuid::Uuid;
use tracing::{debug, info, warn, error, instrument};

/// Lifecycle configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleConfig {
    /// Startup timeout in seconds
    pub startup_timeout_secs: u64,
    /// Shutdown timeout in seconds  
    pub shutdown_timeout_secs: u64,
    /// Grace period for shutdown in seconds
    pub shutdown_grace_period_secs: u64,
    /// Enable dependency checking
    pub dependency_checking: bool,
    /// Enable pre-start hooks
    pub pre_start_hooks: bool,
    /// Enable post-stop hooks
    pub post_stop_hooks: bool,
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self {
            startup_timeout_secs: 120,
            shutdown_timeout_secs: 60,
            shutdown_grace_period_secs: 30,
            dependency_checking: true,
            pre_start_hooks: true,
            post_stop_hooks: true,
        }
    }
}

/// Service dependency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDependency {
    pub service_id: Uuid,
    pub service_name: String,
    pub required: bool,
    pub version_constraint: Option<String>,
}

/// Lifecycle event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleEvent {
    pub service_id: Uuid,
    pub event_type: LifecycleEventType,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub success: bool,
    pub error: Option<String>,
    pub duration_ms: u64,
}

/// Lifecycle event type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecycleEventType {
    PreStart,
    Starting,
    Started,
    PreStop,
    Stopping,
    Stopped,
    Failed,
    Recovering,
}

/// Service lifecycle definition
#[derive(Debug, Clone)]
struct ServiceLifecycle {
    service_id: Uuid,
    current_state: DeploymentState,
    dependencies: Vec<ServiceDependency>,
    dependents: HashSet<Uuid>,
    startup_command: Option<String>,
    shutdown_command: Option<String>,
    health_check_command: Option<String>,
    pre_start_hooks: Vec<String>,
    post_stop_hooks: Vec<String>,
    environment: HashMap<String, String>,
}

/// Lifecycle manager
pub struct LifecycleManager {
    config: Arc<LifecycleConfig>,
    services: Arc<RwLock<HashMap<Uuid, ServiceLifecycle>>>,
    events: Arc<RwLock<Vec<LifecycleEvent>>>,
    state_machine: Arc<StateValidator>,
}

/// State machine for validating transitions
struct StateValidator;

impl StateValidator {
    /// Check if state transition is valid
    fn is_valid_transition(from: DeploymentState, to: DeploymentState) -> bool {
        use DeploymentState::*;
        
        match (from, to) {
            // Starting states
            (Pending, Initializing) => true,
            (Initializing, Starting) => true,
            (Starting, Running) => true,
            
            // Stopping states
            (Running, Stopping) => true,
            (Stopping, Stopped) => true,
            
            // Failure states
            (_, Failed) => true,
            (Failed, Recovering) => true,
            (Recovering, Initializing) => true,
            (Recovering, Stopped) => true,
            
            // Allow stopping from any state
            (_, Stopping) => true,
            
            // Invalid transitions
            _ => false,
        }
    }
}

impl LifecycleManager {
    /// Create a new lifecycle manager
    pub fn new(config: LifecycleConfig) -> Self {
        Self {
            config: Arc::new(config),
            services: Arc::new(RwLock::new(HashMap::new())),
            events: Arc::new(RwLock::new(Vec::new())),
            state_machine: Arc::new(StateValidator),
        }
    }
    
    /// Register a service with lifecycle management
    #[instrument(skip(self))]
    pub async fn register_service(
        &self,
        service_id: Uuid,
        dependencies: Vec<ServiceDependency>,
    ) -> Result<(), ServiceError> {
        let lifecycle = ServiceLifecycle {
            service_id,
            current_state: DeploymentState::Pending,
            dependencies: dependencies.clone(),
            dependents: HashSet::new(),
            startup_command: None,
            shutdown_command: None,
            health_check_command: None,
            pre_start_hooks: Vec::new(),
            post_stop_hooks: Vec::new(),
            environment: HashMap::new(),
        };
        
        let mut services = self.services.write().await;
        
        // Register as dependent for each dependency
        for dep in &dependencies {
            if let Some(dep_lifecycle) = services.get_mut(&dep.service_id) {
                dep_lifecycle.dependents.insert(service_id);
            }
        }
        
        services.insert(service_id, lifecycle);
        
        debug!("Registered service {} with {} dependencies", service_id, dependencies.len());
        Ok(())
    }
    
    /// Start a service
    #[instrument(skip(self))]
    pub async fn start_service(&self, service_id: Uuid) -> Result<(), ServiceError> {
        let start_time = std::time::Instant::now();
        
        // Check dependencies
        if self.config.dependency_checking {
            self.check_dependencies(service_id).await?;
        }
        
        // Execute pre-start hooks
        if self.config.pre_start_hooks {
            self.execute_pre_start_hooks(service_id).await?;
        }
        
        // Transition through states
        self.transition_state(service_id, DeploymentState::Initializing).await?;
        
        // Simulate initialization
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        self.transition_state(service_id, DeploymentState::Starting).await?;
        
        // Execute startup command
        self.execute_startup_command(service_id).await?;
        
        self.transition_state(service_id, DeploymentState::Running).await?;
        
        // Record event
        let event = LifecycleEvent {
            service_id,
            event_type: LifecycleEventType::Started,
            timestamp: chrono::Utc::now(),
            success: true,
            error: None,
            duration_ms: start_time.elapsed().as_millis() as u64,
        };
        
        self.record_event(event).await;
        
        info!("Service {} started successfully", service_id);
        Ok(())
    }
    
    /// Stop a service
    #[instrument(skip(self))]
    pub async fn stop_service(&self, service_id: Uuid) -> Result<(), ServiceError> {
        let start_time = std::time::Instant::now();
        
        // Check dependents
        if self.config.dependency_checking {
            self.check_dependents(service_id).await?;
        }
        
        self.transition_state(service_id, DeploymentState::Stopping).await?;
        
        // Execute shutdown command
        self.execute_shutdown_command(service_id).await?;
        
        // Grace period
        tokio::time::sleep(
            tokio::time::Duration::from_secs(self.config.shutdown_grace_period_secs)
        ).await;
        
        self.transition_state(service_id, DeploymentState::Stopped).await?;
        
        // Execute post-stop hooks
        if self.config.post_stop_hooks {
            self.execute_post_stop_hooks(service_id).await?;
        }
        
        // Record event
        let event = LifecycleEvent {
            service_id,
            event_type: LifecycleEventType::Stopped,
            timestamp: chrono::Utc::now(),
            success: true,
            error: None,
            duration_ms: start_time.elapsed().as_millis() as u64,
        };
        
        self.record_event(event).await;
        
        info!("Service {} stopped successfully", service_id);
        Ok(())
    }
    
    /// Transition service state
    async fn transition_state(
        &self,
        service_id: Uuid,
        new_state: DeploymentState,
    ) -> Result<(), ServiceError> {
        let mut services = self.services.write().await;
        
        let lifecycle = services.get_mut(&service_id)
            .ok_or_else(|| ServiceError::NotFound(service_id.to_string()))?;
        
        let current_state = lifecycle.current_state;
        
        if !StateValidator::is_valid_transition(current_state, new_state) {
            return Err(ServiceError::InvalidStateTransition(
                format!("{:?} -> {:?}", current_state, new_state)
            ));
        }
        
        lifecycle.current_state = new_state;
        
        debug!("Service {} transitioned from {:?} to {:?}", 
               service_id, current_state, new_state);
        
        Ok(())
    }
    
    /// Check service dependencies
    async fn check_dependencies(&self, service_id: Uuid) -> Result<(), ServiceError> {
        let services = self.services.read().await;
        
        let lifecycle = services.get(&service_id)
            .ok_or_else(|| ServiceError::NotFound(service_id.to_string()))?;
        
        for dep in &lifecycle.dependencies {
            if dep.required {
                if let Some(dep_lifecycle) = services.get(&dep.service_id) {
                    if dep_lifecycle.current_state != DeploymentState::Running {
                        return Err(ServiceError::LifecycleError(
                            format!("Required dependency {} is not running", dep.service_name)
                        ));
                    }
                } else {
                    return Err(ServiceError::LifecycleError(
                        format!("Required dependency {} not found", dep.service_name)
                    ));
                }
            }
        }
        
        Ok(())
    }
    
    /// Check service dependents
    async fn check_dependents(&self, service_id: Uuid) -> Result<(), ServiceError> {
        let services = self.services.read().await;
        
        let lifecycle = services.get(&service_id)
            .ok_or_else(|| ServiceError::NotFound(service_id.to_string()))?;
        
        for dependent_id in &lifecycle.dependents {
            if let Some(dependent) = services.get(dependent_id) {
                if dependent.current_state == DeploymentState::Running {
                    warn!("Service {} has running dependent {}", service_id, dependent_id);
                    // In production, might want to block or cascade stop
                }
            }
        }
        
        Ok(())
    }
    
    /// Execute pre-start hooks
    async fn execute_pre_start_hooks(&self, service_id: Uuid) -> Result<(), ServiceError> {
        let services = self.services.read().await;
        
        let lifecycle = services.get(&service_id)
            .ok_or_else(|| ServiceError::NotFound(service_id.to_string()))?;
        
        for hook in &lifecycle.pre_start_hooks {
            debug!("Executing pre-start hook for {}: {}", service_id, hook);
            // Execute hook command
            // In production, would use actual command execution
        }
        
        Ok(())
    }
    
    /// Execute post-stop hooks
    async fn execute_post_stop_hooks(&self, service_id: Uuid) -> Result<(), ServiceError> {
        let services = self.services.read().await;
        
        let lifecycle = services.get(&service_id)
            .ok_or_else(|| ServiceError::NotFound(service_id.to_string()))?;
        
        for hook in &lifecycle.post_stop_hooks {
            debug!("Executing post-stop hook for {}: {}", service_id, hook);
            // Execute hook command
        }
        
        Ok(())
    }
    
    /// Execute startup command
    async fn execute_startup_command(&self, service_id: Uuid) -> Result<(), ServiceError> {
        let services = self.services.read().await;
        
        let lifecycle = services.get(&service_id)
            .ok_or_else(|| ServiceError::NotFound(service_id.to_string()))?;
        
        if let Some(command) = &lifecycle.startup_command {
            debug!("Executing startup command for {}: {}", service_id, command);
            // Execute command with timeout
            // In production, would use actual command execution
        }
        
        Ok(())
    }
    
    /// Execute shutdown command
    async fn execute_shutdown_command(&self, service_id: Uuid) -> Result<(), ServiceError> {
        let services = self.services.read().await;
        
        let lifecycle = services.get(&service_id)
            .ok_or_else(|| ServiceError::NotFound(service_id.to_string()))?;
        
        if let Some(command) = &lifecycle.shutdown_command {
            debug!("Executing shutdown command for {}: {}", service_id, command);
            // Execute command with timeout
        }
        
        Ok(())
    }
    
    /// Record lifecycle event
    async fn record_event(&self, event: LifecycleEvent) {
        let mut events = self.events.write().await;
        events.push(event);
        
        // Keep only last 10000 events
        if events.len() > 10000 {
            events.drain(0..events.len() - 10000);
        }
    }
    
    /// Get service state
    pub async fn get_service_state(&self, service_id: Uuid) -> Result<DeploymentState, ServiceError> {
        let services = self.services.read().await;
        
        services.get(&service_id)
            .map(|l| l.current_state)
            .ok_or_else(|| ServiceError::NotFound(service_id.to_string()))
    }
    
    /// Get lifecycle events
    pub async fn get_events(&self, service_id: Option<Uuid>, limit: usize) -> Vec<LifecycleEvent> {
        let events = self.events.read().await;
        
        if let Some(id) = service_id {
            events.iter()
                .filter(|e| e.service_id == id)
                .rev()
                .take(limit)
                .cloned()
                .collect()
        } else {
            events.iter()
                .rev()
                .take(limit)
                .cloned()
                .collect()
        }
    }
    
    /// Set service configuration
    pub async fn configure_service(
        &self,
        service_id: Uuid,
        startup_command: Option<String>,
        shutdown_command: Option<String>,
        environment: HashMap<String, String>,
    ) -> Result<(), ServiceError> {
        let mut services = self.services.write().await;
        
        let lifecycle = services.get_mut(&service_id)
            .ok_or_else(|| ServiceError::NotFound(service_id.to_string()))?;
        
        lifecycle.startup_command = startup_command;
        lifecycle.shutdown_command = shutdown_command;
        lifecycle.environment = environment;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_lifecycle_manager_creation() {
        let config = LifecycleConfig::default();
        let manager = LifecycleManager::new(config);
        
        let events = manager.get_events(None, 10).await;
        assert!(events.is_empty());
    }
    
    #[tokio::test]
    async fn test_service_lifecycle() {
        let config = LifecycleConfig::default();
        let manager = LifecycleManager::new(config);
        
        let service_id = Uuid::new_v4();
        
        // Register service
        manager.register_service(service_id, vec![]).await.unwrap();
        
        // Check initial state
        let state = manager.get_service_state(service_id).await.unwrap();
        assert_eq!(state, DeploymentState::Pending);
        
        // Start service
        manager.start_service(service_id).await.unwrap();
        
        let state = manager.get_service_state(service_id).await.unwrap();
        assert_eq!(state, DeploymentState::Running);
        
        // Stop service
        manager.stop_service(service_id).await.unwrap();
        
        let state = manager.get_service_state(service_id).await.unwrap();
        assert_eq!(state, DeploymentState::Stopped);
    }
    
    #[tokio::test]
    async fn test_state_transitions() {
        use DeploymentState::*;
        
        assert!(StateValidator::is_valid_transition(Pending, Initializing));
        assert!(StateValidator::is_valid_transition(Initializing, Starting));
        assert!(StateValidator::is_valid_transition(Starting, Running));
        assert!(StateValidator::is_valid_transition(Running, Stopping));
        assert!(StateValidator::is_valid_transition(Stopping, Stopped));
        
        assert!(!StateValidator::is_valid_transition(Stopped, Running));
        assert!(!StateValidator::is_valid_transition(Pending, Running));
    }
}