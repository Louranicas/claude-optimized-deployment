//! Lifecycle Manager - State Machines as Poetry
//!
//! This isn't just lifecycle management. It's a symphony of state transitions,
//! each one carefully orchestrated to ensure perfect plugin behavior.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{ RwLock};
use tokio::time::{timeout, Duration};
use tracing::{ info, error, instrument};
use serde_json::Value;

use super::{
    PluginError as Error, Handle, State, Result,
    traits::Plugin,
};

/// Lifecycle manager for plugins
pub struct LifecycleManager {
    /// Active plugins
    plugins: Arc<RwLock<HashMap<String, ManagedPlugin>>>,
    
    /// State machine for lifecycle transitions
    state_machine: Arc<StateMachine>,
    
    /// Health monitor
    health_monitor: Arc<HealthMonitor>,
    
    /// Recovery strategies
    recovery: Arc<RecoveryManager>,
    
    /// Configuration
    config: LifecycleConfig,
}

/// Managed plugin with lifecycle tracking
struct ManagedPlugin {
    /// The plugin handle
    handle: Arc<RwLock<Handle>>,
    
    /// Current lifecycle phase
    phase: LifecyclePhase,
    
    /// Health status
    health: HealthStatus,
    
    /// Restart count
    restart_count: u32,
    
    /// Last state change
    last_transition: std::time::SystemTime,
}

/// Lifecycle phases (more detailed than State)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum LifecyclePhase {
    /// Just loaded, not initialized
    Loaded,
    
    /// Initialization in progress
    Initializing,
    
    /// Initialization complete, starting up
    Starting,
    
    /// Fully operational
    Running,
    
    /// Temporarily suspended
    Suspended,
    
    /// Shutting down gracefully
    Stopping,
    
    /// Completely stopped
    Stopped,
    
    /// In error state
    Failed,
    
    /// Being reloaded
    Reloading,
}

/// Health status of a plugin
#[derive(Debug, Clone)]
struct HealthStatus {
    /// Is the plugin healthy?
    healthy: bool,
    
    /// Consecutive health check failures
    failure_count: u32,
    
    /// Last successful health check
    last_success: Option<std::time::SystemTime>,
    
    /// Last error message
    last_error: Option<String>,
}

/// Lifecycle configuration
#[derive(Debug, Clone)]
pub struct LifecycleConfig {
    /// Maximum initialization time
    pub init_timeout: Duration,
    
    /// Maximum shutdown time
    pub shutdown_timeout: Duration,
    
    /// Health check interval
    pub health_check_interval: Duration,
    
    /// Maximum consecutive health failures
    pub max_health_failures: u32,
    
    /// Maximum restart attempts
    pub max_restarts: u32,
    
    /// Restart backoff multiplier
    pub restart_backoff: f64,
    
    /// Enable automatic recovery
    pub auto_recovery: bool,
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self {
            init_timeout: Duration::from_secs(30),
            shutdown_timeout: Duration::from_secs(30),
            health_check_interval: Duration::from_secs(60),
            max_health_failures: 3,
            max_restarts: 5,
            restart_backoff: 2.0,
            auto_recovery: true,
        }
    }
}

/// State machine for lifecycle transitions
struct StateMachine {
    /// Valid transitions
    transitions: HashMap<(LifecyclePhase, LifecyclePhase), TransitionValidator>,
}

/// Transition validator function
type TransitionValidator = Box<dyn Fn(&ManagedPlugin) -> bool + Send + Sync + 'static>;

// Validator functions
fn always_valid(_: &ManagedPlugin) -> bool {
    true
}

fn check_healthy(p: &ManagedPlugin) -> bool {
    p.health.healthy
}

impl StateMachine {
    fn new() -> Self {
        let mut transitions = HashMap::new();
        
        // Define valid state transitions
        transitions.insert(
            (LifecyclePhase::Loaded, LifecyclePhase::Initializing),
            Box::new(always_valid) as TransitionValidator,
        );
        
        transitions.insert(
            (LifecyclePhase::Initializing, LifecyclePhase::Starting),
            Box::new(check_healthy) as TransitionValidator,
        );
        
        transitions.insert(
            (LifecyclePhase::Starting, LifecyclePhase::Running),
            Box::new(check_healthy) as TransitionValidator,
        );
        
        transitions.insert(
            (LifecyclePhase::Running, LifecyclePhase::Suspended),
            Box::new(always_valid) as TransitionValidator,
        );
        
        transitions.insert(
            (LifecyclePhase::Suspended, LifecyclePhase::Running),
            Box::new(check_healthy) as TransitionValidator,
        );
        
        transitions.insert(
            (LifecyclePhase::Running, LifecyclePhase::Stopping),
            Box::new(always_valid) as TransitionValidator,
        );
        
        transitions.insert(
            (LifecyclePhase::Stopping, LifecyclePhase::Stopped),
            Box::new(always_valid) as TransitionValidator,
        );
        
        // Reload transitions
        transitions.insert(
            (LifecyclePhase::Running, LifecyclePhase::Reloading),
            Box::new(always_valid) as TransitionValidator,
        );
        
        transitions.insert(
            (LifecyclePhase::Reloading, LifecyclePhase::Running),
            Box::new(|p: &ManagedPlugin| p.health.healthy) as Box<dyn Fn(&ManagedPlugin) -> bool + Send + Sync>,
        );
        
        // Error transitions
        for phase in [
            LifecyclePhase::Initializing,
            LifecyclePhase::Starting,
            LifecyclePhase::Running,
            LifecyclePhase::Stopping,
            LifecyclePhase::Reloading,
        ] {
            transitions.insert(
                (phase, LifecyclePhase::Failed),
                Box::new(always_valid) as TransitionValidator,
            );
        }
        
        Self { transitions }
    }
    
    fn can_transition(&self, from: LifecyclePhase, to: LifecyclePhase, plugin: &ManagedPlugin) -> bool {
        if let Some(validator) = self.transitions.get(&(from, to)) {
            validator(plugin)
        } else {
            false
        }
    }
}

/// Health monitor for plugins
struct HealthMonitor {
    /// Health check tasks
    tasks: Arc<RwLock<HashMap<String, tokio::task::JoinHandle<()>>>>,
}

impl HealthMonitor {
    fn new() -> Self {
        Self {
            tasks: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    async fn start_monitoring(
        &self,
        plugin_id: String,
        handle: Arc<RwLock<Handle>>,
        interval: Duration,
        max_failures: u32,
    ) {
        let tasks = self.tasks.clone();
        let plugin_id_clone = plugin_id.clone();
        
        let task = tokio::spawn(async move {
            let mut failures = 0;
            
            loop {
                tokio::time::sleep(interval).await;
                
                match handle.read().await.health_check().await {
                    Ok(healthy) => {
                        if healthy {
                            failures = 0;
                        } else {
                            failures += 1;
                        }
                    }
                    Err(e) => {
                        error!("Health check failed for {}: {}", plugin_id_clone, e);
                        failures += 1;
                    }
                }
                
                if failures >= max_failures {
                    error!("{} exceeded max health failures", plugin_id_clone);
                    // TODO: Trigger recovery
                    break;
                }
            }
            
            // Remove self from tasks
            let mut tasks = tasks.write().await;
            tasks.remove(&plugin_id_clone);
        });
        
        let mut tasks = self.tasks.write().await;
        tasks.insert(plugin_id, task);
    }
    
    async fn stop_monitoring(&self, plugin_id: &str) {
        let mut tasks = self.tasks.write().await;
        if let Some(task) = tasks.remove(plugin_id) {
            task.abort();
        }
    }
}

/// Recovery manager for failed plugins
struct RecoveryManager {
    /// Recovery strategies
    strategies: Vec<Box<dyn RecoveryStrategy>>,
}

#[async_trait::async_trait]
trait RecoveryStrategy: Send + Sync {
    /// Attempt recovery
    async fn recover(&self, plugin: &ManagedPlugin) -> Result<()>;
    
    /// Check if this strategy applies
    fn applies_to(&self, plugin: &ManagedPlugin) -> bool;
}

/// Simple restart strategy
struct RestartStrategy {
    max_restarts: u32,
}

#[async_trait::async_trait]
impl RecoveryStrategy for RestartStrategy {
    async fn recover(&self, plugin: &ManagedPlugin) -> Result<()> {
        if plugin.restart_count >= self.max_restarts {
            return Err(Error::ExecutionError(
                format!("Max restarts ({}) exceeded", self.max_restarts)
            ));
        }
        
        // Shutdown and reinitialize
        {
            let mut handle = plugin.handle.write().await;
            handle.shutdown().await?;
            handle.initialize(Value::Object(serde_json::Map::new())).await?;
        }
        
        Ok(())
    }
    
    fn applies_to(&self, plugin: &ManagedPlugin) -> bool {
        plugin.phase == LifecyclePhase::Failed
    }
}

impl LifecycleManager {
    /// Create a new lifecycle manager
    pub fn new(config: LifecycleConfig) -> Self {
        let mut recovery_strategies: Vec<Box<dyn RecoveryStrategy>> = vec![];
        
        if config.auto_recovery {
            recovery_strategies.push(Box::new(RestartStrategy {
                max_restarts: config.max_restarts,
            }));
        }
        
        Self {
            plugins: Arc::new(RwLock::new(HashMap::new())),
            state_machine: Arc::new(StateMachine::new()),
            health_monitor: Arc::new(HealthMonitor::new()),
            recovery: Arc::new(RecoveryManager {
                strategies: recovery_strategies,
            }),
            config,
        }
    }
    
    /// Manage a plugin's lifecycle
    #[instrument(skip(self, handle))]
    pub async fn manage(&self, plugin_id: String, handle: Handle) -> Result<()> {
        info!("Managing lifecycle for plugin: {}", plugin_id);
        
        let managed = ManagedPlugin {
            handle: Arc::new(RwLock::new(handle)),
            phase: LifecyclePhase::Loaded,
            health: HealthStatus {
                healthy: true,
                failure_count: 0,
                last_success: None,
                last_error: None,
            },
            restart_count: 0,
            last_transition: std::time::SystemTime::now(),
        };
        
        // Clone handle before storing
        let handle_for_monitor = managed.handle.clone();
        
        // Store managed plugin
        {
            let mut plugins = self.plugins.write().await;
            plugins.insert(plugin_id.clone(), managed);
        }
        
        // Start health monitoring
        self.health_monitor.start_monitoring(
            plugin_id.clone(),
            handle_for_monitor,
            self.config.health_check_interval,
            self.config.max_health_failures,
        ).await;
        
        Ok(())
    }
    
    /// Initialize a plugin
    #[instrument(skip(self))]
    pub async fn initialize(&self, plugin_id: &str, config: Value) -> Result<()> {
        self.transition(plugin_id, LifecyclePhase::Initializing).await?;
        
        let handle = {
            let plugins = self.plugins.read().await;
            plugins.get(plugin_id)
                .ok_or_else(|| Error::NotFound(plugin_id.to_string()))?
                .handle
                .clone()
        };
        
        // Initialize with timeout
        let init_future = async {
            let mut plugin = handle.write().await;
            plugin.initialize(config).await
        };
        match timeout(self.config.init_timeout, init_future).await {
            Ok(Ok(())) => {
                self.transition(plugin_id, LifecyclePhase::Starting).await?;
                self.transition(plugin_id, LifecyclePhase::Running).await?;
                Ok(())
            }
            Ok(Err(e)) => {
                self.transition(plugin_id, LifecyclePhase::Failed).await?;
                Err(e)
            }
            Err(_) => {
                self.transition(plugin_id, LifecyclePhase::Failed).await?;
                Err(Error::InitializationFailed(
                    format!("Initialization timed out after {:?}", self.config.init_timeout)
                ))
            }
        }
    }
    
    /// Shutdown a plugin
    #[instrument(skip(self))]
    pub async fn shutdown(&self, plugin_id: &str) -> Result<()> {
        self.transition(plugin_id, LifecyclePhase::Stopping).await?;
        
        let handle = {
            let plugins = self.plugins.read().await;
            plugins.get(plugin_id)
                .ok_or_else(|| Error::NotFound(plugin_id.to_string()))?
                .handle
                .clone()
        };
        
        // Stop health monitoring
        self.health_monitor.stop_monitoring(plugin_id).await;
        
        // Shutdown with timeout
        let shutdown_future = async {
            let mut plugin = handle.write().await;
            plugin.shutdown().await
        };
        match timeout(self.config.shutdown_timeout, shutdown_future).await {
            Ok(Ok(())) => {
                self.transition(plugin_id, LifecyclePhase::Stopped).await?;
                Ok(())
            }
            Ok(Err(e)) => {
                self.transition(plugin_id, LifecyclePhase::Failed).await?;
                Err(e)
            }
            Err(_) => {
                self.transition(plugin_id, LifecyclePhase::Failed).await?;
                Err(Error::ExecutionError(
                    format!("Shutdown timed out after {:?}", self.config.shutdown_timeout)
                ))
            }
        }
    }
    
    /// Reload a plugin
    #[instrument(skip(self))]
    pub async fn reload(&self, plugin_id: &str) -> Result<()> {
        // Check if plugin supports hot reload
        let (handle, old_state) = {
            let plugins = self.plugins.read().await;
            let managed = plugins.get(plugin_id)
                .ok_or_else(|| Error::NotFound(plugin_id.to_string()))?;
            (managed.handle.clone(), managed.phase)
        };
        
        // Transition to reloading
        self.transition(plugin_id, LifecyclePhase::Reloading).await?;
        
        // TODO: Implement actual reload logic
        // This would involve:
        // 1. Saving state if HotReloadable
        // 2. Unloading the plugin
        // 3. Loading new version
        // 4. Restoring state
        
        // For now, just transition back
        self.transition(plugin_id, old_state).await?;
        
        Ok(())
    }
    
    /// Suspend a plugin
    #[instrument(skip(self))]
    pub async fn suspend(&self, plugin_id: &str) -> Result<()> {
        self.transition(plugin_id, LifecyclePhase::Suspended).await
    }
    
    /// Resume a plugin
    #[instrument(skip(self))]
    pub async fn resume(&self, plugin_id: &str) -> Result<()> {
        self.transition(plugin_id, LifecyclePhase::Running).await
    }
    
    /// Get plugin phase
    pub async fn get_phase(&self, plugin_id: &str) -> Result<LifecyclePhase> {
        let plugins = self.plugins.read().await;
        plugins.get(plugin_id)
            .map(|p| p.phase)
            .ok_or_else(|| Error::NotFound(plugin_id.to_string()))
    }
    
    /// Transition to a new phase
    async fn transition(&self, plugin_id: &str, to: LifecyclePhase) -> Result<()> {
        let mut plugins = self.plugins.write().await;
        
        let managed = plugins.get_mut(plugin_id)
            .ok_or_else(|| Error::NotFound(plugin_id.to_string()))?;
        
        let from = managed.phase;
        
        // Check if transition is valid
        if !self.state_machine.can_transition(from, to, managed) {
            return Err(Error::ExecutionError(
                format!("Invalid transition from {:?} to {:?}", from, to)
            ));
        }
        
        // Update phase
        managed.phase = to;
        managed.last_transition = std::time::SystemTime::now();
        
        info!("{} transitioned from {:?} to {:?}", plugin_id, from, to);
        
        // Update plugin handle state
        let state = match to {
            LifecyclePhase::Loaded => State::Loaded,
            LifecyclePhase::Initializing => State::Initializing,
            LifecyclePhase::Starting | LifecyclePhase::Running => State::Ready,
            LifecyclePhase::Suspended | LifecyclePhase::Stopping => State::ShuttingDown,
            LifecyclePhase::Stopped => State::Shutdown,
            LifecyclePhase::Failed => State::Error,
            LifecyclePhase::Reloading => State::Initializing,
        };
        
        // State is tracked externally, not on the plugin itself
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_state_machine() {
        let sm = StateMachine::new();
        let plugin = ManagedPlugin {
            handle: Arc::new(Handle::new(Box::new(crate::plugin::tests::TestPlugin::new()))),
            phase: LifecyclePhase::Loaded,
            health: HealthStatus {
                healthy: true,
                failure_count: 0,
                last_success: None,
                last_error: None,
            },
            restart_count: 0,
            last_transition: std::time::SystemTime::now(),
        };
        
        assert!(sm.can_transition(LifecyclePhase::Loaded, LifecyclePhase::Initializing, &plugin));
        assert!(!sm.can_transition(LifecyclePhase::Loaded, LifecyclePhase::Running, &plugin));
    }
}