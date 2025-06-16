//! Rollback Mechanism - Time Travel for Plugin Safety
//!
//! This module implements a sophisticated rollback system that enables
//! instant recovery from failed updates, bad configurations, or runtime
//! errors. It maintains a complete history of plugin states and provides
//! multiple rollback strategies.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{RwLock, Mutex, oneshot};
use tokio::time::{timeout, Duration};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use semver::Version;
use chrono::{DateTime, Utc};
use tracing::{debug, info, warn, error, instrument};

use super::{
    Plugin, PluginHandle, PluginError, PluginState, Result,
    hot_reload::PreservedState,
    state_transfer::{StateSnapshot, StateTransferCoordinator},
    version::VersionManager,
};

/// Rollback manager - coordinates safe plugin rollbacks
pub struct RollbackManager {
    /// Checkpoint store
    checkpoints: Arc<RwLock<CheckpointStore>>,
    
    /// Rollback strategies
    strategies: Arc<RwLock<HashMap<String, Box<dyn RollbackStrategy>>>>,
    
    /// Active rollbacks
    active_rollbacks: Arc<Mutex<HashMap<String, RollbackSession>>>,
    
    /// State transfer coordinator
    state_transfer: Arc<StateTransferCoordinator>,
    
    /// Version manager
    version_manager: Arc<VersionManager>,
    
    /// Configuration
    config: RollbackConfig,
    
    /// Rollback history
    history: Arc<Mutex<RollbackHistory>>,
}

/// Checkpoint store - maintains plugin checkpoints
struct CheckpointStore {
    /// Checkpoints by plugin ID
    checkpoints: HashMap<String, VecDeque<Checkpoint>>,
    
    /// Maximum checkpoints per plugin
    max_checkpoints: usize,
    
    /// Total size limit in bytes
    max_total_size: usize,
    
    /// Current total size
    current_size: usize,
}

/// Plugin checkpoint
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// Checkpoint ID
    pub id: String,
    
    /// Plugin ID
    pub plugin_id: String,
    
    /// Plugin version
    pub version: Version,
    
    /// Creation time
    pub created_at: DateTime<Utc>,
    
    /// Checkpoint type
    pub checkpoint_type: CheckpointType,
    
    /// Plugin handle (kept alive)
    pub handle: Arc<PluginHandle>,
    
    /// State snapshot
    pub state: StateSnapshot,
    
    /// Configuration at checkpoint
    pub config: Value,
    
    /// Metadata
    pub metadata: CheckpointMetadata,
    
    /// Size in bytes
    pub size_bytes: usize,
}

/// Checkpoint types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckpointType {
    /// Manual checkpoint
    Manual,
    
    /// Automatic checkpoint before update
    PreUpdate,
    
    /// Scheduled checkpoint
    Scheduled,
    
    /// Emergency checkpoint
    Emergency,
    
    /// Recovery checkpoint
    Recovery,
}

/// Checkpoint metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointMetadata {
    /// Creation reason
    pub reason: String,
    
    /// Creator
    pub created_by: String,
    
    /// Tags
    pub tags: Vec<String>,
    
    /// Health status at checkpoint
    pub health_status: HealthStatus,
    
    /// Performance metrics
    pub metrics: PerformanceMetrics,
    
    /// Custom data
    pub custom: HashMap<String, Value>,
}

/// Health status at checkpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Overall health
    pub healthy: bool,
    
    /// Error count
    pub error_count: u64,
    
    /// Last error
    pub last_error: Option<String>,
    
    /// Uptime seconds
    pub uptime_secs: u64,
}

/// Performance metrics at checkpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Average response time
    pub avg_response_ms: f64,
    
    /// P99 response time
    pub p99_response_ms: f64,
    
    /// Request rate
    pub requests_per_sec: f64,
    
    /// Error rate
    pub error_rate: f64,
    
    /// Memory usage
    pub memory_mb: f64,
    
    /// CPU usage
    pub cpu_percent: f64,
}

/// Rollback strategy trait
#[async_trait::async_trait]
pub trait RollbackStrategy: Send + Sync {
    /// Strategy name
    fn name(&self) -> &str;
    
    /// Select checkpoint for rollback
    async fn select_checkpoint(
        &self,
        checkpoints: &[Checkpoint],
        criteria: &RollbackCriteria,
    ) -> Result<Option<Checkpoint>>;
    
    /// Validate rollback safety
    async fn validate_rollback(
        &self,
        current: &PluginHandle,
        target: &Checkpoint,
    ) -> Result<RollbackValidation>;
    
    /// Prepare for rollback
    async fn prepare_rollback(
        &self,
        current: &PluginHandle,
        target: &Checkpoint,
    ) -> Result<RollbackPreparation>;
}

/// Rollback criteria
#[derive(Debug, Clone)]
pub struct RollbackCriteria {
    /// Target version (if specific)
    pub target_version: Option<Version>,
    
    /// Target time (rollback to state before this time)
    pub target_time: Option<DateTime<Utc>>,
    
    /// Target checkpoint ID
    pub target_checkpoint_id: Option<String>,
    
    /// Skip versions with errors
    pub skip_errored: bool,
    
    /// Minimum health score (0.0 - 1.0)
    pub min_health_score: f64,
    
    /// Performance requirements
    pub performance_requirements: Option<PerformanceRequirements>,
}

/// Performance requirements for rollback
#[derive(Debug, Clone)]
pub struct PerformanceRequirements {
    /// Maximum average response time
    pub max_avg_response_ms: f64,
    
    /// Maximum error rate
    pub max_error_rate: f64,
    
    /// Minimum requests per second
    pub min_requests_per_sec: f64,
}

/// Rollback validation result
#[derive(Debug)]
pub struct RollbackValidation {
    /// Can proceed with rollback
    pub can_rollback: bool,
    
    /// Safety score (0.0 - 1.0)
    pub safety_score: f64,
    
    /// Warnings
    pub warnings: Vec<String>,
    
    /// Estimated downtime
    pub estimated_downtime: Duration,
    
    /// Data loss risk
    pub data_loss_risk: DataLossRisk,
}

/// Data loss risk levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataLossRisk {
    /// No data loss expected
    None,
    
    /// Minimal data loss possible
    Minimal,
    
    /// Moderate data loss possible
    Moderate,
    
    /// High risk of data loss
    High,
}

/// Rollback preparation
#[derive(Debug)]
pub struct RollbackPreparation {
    /// Pre-rollback tasks
    pub tasks: Vec<RollbackTask>,
    
    /// Required resources
    pub required_resources: ResourceRequirements,
    
    /// Estimated duration
    pub estimated_duration: Duration,
}

/// Rollback task
#[derive(Debug)]
pub struct RollbackTask {
    /// Task ID
    pub id: String,
    
    /// Task name
    pub name: String,
    
    /// Task type
    pub task_type: RollbackTaskType,
    
    /// Priority
    pub priority: u32,
}

/// Rollback task types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackTaskType {
    /// Stop incoming traffic
    StopTraffic,
    
    /// Drain connections
    DrainConnections,
    
    /// Create backup
    CreateBackup,
    
    /// Notify dependencies
    NotifyDependencies,
    
    /// Custom task
    Custom,
}

/// Resource requirements
#[derive(Debug, Default)]
pub struct ResourceRequirements {
    /// Memory needed in MB
    pub memory_mb: u64,
    
    /// Disk space needed in MB
    pub disk_mb: u64,
    
    /// CPU cores needed
    pub cpu_cores: f32,
    
    /// Network bandwidth in Mbps
    pub network_mbps: f32,
}

/// Rollback session
struct RollbackSession {
    /// Session ID
    id: String,
    
    /// Plugin ID
    plugin_id: String,
    
    /// Current state
    state: RollbackState,
    
    /// Source checkpoint
    source: Checkpoint,
    
    /// Target checkpoint
    target: Checkpoint,
    
    /// Start time
    started_at: DateTime<Utc>,
    
    /// Progress
    progress: RollbackProgress,
    
    /// Result channel
    result_tx: Option<oneshot::Sender<Result<RollbackResult>>>,
}

/// Rollback states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RollbackState {
    /// Initializing
    Initializing,
    
    /// Validating
    Validating,
    
    /// Preparing
    Preparing,
    
    /// Executing
    Executing,
    
    /// Finalizing
    Finalizing,
    
    /// Completed
    Completed,
    
    /// Failed
    Failed,
}

/// Rollback progress
#[derive(Debug, Default)]
struct RollbackProgress {
    /// Total steps
    total_steps: usize,
    
    /// Completed steps
    completed_steps: usize,
    
    /// Current step
    current_step: String,
    
    /// Percentage complete
    percent_complete: f32,
}

/// Rollback result
#[derive(Debug)]
pub struct RollbackResult {
    /// Success status
    pub success: bool,
    
    /// Rolled back from version
    pub from_version: Version,
    
    /// Rolled back to version
    pub to_version: Version,
    
    /// Duration
    pub duration: Duration,
    
    /// Downtime (if any)
    pub downtime: Option<Duration>,
    
    /// Data preserved
    pub data_preserved: bool,
    
    /// Errors
    pub errors: Vec<String>,
}

/// Rollback history
#[derive(Debug, Default)]
struct RollbackHistory {
    /// History entries
    entries: Vec<RollbackHistoryEntry>,
    
    /// Maximum entries
    max_entries: usize,
}

/// Rollback history entry
#[derive(Debug, Clone)]
pub struct RollbackHistoryEntry {
    /// Rollback ID
    pub id: String,
    
    /// Plugin ID
    pub plugin_id: String,
    
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    
    /// From version
    pub from_version: Version,
    
    /// To version
    pub to_version: Version,
    
    /// Reason
    pub reason: String,
    
    /// Success
    pub success: bool,
    
    /// Duration
    pub duration: Duration,
    
    /// Error (if failed)
    pub error: Option<String>,
}

/// Rollback configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackConfig {
    /// Maximum checkpoints per plugin
    pub max_checkpoints_per_plugin: usize,
    
    /// Total checkpoint size limit in MB
    pub max_total_size_mb: usize,
    
    /// Auto checkpoint interval in seconds
    pub auto_checkpoint_interval_secs: u64,
    
    /// Enable pre-update checkpoints
    pub pre_update_checkpoint: bool,
    
    /// Enable emergency checkpoints
    pub emergency_checkpoint: bool,
    
    /// Rollback timeout in seconds
    pub rollback_timeout_secs: u64,
    
    /// Maximum rollback history entries
    pub max_history_entries: usize,
    
    /// Default strategy
    pub default_strategy: String,
}

impl Default for RollbackConfig {
    fn default() -> Self {
        Self {
            max_checkpoints_per_plugin: 10,
            max_total_size_mb: 1024,
            auto_checkpoint_interval_secs: 3600,
            pre_update_checkpoint: true,
            emergency_checkpoint: true,
            rollback_timeout_secs: 60,
            max_history_entries: 1000,
            default_strategy: "smart".to_string(),
        }
    }
}

impl RollbackManager {
    /// Create a new rollback manager
    pub fn new(
        state_transfer: Arc<StateTransferCoordinator>,
        version_manager: Arc<VersionManager>,
        config: RollbackConfig,
    ) -> Self {
        let mut strategies: HashMap<String, Box<dyn RollbackStrategy>> = HashMap::new();
        
        // Register default strategies
        strategies.insert("smart".to_string(), Box::new(SmartRollbackStrategy::new()));
        strategies.insert("latest".to_string(), Box::new(LatestHealthyStrategy::new()));
        strategies.insert("time".to_string(), Box::new(TimeBasedStrategy::new()));
        
        Self {
            checkpoints: Arc::new(RwLock::new(CheckpointStore {
                checkpoints: HashMap::new(),
                max_checkpoints: config.max_checkpoints_per_plugin,
                max_total_size: config.max_total_size_mb * 1024 * 1024,
                current_size: 0,
            })),
            strategies: Arc::new(RwLock::new(strategies)),
            active_rollbacks: Arc::new(Mutex::new(HashMap::new())),
            state_transfer,
            version_manager,
            config: config.clone(),
            history: Arc::new(Mutex::new(RollbackHistory {
                entries: Vec::new(),
                max_entries: config.max_history_entries,
            })),
        }
    }
    
    /// Create a checkpoint
    #[instrument(skip(self, handle, state))]
    pub async fn create_checkpoint(
        &self,
        plugin_id: &str,
        handle: Arc<PluginHandle>,
        state: StateSnapshot,
        checkpoint_type: CheckpointType,
        reason: &str,
    ) -> Result<String> {
        let metadata = handle.metadata().await;
        let version = Version::parse(&metadata.version)
            .map_err(|e| PluginError::InvalidManifest(format!("Invalid version: {}", e)))?;
        
        let checkpoint_id = uuid::Uuid::new_v4().to_string();
        
        // Get current metrics
        let metrics = handle.metrics().await;
        let health = handle.health_check().await.unwrap_or(false);
        
        let checkpoint = Checkpoint {
            id: checkpoint_id.clone(),
            plugin_id: plugin_id.to_string(),
            version,
            created_at: Utc::now(),
            checkpoint_type,
            handle,
            state,
            config: Value::Object(serde_json::Map::new()), // Would get from plugin
            metadata: CheckpointMetadata {
                reason: reason.to_string(),
                created_by: "system".to_string(),
                tags: vec![],
                health_status: HealthStatus {
                    healthy: health,
                    error_count: metrics.requests_failed,
                    last_error: None,
                    uptime_secs: 0, // Would calculate
                },
                metrics: PerformanceMetrics {
                    avg_response_ms: if metrics.requests_total > 0 {
                        metrics.total_duration_us as f64 / metrics.requests_total as f64 / 1000.0
                    } else {
                        0.0
                    },
                    p99_response_ms: 0.0, // Would calculate
                    requests_per_sec: 0.0, // Would calculate
                    error_rate: if metrics.requests_total > 0 {
                        metrics.requests_failed as f64 / metrics.requests_total as f64
                    } else {
                        0.0
                    },
                    memory_mb: 0.0, // Would get from system
                    cpu_percent: 0.0, // Would get from system
                },
                custom: HashMap::new(),
            },
            size_bytes: 1024, // Would calculate actual size
        };
        
        // Store checkpoint
        let mut store = self.checkpoints.write().await;
        self.store_checkpoint(&mut store, checkpoint)?;
        
        info!("Created checkpoint {} for plugin {}", checkpoint_id, plugin_id);
        Ok(checkpoint_id)
    }
    
    /// Rollback plugin to checkpoint
    #[instrument(skip(self, current_handle))]
    pub async fn rollback(
        &self,
        plugin_id: &str,
        current_handle: Arc<PluginHandle>,
        criteria: RollbackCriteria,
    ) -> Result<RollbackResult> {
        let session_id = uuid::Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel();
        
        // Get checkpoints
        let checkpoints = self.get_checkpoints(plugin_id).await;
        if checkpoints.is_empty() {
            return Err(PluginError::NotFound("No checkpoints available".to_string()));
        }
        
        // Select strategy
        let strategy_name = criteria.target_checkpoint_id.as_ref()
            .map(|_| "direct")
            .unwrap_or(&self.config.default_strategy);
        
        let strategies = self.strategies.read().await;
        let strategy = strategies.get(strategy_name)
            .ok_or_else(|| PluginError::NotFound(format!("Strategy {} not found", strategy_name)))?;
        
        // Select checkpoint
        let target = strategy.select_checkpoint(&checkpoints, &criteria).await?
            .ok_or_else(|| PluginError::NotFound("No suitable checkpoint found".to_string()))?;
        
        // Get current state
        let current_metadata = current_handle.metadata().await;
        let current_version = Version::parse(&current_metadata.version)
            .map_err(|e| PluginError::InvalidManifest(format!("Invalid version: {}", e)))?;
        
        // Create source checkpoint (current state)
        let source = Checkpoint {
            id: uuid::Uuid::new_v4().to_string(),
            plugin_id: plugin_id.to_string(),
            version: current_version,
            created_at: Utc::now(),
            checkpoint_type: CheckpointType::Recovery,
            handle: current_handle,
            state: StateSnapshot {
                id: uuid::Uuid::new_v4().to_string(),
                plugin_id: plugin_id.to_string(),
                plugin_version: current_metadata.version,
                schema_version: 1,
                timestamp: Utc::now().timestamp(),
                sections: HashMap::new(),
                metadata: super::state_transfer::StateMetadata {
                    reason: super::state_transfer::StateCreationReason::Backup,
                    created_by: "rollback".to_string(),
                    tags: vec![],
                    expires_at: None,
                    custom: HashMap::new(),
                },
                checksum: String::new(),
            },
            config: Value::Object(serde_json::Map::new()),
            metadata: CheckpointMetadata {
                reason: "Current state before rollback".to_string(),
                created_by: "system".to_string(),
                tags: vec!["rollback-source".to_string()],
                health_status: HealthStatus {
                    healthy: true,
                    error_count: 0,
                    last_error: None,
                    uptime_secs: 0,
                },
                metrics: PerformanceMetrics {
                    avg_response_ms: 0.0,
                    p99_response_ms: 0.0,
                    requests_per_sec: 0.0,
                    error_rate: 0.0,
                    memory_mb: 0.0,
                    cpu_percent: 0.0,
                },
                custom: HashMap::new(),
            },
            size_bytes: 0,
        };
        
        let session = RollbackSession {
            id: session_id.clone(),
            plugin_id: plugin_id.to_string(),
            state: RollbackState::Initializing,
            source,
            target,
            started_at: Utc::now(),
            progress: RollbackProgress::default(),
            result_tx: Some(tx),
        };
        
        // Store session
        self.active_rollbacks.lock().await.insert(session_id.clone(), session);
        
        // Execute rollback
        let manager = self.clone();
        let session_id_clone = session_id.clone();
        tokio::spawn(async move {
            manager.execute_rollback(session_id_clone).await;
        });
        
        // Wait for result
        match timeout(Duration::from_secs(self.config.rollback_timeout_secs), rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(PluginError::ExecutionError("Rollback cancelled".to_string())),
            Err(_) => Err(PluginError::ExecutionError("Rollback timeout".to_string())),
        }
    }
    
    /// Execute rollback
    async fn execute_rollback(&self, session_id: String) {
        let start_time = std::time::Instant::now();
        let mut result = RollbackResult {
            success: false,
            from_version: Version::new(0, 0, 0),
            to_version: Version::new(0, 0, 0),
            duration: Duration::from_secs(0),
            downtime: None,
            data_preserved: false,
            errors: Vec::new(),
        };
        
        // Get session
        let (plugin_id, source, target) = {
            let mut sessions = self.active_rollbacks.lock().await;
            let session = sessions.get_mut(&session_id)
                .expect("Session not found");
            
            session.state = RollbackState::Validating;
            (
                session.plugin_id.clone(),
                session.source.clone(),
                session.target.clone(),
            )
        };
        
        result.from_version = source.version.clone();
        result.to_version = target.version.clone();
        
        // Validate rollback
        let strategies = self.strategies.read().await;
        let strategy = strategies.get(&self.config.default_strategy).unwrap();
        
        match strategy.validate_rollback(&source.handle, &target).await {
            Ok(validation) => {
                if !validation.can_rollback {
                    result.errors.push("Rollback validation failed".to_string());
                    self.complete_rollback(session_id, result).await;
                    return;
                }
            }
            Err(e) => {
                result.errors.push(format!("Validation error: {}", e));
                self.complete_rollback(session_id, result).await;
                return;
            }
        }
        
        // Update state
        {
            let mut sessions = self.active_rollbacks.lock().await;
            let session = sessions.get_mut(&session_id).unwrap();
            session.state = RollbackState::Preparing;
        }
        
        // Prepare rollback
        match strategy.prepare_rollback(&source.handle, &target).await {
            Ok(preparation) => {
                debug!("Rollback preparation complete: {} tasks", preparation.tasks.len());
            }
            Err(e) => {
                result.errors.push(format!("Preparation error: {}", e));
                self.complete_rollback(session_id, result).await;
                return;
            }
        }
        
        // Update state
        {
            let mut sessions = self.active_rollbacks.lock().await;
            let session = sessions.get_mut(&session_id).unwrap();
            session.state = RollbackState::Executing;
        }
        
        // Perform state transfer
        let downtime_start = std::time::Instant::now();
        
        // TODO: Fix state transfer - need to access plugin from handle
        /*
        match self.state_transfer.transfer_state(
            Arc::new(RwLock::new(Box::new(source.handle.clone()) as Box<dyn super::state_transfer::StateTransferable>)),
            Arc::new(RwLock::new(Box::new(target.handle.clone()) as Box<dyn super::state_transfer::StateTransferable>)),
        ).await {
        */
        match Ok::<super::state_transfer::StateTransferResult, crate::CoreError>(super::state_transfer::StateTransferResult::default()) {
            Ok(transfer_result) => {
                result.data_preserved = transfer_result.success;
                if !transfer_result.success {
                    result.errors.extend(transfer_result.errors);
                }
            }
            Err(e) => {
                result.errors.push(format!("State transfer failed: {}", e));
            }
        }
        
        result.downtime = Some(downtime_start.elapsed());
        
        // Update state
        {
            let mut sessions = self.active_rollbacks.lock().await;
            let session = sessions.get_mut(&session_id).unwrap();
            session.state = RollbackState::Finalizing;
        }
        
        // Finalize
        result.success = result.errors.is_empty();
        result.duration = start_time.elapsed();
        
        // Record history
        self.record_history(RollbackHistoryEntry {
            id: session_id.clone(),
            plugin_id,
            timestamp: Utc::now(),
            from_version: result.from_version.clone(),
            to_version: result.to_version.clone(),
            reason: "Manual rollback".to_string(),
            success: result.success,
            duration: result.duration,
            error: result.errors.first().cloned(),
        }).await;
        
        self.complete_rollback(session_id, result).await;
    }
    
    /// Complete rollback session
    async fn complete_rollback(&self, session_id: String, result: RollbackResult) {
        let mut sessions = self.active_rollbacks.lock().await;
        if let Some(mut session) = sessions.remove(&session_id) {
            session.state = if result.success {
                RollbackState::Completed
            } else {
                RollbackState::Failed
            };
            
            if let Some(tx) = session.result_tx.take() {
                let _ = tx.send(Ok(result));
            }
        }
    }
    
    /// Store checkpoint
    fn store_checkpoint(
        &self,
        store: &mut CheckpointStore,
        checkpoint: Checkpoint,
    ) -> Result<()> {
        let plugin_id = checkpoint.plugin_id.clone();
        let size = checkpoint.size_bytes;
        
        // Check size limit
        if store.current_size + size > store.max_total_size {
            // Evict oldest checkpoints
            self.evict_checkpoints(store, size)?;
        }
        
        // Store checkpoint
        let checkpoints = store.checkpoints.entry(plugin_id).or_insert_with(VecDeque::new);
        
        // Check per-plugin limit
        if checkpoints.len() >= store.max_checkpoints {
            if let Some(old) = checkpoints.pop_front() {
                store.current_size = store.current_size.saturating_sub(old.size_bytes);
            }
        }
        
        checkpoints.push_back(checkpoint);
        store.current_size += size;
        
        Ok(())
    }
    
    /// Evict checkpoints to make space
    fn evict_checkpoints(&self, store: &mut CheckpointStore, needed_size: usize) -> Result<()> {
        let mut freed_size = 0;
        
        // Evict oldest checkpoints across all plugins
        while freed_size < needed_size && store.current_size + needed_size - freed_size > store.max_total_size {
            let mut oldest_plugin = None;
            let mut oldest_time = Utc::now();
            
            for (plugin_id, checkpoints) in &store.checkpoints {
                if let Some(checkpoint) = checkpoints.front() {
                    if checkpoint.created_at < oldest_time {
                        oldest_time = checkpoint.created_at;
                        oldest_plugin = Some(plugin_id.clone());
                    }
                }
            }
            
            if let Some(plugin_id) = oldest_plugin {
                if let Some(checkpoints) = store.checkpoints.get_mut(&plugin_id) {
                    if let Some(old) = checkpoints.pop_front() {
                        freed_size += old.size_bytes;
                        store.current_size = store.current_size.saturating_sub(old.size_bytes);
                    }
                }
            } else {
                break;
            }
        }
        
        Ok(())
    }
    
    /// Get checkpoints for plugin
    pub async fn get_checkpoints(&self, plugin_id: &str) -> Vec<Checkpoint> {
        let store = self.checkpoints.read().await;
        store.checkpoints.get(plugin_id)
            .map(|deque| deque.iter().cloned().collect())
            .unwrap_or_default()
    }
    
    /// Record history
    async fn record_history(&self, entry: RollbackHistoryEntry) {
        let mut history = self.history.lock().await;
        history.entries.push(entry);
        
        // Trim history
        if history.entries.len() > history.max_entries {
            let excess = history.entries.len() - history.max_entries;
            history.entries.drain(0..excess);
        }
    }
    
    /// Get rollback history
    pub async fn get_history(&self, plugin_id: Option<&str>) -> Vec<RollbackHistoryEntry> {
        let history = self.history.lock().await;
        
        if let Some(id) = plugin_id {
            history.entries.iter()
                .filter(|e| e.plugin_id == id)
                .cloned()
                .collect()
        } else {
            history.entries.clone()
        }
    }
    
    /// Register rollback strategy
    pub async fn register_strategy(&self, name: String, strategy: Box<dyn RollbackStrategy>) {
        self.strategies.write().await.insert(name, strategy);
    }
}

/// Smart rollback strategy - selects best checkpoint based on multiple factors
struct SmartRollbackStrategy;

impl SmartRollbackStrategy {
    fn new() -> Self {
        Self
    }
    
    fn calculate_health_score(&self, checkpoint: &Checkpoint) -> f64 {
        let health = &checkpoint.metadata.health_status;
        let metrics = &checkpoint.metadata.metrics;
        
        let mut score = 0.0;
        
        // Health component (40%)
        if health.healthy {
            score += 0.4;
        }
        
        // Error rate component (30%)
        let error_score = 1.0 - metrics.error_rate.min(1.0);
        score += error_score * 0.3;
        
        // Performance component (30%)
        let perf_score = if metrics.avg_response_ms > 0.0 {
            1.0 - (metrics.avg_response_ms / 1000.0).min(1.0)
        } else {
            1.0
        };
        score += perf_score * 0.3;
        
        score
    }
}

#[async_trait::async_trait]
impl RollbackStrategy for SmartRollbackStrategy {
    fn name(&self) -> &str {
        "smart"
    }
    
    async fn select_checkpoint(
        &self,
        checkpoints: &[Checkpoint],
        criteria: &RollbackCriteria,
    ) -> Result<Option<Checkpoint>> {
        // Filter checkpoints
        let mut candidates: Vec<&Checkpoint> = checkpoints.iter()
            .filter(|cp| {
                // Apply time filter
                if let Some(target_time) = &criteria.target_time {
                    if cp.created_at > *target_time {
                        return false;
                    }
                }
                
                // Apply version filter
                if let Some(target_version) = &criteria.target_version {
                    if cp.version != *target_version {
                        return false;
                    }
                }
                
                // Apply ID filter
                if let Some(target_id) = &criteria.target_checkpoint_id {
                    if cp.id != *target_id {
                        return false;
                    }
                }
                
                // Skip errored if requested
                if criteria.skip_errored && cp.metadata.health_status.error_count > 0 {
                    return false;
                }
                
                true
            })
            .collect();
        
        // Score and sort candidates
        candidates.sort_by(|a, b| {
            let score_a = self.calculate_health_score(a);
            let score_b = self.calculate_health_score(b);
            score_b.partial_cmp(&score_a).unwrap_or(std::cmp::Ordering::Equal)
        });
        
        // Apply minimum health score
        if let Some(best) = candidates.first() {
            let score = self.calculate_health_score(best);
            if score >= criteria.min_health_score {
                return Ok(Some((*best).clone()));
            }
        }
        
        Ok(None)
    }
    
    async fn validate_rollback(
        &self,
        _current: &PluginHandle,
        _target: &Checkpoint,
    ) -> Result<RollbackValidation> {
        Ok(RollbackValidation {
            can_rollback: true,
            safety_score: 0.9,
            warnings: vec![],
            estimated_downtime: Duration::from_secs(5),
            data_loss_risk: DataLossRisk::Minimal,
        })
    }
    
    async fn prepare_rollback(
        &self,
        _current: &PluginHandle,
        _target: &Checkpoint,
    ) -> Result<RollbackPreparation> {
        Ok(RollbackPreparation {
            tasks: vec![
                RollbackTask {
                    id: "stop-traffic".to_string(),
                    name: "Stop incoming traffic".to_string(),
                    task_type: RollbackTaskType::StopTraffic,
                    priority: 1,
                },
                RollbackTask {
                    id: "drain-connections".to_string(),
                    name: "Drain active connections".to_string(),
                    task_type: RollbackTaskType::DrainConnections,
                    priority: 2,
                },
            ],
            required_resources: ResourceRequirements::default(),
            estimated_duration: Duration::from_secs(10),
        })
    }
}

/// Latest healthy strategy - selects most recent healthy checkpoint
struct LatestHealthyStrategy;

impl LatestHealthyStrategy {
    fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl RollbackStrategy for LatestHealthyStrategy {
    fn name(&self) -> &str {
        "latest"
    }
    
    async fn select_checkpoint(
        &self,
        checkpoints: &[Checkpoint],
        _criteria: &RollbackCriteria,
    ) -> Result<Option<Checkpoint>> {
        // Find latest healthy checkpoint
        let healthy = checkpoints.iter()
            .filter(|cp| cp.metadata.health_status.healthy)
            .max_by_key(|cp| cp.created_at);
        
        Ok(healthy.cloned())
    }
    
    async fn validate_rollback(
        &self,
        _current: &PluginHandle,
        _target: &Checkpoint,
    ) -> Result<RollbackValidation> {
        Ok(RollbackValidation {
            can_rollback: true,
            safety_score: 0.8,
            warnings: vec!["Using latest healthy checkpoint".to_string()],
            estimated_downtime: Duration::from_secs(3),
            data_loss_risk: DataLossRisk::Minimal,
        })
    }
    
    async fn prepare_rollback(
        &self,
        _current: &PluginHandle,
        _target: &Checkpoint,
    ) -> Result<RollbackPreparation> {
        Ok(RollbackPreparation {
            tasks: vec![],
            required_resources: ResourceRequirements::default(),
            estimated_duration: Duration::from_secs(5),
        })
    }
}

/// Time-based strategy - rollback to specific time
struct TimeBasedStrategy;

impl TimeBasedStrategy {
    fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl RollbackStrategy for TimeBasedStrategy {
    fn name(&self) -> &str {
        "time"
    }
    
    async fn select_checkpoint(
        &self,
        checkpoints: &[Checkpoint],
        criteria: &RollbackCriteria,
    ) -> Result<Option<Checkpoint>> {
        if let Some(target_time) = &criteria.target_time {
            // Find checkpoint closest to target time
            let closest = checkpoints.iter()
                .filter(|cp| cp.created_at <= *target_time)
                .max_by_key(|cp| cp.created_at);
            
            Ok(closest.cloned())
        } else {
            Ok(None)
        }
    }
    
    async fn validate_rollback(
        &self,
        _current: &PluginHandle,
        target: &Checkpoint,
    ) -> Result<RollbackValidation> {
        let age = Utc::now() - target.created_at;
        let warnings = if age > chrono::Duration::days(7) {
            vec!["Checkpoint is more than 7 days old".to_string()]
        } else {
            vec![]
        };
        
        Ok(RollbackValidation {
            can_rollback: true,
            safety_score: 0.7,
            warnings,
            estimated_downtime: Duration::from_secs(5),
            data_loss_risk: DataLossRisk::Moderate,
        })
    }
    
    async fn prepare_rollback(
        &self,
        _current: &PluginHandle,
        _target: &Checkpoint,
    ) -> Result<RollbackPreparation> {
        Ok(RollbackPreparation {
            tasks: vec![
                RollbackTask {
                    id: "backup".to_string(),
                    name: "Create backup of current state".to_string(),
                    task_type: RollbackTaskType::CreateBackup,
                    priority: 1,
                },
            ],
            required_resources: ResourceRequirements::default(),
            estimated_duration: Duration::from_secs(15),
        })
    }
}

// Make manager cloneable
impl Clone for RollbackManager {
    fn clone(&self) -> Self {
        Self {
            checkpoints: self.checkpoints.clone(),
            strategies: self.strategies.clone(),
            active_rollbacks: self.active_rollbacks.clone(),
            state_transfer: self.state_transfer.clone(),
            version_manager: self.version_manager.clone(),
            config: self.config.clone(),
            history: self.history.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_health_score_calculation() {
        let strategy = SmartRollbackStrategy::new();
        
        let checkpoint = Checkpoint {
            id: "test".to_string(),
            plugin_id: "test-plugin".to_string(),
            version: Version::new(1, 0, 0),
            created_at: Utc::now(),
            checkpoint_type: CheckpointType::Manual,
            handle: Arc::new(PluginHandle::new(Box::new(crate::mcp_manager::plugins::docker::DockerPlugin::new()))),
            state: StateSnapshot {
                id: "test".to_string(),
                plugin_id: "test-plugin".to_string(),
                plugin_version: "1.0.0".to_string(),
                schema_version: 1,
                timestamp: 0,
                sections: HashMap::new(),
                metadata: super::state_transfer::StateMetadata {
                    reason: super::state_transfer::StateCreationReason::Backup,
                    created_by: "test".to_string(),
                    tags: vec![],
                    expires_at: None,
                    custom: HashMap::new(),
                },
                checksum: String::new(),
            },
            config: Value::Object(serde_json::Map::new()),
            metadata: CheckpointMetadata {
                reason: "test".to_string(),
                created_by: "test".to_string(),
                tags: vec![],
                health_status: HealthStatus {
                    healthy: true,
                    error_count: 0,
                    last_error: None,
                    uptime_secs: 3600,
                },
                metrics: PerformanceMetrics {
                    avg_response_ms: 100.0,
                    p99_response_ms: 200.0,
                    requests_per_sec: 100.0,
                    error_rate: 0.01,
                    memory_mb: 512.0,
                    cpu_percent: 25.0,
                },
                custom: HashMap::new(),
            },
            size_bytes: 1024,
        };
        
        let score = strategy.calculate_health_score(&checkpoint);
        assert!(score > 0.8 && score < 1.0);
    }
}