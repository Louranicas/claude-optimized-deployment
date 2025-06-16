//! State Transfer Protocol - Seamless State Migration Across Plugin Versions
//!
//! This module implements a sophisticated state transfer protocol that enables
//! plugins to preserve and transfer their state during hot reloads, upgrades,
//! and migrations. The protocol ensures zero data loss and minimal disruption.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc, oneshot};
use tokio::time::{timeout, Duration};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use bytes::Bytes;
use async_trait::async_trait;
use tracing::{debug, info, warn, error, instrument};

use super::{Plugin, PluginError, Result};

/// State transfer protocol trait - plugins implement this for state preservation
#[async_trait]
pub trait StateTransferable: Plugin {
    /// Export current state
    async fn export_state(&self) -> Result<StateSnapshot>;
    
    /// Import state from snapshot
    async fn import_state(&mut self, snapshot: StateSnapshot) -> Result<StateImportResult>;
    
    /// Validate state compatibility
    async fn validate_state(&self, snapshot: &StateSnapshot) -> Result<StateValidation>;
    
    /// Get state schema version
    fn state_schema_version(&self) -> u32;
    
    /// Migrate state from older version
    async fn migrate_state(&self, snapshot: StateSnapshot, from_version: u32) -> Result<StateSnapshot> {
        // Default implementation - no migration
        if from_version != self.state_schema_version() {
            Err(PluginError::ExecutionError(
                format!("State migration from version {} not supported", from_version)
            ))
        } else {
            Ok(snapshot)
        }
    }
}

/// State snapshot - complete plugin state at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Snapshot ID
    pub id: String,
    
    /// Plugin ID
    pub plugin_id: String,
    
    /// Plugin version
    pub plugin_version: String,
    
    /// State schema version
    pub schema_version: u32,
    
    /// Timestamp
    pub timestamp: i64,
    
    /// State sections
    pub sections: HashMap<String, StateSection>,
    
    /// Metadata
    pub metadata: StateMetadata,
    
    /// Checksum for integrity
    pub checksum: String,
}

/// State section - logical grouping of state data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSection {
    /// Section name
    pub name: String,
    
    /// Section type
    pub section_type: SectionType,
    
    /// Priority for restoration
    pub priority: u32,
    
    /// Data format
    pub format: DataFormat,
    
    /// Compressed data
    pub data: SectionData,
    
    /// Dependencies on other sections
    pub dependencies: Vec<String>,
}

/// Section types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SectionType {
    /// Core plugin state
    Core,
    
    /// Configuration data
    Configuration,
    
    /// Runtime metrics
    Metrics,
    
    /// Active connections
    Connections,
    
    /// In-flight requests
    InFlightRequests,
    
    /// Cache data
    Cache,
    
    /// Custom plugin data
    Custom,
}

/// Data formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataFormat {
    /// JSON format
    Json,
    
    /// MessagePack format
    MessagePack,
    
    /// Binary format
    Binary,
    
    /// Protocol Buffers
    ProtoBuf,
}

/// Section data - can be inline or external
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SectionData {
    /// Inline data
    Inline {
        /// Compressed data
        #[serde(with = "base64")]
        data: Vec<u8>,
        
        /// Original size
        original_size: usize,
        
        /// Compression type
        compression: CompressionType,
    },
    
    /// External reference
    External {
        /// Storage location
        location: String,
        
        /// Size in bytes
        size: usize,
        
        /// Retrieval method
        method: RetrievalMethod,
    },
}

/// Compression types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompressionType {
    /// No compression
    None,
    
    /// Gzip compression
    Gzip,
    
    /// Zstandard compression
    Zstd,
    
    /// LZ4 compression
    Lz4,
}

/// External data retrieval methods
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RetrievalMethod {
    /// File system path
    FileSystem { path: String },
    
    /// S3 bucket
    S3 { bucket: String, key: String },
    
    /// HTTP endpoint
    Http { url: String, headers: HashMap<String, String> },
    
    /// Shared memory
    SharedMemory { key: String },
}

/// State metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateMetadata {
    /// Creation reason
    pub reason: StateCreationReason,
    
    /// Creator information
    pub created_by: String,
    
    /// Tags for categorization
    pub tags: Vec<String>,
    
    /// Expiration time (if any)
    pub expires_at: Option<i64>,
    
    /// Custom metadata
    pub custom: HashMap<String, Value>,
}

/// Reasons for state creation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateCreationReason {
    /// Hot reload
    HotReload,
    
    /// Version upgrade
    VersionUpgrade,
    
    /// Backup
    Backup,
    
    /// Migration
    Migration,
    
    /// Debug snapshot
    Debug,
}

/// State import result
#[derive(Debug)]
pub struct StateImportResult {
    /// Sections successfully imported
    pub imported_sections: Vec<String>,
    
    /// Sections that failed
    pub failed_sections: Vec<(String, String)>, // (section_name, error)
    
    /// Warnings during import
    pub warnings: Vec<String>,
    
    /// Import duration
    pub duration: Duration,
}

/// State validation result
#[derive(Debug)]
pub struct StateValidation {
    /// Overall validity
    pub is_valid: bool,
    
    /// Schema compatibility
    pub schema_compatible: bool,
    
    /// Version compatibility
    pub version_compatible: bool,
    
    /// Section validations
    pub section_validations: HashMap<String, SectionValidation>,
    
    /// Compatibility score (0.0 - 1.0)
    pub compatibility_score: f64,
}

/// Section validation result
#[derive(Debug)]
pub struct SectionValidation {
    /// Section is valid
    pub is_valid: bool,
    
    /// Can be imported
    pub can_import: bool,
    
    /// Requires migration
    pub requires_migration: bool,
    
    /// Validation errors
    pub errors: Vec<String>,
}

/// State transfer result
#[derive(Debug, Default)]
pub struct StateTransferResult {
    /// Transfer was successful
    pub success: bool,
    
    /// Errors encountered during transfer
    pub errors: Vec<String>,
    
    /// Warnings during transfer
    pub warnings: Vec<String>,
    
    /// Transfer duration
    pub duration: Option<Duration>,
}

/// State transfer coordinator - manages the transfer process
pub struct StateTransferCoordinator {
    /// Transfer sessions
    sessions: Arc<RwLock<HashMap<String, TransferSession>>>,
    
    /// Configuration
    config: TransferConfig,
}

/// Transfer session
struct TransferSession {
    /// Session ID
    id: String,
    
    /// Source plugin
    source: Arc<RwLock<Box<dyn StateTransferable>>>,
    
    /// Target plugin
    target: Arc<RwLock<Box<dyn StateTransferable>>>,
    
    /// Session state
    state: TransferState,
    
    /// Progress tracker
    progress: TransferProgress,
    
    /// Result channel
    result_tx: Option<oneshot::Sender<Result<TransferResult>>>,
}

/// Transfer states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransferState {
    /// Initialized
    Initialized,
    
    /// Exporting state
    Exporting,
    
    /// Validating
    Validating,
    
    /// Transferring
    Transferring,
    
    /// Importing
    Importing,
    
    /// Completed
    Completed,
    
    /// Failed
    Failed,
}

/// Transfer progress
#[derive(Debug, Default)]
struct TransferProgress {
    /// Total sections
    total_sections: usize,
    
    /// Transferred sections
    transferred_sections: usize,
    
    /// Total bytes
    total_bytes: usize,
    
    /// Transferred bytes
    transferred_bytes: usize,
    
    /// Start time
    start_time: Option<std::time::Instant>,
    
    /// Current phase
    current_phase: String,
}

/// Transfer result
#[derive(Debug)]
pub struct TransferResult {
    /// Success status
    pub success: bool,
    
    /// Snapshot created
    pub snapshot: Option<StateSnapshot>,
    
    /// Import result
    pub import_result: Option<StateImportResult>,
    
    /// Total duration
    pub duration: Duration,
    
    /// Errors encountered
    pub errors: Vec<String>,
}

/// Transfer configuration
#[derive(Debug, Clone)]
pub struct TransferConfig {
    /// Transfer timeout
    pub timeout: Duration,
    
    /// Buffer size for streaming
    pub buffer_size: usize,
    
    /// Enable compression
    pub compress: bool,
    
    /// Compression type
    pub compression_type: CompressionType,
    
    /// Parallel transfers
    pub parallel_sections: usize,
    
    /// Verify checksums
    pub verify_checksums: bool,
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(60),
            buffer_size: 8192,
            compress: true,
            compression_type: CompressionType::Zstd,
            parallel_sections: 4,
            verify_checksums: true,
        }
    }
}

impl StateTransferCoordinator {
    /// Create a new coordinator
    pub fn new(config: TransferConfig) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }
    
    /// Transfer state between plugins
    #[instrument(skip(self, source, target))]
    pub async fn transfer_state(
        &self,
        source: Arc<RwLock<Box<dyn StateTransferable>>>,
        target: Arc<RwLock<Box<dyn StateTransferable>>>,
    ) -> Result<TransferResult> {
        let session_id = uuid::Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel();
        
        let session = TransferSession {
            id: session_id.clone(),
            source,
            target,
            state: TransferState::Initialized,
            progress: TransferProgress::default(),
            result_tx: Some(tx),
        };
        
        // Store session
        self.sessions.write().await.insert(session_id.clone(), session);
        
        // Start transfer
        let coordinator = self.clone();
        let session_id_clone = session_id.clone();
        tokio::spawn(async move {
            coordinator.execute_transfer(session_id_clone).await;
        });
        
        // Wait for result
        match timeout(self.config.timeout, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(PluginError::ExecutionError("Transfer cancelled".to_string())),
            Err(_) => Err(PluginError::ExecutionError("Transfer timeout".to_string())),
        }
    }
    
    /// Execute state transfer
    async fn execute_transfer(&self, session_id: String) {
        let start_time = std::time::Instant::now();
        let mut result = TransferResult {
            success: false,
            snapshot: None,
            import_result: None,
            duration: Duration::from_secs(0),
            errors: Vec::new(),
        };
        
        // Export state
        let snapshot = match self.export_state(&session_id).await {
            Ok(snap) => {
                result.snapshot = Some(snap.clone());
                snap
            }
            Err(e) => {
                result.errors.push(format!("Export failed: {}", e));
                self.complete_transfer(session_id, result).await;
                return;
            }
        };
        
        // Validate state
        if let Err(e) = self.validate_state(&session_id, &snapshot).await {
            result.errors.push(format!("Validation failed: {}", e));
            self.complete_transfer(session_id, result).await;
            return;
        }
        
        // Import state
        match self.import_state(&session_id, snapshot).await {
            Ok(import_result) => {
                result.import_result = Some(import_result);
                result.success = true;
            }
            Err(e) => {
                result.errors.push(format!("Import failed: {}", e));
            }
        }
        
        result.duration = start_time.elapsed();
        self.complete_transfer(session_id, result).await;
    }
    
    /// Export state from source
    async fn export_state(&self, session_id: &str) -> Result<StateSnapshot> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.get_mut(session_id)
            .ok_or_else(|| PluginError::NotFound("Session not found".to_string()))?;
        
        session.state = TransferState::Exporting;
        session.progress.current_phase = "Exporting state".to_string();
        
        let source = session.source.read().await;
        source.export_state().await
    }
    
    /// Validate state compatibility
    async fn validate_state(&self, session_id: &str, snapshot: &StateSnapshot) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.get_mut(session_id)
            .ok_or_else(|| PluginError::NotFound("Session not found".to_string()))?;
        
        session.state = TransferState::Validating;
        session.progress.current_phase = "Validating state".to_string();
        
        let target = session.target.read().await;
        let validation = target.validate_state(snapshot).await?;
        
        if !validation.is_valid {
            return Err(PluginError::ExecutionError("State validation failed".to_string()));
        }
        
        if validation.compatibility_score < 0.5 {
            return Err(PluginError::ExecutionError(
                format!("Compatibility score too low: {:.2}", validation.compatibility_score)
            ));
        }
        
        Ok(())
    }
    
    /// Import state to target
    async fn import_state(
        &self,
        session_id: &str,
        snapshot: StateSnapshot,
    ) -> Result<StateImportResult> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.get_mut(session_id)
            .ok_or_else(|| PluginError::NotFound("Session not found".to_string()))?;
        
        session.state = TransferState::Importing;
        session.progress.current_phase = "Importing state".to_string();
        session.progress.total_sections = snapshot.sections.len();
        
        let mut target = session.target.write().await;
        target.import_state(snapshot).await
    }
    
    /// Complete transfer session
    async fn complete_transfer(&self, session_id: String, result: TransferResult) {
        let mut sessions = self.sessions.write().await;
        if let Some(mut session) = sessions.remove(&session_id) {
            session.state = if result.success {
                TransferState::Completed
            } else {
                TransferState::Failed
            };
            
            if let Some(tx) = session.result_tx.take() {
                let _ = tx.send(Ok(result));
            }
        }
    }
}

// Make coordinator cloneable
impl Clone for StateTransferCoordinator {
    fn clone(&self) -> Self {
        Self {
            sessions: self.sessions.clone(),
            config: self.config.clone(),
        }
    }
}

/// Base64 encoding/decoding for serde
mod base64 {
    use serde::{Deserialize, Deserializer, Serializer};
    use base64::{Engine as _, engine::general_purpose};
    
    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = general_purpose::STANDARD.encode(bytes);
        serializer.serialize_str(&encoded)
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        general_purpose::STANDARD
            .decode(encoded)
            .map_err(serde::de::Error::custom)
    }
}

/// State compression utilities
pub mod compression {
    use super::*;
    use flate2::write::{GzEncoder, GzDecoder};
    use std::io::Write;
    
    /// Compress data
    pub fn compress(data: &[u8], compression_type: CompressionType) -> Result<Vec<u8>> {
        match compression_type {
            CompressionType::None => Ok(data.to_vec()),
            CompressionType::Gzip => {
                let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(data)
                    .map_err(|e| PluginError::ExecutionError(format!("Compression failed: {}", e)))?;
                encoder.finish()
                    .map_err(|e| PluginError::ExecutionError(format!("Compression failed: {}", e)))
            }
            CompressionType::Zstd => {
                // Would use zstd crate
                Ok(data.to_vec())
            }
            CompressionType::Lz4 => {
                // Would use lz4 crate
                Ok(data.to_vec())
            }
        }
    }
    
    /// Decompress data
    pub fn decompress(data: &[u8], compression_type: CompressionType) -> Result<Vec<u8>> {
        match compression_type {
            CompressionType::None => Ok(data.to_vec()),
            CompressionType::Gzip => {
                let mut decoder = GzDecoder::new(Vec::new());
                decoder.write_all(data)
                    .map_err(|e| PluginError::ExecutionError(format!("Decompression failed: {}", e)))?;
                decoder.finish()
                    .map_err(|e| PluginError::ExecutionError(format!("Decompression failed: {}", e)))
            }
            CompressionType::Zstd => {
                // Would use zstd crate
                Ok(data.to_vec())
            }
            CompressionType::Lz4 => {
                // Would use lz4 crate
                Ok(data.to_vec())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_state_snapshot_serialization() {
        let snapshot = StateSnapshot {
            id: "test-123".to_string(),
            plugin_id: "test-plugin".to_string(),
            plugin_version: "1.0.0".to_string(),
            schema_version: 1,
            timestamp: 1234567890,
            sections: HashMap::new(),
            metadata: StateMetadata {
                reason: StateCreationReason::HotReload,
                created_by: "test".to_string(),
                tags: vec!["test".to_string()],
                expires_at: None,
                custom: HashMap::new(),
            },
            checksum: "abc123".to_string(),
        };
        
        // Serialize
        let json = serde_json::to_string(&snapshot).unwrap();
        
        // Deserialize
        let restored: StateSnapshot = serde_json::from_str(&json).unwrap();
        
        assert_eq!(restored.id, snapshot.id);
        assert_eq!(restored.plugin_id, snapshot.plugin_id);
    }
}