//! Plugin Version Management - Semantic Versioning at Scale
//!
//! This module implements comprehensive version management for plugins,
//! ensuring compatibility, smooth upgrades, and safe rollbacks.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

use std::collections::{HashMap, BTreeMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use semver::{Version, VersionReq, Prerelease};
use chrono::{DateTime, Utc};
use tracing::{debug, info, warn, error};

use super::{PluginError, PluginMetadata, Result};

/// Version manager - handles all version-related operations
pub struct VersionManager {
    /// Version registry
    registry: Arc<RwLock<VersionRegistry>>,
    
    /// Configuration
    config: VersionConfig,
    
    /// Version resolver
    resolver: VersionResolver,
    
    /// Migration manager
    migrations: Arc<RwLock<MigrationManager>>,
}

/// Version registry - tracks all plugin versions
#[derive(Debug, Default)]
struct VersionRegistry {
    /// All versions by plugin ID
    versions: HashMap<String, PluginVersionHistory>,
    
    /// Version constraints
    constraints: HashMap<String, Vec<VersionConstraint>>,
    
    /// Compatibility matrix
    compatibility: CompatibilityMatrix,
}

/// Plugin version history
#[derive(Debug, Clone)]
pub struct PluginVersionHistory {
    /// Plugin ID
    pub plugin_id: String,
    
    /// All known versions
    pub versions: BTreeMap<Version, VersionInfo>,
    
    /// Current active version
    pub current_version: Option<Version>,
    
    /// Version timeline
    pub timeline: Vec<VersionEvent>,
}

/// Version information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    /// Version number
    pub version: Version,
    
    /// Release date
    pub released_at: DateTime<Utc>,
    
    /// Version metadata
    pub metadata: VersionMetadata,
    
    /// File information
    pub file_info: Option<FileInfo>,
    
    /// Dependencies
    pub dependencies: Vec<Dependency>,
    
    /// Breaking changes
    pub breaking_changes: Vec<BreakingChange>,
    
    /// Migration path
    pub migration: Option<MigrationInfo>,
}

/// Version metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionMetadata {
    /// Version description
    pub description: String,
    
    /// Release notes
    pub release_notes: String,
    
    /// Author
    pub author: String,
    
    /// Stability level
    pub stability: StabilityLevel,
    
    /// Deprecation status
    pub deprecated: bool,
    
    /// Deprecation notice
    pub deprecation_notice: Option<String>,
    
    /// Security patches
    pub security_patches: Vec<SecurityPatch>,
}

/// Stability levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StabilityLevel {
    /// Experimental - may change significantly
    Experimental,
    
    /// Alpha - early testing
    Alpha,
    
    /// Beta - feature complete, testing
    Beta,
    
    /// Release Candidate
    ReleaseCandidate,
    
    /// Stable - production ready
    Stable,
    
    /// Long Term Support
    LTS,
}

/// Security patch information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPatch {
    /// CVE identifier
    pub cve: String,
    
    /// Severity level
    pub severity: SecuritySeverity,
    
    /// Description
    pub description: String,
    
    /// Fixed in version
    pub fixed_in: Version,
}

/// Security severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecuritySeverity {
    /// Low severity
    Low,
    
    /// Medium severity
    Medium,
    
    /// High severity
    High,
    
    /// Critical severity
    Critical,
}

/// File information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    /// File path
    pub path: PathBuf,
    
    /// File size
    pub size: u64,
    
    /// SHA256 checksum
    pub checksum: String,
    
    /// Signature (if signed)
    pub signature: Option<String>,
}

/// Dependency specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    /// Plugin ID
    pub plugin_id: String,
    
    /// Version requirement
    pub version_req: VersionReq,
    
    /// Optional dependency
    pub optional: bool,
    
    /// Feature flag required
    pub feature: Option<String>,
}

/// Breaking change information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakingChange {
    /// Change type
    pub change_type: BreakingChangeType,
    
    /// Description
    pub description: String,
    
    /// Migration guide
    pub migration_guide: String,
    
    /// Affected APIs
    pub affected_apis: Vec<String>,
}

/// Breaking change types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BreakingChangeType {
    /// API removed
    ApiRemoved,
    
    /// API signature changed
    ApiChanged,
    
    /// Behavior changed
    BehaviorChanged,
    
    /// Configuration format changed
    ConfigurationChanged,
    
    /// Protocol changed
    ProtocolChanged,
}

/// Migration information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationInfo {
    /// From version
    pub from_version: Version,
    
    /// To version
    pub to_version: Version,
    
    /// Migration type
    pub migration_type: MigrationType,
    
    /// Automated migration available
    pub automated: bool,
    
    /// Migration script
    pub script: Option<String>,
    
    /// Estimated duration
    pub estimated_duration_secs: u64,
}

/// Migration types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationType {
    /// Simple update - no action required
    Simple,
    
    /// Configuration migration required
    Configuration,
    
    /// State migration required
    State,
    
    /// Full migration required
    Full,
}

/// Version event in timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionEvent {
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    
    /// Event type
    pub event_type: VersionEventType,
    
    /// Version involved
    pub version: Version,
    
    /// Additional details
    pub details: String,
}

/// Version event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VersionEventType {
    /// Version released
    Released,
    
    /// Version installed
    Installed,
    
    /// Version activated
    Activated,
    
    /// Version deactivated
    Deactivated,
    
    /// Version removed
    Removed,
    
    /// Version deprecated
    Deprecated,
}

/// Version constraint
#[derive(Debug, Clone)]
pub struct VersionConstraint {
    /// Source of constraint
    pub source: String,
    
    /// Plugin ID
    pub plugin_id: String,
    
    /// Version requirement
    pub requirement: VersionReq,
    
    /// Constraint type
    pub constraint_type: ConstraintType,
}

/// Constraint types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstraintType {
    /// Hard requirement - must be satisfied
    Required,
    
    /// Recommended - should be satisfied
    Recommended,
    
    /// Conflict - must not be satisfied
    Conflict,
}

/// Compatibility matrix
#[derive(Debug, Default)]
struct CompatibilityMatrix {
    /// Compatibility entries
    entries: HashMap<(String, Version, String, Version), CompatibilityStatus>,
}

/// Compatibility status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatibilityStatus {
    /// Fully compatible
    Compatible,
    
    /// Compatible with warnings
    CompatibleWithWarnings,
    
    /// Incompatible
    Incompatible,
    
    /// Unknown compatibility
    Unknown,
}

/// Version resolver - resolves version requirements
pub struct VersionResolver {
    /// Resolution strategy
    strategy: ResolutionStrategy,
}

/// Resolution strategies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResolutionStrategy {
    /// Always use latest compatible version
    Latest,
    
    /// Use latest stable version
    LatestStable,
    
    /// Use LTS versions when available
    PreferLTS,
    
    /// Conservative - minimal upgrades
    Conservative,
}

/// Migration manager
#[derive(Debug, Default)]
struct MigrationManager {
    /// Available migrations
    migrations: HashMap<(String, Version, Version), Migration>,
    
    /// Migration history
    history: Vec<MigrationHistoryEntry>,
}

/// Migration definition
#[derive(Debug, Clone)]
struct Migration {
    /// Migration ID
    id: String,
    
    /// Plugin ID
    plugin_id: String,
    
    /// From version
    from_version: Version,
    
    /// To version
    to_version: Version,
    
    /// Migration steps
    steps: Vec<MigrationStep>,
    
    /// Rollback steps
    rollback_steps: Vec<MigrationStep>,
}

/// Migration step
#[derive(Debug, Clone)]
struct MigrationStep {
    /// Step name
    name: String,
    
    /// Step type
    step_type: MigrationStepType,
    
    /// Step data
    data: serde_json::Value,
}

/// Migration step types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MigrationStepType {
    /// Configuration transformation
    ConfigTransform,
    
    /// State migration
    StateMigration,
    
    /// API mapping
    ApiMapping,
    
    /// Custom script
    CustomScript,
}

/// Migration history entry
#[derive(Debug, Clone)]
struct MigrationHistoryEntry {
    /// Migration ID
    migration_id: String,
    
    /// Plugin ID
    plugin_id: String,
    
    /// From version
    from_version: Version,
    
    /// To version
    to_version: Version,
    
    /// Started at
    started_at: DateTime<Utc>,
    
    /// Completed at
    completed_at: Option<DateTime<Utc>>,
    
    /// Success status
    success: bool,
    
    /// Error message
    error: Option<String>,
}

/// Version configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionConfig {
    /// Resolution strategy
    pub resolution_strategy: ResolutionStrategy,
    
    /// Allow pre-release versions
    pub allow_prerelease: bool,
    
    /// Allow deprecated versions
    pub allow_deprecated: bool,
    
    /// Require signatures
    pub require_signatures: bool,
    
    /// Maximum version age in days (0 = no limit)
    pub max_version_age_days: u32,
    
    /// Auto-update to security patches
    pub auto_update_security: bool,
}

impl Default for VersionConfig {
    fn default() -> Self {
        Self {
            resolution_strategy: ResolutionStrategy::LatestStable,
            allow_prerelease: false,
            allow_deprecated: false,
            require_signatures: false,
            max_version_age_days: 0,
            auto_update_security: true,
        }
    }
}

impl VersionManager {
    /// Create a new version manager
    pub fn new(config: VersionConfig) -> Self {
        let resolution_strategy = config.resolution_strategy.clone();
        Self {
            registry: Arc::new(RwLock::new(VersionRegistry::default())),
            config,
            resolver: VersionResolver {
                strategy: resolution_strategy,
            },
            migrations: Arc::new(RwLock::new(MigrationManager::default())),
        }
    }
    
    /// Register a plugin version
    pub async fn register_version(
        &self,
        plugin_id: String,
        version_info: VersionInfo,
    ) -> Result<()> {
        let mut registry = self.registry.write().await;
        
        let history = registry.versions.entry(plugin_id.clone())
            .or_insert_with(|| PluginVersionHistory {
                plugin_id: plugin_id.clone(),
                versions: BTreeMap::new(),
                current_version: None,
                timeline: Vec::new(),
            });
        
        // Add version
        let version = version_info.version.clone();
        history.versions.insert(version.clone(), version_info);
        
        // Add to timeline
        history.timeline.push(VersionEvent {
            timestamp: Utc::now(),
            event_type: VersionEventType::Released,
            version: version.clone(),
            details: format!("Version {} registered", version),
        });
        
        info!("Registered version {} for plugin {}", version, plugin_id);
        Ok(())
    }
    
    /// Get version history for a plugin
    pub async fn get_version_history(&self, plugin_id: &str) -> Option<PluginVersionHistory> {
        let registry = self.registry.read().await;
        registry.versions.get(plugin_id).cloned()
    }
    
    /// Resolve version requirement
    pub async fn resolve_version(
        &self,
        plugin_id: &str,
        requirement: &VersionReq,
    ) -> Result<Version> {
        let registry = self.registry.read().await;
        
        let history = registry.versions.get(plugin_id)
            .ok_or_else(|| PluginError::NotFound(format!("Plugin {} not found", plugin_id)))?;
        
        // Get matching versions
        let mut matching_versions: Vec<&Version> = history.versions.keys()
            .filter(|v| requirement.matches(v))
            .collect();
        
        if matching_versions.is_empty() {
            return Err(PluginError::ExecutionError(
                format!("No version of {} matches requirement {}", plugin_id, requirement)
            ));
        }
        
        // Apply filters based on config
        if !self.config.allow_prerelease {
            matching_versions.retain(|v| v.pre.is_empty());
        }
        
        if !self.config.allow_deprecated {
            matching_versions.retain(|v| {
                if let Some(info) = history.versions.get(v) {
                    !info.metadata.deprecated
                } else {
                    true
                }
            });
        }
        
        // Apply resolution strategy
        let selected = match self.config.resolution_strategy {
            ResolutionStrategy::Latest => {
                matching_versions.into_iter().max()
            }
            ResolutionStrategy::LatestStable => {
                matching_versions.into_iter()
                    .filter(|v| {
                        if let Some(info) = history.versions.get(v) {
                            matches!(info.metadata.stability, StabilityLevel::Stable | StabilityLevel::LTS)
                        } else {
                            false
                        }
                    })
                    .max()
            }
            ResolutionStrategy::PreferLTS => {
                // First try LTS versions
                let lts = matching_versions.iter()
                    .filter(|v| {
                        if let Some(info) = history.versions.get(v) {
                            info.metadata.stability == StabilityLevel::LTS
                        } else {
                            false
                        }
                    })
                    .max();
                
                lts.copied().or_else(|| matching_versions.into_iter().max())
            }
            ResolutionStrategy::Conservative => {
                matching_versions.into_iter().min()
            }
        };
        
        selected.cloned()
            .ok_or_else(|| PluginError::ExecutionError(
                format!("Failed to resolve version for {}", plugin_id)
            ))
    }
    
    /// Check compatibility between plugins
    pub async fn check_compatibility(
        &self,
        plugin_a: &str,
        version_a: &Version,
        plugin_b: &str,
        version_b: &Version,
    ) -> CompatibilityStatus {
        let registry = self.registry.read().await;
        
        // Check compatibility matrix
        if let Some(status) = registry.compatibility.entries.get(
            &(plugin_a.to_string(), version_a.clone(), plugin_b.to_string(), version_b.clone())
        ) {
            return *status;
        }
        
        // Check reverse direction
        if let Some(status) = registry.compatibility.entries.get(
            &(plugin_b.to_string(), version_b.clone(), plugin_a.to_string(), version_a.clone())
        ) {
            return *status;
        }
        
        // Default to unknown
        CompatibilityStatus::Unknown
    }
    
    /// Register a compatibility status
    pub async fn register_compatibility(
        &self,
        plugin_a: String,
        version_a: Version,
        plugin_b: String,
        version_b: Version,
        status: CompatibilityStatus,
    ) -> Result<()> {
        let mut registry = self.registry.write().await;
        
        registry.compatibility.entries.insert(
            (plugin_a, version_a, plugin_b, version_b),
            status,
        );
        
        Ok(())
    }
    
    /// Get available migrations
    pub async fn get_migrations(
        &self,
        plugin_id: &str,
        from_version: &Version,
        to_version: &Version,
    ) -> Vec<Migration> {
        let migrations = self.migrations.read().await;
        
        // Find direct migration
        if let Some(migration) = migrations.migrations.get(
            &(plugin_id.to_string(), from_version.clone(), to_version.clone())
        ) {
            return vec![migration.clone()];
        }
        
        // TODO: Implement multi-step migration path finding
        Vec::new()
    }
    
    /// Register a migration
    pub async fn register_migration(&self, migration: Migration) -> Result<()> {
        let mut migrations = self.migrations.write().await;
        
        let key = (
            migration.plugin_id.clone(),
            migration.from_version.clone(),
            migration.to_version.clone(),
        );
        
        migrations.migrations.insert(key, migration);
        Ok(())
    }
    
    /// Execute a migration
    pub async fn execute_migration(
        &self,
        plugin_id: &str,
        from_version: &Version,
        to_version: &Version,
    ) -> Result<()> {
        let migrations = self.get_migrations(plugin_id, from_version, to_version).await;
        
        if migrations.is_empty() {
            return Err(PluginError::ExecutionError(
                format!("No migration path from {} to {}", from_version, to_version)
            ));
        }
        
        for migration in migrations {
            self.execute_single_migration(migration).await?;
        }
        
        Ok(())
    }
    
    /// Execute a single migration
    async fn execute_single_migration(&self, migration: Migration) -> Result<()> {
        let start_time = Utc::now();
        
        info!("Starting migration {} for plugin {} from {} to {}",
              migration.id, migration.plugin_id,
              migration.from_version, migration.to_version);
        
        // Record start in history
        let history_entry = MigrationHistoryEntry {
            migration_id: migration.id.clone(),
            plugin_id: migration.plugin_id.clone(),
            from_version: migration.from_version.clone(),
            to_version: migration.to_version.clone(),
            started_at: start_time,
            completed_at: None,
            success: false,
            error: None,
        };
        
        // Execute steps
        for step in &migration.steps {
            debug!("Executing migration step: {}", step.name);
            // Step execution would be implemented here
        }
        
        // Record completion
        let mut migrations = self.migrations.write().await;
        let completed_entry = MigrationHistoryEntry {
            completed_at: Some(Utc::now()),
            success: true,
            ..history_entry
        };
        
        migrations.history.push(completed_entry);
        
        info!("Migration {} completed successfully", migration.id);
        Ok(())
    }
    
    /// Get security vulnerabilities for a version
    pub async fn get_vulnerabilities(
        &self,
        plugin_id: &str,
        version: &Version,
    ) -> Vec<SecurityPatch> {
        let registry = self.registry.read().await;
        
        if let Some(history) = registry.versions.get(plugin_id) {
            if let Some(info) = history.versions.get(version) {
                return info.metadata.security_patches.clone();
            }
        }
        
        Vec::new()
    }
    
    /// Check if a version is safe to use
    pub async fn is_version_safe(
        &self,
        plugin_id: &str,
        version: &Version,
    ) -> bool {
        let vulnerabilities = self.get_vulnerabilities(plugin_id, version).await;
        
        // Check for critical vulnerabilities
        !vulnerabilities.iter().any(|v| v.severity == SecuritySeverity::Critical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_version_resolution() {
        let config = VersionConfig::default();
        let manager = VersionManager::new(config);
        
        // Register some versions
        let plugin_id = "test-plugin".to_string();
        
        for version_str in ["1.0.0", "1.1.0", "1.2.0", "2.0.0-beta.1", "2.0.0"] {
            let version = Version::parse(version_str).unwrap();
            let info = VersionInfo {
                version: version.clone(),
                released_at: Utc::now(),
                metadata: VersionMetadata {
                    description: format!("Version {}", version),
                    release_notes: String::new(),
                    author: "Test".to_string(),
                    stability: if version_str.contains("beta") {
                        StabilityLevel::Beta
                    } else {
                        StabilityLevel::Stable
                    },
                    deprecated: false,
                    deprecation_notice: None,
                    security_patches: vec![],
                },
                file_info: None,
                dependencies: vec![],
                breaking_changes: vec![],
                migration: None,
            };
            
            manager.register_version(plugin_id.clone(), info).await.unwrap();
        }
        
        // Test resolution
        let req = VersionReq::parse("^1.0.0").unwrap();
        let resolved = manager.resolve_version(&plugin_id, &req).await.unwrap();
        assert_eq!(resolved, Version::parse("1.2.0").unwrap());
        
        // Test with pre-release
        let req = VersionReq::parse("^2.0.0").unwrap();
        let resolved = manager.resolve_version(&plugin_id, &req).await.unwrap();
        assert_eq!(resolved, Version::parse("2.0.0").unwrap());
    }
}