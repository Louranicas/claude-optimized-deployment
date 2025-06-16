//! Plugin Discovery - Finding Needles in Digital Haystacks
//!
//! This module doesn't just find plugins. It discovers them like an archaeologist
//! uncovering ancient artifacts, each one a potential treasure of functionality.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

use notify::{Watcher, RecursiveMode, Event, EventKind};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{ info, warn, error};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};

use super::{PluginError, Result};

/// Plugin discovery service
pub struct DiscoveryService {
    /// Discovery configuration
    config: DiscoveryConfig,
    
    /// File system watcher
    watcher: Option<notify::RecommendedWatcher>,
    
    /// Discovered plugins
    discovered: Arc<RwLock<DiscoveredPlugins>>,
    
    /// Discovery event channel
    event_tx: mpsc::UnboundedSender<DiscoveryEvent>,
    event_rx: Arc<RwLock<mpsc::UnboundedReceiver<DiscoveryEvent>>>,
    
    /// Pattern matcher
    matcher: Arc<PluginMatcher>,
}

/// Discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Directories to watch
    pub watch_dirs: Vec<PathBuf>,
    
    /// File patterns to match
    pub patterns: Vec<String>,
    
    /// Exclude patterns
    pub exclude_patterns: Vec<String>,
    
    /// Enable file system watching
    pub enable_watch: bool,
    
    /// Scan recursively
    pub recursive: bool,
    
    /// Scan interval for polling (if watching disabled)
    pub scan_interval_secs: u64,
    
    /// Validate plugin files
    pub validate_plugins: bool,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            watch_dirs: vec![PathBuf::from("plugins")],
            #[cfg(target_os = "windows")]
            patterns: vec!["*.dll".to_string()],
            #[cfg(target_os = "macos")]
            patterns: vec!["*.dylib".to_string()],
            #[cfg(target_os = "linux")]
            patterns: vec!["*.so".to_string()],
            exclude_patterns: vec![
                "*test*".to_string(),
                "*debug*".to_string(),
                ".*".to_string(),
            ],
            enable_watch: true,
            recursive: true,
            scan_interval_secs: 60,
            validate_plugins: true,
        }
    }
}

/// Discovered plugins tracking
struct DiscoveredPlugins {
    /// All discovered plugin paths
    plugins: HashSet<PathBuf>,
    
    /// Plugin metadata cache
    metadata: HashMap<PathBuf, PluginMetadata>,
    
    /// Discovery timestamps
    timestamps: HashMap<PathBuf, std::time::SystemTime>,
}

/// Plugin metadata from discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    /// File name
    pub filename: String,
    
    /// File size
    pub size: u64,
    
    /// Last modified time
    pub modified: std::time::SystemTime,
    
    /// Hash of file contents
    pub hash: Option<String>,
    
    /// Detected plugin type
    pub plugin_type: Option<PluginType>,
}

/// Plugin types that can be discovered
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginType {
    /// Native shared library
    Native,
    
    /// WebAssembly module
    Wasm,
    
    /// Python script
    Python,
    
    /// JavaScript module
    JavaScript,
}

/// Discovery events
#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    /// New plugin discovered
    PluginFound {
        path: PathBuf,
        metadata: PluginMetadata,
    },
    
    /// Plugin file modified
    PluginModified {
        path: PathBuf,
        metadata: PluginMetadata,
    },
    
    /// Plugin file removed
    PluginRemoved {
        path: PathBuf,
    },
    
    /// Discovery error
    Error {
        path: Option<PathBuf>,
        error: String,
    },
}

/// Pattern matcher for plugins
struct PluginMatcher {
    /// Include patterns
    include_set: GlobSet,
    
    /// Exclude patterns
    exclude_set: GlobSet,
}

impl PluginMatcher {
    fn new(patterns: &[String], exclude_patterns: &[String]) -> Result<Self> {
        let mut include_builder = GlobSetBuilder::new();
        for pattern in patterns {
            let glob = Glob::new(pattern).map_err(|e| {
                PluginError::InvalidManifest(format!("Invalid pattern '{}': {}", pattern, e))
            })?;
            include_builder.add(glob);
        }
        
        let mut exclude_builder = GlobSetBuilder::new();
        for pattern in exclude_patterns {
            let glob = Glob::new(pattern).map_err(|e| {
                PluginError::InvalidManifest(format!("Invalid exclude pattern '{}': {}", pattern, e))
            })?;
            exclude_builder.add(glob);
        }
        
        Ok(Self {
            include_set: include_builder.build().map_err(|e| {
                PluginError::InvalidManifest(format!("Failed to build include set: {}", e))
            })?,
            exclude_set: exclude_builder.build().map_err(|e| {
                PluginError::InvalidManifest(format!("Failed to build exclude set: {}", e))
            })?,
        })
    }
    
    fn matches(&self, path: &Path) -> bool {
        self.include_set.is_match(path) && !self.exclude_set.is_match(path)
    }
}

impl DiscoveryService {
    /// Create a new discovery service
    pub fn new(config: DiscoveryConfig) -> Result<Self> {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let matcher = Arc::new(PluginMatcher::new(&config.patterns, &config.exclude_patterns)?);
        
        Ok(Self {
            config,
            watcher: None,
            discovered: Arc::new(RwLock::new(DiscoveredPlugins {
                plugins: HashSet::new(),
                metadata: HashMap::new(),
                timestamps: HashMap::new(),
            })),
            event_tx,
            event_rx: Arc::new(RwLock::new(event_rx)),
            matcher,
        })
    }
    
    /// Start discovery service
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting plugin discovery service");
        
        // Initial scan
        self.scan_all().await?;
        
        // Setup file watching if enabled
        if self.config.enable_watch {
            self.setup_watcher()?;
        } else {
            // Start polling task
            self.start_polling();
        }
        
        Ok(())
    }
    
    /// Stop discovery service
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping plugin discovery service");
        
        // Stop watcher
        self.watcher = None;
        
        Ok(())
    }
    
    /// Get discovered plugins
    pub async fn get_plugins(&self) -> Vec<PathBuf> {
        let discovered = self.discovered.read().await;
        discovered.plugins.iter().cloned().collect()
    }
    
    /// Get plugin metadata
    pub async fn get_metadata(&self, path: &Path) -> Option<PluginMetadata> {
        let discovered = self.discovered.read().await;
        discovered.metadata.get(path).cloned()
    }
    
    /// Get discovery events receiver
    pub async fn events(&self) -> mpsc::UnboundedReceiver<DiscoveryEvent> {
        // This is a simplified version - in production, you'd want
        // a broadcast channel or similar for multiple subscribers
        let mut rx = self.event_rx.write().await;
        // Create a new channel and swap
        let (tx, new_rx) = mpsc::unbounded_channel();
        // Forward events to new channel
        // (simplified - would need proper implementation)
        new_rx
    }
    
    /// Manually scan for plugins
    pub async fn scan(&self, path: &Path) -> Result<Vec<PathBuf>> {
        let mut found = Vec::new();
        
        if path.is_file() {
            if self.matcher.matches(path) {
                found.push(path.to_path_buf());
            }
        } else if path.is_dir() {
            found.extend(self.scan_directory(path).await?);
        }
        
        Ok(found)
    }
    
    // Private helper methods
    
    async fn scan_all(&self) -> Result<()> {
        for dir in &self.config.watch_dirs {
            if !dir.exists() {
                warn!("Watch directory does not exist: {:?}", dir);
                continue;
            }
            
            let plugins = self.scan_directory(dir).await?;
            for path in plugins {
                self.process_plugin_found(path).await?;
            }
        }
        
        Ok(())
    }
    
    fn scan_directory<'a>(&'a self, dir: &'a Path) -> futures::future::BoxFuture<'a, Result<Vec<PathBuf>>> {
        Box::pin(async move {
            let mut plugins = Vec::new();
            
            let entries = tokio::fs::read_dir(dir).await.map_err(|e| {
                PluginError::LoadingFailed(format!("Failed to read directory {:?}: {}", dir, e))
            })?;
            
            let mut entries = entries;
            while let Some(entry) = entries.next_entry().await.map_err(|e| {
                PluginError::LoadingFailed(format!("Failed to read entry: {}", e))
            })? {
                let path = entry.path();
                
                if path.is_file() && self.matcher.matches(&path) {
                    plugins.push(path);
                } else if path.is_dir() && self.config.recursive {
                    // Recursively scan subdirectories
                    let sub_plugins = self.scan_directory(&path).await?;
                    plugins.extend(sub_plugins);
                }
            }
            
            Ok(plugins)
        })
    }
    
    async fn process_plugin_found(&self, path: PathBuf) -> Result<()> {
        // Get file metadata
        let file_meta = tokio::fs::metadata(&path).await.map_err(|e| {
            PluginError::LoadingFailed(format!("Failed to get metadata for {:?}: {}", path, e))
        })?;
        
        let metadata = PluginMetadata {
            filename: path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string(),
            size: file_meta.len(),
            modified: file_meta.modified().unwrap_or(std::time::SystemTime::now()),
            hash: None, // TODO: Calculate hash if validation enabled
            plugin_type: Self::detect_plugin_type(&path),
        };
        
        // Store in discovered set
        {
            let mut discovered = self.discovered.write().await;
            discovered.plugins.insert(path.clone());
            discovered.metadata.insert(path.clone(), metadata.clone());
            discovered.timestamps.insert(path.clone(), std::time::SystemTime::now());
        }
        
        // Send event
        let _ = self.event_tx.send(DiscoveryEvent::PluginFound {
            path,
            metadata,
        });
        
        Ok(())
    }
    
    fn detect_plugin_type(path: &Path) -> Option<PluginType> {
        path.extension()
            .and_then(|ext| ext.to_str())
            .and_then(|ext| match ext {
                "so" | "dll" | "dylib" => Some(PluginType::Native),
                "wasm" => Some(PluginType::Wasm),
                "py" => Some(PluginType::Python),
                "js" | "mjs" => Some(PluginType::JavaScript),
                _ => None,
            })
    }
    
    fn setup_watcher(&mut self) -> Result<()> {
        let event_tx = self.event_tx.clone();
        let matcher = self.matcher.clone();
        let discovered = self.discovered.clone();
        
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            match res {
                Ok(event) => {
                    if let Err(e) = Self::handle_fs_event(event, &event_tx, &matcher, discovered.clone()) {
                        error!("Error handling FS event: {}", e);
                    }
                }
                Err(e) => {
                    error!("File watcher error: {}", e);
                    let _ = event_tx.send(DiscoveryEvent::Error {
                        path: None,
                        error: e.to_string(),
                    });
                }
            }
        }).map_err(|e| {
            PluginError::LoadingFailed(format!("Failed to create file watcher: {}", e))
        })?;
        
        // Watch all configured directories
        for dir in &self.config.watch_dirs {
            if dir.exists() {
                let mode = if self.config.recursive {
                    RecursiveMode::Recursive
                } else {
                    RecursiveMode::NonRecursive
                };
                
                watcher.watch(dir, mode).map_err(|e| {
                    PluginError::LoadingFailed(format!("Failed to watch {:?}: {}", dir, e))
                })?;
            }
        }
        
        self.watcher = Some(watcher);
        Ok(())
    }
    
    fn handle_fs_event(
        event: Event,
        event_tx: &mpsc::UnboundedSender<DiscoveryEvent>,
        matcher: &PluginMatcher,
        discovered: Arc<RwLock<DiscoveredPlugins>>,
    ) -> Result<()> {

        
        match event.kind {
            EventKind::Create(_) => {
                for path in event.paths {
                    if matcher.matches(&path) {
                        // Process in background
                        let event_tx = event_tx.clone();
                        let discovered = discovered.clone();
                        tokio::spawn(async move {
                            // Similar to process_plugin_found but async
                        });
                    }
                }
            }
            EventKind::Modify(_) => {
                for path in event.paths {
                    if matcher.matches(&path) {
                        let _ = event_tx.send(DiscoveryEvent::PluginModified {
                            path: path.clone(),
                            metadata: PluginMetadata {
                                filename: path.file_name()
                                    .and_then(|n| n.to_str())
                                    .unwrap_or("unknown")
                                    .to_string(),
                                size: 0, // Would need to fetch
                                modified: std::time::SystemTime::now(),
                                hash: None,
                                plugin_type: Self::detect_plugin_type(&path),
                            },
                        });
                    }
                }
            }
            EventKind::Remove(_) => {
                for path in event.paths {
                    if matcher.matches(&path) {
                        let _ = event_tx.send(DiscoveryEvent::PluginRemoved { path });
                    }
                }
            }
            _ => {}
        }
        
        Ok(())
    }
    
    fn start_polling(&self) {
        let config = self.config.clone();
        let discovered = self.discovered.clone();
        let event_tx = self.event_tx.clone();
        let matcher = self.matcher.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                std::time::Duration::from_secs(config.scan_interval_secs)
            );
            
            loop {
                interval.tick().await;
                
                // Scan all directories
                for dir in &config.watch_dirs {
                    if !dir.exists() {
                        continue;
                    }
                    
                    // TODO: Implement polling logic
                    // Compare with discovered set and emit events
                }
            }
        });
    }
}

/// Builder for discovery service
pub struct DiscoveryBuilder {
    config: DiscoveryConfig,
}

impl DiscoveryBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            config: DiscoveryConfig::default(),
        }
    }
    
    /// Add a watch directory
    pub fn add_watch_dir<P: Into<PathBuf>>(mut self, dir: P) -> Self {
        self.config.watch_dirs.push(dir.into());
        self
    }
    
    /// Set watch directories
    pub fn watch_dirs<I, P>(mut self, dirs: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        self.config.watch_dirs = dirs.into_iter().map(|p| p.into()).collect();
        self
    }
    
    /// Add a file pattern
    pub fn add_pattern<S: Into<String>>(mut self, pattern: S) -> Self {
        self.config.patterns.push(pattern.into());
        self
    }
    
    /// Add an exclude pattern
    pub fn add_exclude<S: Into<String>>(mut self, pattern: S) -> Self {
        self.config.exclude_patterns.push(pattern.into());
        self
    }
    
    /// Enable/disable file watching
    pub fn enable_watch(mut self, enable: bool) -> Self {
        self.config.enable_watch = enable;
        self
    }
    
    /// Enable/disable recursive scanning
    pub fn recursive(mut self, recursive: bool) -> Self {
        self.config.recursive = recursive;
        self
    }
    
    /// Set scan interval for polling
    pub fn scan_interval(mut self, seconds: u64) -> Self {
        self.config.scan_interval_secs = seconds;
        self
    }
    
    /// Enable/disable plugin validation
    pub fn validate_plugins(mut self, validate: bool) -> Self {
        self.config.validate_plugins = validate;
        self
    }
    
    /// Build the discovery service
    pub fn build(self) -> Result<DiscoveryService> {
        DiscoveryService::new(self.config)
    }
}

impl Default for DiscoveryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_plugin_matcher() {
        let matcher = PluginMatcher::new(
            &["*.so".to_string(), "*.dll".to_string()],
            &["*test*".to_string()],
        ).unwrap();
        
        assert!(matcher.matches(Path::new("plugin.so")));
        assert!(matcher.matches(Path::new("my_plugin.dll")));
        assert!(!matcher.matches(Path::new("plugin_test.so")));
        assert!(!matcher.matches(Path::new("plugin.txt")));
    }
    
    #[test]
    fn test_plugin_type_detection() {
        assert_eq!(
            DiscoveryService::detect_plugin_type(Path::new("plugin.so")),
            Some(PluginType::Native)
        );
        assert_eq!(
            DiscoveryService::detect_plugin_type(Path::new("plugin.wasm")),
            Some(PluginType::Wasm)
        );
        assert_eq!(
            DiscoveryService::detect_plugin_type(Path::new("plugin.py")),
            Some(PluginType::Python)
        );
        assert_eq!(
            DiscoveryService::detect_plugin_type(Path::new("plugin.txt")),
            None
        );
    }
}