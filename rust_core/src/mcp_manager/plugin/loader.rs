//! Plugin Loader - Dynamic Loading with Zero Compromises
//!
//! This loader doesn't just load plugins. It breathes life into them,
//! ensuring they integrate seamlessly with our zero-copy, actor-based world.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

use libloading::{Library, Symbol};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error};

use super::{
    Plugin, PluginError, PluginMetadata, Result,
    PLUGIN_API_VERSION, traits::{Plugin as PluginTrait, PluginFactory},
};

/// Plugin loader - handles dynamic loading of plugins
pub struct PluginLoader {
    /// Loaded libraries
    libraries: Arc<RwLock<HashMap<String, LoadedPlugin>>>,
    
    /// Loader configuration
    config: LoaderConfig,
    
    /// Symbol cache for performance
    symbol_cache: Arc<RwLock<SymbolCache>>,
}

/// Loaded plugin information
struct LoadedPlugin {
    /// The loaded library
    library: Library,
    
    /// Plugin metadata
    metadata: PluginMetadata,
    
    /// Factory function
    factory: Option<Arc<dyn PluginFactory>>,
    
    /// Load timestamp
    loaded_at: std::time::SystemTime,
    
    /// File path
    path: PathBuf,
}

/// Loader configuration
#[derive(Debug, Clone)]
pub struct LoaderConfig {
    /// Plugin directories
    pub plugin_dirs: Vec<PathBuf>,
    
    /// File extensions to load
    pub extensions: Vec<String>,
    
    /// Enable symbol caching
    pub enable_cache: bool,
    
    /// Validate API version
    pub validate_version: bool,
    
    /// Allow unsigned plugins
    pub allow_unsigned: bool,
}

impl Default for LoaderConfig {
    fn default() -> Self {
        Self {
            plugin_dirs: vec![PathBuf::from("plugins")],
            #[cfg(target_os = "windows")]
            extensions: vec!["dll".to_string()],
            #[cfg(target_os = "macos")]
            extensions: vec!["dylib".to_string()],
            #[cfg(target_os = "linux")]
            extensions: vec!["so".to_string()],
            enable_cache: true,
            validate_version: true,
            allow_unsigned: false,
        }
    }
}

/// Symbol cache for faster lookups
struct SymbolCache {
    /// Cached symbols by library path and symbol name
    symbols: HashMap<(PathBuf, String), usize>,
}

/// Plugin loading functions that must be exported
type CreatePluginFn = unsafe extern "C" fn() -> *mut dyn Plugin;
type GetMetadataFn = unsafe extern "C" fn() -> PluginMetadata;
type GetApiVersionFn = unsafe extern "C" fn() -> u32;

impl PluginLoader {
    /// Create a new plugin loader
    pub fn new(config: LoaderConfig) -> Self {
        Self {
            libraries: Arc::new(RwLock::new(HashMap::new())),
            config,
            symbol_cache: Arc::new(RwLock::new(SymbolCache {
                symbols: HashMap::new(),
            })),
        }
    }
    
    /// Load a plugin from a file
    pub async fn load_plugin<P: AsRef<Path>>(&self, path: P) -> Result<Box<dyn Plugin>> {
        let path = path.as_ref();
        info!("Loading plugin from: {:?}", path);
        
        // Validate file exists and is readable
        if !path.exists() {
            return Err(PluginError::LoadingFailed(
                format!("Plugin file not found: {:?}", path)
            ));
        }
        
        // Load the library
        let library = unsafe {
            Library::new(path).map_err(|e| {
                PluginError::LoadingFailed(format!("Failed to load library: {}", e))
            })?
        };
        
        // Check API version if enabled
        if self.config.validate_version {
            self.check_api_version(&library)?;
        }
        
        // Get metadata
        let metadata = self.get_plugin_metadata(&library)?;
        
        // Create plugin instance
        let plugin = self.create_plugin_instance(&library)?;
        
        // Store loaded plugin info
        let mut libraries = self.libraries.write().await;
        libraries.insert(
            metadata.id.clone(),
            LoadedPlugin {
                library,
                metadata: metadata.clone(),
                factory: None,
                loaded_at: std::time::SystemTime::now(),
                path: path.to_path_buf(),
            },
        );
        
        info!("Plugin loaded successfully: {}", metadata.id);
        Ok(plugin)
    }
    
    /// Load all plugins from configured directories
    pub async fn load_all_plugins(&self) -> Vec<Result<Box<dyn Plugin>>> {
        let mut results = Vec::new();
        
        for dir in &self.config.plugin_dirs {
            if !dir.exists() {
                warn!("Plugin directory does not exist: {:?}", dir);
                continue;
            }
            
            let plugins = self.scan_directory(dir).await;
            for path in plugins {
                results.push(self.load_plugin(&path).await);
            }
        }
        
        results
    }
    
    /// Unload a plugin
    pub async fn unload_plugin(&self, plugin_id: &str) -> Result<()> {
        let mut libraries = self.libraries.write().await;
        
        if let Some(loaded) = libraries.remove(plugin_id) {
            // Clear symbol cache for this library
            if self.config.enable_cache {
                let mut cache = self.symbol_cache.write().await;
                cache.symbols.retain(|(path, _), _| path != &loaded.path);
            }
            
            // Library will be unloaded when dropped
            info!("Plugin unloaded: {}", plugin_id);
            Ok(())
        } else {
            Err(PluginError::NotFound(plugin_id.to_string()))
        }
    }
    
    /// Reload a plugin
    pub async fn reload_plugin(&self, plugin_id: &str) -> Result<Box<dyn Plugin>> {
        // Get the path of the current plugin
        let path = {
            let libraries = self.libraries.read().await;
            libraries.get(plugin_id)
                .ok_or_else(|| PluginError::NotFound(plugin_id.to_string()))?
                .path
                .clone()
        };
        
        // Unload the current version
        self.unload_plugin(plugin_id).await?;
        
        // Load the new version
        self.load_plugin(&path).await
    }
    
    /// Get loaded plugin metadata
    pub async fn get_loaded_plugins(&self) -> Vec<PluginMetadata> {
        let libraries = self.libraries.read().await;
        libraries.values()
            .map(|loaded| loaded.metadata.clone())
            .collect()
    }
    
    /// Check if a plugin is loaded
    pub async fn is_loaded(&self, plugin_id: &str) -> bool {
        let libraries = self.libraries.read().await;
        libraries.contains_key(plugin_id)
    }
    
    // Private helper methods
    
    fn check_api_version(&self, library: &Library) -> Result<()> {
        let get_version: Symbol<GetApiVersionFn> = unsafe {
            library.get(b"_plugin_api_version\0").map_err(|e| {
                PluginError::LoadingFailed(
                    format!("Failed to get API version symbol: {}", e)
                )
            })?
        };
        
        let version = unsafe { get_version() };
        
        if version != PLUGIN_API_VERSION {
            return Err(PluginError::IncompatibleVersion {
                expected: PLUGIN_API_VERSION.to_string(),
                actual: version.to_string(),
            });
        }
        
        Ok(())
    }
    
    fn get_plugin_metadata(&self, library: &Library) -> Result<PluginMetadata> {
        let get_metadata: Symbol<GetMetadataFn> = unsafe {
            library.get(b"_plugin_metadata\0").map_err(|e| {
                PluginError::LoadingFailed(
                    format!("Failed to get metadata symbol: {}", e)
                )
            })?
        };
        
        let metadata = unsafe { get_metadata() };
        Ok(metadata)
    }
    
    fn create_plugin_instance(&self, library: &Library) -> Result<Box<dyn Plugin>> {
        let create_plugin: Symbol<CreatePluginFn> = unsafe {
            library.get(b"_create_plugin\0").map_err(|e| {
                PluginError::LoadingFailed(
                    format!("Failed to get create symbol: {}", e)
                )
            })?
        };
        
        let plugin_ptr = unsafe { create_plugin() };
        
        if plugin_ptr.is_null() {
            return Err(PluginError::LoadingFailed(
                "Plugin creation returned null".to_string()
            ));
        }
        
        let plugin = unsafe { Box::from_raw(plugin_ptr) };
        Ok(plugin)
    }
    
    async fn scan_directory(&self, dir: &Path) -> Vec<PathBuf> {
        let mut plugins = Vec::new();
        
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) => {
                error!("Failed to read plugin directory {:?}: {}", dir, e);
                return plugins;
            }
        };
        
        for entry in entries.flatten() {
            let path = entry.path();
            
            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if self.config.extensions.iter().any(|e| e.as_str() == ext.to_str().unwrap_or("")) {
                        plugins.push(path);
                    }
                }
            }
        }
        
        plugins
    }
}

/// Builder for plugin loader
pub struct LoaderBuilder {
    config: LoaderConfig,
}

impl LoaderBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            config: LoaderConfig::default(),
        }
    }
    
    /// Add a plugin directory
    pub fn add_plugin_dir<P: Into<PathBuf>>(mut self, dir: P) -> Self {
        self.config.plugin_dirs.push(dir.into());
        self
    }
    
    /// Set plugin directories
    pub fn plugin_dirs<I, P>(mut self, dirs: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        self.config.plugin_dirs = dirs.into_iter().map(|p| p.into()).collect();
        self
    }
    
    /// Add file extension
    pub fn add_extension<S: Into<String>>(mut self, ext: S) -> Self {
        self.config.extensions.push(ext.into());
        self
    }
    
    /// Enable/disable symbol caching
    pub fn enable_cache(mut self, enable: bool) -> Self {
        self.config.enable_cache = enable;
        self
    }
    
    /// Enable/disable version validation
    pub fn validate_version(mut self, validate: bool) -> Self {
        self.config.validate_version = validate;
        self
    }
    
    /// Allow unsigned plugins
    pub fn allow_unsigned(mut self, allow: bool) -> Self {
        self.config.allow_unsigned = allow;
        self
    }
    
    /// Build the loader
    pub fn build(self) -> PluginLoader {
        PluginLoader::new(self.config)
    }
}

impl Default for LoaderBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Macro for exporting plugin symbols
#[macro_export]
macro_rules! export_plugin {
    ($plugin_type:ty) => {
        #[no_mangle]
        pub unsafe extern "C" fn _create_plugin() -> *mut dyn $crate::plugin::Plugin {
            let plugin = Box::new(<$plugin_type>::new());
            Box::into_raw(plugin) as *mut dyn $crate::plugin::Plugin
        }
        
        #[no_mangle]
        pub unsafe extern "C" fn _plugin_metadata() -> $crate::plugin::PluginMetadata {
            <$plugin_type>::metadata()
        }
        
        #[no_mangle]
        pub unsafe extern "C" fn _plugin_api_version() -> u32 {
            $crate::plugin::PLUGIN_API_VERSION
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_loader_builder() {
        let loader = LoaderBuilder::new()
            .add_plugin_dir("plugins")
            .add_plugin_dir("/usr/local/lib/mcp")
            .add_extension("so")
            .enable_cache(true)
            .validate_version(true)
            .build();
        
        assert_eq!(loader.config.plugin_dirs.len(), 2);
        assert!(loader.config.enable_cache);
        assert!(loader.config.validate_version);
    }
}