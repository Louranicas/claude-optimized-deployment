//! Plugin Loader Unit Tests
//!
//! Tests for the plugin loading and dynamic library management.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

use claude_optimized_deployment_rust::mcp_manager::plugin::{*, loader::*};
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;
use std::fs;

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a mock plugin library file for testing
    fn create_mock_plugin_lib(dir: &TempDir, name: &str) -> PathBuf {
        let lib_path = dir.path().join(format!("lib{}.so", name));
        // Create a dummy file (not a real library)
        fs::write(&lib_path, b"dummy library content").unwrap();
        lib_path
    }

    #[test]
    fn test_plugin_loader_creation() {
        let loader = PluginLoader::new();
        assert!(loader.search_paths().is_empty());
    }

    #[test]
    fn test_plugin_loader_with_paths() {
        let paths = vec![
            PathBuf::from("/usr/lib/plugins"),
            PathBuf::from("/opt/plugins"),
        ];
        
        let loader = PluginLoader::with_paths(paths.clone());
        let search_paths = loader.search_paths();
        
        assert_eq!(search_paths.len(), 2);
        assert_eq!(search_paths[0], paths[0]);
        assert_eq!(search_paths[1], paths[1]);
    }

    #[test]
    fn test_plugin_loader_add_path() {
        let mut loader = PluginLoader::new();
        let path = PathBuf::from("/custom/plugins");
        
        loader.add_search_path(path.clone());
        let search_paths = loader.search_paths();
        
        assert_eq!(search_paths.len(), 1);
        assert_eq!(search_paths[0], path);
        
        // Add another path
        let path2 = PathBuf::from("/another/path");
        loader.add_search_path(path2.clone());
        
        let search_paths = loader.search_paths();
        assert_eq!(search_paths.len(), 2);
    }

    #[tokio::test]
    async fn test_plugin_loader_discover() {
        let temp_dir = TempDir::new().unwrap();
        let mut loader = PluginLoader::new();
        loader.add_search_path(temp_dir.path().to_path_buf());
        
        // Create some mock plugin files
        create_mock_plugin_lib(&temp_dir, "plugin1");
        create_mock_plugin_lib(&temp_dir, "plugin2");
        
        // Create non-plugin file
        fs::write(temp_dir.path().join("not_a_plugin.txt"), b"text").unwrap();
        
        let discovered = loader.discover_plugins().await;
        assert_eq!(discovered.len(), 2);
        
        // Check that discovered paths are correct
        let names: Vec<String> = discovered.iter()
            .map(|p| p.file_stem().unwrap().to_string_lossy().to_string())
            .collect();
        
        assert!(names.contains(&"libplugin1".to_string()));
        assert!(names.contains(&"libplugin2".to_string()));
    }

    #[tokio::test]
    async fn test_plugin_loader_empty_directory() {
        let temp_dir = TempDir::new().unwrap();
        let mut loader = PluginLoader::new();
        loader.add_search_path(temp_dir.path().to_path_buf());
        
        let discovered = loader.discover_plugins().await;
        assert_eq!(discovered.len(), 0);
    }

    #[tokio::test]
    async fn test_plugin_loader_nonexistent_path() {
        let mut loader = PluginLoader::new();
        loader.add_search_path(PathBuf::from("/nonexistent/path"));
        
        let discovered = loader.discover_plugins().await;
        assert_eq!(discovered.len(), 0);
    }

    #[tokio::test]
    async fn test_plugin_loader_load_error() {
        let loader = PluginLoader::new();
        let result = loader.load_plugin(&PathBuf::from("/nonexistent/plugin.so")).await;
        
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PluginError::LoadingFailed(_)
        ));
    }

    #[test]
    fn test_plugin_manifest_parsing() {
        let manifest_json = r#"{
            "id": "test-plugin",
            "name": "Test Plugin",
            "version": "1.0.0",
            "author": "Test Author",
            "description": "A test plugin",
            "license": "MIT",
            "min_mcp_version": "1.0.0",
            "dependencies": [
                {
                    "id": "dep1",
                    "version": "^1.0.0",
                    "optional": false
                }
            ],
            "provides": [
                {
                    "namespace": "test",
                    "name": "operation",
                    "version": 1
                }
            ],
            "requires": []
        }"#;
        
        let manifest: PluginManifest = serde_json::from_str(manifest_json).unwrap();
        assert_eq!(manifest.id, "test-plugin");
        assert_eq!(manifest.version, "1.0.0");
        assert_eq!(manifest.dependencies.len(), 1);
        assert_eq!(manifest.provides.len(), 1);
    }

    #[test]
    fn test_plugin_manifest_minimal() {
        let manifest_json = r#"{
            "id": "minimal",
            "name": "Minimal Plugin",
            "version": "0.1.0",
            "author": "Test",
            "description": "Minimal plugin",
            "license": "MIT",
            "min_mcp_version": "1.0.0"
        }"#;
        
        let manifest: PluginManifest = serde_json::from_str(manifest_json).unwrap();
        assert_eq!(manifest.id, "minimal");
        assert!(manifest.dependencies.is_empty());
        assert!(manifest.provides.is_empty());
        assert!(manifest.requires.is_empty());
    }

    #[test]
    fn test_library_handle() {
        // Create a mock library handle
        let handle = LibraryHandle {
            library: Arc::new(unsafe { libloading::Library::new("libc.so.6").unwrap() }),
            path: PathBuf::from("/lib/libc.so.6"),
        };
        
        assert_eq!(handle.path, PathBuf::from("/lib/libc.so.6"));
    }

    #[tokio::test]
    async fn test_plugin_loader_concurrent_discover() {
        let temp_dir = TempDir::new().unwrap();
        let loader = Arc::new(PluginLoader::new());
        
        // Create plugins
        for i in 0..10 {
            create_mock_plugin_lib(&temp_dir, &format!("concurrent{}", i));
        }
        
        // Add search path
        let mut loader_mut = Arc::try_unwrap(loader.clone()).unwrap_or_else(|arc| (*arc).clone());
        loader_mut.add_search_path(temp_dir.path().to_path_buf());
        let loader = Arc::new(loader_mut);
        
        // Spawn multiple discover tasks
        let mut tasks = vec![];
        for _ in 0..5 {
            let loader_clone = loader.clone();
            let task = tokio::spawn(async move {
                loader_clone.discover_plugins().await
            });
            tasks.push(task);
        }
        
        // Wait for all tasks
        let results: Vec<_> = futures::future::join_all(tasks).await;
        
        // All should discover the same plugins
        for result in results {
            let plugins = result.unwrap();
            assert_eq!(plugins.len(), 10);
        }
    }

    #[test]
    fn test_plugin_loader_duplicate_paths() {
        let mut loader = PluginLoader::new();
        let path = PathBuf::from("/plugins");
        
        loader.add_search_path(path.clone());
        loader.add_search_path(path.clone());
        
        // Should not add duplicate paths
        let search_paths = loader.search_paths();
        assert_eq!(search_paths.len(), 1);
    }

    #[test]
    fn test_plugin_loader_clear_paths() {
        let mut loader = PluginLoader::new();
        
        loader.add_search_path(PathBuf::from("/path1"));
        loader.add_search_path(PathBuf::from("/path2"));
        assert_eq!(loader.search_paths().len(), 2);
        
        loader.clear_search_paths();
        assert_eq!(loader.search_paths().len(), 0);
    }

    #[tokio::test]
    async fn test_plugin_loader_file_patterns() {
        let temp_dir = TempDir::new().unwrap();
        let mut loader = PluginLoader::new();
        loader.add_search_path(temp_dir.path().to_path_buf());
        
        // Create files with different extensions
        fs::write(temp_dir.path().join("libplugin.so"), b"").unwrap();
        fs::write(temp_dir.path().join("plugin.dll"), b"").unwrap();
        fs::write(temp_dir.path().join("libplugin.dylib"), b"").unwrap();
        fs::write(temp_dir.path().join("plugin.txt"), b"").unwrap();
        
        let discovered = loader.discover_plugins().await;
        
        // Should find library files based on platform
        #[cfg(target_os = "linux")]
        assert_eq!(discovered.len(), 1); // Only .so files
        
        #[cfg(target_os = "windows")]
        assert_eq!(discovered.len(), 1); // Only .dll files
        
        #[cfg(target_os = "macos")]
        assert_eq!(discovered.len(), 1); // Only .dylib files
    }
}