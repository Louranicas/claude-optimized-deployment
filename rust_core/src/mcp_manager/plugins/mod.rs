//! Built-in MCP Server Plugins
//!
//! These plugins demonstrate the power of the plugin system.
//! Each one is a masterpiece of extensibility and performance.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

pub mod docker;
pub mod kubernetes;
pub mod prometheus;

use crate::mcp_manager::plugin::{Plugin, PluginMetadata, Capability};

/// Create all built-in plugins
pub fn create_builtin_plugins() -> Vec<Box<dyn Plugin>> {
    vec![
        Box::new(docker::DockerPlugin::new()),
        Box::new(kubernetes::KubernetesPlugin::new()),
        Box::new(prometheus::PrometheusPlugin::new()),
    ]
}

/// Get metadata for all built-in plugins
pub fn builtin_metadata() -> Vec<PluginMetadata> {
    vec![
        docker::DockerPlugin::metadata(),
        kubernetes::KubernetesPlugin::metadata(),
        prometheus::PrometheusPlugin::metadata(),
    ]
}