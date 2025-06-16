#!/usr/bin/env python3
"""
Fix remaining warnings in rust_core.
"""

import re
from pathlib import Path

# Map of files and their unused imports
REMAINING_FIXES = {
    "src/synthex/performance_optimizer.rs": [
        "std::hint::black_box",
        "crate::synthex::query_parser::ExecutionPlan", 
        "crate::synthex::SearchResult"
    ],
    "src/synthex/bashgod_optimizer.rs": [
        "tokio::sync::RwLock",
        "LockFreeCommandQueue",
        "SimdPatternMatcher"
    ],
    "src/synthex/bashgod/mod.rs": [
        "AtomicU32", "AtomicU64", "AtomicUsize", "Ordering"
    ],
    "src/synthex/bashgod/mcp_integration.rs": [
        "tokio::sync::RwLock"
    ],
    "src/synthex/python_bindings.rs": [
        "crate::synthex::query::SubQuery"
    ],
    "src/mcp_manager/plugin/traits.rs": [
        "traits::*"
    ],
    "src/mcp_manager/plugin/config.rs": [
        "Error"
    ],
    "src/mcp_manager/plugin/events.rs": [
        "Event"
    ],
    "src/mcp_manager/plugin/registry.rs": [
        "PluginState"
    ],
    "src/mcp_manager/plugin/loader.rs": [
        "Path", "error", "warn"
    ],
    "src/mcp_manager/plugin/security.rs": [
        "Prerelease"
    ],
    "src/mcp_manager/plugin/metrics.rs": [
        "PluginMetadata"
    ],
    "src/mcp_manager/plugin/discovery.rs": [
        "mpsc"
    ],
    "src/mcp_manager/plugin/api/gateway.rs": [
        "bytes::Bytes"
    ],
    "src/mcp_manager/plugin/api/rest.rs": [
        "debug", "error", "info", "warn"
    ],
    "src/mcp_manager/plugin/hot_reload/mod.rs": [
        "error", "warn"
    ],
    "src/mcp_manager/plugin/hot_reload/state.rs": [
        "PluginState", "hot_reload::PreservedState"
    ],
    "src/mcp_manager/plugin/messaging.rs": [
        "Semaphore", "broadcast"
    ],
    "src/mcp_manager/plugin/logging.rs": [
        "BufReader"
    ],
    "src/mcp_manager/plugins/docker.rs": [
        "Config as ContainerConfig", "CreateContainerOptions", "ListContainersOptions",
        "CreateImageOptions", "ListImagesOptions",
        "CreateNetworkOptions", "ListNetworksOptions",
        "CreateVolumeOptions", "ListVolumesOptions",
        "error"
    ],
    "src/mcp_manager/plugins/kubernetes.rs": [
        "PluginDependency", "error", "warn",
        "Config as KubeConfig",
        "DaemonSet", "StatefulSet",
        "CronJob", "Job",
        "Ingress", "NetworkPolicy",
        "ClusterRoleBinding", "ClusterRole", "RoleBinding", "Role",
        "k8s_openapi::api::storage::v1::StorageClass"
    ],
    "src/mcp_manager/plugins/prometheus.rs": [
        "UNIX_EPOCH", "error", "warn"
    ],
    "src/mcp_manager/benchmarks.rs": [
        "Capability",
        "std::sync::Arc",
        "std::collections::hash_map::DefaultHasher"
    ],
    "src/mcp_manager/integration_tests.rs": [
        "Deserialize", "Serialize"
    ],
    "src/mcp_manager/mod.rs": [
        "warn",
        "DeploymentManager", "HealthMonitor", "MetricsCollector",
        "RwLock", "mpsc",
        "PerformanceMetrics"
    ]
}

def fix_unused_import(file_path, import_name):
    """Remove unused import from file."""
    full_path = Path("/home/louranicas/projects/claude-optimized-deployment/rust_core") / file_path
    
    if not full_path.exists():
        print(f"File not found: {full_path}")
        return False
    
    content = full_path.read_text()
    lines = content.split('\n')
    
    modified = False
    new_lines = []
    
    for line in lines:
        original_line = line
        
        # Handle different import patterns
        if f"use {import_name};" in line:
            continue  # Skip this line
        elif f", {import_name}" in line or f"{import_name}," in line:
            line = re.sub(rf',\s*{re.escape(import_name)}', '', line)
            line = re.sub(rf'{re.escape(import_name)}\s*,', '', line)
        elif f"{{{import_name}}}" in line:
            line = re.sub(rf'use\s+[^;]+::\{{{re.escape(import_name)}\}};', '', line)
        elif import_name in line and "use" in line:
            # More complex patterns
            line = re.sub(rf'\b{re.escape(import_name)}\b,?\s*', '', line)
            # Clean up empty braces
            line = re.sub(r'use\s+[^:]+::\{\s*\};', '', line)
            line = re.sub(r',\s*}', '}', line)
            line = re.sub(r'{\s*,', '{', line)
            line = re.sub(r',\s*,', ',', line)
        
        if line != original_line:
            modified = True
            if line.strip() in ["", "use ;", "use {};", "use"]:
                continue  # Skip empty lines
        
        new_lines.append(line)
    
    if modified:
        full_path.write_text('\n'.join(new_lines))
        print(f"Fixed imports in {file_path}")
        return True
    
    return False

def fix_all_warnings():
    """Fix all remaining warnings."""
    total_fixed = 0
    
    for file_path, imports in REMAINING_FIXES.items():
        for import_name in imports:
            if fix_unused_import(file_path, import_name):
                total_fixed += 1
    
    print(f"\nTotal imports fixed: {total_fixed}")

def fix_deprecated_features():
    """Fix any deprecated features."""
    # Fix panic settings in profiles
    cargo_path = Path("/home/louranicas/projects/claude-optimized-deployment/Cargo.toml")
    if cargo_path.exists():
        content = cargo_path.read_text()
        # Remove panic settings from bench and test profiles
        lines = content.split('\n')
        new_lines = []
        skip_panic = False
        
        for i, line in enumerate(lines):
            if "[profile.bench]" in line or "[profile.test]" in line:
                skip_panic = True
            elif skip_panic and line.strip().startswith("panic"):
                continue  # Skip panic line
            elif skip_panic and line.strip() and not line.strip().startswith("#"):
                skip_panic = False
            
            new_lines.append(line)
        
        cargo_path.write_text('\n'.join(new_lines))
        print("Fixed panic settings in Cargo.toml")

def main():
    print("Fixing remaining warnings in rust_core...")
    fix_all_warnings()
    fix_deprecated_features()
    print("\nDone! Run 'cargo build -p code_rust_core' to verify.")

if __name__ == "__main__":
    main()