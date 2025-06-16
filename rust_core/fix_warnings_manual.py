#!/usr/bin/env python3
"""
Manually fix Rust warnings by parsing and removing unused imports.
"""

import os
import re
import subprocess
from pathlib import Path

def remove_unused_imports():
    """Remove unused imports from rust_core files."""
    
    # Get build output with warnings
    result = subprocess.run(
        ["cargo", "build", "-p", "code_rust_core", "2>&1", "|", "grep", "-A2", "warning:", "|", "head", "-500"],
        shell=True,
        cwd="/home/louranicas/projects/claude-optimized-deployment",
        capture_output=True,
        text=True
    )
    
    warnings_to_fix = [
        # Format: (file_path, line, import_name)
        ("rust_core/src/infrastructure.rs", 17, "crate::async_helpers::py_run_async"),
        ("rust_core/src/performance.rs", 14, "CoreResult"),
        ("rust_core/src/security.rs", 18, "CoreResult"),
        ("rust_core/src/security_enhanced.rs", 15, "Sha256"),
        ("rust_core/src/security_enhanced.rs", 15, "Sha512"),
        ("rust_core/src/security_enhanced.rs", 16, "Hmac"),
        ("rust_core/src/security_enhanced.rs", 21, "Argon2"),
        ("rust_core/src/security_enhanced.rs", 21, "PasswordHash"),
        ("rust_core/src/security_enhanced.rs", 21, "PasswordHasher"),
        ("rust_core/src/security_enhanced.rs", 21, "PasswordVerifier"),
        ("rust_core/src/security_enhanced.rs", 22, "argon2::password_hash::SaltString"),
        ("rust_core/src/security_enhanced.rs", 27, "std::process::Command"),
        ("rust_core/src/security_enhanced.rs", 35, "CoreResult"),
        ("rust_core/src/python_bindings.rs", 5, "pyo3::prelude::*"),
        ("rust_core/src/circle_of_experts/consensus.rs", 18, "simd_sum_f32"),
        ("rust_core/src/circle_of_experts/python_bindings.rs", 15, "ConsensusResult"),
        ("rust_core/src/circle_of_experts/python_bindings.rs", 201, "crate::circle_of_experts::consensus::*"),
        ("rust_core/src/adaptive_learning.rs", 10, "PyArray1"),
        ("rust_core/src/adaptive_learning.rs", 10, "PyArray2"),
        ("rust_core/src/async_helpers.rs", 9, "std::sync::Arc"),
        ("rust_core/src/async_helpers.rs", 10, "futures::future::BoxFuture"),
        ("rust_core/src/memory_mapped.rs", 18, "std::path::Path"),
        ("rust_core/src/simd_ops.rs", 18, "std::arch::x86_64::*"),
        ("rust_core/src/zero_copy_net.rs", 22, "Bytes"),
        ("rust_core/src/zero_copy_net.rs", 23, "Socket"),
        ("rust_core/src/zero_copy_net.rs", 23, "Domain"),
        ("rust_core/src/zero_copy_net.rs", 23, "Type"),
        ("rust_core/src/zero_copy_net.rs", 23, "Protocol"),
        ("rust_core/src/zero_copy_net.rs", 24, "SocketAddr"),
        ("rust_core/src/zero_copy_net.rs", 24, "IpAddr"),
        ("rust_core/src/zero_copy_net.rs", 24, "Ipv4Addr"),
        ("rust_core/src/zero_copy_net.rs", 26, "crossbeam::channel"),
        ("rust_core/src/lockfree_collections.rs", 17, "AtomicPtr"),
        ("rust_core/src/lockfree_collections.rs", 19, "std::ptr"),
        ("rust_core/src/lockfree_collections.rs", 21, "self"),
        ("rust_core/src/lockfree_collections.rs", 21, "Atomic"),
        ("rust_core/src/lockfree_collections.rs", 21, "Owned"),
        ("rust_core/src/lockfree_collections.rs", 21, "Shared"),
        ("rust_core/src/lockfree_collections.rs", 21, "Guard"),
        ("rust_core/src/lockfree_collections.rs", 29, "CoreResult"),
        ("rust_core/src/orchestrator/engine.rs", 11, "std::collections::HashMap"),
        ("rust_core/src/orchestrator/engine.rs", 13, "Mutex"),
        ("rust_core/src/orchestrator/engine.rs", 15, "warn"),
        ("rust_core/src/orchestrator/scheduler.rs", 11, "interval"),
        ("rust_core/src/orchestrator/scheduler.rs", 11, "Duration"),
        ("rust_core/src/orchestrator/scheduler.rs", 12, "info"),
        ("rust_core/src/orchestrator/scheduler.rs", 12, "warn"),
        ("rust_core/src/orchestrator/executor.rs", 11, "Mutex"),
        ("rust_core/src/orchestrator/mod.rs", 14, "std::sync::Arc"),
        ("rust_core/src/orchestrator/mod.rs", 15, "tokio::sync::RwLock"),
        ("rust_core/src/orchestrator/mod.rs", 16, "dashmap::DashMap"),
        ("rust_core/src/services/registry.rs", 12, "info"),
        ("rust_core/src/services/registry.rs", 12, "warn"),
        ("rust_core/src/services/health_check.rs", 7, "ServiceMetadata"),
        ("rust_core/src/services/health_check.rs", 12, "warn"),
        ("rust_core/src/services/health_check.rs", 12, "error"),
        ("rust_core/src/services/lifecycle.rs", 7, "ServiceMetadata"),
        ("rust_core/src/services/lifecycle.rs", 10, "mpsc"),
        ("rust_core/src/services/lifecycle.rs", 12, "error"),
        ("rust_core/src/resources/cpu_manager.rs", 9, "warn"),
        ("rust_core/src/resources/memory_manager.rs", 9, "error"),
        ("rust_core/src/resources/mod.rs", 11, "tokio::sync::RwLock"),
        ("rust_core/src/network/port_allocator.rs", 9, "warn"),
        ("rust_core/src/network/mod.rs", 11, "Ipv4Addr"),
        ("rust_core/src/network/mod.rs", 12, "tokio::sync::RwLock"),
        ("rust_core/src/reliability/circuit_breaker.rs", 9, "debug"),
    ]
    
    for file_path, line_num, import_name in warnings_to_fix:
        fix_import(file_path, line_num, import_name)

def fix_import(file_path, line_num, import_name):
    """Fix a specific unused import."""
    full_path = Path("/home/louranicas/projects/claude-optimized-deployment") / file_path
    
    if not full_path.exists():
        print(f"File not found: {full_path}")
        return
    
    lines = full_path.read_text().split('\n')
    
    if line_num <= len(lines):
        line = lines[line_num - 1]
        
        # Handle different import patterns
        if f"use {import_name};" in line:
            # Simple case: entire line is the import
            lines[line_num - 1] = ""
        elif f"::{{{import_name}}}" in line:
            # Single import in braces: use foo::{bar};
            lines[line_num - 1] = ""
        elif f"{{{import_name}," in line or f", {import_name}" in line or f", {import_name}," in line:
            # Multiple imports in braces
            # Remove the specific import
            line = line.replace(f"{import_name}, ", "")
            line = line.replace(f", {import_name}", "")
            line = line.replace(f"{{{import_name},", "{{")
            line = line.replace(f",{import_name}}}", "}}")
            
            # Clean up empty braces
            line = re.sub(r'use\s+[^:]+::\{\s*\};', '', line)
            lines[line_num - 1] = line
        elif f"::{import_name}" in line:
            # Direct import: use foo::bar;
            # Check if it's the only import
            if line.count("::") == 1:
                lines[line_num - 1] = ""
            else:
                # Multiple :: means complex path, be careful
                line = line.replace(f"::{import_name}", "")
                lines[line_num - 1] = line
        else:
            # Complex case - try generic removal
            line = re.sub(rf'\b{re.escape(import_name)}\b,?\s*', '', line)
            # Clean up trailing commas
            line = re.sub(r',\s*}', '}', line)
            line = re.sub(r',\s*;', ';', line)
            lines[line_num - 1] = line
        
        # Write back
        full_path.write_text('\n'.join(lines))
        print(f"Fixed: {file_path}:{line_num} - removed {import_name}")

def fix_deprecated_base64():
    """Fix deprecated base64::encode calls."""
    rust_core = Path("/home/louranicas/projects/claude-optimized-deployment/rust_core")
    
    for rust_file in rust_core.rglob("*.rs"):
        if "target" in str(rust_file):
            continue
            
        content = rust_file.read_text()
        
        if "base64::encode" in content:
            # Add import
            if "use base64::Engine;" not in content:
                lines = content.split('\n')
                # Find last use statement
                last_use = -1
                for i, line in enumerate(lines):
                    if line.strip().startswith("use "):
                        last_use = i
                
                if last_use >= 0:
                    lines.insert(last_use + 1, "use base64::Engine;")
                
                content = '\n'.join(lines)
            
            # Replace calls
            content = re.sub(
                r'base64::encode\(([^)]+)\)',
                r'base64::engine::general_purpose::STANDARD.encode(\1)',
                content
            )
            
            rust_file.write_text(content)
            print(f"Fixed deprecated base64 in: {rust_file}")

def fix_cfg_warnings():
    """Fix unexpected cfg condition warnings."""
    rust_core = Path("/home/louranicas/projects/claude-optimized-deployment/rust_core")
    
    # Files with cfg issues
    files_to_fix = [
        "src/synthex/performance_optimizer.rs",
        "src/synthex/bashgod_optimizer.rs",
    ]
    
    for file_path in files_to_fix:
        full_path = rust_core / file_path
        if full_path.exists():
            content = full_path.read_text()
            
            # Replace feature = "candle" with feature = "ml"
            content = content.replace('feature = "candle"', 'feature = "ml"')
            
            full_path.write_text(content)
            print(f"Fixed cfg conditions in: {file_path}")

def main():
    print("Fixing Rust warnings in rust_core...")
    
    # Fix unused imports
    remove_unused_imports()
    
    # Fix deprecated base64
    fix_deprecated_base64()
    
    # Fix cfg warnings
    fix_cfg_warnings()
    
    print("\nDone! Run 'cargo build -p code_rust_core' to check remaining warnings.")

if __name__ == "__main__":
    main()