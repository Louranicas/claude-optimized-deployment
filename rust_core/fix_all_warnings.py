#!/usr/bin/env python3
"""
Fix all remaining warnings in rust_core.
"""

import os
import re
import subprocess
from pathlib import Path

# Additional warnings to fix
ADDITIONAL_FIXES = [
    # Synthex module
    ("rust_core/src/synthex/query_parser.rs", 7, "HashSet"),
    ("rust_core/src/synthex/parallel_executor.rs", 5, "tokio::task::JoinSet"),
    ("rust_core/src/synthex/result_aggregator.rs", 4, "crate::synthex::query::SubQuery"),
    ("rust_core/src/synthex/result_aggregator.rs", 8, "std::cmp::Ordering"),
    ("rust_core/src/synthex/mcp_v2.rs", 6, "Buf"),
    ("rust_core/src/synthex/mcp_v2.rs", 6, "BufMut"),
    ("rust_core/src/synthex/mcp_v2.rs", 13, "mpsc"),
    ("rust_core/src/synthex/agents/web_agent.rs", 4, "crate::synthex::query::SubQuery"),
    ("rust_core/src/synthex/agents/web_agent.rs", 10, "regex::Regex"),
    ("rust_core/src/synthex/agents/web_agent.rs", 13, "Serialize"),
    ("rust_core/src/synthex/agents/web_agent.rs", 13, "Deserialize"),
    ("rust_core/src/synthex/agents/database_agent.rs", 4, "crate::synthex::query::SubQuery"),
    ("rust_core/src/synthex/agents/api_agent.rs", 4, "crate::synthex::query::SubQuery"),
    ("rust_core/src/synthex/agents/file_agent.rs", 4, "crate::synthex::query::SubQuery"),
    ("rust_core/src/synthex/agents/knowledge_base_agent.rs", 4, "crate::synthex::query::SubQuery"),
    ("rust_core/src/synthex/agents/knowledge_base_agent.rs", 5, "std::path::Path"),
    ("rust_core/src/synthex/agents/mod.rs", 13, "crate::synthex::query::SubQuery"),
    ("rust_core/src/synthex/knowledge_graph.rs", 3, "crate::synthex::query::SubQuery"),
    ("rust_core/src/synthex/engine.rs", 6, "AgentType"),
    ("rust_core/src/synthex/engine.rs", 8, "QueryOptions"),
    ("rust_core/src/synthex/engine.rs", 9, "SearchItem"),
    ("rust_core/src/synthex/engine.rs", 16, "DateTime"),
    ("rust_core/src/synthex/engine.rs", 19, "serde_json::json"),
    ("rust_core/src/synthex/service.rs", 7, "SynthexStats"),
    ("rust_core/src/synthex/service.rs", 13, "serde_json::json"),
    ("rust_core/src/synthex/mod.rs", 22, "tokio::sync::RwLock"),
    ("rust_core/src/synthex/mod.rs", 144, "crate::synthex::query::SubQuery"),
    # MCP Manager
    ("rust_core/src/mcp_manager/deployment.rs", 4, "DeploymentConfig"),
    ("rust_core/src/mcp_manager/deployment.rs", 7, "ServerState"),
    ("rust_core/src/mcp_manager/metrics.rs", 5, "Counter"),
    ("rust_core/src/mcp_manager/metrics.rs", 5, "CounterVec"),
    ("rust_core/src/mcp_manager/metrics.rs", 5, "Gauge"),
    ("rust_core/src/mcp_manager/metrics.rs", 5, "Histogram"),
    ("rust_core/src/mcp_manager/metrics.rs", 6, "IntCounter"),
    ("rust_core/src/mcp_manager/metrics.rs", 6, "IntGauge"),
    ("rust_core/src/mcp_manager/async_traits.rs", 6, "std::pin::Pin"),
    ("rust_core/src/mcp_manager/launcher.rs", 14, "std::env"),
    ("rust_core/src/mcp_manager/plugin/traits.rs", 14, "PluginError"),
    ("rust_core/src/mcp_manager/plugin/registry.rs", 14, "debug"),
    ("rust_core/src/mcp_manager/plugin/registry.rs", 14, "error"),
    ("rust_core/src/mcp_manager/plugin/registry.rs", 14, "warn"),
    ("rust_core/src/mcp_manager/plugin/loader.rs", 13, "debug"),
    ("rust_core/src/mcp_manager/plugin/lifecycle.rs", 10, "mpsc"),
    ("rust_core/src/mcp_manager/plugin/lifecycle.rs", 10, "oneshot"),
    ("rust_core/src/mcp_manager/plugin/lifecycle.rs", 12, "debug"),
    ("rust_core/src/mcp_manager/plugin/lifecycle.rs", 12, "warn"),
    ("rust_core/src/mcp_manager/plugin/lifecycle.rs", 17, "HotReloadable"),
    ("rust_core/src/mcp_manager/plugin/lifecycle.rs", 17, "Configurable"),
    ("rust_core/src/mcp_manager/plugin/discovery.rs", 13, "debug"),
    ("rust_core/src/mcp_manager/plugin/discovery.rs", 429, "std::collections::HashMap"),
    ("rust_core/src/mcp_manager/plugin/capabilities.rs", 12, "VersionReq"),
    ("rust_core/src/mcp_manager/plugin/negotiation.rs", 8, "HashSet"),
    ("rust_core/src/mcp_manager/plugin/negotiation.rs", 13, "Version"),
    ("rust_core/src/mcp_manager/plugin/negotiation.rs", 14, "debug"),
]

def fix_import(file_path, line_num, import_name):
    """Fix a specific unused import."""
    full_path = Path("/home/louranicas/projects/claude-optimized-deployment") / file_path
    
    if not full_path.exists():
        print(f"File not found: {full_path}")
        return False
    
    try:
        lines = full_path.read_text().split('\n')
        
        if line_num <= len(lines):
            line = lines[line_num - 1]
            original_line = line
            
            # Handle different import patterns
            if f"use {import_name};" in line:
                lines[line_num - 1] = ""
            elif f", {import_name}," in line:
                line = line.replace(f", {import_name},", ",")
                lines[line_num - 1] = line
            elif f", {import_name}" in line and line.endswith(";"):
                line = line.replace(f", {import_name}", "")
                lines[line_num - 1] = line
            elif f"{{{import_name}," in line:
                line = line.replace(f"{{{import_name},", "{")
                lines[line_num - 1] = line
            elif f", {import_name}}}" in line:
                line = line.replace(f", {import_name}}}", "}")
                lines[line_num - 1] = line
            elif f"::{import_name}" in line:
                # Check if it's part of a larger import
                if "::{" in line and "}" in line:
                    # Multiple imports in braces
                    line = re.sub(rf'\b{re.escape(import_name)}\b,?\s*', '', line)
                    line = re.sub(r',\s*}', '}', line)
                    line = re.sub(r'{\s*,', '{', line)
                    line = re.sub(r',\s*,', ',', line)
                    lines[line_num - 1] = line
                else:
                    # Direct import
                    lines[line_num - 1] = ""
            else:
                # Generic pattern matching
                line = re.sub(rf'\b{re.escape(import_name)}\b,?\s*', '', line)
                line = re.sub(r',\s*}', '}', line)
                line = re.sub(r',\s*;', ';', line)
                line = re.sub(r'{\s*}', '', line)  # Remove empty braces
                lines[line_num - 1] = line
            
            # Clean up empty use statements
            if lines[line_num - 1].strip() in ["use ;", "use {};", "use"]:
                lines[line_num - 1] = ""
            
            # Write back
            full_path.write_text('\n'.join(lines))
            
            if lines[line_num - 1] != original_line:
                print(f"Fixed: {file_path}:{line_num} - removed {import_name}")
                return True
        
    except Exception as e:
        print(f"Error fixing {file_path}:{line_num} - {e}")
    
    return False

def fix_unused_variables():
    """Fix unused variable warnings."""
    files_with_unused_vars = [
        ("rust_core/src/synthex/agents/web_agent.rs", "context", "_context"),
        ("rust_core/src/synthex/agents/database_agent.rs", "context", "_context"),
        ("rust_core/src/synthex/agents/api_agent.rs", "context", "_context"),
        ("rust_core/src/synthex/agents/file_agent.rs", "context", "_context"),
        ("rust_core/src/synthex/agents/knowledge_base_agent.rs", "context", "_context"),
        ("rust_core/src/synthex/python_bindings.rs", "py", "_py"),
    ]
    
    for file_path, old_var, new_var in files_with_unused_vars:
        full_path = Path("/home/louranicas/projects/claude-optimized-deployment") / file_path
        if full_path.exists():
            content = full_path.read_text()
            # Match variable in function parameters
            content = re.sub(rf'\b{old_var}\b(?=\s*:)', new_var, content)
            full_path.write_text(content)
            print(f"Fixed unused variable {old_var} -> {new_var} in {file_path}")

def fix_unused_macros():
    """Remove unused macro definitions."""
    file_path = Path("/home/louranicas/projects/claude-optimized-deployment/rust_core/src/synthex/agents/file_agent.rs")
    if file_path.exists():
        lines = file_path.read_text().split('\n')
        new_lines = []
        skip_macro = False
        
        for line in lines:
            if "macro_rules! hashmap" in line:
                skip_macro = True
            elif skip_macro and line.strip() == "}":
                skip_macro = False
                continue
            
            if not skip_macro:
                new_lines.append(line)
        
        file_path.write_text('\n'.join(new_lines))
        print("Removed unused hashmap macro from file_agent.rs")

def fix_mutable_warnings():
    """Fix unnecessary mutable warnings."""
    fixes = [
        ("rust_core/src/synthex/engine.rs", "let mut agent_responses", "let agent_responses"),
        ("rust_core/src/synthex/service.rs", "let mut agents", "let agents"),
    ]
    
    for file_path, old_code, new_code in fixes:
        full_path = Path("/home/louranicas/projects/claude-optimized-deployment") / file_path
        if full_path.exists():
            content = full_path.read_text()
            if old_code in content:
                content = content.replace(old_code, new_code)
                full_path.write_text(content)
                print(f"Fixed unnecessary mutable in {file_path}")

def fix_sbg_error_imports():
    """Fix unused SBGError imports."""
    files = [
        "rust_core/src/synthex/bashgod/actor.rs",
        "rust_core/src/synthex/bashgod/command_generator.rs",
        "rust_core/src/synthex/bashgod/hybrid_memory.rs",
        "rust_core/src/synthex/bashgod/learning_engine.rs",
        "rust_core/src/synthex/bashgod/mod.rs",
        "rust_core/src/synthex/bashgod/mcp_integration.rs",
        "rust_core/src/synthex/bashgod/pattern_matcher.rs",
        "rust_core/src/synthex/bashgod/tensor_memory.rs",
    ]
    
    for file_path in files:
        full_path = Path("/home/louranicas/projects/claude-optimized-deployment") / file_path
        if full_path.exists():
            lines = full_path.read_text().split('\n')
            new_lines = []
            
            for line in lines:
                if "SBGError" in line and "use" in line:
                    # Remove or comment out the import
                    if ", SBGError" in line:
                        line = line.replace(", SBGError", "")
                    elif "SBGError," in line:
                        line = line.replace("SBGError,", "")
                    elif "use crate::synthex::bashgod::SBGError;" in line:
                        continue  # Skip this line entirely
                
                new_lines.append(line)
            
            full_path.write_text('\n'.join(new_lines))
            print(f"Fixed SBGError import in {file_path}")

def fix_plugin_imports():
    """Fix unused Plugin imports."""
    files = [
        "rust_core/src/mcp_manager/plugin/traits.rs",
        "rust_core/src/mcp_manager/plugin/handle.rs",
        "rust_core/src/mcp_manager/plugin/lifecycle.rs",
        "rust_core/src/mcp_manager/plugin/negotiation.rs",
    ]
    
    for file_path in files:
        full_path = Path("/home/louranicas/projects/claude-optimized-deployment") / file_path
        if full_path.exists():
            content = full_path.read_text()
            # Remove Plugin from imports
            content = re.sub(r'\bPlugin,?\s*', '', content)
            content = re.sub(r',\s*Plugin\b', '', content)
            full_path.write_text(content)
            print(f"Fixed Plugin import in {file_path}")

def main():
    print("Fixing all warnings in rust_core...")
    
    # Fix additional imports
    fixed_count = 0
    for file_path, line_num, import_name in ADDITIONAL_FIXES:
        if fix_import(file_path, line_num, import_name):
            fixed_count += 1
    
    print(f"\nFixed {fixed_count} unused imports")
    
    # Fix unused variables
    fix_unused_variables()
    
    # Fix unused macros
    fix_unused_macros()
    
    # Fix mutable warnings
    fix_mutable_warnings()
    
    # Fix SBGError imports
    fix_sbg_error_imports()
    
    # Fix Plugin imports
    fix_plugin_imports()
    
    # Run cargo fmt
    print("\nRunning cargo fmt...")
    subprocess.run(
        ["cargo", "fmt", "-p", "code_rust_core"],
        cwd="/home/louranicas/projects/claude-optimized-deployment"
    )
    
    print("\nDone! Run 'cargo build -p code_rust_core' to check remaining warnings.")

if __name__ == "__main__":
    main()