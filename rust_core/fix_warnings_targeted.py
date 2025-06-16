#!/usr/bin/env python3
"""
Fix Rust warnings in rust_core by removing unused imports and fixing deprecated code.
"""

import os
import re
import subprocess
from pathlib import Path

def get_warnings():
    """Get all warnings from cargo build."""
    result = subprocess.run(
        ["cargo", "build", "-p", "code_rust_core"],
        cwd="/home/louranicas/projects/claude-optimized-deployment",
        capture_output=True,
        text=True
    )
    
    warnings = []
    lines = result.stderr.split('\n')
    
    i = 0
    while i < len(lines):
        if 'warning:' in lines[i]:
            warning = {'message': lines[i]}
            
            # Get file and line info
            if i + 1 < len(lines) and '-->' in lines[i + 1]:
                match = re.match(r'\s*-->\s*(.+):(\d+):(\d+)', lines[i + 1])
                if match:
                    warning['file'] = match.group(1)
                    warning['line'] = int(match.group(2))
                    warning['column'] = int(match.group(3))
            
            # Get the actual code line
            if i + 3 < len(lines) and '|' in lines[i + 3]:
                warning['code'] = lines[i + 3].strip()
            
            warnings.append(warning)
        i += 1
    
    return warnings

def fix_unused_import(file_path, line_num, import_name):
    """Remove an unused import from a file."""
    rust_core_path = Path("/home/louranicas/projects/claude-optimized-deployment/rust_core")
    full_path = rust_core_path / file_path.replace("rust_core/", "")
    
    if not full_path.exists():
        print(f"File not found: {full_path}")
        return False
    
    with open(full_path, 'r') as f:
        lines = f.readlines()
    
    if line_num <= len(lines):
        line = lines[line_num - 1]
        
        # Handle different import patterns
        if f"use {import_name};" in line:
            # Simple import: use foo;
            lines[line_num - 1] = ""
        elif f", {import_name}" in line:
            # Multiple imports: use foo::{bar, baz, qux};
            line = line.replace(f", {import_name}", "")
            lines[line_num - 1] = line
        elif f"{import_name}, " in line:
            # Multiple imports: use foo::{bar, baz, qux};
            line = line.replace(f"{import_name}, ", "")
            lines[line_num - 1] = line
        elif f"{{{import_name}}}" in line:
            # Single import in braces: use foo::{bar};
            line = re.sub(rf"use\s+.*::\{{{import_name}\}};", "", line)
            lines[line_num - 1] = line
        else:
            # Try to handle more complex cases
            # Check if it's part of a multi-line import
            if '::{' in line and not '}' in line:
                # Start of multi-line import
                j = line_num
                while j < len(lines) and '}' not in lines[j]:
                    if import_name in lines[j]:
                        lines[j] = lines[j].replace(f"{import_name},", "").replace(f", {import_name}", "").replace(import_name, "")
                    j += 1
            else:
                # Try generic removal
                lines[line_num - 1] = line.replace(import_name, "")
        
        # Clean up empty lines or lines with just "use ;"
        lines[line_num - 1] = re.sub(r'^use\s*;\s*$', '', lines[line_num - 1])
        
        with open(full_path, 'w') as f:
            f.writelines(lines)
        
        return True
    
    return False

def fix_deprecated_base64():
    """Fix deprecated base64::encode usage."""
    rust_core_path = Path("/home/louranicas/projects/claude-optimized-deployment/rust_core")
    
    # Find all Rust files
    for rust_file in rust_core_path.rglob("*.rs"):
        content = rust_file.read_text()
        
        if "base64::encode" in content:
            # Replace base64::encode with use base64::Engine
            content = re.sub(
                r'base64::encode\(([^)]+)\)',
                r'base64::engine::general_purpose::STANDARD.encode(\1)',
                content
            )
            
            # Add the import if needed
            if "use base64::Engine" not in content and "base64::engine" in content:
                # Find the last use statement
                lines = content.split('\n')
                last_use_idx = -1
                for i, line in enumerate(lines):
                    if line.strip().startswith('use '):
                        last_use_idx = i
                
                if last_use_idx >= 0:
                    lines.insert(last_use_idx + 1, "use base64::Engine;")
                    content = '\n'.join(lines)
            
            rust_file.write_text(content)

def main():
    print("Analyzing warnings...")
    warnings = get_warnings()
    
    # Group warnings by type
    unused_imports = []
    deprecated = []
    other = []
    
    for w in warnings:
        if 'unused import' in w['message']:
            # Extract import name
            match = re.search(r'unused import:\s*`([^`]+)`', w['message'])
            if match and 'file' in w:
                w['import_name'] = match.group(1)
                unused_imports.append(w)
        elif 'deprecated' in w['message']:
            deprecated.append(w)
        else:
            other.append(w)
    
    print(f"Found {len(unused_imports)} unused imports")
    print(f"Found {len(deprecated)} deprecated usages")
    print(f"Found {len(other)} other warnings")
    
    # Fix unused imports
    fixed_count = 0
    for w in unused_imports:
        if fix_unused_import(w['file'], w['line'], w['import_name']):
            fixed_count += 1
    
    print(f"Fixed {fixed_count} unused imports")
    
    # Fix deprecated base64 usage
    fix_deprecated_base64()
    print("Fixed deprecated base64 usage")
    
    # Run cargo fmt to clean up
    subprocess.run(
        ["cargo", "fmt", "-p", "code_rust_core"],
        cwd="/home/louranicas/projects/claude-optimized-deployment"
    )
    
    print("Done! Run cargo build to see remaining warnings.")

if __name__ == "__main__":
    main()