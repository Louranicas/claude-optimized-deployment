#!/bin/bash

# Fix unused imports and variables in rust_core

echo "Fixing Rust warnings in rust_core..."

# First, let's use cargo fix to automatically fix what it can
cd /home/louranicas/projects/claude-optimized-deployment
cargo fix -p code_rust_core --allow-dirty --allow-staged 2>&1

# Count remaining warnings
WARNINGS_BEFORE=$(cargo build -p code_rust_core 2>&1 | grep -E "warning:" | wc -l)
echo "Warnings before manual fixes: $WARNINGS_BEFORE"

# Get detailed warning information
cargo build -p code_rust_core 2>&1 | grep -E "warning:|-->" | grep -B1 "unused import" > /tmp/unused_imports.txt

# Run clippy with auto-fix
cargo clippy -p code_rust_core --fix --allow-dirty --allow-staged 2>&1

# Count warnings after fixes
WARNINGS_AFTER=$(cargo build -p code_rust_core 2>&1 | grep -E "warning:" | wc -l)
echo "Warnings after fixes: $WARNINGS_AFTER"

echo "Fixed $(($WARNINGS_BEFORE - $WARNINGS_AFTER)) warnings"