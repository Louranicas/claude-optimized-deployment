#!/bin/bash
# Build script for MCP Rust Core

set -e

echo "Building MCP Rust Core..."

# Install dependencies if needed
if ! command -v maturin &> /dev/null; then
    echo "Installing maturin..."
    pip install maturin
fi

# Build in release mode
echo "Building release version..."
maturin build --release

# Run tests
echo "Running Rust tests..."
cargo test --release

# Run benchmarks
echo "Running benchmarks..."
cargo bench

# Build Python wheel
echo "Building Python wheel..."
maturin develop --release

echo "Build complete!"
echo ""
echo "To use from Python:"
echo "  import mcp_rust_core"
echo ""
echo "To run Python tests:"
echo "  python ../test_rust_core.py"