#!/bin/bash
# Build script for Rust Python bindings

set -e

echo "🦀 Building Rust MCP Manager Python bindings..."

# Change to project root
cd "$(dirname "$0")/.."

# Install maturin if not already installed
if ! command -v maturin &> /dev/null; then
    echo "📦 Installing maturin..."
    pip install maturin
fi

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf target/wheels

# Build the bindings
echo "🔨 Building with maturin..."
maturin develop --manifest-path rust_core/Cargo.toml --release

# Run tests
echo "🧪 Running binding tests..."
python test_mcp_bindings.py

if [ $? -eq 0 ]; then
    echo "✅ Build successful! MCP Manager Python bindings are ready to use."
    echo ""
    echo "Example usage:"
    echo "  from claude_optimized_deployment_rust import mcp_manager"
    echo "  manager = mcp_manager.PyMcpManager()"
    echo ""
    echo "Run the example:"
    echo "  python examples/mcp_manager_python_example.py"
else
    echo "❌ Build or tests failed. Please check the errors above."
    exit 1
fi