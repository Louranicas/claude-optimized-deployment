#!/bin/bash
# Build script for Academic MCP Integration

set -e

echo "🔨 Building Academic MCP Integration..."

# Build Rust components
echo "🦀 Building Rust modules..."
cd academic_mcp_rust
maturin build --release
cd ..

# Install Python dependencies
echo "🐍 Installing Python dependencies..."
pip install -r requirements.txt

# Run tests
echo "🧪 Running tests..."
pytest tests/academic_mcp -v

# Build documentation
echo "📚 Building documentation..."
cd docs
make html
cd ..

echo "✅ Build complete!"
