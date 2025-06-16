#!/bin/bash
# Build and run the MCP V2 demo example

cd "$(dirname "$0")/.."

echo "🦀 MCP V2 Actor-Based Architecture Demo"
echo "======================================"
echo ""
echo "This demo showcases:"
echo "• Zero-lock message passing between actors"
echo "• Concurrent server management"  
echo "• Health monitoring actors"
echo "• Performance metrics collection"
echo "• Graceful failure handling"
echo ""

# Check if we're in a workspace or standalone
if [ -f "../Cargo.toml" ] && grep -q "workspace" ../Cargo.toml 2>/dev/null; then
    echo "📦 Building as part of workspace..."
    cd ..
    cargo build --example mcp_v2_demo --package mcp_launcher_rust 2>/dev/null || {
        echo "⚠️  Workspace build failed, trying standalone build..."
        cd mcp_launcher_rust
        cargo build --example mcp_v2_demo
    }
    cargo run --example mcp_v2_demo --package mcp_launcher_rust
else
    echo "📦 Building standalone..."
    cargo build --example mcp_v2_demo
    cargo run --example mcp_v2_demo
fi