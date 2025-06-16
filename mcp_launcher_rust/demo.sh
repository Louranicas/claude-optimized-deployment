#!/bin/bash
# MCP Launcher Demo Script

echo "🦀 MCP Launcher Demo"
echo "===================="
echo ""

# Check if cargo is installed
if ! command -v cargo &> /dev/null; then
    echo "❌ Cargo not found. Please install Rust first."
    echo "Visit: https://rustup.rs/"
    exit 1
fi

# Setup environment
echo "📝 Setting up environment..."
if [ ! -f .env.mcp ]; then
    cp .env.mcp.example .env.mcp
    echo "✅ Created .env.mcp - please add your API keys"
fi

# Create required directories
mkdir -p data logs

# Build the launcher
echo ""
echo "🔨 Building MCP launcher..."
cargo build --bin mcp_launcher

# Check build status
if [ $? -eq 0 ]; then
    echo "✅ Build successful!"
else
    echo "❌ Build failed. Please check the error messages above."
    exit 1
fi

# Display usage
echo ""
echo "📖 Usage Instructions:"
echo "====================="
echo ""
echo "1. Configure API keys in .env.mcp"
echo "2. Run the launcher:"
echo "   cargo run --bin mcp_launcher"
echo ""
echo "3. Check server status:"
echo "   cargo run --bin mcp_launcher status"
echo ""
echo "4. Stop all servers:"
echo "   cargo run --bin mcp_launcher stop"
echo ""
echo "🎯 Ready to launch MCP servers!"