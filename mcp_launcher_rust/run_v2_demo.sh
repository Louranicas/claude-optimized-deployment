#!/bin/bash
# Script to run the MCP V2 Actor Demo

echo "🚀 Running MCP V2 Actor-Based Demo"
echo "=================================="

# Compile the example
echo "📦 Compiling example..."
rustc --edition=2021 \
  examples/mcp_v2_demo.rs \
  --extern tokio=$(find ~/.cargo/registry -name "libtokio*.rlib" | head -1) \
  --extern serde=$(find ~/.cargo/registry -name "libserde-*.rlib" | grep -v derive | head -1) \
  --extern tracing=$(find ~/.cargo/registry -name "libtracing-*.rlib" | head -1) \
  -L dependency=$(find ~/.cargo/registry -type d -name "deps" | head -1) \
  -o mcp_v2_demo_bin

if [ $? -eq 0 ]; then
  echo "✅ Compilation successful!"
  echo ""
  echo "🎬 Running demo..."
  echo ""
  ./mcp_v2_demo_bin
  rm -f mcp_v2_demo_bin
else
  echo "❌ Compilation failed"
  echo ""
  echo "To run this demo, ensure you have the required dependencies:"
  echo "  cargo add tokio --features full"
  echo "  cargo add serde --features derive" 
  echo "  cargo add tracing"
  echo "  cargo add tracing-subscriber"
fi