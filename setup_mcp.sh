#!/bin/bash

# MCP Setup Script for Claude Code
# This script helps configure MCP servers for Claude Code

set -e

echo "🚀 Claude Code MCP Setup Script"
echo "================================"

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]] || [[ "$OSTYPE" == "darwin"* ]]; then
    CONFIG_DIR="$HOME/.config/claude"
    CONFIG_FILE="$CONFIG_DIR/mcp.json"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
    CONFIG_DIR="$APPDATA/claude"
    CONFIG_FILE="$CONFIG_DIR/mcp.json"
else
    echo "❌ Unsupported OS: $OSTYPE"
    exit 1
fi

# Create config directory if it doesn't exist
echo "📁 Creating configuration directory..."
mkdir -p "$CONFIG_DIR"

# Check if config already exists
if [ -f "$CONFIG_FILE" ]; then
    echo "⚠️  MCP configuration already exists at: $CONFIG_FILE"
    read -p "Do you want to backup and create a new one? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        BACKUP_FILE="$CONFIG_FILE.backup.$(date +%Y%m%d_%H%M%S)"
        cp "$CONFIG_FILE" "$BACKUP_FILE"
        echo "✅ Backed up to: $BACKUP_FILE"
    else
        echo "ℹ️  Keeping existing configuration"
        exit 0
    fi
fi

# Create basic MCP configuration
echo "📝 Creating MCP configuration..."

cat > "$CONFIG_FILE" << 'EOF'
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem"],
      "env": {}
    }
  }
}
EOF

echo "✅ Basic MCP configuration created at: $CONFIG_FILE"

# Ask about additional servers
echo ""
echo "Would you like to configure additional MCP servers?"
echo ""

# Brave Search
read -p "Configure Brave Search? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    read -p "Enter your Brave Search API key (or press Enter to skip): " BRAVE_KEY
    if [ ! -z "$BRAVE_KEY" ]; then
        # Use jq if available, otherwise use sed
        if command -v jq &> /dev/null; then
            jq '.mcpServers["brave-search"] = {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-brave-search"],
                "env": {"BRAVE_API_KEY": "'$BRAVE_KEY'"}
            }' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
        else
            echo "⚠️  jq not found. Please manually add Brave Search configuration."
        fi
    fi
fi

# GitHub
read -p "Configure GitHub integration? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    read -p "Enter your GitHub token (or press Enter to skip): " GITHUB_TOKEN
    if [ ! -z "$GITHUB_TOKEN" ]; then
        if command -v jq &> /dev/null; then
            jq '.mcpServers["github"] = {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-github"],
                "env": {"GITHUB_TOKEN": "'$GITHUB_TOKEN'"}
            }' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
        else
            echo "⚠️  jq not found. Please manually add GitHub configuration."
        fi
    fi
fi

# Display final configuration
echo ""
echo "📋 Final MCP Configuration:"
echo "=========================="
cat "$CONFIG_FILE"
echo ""
echo "=========================="

# Copy example configuration from project if available
if [ -f "mcp_configs/mcp_master_config_20250607_125216.json" ]; then
    echo ""
    echo "ℹ️  Found project-specific MCP configuration"
    read -p "Would you like to see an example with all available servers? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo ""
        cat mcp_configs/mcp_master_config_20250607_125216.json
        echo ""
        echo "ℹ️  You can copy settings from the above example to your config at:"
        echo "   $CONFIG_FILE"
    fi
fi

echo ""
echo "✅ MCP Setup Complete!"
echo ""
echo "Next steps:"
echo "1. Edit $CONFIG_FILE to add more servers or API keys"
echo "2. Restart Claude Code to load the new configuration"
echo "3. Run 'claude mcp' to verify the configuration"
echo ""
echo "For detailed instructions, see: MCP_SETUP_GUIDE.md"