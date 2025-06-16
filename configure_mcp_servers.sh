#!/bin/bash

# MCP Server Configuration Script
# This script helps configure and test all MCP servers

set -e

CONFIG_FILE="$HOME/.config/claude/mcp.json"

echo "🚀 MCP Server Configuration Tool"
echo "================================"
echo ""

# Function to update JSON config
update_config() {
    local server=$1
    local key=$2
    local value=$3
    
    if command -v jq &> /dev/null; then
        jq ".mcpServers[\"$server\"].env[\"$key\"] = \"$value\"" "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
        echo "✅ Updated $server with $key"
    else
        echo "❌ jq is required. Install with: sudo apt-get install jq"
        exit 1
    fi
}

# Function to test server availability
test_server() {
    local server=$1
    echo -n "Testing $server... "
    
    # Check if npx can find the package
    if npx -y $2 --version &> /dev/null || npx -y $2 --help &> /dev/null; then
        echo "✅ Available"
        return 0
    else
        echo "❌ Not available"
        return 1
    fi
}

echo "📋 Current MCP Configuration:"
echo "============================"
cat "$CONFIG_FILE" | jq '.'
echo ""

echo "🔧 Configuring API Keys and Credentials"
echo "======================================"
echo ""

# GitHub Token
echo "1. GitHub Token Configuration"
echo "   - Go to: https://github.com/settings/tokens"
echo "   - Generate a new token with 'repo' scope"
read -p "   Enter GitHub token (or press Enter to skip): " GITHUB_TOKEN
if [ ! -z "$GITHUB_TOKEN" ]; then
    update_config "github" "GITHUB_TOKEN" "$GITHUB_TOKEN"
fi
echo ""

# Slack Bot Token
echo "2. Slack Bot Token Configuration"
echo "   - Go to: https://api.slack.com/apps"
echo "   - Create an app and get bot token"
read -p "   Enter Slack bot token (or press Enter to skip): " SLACK_TOKEN
if [ ! -z "$SLACK_TOKEN" ]; then
    update_config "slack" "SLACK_BOT_TOKEN" "$SLACK_TOKEN"
fi
echo ""

# PostgreSQL Configuration
echo "3. PostgreSQL Configuration"
echo "   Current: postgresql://user:password@localhost:5432/claude_deployment"
read -p "   Enter PostgreSQL URL (or press Enter to keep default): " PG_URL
if [ ! -z "$PG_URL" ]; then
    update_config "postgres" "POSTGRES_URL" "$PG_URL"
fi
echo ""

# OpenWeather API Key
echo "4. OpenWeather API Configuration"
echo "   - Go to: https://openweathermap.org/api"
echo "   - Sign up for free API key"
read -p "   Enter OpenWeather API key (or press Enter to skip): " WEATHER_KEY
if [ ! -z "$WEATHER_KEY" ]; then
    update_config "weather" "OPENWEATHER_API_KEY" "$WEATHER_KEY"
fi
echo ""

# Anthropic API Key
echo "5. Anthropic API Configuration"
echo "   - Go to: https://console.anthropic.com/"
echo "   - Get your API key"
read -p "   Enter Anthropic API key (or press Enter to skip): " ANTHROPIC_KEY
if [ ! -z "$ANTHROPIC_KEY" ]; then
    update_config "anthropic" "ANTHROPIC_API_KEY" "$ANTHROPIC_KEY"
fi
echo ""

echo "🧪 Testing MCP Servers"
echo "===================="
echo ""

# Test each server
test_server "filesystem" "@modelcontextprotocol/server-filesystem"
test_server "brave-search" "@modelcontextprotocol/server-brave-search"
test_server "github" "@modelcontextprotocol/server-github"
test_server "postgres" "@modelcontextprotocol/server-postgres"
test_server "memory" "@modelcontextprotocol/server-memory"
test_server "slack" "@modelcontextprotocol/server-slack"
test_server "puppeteer" "@modelcontextprotocol/server-puppeteer"
test_server "desktop-commander" "@wonderwhy-er/desktop-commander"
test_server "git" "@modelcontextprotocol/server-git"
test_server "sqlite" "@modelcontextprotocol/server-sqlite"
test_server "time" "@modelcontextprotocol/server-time"
test_server "fetch" "@modelcontextprotocol/server-fetch"

echo ""
echo "📁 Creating necessary directories"
echo "================================"

# Create data directory for SQLite
mkdir -p "$HOME/projects/claude-optimized-deployment/data"
echo "✅ Created data directory for SQLite"

echo ""
echo "🎯 Final Configuration"
echo "===================="
cat "$CONFIG_FILE" | jq '.' | head -50
echo ""

echo "✅ MCP Server configuration complete!"
echo ""
echo "Next steps:"
echo "1. Restart Claude Code to load the new configuration"
echo "2. Run 'claude mcp' to verify all servers are loaded"
echo "3. Test individual servers in Claude Code"
echo ""
echo "Available MCP servers:"
echo "- filesystem: File system operations"
echo "- brave-search: Web search via Brave"
echo "- github: GitHub repository interactions"
echo "- postgres: PostgreSQL database access"
echo "- memory: Persistent memory storage"
echo "- slack: Slack workspace integration"
echo "- puppeteer: Web automation"
echo "- desktop-commander: Desktop control"
echo "- git: Git operations"
echo "- sqlite: SQLite database access"
echo "- time: Time and date utilities"
echo "- fetch: HTTP requests"
echo ""
echo "For detailed usage, see: MCP_SETUP_GUIDE.md"