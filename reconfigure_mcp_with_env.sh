#!/bin/bash

# Reconfigure MCP servers with environment variables

echo "🔄 Reconfiguring MCP servers with credentials..."
echo "=============================================="

# Check if environment variables are loaded
if [ -z "$GITHUB_TOKEN" ] && [ -z "$POSTGRES_URL" ] && [ -z "$SLACK_BOT_TOKEN" ]; then
    echo "⚠️  No environment variables found!"
    echo "   Please run: source .env.mcp"
    echo "   After setting your credentials in .env.mcp"
    exit 1
fi

# Reconfigure GitHub if token is set
if [ ! -z "$GITHUB_TOKEN" ]; then
    echo -e "\n🔧 Reconfiguring GitHub server..."
    claude mcp remove github 2>/dev/null
    if claude mcp add github npx -- -y @modelcontextprotocol/server-github -e GITHUB_TOKEN=$GITHUB_TOKEN; then
        echo "✅ GitHub server configured with token"
    else
        echo "❌ Failed to configure GitHub server"
    fi
else
    echo "⏭️  Skipping GitHub (no token set)"
fi

# Reconfigure PostgreSQL if URL is set
if [ ! -z "$POSTGRES_URL" ]; then
    echo -e "\n🔧 Reconfiguring PostgreSQL server..."
    claude mcp remove postgres 2>/dev/null
    if claude mcp add postgres npx -- -y @modelcontextprotocol/server-postgres -e POSTGRES_URL=$POSTGRES_URL; then
        echo "✅ PostgreSQL server configured with connection string"
    else
        echo "❌ Failed to configure PostgreSQL server"
    fi
else
    echo "⏭️  Skipping PostgreSQL (no URL set)"
fi

# Reconfigure Slack if token is set
if [ ! -z "$SLACK_BOT_TOKEN" ]; then
    echo -e "\n🔧 Reconfiguring Slack server..."
    claude mcp remove slack 2>/dev/null
    if claude mcp add slack npx -- -y @modelcontextprotocol/server-slack -e SLACK_BOT_TOKEN=$SLACK_BOT_TOKEN; then
        echo "✅ Slack server configured with bot token"
    else
        echo "❌ Failed to configure Slack server"
    fi
else
    echo "⏭️  Skipping Slack (no token set)"
fi

# Optional: Configure additional servers if variables are set
if [ ! -z "$OPENAI_API_KEY" ]; then
    echo -e "\n🔧 Adding OpenAI server..."
    claude mcp add openai npx -- -y @modelcontextprotocol/server-openai -e OPENAI_API_KEY=$OPENAI_API_KEY
fi

if [ ! -z "$ANTHROPIC_API_KEY" ]; then
    echo -e "\n🔧 Adding Anthropic server..."
    claude mcp add anthropic npx -- -y @anthropic/mcp-server-anthropic -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY
fi

if [ ! -z "$AWS_ACCESS_KEY_ID" ] && [ ! -z "$AWS_SECRET_ACCESS_KEY" ]; then
    echo -e "\n🔧 Adding AWS server..."
    claude mcp add aws npx -- -y @modelcontextprotocol/server-aws -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY
fi

echo -e "\n📋 Final MCP server list:"
echo "========================"
claude mcp list

echo -e "\n✅ Reconfiguration complete!"
echo "   Restart Claude Code to apply changes"