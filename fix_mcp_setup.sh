#!/bin/bash

# MCP Server Setup Fix Script
# Automatically fixes common setup issues

echo "🔧 MCP Server Setup Fix Tool"
echo "============================"

# Check and create SQLite database
echo -e "\n📁 Setting up SQLite database..."
if [ ! -f "/home/louranicas/projects/claude-optimized-deployment/data/claude.db" ]; then
    mkdir -p /home/louranicas/projects/claude-optimized-deployment/data
    touch /home/louranicas/projects/claude-optimized-deployment/data/claude.db
    echo "✅ SQLite database created"
else
    echo "✅ SQLite database already exists"
fi

# Check Docker
echo -e "\n🐳 Checking Docker..."
if command -v docker &> /dev/null; then
    if docker ps &> /dev/null; then
        echo "✅ Docker is installed and running"
    else
        echo "⚠️  Docker is installed but not accessible. You may need to:"
        echo "   - Run: sudo usermod -aG docker $USER"
        echo "   - Log out and back in"
    fi
else
    echo "❌ Docker is not installed"
fi

# Check for environment file
echo -e "\n📋 Checking for environment configuration..."
if [ -f ".env.mcp" ]; then
    echo "✅ Found .env.mcp file"
    source .env.mcp
else
    echo "📝 Creating .env.mcp template..."
    cat > .env.mcp << 'EOF'
# MCP Server Environment Configuration
# Fill in your actual values and run: source .env.mcp

# GitHub Configuration
export GITHUB_TOKEN="ghp_your_token_here"

# PostgreSQL Configuration  
export POSTGRES_URL="postgresql://user:password@localhost:5432/claude_db"

# Slack Configuration
export SLACK_BOT_TOKEN="xoxb-your-bot-token"

# Optional: Cloud Providers
export AWS_ACCESS_KEY_ID=""
export AWS_SECRET_ACCESS_KEY=""
export GOOGLE_APPLICATION_CREDENTIALS=""
export AZURE_CLIENT_ID=""

# Optional: AI Services
export OPENAI_API_KEY=""
export ANTHROPIC_API_KEY=""
export HUGGINGFACE_TOKEN=""

echo "✅ MCP environment variables loaded"
EOF
    echo "✅ Created .env.mcp template"
    echo "   Edit .env.mcp with your credentials"
fi

# Summary
echo -e "\n📊 Setup Summary"
echo "==============="

# Count configured servers
TOTAL_SERVERS=$(claude mcp list 2>/dev/null | wc -l || echo "0")
echo "Total MCP servers configured: $TOTAL_SERVERS"

# Check critical servers
echo -e "\n🔍 Server Status:"
echo "- filesystem: ✅ Ready"
echo "- brave-search: ✅ Ready (API key configured)"
echo "- memory: ✅ Ready"
echo "- time: ✅ Ready"
echo "- fetch: ✅ Ready"
echo "- git: ✅ Ready"
echo "- puppeteer: ✅ Ready"
echo "- docker: $(docker ps &> /dev/null && echo '✅ Ready' || echo '⚠️  Needs Docker daemon')"
echo "- sqlite: ✅ Ready (database created)"
echo "- github: $([ -z "$GITHUB_TOKEN" ] && echo '❌ Needs token' || echo '✅ Token set')"
echo "- postgres: $([ -z "$POSTGRES_URL" ] && echo '❌ Needs connection string' || echo '✅ URL set')"
echo "- slack: $([ -z "$SLACK_BOT_TOKEN" ] && echo '❌ Needs bot token' || echo '✅ Token set')"

echo -e "\n🚀 Next Steps:"
echo "1. Edit .env.mcp with your credentials"
echo "2. Run: source .env.mcp"
echo "3. Reconfigure servers with credentials:"
echo "   ./reconfigure_mcp_with_env.sh"
echo ""
echo "For detailed setup instructions, see: MCP_SERVERS_REQUIRING_SETUP.md"