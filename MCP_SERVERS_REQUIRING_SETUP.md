# MCP Servers Requiring Additional Setup

## 🔴 Critical Setup Required (Won't work without configuration)

### 1. **GitHub Server**
**Status**: ❌ Missing API Token  
**Required Setup**:
```bash
# Generate token at: https://github.com/settings/tokens
# Required scopes: repo, read:org, workflow
export GITHUB_TOKEN="ghp_your_token_here"

# Add to MCP server
claude mcp remove github
claude mcp add github npx -- -y @modelcontextprotocol/server-github -e GITHUB_TOKEN=$GITHUB_TOKEN
```

### 2. **PostgreSQL Server**
**Status**: ❌ Missing Connection String  
**Required Setup**:
```bash
# Set connection string
export POSTGRES_URL="postgresql://username:password@localhost:5432/database_name"

# Add to MCP server
claude mcp remove postgres
claude mcp add postgres npx -- -y @modelcontextprotocol/server-postgres -e POSTGRES_URL=$POSTGRES_URL
```

### 3. **Slack Server**
**Status**: ❌ Missing Bot Token  
**Required Setup**:
```bash
# Create Slack app at: https://api.slack.com/apps
# Install to workspace and get bot token
export SLACK_BOT_TOKEN="xoxb-your-bot-token"

# Add to MCP server
claude mcp remove slack
claude mcp add slack npx -- -y @modelcontextprotocol/server-slack -e SLACK_BOT_TOKEN=$SLACK_BOT_TOKEN
```

### 4. **Docker Server**
**Status**: ⚠️  Requires Docker Daemon  
**Required Setup**:
```bash
# Ensure Docker is installed and running
docker --version
sudo systemctl status docker

# If not installed:
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Verify Docker socket access
ls -la /var/run/docker.sock
```

### 5. **SQLite Server**
**Status**: ⚠️  Database file doesn't exist  
**Required Setup**:
```bash
# Create database directory and file
mkdir -p /home/louranicas/projects/claude-optimized-deployment/data
touch /home/louranicas/projects/claude-optimized-deployment/data/claude.db

# Initialize database (optional)
sqlite3 /home/louranicas/projects/claude-optimized-deployment/data/claude.db << EOF
CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
EOF
```

## 🟡 Optional Enhancement Setup

### 6. **Puppeteer Server**
**Status**: ✅ Works but can be enhanced  
**Optional Setup**:
```bash
# Install Chrome/Chromium for better compatibility
sudo apt-get update
sudo apt-get install -y chromium-browser

# Or install Google Chrome
wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
sudo sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list'
sudo apt-get update
sudo apt-get install google-chrome-stable
```

### 7. **Git Server**
**Status**: ✅ Works with local repos  
**Optional Setup**:
```bash
# Configure git identity (if not set)
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"

# Set default editor
git config --global core.editor "vim"
```

## 🟢 Fully Configured (No setup required)

### Ready to Use:
- ✅ **filesystem** - Configured for `/home/louranicas/projects`
- ✅ **brave-search** - API key already configured
- ✅ **memory** - Works out of the box
- ✅ **time** - No configuration needed
- ✅ **fetch** - Ready for HTTP requests

## 📋 Setup Priority Order

1. **GitHub** (Critical for code management)
2. **PostgreSQL** (If using database features)
3. **Slack** (If using team notifications)
4. **SQLite** (Create database file)
5. **Docker** (Ensure daemon is running)

## 🚀 Quick Setup Script

Create a `.env.mcp` file:
```bash
cat > .env.mcp << 'EOF'
# GitHub Configuration
export GITHUB_TOKEN="ghp_your_token_here"

# PostgreSQL Configuration
export POSTGRES_URL="postgresql://user:password@localhost:5432/claude_db"

# Slack Configuration
export SLACK_BOT_TOKEN="xoxb-your-bot-token"

# Load all variables
echo "✅ MCP environment variables loaded"
EOF

# Source the file
source .env.mcp
```

Then reconfigure servers:
```bash
# Reconfigure servers with credentials
claude mcp remove github
claude mcp add github npx -- -y @modelcontextprotocol/server-github -e GITHUB_TOKEN=$GITHUB_TOKEN

claude mcp remove postgres  
claude mcp add postgres npx -- -y @modelcontextprotocol/server-postgres -e POSTGRES_URL=$POSTGRES_URL

claude mcp remove slack
claude mcp add slack npx -- -y @modelcontextprotocol/server-slack -e SLACK_BOT_TOKEN=$SLACK_BOT_TOKEN
```

## 🧪 Testing Commands

After setup, test each server:

```bash
# Test GitHub
"Show my GitHub repositories"

# Test PostgreSQL
"Connect to the PostgreSQL database and show tables"

# Test Slack
"List Slack channels"

# Test Docker
"List running Docker containers"

# Test SQLite
"Create a test table in SQLite"
```

## 📊 Summary

- **Total Configured Servers**: 12
- **Requiring Critical Setup**: 3 (GitHub, PostgreSQL, Slack)
- **Requiring Minor Setup**: 2 (Docker daemon, SQLite file)
- **Fully Ready**: 7 servers

Complete the setup for the 5 servers above to unlock full MCP functionality in the CORE environment.