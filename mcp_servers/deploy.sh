#!/bin/bash

# MCP Server Deployment Script
echo "🚀 Deploying MCP Servers..."

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo -e "${RED}❌ Node.js is not installed. Please install Node.js 18+ first.${NC}"
    exit 1
fi

# Check Node.js version
NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
    echo -e "${RED}❌ Node.js version 18+ is required. Current version: $(node -v)${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Node.js $(node -v) detected${NC}"

# Navigate to MCP servers directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Check if API keys are configured
if [ ! -f "config/api_keys.env" ]; then
    echo -e "${RED}❌ API keys not configured. Please create config/api_keys.env file.${NC}"
    echo "Example:"
    echo "  TAVILY_API_KEY=your-tavily-key"
    echo "  SMITHERY_API_KEY=your-smithery-key"
    echo "  BRAVE_API_KEY=your-brave-key"
    exit 1
fi

# Install dependencies
echo -e "${YELLOW}📦 Installing dependencies...${NC}"
npm install

# Build TypeScript files
echo -e "${YELLOW}🔨 Building TypeScript files...${NC}"
npm run build

# Run tests
echo -e "${YELLOW}🧪 Running API connectivity tests...${NC}"
npm run test:api || {
    echo -e "${RED}❌ API tests failed. Please check your API keys.${NC}"
    exit 1
}

# Create systemd service (optional, for production)
if [ "$1" == "--systemd" ]; then
    echo -e "${YELLOW}🔧 Creating systemd service...${NC}"
    
    cat > /tmp/mcp-servers.service << EOF
[Unit]
Description=MCP Servers
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$SCRIPT_DIR
ExecStart=/usr/bin/node $SCRIPT_DIR/dist/index.js
Restart=on-failure
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=mcp-servers
Environment="NODE_ENV=production"

[Install]
WantedBy=multi-user.target
EOF

    sudo cp /tmp/mcp-servers.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable mcp-servers
    echo -e "${GREEN}✓ Systemd service created${NC}"
fi

# Start servers
if [ "$1" == "--start" ] || [ "$2" == "--start" ]; then
    echo -e "${YELLOW}🚀 Starting MCP servers...${NC}"
    
    if [ "$1" == "--systemd" ] || [ "$2" == "--systemd" ]; then
        sudo systemctl start mcp-servers
        echo -e "${GREEN}✓ MCP servers started as systemd service${NC}"
        echo "Check status: sudo systemctl status mcp-servers"
        echo "View logs: sudo journalctl -u mcp-servers -f"
    else
        npm start &
        MCP_PID=$!
        echo -e "${GREEN}✓ MCP servers started (PID: $MCP_PID)${NC}"
        echo "Servers running at: http://localhost:3000"
        echo "Stop with: kill $MCP_PID"
    fi
fi

echo -e "${GREEN}✅ MCP Server deployment complete!${NC}"
echo ""
echo "Available commands:"
echo "  npm start         - Start all servers"
echo "  npm run dev       - Start in development mode"
echo "  npm test          - Run tests"
echo "  npm run test:api  - Test API connectivity"
echo ""
echo "API endpoints:"
echo "  http://localhost:3000/health"
echo "  http://localhost:3000/api/servers"
echo "  ws://localhost:3000/ws"