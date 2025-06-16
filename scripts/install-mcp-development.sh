#!/bin/bash
# MCP (Model Context Protocol) Development Environment Setup
# Comprehensive installation for MCP server development

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +'%H:%M:%S')] $1${NC}"; }
warn() { echo -e "${YELLOW}[WARNING] $1${NC}"; }
info() { echo -e "${BLUE}[INFO] $1${NC}"; }

# Check prerequisites
check_prerequisites() {
    log "🔍 Checking prerequisites..."
    
    if ! command -v node >/dev/null 2>&1; then
        echo "❌ Node.js not found. Please install Node.js first."
        exit 1
    fi
    
    if ! command -v python3 >/dev/null 2>&1; then
        echo "❌ Python3 not found. Please install Python3 first."
        exit 1
    fi
    
    if ! command -v cargo >/dev/null 2>&1; then
        echo "❌ Rust/Cargo not found. Please install Rust first."
        exit 1
    fi
    
    log "✅ Prerequisites check passed"
    echo "  Node.js: $(node --version)"
    echo "  Python: $(python3 --version)"
    echo "  Rust: $(cargo --version)"
}

# Install MCP CLI and core tools
install_mcp_cli() {
    log "📦 Installing MCP CLI and core tools..."
    
    # Install MCP CLI globally
    npm install -g @modelcontextprotocol/cli
    
    # Install TypeScript development tools
    npm install -g typescript tsx ts-node
    
    # Install development and testing tools
    npm install -g nodemon concurrently
    
    log "✅ MCP CLI and development tools installed"
}

# Install MCP server packages
install_mcp_servers() {
    log "🚀 Installing MCP server packages..."
    
    local project_dir="/home/louranicas/projects/claude-optimized-deployment"
    cd "$project_dir"
    
    # Install core MCP servers
    npm install \
        @modelcontextprotocol/server-filesystem \
        @modelcontextprotocol/server-memory \
        @modelcontextprotocol/server-postgres \
        @modelcontextprotocol/server-sqlite \
        @wonderwhy-er/desktop-commander
    
    # Install MCP development dependencies
    npm install --save-dev \
        @modelcontextprotocol/inspector \
        @modelcontextprotocol/testing \
        @types/node \
        jest \
        @types/jest
        
    log "✅ MCP server packages installed"
}

# Install Python MCP libraries
install_python_mcp() {
    log "🐍 Installing Python MCP libraries..."
    
    local project_dir="/home/louranicas/projects/claude-optimized-deployment"
    cd "$project_dir"
    
    # Create or activate MCP development environment
    if [[ ! -d "venv_mcp" ]]; then
        python3 -m venv venv_mcp
        log "Created venv_mcp environment"
    fi
    
    source venv_mcp/bin/activate
    pip install --upgrade pip setuptools wheel
    
    # Install MCP Python packages
    pip install \
        mcp \
        mcp-server-git \
        mcp-server-filesystem \
        pydantic \
        aiofiles \
        asyncio-mqtt \
        websockets \
        jsonschema
    
    # Install additional development tools
    pip install \
        pytest \
        pytest-asyncio \
        black \
        mypy \
        ruff
    
    deactivate
    log "✅ Python MCP libraries installed"
}

# Create MCP development workspace
create_mcp_workspace() {
    log "🏗️  Creating MCP development workspace..."
    
    local project_dir="/home/louranicas/projects/claude-optimized-deployment"
    local mcp_dir="$project_dir/mcp_development"
    
    mkdir -p "$mcp_dir"/{servers,clients,tools,tests,examples}
    
    # Create package.json for MCP workspace
    cat > "$mcp_dir/package.json" << 'EOF'
{
  "name": "mcp-development-workspace",
  "version": "1.0.0",
  "description": "MCP server development workspace",
  "type": "module",
  "scripts": {
    "dev": "concurrently \"npm run dev:*\"",
    "test": "jest",
    "build": "tsc",
    "start": "node dist/index.js",
    "inspect": "mcp-inspector"
  },
  "dependencies": {
    "@modelcontextprotocol/sdk": "*",
    "@modelcontextprotocol/server-filesystem": "*",
    "@modelcontextprotocol/server-memory": "*"
  },
  "devDependencies": {
    "@types/node": "^20.0.0",
    "typescript": "^5.0.0",
    "jest": "^29.0.0",
    "concurrently": "^8.0.0",
    "nodemon": "^3.0.0"
  }
}
EOF

    # Create TypeScript configuration
    cat > "$mcp_dir/tsconfig.json" << 'EOF'
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "Node",
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "removeComments": false,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "strictFunctionTypes": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,
    "noUncheckedIndexedAccess": true,
    "noImplicitOverride": true,
    "allowUnusedLabels": false,
    "allowUnreachableCode": false,
    "exactOptionalPropertyTypes": true
  },
  "include": [
    "src/**/*"
  ],
  "exclude": [
    "node_modules",
    "dist",
    "tests"
  ]
}
EOF

    # Create example MCP server structure
    mkdir -p "$mcp_dir/src/servers/example"
    cat > "$mcp_dir/src/servers/example/index.ts" << 'EOF'
#!/usr/bin/env node

/**
 * Example MCP Server Implementation
 * Demonstrates basic MCP server functionality
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  Tool,
  CallToolRequest,
  CallToolResult,
} from "@modelcontextprotocol/sdk/types.js";

// Define available tools
const TOOLS: Tool[] = [
  {
    name: "echo",
    description: "Echo back the provided text",
    inputSchema: {
      type: "object",
      properties: {
        text: {
          type: "string",
          description: "Text to echo back",
        },
      },
      required: ["text"],
    },
  },
  {
    name: "timestamp",
    description: "Get current timestamp",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
];

class ExampleMCPServer {
  private server: Server;

  constructor() {
    this.server = new Server(
      {
        name: "example-mcp-server",
        version: "1.0.0",
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupToolHandlers();
    this.setupErrorHandling();
  }

  private setupToolHandlers(): void {
    // Handle tool listing
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return { tools: TOOLS };
    });

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request: CallToolRequest): Promise<CallToolResult> => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case "echo":
            return {
              content: [
                {
                  type: "text",
                  text: `Echo: ${args?.text || "No text provided"}`,
                },
              ],
            };

          case "timestamp":
            return {
              content: [
                {
                  type: "text",
                  text: `Current timestamp: ${new Date().toISOString()}`,
                },
              ],
            };

          default:
            throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    });
  }

  private setupErrorHandling(): void {
    this.server.onerror = (error) => {
      console.error("[MCP Error]", error);
    };

    process.on('SIGINT', async () => {
      await this.server.close();
      process.exit(0);
    });
  }

  async run(): Promise<void> {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    
    console.error("Example MCP Server running on stdio");
  }
}

// Start the server
const server = new ExampleMCPServer();
server.run().catch((error) => {
  console.error("Failed to start server:", error);
  process.exit(1);
});
EOF

    # Create Python MCP server example
    mkdir -p "$mcp_dir/src/servers/python-example"
    cat > "$mcp_dir/src/servers/python-example/server.py" << 'EOF'
#!/usr/bin/env python3
"""
Example Python MCP Server
Demonstrates basic MCP server functionality in Python
"""

import asyncio
import json
import sys
from typing import Any, Dict, List, Optional

from mcp import Server, types
from mcp.server.stdio import stdio_server


class ExamplePythonServer:
    """Example MCP server implementation in Python."""
    
    def __init__(self):
        self.server = Server("example-python-server")
        self.setup_handlers()
    
    def setup_handlers(self):
        """Set up MCP request handlers."""
        
        @self.server.list_tools()
        async def list_tools() -> List[types.Tool]:
            """List available tools."""
            return [
                types.Tool(
                    name="python_info",
                    description="Get Python system information",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                        "additionalProperties": False,
                    },
                ),
                types.Tool(
                    name="calculate",
                    description="Perform basic mathematical calculations",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "expression": {
                                "type": "string",
                                "description": "Mathematical expression to evaluate",
                            }
                        },
                        "required": ["expression"],
                    },
                ),
            ]
        
        @self.server.call_tool()
        async def call_tool(name: str, arguments: Dict[str, Any]) -> List[types.TextContent]:
            """Handle tool calls."""
            
            if name == "python_info":
                import platform
                import sys
                
                info = {
                    "python_version": sys.version,
                    "platform": platform.platform(),
                    "architecture": platform.architecture(),
                    "processor": platform.processor(),
                }
                
                return [
                    types.TextContent(
                        type="text",
                        text=f"Python System Information:\n{json.dumps(info, indent=2)}"
                    )
                ]
            
            elif name == "calculate":
                expression = arguments.get("expression", "")
                
                try:
                    # Safe evaluation of mathematical expressions
                    allowed_names = {
                        k: v for k, v in __builtins__.items() 
                        if k in ["abs", "round", "min", "max", "sum", "pow"]
                    }
                    allowed_names.update({
                        "sqrt": lambda x: x ** 0.5,
                        "pi": 3.141592653589793,
                        "e": 2.718281828459045,
                    })
                    
                    result = eval(expression, {"__builtins__": {}}, allowed_names)
                    
                    return [
                        types.TextContent(
                            type="text",
                            text=f"Result: {expression} = {result}"
                        )
                    ]
                    
                except Exception as e:
                    return [
                        types.TextContent(
                            type="text",
                            text=f"Error evaluating expression '{expression}': {str(e)}"
                        )
                    ]
            
            else:
                raise ValueError(f"Unknown tool: {name}")
    
    async def run(self):
        """Run the MCP server."""
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options()
            )


async def main():
    """Main entry point."""
    server = ExamplePythonServer()
    await server.run()


if __name__ == "__main__":
    asyncio.run(main())
EOF

    # Create MCP development scripts
    cat > "$mcp_dir/scripts/dev-server.sh" << 'EOF'
#!/bin/bash
# Development script for running MCP servers

set -euo pipefail

SERVER_TYPE=${1:-"typescript"}
SERVER_NAME=${2:-"example"}

case $SERVER_TYPE in
    "typescript"|"ts")
        echo "Starting TypeScript MCP server: $SERVER_NAME"
        cd "src/servers/$SERVER_NAME"
        npx tsx index.ts
        ;;
    "python"|"py")
        echo "Starting Python MCP server: $SERVER_NAME"
        cd "src/servers/$SERVER_NAME"
        python3 server.py
        ;;
    *)
        echo "Usage: $0 <typescript|python> [server-name]"
        echo "Available servers:"
        ls src/servers/
        exit 1
        ;;
esac
EOF

    chmod +x "$mcp_dir/scripts/dev-server.sh"
    mkdir -p "$mcp_dir/scripts"
    
    # Create MCP testing script
    cat > "$mcp_dir/scripts/test-mcp.sh" << 'EOF'
#!/bin/bash
# Test MCP server functionality

set -euo pipefail

SERVER_CMD=${1:-"npx tsx src/servers/example/index.ts"}

echo "Testing MCP server: $SERVER_CMD"
echo "========================================"

# Test tool listing
echo "1. Testing tool listing..."
echo '{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}' | $SERVER_CMD

echo -e "\n2. Testing echo tool..."
echo '{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "echo", "arguments": {"text": "Hello MCP!"}}}' | $SERVER_CMD

echo -e "\n3. Testing timestamp tool..."
echo '{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "timestamp", "arguments": {}}}' | $SERVER_CMD

echo -e "\nMCP server test complete!"
EOF

    chmod +x "$mcp_dir/scripts/test-mcp.sh"
    
    log "✅ MCP development workspace created at $mcp_dir"
}

# Create MCP configuration files
create_mcp_configs() {
    log "⚙️  Creating MCP configuration files..."
    
    local project_dir="/home/louranicas/projects/claude-optimized-deployment"
    local config_dir="$project_dir/config/mcp"
    
    mkdir -p "$config_dir"
    
    # Create MCP server registry
    cat > "$config_dir/server-registry.json" << 'EOF'
{
  "servers": {
    "filesystem": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-filesystem", "/home/louranicas/projects"],
      "description": "File system operations server"
    },
    "memory": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-memory"],
      "description": "In-memory data storage server"
    },
    "postgres": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-postgres"],
      "env": {
        "POSTGRES_URL": "postgresql://localhost:5432/claude_development"
      },
      "description": "PostgreSQL database server"
    },
    "example-ts": {
      "command": "npx",
      "args": ["tsx", "mcp_development/src/servers/example/index.ts"],
      "description": "Example TypeScript MCP server"
    },
    "example-python": {
      "command": "python3",
      "args": ["mcp_development/src/servers/python-example/server.py"],
      "description": "Example Python MCP server"
    }
  },
  "client_config": {
    "timeout": 30000,
    "max_retries": 3,
    "log_level": "info"
  }
}
EOF

    # Create development environment configuration
    cat > "$config_dir/development.env" << 'EOF'
# MCP Development Environment Configuration

# Server settings
MCP_SERVER_TIMEOUT=30000
MCP_MAX_RETRIES=3
MCP_LOG_LEVEL=debug

# Database settings
POSTGRES_URL=postgresql://localhost:5432/claude_development
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=claude_development
POSTGRES_USER=postgres

# Redis settings
REDIS_URL=redis://localhost:6379
REDIS_HOST=localhost
REDIS_PORT=6379

# File system settings
MCP_WORKSPACE_ROOT=/home/louranicas/projects/claude-optimized-deployment
MCP_ALLOWED_PATHS=/home/louranicas/projects

# Security settings
MCP_ENABLE_SECURITY=true
MCP_ALLOWED_COMMANDS=npx,node,python3,tsx
EOF

    log "✅ MCP configuration files created"
}

# Install MCP development tools
install_mcp_tools() {
    log "🔧 Installing additional MCP development tools..."
    
    # Install MCP inspector for debugging
    npm install -g @modelcontextprotocol/inspector
    
    # Install MCP testing utilities
    npm install -g @modelcontextprotocol/testing
    
    # Create MCP development utilities
    local project_dir="/home/louranicas/projects/claude-optimized-deployment"
    
    cat > "$project_dir/scripts/mcp-inspector.sh" << 'EOF'
#!/bin/bash
# Launch MCP Inspector for debugging

SERVER_CMD=${1:-"npx tsx mcp_development/src/servers/example/index.ts"}

echo "Launching MCP Inspector for: $SERVER_CMD"
npx @modelcontextprotocol/inspector $SERVER_CMD
EOF

    chmod +x "$project_dir/scripts/mcp-inspector.sh"
    
    log "✅ MCP development tools installed"
}

# Test MCP installation
test_mcp_installation() {
    log "🧪 Testing MCP installation..."
    
    # Test MCP CLI
    if command -v mcp >/dev/null 2>&1; then
        log "✅ MCP CLI installed: $(mcp --version 2>/dev/null || echo 'Version check failed')"
    else
        warn "MCP CLI not found in PATH"
    fi
    
    # Test Node.js MCP packages
    local project_dir="/home/louranicas/projects/claude-optimized-deployment"
    cd "$project_dir"
    
    if npm list @modelcontextprotocol/server-filesystem >/dev/null 2>&1; then
        log "✅ MCP filesystem server installed"
    else
        warn "MCP filesystem server not found"
    fi
    
    # Test Python MCP packages
    if [[ -d "venv_mcp" ]]; then
        source venv_mcp/bin/activate
        if python -c "import mcp" 2>/dev/null; then
            log "✅ Python MCP library installed"
        else
            warn "Python MCP library not found"
        fi
        deactivate
    fi
    
    # Test example server compilation
    if [[ -f "mcp_development/src/servers/example/index.ts" ]]; then
        cd mcp_development
        if npx tsc --noEmit src/servers/example/index.ts 2>/dev/null; then
            log "✅ TypeScript MCP server compiles successfully"
        else
            warn "TypeScript MCP server compilation failed"
        fi
    fi
    
    log "✅ MCP installation testing complete"
}

# Main installation flow
main() {
    log "🚀 Installing MCP development environment"
    
    check_prerequisites
    install_mcp_cli
    install_mcp_servers
    install_python_mcp
    create_mcp_workspace
    create_mcp_configs
    install_mcp_tools
    test_mcp_installation
    
    log "✅ MCP development environment installation complete!"
    echo ""
    echo "MCP Development Environment Ready!"
    echo "=================================="
    echo ""
    echo "Available commands:"
    echo "  mcp --help                    # MCP CLI help"
    echo "  ./scripts/mcp-inspector.sh    # Launch MCP inspector"
    echo "  cd mcp_development && npm run dev  # Start development environment"
    echo ""
    echo "Example servers created:"
    echo "  TypeScript: mcp_development/src/servers/example/"
    echo "  Python:     mcp_development/src/servers/python-example/"
    echo ""
    echo "Configuration:"
    echo "  Registry:   config/mcp/server-registry.json"
    echo "  Environment: config/mcp/development.env"
    echo ""
    echo "Next steps:"
    echo "1. Review the example servers in mcp_development/src/servers/"
    echo "2. Test the servers with: cd mcp_development && ./scripts/test-mcp.sh"
    echo "3. Use MCP inspector for debugging: ./scripts/mcp-inspector.sh"
    echo "4. Develop your own MCP servers in the workspace"
}

main "$@"