#!/usr/bin/env python3
"""
Complete MCP Server Setup Script
Installs and configures desktop-commander and other essential MCP servers
"""

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from datetime import datetime

# Essential MCP servers including desktop-commander
MCP_SERVERS = [
    {
        "name": "desktop-commander",
        "npm_package": "@wonderwhy-er/desktop-commander",
        "description": "Desktop control and command execution",
        "priority": 1,
        "config": {
            "allowed_commands": ["ls", "pwd", "echo", "cat", "grep", "find"],
            "max_output_length": 10000,
            "timeout": 30000
        }
    },
    {
        "name": "filesystem",
        "npm_package": "@modelcontextprotocol/server-filesystem",
        "description": "File system operations",
        "priority": 2,
        "config": {
            "allowed_directories": ["~/projects", "~/Documents"],
            "max_file_size": 10485760
        }
    },
    {
        "name": "postgres",
        "npm_package": "@modelcontextprotocol/server-postgres", 
        "description": "PostgreSQL database integration",
        "priority": 3,
        "config": {
            "connection_string": "postgresql://localhost:5432/mcp_db"
        }
    },
    {
        "name": "github",
        "npm_package": "@modelcontextprotocol/server-github",
        "description": "GitHub API integration",
        "priority": 4,
        "config": {
            "token": os.environ.get("GITHUB_TOKEN", "")
        }
    },
    {
        "name": "memory",
        "npm_package": "@modelcontextprotocol/server-memory",
        "description": "AI memory and context",
        "priority": 5,
        "config": {
            "storage_path": "./mcp_memory"
        }
    },
    {
        "name": "brave-search",
        "npm_package": "@modelcontextprotocol/server-brave-search",
        "description": "Brave search integration",
        "priority": 6,
        "config": {
            "api_key": os.environ.get("BRAVE_API_KEY", "BSAigVAUU4-V72PjB48t8_CqN00Hh5z")
        }
    },
    {
        "name": "slack",
        "npm_package": "@modelcontextprotocol/server-slack",
        "description": "Slack communication",
        "priority": 7,
        "config": {
            "bot_token": os.environ.get("SLACK_BOT_TOKEN", "")
        }
    },
    {
        "name": "puppeteer",
        "npm_package": "@modelcontextprotocol/server-puppeteer",
        "description": "Browser automation",
        "priority": 8,
        "config": {
            "headless": True,
            "defaultViewport": {"width": 1920, "height": 1080}
        }
    }
]

class MCPServerSetup:
    def __init__(self):
        self.base_dir = Path.cwd() / "mcp_servers"
        self.config_dir = Path.cwd() / "mcp_configs"
        self.results = []
        self.installed = 0
        self.failed = 0
        
    async def setup_directories(self):
        """Create necessary directories"""
        print("📁 Setting up directories...")
        self.base_dir.mkdir(exist_ok=True)
        self.config_dir.mkdir(exist_ok=True)
        print(f"✅ Created directories: {self.base_dir}, {self.config_dir}")
        
    async def check_npm(self):
        """Check npm availability"""
        try:
            result = subprocess.run(['npm', '--version'], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✅ npm version: {result.stdout.strip()}")
                return True
        except:
            pass
        print("❌ npm not found. Please install Node.js")
        return False
        
    async def install_server(self, server):
        """Install a single MCP server"""
        print(f"\n📦 Installing {server['name']}...")
        print(f"   Package: {server['npm_package']}")
        
        try:
            # Check if already installed
            check_cmd = ['npm', 'list', server['npm_package']]
            check_result = subprocess.run(check_cmd, cwd=self.base_dir, capture_output=True)
            
            if check_result.returncode == 0:
                print(f"✅ {server['name']} already installed")
                self.installed += 1
                self.results.append({
                    'server': server['name'],
                    'status': 'already_installed',
                    'package': server['npm_package']
                })
                return True
                
            # Install the package
            install_cmd = ['npm', 'install', server['npm_package']]
            result = subprocess.run(install_cmd, cwd=self.base_dir, capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"✅ Successfully installed {server['name']}")
                self.installed += 1
                self.results.append({
                    'server': server['name'],
                    'status': 'success',
                    'package': server['npm_package']
                })
                return True
            else:
                print(f"❌ Failed to install {server['name']}: {result.stderr}")
                self.failed += 1
                self.results.append({
                    'server': server['name'],
                    'status': 'failed',
                    'error': result.stderr
                })
                return False
                
        except Exception as e:
            print(f"❌ Exception installing {server['name']}: {e}")
            self.failed += 1
            self.results.append({
                'server': server['name'],
                'status': 'error',
                'error': str(e)
            })
            return False
            
    async def create_server_config(self, server):
        """Create configuration for a server"""
        config_file = self.config_dir / f"{server['name']}.json"
        
        config = {
            "name": server['name'],
            "description": server['description'],
            "npm_package": server['npm_package'],
            "path": f"../mcp_servers/node_modules/{server['npm_package']}",
            "settings": server.get('config', {})
        }
        
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
            
        print(f"✅ Created config: {config_file}")
        
    async def create_master_config(self):
        """Create master MCP configuration"""
        print("\n📝 Creating master configuration...")
        
        servers = {}
        for server in MCP_SERVERS:
            if any(r['server'] == server['name'] and r['status'] in ['success', 'already_installed'] 
                   for r in self.results):
                servers[server['name']] = {
                    "command": "npx",
                    "args": ["-y", server['npm_package']],
                    "env": {}
                }
                
                # Add environment variables if needed
                if server['name'] == 'brave-search':
                    servers[server['name']]['env']['BRAVE_API_KEY'] = server['config']['api_key']
                elif server['name'] == 'github':
                    servers[server['name']]['env']['GITHUB_TOKEN'] = server['config']['token']
                elif server['name'] == 'slack':
                    servers[server['name']]['env']['SLACK_BOT_TOKEN'] = server['config']['bot_token']
                    
        # Create MCP settings file for Claude Desktop
        mcp_settings = {
            "mcpServers": servers
        }
        
        # Save to Claude Desktop config location
        claude_config_dir = Path.home() / "Library" / "Application Support" / "Claude"
        claude_config_dir.mkdir(parents=True, exist_ok=True)
        
        claude_config_file = claude_config_dir / "claude_desktop_config.json"
        
        # Load existing config if it exists
        if claude_config_file.exists():
            with open(claude_config_file, 'r') as f:
                existing_config = json.load(f)
        else:
            existing_config = {}
            
        # Merge configurations
        if 'mcpServers' in existing_config:
            existing_config['mcpServers'].update(servers)
        else:
            existing_config['mcpServers'] = servers
            
        # Save updated config
        with open(claude_config_file, 'w') as f:
            json.dump(existing_config, f, indent=2)
            
        print(f"✅ Updated Claude Desktop config: {claude_config_file}")
        
        # Also save a backup
        backup_file = self.config_dir / f"mcp_master_config_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(backup_file, 'w') as f:
            json.dump(mcp_settings, f, indent=2)
            
        print(f"✅ Backup saved to: {backup_file}")
        
    async def test_desktop_commander(self):
        """Test desktop-commander functionality"""
        print("\n🧪 Testing desktop-commander...")
        
        try:
            # Test basic command
            test_cmd = ['npx', '-y', '@wonderwhy-er/desktop-commander', 'ls']
            result = subprocess.run(test_cmd, cwd=self.base_dir, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                print("✅ Desktop-commander test successful!")
                print(f"   Output preview: {result.stdout[:100]}...")
            else:
                print(f"❌ Desktop-commander test failed: {result.stderr}")
                
        except Exception as e:
            print(f"❌ Error testing desktop-commander: {e}")
            
    def generate_report(self):
        """Generate installation report"""
        print("\n" + "="*80)
        print("🎯 MCP SERVER SETUP REPORT")
        print("="*80)
        print(f"✅ Successfully Installed: {self.installed}")
        print(f"❌ Failed: {self.failed}")
        print(f"📦 Total Servers: {len(MCP_SERVERS)}")
        
        if self.installed > 0:
            print("\n✅ Installed Servers:")
            for result in self.results:
                if result['status'] in ['success', 'already_installed']:
                    print(f"  • {result['server']} ({result['package']})")
                    
        if self.failed > 0:
            print("\n❌ Failed Installations:")
            for result in self.results:
                if result['status'] not in ['success', 'already_installed']:
                    print(f"  • {result['server']}: {result.get('error', 'Unknown error')[:100]}")
                    
        print("\n🚀 Capabilities Enabled:")
        print("  • Desktop command execution (desktop-commander)")
        print("  • File system operations")
        print("  • Database connectivity")
        print("  • GitHub integration")
        print("  • AI memory persistence")
        print("  • Web search (Brave)")
        print("  • Browser automation")
        print("  • Team communication (Slack)")
        
        print("\n📝 Next Steps:")
        print("  1. Restart Claude Desktop to load new servers")
        print("  2. Test server connections in Claude")
        print("  3. Configure any missing API keys")
        print("  4. Start using enhanced capabilities!")
        
        print("="*80)
        
        # Save detailed report
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_servers': len(MCP_SERVERS),
                'installed': self.installed,
                'failed': self.failed
            },
            'results': self.results,
            'servers': MCP_SERVERS
        }
        
        report_path = f"mcp_setup_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
            
        print(f"\n📄 Detailed report saved to: {report_path}")


async def main():
    print("🚀 COMPLETE MCP SERVER SETUP")
    print("📦 Installing Essential MCP Servers")
    print("🎯 Priority: desktop-commander from Smithery")
    print("="*80)
    
    setup = MCPServerSetup()
    
    # Check npm
    if not await setup.check_npm():
        return 1
        
    # Setup directories
    await setup.setup_directories()
    
    # Initialize npm if needed
    package_json = setup.base_dir / "package.json"
    if not package_json.exists():
        print("\n📦 Initializing npm package...")
        init_cmd = ['npm', 'init', '-y']
        subprocess.run(init_cmd, cwd=setup.base_dir, capture_output=True)
        
    # Install servers
    for server in sorted(MCP_SERVERS, key=lambda x: x['priority']):
        await setup.install_server(server)
        if server['name'] in ['desktop-commander', 'filesystem', 'postgres', 'github', 'memory']:
            await setup.create_server_config(server)
            
    # Create master configuration
    if setup.installed > 0:
        await setup.create_master_config()
        
    # Test desktop-commander
    if any(r['server'] == 'desktop-commander' and r['status'] in ['success', 'already_installed'] 
           for r in setup.results):
        await setup.test_desktop_commander()
        
    # Generate report
    setup.generate_report()
    
    return 0 if setup.installed > 0 else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)