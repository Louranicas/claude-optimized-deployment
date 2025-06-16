#!/usr/bin/env python3
"""
Enhanced MCP Server Integration Script
Integrates the most valuable MCP servers based on adjusted scoring
"""

import asyncio
import json
import os
from pathlib import Path
from datetime import datetime
import subprocess
import sys

# Top recommended servers based on analysis
RECOMMENDED_SERVERS = [
    {
        "name": "filesystem-mcp-server",
        "npm_package": "@modelcontextprotocol/server-filesystem",
        "description": "Platform-agnostic file system capabilities",
        "priority": 1
    },
    {
        "name": "postgresql-mcp-server", 
        "npm_package": "@modelcontextprotocol/server-postgres",
        "description": "PostgreSQL database integration",
        "priority": 2
    },
    {
        "name": "git-mcp",
        "npm_package": "@modelcontextprotocol/server-git",
        "description": "Git operations for repositories",
        "priority": 3
    },
    {
        "name": "memory-mcp-server",
        "npm_package": "@modelcontextprotocol/server-memory",
        "description": "AI memory and context retention",
        "priority": 4
    },
    {
        "name": "elasticsearch-mcp-server",
        "npm_package": "@modelcontextprotocol/server-elasticsearch",
        "description": "Log analysis and search",
        "priority": 5
    }
]

class MCPServerIntegrator:
    def __init__(self):
        self.results = []
        self.integrated = 0
        self.failed = 0
        
    async def check_npm(self):
        """Check if npm is available"""
        try:
            result = subprocess.run(['npm', '--version'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✅ npm version: {result.stdout.strip()}")
                return True
            else:
                print("❌ npm not found")
                return False
        except Exception as e:
            print(f"❌ Error checking npm: {e}")
            return False
    
    async def install_server(self, server):
        """Install an MCP server via npm"""
        print(f"\n📦 Installing {server['name']}...")
        print(f"   Package: {server['npm_package']}")
        
        try:
            # Create MCP servers directory
            mcp_dir = Path("mcp_servers")
            mcp_dir.mkdir(exist_ok=True)
            
            # Install the package
            result = subprocess.run(
                ['npm', 'install', server['npm_package']],
                cwd=mcp_dir,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                print(f"✅ Successfully installed {server['name']}")
                self.integrated += 1
                self.results.append({
                    'server': server['name'],
                    'status': 'success',
                    'package': server['npm_package']
                })
                return True
            else:
                print(f"❌ Failed to install {server['name']}")
                print(f"   Error: {result.stderr}")
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
    
    async def create_server_configs(self):
        """Create configuration files for integrated servers"""
        print("\n📝 Creating server configurations...")
        
        configs_dir = Path("mcp_server_configs")
        configs_dir.mkdir(exist_ok=True)
        
        # Filesystem server config
        filesystem_config = {
            "name": "filesystem-mcp-server",
            "path": "./mcp_servers/node_modules/@modelcontextprotocol/server-filesystem",
            "permissions": {
                "read": True,
                "write": True,
                "base_path": os.path.expanduser("~")
            }
        }
        
        # PostgreSQL server config
        postgres_config = {
            "name": "postgresql-mcp-server",
            "path": "./mcp_servers/node_modules/@modelcontextprotocol/server-postgres",
            "connection": {
                "host": "localhost",
                "port": 5432,
                "database": "mcp_db",
                "user": "mcp_user"
            }
        }
        
        # Git server config
        git_config = {
            "name": "git-mcp",
            "path": "./mcp_servers/node_modules/@modelcontextprotocol/server-git",
            "repositories": [
                os.getcwd()
            ]
        }
        
        # Memory server config
        memory_config = {
            "name": "memory-mcp-server",
            "path": "./mcp_servers/node_modules/@modelcontextprotocol/server-memory",
            "storage": {
                "type": "persistent",
                "path": "./mcp_memory_store"
            }
        }
        
        # Elasticsearch server config
        elasticsearch_config = {
            "name": "elasticsearch-mcp-server",
            "path": "./mcp_servers/node_modules/@modelcontextprotocol/server-elasticsearch",
            "connection": {
                "host": "localhost",
                "port": 9200,
                "index_prefix": "mcp_"
            }
        }
        
        configs = {
            "filesystem": filesystem_config,
            "postgresql": postgres_config,
            "git": git_config,
            "memory": memory_config,
            "elasticsearch": elasticsearch_config
        }
        
        for name, config in configs.items():
            config_path = configs_dir / f"{name}_config.json"
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
            print(f"✅ Created config: {config_path}")
    
    async def update_main_config(self):
        """Update the main MCP configuration"""
        print("\n🔧 Updating main MCP configuration...")
        
        # Read existing config if it exists
        config_path = Path("mcp_server_config.json")
        if config_path.exists():
            with open(config_path, 'r') as f:
                config = json.load(f)
        else:
            config = {
                "core_servers": [],
                "new_servers": [],
                "categories": {}
            }
        
        # Add new servers
        new_servers = [r['server'] for r in self.results if r['status'] == 'success']
        config['new_servers'].extend(new_servers)
        config['total_servers'] = len(config.get('core_servers', [])) + len(config['new_servers'])
        
        # Update categories
        if 'categories' not in config:
            config['categories'] = {}
            
        config['categories'].update({
            'filesystem': ['filesystem-mcp-server'],
            'database': ['postgresql-mcp-server'],
            'version_control': ['git-mcp'],
            'ai_enhanced': ['memory-mcp-server'],
            'monitoring': ['elasticsearch-mcp-server']
        })
        
        # Save updated config
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        new_config_path = f"mcp_server_config_integrated_{timestamp}.json"
        with open(new_config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"✅ Updated configuration saved to: {new_config_path}")
    
    def generate_report(self):
        """Generate integration report"""
        print("\n" + "="*80)
        print("🎯 MCP SERVER INTEGRATION REPORT")
        print("="*80)
        print(f"✅ Successfully Integrated: {self.integrated}")
        print(f"❌ Failed: {self.failed}")
        
        if self.integrated > 0:
            print("\n📦 Integrated Servers:")
            for result in self.results:
                if result['status'] == 'success':
                    print(f"  ✅ {result['server']}")
        
        if self.failed > 0:
            print("\n❌ Failed Integrations:")
            for result in self.results:
                if result['status'] != 'success':
                    print(f"  ❌ {result['server']} - {result.get('error', 'Unknown error')}")
        
        print("\n🚀 New Capabilities Added:")
        print("  • Enhanced file system operations")
        print("  • PostgreSQL database connectivity")
        print("  • Git repository management")
        print("  • AI memory persistence")
        print("  • Elasticsearch log analysis")
        
        print("\n📝 Next Steps:")
        print("  1. Configure environment variables for each server")
        print("  2. Start servers using the generated configs")
        print("  3. Test server connections")
        print("  4. Update client applications to use new servers")
        
        print("="*80)
        
        # Save detailed report
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'attempted': len(RECOMMENDED_SERVERS),
                'integrated': self.integrated,
                'failed': self.failed
            },
            'results': self.results,
            'servers': RECOMMENDED_SERVERS
        }
        
        report_path = f"mcp_integration_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Detailed report saved to: {report_path}")


async def main():
    print("🚀 MCP SERVER INTEGRATION")
    print("📦 Installing Top Recommended Servers")
    print("="*80)
    
    integrator = MCPServerIntegrator()
    
    # Check npm availability
    if not await integrator.check_npm():
        print("\n⚠️ npm is required for MCP server installation")
        print("Please install Node.js and npm first")
        return 1
    
    # Install servers
    for server in RECOMMENDED_SERVERS:
        await integrator.install_server(server)
    
    # Create configurations
    if integrator.integrated > 0:
        await integrator.create_server_configs()
        await integrator.update_main_config()
    
    # Generate report
    integrator.generate_report()
    
    return 0 if integrator.integrated > 0 else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)