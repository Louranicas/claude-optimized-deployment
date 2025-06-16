#!/usr/bin/env python3
"""
Final MCP.so Server Integration
Installs verified and available MCP servers from mcp.so ecosystem
"""

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from datetime import datetime

# Verified available servers from mcp.so ecosystem
VERIFIED_MCPSO_SERVERS = [
    {
        "name": "tavily-mcp",
        "npm_package": "tavily-mcp",
        "description": "Advanced web search using Tavily API - alternative to Brave search",
        "category": "search",
        "capabilities": ["web_search", "ai_search", "real_time_search", "web_extraction"],
        "priority": 1,
        "config": {
            "api_key": os.environ.get("TAVILY_API_KEY", "")
        }
    },
    {
        "name": "sequential-thinking",
        "npm_package": "@modelcontextprotocol/server-sequential-thinking",
        "description": "Dynamic and reflective problem-solving for complex tasks",
        "category": "ai",
        "capabilities": ["sequential_reasoning", "problem_solving", "step_by_step_analysis"],
        "priority": 2
    },
    {
        "name": "redis",
        "npm_package": "@modelcontextprotocol/server-redis",
        "description": "Redis key-value store for caching and real-time data",
        "category": "database",
        "capabilities": ["caching", "key_value_store", "pub_sub", "real_time_data"],
        "priority": 3,
        "config": {
            "host": "localhost",
            "port": 6379
        }
    },
    {
        "name": "google-maps",
        "npm_package": "@modelcontextprotocol/server-google-maps",
        "description": "Google Maps API integration for location services",
        "category": "location",
        "capabilities": ["geocoding", "directions", "places_search", "distance_matrix"],
        "priority": 4,
        "config": {
            "api_key": os.environ.get("GOOGLE_MAPS_API_KEY", "")
        }
    },
    {
        "name": "gdrive",
        "npm_package": "@modelcontextprotocol/server-gdrive",
        "description": "Google Drive integration for cloud storage",
        "category": "storage",
        "capabilities": ["file_upload", "file_download", "folder_management", "sharing"],
        "priority": 5,
        "config": {
            "client_id": os.environ.get("GOOGLE_CLIENT_ID", ""),
            "client_secret": os.environ.get("GOOGLE_CLIENT_SECRET", "")
        }
    },
    {
        "name": "everything",
        "npm_package": "@modelcontextprotocol/server-everything",
        "description": "Comprehensive MCP server exercising all protocol features",
        "category": "utility",
        "capabilities": ["protocol_testing", "feature_demonstration", "debugging"],
        "priority": 6
    },
    {
        "name": "vercel-mcp-adapter",
        "npm_package": "@vercel/mcp-adapter",
        "description": "Vercel integration for Next.js and serverless deployments",
        "category": "deployment",
        "capabilities": ["vercel_deploy", "nextjs_integration", "serverless_functions"],
        "priority": 7
    },
    {
        "name": "smithery-sdk",
        "npm_package": "@smithery/sdk",
        "description": "SDK for developing and managing MCP servers with Smithery",
        "category": "development",
        "capabilities": ["server_development", "smithery_integration", "mcp_management"],
        "priority": 8
    }
]

class MCPSOFinalIntegrator:
    def __init__(self):
        self.base_dir = Path.cwd() / "mcp_servers"
        self.config_dir = Path.cwd() / "mcp_configs"
        self.results = []
        self.installed = 0
        self.failed = 0
        
    async def install_server(self, server):
        """Install a verified MCP server"""
        print(f"\n📦 Installing {server['name']}...")
        print(f"   Package: {server['npm_package']}")
        print(f"   Category: {server['category']}")
        
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
                    'package': server['npm_package'],
                    'category': server['category']
                })
                
                # Create configuration
                await self.create_server_config(server)
                return True
            else:
                print(f"❌ Failed to install {server['name']}")
                print(f"   Error: {result.stderr[:200]}")
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
        """Create configuration for installed server"""
        config = {
            "name": server['name'],
            "description": server['description'],
            "category": server['category'],
            "capabilities": server['capabilities'],
            "package": server['npm_package'],
            "settings": server.get('config', {})
        }
        
        config_file = self.config_dir / f"{server['name']}_mcpso.json"
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
            
        print(f"✅ Created config: {config_file}")
        
    async def update_claude_config(self):
        """Update Claude Desktop configuration with new servers"""
        print("\n📝 Updating Claude Desktop configuration...")
        
        claude_config_dir = Path.home() / "Library" / "Application Support" / "Claude"
        claude_config_dir.mkdir(parents=True, exist_ok=True)
        
        claude_config_file = claude_config_dir / "claude_desktop_config.json"
        
        # Load existing config
        if claude_config_file.exists():
            with open(claude_config_file, 'r') as f:
                config = json.load(f)
        else:
            config = {"mcpServers": {}}
            
        # Add new servers
        for result in self.results:
            if result['status'] in ['success', 'already_installed']:
                server = next(s for s in VERIFIED_MCPSO_SERVERS if s['name'] == result['server'])
                
                config['mcpServers'][server['name']] = {
                    "command": "npx",
                    "args": ["-y", server['npm_package']],
                    "env": {}
                }
                
                # Add environment variables
                if server.get('config'):
                    for key, value in server['config'].items():
                        if value:  # Only add if value exists
                            env_key = key.upper()
                            config['mcpServers'][server['name']]['env'][env_key] = value
                            
        # Save updated config
        with open(claude_config_file, 'w') as f:
            json.dump(config, f, indent=2)
            
        print(f"✅ Updated Claude Desktop config")
        
        # Create backup
        backup_file = self.config_dir / f"claude_config_mcpso_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(backup_file, 'w') as f:
            json.dump(config, f, indent=2)
            
        print(f"✅ Backup saved to: {backup_file}")
        
    def generate_report(self):
        """Generate final integration report"""
        print("\n" + "="*80)
        print("🎯 MCP.SO FINAL INTEGRATION REPORT")
        print("="*80)
        print(f"✅ Successfully Installed: {self.installed}")
        print(f"❌ Failed: {self.failed}")
        print(f"📦 Total Attempted: {len(VERIFIED_MCPSO_SERVERS)}")
        
        # Group by category
        categories = {}
        for result in self.results:
            if result['status'] in ['success', 'already_installed']:
                server = next(s for s in VERIFIED_MCPSO_SERVERS if s['name'] == result['server'])
                cat = server['category']
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(server['name'])
                
        if categories:
            print("\n📊 Installed by Category:")
            for cat, servers in sorted(categories.items()):
                print(f"  • {cat.title()}: {', '.join(servers)}")
                
        print("\n🚀 New Capabilities Added:")
        if 'search' in categories:
            print("  • Advanced AI-powered web search (Tavily)")
        if 'ai' in categories:
            print("  • Sequential thinking and complex reasoning")
        if 'database' in categories:
            print("  • High-performance caching with Redis")
        if 'location' in categories:
            print("  • Geospatial and mapping services")
        if 'storage' in categories:
            print("  • Cloud storage integration (Google Drive)")
        if 'deployment' in categories:
            print("  • Vercel serverless deployment")
        if 'development' in categories:
            print("  • Enhanced MCP server development tools")
            
        print("\n📈 Infrastructure Summary:")
        print(f"  • Previous MCP servers: 19")
        print(f"  • New servers added: {self.installed}")
        print(f"  • Total servers: {19 + self.installed}")
        print(f"  • Infrastructure growth: {(self.installed / 19 * 100):.1f}%")
        
        print("\n📝 Required Environment Variables:")
        env_needed = []
        for server in VERIFIED_MCPSO_SERVERS:
            if server.get('config'):
                for key, value in server['config'].items():
                    if not value and key.endswith('_key'):
                        env_needed.append(f"{server['name']}: {key.upper()}")
                        
        if env_needed:
            for env in env_needed:
                print(f"  • {env}")
                
        print("\n✨ Next Steps:")
        print("  1. Configure API keys for enhanced functionality")
        print("  2. Restart Claude Desktop to load new servers")
        print("  3. Test new capabilities in Claude")
        
        print("="*80)
        
        # Save report
        report = {
            'timestamp': datetime.now().isoformat(),
            'source': 'mcp.so',
            'summary': {
                'attempted': len(VERIFIED_MCPSO_SERVERS),
                'installed': self.installed,
                'failed': self.failed
            },
            'results': self.results,
            'servers': VERIFIED_MCPSO_SERVERS,
            'total_infrastructure': 19 + self.installed
        }
        
        report_path = f"mcpso_final_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
            
        print(f"\n📄 Detailed report saved to: {report_path}")


async def main():
    print("🚀 MCP.SO VERIFIED SERVER INSTALLATION")
    print("📦 Installing High-Value Servers from mcp.so")
    print("🔧 Enhancing Infrastructure with Specialized Capabilities")
    print("="*80)
    
    integrator = MCPSOFinalIntegrator()
    
    # Ensure directories exist
    integrator.base_dir.mkdir(exist_ok=True)
    integrator.config_dir.mkdir(exist_ok=True)
    
    # Install servers
    for server in sorted(VERIFIED_MCPSO_SERVERS, key=lambda x: x['priority']):
        await integrator.install_server(server)
        
    # Update Claude configuration
    if integrator.installed > 0:
        await integrator.update_claude_config()
        
    # Generate report
    integrator.generate_report()
    
    return 0 if integrator.installed > 0 else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)