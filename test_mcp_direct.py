#!/usr/bin/env python3
"""
Direct MCP Server Testing - Minimal Dependencies
Tests MCP servers directly without complex initialization
"""

import asyncio
import json
import sys
import os
from pathlib import Path
from datetime import datetime
import time
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))


class DirectMCPTester:
    """Direct MCP server tester"""
    
    def __init__(self):
        self.results = {}
        self.start_time = datetime.now()
        
    async def test_mcp_initialization(self):
        """Test basic MCP initialization"""
        logger.info("Testing MCP initialization...")
        
        try:
            # Test import
            logger.info("Testing imports...")
            from src.mcp import manager
            logger.info("✅ MCP manager module imported")
            
            from src.mcp.servers import MCPServerRegistry
            logger.info("✅ MCP server registry imported")
            
            # Test server registration
            logger.info("\nTesting server registration...")
            registry = MCPServerRegistry()
            
            # Check available servers
            server_count = len(registry.servers) if hasattr(registry, 'servers') else 0
            logger.info(f"📦 Found {server_count} registered servers")
            
            if hasattr(registry, 'servers'):
                for server_name in registry.servers:
                    logger.info(f"  - {server_name}")
            
            self.results['initialization'] = {
                'success': True,
                'server_count': server_count,
                'servers': list(registry.servers.keys()) if hasattr(registry, 'servers') else []
            }
            
        except Exception as e:
            logger.error(f"❌ Initialization failed: {e}")
            self.results['initialization'] = {
                'success': False,
                'error': str(e)
            }
            return False
        
        return True
    
    async def test_mcp_tools(self):
        """Test MCP tool execution"""
        logger.info("\nTesting MCP tool execution...")
        
        try:
            from src.mcp.manager import get_mcp_manager
            
            # Set minimal environment
            os.environ.setdefault('ENVIRONMENT', 'test')
            
            # Initialize manager
            manager = get_mcp_manager()
            
            # Try to initialize
            await manager.initialize()
            
            # Test a simple tool if available
            if hasattr(manager, 'call_tool'):
                logger.info("✅ MCP manager has call_tool method")
                
                # Try a safe test
                try:
                    # Test with echo command (safe)
                    result = await manager.call_tool(
                        "desktop-commander.execute_command",
                        {"command": "echo 'MCP Test Active'"}
                    )
                    logger.info(f"✅ Tool execution successful: {result}")
                    self.results['tool_execution'] = {
                        'success': True,
                        'test_result': str(result)
                    }
                except Exception as e:
                    logger.warning(f"⚠️ Tool execution failed: {e}")
                    self.results['tool_execution'] = {
                        'success': False,
                        'error': str(e)
                    }
            
        except Exception as e:
            logger.error(f"❌ MCP tools test failed: {e}")
            self.results['tool_execution'] = {
                'success': False,
                'error': str(e)
            }
    
    async def test_server_health(self):
        """Test server health checks"""
        logger.info("\nTesting server health checks...")
        
        server_health = {}
        
        # List of servers to check
        servers_to_check = [
            "brave",
            "desktop-commander", 
            "docker",
            "kubernetes",
            "azure-devops",
            "windows-system",
            "prometheus-monitoring",
            "security-scanner",
            "slack-notifications",
            "s3-storage",
            "cloud-storage"
        ]
        
        for server in servers_to_check:
            try:
                # Check if server module exists
                module_path = f"src.mcp.servers.{server.replace('-', '_')}"
                __import__(module_path)
                server_health[server] = "✅ Available"
                logger.info(f"  {server}: ✅ Module found")
            except ImportError:
                server_health[server] = "❌ Not found"
                logger.warning(f"  {server}: ❌ Module not found")
            except Exception as e:
                server_health[server] = f"⚠️ Error: {str(e)}"
                logger.error(f"  {server}: ⚠️ Error: {e}")
        
        self.results['server_health'] = server_health
    
    def generate_report(self):
        """Generate test report"""
        duration = (datetime.now() - self.start_time).total_seconds()
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'duration': duration,
            'results': self.results
        }
        
        # Display summary
        print("\n" + "="*60)
        print("MCP SERVER TEST REPORT")
        print("="*60)
        print(f"Duration: {duration:.2f}s")
        print(f"\nInitialization: {'✅ Success' if self.results.get('initialization', {}).get('success') else '❌ Failed'}")
        
        if 'initialization' in self.results and self.results['initialization'].get('success'):
            print(f"Servers found: {self.results['initialization'].get('server_count', 0)}")
            servers = self.results['initialization'].get('servers', [])
            if servers:
                print("Available servers:")
                for server in servers:
                    print(f"  - {server}")
        
        if 'server_health' in self.results:
            print("\nServer Health:")
            for server, status in self.results['server_health'].items():
                print(f"  {server}: {status}")
        
        # Save report
        report_path = f"mcp_direct_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\nReport saved to: {report_path}")
        print("="*60)


async def main():
    """Run direct MCP tests"""
    print("🔍 DIRECT MCP SERVER TESTING")
    print("="*60)
    
    tester = DirectMCPTester()
    
    # Run tests
    await tester.test_mcp_initialization()
    await tester.test_mcp_tools()
    await tester.test_server_health()
    
    # Generate report
    tester.generate_report()
    
    # Check overall success
    init_success = tester.results.get('initialization', {}).get('success', False)
    
    if init_success:
        print("\n✅ Basic MCP functionality verified")
        return 0
    else:
        print("\n❌ MCP initialization issues detected")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)