#!/usr/bin/env python3
"""
BASH GOD MCP CLIENT - Integration Interface
Client interface for communicating with the Bash God MCP Server
Provides high-level API for command execution and chain orchestration
"""

import asyncio
import json
import logging
import uuid
from typing import Dict, List, Any, Optional
import websockets
import aiohttp

logger = logging.getLogger('BashGodMCPClient')

class BashGodMCPClient:
    """Client for communicating with Bash God MCP Server"""
    
    def __init__(self, server_url: str = "ws://localhost:8080", timeout: int = 30):
        self.server_url = server_url
        self.timeout = timeout
        self.websocket = None
        self.request_id = 0
    
    def _get_next_request_id(self) -> int:
        """Get next request ID"""
        self.request_id += 1
        return self.request_id
    
    async def connect(self):
        """Connect to the MCP server"""
        try:
            self.websocket = await websockets.connect(self.server_url)
            logger.info(f"Connected to Bash God MCP Server at {self.server_url}")
        except Exception as e:
            logger.error(f"Failed to connect to server: {e}")
            raise
    
    async def disconnect(self):
        """Disconnect from the MCP server"""
        if self.websocket:
            await self.websocket.close()
            self.websocket = None
            logger.info("Disconnected from Bash God MCP Server")
    
    async def _send_request(self, method: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Send JSON-RPC 2.0 request to server"""
        if not self.websocket:
            await self.connect()
        
        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": self._get_next_request_id()
        }
        
        await self.websocket.send(json.dumps(request))
        response_str = await asyncio.wait_for(
            self.websocket.recv(), 
            timeout=self.timeout
        )
        
        response = json.loads(response_str)
        
        if "error" in response:
            raise Exception(f"Server error: {response['error']}")
        
        return response.get("result", {})
    
    async def list_commands(self, category: str = None, safety_level: str = None) -> List[Dict[str, Any]]:
        """List available bash commands"""
        params = {}
        if category:
            params["category"] = category
        if safety_level:
            params["safety_level"] = safety_level
        
        result = await self._send_request("bash_god/list_commands", params)
        return result.get("commands", [])
    
    async def execute_command(self, command_id: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute a single bash command"""
        params = {
            "command_id": command_id,
            "context": context or {}
        }
        
        return await self._send_request("bash_god/execute_command", params)
    
    async def execute_chain(self, chain_id: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute a command chain"""
        params = {
            "chain_id": chain_id,
            "context": context or {}
        }
        
        return await self._send_request("bash_god/execute_chain", params)
    
    async def search_commands(self, query: str) -> List[Dict[str, Any]]:
        """Search for commands by name or description"""
        params = {"query": query}
        result = await self._send_request("bash_god/search_commands", params)
        return result.get("commands", [])
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get system status and metrics"""
        return await self._send_request("bash_god/get_system_status")
    
    async def validate_command(self, command: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Validate a bash command for safety"""
        params = {
            "command": command,
            "context": context or {}
        }
        
        return await self._send_request("bash_god/validate_command", params)
    
    # High-level convenience methods
    
    async def system_health_check(self) -> Dict[str, Any]:
        """Perform comprehensive system health check"""
        return await self.execute_chain("system_health")
    
    async def performance_optimize(self) -> Dict[str, Any]:
        """Execute AMD Ryzen performance optimization"""
        return await self.execute_chain("performance_optimize")
    
    async def security_audit(self) -> Dict[str, Any]:
        """Perform comprehensive security audit"""
        return await self.execute_chain("security_audit")
    
    async def devops_pipeline(self) -> Dict[str, Any]:
        """Execute high-performance DevOps pipeline"""
        return await self.execute_chain("devops_pipeline")
    
    async def find_large_files(self, path: str = "/", size_mb: int = 100) -> Dict[str, Any]:
        """Find large files in filesystem"""
        context = {
            "path": path,
            "size_mb": size_mb
        }
        return await self.execute_command("sys_disk_usage", context)
    
    async def monitor_processes(self, limit: int = 20) -> Dict[str, Any]:
        """Monitor system processes"""
        context = {"limit": limit}
        return await self.execute_command("sys_process_monitor", context)
    
    async def optimize_amd_ryzen(self) -> Dict[str, Any]:
        """Apply AMD Ryzen specific optimizations"""
        context = {"amd_ryzen_optimizations": True}
        return await self.execute_command("perf_amd_ryzen_governor", context)

# Example usage
async def demo_bash_god_client():
    """Demonstration of Bash God MCP Client usage"""
    client = BashGodMCPClient()
    
    try:
        await client.connect()
        
        # List available commands
        print("=== Available Commands ===")
        commands = await client.list_commands(category="system_administration")
        for cmd in commands[:5]:
            print(f"- {cmd['name']}: {cmd['description']}")
        
        # Execute system health check
        print("\n=== System Health Check ===")
        health_result = await client.system_health_check()
        print(f"Health check completed in {health_result.get('duration', 0):.2f}s")
        
        # Search for performance commands
        print("\n=== Performance Commands ===")
        perf_commands = await client.search_commands("performance")
        for cmd in perf_commands[:3]:
            print(f"- {cmd['name']}")
        
        # Get system status
        print("\n=== System Status ===")
        status = await client.get_system_status()
        bash_god_info = status.get("bash_god", {})
        print(f"Commands loaded: {bash_god_info.get('commands_loaded', 0)}")
        print(f"Chains loaded: {bash_god_info.get('chains_loaded', 0)}")
        
        # Validate a command
        print("\n=== Command Validation ===")
        validation = await client.validate_command("rm -rf /tmp/*")
        print(f"Safety level: {validation.get('safety_level')}")
        print(f"Is safe: {validation.get('is_safe')}")
        if validation.get('warnings'):
            print(f"Warnings: {validation['warnings']}")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        await client.disconnect()

if __name__ == "__main__":
    asyncio.run(demo_bash_god_client())