#!/usr/bin/env python3
"""
Launch all MCP servers for the Claude-Optimized Deployment Engine.
"""

import os
import sys
import asyncio
import logging
from typing import Dict, Any, List

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.mcp.manager import MCPManager
from src.mcp.registry import MCPRegistry
from src.mcp.servers import BraveMCPServer
from src.mcp.devops_servers import DockerMCPServer, KubernetesMCPServer, GitMCPServer, GitHubMCPServer
from src.mcp.infrastructure_servers import (
    PrometheusMCPServer, CloudStorageMCPServer, S3MCPServer,
    SlackMCPServer, CommanderMCPServer
)
from src.mcp.security.sast_server import SASTMCPServer
from src.mcp.security.scanner_server import SecurityScannerMCPServer
from src.mcp.security.supply_chain_server import SupplyChainMCPServer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class MCPServerLauncher:
    """Launcher for all MCP servers."""
    
    def __init__(self):
        self.manager = MCPManager()
        self.servers = {}
        self.failed_servers = []
    
    async def launch_devops_servers(self):
        """Launch DevOps-related MCP servers."""
        logger.info("Launching DevOps MCP servers...")
        
        servers_config = [
            {
                "name": "docker",
                "class": DockerMCPServer,
                "config": {},
                "description": "Docker container management"
            },
            {
                "name": "kubernetes",
                "class": KubernetesMCPServer,
                "config": {},
                "description": "Kubernetes cluster management"
            },
            {
                "name": "git",
                "class": GitMCPServer,
                "config": {},
                "description": "Git repository operations"
            },
            {
                "name": "github",
                "class": GitHubMCPServer,
                "config": {"token": os.getenv("GITHUB_TOKEN")},
                "description": "GitHub API operations",
                "skip_if_no_env": "GITHUB_TOKEN"
            }
        ]
        
        for server_cfg in servers_config:
            await self._launch_server(server_cfg)
    
    async def launch_infrastructure_servers(self):
        """Launch infrastructure MCP servers."""
        logger.info("Launching Infrastructure MCP servers...")
        
        servers_config = [
            {
                "name": "prometheus",
                "class": PrometheusMCPServer,
                "config": {"url": os.getenv("PROMETHEUS_URL", "http://localhost:9090")},
                "description": "Prometheus metrics monitoring"
            },
            {
                "name": "s3",
                "class": S3MCPServer,
                "config": {
                    "access_key": os.getenv("AWS_ACCESS_KEY_ID"),
                    "secret_key": os.getenv("AWS_SECRET_ACCESS_KEY"),
                    "region": os.getenv("AWS_DEFAULT_REGION", "us-east-1")
                },
                "description": "AWS S3 storage operations",
                "skip_if_no_env": "AWS_ACCESS_KEY_ID"
            },
            {
                "name": "slack",
                "class": SlackMCPServer,
                "config": {"token": os.getenv("SLACK_TOKEN")},
                "description": "Slack messaging integration",
                "skip_if_no_env": "SLACK_TOKEN"
            },
            {
                "name": "commander",
                "class": CommanderMCPServer,
                "config": {},
                "description": "Infrastructure command execution"
            }
        ]
        
        for server_cfg in servers_config:
            await self._launch_server(server_cfg)
    
    async def launch_security_servers(self):
        """Launch security MCP servers."""
        logger.info("Launching Security MCP servers...")
        
        servers_config = [
            {
                "name": "sast",
                "class": SASTMCPServer,
                "config": {},
                "description": "Static Application Security Testing"
            },
            {
                "name": "security-scanner",
                "class": SecurityScannerMCPServer,
                "config": {},
                "description": "Comprehensive security scanning"
            },
            {
                "name": "supply-chain",
                "class": SupplyChainMCPServer,
                "config": {},
                "description": "Supply chain security analysis"
            }
        ]
        
        for server_cfg in servers_config:
            await self._launch_server(server_cfg)
    
    async def launch_search_servers(self):
        """Launch search and knowledge servers."""
        logger.info("Launching Search MCP servers...")
        
        servers_config = [
            {
                "name": "brave-search",
                "class": BraveMCPServer,
                "config": {"api_key": os.getenv("BRAVE_API_KEY")},
                "description": "Brave web search",
                "skip_if_no_env": "BRAVE_API_KEY"
            }
        ]
        
        for server_cfg in servers_config:
            await self._launch_server(server_cfg)
    
    async def _launch_server(self, server_cfg: Dict[str, Any]):
        """Launch a single MCP server."""
        name = server_cfg["name"]
        
        # Check if we should skip due to missing env vars
        if "skip_if_no_env" in server_cfg:
            env_var = server_cfg["skip_if_no_env"]
            if not os.getenv(env_var):
                logger.warning(f"⚠️  Skipping {name}: {env_var} not set")
                return
        
        try:
            # Create server instance
            server_class = server_cfg["class"]
            config = server_cfg.get("config", {})
            
            # Filter out None values from config
            config = {k: v for k, v in config.items() if v is not None}
            
            server = server_class(**config)
            
            # Register with manager
            self.manager.registry.register(server)
            self.servers[name] = server
            
            logger.info(f"✅ Launched {name}: {server_cfg['description']}")
            
        except Exception as e:
            logger.error(f"❌ Failed to launch {name}: {str(e)}")
            self.failed_servers.append((name, str(e)))
    
    async def launch_all(self):
        """Launch all MCP servers."""
        logger.info("=" * 60)
        logger.info("MCP Server Launcher - Starting all servers")
        logger.info("=" * 60)
        
        # Launch servers by category
        await self.launch_devops_servers()
        await self.launch_infrastructure_servers()
        await self.launch_security_servers()
        await self.launch_search_servers()
        
        # Summary
        logger.info("\n" + "=" * 60)
        logger.info("MCP Server Launch Summary")
        logger.info("=" * 60)
        logger.info(f"✅ Successfully launched: {len(self.servers)} servers")
        
        if self.servers:
            logger.info("\nActive servers:")
            for name, server in self.servers.items():
                info = server.get_server_info()
                logger.info(f"  - {name} v{info.version}: {info.description}")
        
        if self.failed_servers:
            logger.info(f"\n❌ Failed to launch: {len(self.failed_servers)} servers")
            for name, error in self.failed_servers:
                logger.info(f"  - {name}: {error}")
        
        # Show available tools
        logger.info("\n" + "-" * 60)
        logger.info("Available MCP Tools")
        logger.info("-" * 60)
        
        all_tools = self.manager.get_available_tools()
        logger.info(f"Total tools available: {len(all_tools)}")
        
        # Group tools by server
        tools_by_server = {}
        for tool in all_tools:
            server_name = tool["name"].split(".")[0]
            if server_name not in tools_by_server:
                tools_by_server[server_name] = []
            tools_by_server[server_name].append(tool["name"])
        
        for server_name, tools in sorted(tools_by_server.items()):
            logger.info(f"\n{server_name} ({len(tools)} tools):")
            for tool in sorted(tools):
                logger.info(f"  - {tool}")
        
        logger.info("\n" + "=" * 60)
        logger.info("MCP servers are ready for use!")
        logger.info("=" * 60)
        
        return self.manager

async def main():
    """Main entry point."""
    launcher = MCPServerLauncher()
    manager = await launcher.launch_all()
    
    # Keep servers running
    logger.info("\nMCP servers are running. Press Ctrl+C to stop.")
    try:
        # Keep the event loop running
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        logger.info("\nShutting down MCP servers...")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("\nShutdown complete.")