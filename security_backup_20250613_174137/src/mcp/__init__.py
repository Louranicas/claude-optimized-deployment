"""
Model Context Protocol (MCP) Integration for CODE

This module provides integration with MCP servers to enhance Claude Code's capabilities
with external tools and services.
"""

# Direct imports (safe)
from src.mcp.protocols import MCPRequest, MCPResponse, MCPTool
from src.mcp.client import MCPClient

__version__ = "0.1.0"
__all__ = [
    "MCPClient",
    "MCPRequest", 
    "MCPResponse",
    "MCPTool",
    "create_mcp_manager",
    "get_server_registry"
]

def create_mcp_manager(permission_checker, server_registry=None):
    """Factory function to create MCP Manager with dependency injection."""
    from src.mcp.manager import MCPManager
    from src.mcp.registry import get_server_registry as get_registry
    
    if server_registry is None:
        server_registry = get_registry(permission_checker)
    
    return MCPManager(server_registry)

def get_server_registry(permission_checker):
    """Factory function to get server registry."""
    from src.mcp.registry import get_server_registry as get_registry
    return get_registry(permission_checker)
