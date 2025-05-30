"""
Model Context Protocol (MCP) Integration for CODE

This module provides integration with MCP servers to enhance Claude Code's capabilities
with external tools and services.
"""

from .client import MCPClient
from .servers import BraveMCPServer, MCPServerRegistry
from .protocols import MCPRequest, MCPResponse, MCPTool
from .manager import MCPManager

__version__ = "0.1.0"
__all__ = [
    "MCPClient",
    "BraveMCPServer",
    "MCPServerRegistry",
    "MCPRequest",
    "MCPResponse",
    "MCPTool",
    "MCPManager"
]
