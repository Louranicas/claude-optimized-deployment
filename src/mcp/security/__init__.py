"""
Security MCP servers for the CODE project.

Military-grade security scanning with zero-trust architecture and
comprehensive authentication middleware.
"""

from src.mcp.security.scanner_server import SecurityScannerMCPServer
from src.mcp.security.auth_middleware import (
    MCPAuthMiddleware,
    UserRole,
    Permission,
    AuthContext,
    require_auth,
    get_auth_middleware,
    session_cleanup_task
)

# Backward compatibility alias
SecurityScannerMCP = SecurityScannerMCPServer

__all__ = [
    "SecurityScannerMCPServer", 
    "SecurityScannerMCP",
    "MCPAuthMiddleware",
    "UserRole", 
    "Permission",
    "AuthContext",
    "require_auth",
    "get_auth_middleware",
    "session_cleanup_task"
]