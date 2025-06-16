"""
MCP Authentication Integration Module

Integrates authentication middleware with all MCP servers to ensure
secure access control across the platform.
"""

from typing import Dict, Any, Optional, List, Callable
import asyncio
import logging
from functools import wraps
import time

from ..protocols import MCPError
from ..servers import MCPServer
from ...auth.middleware import AuthMiddleware
from ...auth.models import User
from ...auth.rbac import RBACManager
from ...core.logging_config import get_logger

logger = get_logger(__name__)

# MCP server permissions mapping
MCP_PERMISSIONS = {
    "infrastructure-commander": {
        "execute_command": ["admin", "operator"],
        "make_command": ["admin", "operator", "developer"],
        "write_file": ["admin", "operator", "developer"],
        "docker_build": ["admin", "operator"],
        "kubectl_apply": ["admin", "operator"],
        "terraform_plan": ["admin"]
    },
    "slack-server": {
        "send_message": ["admin", "operator", "viewer"],
        "create_channel": ["admin", "operator"],
        "invite_user": ["admin", "operator"]
    },
    "prometheus-server": {
        "query_metrics": ["admin", "operator", "viewer"],
        "create_alert": ["admin", "operator"],
        "delete_alert": ["admin"]
    },
    "sast-security-server": {
        "run_security_scan": ["admin", "operator"],
        "get_scan_results": ["admin", "operator", "viewer"],
        "configure_rules": ["admin"]
    },
    "supply-chain-server": {
        "scan_dependencies": ["admin", "operator"],
        "get_vulnerability_report": ["admin", "operator", "viewer"],
        "update_policies": ["admin"]
    },
    "scanner-server": {
        "container_scan": ["admin", "operator"],
        "network_scan": ["admin"],
        "get_scan_history": ["admin", "operator", "viewer"]
    },
    "cloud-storage-server": {
        "upload_file": ["admin", "operator"],
        "download_file": ["admin", "operator", "viewer"],
        "list_files": ["admin", "operator", "viewer"],
        "delete_file": ["admin"]
    },
    "s3-server": {
        "create_bucket": ["admin"],
        "upload_object": ["admin", "operator"],
        "download_object": ["admin", "operator", "viewer"],
        "delete_object": ["admin"]
    },
    "devops-servers": {
        "deploy_application": ["admin", "operator"],
        "rollback_deployment": ["admin", "operator"],
        "get_deployment_status": ["admin", "operator", "viewer"],
        "scale_application": ["admin", "operator"]
    },
    "communication-hub": {
        "broadcast_message": ["admin"],
        "send_notification": ["admin", "operator"],
        "get_message_history": ["admin", "operator", "viewer"]
    }
}

# Rate limiting configurations per server
RATE_LIMITS = {
    "infrastructure-commander": {
        "execute_command": {"per_minute": 10, "burst": 3},
        "kubectl_apply": {"per_minute": 5, "burst": 1},
        "terraform_plan": {"per_minute": 3, "burst": 1}
    },
    "slack-server": {
        "send_message": {"per_minute": 30, "burst": 10}
    },
    "prometheus-server": {
        "query_metrics": {"per_minute": 100, "burst": 20}
    },
    "sast-security-server": {
        "run_security_scan": {"per_minute": 2, "burst": 1}
    },
    "supply-chain-server": {
        "scan_dependencies": {"per_minute": 5, "burst": 2}
    },
    "scanner-server": {
        "container_scan": {"per_minute": 5, "burst": 2},
        "network_scan": {"per_minute": 1, "burst": 1}
    }
}


class MCPAuthenticationError(MCPError):
    """MCP authentication specific error."""
    
    def __init__(self, message: str, code: int = -32000):
        super().__init__(code, message)


class MCPAuthorizationError(MCPError):
    """MCP authorization specific error."""
    
    def __init__(self, message: str, code: int = -32001):
        super().__init__(code, message)


class MCPRateLimitError(MCPError):
    """MCP rate limit specific error."""
    
    def __init__(self, message: str, code: int = -32002):
        super().__init__(code, message)


class MCPAuthMiddleware:
    """Authentication middleware for MCP servers."""
    
    def __init__(self, auth_middleware: AuthMiddleware, rbac_manager: RBACManager):
        """Initialize MCP authentication middleware."""
        self.auth_middleware = auth_middleware
        self.rbac_manager = rbac_manager
        
        # Rate limiting storage (use Redis in production)
        self.rate_limit_storage: Dict[str, List[float]] = {}
        
        # Audit logging
        self.audit_enabled = True
        self.audit_log: List[Dict[str, Any]] = []
    
    def require_auth(self, server_name: str, tool_name: str):
        """Decorator to require authentication for MCP tool calls."""
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            async def wrapper(self_server, *args, **kwargs):
                # Get current user from context
                current_user = getattr(self_server, '_current_user', None)
                
                if not current_user:
                    await self._audit_log_access_attempt(
                        server_name, tool_name, None, "AUTHENTICATION_FAILED", 
                        "No authentication provided"
                    )
                    raise MCPAuthenticationError(
                        f"Authentication required for {server_name}:{tool_name}"
                    )
                
                # Check authorization
                if not await self._check_authorization(current_user, server_name, tool_name):
                    await self._audit_log_access_attempt(
                        server_name, tool_name, current_user.id, "AUTHORIZATION_FAILED",
                        f"User {current_user.username} lacks permission"
                    )
                    raise MCPAuthorizationError(
                        f"Insufficient permissions for {server_name}:{tool_name}"
                    )
                
                # Check rate limits
                if not await self._check_rate_limits(current_user, server_name, tool_name):
                    await self._audit_log_access_attempt(
                        server_name, tool_name, current_user.id, "RATE_LIMIT_EXCEEDED",
                        f"Rate limit exceeded for {tool_name}"
                    )
                    raise MCPRateLimitError(
                        f"Rate limit exceeded for {server_name}:{tool_name}"
                    )
                
                # Log successful access
                await self._audit_log_access_attempt(
                    server_name, tool_name, current_user.id, "SUCCESS",
                    f"Tool executed successfully"
                )
                
                return await func(self_server, *args, **kwargs)
            
            return wrapper
        return decorator
    
    async def _check_authorization(self, user: User, server_name: str, tool_name: str) -> bool:
        """Check if user is authorized to call the tool."""
        # Check if server has permission requirements
        if server_name not in MCP_PERMISSIONS:
            logger.warning(f"No permission configuration for server: {server_name}")
            return True  # Allow by default if not configured
        
        server_perms = MCP_PERMISSIONS[server_name]
        
        # Check if tool has permission requirements
        if tool_name not in server_perms:
            logger.warning(f"No permission configuration for tool: {server_name}:{tool_name}")
            return True  # Allow by default if not configured
        
        required_roles = server_perms[tool_name]
        
        # Check if user has any of the required roles
        user_roles = set(user.roles) if hasattr(user, 'roles') and user.roles else set()
        required_roles_set = set(required_roles)
        
        has_permission = bool(user_roles.intersection(required_roles_set))
        
        logger.debug(f"Authorization check: user_roles={user_roles}, required={required_roles_set}, granted={has_permission}")
        
        return has_permission
    
    async def _check_rate_limits(self, user: User, server_name: str, tool_name: str) -> bool:
        """Check rate limits for user and tool."""
        # Get rate limit configuration
        if server_name not in RATE_LIMITS:
            return True  # No rate limits configured
        
        server_limits = RATE_LIMITS[server_name]
        if tool_name not in server_limits:
            return True  # No rate limits for this tool
        
        limits = server_limits[tool_name]
        per_minute = limits.get("per_minute", 60)
        burst = limits.get("burst", 10)
        
        # Create identifier
        identifier = f"{user.id}:{server_name}:{tool_name}"
        current_time = time.time()
        
        # Initialize storage
        if identifier not in self.rate_limit_storage:
            self.rate_limit_storage[identifier] = []
        
        # Clean old entries
        self.rate_limit_storage[identifier] = [
            t for t in self.rate_limit_storage[identifier]
            if current_time - t < 60  # Keep last minute
        ]
        
        history = self.rate_limit_storage[identifier]
        
        # Check burst limit
        recent_requests = [t for t in history if current_time - t < 1]
        if len(recent_requests) >= burst:
            return False
        
        # Check per-minute limit
        if len(history) >= per_minute:
            return False
        
        # Record request
        self.rate_limit_storage[identifier].append(current_time)
        return True
    
    async def _audit_log_access_attempt(self, server_name: str, tool_name: str, 
                                      user_id: Optional[str], status: str, message: str):
        """Log access attempt for audit trail."""
        if not self.audit_enabled:
            return
        
        audit_entry = {
            "timestamp": time.time(),
            "server_name": server_name,
            "tool_name": tool_name,
            "user_id": user_id,
            "status": status,
            "message": message,
            "ip_address": "unknown"  # Could be extracted from request context
        }
        
        self.audit_log.append(audit_entry)
        
        # Keep only last 10000 entries
        if len(self.audit_log) > 10000:
            self.audit_log = self.audit_log[-10000:]
        
        # Log to system logger
        logger.info(f"MCP Access: {status} - {server_name}:{tool_name} - User: {user_id} - {message}")
    
    def inject_user_context(self, server: MCPServer, user: User):
        """Inject user context into MCP server instance."""
        server._current_user = user
        server._auth_context = {
            "user_id": user.id,
            "username": user.username,
            "roles": user.roles if hasattr(user, 'roles') else [],
            "permissions": list(user.permissions) if hasattr(user, 'permissions') else [],
            "authenticated_at": time.time()
        }
    
    def get_audit_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent audit logs."""
        return self.audit_log[-limit:]
    
    def clear_audit_logs(self):
        """Clear audit logs."""
        self.audit_log.clear()
    
    def get_rate_limit_status(self, user_id: str) -> Dict[str, Any]:
        """Get rate limit status for user."""
        current_time = time.time()
        status = {}
        
        for identifier, history in self.rate_limit_storage.items():
            if identifier.startswith(f"{user_id}:"):
                parts = identifier.split(":")
                if len(parts) >= 3:
                    server_name = parts[1]
                    tool_name = parts[2]
                    
                    # Clean old entries
                    recent_history = [t for t in history if current_time - t < 60]
                    
                    status[f"{server_name}:{tool_name}"] = {
                        "requests_last_minute": len(recent_history),
                        "next_reset": int(current_time + 60) if recent_history else None
                    }
        
        return status


def integrate_auth_with_server(server: MCPServer, auth_middleware: MCPAuthMiddleware, 
                              server_name: str) -> MCPServer:
    """Integrate authentication with an MCP server."""
    
    # Get original tool methods
    original_call_tool = server.call_tool
    
    # Wrap call_tool with authentication
    @wraps(original_call_tool)
    async def authenticated_call_tool(tool_name: str, arguments: Dict[str, Any]) -> Any:
        # Check if authentication is required for this tool
        if server_name in MCP_PERMISSIONS and tool_name in MCP_PERMISSIONS[server_name]:
            current_user = getattr(server, '_current_user', None)
            
            if not current_user:
                raise MCPAuthenticationError(
                    f"Authentication required for {server_name}:{tool_name}"
                )
            
            # Check authorization
            if not await auth_middleware._check_authorization(current_user, server_name, tool_name):
                raise MCPAuthorizationError(
                    f"Insufficient permissions for {server_name}:{tool_name}"
                )
            
            # Check rate limits
            if not await auth_middleware._check_rate_limits(current_user, server_name, tool_name):
                raise MCPRateLimitError(
                    f"Rate limit exceeded for {server_name}:{tool_name}"
                )
            
            # Log access attempt
            await auth_middleware._audit_log_access_attempt(
                server_name, tool_name, current_user.id, "SUCCESS",
                f"Tool executed successfully"
            )
        
        # Call original method
        return await original_call_tool(tool_name, arguments)
    
    # Replace the method
    server.call_tool = authenticated_call_tool
    
    return server


async def setup_mcp_authentication(servers: Dict[str, MCPServer], 
                                 auth_middleware: AuthMiddleware,
                                 rbac_manager: RBACManager) -> Dict[str, MCPServer]:
    """Set up authentication for all MCP servers."""
    
    mcp_auth = MCPAuthMiddleware(auth_middleware, rbac_manager)
    authenticated_servers = {}
    
    for server_name, server in servers.items():
        logger.info(f"Integrating authentication with {server_name}")
        authenticated_servers[server_name] = integrate_auth_with_server(
            server, mcp_auth, server_name
        )
    
    logger.info(f"Authentication integrated with {len(authenticated_servers)} MCP servers")
    return authenticated_servers


__all__ = [
    "MCPAuthMiddleware",
    "MCPAuthenticationError", 
    "MCPAuthorizationError",
    "MCPRateLimitError",
    "integrate_auth_with_server",
    "setup_mcp_authentication"
]