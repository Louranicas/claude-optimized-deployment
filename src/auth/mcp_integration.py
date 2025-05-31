"""MCP Server Authentication Integration.

Integrates RBAC with MCP servers to check permissions before tool execution.
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import asyncio

from ..mcp.protocols import MCPServer, MCPTool
from .permissions import PermissionChecker, ResourceType
from .models import User


@dataclass
class AuthenticatedMCPContext:
    """Context for authenticated MCP operations."""
    user: User
    session_id: str
    permissions: List[str]
    metadata: Dict[str, Any]


class AuthenticatedMCPServer(MCPServer):
    """MCP Server wrapper with authentication and authorization."""
    
    def __init__(self, server: MCPServer, permission_checker: PermissionChecker):
        """
        Initialize authenticated MCP server.
        
        Args:
            server: Original MCP server instance
            permission_checker: Permission checker instance
        """
        self.server = server
        self.permission_checker = permission_checker
        self._context: Optional[AuthenticatedMCPContext] = None
    
    def set_context(self, context: AuthenticatedMCPContext) -> None:
        """Set authentication context for requests."""
        self._context = context
    
    def get_server_info(self) -> Dict[str, Any]:
        """Get server information."""
        return self.server.get_server_info()
    
    def get_tools(self) -> List[MCPTool]:
        """Get available tools, filtered by permissions."""
        if not self._context:
            return []
        
        all_tools = self.server.get_tools()
        filtered_tools = []
        
        for tool in all_tools:
            # Check if user has permission for this tool
            resource = f"mcp.{self.server.__class__.__name__.lower()}"
            if self._check_tool_permission(resource, tool.name):
                filtered_tools.append(tool)
        
        return filtered_tools
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Call a tool with permission checking."""
        if not self._context:
            raise PermissionError("No authentication context provided")
        
        # Build resource identifier
        server_name = self.server.__class__.__name__.lower().replace("mcp", "")
        resource = f"mcp.{server_name}"
        
        # Check permission
        if not self._check_tool_permission(resource, tool_name):
            raise PermissionError(f"Permission denied for tool: {tool_name}")
        
        # Audit the tool call
        await self._audit_tool_call(tool_name, arguments)
        
        # Call the original tool
        try:
            result = await self.server.call_tool(tool_name, arguments)
            
            # Audit successful execution
            await self._audit_tool_success(tool_name, result)
            
            return result
            
        except Exception as e:
            # Audit failure
            await self._audit_tool_failure(tool_name, str(e))
            raise
    
    def _check_tool_permission(self, resource: str, tool_name: str) -> bool:
        """Check if user has permission to use a tool."""
        if not self._context:
            return False
        
        # Admin users have full access
        if "admin" in self._context.user.roles:
            return True
        
        # Check specific tool permission
        specific_resource = f"{resource}.{tool_name}"
        context = {
            "session_id": self._context.session_id,
            "tool_name": tool_name,
            "metadata": self._context.metadata
        }
        
        # Check both specific tool and general server permission
        return (
            self.permission_checker.check_permission(
                self._context.user.id,
                self._context.user.roles,
                specific_resource,
                "execute",
                context
            ) or
            self.permission_checker.check_permission(
                self._context.user.id,
                self._context.user.roles,
                resource,
                "execute",
                context
            )
        )
    
    async def _audit_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> None:
        """Audit tool call attempt."""
        # In a real implementation, this would log to an audit service
        audit_entry = {
            "timestamp": asyncio.get_event_loop().time(),
            "user_id": self._context.user.id,
            "session_id": self._context.session_id,
            "action": "mcp_tool_call",
            "resource": f"{self.server.__class__.__name__}.{tool_name}",
            "arguments": arguments,
            "status": "attempted"
        }
        # Log audit entry
        print(f"AUDIT: {audit_entry}")
    
    async def _audit_tool_success(self, tool_name: str, result: Any) -> None:
        """Audit successful tool execution."""
        audit_entry = {
            "timestamp": asyncio.get_event_loop().time(),
            "user_id": self._context.user.id,
            "session_id": self._context.session_id,
            "action": "mcp_tool_success",
            "resource": f"{self.server.__class__.__name__}.{tool_name}",
            "status": "success"
        }
        print(f"AUDIT: {audit_entry}")
    
    async def _audit_tool_failure(self, tool_name: str, error: str) -> None:
        """Audit tool execution failure."""
        audit_entry = {
            "timestamp": asyncio.get_event_loop().time(),
            "user_id": self._context.user.id,
            "session_id": self._context.session_id,
            "action": "mcp_tool_failure",
            "resource": f"{self.server.__class__.__name__}.{tool_name}",
            "error": error,
            "status": "failed"
        }
        print(f"AUDIT: {audit_entry}")


class AuthenticatedMCPManager:
    """MCP Manager with authentication support."""
    
    def __init__(self, mcp_manager: Any, permission_checker: PermissionChecker):
        """
        Initialize authenticated MCP manager.
        
        Args:
            mcp_manager: Original MCP manager instance
            permission_checker: Permission checker instance
        """
        self.mcp_manager = mcp_manager
        self.permission_checker = permission_checker
        self._authenticated_servers: Dict[str, AuthenticatedMCPServer] = {}
    
    async def initialize(self, context: AuthenticatedMCPContext) -> None:
        """Initialize with authentication context."""
        # Initialize underlying manager
        await self.mcp_manager.initialize()
        
        # Wrap all servers with authentication
        for server_name, server in self.mcp_manager.registry.servers.items():
            auth_server = AuthenticatedMCPServer(server, self.permission_checker)
            auth_server.set_context(context)
            self._authenticated_servers[server_name] = auth_server
    
    def get_available_servers(self, user: User) -> List[str]:
        """Get list of servers available to user."""
        available = []
        
        for server_name in self.mcp_manager.registry.servers.keys():
            resource = f"mcp.{server_name}"
            
            # Check if user has any permission on this server
            if self.permission_checker.check_permission(
                user.id, user.roles, resource, "read"
            ):
                available.append(server_name)
        
        return available
    
    def get_available_tools(self, user: User) -> List[Dict[str, Any]]:
        """Get all tools available to user across all servers."""
        context = AuthenticatedMCPContext(
            user=user,
            session_id="temp",
            permissions=list(user.permissions),
            metadata={}
        )
        
        available_tools = []
        
        for server_name, server in self.mcp_manager.registry.servers.items():
            auth_server = AuthenticatedMCPServer(server, self.permission_checker)
            auth_server.set_context(context)
            
            # Get filtered tools
            tools = auth_server.get_tools()
            
            for tool in tools:
                available_tools.append({
                    "server": server_name,
                    "tool": tool.name,
                    "description": tool.description,
                    "parameters": [p.to_dict() for p in tool.parameters]
                })
        
        return available_tools
    
    async def call_tool(self, context: AuthenticatedMCPContext,
                       server_name: str, tool_name: str,
                       arguments: Dict[str, Any]) -> Any:
        """Call a tool with authentication context."""
        # Get or create authenticated server
        if server_name not in self._authenticated_servers:
            if server_name not in self.mcp_manager.registry.servers:
                raise ValueError(f"Server not found: {server_name}")
            
            server = self.mcp_manager.registry.servers[server_name]
            auth_server = AuthenticatedMCPServer(server, self.permission_checker)
            self._authenticated_servers[server_name] = auth_server
        
        # Set context and call tool
        auth_server = self._authenticated_servers[server_name]
        auth_server.set_context(context)
        
        return await auth_server.call_tool(tool_name, arguments)
    
    def register_mcp_permissions(self) -> None:
        """Register default MCP permissions in RBAC system."""
        # Define MCP server permissions
        mcp_resources = {
            "mcp.desktop": ["execute_command", "make_command", "write_file"],
            "mcp.docker": ["docker_build", "docker_run", "docker_ps", "docker_stop"],
            "mcp.kubernetes": ["kubectl_apply", "kubectl_get", "kubectl_delete"],
            "mcp.azure_devops": ["list_projects", "create_pipeline", "manage_work_items"],
            "mcp.windows": ["powershell_command", "registry_operations", "service_management"],
            "mcp.prometheus": ["prometheus_query", "prometheus_query_range", "prometheus_targets"],
            "mcp.security_scanner": ["npm_audit", "python_safety_check", "docker_security_scan", "file_security_scan"],
            "mcp.slack": ["send_notification", "post_message", "list_channels"],
            "mcp.s3": ["s3_upload_file", "s3_list_buckets", "s3_create_presigned_url"],
            "mcp.brave_search": ["brave_web_search", "brave_news_search", "brave_image_search"],
        }
        
        # Register each resource and its tools
        for resource, tools in mcp_resources.items():
            # Register resource-level permissions
            self.permission_checker.register_resource_permission(
                ResourceType.MCP_SERVER,
                resource,
                initial_permissions={
                    "role:admin": {"*": True},
                    "role:operator": {"execute": True, "read": True},
                    "role:viewer": {"read": True},
                    "role:mcp_service": {"*": True}
                }
            )
            
            # Register tool-specific permissions
            for tool in tools:
                tool_resource = f"{resource}.{tool}"
                self.permission_checker.register_resource_permission(
                    ResourceType.MCP_TOOL,
                    tool_resource,
                    initial_permissions={
                        "role:admin": {"*": True},
                        "role:mcp_service": {"execute": True}
                    }
                )
    
    def get_permission_matrix(self) -> Dict[str, Dict[str, List[str]]]:
        """Get permission matrix for all MCP resources."""
        matrix = {}
        
        # Get all registered MCP resources
        for resource_key, resource_perm in self.permission_checker.resource_permissions.items():
            if resource_perm.resource_type in [ResourceType.MCP_SERVER, ResourceType.MCP_TOOL]:
                if resource_perm.resource_id not in matrix:
                    matrix[resource_perm.resource_id] = {}
                
                # Extract permissions by principal
                for principal, perms in resource_perm.permissions.items():
                    if isinstance(perms, dict):
                        matrix[resource_perm.resource_id][principal] = list(perms.keys())
                    else:
                        matrix[resource_perm.resource_id][principal] = ["*"]
        
        return matrix