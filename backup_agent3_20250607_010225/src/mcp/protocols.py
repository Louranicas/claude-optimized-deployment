"""
MCP Protocol definitions and data models.

Based on the Model Context Protocol specification for tool integration.
"""

from __future__ import annotations
from typing import Dict, Any, List, Optional, Union
from enum import Enum
from pydantic import BaseModel, Field
from datetime import datetime
import uuid
import logging
from functools import wraps

# Authentication components imported lazily to avoid circular imports
from src.core.exceptions import AuthenticationError, PermissionDeniedError

logger = logging.getLogger(__name__)


class MCPMessageType(str, Enum):
    """MCP message types."""
    REQUEST = "request"
    RESPONSE = "response"
    NOTIFICATION = "notification"
    ERROR = "error"


class MCPMethod(str, Enum):
    """Standard MCP methods."""
    # Tool methods
    TOOLS_LIST = "tools/list"
    TOOLS_CALL = "tools/call"
    
    # Resource methods
    RESOURCES_LIST = "resources/list"
    RESOURCES_READ = "resources/read"
    
    # Prompt methods
    PROMPTS_LIST = "prompts/list"
    PROMPTS_GET = "prompts/get"
    
    # Server methods
    INITIALIZE = "initialize"
    SHUTDOWN = "shutdown"
    PING = "ping"


class MCPToolParameter(BaseModel):
    """Parameter definition for MCP tools."""
    name: str
    type: str = "string"
    description: Optional[str] = None
    required: bool = True
    enum: Optional[List[str]] = None
    default: Optional[Any] = None


class MCPTool(BaseModel):
    """MCP tool definition."""
    name: str
    description: str
    parameters: List[MCPToolParameter] = Field(default_factory=list)
    returns: Optional[Dict[str, Any]] = None
    examples: Optional[List[Dict[str, Any]]] = None
    
    def to_claude_format(self) -> Dict[str, Any]:
        """Convert to Claude tool format."""
        properties = {}
        required = []
        
        for param in self.parameters:
            properties[param.name] = {
                "type": param.type,
                "description": param.description or ""
            }
            if param.enum:
                properties[param.name]["enum"] = param.enum
            if param.default is not None:
                properties[param.name]["default"] = param.default
            
            if param.required:
                required.append(param.name)
        
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": {
                "type": "object",
                "properties": properties,
                "required": required
            }
        }


class MCPRequest(BaseModel):
    """MCP request message."""
    jsonrpc: str = "2.0"
    id: Union[str, int] = Field(default_factory=lambda: str(uuid.uuid4()))
    method: str
    params: Optional[Dict[str, Any]] = None
    
    class Config:
        use_enum_values = True


class MCPResponse(BaseModel):
    """MCP response message."""
    jsonrpc: str = "2.0"
    id: Union[str, int]
    result: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None
    
    @property
    def is_error(self) -> bool:
        """Check if response is an error."""
        return self.error is not None
    
    def raise_for_error(self) -> None:
        """Raise exception if response contains error."""
        if self.error:
            raise MCPError(
                code=self.error.get("code", -1),
                message=self.error.get("message", "Unknown error"),
                data=self.error.get("data")
            )


class MCPNotification(BaseModel):
    """MCP notification message."""
    jsonrpc: str = "2.0"
    method: str
    params: Optional[Dict[str, Any]] = None


class MCPError(Exception):
    """MCP protocol error."""
    def __init__(self, code: int, message: str, data: Optional[Any] = None):
        self.code = code
        self.message = message
        self.data = data
        super().__init__(f"MCP Error {code}: {message}")


class MCPCapabilities(BaseModel):
    """Server capabilities."""
    tools: bool = True
    resources: bool = False
    prompts: bool = False
    experimental: Dict[str, Any] = Field(default_factory=dict)


class MCPServerInfo(BaseModel):
    """MCP server information."""
    name: str
    version: str
    description: Optional[str] = None
    capabilities: MCPCapabilities = Field(default_factory=MCPCapabilities)


class BraveSearchResult(BaseModel):
    """Brave search result model."""
    title: str
    url: str
    description: str
    snippet: Optional[str] = None
    date: Optional[datetime] = None
    thumbnail: Optional[str] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class BraveSearchResponse(BaseModel):
    """Brave search response model."""
    query: str
    results: List[BraveSearchResult]
    total_results: Optional[int] = None
    search_time: Optional[float] = None
    
    def to_mcp_response(self, request_id: Union[str, int]) -> MCPResponse:
        """Convert to MCP response format."""
        return MCPResponse(
            id=request_id,
            result={
                "query": self.query,
                "results": [r.dict() for r in self.results],
                "metadata": {
                    "total_results": self.total_results,
                    "search_time": self.search_time
                }
            }
        )


class MCPServer:
    """Base class for MCP servers with built-in authentication."""
    
    def __init__(self, name: str, version: str = "1.0.0", 
                 permission_checker: Optional[Any] = None):
        self.name = name
        self.version = version
        self.capabilities = MCPCapabilities()
        self.permission_checker = permission_checker
        
        # Default permissions required for this server
        self.required_permissions = {
            "list_tools": f"mcp.{name}:list",
            "call_tool": f"mcp.{name}:execute",
            "get_info": f"mcp.{name}:read"
        }
        
        # Tool-specific permissions (can be overridden by subclasses)
        self.tool_permissions: Dict[str, str] = {}
    
    def get_server_info(self, user: Any) -> MCPServerInfo:
        """
        Get server information.
        
        Args:
            user: User for permission checking (REQUIRED)
            
        Returns:
            Server information
            
        Raises:
            AuthenticationError: If no user provided
            PermissionDeniedError: If user lacks permission
        """
        # SECURITY FIX: User parameter is now required (not Optional)
        if not user:
            raise AuthenticationError("Authentication required to get server info")
            
        # Check read permission (always required now)
        if not self._check_permission(user, self.required_permissions["get_info"]):
            raise PermissionDeniedError(
                f"Permission denied: {self.required_permissions['get_info']}"
            )
        
        return MCPServerInfo(
            name=self.name,
            version=self.version,
            capabilities=self.capabilities
        )
    
    def get_tools(self, user: Any) -> List[MCPTool]:
        """
        Get available tools.
        
        Args:
            user: User for permission checking (REQUIRED)
            
        Returns:
            List of available tools (filtered by permissions)
            
        Raises:
            AuthenticationError: If no user provided
            PermissionDeniedError: If user lacks permission to list tools
        """
        # SECURITY FIX: User parameter is now required (not Optional)
        if not user:
            raise AuthenticationError("Authentication required to list tools")
            
        # Check list permission (always required now)
        if not self._check_permission(user, self.required_permissions["list_tools"]):
            raise PermissionDeniedError(
                f"Permission denied: {self.required_permissions['list_tools']}"
            )
        
        # Get all tools from implementation
        all_tools = self._get_all_tools()
        
        # Filter tools based on user permissions (always required now)
        filtered_tools = []
        for tool in all_tools:
            # Check if user has permission for this specific tool
            tool_permission = self.tool_permissions.get(
                tool.name, 
                f"mcp.{self.name}.{tool.name}:execute"
            )
            if self._check_permission(user, tool_permission):
                filtered_tools.append(tool)
        return filtered_tools
    
    def _get_all_tools(self) -> List[MCPTool]:
        """Get all available tools. Must be implemented by subclasses."""
        raise NotImplementedError
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any], 
                       user: Any, context: Optional[Dict[str, Any]] = None) -> Any:
        """
        Call a tool with authentication and permission checking.
        
        Args:
            tool_name: Name of the tool to call
            arguments: Tool arguments
            user: User making the request (REQUIRED - no longer optional)
            context: Additional context for permission checking (user_context)
            
        Returns:
            Tool execution result
            
        Raises:
            AuthenticationError: If no user provided or invalid user
            PermissionDeniedError: If user lacks permission
            MCPError: If tool execution fails
        """
        # SECURITY FIX: User parameter is now required (not Optional)
        # This prevents authentication bypass when user is None
        if not user or not hasattr(user, 'id') or not hasattr(user, 'username'):
            raise AuthenticationError("Valid authenticated user required to call tools")
        
        # Check general execution permission
        if self.permission_checker:
            if not self._check_permission(user, self.required_permissions["call_tool"], context):
                raise PermissionDeniedError(
                    f"Permission denied: {self.required_permissions['call_tool']}"
                )
            
            # Check tool-specific permission
            tool_permission = self.tool_permissions.get(
                tool_name,
                f"mcp.{self.name}.{tool_name}:execute"
            )
            if not self._check_permission(user, tool_permission, context):
                raise PermissionDeniedError(
                    f"Permission denied for tool {tool_name}: {tool_permission}"
                )
        
        # Build user_context for auditing and permission checking
        user_context = context or {}
        user_context["user_id"] = user.id
        user_context["username"] = user.username
        
        # Log the tool call for auditing
        logger.info(
            f"User {user.username} calling tool {tool_name} on server {self.name}",
            extra={
                "user_id": user.id,
                "server": self.name,
                "tool": tool_name,
                "user_context": user_context
            }
        )
        
        try:
            # Call the actual tool implementation with user_context
            result = await self._call_tool_impl(tool_name, arguments, user, user_context)
            
            # Log successful execution
            logger.info(
                f"Tool {tool_name} executed successfully by user {user.username}",
                extra={
                    "user_id": user.id,
                    "server": self.name,
                    "tool": tool_name,
                    "success": True
                }
            )
            
            return result
            
        except Exception as e:
            # Log failed execution
            logger.error(
                f"Tool {tool_name} execution failed for user {user.username}: {str(e)}",
                extra={
                    "user_id": user.id,
                    "server": self.name,
                    "tool": tool_name,
                    "success": False,
                    "error": str(e)
                }
            )
            raise
    
    async def _call_tool_impl(self, tool_name: str, arguments: Dict[str, Any], 
                             user: Any, context: Optional[Dict[str, Any]] = None) -> Any:
        """
        Actual tool implementation. Must be implemented by subclasses.
        
        Args:
            tool_name: Name of the tool to call
            arguments: Tool arguments
            user: Authenticated user
            context: Additional context
            
        Returns:
            Tool execution result
        """
        raise NotImplementedError
    
    def _check_permission(self, user: Any, permission: str, 
                         context: Optional[Dict[str, Any]] = None) -> bool:
        """
        Check if user has permission.
        
        Args:
            user: User to check
            permission: Permission string (e.g., "mcp.docker:execute")
            context: Additional context for permission checking
            
        Returns:
            True if permission granted, False otherwise
            
        Raises:
            PermissionDeniedError: If no permission checker is configured (security hardening)
        """
        if not self.permission_checker:
            # SECURITY FIX: No permission checker configured should be a hard failure
            # This prevents authentication bypass when permission checker is missing
            logger.error(
                f"SECURITY VIOLATION: No permission checker configured for MCP server {self.name}, "
                "denying access for security"
            )
            raise PermissionDeniedError(
                f"Authentication system not properly configured for MCP server {self.name}"
            )
        
        # Parse resource and action from permission string
        if ":" in permission:
            resource, action = permission.rsplit(":", 1)
        else:
            resource = permission
            action = "*"
        
        return self.permission_checker.check_permission(
            user_id=user.id,
            user_roles=user.roles,
            resource=resource,
            action=action,
            context=context
        )
    
    def set_tool_permission(self, tool_name: str, permission: str) -> None:
        """
        Set custom permission requirement for a specific tool.
        
        Args:
            tool_name: Name of the tool
            permission: Permission string required
        """
        self.tool_permissions[tool_name] = permission
    
    def register_resource_permissions(self) -> None:
        """
        Register this MCP server's resource permissions.
        Should be called during server initialization.
        """
        if not self.permission_checker:
            return
        
        # Register the server as a resource
        self.permission_checker.register_resource_permission(
            resource_type=ResourceType.MCP_SERVER,
            resource_id=self.name,
            initial_permissions={
                # Default permissions for admin role
                "role:admin": {
                    "*": True  # Full access
                },
                # Default permissions for user role
                "role:user": {
                    "list": True,
                    "read": True,
                    "execute": False  # Must be explicitly granted
                }
            }
        )
        
        # Register each tool as a resource
        try:
            tools = self._get_all_tools()
            for tool in tools:
                self.permission_checker.register_resource_permission(
                    resource_type=ResourceType.MCP_TOOL,
                    resource_id=f"{self.name}.{tool.name}",
                    initial_permissions={
                        "role:admin": {"*": True},
                        "role:user": {"execute": False}
                    }
                )
        except NotImplementedError:
            # Subclass hasn't implemented _get_all_tools yet
            pass
