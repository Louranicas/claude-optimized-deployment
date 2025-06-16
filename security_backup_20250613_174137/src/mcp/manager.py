"""
MCP Manager for Claude Code integration.

Manages MCP servers and provides a unified interface for tool calling.
"""

from __future__ import annotations
import asyncio
import logging
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
import time

from src.mcp.registry import MCPServerRegistry, get_server_registry
from src.mcp.protocols import MCPTool, MCPError, MCPServerInfo, MCPServer
__all__ = [
    "MCPToolCall",
    "MCPContext",
    "MCPManager",
    "get_mcp_manager"
]

from src.core.exceptions import (
    MCPError as MCPException,
    MCPServerNotFoundError,
    MCPToolNotFoundError,
    MCPToolExecutionError,
    MCPInitializationError,
    handle_error
)
from src.core.logging_config import (
    get_logger, 
    mcp_logger,
    correlation_context
)
from src.core.circuit_breaker import (
    CircuitBreakerConfig,
    get_circuit_breaker_manager,
    CircuitOpenError
)
from src.core.lru_cache import create_ttl_dict
from src.core.cleanup_scheduler import get_cleanup_scheduler

# Optional Circle of Experts integration
try:
    from src.circle_of_experts.models.query import ExpertQuery
    from src.circle_of_experts.models.response import ExpertResponse
    CIRCLE_OF_EXPERTS_AVAILABLE = True
except ImportError:
    # Define minimal placeholders if Circle of Experts not available
    class ExpertQuery:
        def __init__(self, **kwargs):
            pass
    
    class ExpertResponse:
        def __init__(self, **kwargs):
            self.content = ""
            self.metadata = {}
            self.references = []
    
    CIRCLE_OF_EXPERTS_AVAILABLE = False

logger = get_logger(__name__)


@dataclass
class MCPToolCall:
    """Record of an MCP tool call."""
    server_name: str
    tool_name: str
    arguments: Dict[str, Any]
    result: Any
    duration_ms: float
    success: bool = True
    error: Optional[str] = None


@dataclass
class MCPContext:
    """Context for MCP operations within Claude Code."""
    query: Optional[ExpertQuery] = None
    tool_calls: List[MCPToolCall] = field(default_factory=list)
    enabled_servers: Set[str] = field(default_factory=set)
    created_at: float = field(default_factory=time.time)
    max_tool_calls: int = 100  # Limit tool call history
    
    def add_tool_call(self, call: MCPToolCall):
        """Add a tool call to the context."""
        self.tool_calls.append(call)
        
        # Enforce size limit to prevent unbounded growth
        if len(self.tool_calls) > self.max_tool_calls:
            # Remove oldest calls, keep last max_tool_calls
            self.tool_calls = self.tool_calls[-self.max_tool_calls:]
    
    def get_tool_history(self) -> List[Dict[str, Any]]:
        """Get tool call history for context."""
        return [
            {
                "server": call.server_name,
                "tool": call.tool_name,
                "arguments": call.arguments,
                "success": call.success,
                "duration_ms": call.duration_ms
            }
            for call in self.tool_calls
        ]
    
    def age_seconds(self) -> float:
        """Get age of context in seconds."""
        return time.time() - self.created_at


class MCPManager:
    """
    Manager for MCP servers in Claude Code.
    
    Provides unified access to all MCP tools and handles:
    - Server registration and lifecycle
    - Tool discovery and execution
    - Context management for Claude Code
    - Error handling and retries
    """
    
    def __init__(self, permission_checker=None):
        """Initialize MCP Manager."""
        # Create a default permission checker if none provided
        if permission_checker is None:
            class DefaultPermissionChecker:
                def check_permission(self, user, resource, action):
                    return True
                def __bool__(self):
                    return True
                def register_resource_permission(self, resource_type, resource_id, initial_permissions):
                    pass
            permission_checker = DefaultPermissionChecker()
        
        self.registry = get_server_registry(permission_checker)
        
        # Use TTL dict for contexts (TTL: 1 hour, max: 200 contexts)
        self.contexts = create_ttl_dict(
            max_size=200,
            ttl=3600.0,  # 1 hour
            cleanup_interval=300.0  # 5 minutes
        )
        
        self._default_enabled_servers = {"brave"}  # Brave enabled by default
        
        # Register cleanup with scheduler
        try:
            cleanup_scheduler = get_cleanup_scheduler()
            cleanup_scheduler.register_cleanable_object(self.contexts)
            cleanup_scheduler.register_task(
                name=f"mcp_manager_{id(self)}_context_cleanup",
                callback=self._cleanup_expired_contexts,
                interval_seconds=300.0,  # 5 minutes
                priority=cleanup_scheduler.TaskPriority.MEDIUM
            )
        except Exception as e:
            logger.warning(f"Could not register with cleanup scheduler: {e}")
    
    async def initialize(self):
        """Initialize all registered MCP servers."""
        logger.info("Initializing MCP Manager...")
        
        # Initialize default servers
        for server_name in self.registry.list_servers():
            try:
                server = self.registry.get(server_name)
                if hasattr(server, 'initialize'):
                    await server.initialize()
                logger.info(f"Initialized MCP server: {server_name}")
            except Exception as e:
                error = MCPInitializationError(
                    f"Failed to initialize {server_name}",
                    server_name=server_name,
                    cause=e
                )
                handle_error(error, logger, reraise=False)
    
    def create_context(self, context_id: str, query: Optional[ExpertQuery] = None) -> MCPContext:
        """
        Create a new MCP context for a Claude Code session.
        
        Args:
            context_id: Unique identifier for the context
            query: Optional expert query associated with this context
            
        Returns:
            New MCPContext instance
        """
        context = MCPContext(
            query=query,
            enabled_servers=self._default_enabled_servers.copy()
        )
        self.contexts[context_id] = context
        return context
    
    def get_context(self, context_id: str) -> Optional[MCPContext]:
        """Get an existing context."""
        return self.contexts.get(context_id)
    
    def enable_server(self, context_id: str, server_name: str):
        """Enable a server for a specific context."""
        context = self.get_context(context_id)
        if context and server_name in self.registry.list_servers():
            context.enabled_servers.add(server_name)
            logger.info(f"Enabled {server_name} for context {context_id}")
    
    def disable_server(self, context_id: str, server_name: str):
        """Disable a server for a specific context."""
        context = self.get_context(context_id)
        if context and server_name in context.enabled_servers:
            context.enabled_servers.remove(server_name)
            logger.info(f"Disabled {server_name} for context {context_id}")
    
    def get_enabled_servers(self, context_id: str) -> List[str]:
        """Get list of enabled servers for a specific context."""
        context = self.get_context(context_id)
        if context:
            return list(context.enabled_servers)
        return []
    
    def get_server_info(self) -> Dict[str, MCPServerInfo]:
        """Get information about all registered servers."""
        server_info = {}
        for server_name in self.registry.list_servers():
            server = self.registry.get(server_name)
            if server:
                server_info[server_name] = server.get_server_info()
        return server_info
    
    def get_available_tools(self, context_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get all available tools, optionally filtered by context.
        
        Args:
            context_id: Optional context ID to filter enabled servers
            
        Returns:
            List of tool definitions in Claude format
        """
        tools = []
        
        # Determine which servers to include
        if context_id:
            context = self.get_context(context_id)
            enabled_servers = context.enabled_servers if context else self._default_enabled_servers
        else:
            enabled_servers = set(self.registry.list_servers())
        
        # Collect tools from enabled servers
        for server_name in enabled_servers:
            server = self.registry.get(server_name)
            if server:
                server_tools = server.get_tools()
                for tool in server_tools:
                    # Convert to Claude format and add server prefix
                    claude_tool = tool.to_claude_format()
                    claude_tool["name"] = f"{server_name}.{tool.name}"
                    tools.append(claude_tool)
        
        return tools
    
    async def call_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        context_id: Optional[str] = None
    ) -> Any:
        """
        Call an MCP tool.
        
        Args:
            tool_name: Tool name in format "server.tool" or just "tool"
            arguments: Tool arguments
            context_id: Optional context ID for tracking
            
        Returns:
            Tool execution result
        """
        start_time = time.time()
        
        # Use correlation context for request tracking
        with correlation_context(context_id):
        
            # Parse tool name
            if "." in tool_name:
                server_name, actual_tool_name = tool_name.split(".", 1)
            else:
                # Try to find tool in any server
                server_name, actual_tool_name = self._find_tool_server(tool_name)
                if not server_name:
                    available_tools = []
                    for srv_name, srv in self.registry.servers.items():
                        available_tools.extend([f"{srv_name}.{t.name}" for t in srv.get_tools()])
                    raise MCPToolNotFoundError(
                        tool_name, 
                        "any", 
                        available_tools=available_tools[:10]  # Show first 10
                    )
            
            # Log tool call with MCP logger
            mcp_logger.log_tool_call(server_name, actual_tool_name, arguments, context_id)
        
        # Check if server is enabled for context
        if context_id:
            context = self.get_context(context_id)
            if context and server_name not in context.enabled_servers:
                raise MCPToolExecutionError(
                    f"Server {server_name} is not enabled for this context",
                    tool_name=actual_tool_name,
                    server_name=server_name,
                    context={"enabled_servers": list(context.enabled_servers)}
                )
        
        # Get server and call tool
        server = self.registry.get(server_name)
        if not server:
            raise MCPServerNotFoundError(
                server_name,
                available_servers=self.registry.list_servers()
            )
        
        # Get circuit breaker for this server/tool combination
        breaker_manager = get_circuit_breaker_manager()
        breaker = await breaker_manager.get_or_create(
            f"mcp_{server_name}_{actual_tool_name}",
            CircuitBreakerConfig(
                failure_threshold=3,
                timeout=60,
                failure_rate_threshold=0.5,
                minimum_calls=5,
                excluded_exceptions=[MCPToolNotFoundError, MCPServerNotFoundError],
                fallback=lambda: self._create_tool_fallback_response(
                    server_name, actual_tool_name, arguments
                )
            )
        )
        
        try:
            # Call tool with circuit breaker protection
            result = await breaker.call(
                server.call_tool,
                actual_tool_name,
                arguments
            )
            duration_ms = (time.time() - start_time) * 1000
            
            # Log successful tool result
            mcp_logger.log_tool_result(server_name, actual_tool_name, True, duration_ms)
            
            # Record in context if provided
            if context_id:
                context = self.get_context(context_id)
                if context:
                    context.add_tool_call(MCPToolCall(
                        server_name=server_name,
                        tool_name=actual_tool_name,
                        arguments=arguments,
                        result=result,
                        duration_ms=duration_ms,
                        success=True
                    ))
            
            return result
            
        except CircuitOpenError as e:
            # Circuit breaker is open - return fallback
            duration_ms = (time.time() - start_time) * 1000
            
            # Log circuit breaker open
            mcp_logger.log_tool_result(server_name, actual_tool_name, False, duration_ms, "Circuit breaker open")
            
            # Record in context
            if context_id:
                context = self.get_context(context_id)
                if context:
                    context.add_tool_call(MCPToolCall(
                        server_name=server_name,
                        tool_name=actual_tool_name,
                        arguments=arguments,
                        result=None,
                        duration_ms=duration_ms,
                        success=False,
                        error="Circuit breaker open"
                    ))
            
            # Return fallback response
            return self._create_tool_fallback_response(server_name, actual_tool_name, arguments)
        
        except MCPException:
            # Re-raise MCP exceptions as-is
            raise
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            
            # Record error in context
            if context_id:
                context = self.get_context(context_id)
                if context:
                    context.add_tool_call(MCPToolCall(
                        server_name=server_name,
                        tool_name=actual_tool_name,
                        arguments=arguments,
                        result=None,
                        duration_ms=duration_ms,
                        success=False,
                        error=str(e)
                    ))
            
            # Log tool failure
            mcp_logger.log_tool_result(server_name, actual_tool_name, False, duration_ms, str(e))
            
            # Wrap in MCPToolExecutionError
            error = MCPToolExecutionError(
                f"Tool execution failed: {str(e)}",
                tool_name=actual_tool_name,
                server_name=server_name,
                arguments=arguments,
                cause=e
            )
            handle_error(error, logger)
            raise error
    
    def _find_tool_server(self, tool_name: str) -> tuple[Optional[str], str]:
        """Find which server provides a tool."""
        for server_name, server in self.registry.servers.items():
            tools = server.get_tools()
            for tool in tools:
                if tool.name == tool_name:
                    return server_name, tool_name
        return None, tool_name
    
    async def search_web(
        self,
        query: str,
        count: int = 10,
        context_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Convenience method for web search using Brave.
        
        Args:
            query: Search query
            count: Number of results
            context_id: Optional context ID
            
        Returns:
            Search results
        """
        return await self.call_tool(
            "brave.brave_web_search",
            {"query": query, "count": count},
            context_id
        )
    
    async def search_news(
        self,
        query: str,
        freshness: str = "pw",
        context_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Convenience method for news search using Brave.
        
        Args:
            query: Search query
            freshness: Time range (pd=day, pw=week, pm=month, py=year)
            context_id: Optional context ID
            
        Returns:
            News results
        """
        return await self.call_tool(
            "brave.brave_news_search",
            {"query": query, "freshness": freshness},
            context_id
        )
    
    def get_server_info(self) -> Dict[str, MCPServerInfo]:
        """Get information about all registered servers."""
        info = {}
        for name, server in self.registry.servers.items():
            info[name] = server.get_server_info()
        return info
    
    async def enhance_expert_response(
        self,
        response: ExpertResponse,
        context_id: str
    ) -> ExpertResponse:
        """
        Enhance an expert response with MCP tool results.
        
        Args:
            response: Expert response to enhance
            context_id: Context ID for this enhancement
            
        Returns:
            Enhanced expert response
        """
        if not CIRCLE_OF_EXPERTS_AVAILABLE:
            logger.warning("Circle of Experts not available for response enhancement")
            return response
        
        # Extract queries from response content
        queries = self._extract_search_queries(response.content)
        
        if queries:
            logger.info(f"Enhancing response with {len(queries)} searches")
            
            # Perform searches
            search_results = []
            for query in queries[:3]:  # Limit to 3 searches
                try:
                    results = await self.search_web(query, count=5, context_id=context_id)
                    search_results.append({
                        "query": query,
                        "results": results.get("results", [])[:3]
                    })
                except Exception as e:
                    logger.error(f"Search failed for '{query}': {e}")
            
            # Add search results to response metadata
            if search_results:
                response.metadata["mcp_searches"] = search_results
                response.metadata["mcp_enhanced"] = True
                
                # Add references
                for search in search_results:
                    for result in search["results"]:
                        if result.get("url"):
                            response.references.append(result["url"])
        
        return response
    
    def _extract_search_queries(self, content: str) -> List[str]:
        """Extract potential search queries from content."""
        # Simple implementation - can be enhanced with NLP
        queries = []
        
        # Look for questions
        import re
        questions = re.findall(r'[^.!?]*\?', content)
        queries.extend([q.strip() for q in questions[:2]])
        
        # Look for "search for" patterns
        search_patterns = re.findall(r'(?:search for|look up|find information about) ([^.!?]+)', content, re.IGNORECASE)
        queries.extend([p.strip() for p in search_patterns])
        
        return queries[:3]  # Limit to 3 queries
    
    def _cleanup_expired_contexts(self) -> int:
        """
        Clean up expired MCP contexts.
        
        Returns:
            Number of expired contexts removed
        """
        try:
            removed_count = self.contexts.cleanup()
            if removed_count > 0:
                logger.info(f"Cleaned up {removed_count} expired MCP contexts")
            return removed_count
        except Exception as e:
            logger.error(f"Error during MCP context cleanup: {e}")
            return 0
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics for monitoring."""
        try:
            stats = self.contexts.get_stats()
            
            # Calculate tool call statistics
            total_tool_calls = 0
            active_contexts = 0
            for context in self.contexts.items():
                if isinstance(context[1], MCPContext):
                    active_contexts += 1
                    total_tool_calls += len(context[1].tool_calls)
            
            return {
                "contexts_cache": stats.to_dict(),
                "active_contexts": active_contexts,
                "total_tool_calls": total_tool_calls,
                "cache_type": "TTLDict with LRU eviction"
            }
        except Exception as e:
            logger.error(f"Error getting cache stats: {e}")
            return {}
    
    def _create_tool_fallback_response(
        self,
        server_name: str,
        tool_name: str,
        arguments: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create fallback response when circuit breaker is open."""
        return {
            "error": "Service temporarily unavailable",
            "details": f"The {server_name}.{tool_name} tool is currently unavailable due to repeated failures. Circuit breaker is open.",
            "server": server_name,
            "tool": tool_name,
            "fallback": True,
            "suggestion": "Please try again later or use an alternative tool."
        }
    
    async def cleanup(self):
        """Clean up all MCP servers."""
        for server_name, server in self.registry.servers.items():
            try:
                if hasattr(server, 'close'):
                    await server.close()
                logger.info(f"Cleaned up MCP server: {server_name}")
            except Exception as e:
                logger.error(f"Error cleaning up {server_name}: {e}")


# Global MCP manager instance
_mcp_manager: Optional[MCPManager] = None


def get_mcp_manager() -> MCPManager:
    """Get the global MCP manager instance."""
    global _mcp_manager
    if _mcp_manager is None:
        _mcp_manager = MCPManager()
    return _mcp_manager

# Authentication Integration
from .security.auth_integration import setup_mcp_authentication, MCPAuthMiddleware
from ..auth.middleware import AuthMiddleware
from ..auth.rbac import RBACManager

from src.core.error_handler import (
    handle_errors,\n    async_handle_errors,\n    log_error,\n    ServiceUnavailableError,\n    ExternalServiceError,\n    ConfigurationError,\n    CircuitBreakerError,\n    RateLimitError
)

class AuthenticatedMCPManager(MCPManager):
    """MCP Manager with authentication integration."""
    
    def __init__(self):
        super().__init__()
        self.auth_middleware = None
        self.rbac_manager = None
        self.authenticated_servers = {}
    
    async def setup_authentication(self, auth_middleware: AuthMiddleware, rbac_manager: RBACManager):
        """Set up authentication for all MCP servers."""
        self.auth_middleware = auth_middleware
        self.rbac_manager = rbac_manager
        
        # Integrate authentication with all servers
        self.authenticated_servers = await setup_mcp_authentication(
            self.servers, auth_middleware, rbac_manager
        )
        
        print(f"Authentication integrated with {len(self.authenticated_servers)} MCP servers")
    
    async def call_authenticated_tool(self, server_name: str, tool_name: str, 
                                    arguments: Dict[str, Any], user: Any) -> Any:
        """Call MCP tool with authentication."""
        if server_name not in self.authenticated_servers:
            raise ValueError(f"Server {server_name} not found or not authenticated")
        
        server = self.authenticated_servers[server_name]
        
        # Inject user context
        if hasattr(server, '_current_user'):
            server._current_user = user
        
        return await server.call_tool(tool_name, arguments)
