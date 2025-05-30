"""
MCP Manager for Claude Code integration.

Manages MCP servers and provides a unified interface for tool calling.
"""

from __future__ import annotations
import asyncio
import logging
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field

from .servers import MCPServerRegistry, MCPServer, BraveMCPServer
from .protocols import MCPTool, MCPError, MCPServerInfo

# Optional Circle of Experts integration
try:
    from ..circle_of_experts.models.query import ExpertQuery
    from ..circle_of_experts.models.response import ExpertResponse
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

logger = logging.getLogger(__name__)


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
    
    def add_tool_call(self, call: MCPToolCall):
        """Add a tool call to the context."""
        self.tool_calls.append(call)
    
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


class MCPManager:
    """
    Manager for MCP servers in Claude Code.
    
    Provides unified access to all MCP tools and handles:
    - Server registration and lifecycle
    - Tool discovery and execution
    - Context management for Claude Code
    - Error handling and retries
    """
    
    def __init__(self):
        """Initialize MCP Manager."""
        self.registry = MCPServerRegistry()
        self.contexts: Dict[str, MCPContext] = {}
        self._default_enabled_servers = {"brave"}  # Brave enabled by default
    
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
                logger.error(f"Failed to initialize {server_name}: {e}")
    
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
        import time
        start_time = time.time()
        
        # Parse tool name
        if "." in tool_name:
            server_name, actual_tool_name = tool_name.split(".", 1)
        else:
            # Try to find tool in any server
            server_name, actual_tool_name = self._find_tool_server(tool_name)
            if not server_name:
                raise MCPError(-32601, f"Tool not found: {tool_name}")
        
        # Check if server is enabled for context
        if context_id:
            context = self.get_context(context_id)
            if context and server_name not in context.enabled_servers:
                raise MCPError(-32603, f"Server {server_name} is not enabled for this context")
        
        # Get server and call tool
        server = self.registry.get(server_name)
        if not server:
            raise MCPError(-32601, f"Server not found: {server_name}")
        
        try:
            result = await server.call_tool(actual_tool_name, arguments)
            duration_ms = (time.time() - start_time) * 1000
            
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
            
            logger.info(f"Tool {tool_name} completed in {duration_ms:.1f}ms")
            return result
            
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
            
            logger.error(f"Tool {tool_name} failed: {e}")
            raise
    
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
