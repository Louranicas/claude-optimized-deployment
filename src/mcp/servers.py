"""
MCP Server implementations, starting with Brave Search.
"""

from __future__ import annotations
import os
import asyncio
import aiohttp
from typing import Dict, Any, List, Optional
from abc import ABC, abstractmethod
import logging

__all__ = [
    "BraveMCPServer"
]

from src.mcp.protocols import (
    MCPTool, MCPToolParameter, MCPServerInfo, MCPCapabilities,
    BraveSearchResult, BraveSearchResponse, MCPError, MCPServer
)

from src.core.error_handler import (
    handle_errors,
    async_handle_errors,
    log_error,
    ServiceUnavailableError,
    ExternalServiceError
)

logger = logging.getLogger(__name__)


class BraveMCPServer(MCPServer):
    """
    Brave Search MCP Server implementation.
    
    Provides web search capabilities through Brave's Search API.
    """
    
    def __init__(self, api_key: Optional[str] = None, permission_checker: Optional[Any] = None):
        """
        Initialize Brave MCP Server.
        
        Args:
            api_key: Brave API key (or from BRAVE_API_KEY env var)
            permission_checker: Optional permission checker for authentication
            
        Raises:
            ValueError: If no API key is provided via parameter or environment variable
        """
        super().__init__(name="brave-search", version="1.0.0", permission_checker=permission_checker)
        
        # Load API key from parameter or environment variable
        self.api_key = api_key or os.getenv('BRAVE_API_KEY')
        
        if not self.api_key:
            raise ValueError(
                "Brave API key is required. Please provide it either as a parameter "
                "or set the BRAVE_API_KEY environment variable."
            )
        self.base_url = "https://api.search.brave.com/res/v1"
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Set up tool-specific permissions
        self.tool_permissions = {
            "brave_web_search": "mcp.brave.search:execute",
            "brave_local_search": "mcp.brave.local:execute",
            "brave_news_search": "mcp.brave.news:execute",
            "brave_image_search": "mcp.brave.images:execute"
        }
        
        # Register resource permissions if permission checker available
        if self.permission_checker:
            self.register_resource_permissions()
    
    def _get_all_tools(self) -> List[MCPTool]:
        """Get available Brave search tools."""
        return [
            MCPTool(
                name="brave_web_search",
                description="Search the web using Brave Search API",
                parameters=[
                    MCPToolParameter(
                        name="query",
                        type="string",
                        description="Search query",
                        required=True
                    ),
                    MCPToolParameter(
                        name="count",
                        type="integer",
                        description="Number of results (1-20)",
                        required=False,
                        default=10
                    ),
                    MCPToolParameter(
                        name="offset",
                        type="integer",
                        description="Offset for pagination",
                        required=False,
                        default=0
                    ),
                    MCPToolParameter(
                        name="country",
                        type="string",
                        description="Country code (e.g., 'US', 'GB')",
                        required=False
                    ),
                    MCPToolParameter(
                        name="search_lang",
                        type="string",
                        description="Search language (e.g., 'en', 'es')",
                        required=False,
                        default="en"
                    ),
                    MCPToolParameter(
                        name="safesearch",
                        type="string",
                        description="Safe search setting",
                        required=False,
                        enum=["off", "moderate", "strict"],
                        default="moderate"
                    )
                ]
            ),
            MCPTool(
                name="brave_local_search",
                description="Search for local businesses and places",
                parameters=[
                    MCPToolParameter(
                        name="query",
                        type="string",
                        description="Local search query (e.g., 'pizza near Central Park')",
                        required=True
                    ),
                    MCPToolParameter(
                        name="count",
                        type="integer",
                        description="Number of results (1-20)",
                        required=False,
                        default=5
                    )
                ]
            ),
            MCPTool(
                name="brave_news_search",
                description="Search for recent news articles",
                parameters=[
                    MCPToolParameter(
                        name="query",
                        type="string",
                        description="News search query",
                        required=True
                    ),
                    MCPToolParameter(
                        name="count",
                        type="integer",
                        description="Number of results (1-20)",
                        required=False,
                        default=10
                    ),
                    MCPToolParameter(
                        name="freshness",
                        type="string",
                        description="Time range for news",
                        required=False,
                        enum=["pd", "pw", "pm", "py"],  # past day, week, month, year
                        default="pw"
                    )
                ]
            ),
            MCPTool(
                name="brave_image_search",
                description="Search for images on the web",
                parameters=[
                    MCPToolParameter(
                        name="query",
                        type="string",
                        description="Image search query",
                        required=True
                    ),
                    MCPToolParameter(
                        name="count",
                        type="integer",
                        description="Number of results (1-50)",
                        required=False,
                        default=10
                    ),
                    MCPToolParameter(
                        name="size",
                        type="string",
                        description="Image size filter",
                        required=False,
                        enum=["small", "medium", "large", "all"],
                        default="all"
                    )
                ]
            )
        ]
    
    async def _call_tool_impl(self, tool_name: str, arguments: Dict[str, Any], 
                             user: Any, context: Optional[Dict[str, Any]] = None) -> Any:
        """Execute a Brave search tool with authentication context."""
        if not self.session:
            self.session = aiohttp.ClientSession()
        
        try:
            # Add user context to logging
            logger.debug(f"User {user.username} executing Brave tool: {tool_name}")
            
            if tool_name == "brave_web_search":
                return await self._web_search(**arguments)
            elif tool_name == "brave_local_search":
                return await self._local_search(**arguments)
            elif tool_name == "brave_news_search":
                return await self._news_search(**arguments)
            elif tool_name == "brave_image_search":
                return await self._image_search(**arguments)
            else:
                raise MCPError(-32601, f"Unknown tool: {tool_name}")
        except Exception as e:
            logger.error(f"Error calling Brave tool {tool_name} for user {user.username}: {e}")
            raise
    
    async def _web_search(
        self,
        query: str,
        count: int = 10,
        offset: int = 0,
        country: Optional[str] = None,
        search_lang: str = "en",
        safesearch: str = "moderate"
    ) -> Dict[str, Any]:
        """Perform web search using Brave API."""
        params = {
            "q": query,
            "count": min(count, 20),
            "offset": offset,
            "search_lang": search_lang,
            "safesearch": safesearch
        }
        
        if country:
            params["country"] = country
        
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "X-Subscription-Token": self.api_key
        }
        
        async with self.session.get(
            f"{self.base_url}/web/search",
            params=params,
            headers=headers
        ) as response:
            if response.status != 200:
                error_text = await response.text()
                raise MCPError(-32000, f"Brave API error: {response.status} - {error_text}")
            
            data = await response.json()
            
            # Convert to our format
            results = []
            for item in data.get("web", {}).get("results", []):
                results.append(BraveSearchResult(
                    title=item.get("title", ""),
                    url=item.get("url", ""),
                    description=item.get("description", ""),
                    snippet=item.get("extra_snippets", [""])[0] if item.get("extra_snippets") else None,
                    thumbnail=item.get("thumbnail", {}).get("src")
                ))
            
            return {
                "query": query,
                "results": [r.dict() for r in results],
                "metadata": {
                    "total_results": len(results),
                    "query_info": data.get("query", {})
                }
            }
    
    async def _local_search(self, query: str, count: int = 5) -> Dict[str, Any]:
        """Perform local search using Brave API."""
        params = {
            "q": query,
            "count": min(count, 20)
        }
        
        headers = {
            "Accept": "application/json",
            "X-Subscription-Token": self.api_key
        }
        
        async with self.session.get(
            f"{self.base_url}/local/search",
            params=params,
            headers=headers
        ) as response:
            if response.status != 200:
                # Fallback to web search if local search not available
                return await self._web_search(query, count)
            
            data = await response.json()
            
            results = []
            for item in data.get("results", []):
                results.append({
                    "name": item.get("name", ""),
                    "address": item.get("address", ""),
                    "phone": item.get("phone", ""),
                    "rating": item.get("rating"),
                    "reviews": item.get("reviews"),
                    "url": item.get("url", ""),
                    "description": item.get("description", "")
                })
            
            return {
                "query": query,
                "results": results,
                "metadata": {
                    "total_results": len(results),
                    "location": data.get("location")
                }
            }
    
    async def _news_search(
        self,
        query: str,
        count: int = 10,
        freshness: str = "pw"
    ) -> Dict[str, Any]:
        """Perform news search using Brave API."""
        params = {
            "q": query,
            "count": min(count, 20),
            "freshness": freshness
        }
        
        headers = {
            "Accept": "application/json",
            "X-Subscription-Token": self.api_key
        }
        
        async with self.session.get(
            f"{self.base_url}/news/search",
            params=params,
            headers=headers
        ) as response:
            if response.status != 200:
                # Fallback to web search with news query
                return await self._web_search(f"{query} news", count)
            
            data = await response.json()
            
            results = []
            for item in data.get("results", []):
                results.append({
                    "title": item.get("title", ""),
                    "url": item.get("url", ""),
                    "description": item.get("description", ""),
                    "source": item.get("source", ""),
                    "published": item.get("published"),
                    "thumbnail": item.get("thumbnail", {}).get("src")
                })
            
            return {
                "query": query,
                "results": results,
                "metadata": {
                    "total_results": len(results),
                    "freshness": freshness
                }
            }
    
    async def _image_search(
        self,
        query: str,
        count: int = 10,
        size: str = "all"
    ) -> Dict[str, Any]:
        """Perform image search using Brave API."""
        params = {
            "q": query,
            "count": min(count, 50),
            "size": size
        }
        
        headers = {
            "Accept": "application/json",
            "X-Subscription-Token": self.api_key
        }
        
        async with self.session.get(
            f"{self.base_url}/images/search",
            params=params,
            headers=headers
        ) as response:
            if response.status != 200:
                error_text = await response.text()
                raise MCPError(-32000, f"Brave API error: {response.status} - {error_text}")
            
            data = await response.json()
            
            results = []
            for item in data.get("results", []):
                results.append({
                    "title": item.get("title", ""),
                    "url": item.get("url", ""),
                    "source": item.get("source", ""),
                    "thumbnail": item.get("thumbnail", {}).get("src"),
                    "width": item.get("width"),
                    "height": item.get("height"),
                    "format": item.get("format")
                })
            
            return {
                "query": query,
                "results": results,
                "metadata": {
                    "total_results": len(results),
                    "size_filter": size
                }
            }
    
    async def close(self):
        """Close the session."""
        if self.session:
            await self.session.close()
            self.session = None
