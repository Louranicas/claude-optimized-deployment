"""
SYNTHEX MCP Server Integration
High-speed MCP server for AI-native search
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
import uuid

from ..mcp.protocols import MCPServer, MCPTool, MCPResource, MCPSubscription
from .engine import SynthexEngine, SearchResult, QueryOptions
from .config import SynthexConfig
from .security import (
    sanitize_query, validate_filters, validate_options,
    rate_limit, SecurityError, RateLimitError,
    validate_subscription_params
)

logger = logging.getLogger(__name__)


class SynthexMcpServer(MCPServer):
    """
    MCP Server for SYNTHEX search engine
    
    Provides high-speed search capabilities through MCP protocol
    """
    
    def __init__(
        self,
        name: str = "synthex",
        config: Optional[SynthexConfig] = None
    ):
        """
        Initialize SYNTHEX MCP Server
        
        Args:
            name: Server name
            config: SYNTHEX configuration
        """
        super().__init__(name)
        self.config = config or SynthexConfig()
        self.engine = SynthexEngine(self.config)
        self._subscriptions: Dict[str, MCPSubscription] = {}
        
        # Register tools
        self._register_tools()
        
        # Register resources
        self._register_resources()
        
    def _register_tools(self) -> None:
        """Register SYNTHEX tools"""
        
        # Main search tool
        self.register_tool(MCPTool(
            name="search",
            description="Execute high-speed parallel search across multiple sources",
            input_schema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of results",
                        "default": 100
                    },
                    "sources": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Data sources to search",
                        "default": ["all"]
                    },
                    "timeout_ms": {
                        "type": "integer",
                        "description": "Search timeout in milliseconds",
                        "default": 5000
                    },
                    "filters": {
                        "type": "object",
                        "description": "Additional filters",
                        "default": {}
                    }
                },
                "required": ["query"]
            },
            handler=self._handle_search
        ))
        
        # Semantic search tool
        self.register_tool(MCPTool(
            name="semantic_search",
            description="Execute semantic search using embeddings",
            input_schema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query"
                    },
                    "embedding": {
                        "type": "array",
                        "items": {"type": "number"},
                        "description": "Query embedding vector"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of results",
                        "default": 50
                    }
                },
                "required": ["query"]
            },
            handler=self._handle_semantic_search
        ))
        
        # Batch search tool
        self.register_tool(MCPTool(
            name="batch_search",
            description="Execute multiple searches in parallel",
            input_schema={
                "type": "object",
                "properties": {
                    "queries": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "query": {"type": "string"},
                                "options": {"type": "object"}
                            },
                            "required": ["query"]
                        },
                        "description": "List of queries to execute"
                    }
                },
                "required": ["queries"]
            },
            handler=self._handle_batch_search
        ))
        
        # Knowledge graph query tool
        self.register_tool(MCPTool(
            name="knowledge_graph_query",
            description="Query the knowledge graph for entity relationships",
            input_schema={
                "type": "object",
                "properties": {
                    "entity": {
                        "type": "string",
                        "description": "Entity to query"
                    },
                    "relationship_type": {
                        "type": "string",
                        "description": "Type of relationship to find"
                    },
                    "max_depth": {
                        "type": "integer",
                        "description": "Maximum relationship depth",
                        "default": 3
                    }
                },
                "required": ["entity"]
            },
            handler=self._handle_knowledge_graph_query
        ))
        
        # Agent status tool
        self.register_tool(MCPTool(
            name="get_agent_status",
            description="Get status of all search agents",
            input_schema={
                "type": "object",
                "properties": {}
            },
            handler=self._handle_get_agent_status
        ))
        
        # Subscribe to updates tool
        self.register_tool(MCPTool(
            name="subscribe_to_updates",
            description="Subscribe to search result updates",
            input_schema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Query to monitor"
                    },
                    "interval_ms": {
                        "type": "integer",
                        "description": "Update interval in milliseconds",
                        "default": 60000
                    }
                },
                "required": ["query"]
            },
            handler=self._handle_subscribe
        ))
    
    def _register_resources(self) -> None:
        """Register SYNTHEX resources"""
        
        # Search history resource
        self.register_resource(MCPResource(
            uri="synthex://history",
            name="Search History",
            description="Recent search queries and results",
            mime_type="application/json"
        ))
        
        # Knowledge graph resource
        self.register_resource(MCPResource(
            uri="synthex://knowledge-graph",
            name="Knowledge Graph",
            description="Entity relationships and semantic connections",
            mime_type="application/json"
        ))
        
        # Agent metrics resource
        self.register_resource(MCPResource(
            uri="synthex://metrics",
            name="Agent Metrics",
            description="Performance metrics for all search agents",
            mime_type="application/json"
        ))
    
    @rate_limit(max_requests=100, window_seconds=60)
    async def _handle_search(self, arguments: Dict[str, Any], client_id: str = "default") -> Dict[str, Any]:
        """Handle search request with security validation"""
        try:
            # Validate and sanitize query
            query = arguments.get("query", "")
            sanitized_query = sanitize_query(query)
            
            # Validate options
            raw_options = {
                "max_results": arguments.get("max_results", 100),
                "timeout_ms": arguments.get("timeout_ms", 5000),
                "sources": arguments.get("sources", ["all"])
            }
            validated_options = validate_options(raw_options)
            
            # Validate filters
            raw_filters = arguments.get("filters", {})
            validated_filters = validate_filters(raw_filters)
            
            # Create options with validated data
            options = QueryOptions(
                max_results=validated_options.get("max_results", 100),
                timeout_ms=validated_options.get("timeout_ms", 5000),
                sources=validated_options.get("sources", ["all"]),
                filters=validated_filters
            )
            
            # Execute search with sanitized query
            result = await self.engine.search(
                query=sanitized_query,
                options=options
            )
            
            # Convert to JSON-serializable format
            return {
                "query_id": result.query_id,
                "total_results": result.total_results,
                "execution_time_ms": result.execution_time_ms,
                "results": result.results,
                "metadata": result.metadata
            }
            
        except SecurityError as e:
            logger.warning(f"Security validation failed: {e}")
            return {
                "error": f"Invalid input: {str(e)}",
                "error_type": "security_error"
            }
        except RateLimitError as e:
            logger.warning(f"Rate limit exceeded: {e}")
            return {
                "error": str(e),
                "error_type": "rate_limit_error"
            }
        except Exception as e:
            logger.error(f"Search failed: {e}")
            return {
                "error": "Search failed. Please try again.",
                "error_type": "internal_error"
            }
    
    async def _handle_semantic_search(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle semantic search request"""
        # TODO: Implement when embeddings are available
        return {
            "error": "Semantic search not yet implemented",
            "query": arguments.get("query")
        }
    
    @rate_limit(max_requests=20, window_seconds=60)  # Lower limit for batch operations
    async def _handle_batch_search(self, arguments: Dict[str, Any], client_id: str = "default") -> Dict[str, Any]:
        """Handle batch search request with validation"""
        queries = arguments.get("queries", [])
        
        # Validate batch size
        if len(queries) > 10:
            return {
                "error": "Batch size exceeds limit of 10 queries",
                "error_type": "validation_error"
            }
        
        results = []
        
        # Execute searches in parallel with client_id
        tasks = []
        for query_obj in queries:
            task = asyncio.create_task(
                self._handle_search({
                    "query": query_obj["query"],
                    **query_obj.get("options", {})
                }, client_id=client_id)
            )
            tasks.append(task)
        
        # Wait for all searches
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, result in enumerate(batch_results):
            if isinstance(result, Exception):
                results.append({
                    "query": queries[i]["query"],
                    "error": str(result)
                })
            else:
                results.append(result)
        
        return {
            "batch_id": str(uuid.uuid4()),
            "total_queries": len(queries),
            "results": results
        }
    
    async def _handle_knowledge_graph_query(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle knowledge graph query"""
        # TODO: Implement when knowledge graph is available
        return {
            "entity": arguments.get("entity"),
            "relationships": [],
            "message": "Knowledge graph integration pending"
        }
    
    async def _handle_get_agent_status(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle get agent status request"""
        try:
            status = await self.engine.get_agent_status()
            return {
                "agents": status,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Failed to get agent status: {e}")
            return {
                "error": str(e)
            }
    
    @rate_limit(max_requests=10, window_seconds=60)  # Limit subscription creation
    async def _handle_subscribe(self, arguments: Dict[str, Any], client_id: str = "default") -> Dict[str, Any]:
        """Handle subscription request with validation"""
        try:
            query = arguments.get("query", "")
            interval_ms = arguments.get("interval_ms", 60000)
            
            # Validate subscription parameters
            sanitized_query, validated_interval = validate_subscription_params(query, interval_ms)
        
        subscription_id = str(uuid.uuid4())
        
            # Create subscription with validated data
            subscription = MCPSubscription(
                id=subscription_id,
                query=sanitized_query,
                interval_ms=validated_interval,
                callback=self._send_update
            )
        
        self._subscriptions[subscription_id] = subscription
        
        # Start monitoring
        asyncio.create_task(self._monitor_subscription(subscription))
        
            return {
                "subscription_id": subscription_id,
                "query": sanitized_query,
                "interval_ms": validated_interval,
                "status": "active"
            }
        
        except SecurityError as e:
            logger.warning(f"Subscription validation failed: {e}")
            return {
                "error": f"Invalid subscription parameters: {str(e)}",
                "error_type": "security_error"
            }
        except RateLimitError as e:
            logger.warning(f"Subscription rate limit exceeded: {e}")
            return {
                "error": str(e),
                "error_type": "rate_limit_error"
            }
    
    async def _monitor_subscription(self, subscription: MCPSubscription) -> None:
        """Monitor a subscription and send updates"""
        while subscription.id in self._subscriptions:
            try:
                # Execute search
                result = await self.engine.search(
                    query=subscription.query,
                    options=QueryOptions()
                )
                
                # Send update
                await subscription.callback({
                    "subscription_id": subscription.id,
                    "timestamp": datetime.now().isoformat(),
                    "results": result.results[:10]  # Send top 10
                })
                
                # Wait for next interval
                await asyncio.sleep(subscription.interval_ms / 1000)
                
            except Exception as e:
                logger.error(f"Subscription {subscription.id} error: {e}")
                await asyncio.sleep(60)  # Back off on error
    
    async def _send_update(self, update: Dict[str, Any]) -> None:
        """Send subscription update"""
        # This would send through MCP protocol
        logger.info(f"Sending update: {update['subscription_id']}")
    
    async def handle_resource_read(self, uri: str) -> Dict[str, Any]:
        """Handle resource read request"""
        if uri == "synthex://history":
            # Return search history
            return {
                "history": [],  # TODO: Implement history tracking
                "timestamp": datetime.now().isoformat()
            }
        
        elif uri == "synthex://knowledge-graph":
            # Return knowledge graph data
            return {
                "nodes": [],
                "edges": [],
                "timestamp": datetime.now().isoformat()
            }
        
        elif uri == "synthex://metrics":
            # Return agent metrics
            status = await self.engine.get_agent_status()
            return {
                "metrics": status,
                "timestamp": datetime.now().isoformat()
            }
        
        else:
            return {
                "error": f"Unknown resource: {uri}"
            }
    
    async def start(self) -> None:
        """Start the MCP server"""
        await super().start()
        await self.engine.initialize()
        logger.info("SYNTHEX MCP Server started")
    
    async def stop(self) -> None:
        """Stop the MCP server"""
        # Cancel all subscriptions
        for subscription in self._subscriptions.values():
            # Subscriptions will stop when removed from dict
            pass
        self._subscriptions.clear()
        
        # Shutdown engine
        await self.engine.shutdown()
        
        await super().stop()
        logger.info("SYNTHEX MCP Server stopped")