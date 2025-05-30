"""
Integration between MCP and Circle of Experts.

Enhances expert capabilities with MCP tools.
"""

from __future__ import annotations
import logging
from typing import Dict, Any, List, Optional
import asyncio

from ..mcp.manager import get_mcp_manager, MCPContext
from ..models.query import ExpertQuery
from ..models.response import ExpertResponse
from ..core.expert_manager import EnhancedExpertManager

logger = logging.getLogger(__name__)


class MCPEnhancedExpertManager(EnhancedExpertManager):
    """
    Expert Manager enhanced with MCP capabilities.
    
    Automatically uses MCP tools to provide better, more informed responses.
    """
    
    def __init__(self, *args, **kwargs):
        """Initialize with MCP support."""
        super().__init__(*args, **kwargs)
        self.mcp_manager = get_mcp_manager()
        self._initialized = False
    
    async def _ensure_mcp_initialized(self):
        """Ensure MCP manager is initialized."""
        if not self._initialized:
            await self.mcp_manager.initialize()
            self._initialized = True
    
    async def consult_experts_with_mcp(
        self,
        title: str,
        content: str,
        requester: str,
        enable_web_search: bool = True,
        enable_news_search: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Consult experts with MCP enhancement.
        
        This method extends the base consult_experts_with_ai by:
        1. Creating an MCP context for the consultation
        2. Enabling appropriate MCP servers based on query
        3. Enhancing expert responses with real-time data
        
        Args:
            title: Query title
            content: Query content
            requester: Who is making the request
            enable_web_search: Enable Brave web search
            enable_news_search: Enable Brave news search
            **kwargs: Additional arguments for base method
            
        Returns:
            Enhanced consultation results with MCP data
        """
        await self._ensure_mcp_initialized()
        
        # Create query for context
        query = await self.query_handler.create_query(
            title=title,
            content=content,
            requester=requester,
            **kwargs
        )
        
        # Create MCP context
        context = self.mcp_manager.create_context(
            context_id=query.id,
            query=query
        )
        
        # Enable servers based on flags
        if enable_web_search:
            context.enabled_servers.add("brave")
        
        # Pre-search for context
        pre_search_results = await self._pre_search_for_context(query, context)
        
        # Add search results to query context
        if pre_search_results:
            query.context["mcp_pre_search"] = pre_search_results
            
            # Update the query in handler
            self.query_handler._active_queries[query.id] = query
        
        # Call base method for expert consultation
        result = await super().consult_experts_with_ai(
            title=title,
            content=content,
            requester=requester,
            **kwargs
        )
        
        # Enhance responses with MCP
        enhanced_responses = []
        for response_data in result.get("responses", []):
            response = ExpertResponse(**response_data)
            enhanced = await self.mcp_manager.enhance_expert_response(
                response,
                context_id=query.id
            )
            enhanced_responses.append(enhanced.dict())
        
        # Update result with enhanced responses
        result["responses"] = enhanced_responses
        
        # Add MCP metadata
        result["mcp_metadata"] = {
            "context_id": query.id,
            "enabled_servers": list(context.enabled_servers),
            "tool_calls": context.get_tool_history(),
            "pre_search_performed": bool(pre_search_results)
        }
        
        return result
    
    async def _pre_search_for_context(
        self,
        query: ExpertQuery,
        context: MCPContext
    ) -> Optional[Dict[str, Any]]:
        """
        Perform pre-search to gather context before expert consultation.
        
        Args:
            query: The expert query
            context: MCP context
            
        Returns:
            Pre-search results
        """
        # Extract key terms from query
        search_queries = self._extract_search_terms(query)
        
        if not search_queries:
            return None
        
        results = {}
        
        # Perform searches
        for search_query in search_queries[:2]:  # Limit pre-searches
            try:
                # Determine search type based on query
                if any(word in query.content.lower() for word in ["news", "recent", "latest", "today"]):
                    search_results = await self.mcp_manager.search_news(
                        search_query,
                        freshness="pd",  # Past day
                        context_id=context.query.id
                    )
                    results[f"news:{search_query}"] = search_results
                else:
                    search_results = await self.mcp_manager.search_web(
                        search_query,
                        count=5,
                        context_id=context.query.id
                    )
                    results[f"web:{search_query}"] = search_results
                    
            except Exception as e:
                logger.error(f"Pre-search failed for '{search_query}': {e}")
        
        return results if results else None
    
    def _extract_search_terms(self, query: ExpertQuery) -> List[str]:
        """Extract search terms from query."""
        # Simple extraction - can be enhanced
        terms = []
        
        # Use title as primary search
        if query.title:
            terms.append(query.title)
        
        # Extract key phrases from content
        content_lower = query.content.lower()
        
        # Look for quoted phrases
        import re
        quoted = re.findall(r'"([^"]+)"', query.content)
        terms.extend(quoted)
        
        # Look for technology/product names (capitalized words)
        proper_nouns = re.findall(r'\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b', query.content)
        terms.extend([noun for noun in proper_nouns if len(noun) > 3])
        
        # Remove duplicates and limit
        seen = set()
        unique_terms = []
        for term in terms:
            if term.lower() not in seen:
                seen.add(term.lower())
                unique_terms.append(term)
        
        return unique_terms[:3]
    
    async def quick_consult_with_search(
        self,
        content: str,
        requester: str = "claude_code",
        search: bool = True
    ) -> Dict[str, Any]:
        """
        Quick consultation with automatic web search.
        
        Args:
            content: Query content
            requester: Who is asking
            search: Enable web search
            
        Returns:
            Enhanced consultation results
        """
        # Extract title
        title = content.split('\n')[0][:100] if '\n' in content else content[:100]
        
        return await self.consult_experts_with_mcp(
            title=title,
            content=content,
            requester=requester,
            enable_web_search=search,
            min_experts=2,
            max_experts=2,
            use_consensus=True,
            expert_timeout=120.0
        )
    
    async def research_topic(
        self,
        topic: str,
        requester: str = "claude_code",
        depth: str = "standard"
    ) -> Dict[str, Any]:
        """
        Research a topic using MCP-enhanced experts.
        
        Args:
            topic: Topic to research
            requester: Who is asking
            depth: Research depth (quick/standard/deep)
            
        Returns:
            Research results
        """
        # Configure based on depth
        configs = {
            "quick": {"experts": 1, "searches": 2, "timeout": 60},
            "standard": {"experts": 2, "searches": 5, "timeout": 120},
            "deep": {"experts": 3, "searches": 10, "timeout": 300}
        }
        
        config = configs.get(depth, configs["standard"])
        
        # Create research query
        content = f"""
Please provide a comprehensive analysis of: {topic}

Include:
1. Current state and trends
2. Key players and technologies
3. Recent developments
4. Future outlook
5. Recommendations

Use web search to find the most recent information.
"""
        
        return await self.consult_experts_with_mcp(
            title=f"Research: {topic}",
            content=content,
            requester=requester,
            enable_web_search=True,
            enable_news_search=True,
            min_experts=config["experts"],
            max_experts=config["experts"],
            expert_timeout=config["timeout"]
        )
    
    async def get_mcp_tools(self) -> List[Dict[str, Any]]:
        """Get available MCP tools for Claude Code."""
        await self._ensure_mcp_initialized()
        return self.mcp_manager.get_available_tools()
    
    async def call_mcp_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any]
    ) -> Any:
        """
        Direct MCP tool call for Claude Code.
        
        Args:
            tool_name: Tool name (e.g., "brave.brave_web_search")
            arguments: Tool arguments
            
        Returns:
            Tool result
        """
        await self._ensure_mcp_initialized()
        
        # Create a temporary context
        import uuid
        context_id = str(uuid.uuid4())
        self.mcp_manager.create_context(context_id)
        
        try:
            return await self.mcp_manager.call_tool(
                tool_name,
                arguments,
                context_id
            )
        finally:
            # Clean up context
            if context_id in self.mcp_manager.contexts:
                del self.mcp_manager.contexts[context_id]
