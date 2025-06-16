"""Unified API manager for coordinating multiple API clients."""

import asyncio
import logging
from typing import Any, Dict, List, Optional, Union

from .base import APIKeyRotator
from .brave_client import BraveClient
from .smithery_client import SmitheryClient
from .tavily_client import TavilyClient

logger = logging.getLogger(__name__)


class APIManager:
    """Unified manager for all API clients."""
    
    def __init__(
        self,
        tavily_api_key: Optional[str] = None,
        smithery_api_key: Optional[str] = None,
        brave_api_key: Optional[str] = None,
        enable_fallbacks: bool = True,
        max_concurrent_requests: int = 10
    ):
        self.enable_fallbacks = enable_fallbacks
        self.semaphore = asyncio.Semaphore(max_concurrent_requests)
        
        # Initialize clients
        self.tavily = TavilyClient(tavily_api_key) if tavily_api_key else None
        self.smithery = SmitheryClient(smithery_api_key) if smithery_api_key else None
        self.brave = BraveClient(brave_api_key) if brave_api_key else None
        
        # Track client status
        self.client_status = {
            'tavily': {'healthy': False, 'last_check': None},
            'smithery': {'healthy': False, 'last_check': None},
            'brave': {'healthy': False, 'last_check': None}
        }
        
        logger.info(f"APIManager initialized with clients: "
                   f"Tavily={self.tavily is not None}, "
                   f"Smithery={self.smithery is not None}, "
                   f"Brave={self.brave is not None}")
    
    async def health_check_all(self) -> Dict[str, Any]:
        """Check health of all API clients."""
        results = {}
        
        async def check_client(name: str, client):
            if client:
                try:
                    health = await client.health_check()
                    valid_key = await client.validate_api_key()
                    results[name] = {
                        'available': True,
                        'healthy': health.get('status') == 'healthy',
                        'api_key_valid': valid_key,
                        'metrics': health.get('metrics', {}),
                        'circuit_breaker': health.get('circuit_breaker', {})
                    }
                    self.client_status[name]['healthy'] = valid_key
                except Exception as e:
                    results[name] = {
                        'available': True,
                        'healthy': False,
                        'api_key_valid': False,
                        'error': str(e)
                    }
                    self.client_status[name]['healthy'] = False
            else:
                results[name] = {'available': False}
        
        # Check all clients concurrently
        await asyncio.gather(
            check_client('tavily', self.tavily),
            check_client('smithery', self.smithery),
            check_client('brave', self.brave),
            return_exceptions=True
        )
        
        return results
    
    async def search_web(
        self,
        query: str,
        max_results: int = 10,
        prefer_client: Optional[str] = None,
        use_cache: bool = True,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Search the web using available clients with fallback.
        
        Args:
            query: Search query
            max_results: Maximum number of results
            prefer_client: Preferred client ("tavily" or "brave")
            use_cache: Use cached results
            **kwargs: Additional client-specific parameters
        
        Returns:
            Combined search results
        """
        async with self.semaphore:
            clients = []
            
            # Determine client priority
            if prefer_client == "tavily" and self.tavily:
                clients = [("tavily", self.tavily)]
                if self.enable_fallbacks and self.brave:
                    clients.append(("brave", self.brave))
            elif prefer_client == "brave" and self.brave:
                clients = [("brave", self.brave)]
                if self.enable_fallbacks and self.tavily:
                    clients.append(("tavily", self.tavily))
            else:
                # Default priority: Tavily, then Brave
                if self.tavily:
                    clients.append(("tavily", self.tavily))
                if self.brave and self.enable_fallbacks:
                    clients.append(("brave", self.brave))
            
            for client_name, client in clients:
                try:
                    logger.info(f"Attempting web search with {client_name}")
                    
                    if client_name == "tavily":
                        result = await client.search(
                            query=query,
                            max_results=max_results,
                            use_cache=use_cache,
                            **kwargs
                        )
                    else:  # brave
                        result = await client.search_web(
                            query=query,
                            count=max_results,
                            use_cache=use_cache,
                            **kwargs
                        )
                    
                    result['source'] = client_name
                    logger.info(f"Web search successful with {client_name}")
                    return result
                    
                except Exception as e:
                    logger.warning(f"Web search failed with {client_name}: {str(e)}")
                    if not self.enable_fallbacks:
                        raise
                    continue
            
            raise Exception("All web search clients failed")
    
    async def search_news(
        self,
        query: str,
        max_results: int = 5,
        days: int = 7,
        prefer_client: Optional[str] = None,
        use_cache: bool = True,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Search for news using available clients.
        
        Args:
            query: News search query
            max_results: Maximum number of results
            days: Number of days to look back
            prefer_client: Preferred client
            use_cache: Use cached results
            **kwargs: Additional parameters
        
        Returns:
            News search results
        """
        async with self.semaphore:
            clients = []
            
            if prefer_client == "tavily" and self.tavily:
                clients = [("tavily", self.tavily)]
                if self.enable_fallbacks and self.brave:
                    clients.append(("brave", self.brave))
            elif prefer_client == "brave" and self.brave:
                clients = [("brave", self.brave)]
                if self.enable_fallbacks and self.tavily:
                    clients.append(("tavily", self.tavily))
            else:
                if self.tavily:
                    clients.append(("tavily", self.tavily))
                if self.brave and self.enable_fallbacks:
                    clients.append(("brave", self.brave))
            
            for client_name, client in clients:
                try:
                    logger.info(f"Attempting news search with {client_name}")
                    
                    if client_name == "tavily":
                        result = await client.search_news(
                            query=query,
                            max_results=max_results,
                            days=days,
                            use_cache=use_cache
                        )
                    else:  # brave
                        freshness_map = {7: "pw", 30: "pm", 365: "py"}
                        freshness = freshness_map.get(days, "pw")
                        result = await client.search_news(
                            query=query,
                            count=max_results,
                            freshness=freshness,
                            use_cache=use_cache,
                            **kwargs
                        )
                    
                    result['source'] = client_name
                    logger.info(f"News search successful with {client_name}")
                    return result
                    
                except Exception as e:
                    logger.warning(f"News search failed with {client_name}: {str(e)}")
                    if not self.enable_fallbacks:
                        raise
                    continue
            
            raise Exception("All news search clients failed")
    
    async def enhance_text(
        self,
        text: str,
        enhancement_type: str = "improve",
        **kwargs
    ) -> Dict[str, Any]:
        """
        Enhance text using Smithery AI.
        
        Args:
            text: Text to enhance
            enhancement_type: Type of enhancement
            **kwargs: Additional parameters
        
        Returns:
            Enhanced text
        """
        if not self.smithery:
            raise Exception("Smithery client not available")
        
        async with self.semaphore:
            try:
                result = await self.smithery.enhance_text(
                    text=text,
                    enhancement_type=enhancement_type,
                    **kwargs
                )
                result['source'] = 'smithery'
                return result
                
            except Exception as e:
                logger.error(f"Text enhancement failed: {str(e)}")
                raise
    
    async def analyze_sentiment(
        self,
        text: str,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Analyze sentiment using Smithery AI.
        
        Args:
            text: Text to analyze
            **kwargs: Additional parameters
        
        Returns:
            Sentiment analysis results
        """
        if not self.smithery:
            raise Exception("Smithery client not available")
        
        async with self.semaphore:
            try:
                result = await self.smithery.analyze_sentiment(
                    text=text,
                    **kwargs
                )
                result['source'] = 'smithery'
                return result
                
            except Exception as e:
                logger.error(f"Sentiment analysis failed: {str(e)}")
                raise
    
    async def extract_content(
        self,
        urls: List[str],
        **kwargs
    ) -> Dict[str, Any]:
        """
        Extract content from URLs using Tavily.
        
        Args:
            urls: List of URLs
            **kwargs: Additional parameters
        
        Returns:
            Extracted content
        """
        if not self.tavily:
            raise Exception("Tavily client not available")
        
        async with self.semaphore:
            try:
                result = await self.tavily.extract(
                    urls=urls,
                    **kwargs
                )
                result['source'] = 'tavily'
                return result
                
            except Exception as e:
                logger.error(f"Content extraction failed: {str(e)}")
                raise
    
    async def search_images(
        self,
        query: str,
        max_results: int = 10,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Search for images using Brave.
        
        Args:
            query: Image search query
            max_results: Maximum number of results
            **kwargs: Additional parameters
        
        Returns:
            Image search results
        """
        if not self.brave:
            raise Exception("Brave client not available")
        
        async with self.semaphore:
            try:
                result = await self.brave.search_images(
                    query=query,
                    count=max_results,
                    **kwargs
                )
                result['source'] = 'brave'
                return result
                
            except Exception as e:
                logger.error(f"Image search failed: {str(e)}")
                raise
    
    async def get_search_suggestions(
        self,
        query: str,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Get search suggestions using Brave.
        
        Args:
            query: Partial query
            **kwargs: Additional parameters
        
        Returns:
            Search suggestions
        """
        if not self.brave:
            raise Exception("Brave client not available")
        
        async with self.semaphore:
            try:
                result = await self.brave.suggest(
                    query=query,
                    **kwargs
                )
                result['source'] = 'brave'
                return result
                
            except Exception as e:
                logger.error(f"Search suggestions failed: {str(e)}")
                raise
    
    async def close(self):
        """Close all API clients."""
        clients = [self.tavily, self.smithery, self.brave]
        await asyncio.gather(
            *[client.close() for client in clients if client],
            return_exceptions=True
        )
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()