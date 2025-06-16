"""Tavily API client for web search functionality."""

import logging
from typing import Any, Dict, List, Optional

from .base import BaseAPIClient

logger = logging.getLogger(__name__)


class TavilyClient(BaseAPIClient):
    """Tavily Search API client."""
    
    def __init__(
        self,
        api_key: str,
        max_retries: int = 3,
        timeout: int = 30,
        cache_ttl: int = 600,  # 10 minutes cache for search results
        **kwargs
    ):
        super().__init__(
            api_key=api_key,
            base_url="https://api.tavily.com",
            max_retries=max_retries,
            timeout=timeout,
            cache_ttl=cache_ttl,
            rate_limit=(50, 60),  # 50 requests per minute
            **kwargs
        )
    
    def _build_headers(self) -> Dict[str, str]:
        """Build request headers for Tavily API."""
        return {
            'Content-Type': 'application/json',
            'User-Agent': 'Claude-Optimized-Deployment/1.0.0'
        }
    
    async def _process_response(self, response: Dict[str, Any]) -> Any:
        """Process Tavily API response."""
        if 'results' in response:
            return {
                'results': response['results'],
                'query': response.get('query', ''),
                'total_results': len(response.get('results', [])),
                'search_time': response.get('response_time', 0)
            }
        return response
    
    async def search(
        self,
        query: str,
        search_depth: str = "basic",
        include_domains: Optional[List[str]] = None,
        exclude_domains: Optional[List[str]] = None,
        max_results: int = 5,
        include_images: bool = False,
        include_answer: bool = False,
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """
        Search the web using Tavily API.
        
        Args:
            query: Search query
            search_depth: "basic" or "advanced"
            include_domains: List of domains to include
            exclude_domains: List of domains to exclude
            max_results: Maximum number of results
            include_images: Include images in results
            include_answer: Include AI-generated answer
            use_cache: Use cached results if available
        
        Returns:
            Search results with metadata
        """
        payload = {
            "api_key": self.api_key,
            "query": query,
            "search_depth": search_depth,
            "max_results": max_results,
            "include_images": include_images,
            "include_answer": include_answer
        }
        
        if include_domains:
            payload["include_domains"] = include_domains
        
        if exclude_domains:
            payload["exclude_domains"] = exclude_domains
        
        try:
            logger.info(f"Searching Tavily for: {query}")
            response = await self._make_request(
                'POST',
                '/search',
                json=payload,
                use_cache=use_cache
            )
            
            processed = await self._process_response(response)
            logger.info(f"Tavily search completed: {processed.get('total_results', 0)} results")
            
            return processed
            
        except Exception as e:
            logger.error(f"Tavily search failed: {str(e)}")
            raise
    
    async def extract(
        self,
        urls: List[str],
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """
        Extract content from URLs using Tavily.
        
        Args:
            urls: List of URLs to extract content from
            use_cache: Use cached results if available
        
        Returns:
            Extracted content
        """
        payload = {
            "api_key": self.api_key,
            "urls": urls
        }
        
        try:
            logger.info(f"Extracting content from {len(urls)} URLs")
            response = await self._make_request(
                'POST',
                '/extract',
                json=payload,
                use_cache=use_cache
            )
            
            logger.info("Content extraction completed")
            return response
            
        except Exception as e:
            logger.error(f"Content extraction failed: {str(e)}")
            raise
    
    async def search_news(
        self,
        query: str,
        max_results: int = 5,
        days: int = 7,
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """
        Search for recent news articles.
        
        Args:
            query: News search query
            max_results: Maximum number of results
            days: Number of days to look back
            use_cache: Use cached results if available
        
        Returns:
            News search results
        """
        # Add time constraint to query
        time_query = f"{query} after:{days}d"
        
        return await self.search(
            query=time_query,
            search_depth="advanced",
            max_results=max_results,
            include_answer=True,
            use_cache=use_cache
        )
    
    async def validate_api_key(self) -> bool:
        """
        Validate the API key by making a test request.
        
        Returns:
            True if API key is valid
        """
        try:
            result = await self.search(
                query="test",
                max_results=1,
                use_cache=False
            )
            return 'results' in result
            
        except Exception as e:
            logger.error(f"API key validation failed: {str(e)}")
            return False