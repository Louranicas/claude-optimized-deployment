"""Brave Search API client for web search functionality."""

import logging
from typing import Any, Dict, List, Optional

from .base import BaseAPIClient

logger = logging.getLogger(__name__)


class BraveClient(BaseAPIClient):
    """Brave Search API client."""
    
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
            base_url="https://api.search.brave.com",
            max_retries=max_retries,
            timeout=timeout,
            cache_ttl=cache_ttl,
            rate_limit=(100, 60),  # 100 requests per minute
            **kwargs
        )
    
    def _build_headers(self) -> Dict[str, str]:
        """Build request headers for Brave Search API."""
        return {
            'X-Subscription-Token': self.api_key,
            'Accept': 'application/json',
            'User-Agent': 'Claude-Optimized-Deployment/1.0.0'
        }
    
    async def _process_response(self, response: Dict[str, Any]) -> Any:
        """Process Brave API response into normalized format."""
        if 'web' in response and 'results' in response['web']:
            web_results = response['web']['results']
            processed_results = []
            
            for result in web_results:
                processed_results.append({
                    'title': result.get('title', ''),
                    'url': result.get('url', ''),
                    'description': result.get('description', ''),
                    'published': result.get('age', ''),
                    'extra_snippets': result.get('extra_snippets', [])
                })
            
            return {
                'results': processed_results,
                'query': response.get('query', {}).get('original', ''),
                'total_results': len(processed_results),
                'infobox': response.get('infobox', {}),
                'news': response.get('news', {}).get('results', []),
                'images': response.get('images', {}).get('results', [])
            }
        
        return response
    
    async def search_web(
        self,
        query: str,
        country: str = "US",
        search_lang: str = "en",
        ui_lang: str = "en-US",
        count: int = 10,
        offset: int = 0,
        safesearch: str = "moderate",
        freshness: Optional[str] = None,
        text_decorations: bool = True,
        spellcheck: bool = True,
        result_filter: Optional[str] = None,
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """
        Search the web using Brave Search API.
        
        Args:
            query: Search query
            country: Country code for localized results
            search_lang: Search language
            ui_lang: UI language
            count: Number of results (max 20)
            offset: Offset for pagination
            safesearch: Safe search setting ("strict", "moderate", "off")
            freshness: Freshness filter ("pd", "pw", "pm", "py")
            text_decorations: Include text decorations in results
            spellcheck: Enable spellcheck
            result_filter: Filter results ("web", "news", "images")
            use_cache: Use cached results if available
        
        Returns:
            Search results with metadata
        """
        params = {
            'q': query,
            'country': country,
            'search_lang': search_lang,
            'ui_lang': ui_lang,
            'count': min(count, 20),  # API limit
            'offset': offset,
            'safesearch': safesearch,
            'text_decorations': text_decorations,
            'spellcheck': spellcheck
        }
        
        if freshness:
            params['freshness'] = freshness
        
        if result_filter:
            params['result_filter'] = result_filter
        
        try:
            logger.info(f"Searching Brave for: {query}")
            response = await self._make_request(
                'GET',
                '/res/v1/web/search',
                params=params,
                use_cache=use_cache
            )
            
            processed = await self._process_response(response)
            logger.info(f"Brave search completed: {processed.get('total_results', 0)} results")
            
            return processed
            
        except Exception as e:
            logger.error(f"Brave search failed: {str(e)}")
            raise
    
    async def search_news(
        self,
        query: str,
        country: str = "US",
        search_lang: str = "en",
        ui_lang: str = "en-US",
        count: int = 10,
        offset: int = 0,
        freshness: str = "pw",  # Past week
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """
        Search for news articles.
        
        Args:
            query: News search query
            country: Country code for localized results
            search_lang: Search language
            ui_lang: UI language
            count: Number of results
            offset: Offset for pagination
            freshness: Freshness filter
            use_cache: Use cached results if available
        
        Returns:
            News search results
        """
        params = {
            'q': query,
            'country': country,
            'search_lang': search_lang,
            'ui_lang': ui_lang,
            'count': min(count, 20),
            'offset': offset,
            'freshness': freshness
        }
        
        try:
            logger.info(f"Searching Brave news for: {query}")
            response = await self._make_request(
                'GET',
                '/res/v1/news/search',
                params=params,
                use_cache=use_cache
            )
            
            # Process news results
            if 'results' in response:
                news_results = []
                for result in response['results']:
                    news_results.append({
                        'title': result.get('title', ''),
                        'url': result.get('url', ''),
                        'description': result.get('description', ''),
                        'age': result.get('age', ''),
                        'meta_url': result.get('meta_url', {}),
                        'thumbnail': result.get('thumbnail', {})
                    })
                
                processed = {
                    'results': news_results,
                    'query': query,
                    'total_results': len(news_results)
                }
            else:
                processed = response
            
            logger.info(f"Brave news search completed: {processed.get('total_results', 0)} results")
            return processed
            
        except Exception as e:
            logger.error(f"Brave news search failed: {str(e)}")
            raise
    
    async def search_images(
        self,
        query: str,
        country: str = "US",
        search_lang: str = "en",
        count: int = 10,
        safesearch: str = "moderate",
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """
        Search for images.
        
        Args:
            query: Image search query
            country: Country code
            search_lang: Search language
            count: Number of results
            safesearch: Safe search setting
            use_cache: Use cached results if available
        
        Returns:
            Image search results
        """
        params = {
            'q': query,
            'country': country,
            'search_lang': search_lang,
            'count': min(count, 20),
            'safesearch': safesearch
        }
        
        try:
            logger.info(f"Searching Brave images for: {query}")
            response = await self._make_request(
                'GET',
                '/res/v1/images/search',
                params=params,
                use_cache=use_cache
            )
            
            # Process image results
            if 'results' in response:
                image_results = []
                for result in response['results']:
                    image_results.append({
                        'title': result.get('title', ''),
                        'url': result.get('url', ''),
                        'thumbnail': result.get('thumbnail', {}),
                        'properties': result.get('properties', {}),
                        'source': result.get('source', '')
                    })
                
                processed = {
                    'results': image_results,
                    'query': query,
                    'total_results': len(image_results)
                }
            else:
                processed = response
            
            logger.info(f"Brave image search completed: {processed.get('total_results', 0)} results")
            return processed
            
        except Exception as e:
            logger.error(f"Brave image search failed: {str(e)}")
            raise
    
    async def suggest(
        self,
        query: str,
        country: str = "US",
        lang: str = "en",
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """
        Get search suggestions.
        
        Args:
            query: Partial query for suggestions
            country: Country code
            lang: Language code
            use_cache: Use cached results if available
        
        Returns:
            Search suggestions
        """
        params = {
            'q': query,
            'country': country,
            'lang': lang
        }
        
        try:
            logger.info(f"Getting Brave suggestions for: {query}")
            response = await self._make_request(
                'GET',
                '/res/v1/suggest/search',
                params=params,
                use_cache=use_cache
            )
            
            return response
            
        except Exception as e:
            logger.error(f"Brave suggestions failed: {str(e)}")
            raise
    
    async def validate_api_key(self) -> bool:
        """
        Validate the API key by making a test request.
        
        Returns:
            True if API key is valid
        """
        try:
            result = await self.search_web(
                query="test",
                count=1,
                use_cache=False
            )
            return 'results' in result
            
        except Exception as e:
            logger.error(f"API key validation failed: {str(e)}")
            return False