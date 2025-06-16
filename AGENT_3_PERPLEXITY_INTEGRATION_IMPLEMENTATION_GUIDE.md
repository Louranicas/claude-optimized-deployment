# Perplexity MCP Integration Implementation Guide

## Overview

This guide provides step-by-step instructions for integrating Perplexity AI's MCP server into the Circle of Experts system to enable real-time web search capabilities.

## Prerequisites

- Python 3.9+
- Node.js 18+ (for MCP server)
- Perplexity API key (Sonar API access)
- Existing Circle of Experts infrastructure

## Installation Steps

### 1. Install Perplexity MCP Server

```bash
# Option 1: NPX (Recommended for quick setup)
npx @ppl-ai/modelcontextprotocol

# Option 2: Docker
docker run -p 3000:3000 \
  -e PERPLEXITY_API_KEY=your_api_key \
  ppl-ai/modelcontextprotocol

# Option 3: From source
git clone https://github.com/ppl-ai/modelcontextprotocol.git
cd modelcontextprotocol
npm install
npm start
```

### 2. Configure MCP Integration

```json
# Add to mcp_configs/perplexity_search.json
{
  "name": "perplexity-search",
  "description": "Real-time web search using Perplexity Sonar API",
  "category": "search",
  "capabilities": [
    "web_search",
    "real_time_search",
    "fact_checking",
    "source_attribution"
  ],
  "package": "@ppl-ai/modelcontextprotocol",
  "settings": {
    "api_key": "YOUR_PERPLEXITY_API_KEY",
    "model": "llama-3.1-sonar-small-128k-online",
    "max_tokens": 1000,
    "temperature": 0.2,
    "return_citations": true,
    "return_images": false
  }
}
```

### 3. Update Circle of Experts Integration

```python
# src/circle_of_experts/search/perplexity_client.py
from typing import Dict, List, Any, Optional
import httpx
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class PerplexitySearchClient:
    """Client for Perplexity Sonar API integration."""
    
    def __init__(self, api_key: str, base_url: str = "https://api.perplexity.ai"):
        self.api_key = api_key
        self.base_url = base_url
        self.client = httpx.AsyncClient(
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=30.0
        )
    
    async def search(
        self,
        query: str,
        model: str = "llama-3.1-sonar-small-128k-online",
        max_tokens: int = 1000,
        temperature: float = 0.2,
        return_citations: bool = True,
        return_images: bool = False
    ) -> Dict[str, Any]:
        """
        Perform a search using Perplexity Sonar API.
        
        Args:
            query: Search query
            model: Perplexity model to use
            max_tokens: Maximum tokens in response
            temperature: Response creativity (0.0-1.0)
            return_citations: Include source citations
            return_images: Include related images
            
        Returns:
            Search results with content and sources
        """
        try:
            payload = {
                "model": model,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a helpful research assistant. Provide accurate, well-sourced information."
                    },
                    {
                        "role": "user", 
                        "content": query
                    }
                ],
                "max_tokens": max_tokens,
                "temperature": temperature,
                "return_citations": return_citations,
                "return_images": return_images,
                "stream": False
            }
            
            response = await self.client.post(
                f"{self.base_url}/chat/completions",
                json=payload
            )
            response.raise_for_status()
            
            result = response.json()
            
            # Extract and format response
            content = result["choices"][0]["message"]["content"]
            citations = result.get("citations", [])
            
            return {
                "content": content,
                "sources": citations,
                "model_used": model,
                "query": query,
                "timestamp": datetime.utcnow().isoformat(),
                "token_usage": result.get("usage", {})
            }
            
        except Exception as e:
            logger.error(f"Perplexity search failed: {e}")
            raise
    
    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()
```

### 4. Enhance Expert Manager with Search

```python
# src/circle_of_experts/core/search_enhanced_expert_manager.py
from typing import Dict, Any, List, Optional
import logging
from ..search.perplexity_client import PerplexitySearchClient
from .expert_manager import ExpertManager

logger = logging.getLogger(__name__)

class SearchEnhancedExpertManager(ExpertManager):
    """Expert Manager enhanced with real-time search capabilities."""
    
    def __init__(self, perplexity_api_key: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.search_client = PerplexitySearchClient(perplexity_api_key)
        self.search_cache = {}
    
    async def consult_experts_with_search(
        self,
        title: str,
        content: str,
        requester: str,
        enable_pre_search: bool = True,
        search_depth: str = "standard",
        **kwargs
    ) -> Dict[str, Any]:
        """
        Consult experts with optional pre-search enhancement.
        
        Args:
            title: Query title
            content: Query content  
            requester: Who is making the request
            enable_pre_search: Whether to perform web search first
            search_depth: Search depth (quick/standard/deep)
            **kwargs: Additional arguments for base method
            
        Returns:
            Enhanced consultation results with search context
        """
        search_results = None
        
        if enable_pre_search:
            # Extract search queries from content
            search_queries = self._extract_search_terms(content, title)
            
            if search_queries:
                search_results = await self._perform_pre_search(
                    search_queries, 
                    depth=search_depth
                )
                
                # Add search context to query content
                if search_results:
                    enhanced_content = self._enhance_content_with_search(
                        content, search_results
                    )
                    content = enhanced_content
        
        # Consult experts with enhanced content
        result = await super().consult_experts(
            title=title,
            content=content,
            requester=requester,
            **kwargs
        )
        
        # Add search metadata
        if search_results:
            result["search_context"] = {
                "pre_search_performed": True,
                "search_results": search_results,
                "search_queries": search_queries,
                "search_depth": search_depth
            }
        
        return result
    
    async def _perform_pre_search(
        self,
        queries: List[str],
        depth: str = "standard"
    ) -> List[Dict[str, Any]]:
        """Perform pre-search for context gathering."""
        # Configure search based on depth
        depth_config = {
            "quick": {"max_queries": 1, "max_tokens": 500},
            "standard": {"max_queries": 2, "max_tokens": 800},
            "deep": {"max_queries": 3, "max_tokens": 1200}
        }
        
        config = depth_config.get(depth, depth_config["standard"])
        search_results = []
        
        for query in queries[:config["max_queries"]]:
            # Check cache first
            cache_key = f"{query}:{depth}"
            if cache_key in self.search_cache:
                search_results.append(self.search_cache[cache_key])
                continue
            
            try:
                result = await self.search_client.search(
                    query=query,
                    max_tokens=config["max_tokens"],
                    temperature=0.2
                )
                search_results.append(result)
                
                # Cache result (TTL: 1 hour)
                self.search_cache[cache_key] = result
                
            except Exception as e:
                logger.error(f"Search failed for query '{query}': {e}")
        
        return search_results
    
    def _extract_search_terms(self, content: str, title: str) -> List[str]:
        """Extract meaningful search terms from query."""
        import re
        
        terms = []
        
        # Use title as primary search term
        if title and len(title.strip()) > 0:
            terms.append(title.strip())
        
        # Extract quoted phrases
        quoted_phrases = re.findall(r'"([^"]+)"', content)
        terms.extend(quoted_phrases)
        
        # Extract technical terms (capitalized sequences)
        tech_terms = re.findall(r'\b[A-Z][a-z]*(?:\s+[A-Z][a-z]*)*\b', content)
        terms.extend([term for term in tech_terms if len(term) > 3])
        
        # Extract keywords based on context
        keywords = self._extract_contextual_keywords(content)
        terms.extend(keywords)
        
        # Remove duplicates and limit
        unique_terms = []
        seen = set()
        for term in terms:
            if term.lower() not in seen and len(term) > 2:
                seen.add(term.lower())
                unique_terms.append(term)
        
        return unique_terms[:3]  # Limit to 3 terms
    
    def _extract_contextual_keywords(self, content: str) -> List[str]:
        """Extract context-specific keywords."""
        # Simple keyword extraction - can be enhanced with NLP
        keywords = []
        
        # Look for technology patterns
        tech_patterns = [
            r'\b(?:API|REST|GraphQL|SDK|CLI)\b',
            r'\b(?:Python|JavaScript|Rust|Go|Java)\b',
            r'\b(?:Docker|Kubernetes|AWS|Azure|GCP)\b',
            r'\b(?:AI|ML|LLM|NLP|ChatGPT|Claude)\b'
        ]
        
        for pattern in tech_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            keywords.extend(matches)
        
        return keywords
    
    def _enhance_content_with_search(
        self,
        original_content: str,
        search_results: List[Dict[str, Any]]
    ) -> str:
        """Enhance query content with search context."""
        if not search_results:
            return original_content
        
        enhanced_content = original_content + "\n\n## Recent Information Context:\n"
        
        for i, result in enumerate(search_results, 1):
            enhanced_content += f"\n### Search Result {i}:\n"
            enhanced_content += f"**Query**: {result['query']}\n"
            enhanced_content += f"**Content**: {result['content'][:500]}...\n"
            
            if result.get('sources'):
                sources = result['sources'][:3]  # Limit sources
                enhanced_content += f"**Sources**: {', '.join(sources)}\n"
        
        enhanced_content += "\nPlease consider this recent information in your response.\n"
        
        return enhanced_content
    
    async def cleanup(self):
        """Cleanup resources."""
        await self.search_client.close()
```

### 5. Configuration Updates

```python
# src/config/search_config.py
from pydantic import BaseSettings
from typing import Optional

class SearchConfig(BaseSettings):
    """Configuration for search integration."""
    
    # Perplexity settings
    perplexity_api_key: str
    perplexity_model: str = "llama-3.1-sonar-small-128k-online"
    perplexity_max_tokens: int = 1000
    perplexity_temperature: float = 0.2
    
    # Search behavior
    enable_search_by_default: bool = True
    search_cache_ttl: int = 3600  # 1 hour
    max_search_queries: int = 3
    search_timeout: float = 30.0
    
    # Cost management
    max_searches_per_hour: int = 100
    enable_search_caching: bool = True
    
    class Config:
        env_prefix = "SEARCH_"
        env_file = ".env"
```

### 6. Environment Configuration

```bash
# .env file additions
SEARCH_PERPLEXITY_API_KEY=your_perplexity_api_key_here
SEARCH_ENABLE_SEARCH_BY_DEFAULT=true
SEARCH_MAX_SEARCHES_PER_HOUR=100
SEARCH_SEARCH_CACHE_TTL=3600
```

### 7. Usage Examples

```python
# Example usage in Circle of Experts
async def example_usage():
    # Initialize search-enhanced expert manager
    manager = SearchEnhancedExpertManager(
        perplexity_api_key="your_api_key",
        credentials_path="path/to/credentials.json"
    )
    
    # Consult experts with automatic search enhancement
    result = await manager.consult_experts_with_search(
        title="Latest Python FastAPI performance optimizations",
        content="""
        I'm working on optimizing a FastAPI application for high throughput.
        What are the latest best practices and performance optimization techniques
        for FastAPI applications in 2024?
        """,
        requester="developer",
        enable_pre_search=True,
        search_depth="deep",
        min_responses=2
    )
    
    # Access enhanced results
    expert_responses = result["responses"]
    search_context = result.get("search_context", {})
    
    print(f"Found {len(expert_responses)} expert responses")
    if search_context.get("pre_search_performed"):
        print(f"Enhanced with {len(search_context['search_results'])} search results")
```

## Testing & Validation

### 1. Unit Tests

```python
# tests/test_perplexity_integration.py
import pytest
from src.circle_of_experts.search.perplexity_client import PerplexitySearchClient

@pytest.mark.asyncio
async def test_perplexity_search():
    client = PerplexitySearchClient(api_key="test_key")
    
    # Mock the API response
    with patch.object(client.client, 'post') as mock_post:
        mock_response = {
            "choices": [{"message": {"content": "Test response"}}],
            "citations": ["https://example.com"],
            "usage": {"total_tokens": 100}
        }
        mock_post.return_value.json.return_value = mock_response
        
        result = await client.search("test query")
        
        assert result["content"] == "Test response"
        assert len(result["sources"]) == 1
        assert result["query"] == "test query"
```

### 2. Integration Tests

```python
# tests/test_search_enhanced_manager.py
import pytest
from src.circle_of_experts.core.search_enhanced_expert_manager import SearchEnhancedExpertManager

@pytest.mark.asyncio
async def test_search_enhanced_consultation():
    manager = SearchEnhancedExpertManager(
        perplexity_api_key="test_key"
    )
    
    result = await manager.consult_experts_with_search(
        title="Test Query",
        content="What is the latest in AI technology?",
        requester="test_user",
        enable_pre_search=True,
        wait_for_responses=False  # For testing
    )
    
    assert "search_context" in result
    assert result["query_id"] is not None
```

## Monitoring & Observability

### 1. Metrics Collection

```python
# src/monitoring/search_metrics.py
from prometheus_client import Counter, Histogram, Gauge
import time

# Metrics
search_requests_total = Counter(
    'search_requests_total',
    'Total search requests',
    ['provider', 'status']
)

search_duration_seconds = Histogram(
    'search_duration_seconds',
    'Search request duration',
    ['provider']
)

search_cache_hits = Counter(
    'search_cache_hits_total',
    'Search cache hits'
)

def track_search_metrics(provider: str):
    """Decorator to track search metrics."""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                search_requests_total.labels(provider=provider, status='success').inc()
                return result
            except Exception as e:
                search_requests_total.labels(provider=provider, status='error').inc()
                raise
            finally:
                duration = time.time() - start_time
                search_duration_seconds.labels(provider=provider).observe(duration)
        return wrapper
    return decorator
```

### 2. Logging Configuration

```python
# Enhanced logging for search operations
import logging

# Configure search logger
search_logger = logging.getLogger('circle_of_experts.search')
search_logger.setLevel(logging.INFO)

# Add structured logging
class SearchLoggerAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        return f"[SEARCH] {msg}", kwargs

# Usage in search client
logger = SearchLoggerAdapter(search_logger, {})
```

## Performance Optimization

### 1. Caching Strategy

```python
# Implement intelligent caching
from typing import Dict, Any
from datetime import datetime, timedelta
import hashlib

class SearchCache:
    """Intelligent search result caching."""
    
    def __init__(self, ttl_hours: int = 1, max_size: int = 1000):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.ttl = timedelta(hours=ttl_hours)
        self.max_size = max_size
    
    def _make_key(self, query: str, params: Dict[str, Any]) -> str:
        """Create cache key from query and parameters."""
        content = f"{query}:{sorted(params.items())}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def get(self, query: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Get cached result if valid."""
        key = self._make_key(query, params)
        
        if key in self.cache:
            entry = self.cache[key]
            if datetime.now() - entry['timestamp'] < self.ttl:
                return entry['result']
            else:
                del self.cache[key]
        
        return None
    
    def set(self, query: str, params: Dict[str, Any], result: Dict[str, Any]):
        """Cache search result."""
        key = self._make_key(query, params)
        
        # Evict oldest entries if at capacity
        if len(self.cache) >= self.max_size:
            oldest_key = min(self.cache.keys(), 
                           key=lambda k: self.cache[k]['timestamp'])
            del self.cache[oldest_key]
        
        self.cache[key] = {
            'result': result,
            'timestamp': datetime.now()
        }
```

### 2. Rate Limiting

```python
# Implement rate limiting for API calls
from asyncio import Semaphore
import asyncio
from datetime import datetime, timedelta

class RateLimiter:
    """Rate limiter for API calls."""
    
    def __init__(self, max_requests: int, time_window: timedelta):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = []
        self.semaphore = Semaphore(max_requests)
    
    async def acquire(self):
        """Acquire permission to make request."""
        async with self.semaphore:
            now = datetime.now()
            
            # Remove old requests outside time window
            self.requests = [req_time for req_time in self.requests 
                           if now - req_time < self.time_window]
            
            # Wait if at limit
            if len(self.requests) >= self.max_requests:
                sleep_time = (self.requests[0] + self.time_window - now).total_seconds()
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)
            
            self.requests.append(now)
```

## Error Handling & Fallbacks

```python
# Robust error handling with fallbacks
class SearchError(Exception):
    """Base search error."""
    pass

class SearchTimeoutError(SearchError):
    """Search timeout error."""
    pass

class SearchQuotaExceededError(SearchError):
    """Search quota exceeded."""
    pass

async def robust_search_with_fallback(
    query: str,
    primary_client: PerplexitySearchClient,
    fallback_enabled: bool = True
) -> Dict[str, Any]:
    """Perform search with robust error handling and fallbacks."""
    
    try:
        # Primary search attempt
        return await primary_client.search(query)
        
    except SearchTimeoutError:
        logger.warning(f"Primary search timed out for query: {query}")
        if fallback_enabled:
            return await fallback_local_search(query)
        raise
        
    except SearchQuotaExceededError:
        logger.error(f"Search quota exceeded for query: {query}")
        if fallback_enabled:
            return await fallback_cached_search(query)
        raise
        
    except Exception as e:
        logger.error(f"Search failed for query '{query}': {e}")
        if fallback_enabled:
            return await fallback_basic_response(query)
        raise

async def fallback_local_search(query: str) -> Dict[str, Any]:
    """Fallback to local knowledge base search."""
    return {
        "content": f"Unable to perform live search. Please consult experts for: {query}",
        "sources": [],
        "fallback_used": "local_knowledge",
        "query": query,
        "timestamp": datetime.utcnow().isoformat()
    }
```

## Deployment Checklist

- [ ] Perplexity API key configured
- [ ] MCP server installed and running
- [ ] Expert Manager updated with search integration
- [ ] Configuration files updated
- [ ] Environment variables set
- [ ] Tests passing
- [ ] Monitoring configured
- [ ] Error handling implemented
- [ ] Rate limiting configured
- [ ] Caching enabled
- [ ] Documentation updated

## Success Metrics

Monitor these metrics to validate successful integration:

1. **Search Success Rate**: >95% successful search requests
2. **Response Enhancement**: >80% of expert queries include search context
3. **Performance Impact**: <500ms additional latency for search-enhanced queries
4. **Cost Efficiency**: <$0.01 per search query on average
5. **Cache Hit Rate**: >60% cache hit rate for repeated queries
6. **Expert Response Quality**: Improved relevance scores from users

## Troubleshooting

### Common Issues

1. **API Key Issues**
   - Verify API key is valid and has sufficient quota
   - Check environment variable configuration

2. **Rate Limiting**
   - Monitor request frequency
   - Implement exponential backoff
   - Use caching to reduce API calls

3. **Search Quality**
   - Refine search term extraction algorithms
   - Adjust search parameters (temperature, max_tokens)
   - Implement query preprocessing

4. **Performance Issues**
   - Enable caching
   - Optimize search term extraction
   - Implement asynchronous processing

This implementation guide provides a comprehensive foundation for integrating Perplexity AI search capabilities into the Circle of Experts system, enabling real-time web search enhancement for expert consultations.