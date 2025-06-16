# API Integration Guide

## Overview

This guide covers the comprehensive API integration system that supports three major external APIs and the deploy-code module integration:
- **Deploy-Code Module API**: Deployment orchestration and automation
- **Tavily API**: Web search and content extraction
- **Smithery API**: AI-powered text enhancement and analysis  
- **Brave Search API**: Web search, news, and image search

## Quick Start

### 1. Installation

Ensure you have the required dependencies:

```bash
pip install aiohttp asyncio pytest
```

### 2. Configuration

Set up your API keys using environment variables:

```bash
export TAVILY_API_KEY="your-tavily-key"
export SMITHERY_API_KEY="your-smithery-key"  
export BRAVE_API_KEY="your-brave-key"
```

Or use the provided test keys for development:
- Tavily: `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`
- Smithery: `85861ba2-5eba-4599-b38d-61f4b3df44a7`
- Brave: `BSAigVAUU4-V72PjB48t8_CqN00Hh5z`

### 3. Basic Usage

```python
import asyncio
from src.api import APIManager

async def main():
    # Initialize the API manager
    async with APIManager(
        tavily_api_key="your-tavily-key",
        smithery_api_key="your-smithery-key", 
        brave_api_key="your-brave-key"
    ) as api_manager:
        
        # Check API health
        health = await api_manager.health_check_all()
        print(health)
        
        # Search the web
        results = await api_manager.search_web("Python programming")
        print(f"Found {results['total_results']} results")
        
        # Enhance text
        enhanced = await api_manager.enhance_text(
            text="This is basic text",
            enhancement_type="improve"
        )
        print(enhanced['content'])

asyncio.run(main())
```

## API Features

### Tavily API Features

- **Web Search**: Comprehensive web search with advanced filtering
- **Content Extraction**: Extract content from specific URLs
- **News Search**: Search for recent news articles
- **Answer Generation**: AI-generated answers to queries

### Smithery API Features  

- **Text Enhancement**: Improve, summarize, expand, or clarify text
- **Sentiment Analysis**: Analyze emotional tone of text
- **Keyword Extraction**: Extract important keywords and phrases
- **Translation**: Translate text between languages
- **Summarization**: Generate extractive or abstractive summaries

### Brave Search API Features

- **Web Search**: Fast and privacy-focused web search
- **News Search**: Recent news articles with filtering
- **Image Search**: Search for images with metadata
- **Search Suggestions**: Auto-complete suggestions
- **Localized Results**: Country and language-specific results

## Advanced Usage

### Individual Client Usage

```python
from src.api import TavilyClient, SmitheryClient, BraveClient

# Use individual clients for specific needs
async with TavilyClient("your-key") as tavily:
    result = await tavily.search(
        query="machine learning",
        search_depth="advanced",
        max_results=10,
        include_answer=True
    )

async with SmitheryClient("your-key") as smithery:
    enhanced = await smithery.enhance_text(
        text="Original text here",
        enhancement_type="improve",
        target_audience="technical professionals"
    )

async with BraveClient("your-key") as brave:
    results = await brave.search_web(
        query="API best practices",
        count=10,
        country="US",
        freshness="pw"  # Past week
    )
```

### Configuration Management

```python
from src.api.config import get_api_config, APIConfigManager

# Load configuration from environment
config = get_api_config()

# Or create custom configuration
custom_config = APIConfigManager.from_dict({
    'tavily': {
        'api_key': 'your-key',
        'cache_ttl': 600,
        'rate_limit_requests': 50
    },
    'enable_fallbacks': True,
    'max_concurrent_requests': 10
})
```

## Built-in Features

### 1. Rate Limiting

All clients include intelligent rate limiting:

```python
# Rate limits are automatically enforced
# Tavily: 50 requests/minute
# Smithery: 30 requests/minute  
# Brave: 100 requests/minute
```

### 2. Response Caching

Responses are cached to improve performance:

```python
# Cache durations:
# Tavily: 10 minutes for search results
# Smithery: 30 minutes for AI results
# Brave: 10 minutes for search results

# Control caching per request
result = await api_manager.search_web(
    query="test", 
    use_cache=False  # Bypass cache
)
```

### 3. Circuit Breaker

Automatic circuit breaker protection:

```python
# Circuit breaker triggers after:
# - 5 consecutive failures (Tavily/Brave)
# - 3 consecutive failures (Smithery)
# - 60 second recovery timeout
```

### 4. Fallback Support

Automatic failover between services:

```python
# Search will try Tavily first, then fall back to Brave
results = await api_manager.search_web(
    query="test",
    prefer_client="tavily"  # Primary choice
)
```

### 5. Retry Logic

Exponential backoff retry for failed requests:

```python
# Automatic retries with:
# - 3 max retries per request
# - 2.0 backoff factor
# - Jitter to prevent thundering herd
```

## Error Handling

### Exception Types

```python
from src.core.exceptions import APIError, RateLimitError

try:
    result = await api_manager.search_web("test")
except RateLimitError as e:
    print(f"Rate limit exceeded: {e}")
except APIError as e:
    print(f"API error: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

### Health Monitoring

```python
# Check health of all services
health = await api_manager.health_check_all()

for service, status in health.items():
    if status.get('healthy'):
        print(f"{service}: ✓ Healthy")
    else:
        print(f"{service}: ✗ Unhealthy - {status.get('error', 'Unknown error')}")
```

## Performance Optimization

### Concurrent Requests

```python
import asyncio

# Process multiple requests concurrently
tasks = [
    api_manager.search_web("query 1"),
    api_manager.enhance_text("text 1"),
    api_manager.search_news("query 2")
]

results = await asyncio.gather(*tasks, return_exceptions=True)
```

### Batch Operations

```python
# Batch similar operations
queries = ["query 1", "query 2", "query 3"]

async def search_batch(queries):
    tasks = [api_manager.search_web(q) for q in queries]
    return await asyncio.gather(*tasks, return_exceptions=True)

results = await search_batch(queries)
```

### Memory Management

```python
# Use context managers for automatic cleanup
async with APIManager(...) as api_manager:
    # Your code here
    pass  # Automatic cleanup
```

## Testing

### Running Tests

```bash
# Run comprehensive integration tests
python test_api_integrations.py

# Run demonstration
python demo_api_integrations.py
```

### Mock Testing

```python
from unittest.mock import patch

# Mock API responses for testing
with patch.object(api_manager.tavily, '_make_request') as mock:
    mock.return_value = {'results': [], 'query': 'test'}
    result = await api_manager.search_web("test")
```

## Best Practices

### 1. API Key Management

- Store API keys in environment variables
- Never commit API keys to version control
- Use different keys for development/production
- Rotate keys regularly

### 2. Error Handling

- Always use try-catch blocks for API calls
- Implement proper logging for debugging
- Handle rate limits gracefully
- Provide fallback responses for failures

### 3. Performance

- Use caching for repeated requests
- Implement request batching where possible
- Monitor API usage and costs
- Use concurrent requests for independent operations

### 4. Security

- Validate all input parameters
- Sanitize response data before use
- Use HTTPS for all API communications
- Implement request timeout limits

### 5. Monitoring

- Track API response times
- Monitor error rates and types
- Set up alerts for service failures
- Log API usage for analysis

## API Limits and Quotas

### Tavily API
- **Rate Limit**: 50 requests/minute
- **Search Depth**: basic/advanced
- **Max Results**: 20 per request
- **Features**: Web search, content extraction, AI answers

### Smithery API
- **Rate Limit**: 30 requests/minute  
- **Text Length**: Up to 10,000 characters
- **Languages**: 100+ supported
- **Features**: Enhancement, analysis, translation

### Brave Search API
- **Rate Limit**: 100 requests/minute
- **Search Types**: Web, news, images
- **Max Results**: 20 per request
- **Regions**: Global with localization

## Troubleshooting

### Common Issues

1. **API Key Invalid**
   ```python
   # Verify API key
   is_valid = await client.validate_api_key()
   ```

2. **Rate Limit Exceeded**
   ```python
   # Check metrics
   health = await client.health_check()
   print(health['metrics']['rate_limits'])
   ```

3. **Network Timeouts**
   ```python
   # Increase timeout
   client = TavilyClient(api_key, timeout=60)
   ```

4. **Cache Issues**
   ```python
   # Clear cache by using use_cache=False
   result = await client.search(query="test", use_cache=False)
   ```

### Debug Logging

```python
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('src.api')
logger.setLevel(logging.DEBUG)
```

## Support and Documentation

- **API Documentation**: Check individual API provider docs
- **Code Examples**: See `demo_api_integrations.py`
- **Test Suite**: Run `test_api_integrations.py`
- **Configuration**: Review `src/api/config.py`

For additional support, check the API provider documentation:
- [Tavily API Docs](https://docs.tavily.com)
- [Smithery API Docs](https://docs.smithery.ai)
- [Brave Search API Docs](https://api.search.brave.com/app/documentation)