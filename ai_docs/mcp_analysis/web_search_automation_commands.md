# Web Search & Automation Commands - MCP Server Analysis

## Overview

This document provides a comprehensive analysis of web operations capabilities available through MCP (Model Context Protocol) servers in the CORE environment. The analysis covers brave-search, HTTP fetch operations, and browser automation workflows.

## Table of Contents

1. [Brave Search MCP Server](#brave-search-mcp-server)
2. [HTTP Fetch Operations](#http-fetch-operations)
3. [Web Automation Workflows](#web-automation-workflows)
4. [Circle of Experts Integration](#circle-of-experts-integration)
5. [Advanced Web Operations](#advanced-web-operations)
6. [Security Considerations](#security-considerations)

---

## Brave Search MCP Server

The Brave Search MCP Server (`BraveMCPServer`) provides comprehensive web search capabilities through Brave's Search API.

### Available Tools

#### 1. brave_web_search
**Purpose**: Search the web using Brave Search API
**Required Parameters**:
- `query` (string): Search query

**Optional Parameters**:
- `count` (integer): Number of results (1-20, default: 10)
- `offset` (integer): Offset for pagination (default: 0)
- `country` (string): Country code (e.g., 'US', 'GB')
- `search_lang` (string): Search language (default: 'en')
- `safesearch` (string): Safe search setting ('off', 'moderate', 'strict', default: 'moderate')

**Example Usage**:
```python
result = await mcp_manager.call_tool(
    "brave.brave_web_search",
    {
        "query": "Claude AI development tools",
        "count": 15,
        "country": "US",
        "safesearch": "moderate"
    }
)
```

**Response Format**:
```json
{
    "query": "search query",
    "results": [
        {
            "title": "Page title",
            "url": "https://example.com",
            "description": "Page description",
            "snippet": "Additional snippet",
            "thumbnail": "thumbnail_url"
        }
    ],
    "metadata": {
        "total_results": 10,
        "query_info": {}
    }
}
```

#### 2. brave_local_search
**Purpose**: Search for local businesses and places
**Required Parameters**:
- `query` (string): Local search query (e.g., 'pizza near Central Park')

**Optional Parameters**:
- `count` (integer): Number of results (1-20, default: 5)

**Example Usage**:
```python
result = await mcp_manager.call_tool(
    "brave.brave_local_search",
    {
        "query": "coffee shops near Silicon Valley",
        "count": 10
    }
)
```

**Response Format**:
```json
{
    "query": "search query",
    "results": [
        {
            "name": "Business name",
            "address": "Business address",
            "phone": "Phone number",
            "rating": 4.5,
            "reviews": 123,
            "url": "Business URL",
            "description": "Business description"
        }
    ],
    "metadata": {
        "total_results": 5,
        "location": "location_info"
    }
}
```

#### 3. brave_news_search
**Purpose**: Search for recent news articles
**Required Parameters**:
- `query` (string): News search query

**Optional Parameters**:
- `count` (integer): Number of results (1-20, default: 10)
- `freshness` (string): Time range ('pd', 'pw', 'pm', 'py' for past day/week/month/year, default: 'pw')

**Example Usage**:
```python
result = await mcp_manager.call_tool(
    "brave.brave_news_search",
    {
        "query": "artificial intelligence latest developments",
        "count": 20,
        "freshness": "pd"  # Past day
    }
)
```

**Response Format**:
```json
{
    "query": "search query",
    "results": [
        {
            "title": "Article title",
            "url": "Article URL",
            "description": "Article description",
            "source": "News source",
            "published": "2024-01-01T00:00:00Z",
            "thumbnail": "thumbnail_url"
        }
    ],
    "metadata": {
        "total_results": 20,
        "freshness": "pd"
    }
}
```

#### 4. brave_image_search
**Purpose**: Search for images on the web
**Required Parameters**:
- `query` (string): Image search query

**Optional Parameters**:
- `count` (integer): Number of results (1-50, default: 10)
- `size` (string): Image size filter ('small', 'medium', 'large', 'all', default: 'all')

**Example Usage**:
```python
result = await mcp_manager.call_tool(
    "brave.brave_image_search",
    {
        "query": "data visualization charts",
        "count": 25,
        "size": "large"
    }
)
```

**Response Format**:
```json
{
    "query": "search query",
    "results": [
        {
            "title": "Image title",
            "url": "Image URL",
            "source": "Source URL",
            "thumbnail": "Thumbnail URL",
            "width": 1920,
            "height": 1080,
            "format": "jpeg"
        }
    ],
    "metadata": {
        "total_results": 25,
        "size_filter": "large"
    }
}
```

### Authentication & Configuration

**API Key Setup**:
```bash
export BRAVE_API_KEY="BSAigVAUU4-V72PjB48t8_CqN00Hh5z"
```

**Initialization**:
```python
brave_server = BraveMCPServer(api_key=os.getenv('BRAVE_API_KEY'))
await brave_server.initialize()
```

---

## HTTP Fetch Operations

### MCP HTTP Transport

The HTTP transport layer (`HTTPTransport`) provides robust HTTP/HTTPS communication capabilities.

#### Configuration
```python
transport = HTTPTransport(
    base_url="https://api.example.com",
    headers={
        "Authorization": "Bearer token",
        "Content-Type": "application/json",
        "User-Agent": "Claude-Optimized-Deployment/1.0.0"
    }
)
```

#### Supported Operations

**GET Requests**:
```python
async with transport.session.get(url, params=params, headers=headers) as response:
    if response.status == 200:
        data = await response.json()
```

**POST Requests**:
```python
async with transport.session.post(url, json=payload, headers=headers) as response:
    result = await response.json()
```

**WebSocket Support**:
```python
ws_transport = WebSocketTransport(
    ws_url="wss://api.example.com/ws",
    headers={"Authorization": "Bearer token"}
)
await ws_transport.connect()
```

### Rate Limiting & Retry Logic

**Built-in Rate Limiting**:
- Brave API: 100 requests per minute
- Automatic retry with exponential backoff
- Circuit breaker pattern for fault tolerance

**Retry Configuration**:
```python
@retry_network(max_attempts=3, timeout=30)
async def api_call():
    # API implementation
    pass
```

---

## Web Automation Workflows

### Browser Automation Capabilities

While dedicated Puppeteer/Playwright MCP servers are not currently implemented in the discovered codebase, the infrastructure supports browser automation through:

#### 1. HTTP-based Web Scraping
```python
async def scrape_website(url: str, selectors: List[str]):
    """Scrape website content using HTTP requests."""
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            html = await response.text()
            # Parse with BeautifulSoup or similar
            return extracted_data
```

#### 2. API Integration Patterns
```python
class WebAutomationMCPServer(MCPServer):
    """Example web automation server structure."""
    
    def _get_all_tools(self):
        return [
            MCPTool(
                name="screenshot_website",
                description="Take a screenshot of a website",
                parameters=[
                    MCPToolParameter(name="url", type="string", required=True),
                    MCPToolParameter(name="width", type="integer", default=1920),
                    MCPToolParameter(name="height", type="integer", default=1080)
                ]
            ),
            MCPTool(
                name="extract_page_content",
                description="Extract content from web page",
                parameters=[
                    MCPToolParameter(name="url", type="string", required=True),
                    MCPToolParameter(name="selectors", type="array", required=False)
                ]
            )
        ]
```

#### 3. Integration with External Services
```python
# Example: Integrating with external browser automation service
async def call_external_automation(action: str, params: Dict[str, Any]):
    async with aiohttp.ClientSession() as session:
        async with session.post(
            "https://automation-service.com/api/v1/execute",
            json={"action": action, "params": params}
        ) as response:
            return await response.json()
```

---

## Circle of Experts Integration

### MCP-Enhanced Expert Consultation

The `MCPEnhancedExpertManager` integrates web search capabilities with expert consultation:

#### Pre-Search Context Gathering
```python
async def consult_experts_with_mcp(
    title: str,
    content: str,
    requester: str,
    enable_web_search: bool = True,
    enable_news_search: bool = False
):
    """Consult experts with MCP web search enhancement."""
    
    # Create MCP context
    context = mcp_manager.create_context(context_id=query.id, query=query)
    
    # Enable search servers
    if enable_web_search:
        context.enabled_servers.add("brave")
    
    # Pre-search for context
    search_results = await _pre_search_for_context(query, context)
    
    # Enhance expert responses with real-time data
    enhanced_responses = await mcp_manager.enhance_expert_response(
        response, context_id=query.id
    )
```

#### Automatic Search Term Extraction
```python
def _extract_search_terms(query: ExpertQuery) -> List[str]:
    """Extract search terms from expert query."""
    terms = []
    
    # Primary search from title
    if query.title:
        terms.append(query.title)
    
    # Extract quoted phrases
    quoted = re.findall(r'"([^"]+)"', query.content)
    terms.extend(quoted)
    
    # Extract proper nouns (technology/product names)
    proper_nouns = re.findall(r'\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b', query.content)
    terms.extend([noun for noun in proper_nouns if len(noun) > 3])
    
    return terms[:3]  # Limit to 3 terms
```

#### Research Workflows
```python
async def research_topic(
    topic: str,
    depth: str = "standard"  # "quick", "standard", "deep"
) -> Dict[str, Any]:
    """Research a topic using MCP-enhanced experts."""
    
    configs = {
        "quick": {"experts": 1, "searches": 2, "timeout": 60},
        "standard": {"experts": 2, "searches": 5, "timeout": 120},
        "deep": {"experts": 3, "searches": 10, "timeout": 300}
    }
    
    config = configs.get(depth, configs["standard"])
    
    return await consult_experts_with_mcp(
        title=f"Research: {topic}",
        content=research_prompt,
        enable_web_search=True,
        enable_news_search=True,
        min_experts=config["experts"],
        expert_timeout=config["timeout"]
    )
```

---

## Advanced Web Operations

### Chained Search Operations
```python
async def comprehensive_web_research(topic: str):
    """Perform comprehensive web research using multiple search types."""
    
    results = {}
    
    # 1. General web search
    web_results = await mcp_manager.call_tool(
        "brave.brave_web_search",
        {"query": topic, "count": 20}
    )
    results["web"] = web_results
    
    # 2. Recent news
    news_results = await mcp_manager.call_tool(
        "brave.brave_news_search",
        {"query": topic, "freshness": "pw", "count": 15}
    )
    results["news"] = news_results
    
    # 3. Images for visual context
    image_results = await mcp_manager.call_tool(
        "brave.brave_image_search",
        {"query": f"{topic} infographic", "count": 10}
    )
    results["images"] = image_results
    
    # 4. Local relevance (if applicable)
    if "near" in topic.lower() or "location" in topic.lower():
        local_results = await mcp_manager.call_tool(
            "brave.brave_local_search",
            {"query": topic, "count": 5}
        )
        results["local"] = local_results
    
    return results
```

### Content Aggregation Patterns
```python
async def aggregate_search_insights(search_results: Dict[str, Any]) -> Dict[str, Any]:
    """Aggregate insights from multiple search results."""
    
    insights = {
        "summary": "",
        "key_sources": [],
        "recent_developments": [],
        "visual_references": [],
        "local_connections": []
    }
    
    # Process web results
    if "web" in search_results:
        insights["key_sources"] = [
            {"title": r["title"], "url": r["url"], "relevance": "high"}
            for r in search_results["web"]["results"][:5]
        ]
    
    # Process news results
    if "news" in search_results:
        insights["recent_developments"] = [
            {
                "title": r["title"],
                "source": r["source"],
                "published": r["published"],
                "url": r["url"]
            }
            for r in search_results["news"]["results"][:3]
        ]
    
    # Process image results
    if "images" in search_results:
        insights["visual_references"] = [
            {"url": r["url"], "title": r["title"]}
            for r in search_results["images"]["results"][:5]
        ]
    
    return insights
```

### Performance Optimization
```python
async def optimized_concurrent_search(queries: List[str]) -> Dict[str, Any]:
    """Perform multiple searches concurrently for better performance."""
    
    tasks = []
    for query in queries:
        task = mcp_manager.call_tool(
            "brave.brave_web_search",
            {"query": query, "count": 10}
        )
        tasks.append(task)
    
    # Execute all searches concurrently
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Process results and handle exceptions
    processed_results = {}
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            logger.error(f"Search failed for query '{queries[i]}': {result}")
        else:
            processed_results[queries[i]] = result
    
    return processed_results
```

---

## Security Considerations

### API Key Management
```python
# Secure API key handling
class SecureBraveClient:
    def __init__(self):
        self.api_key = self._get_secure_api_key()
    
    def _get_secure_api_key(self) -> str:
        """Securely retrieve API key from environment or vault."""
        key = os.getenv('BRAVE_API_KEY')
        if not key:
            raise ConfigurationError("BRAVE_API_KEY not configured")
        return key
    
    def _build_headers(self) -> Dict[str, str]:
        """Build secure headers for API requests."""
        return {
            'X-Subscription-Token': self.api_key,
            'Accept': 'application/json',
            'User-Agent': 'Claude-Optimized-Deployment/1.0.0'
        }
```

### Input Validation
```python
def validate_search_query(query: str) -> str:
    """Validate and sanitize search queries."""
    if not query or len(query.strip()) == 0:
        raise ValueError("Search query cannot be empty")
    
    if len(query) > 500:
        raise ValueError("Search query too long (max 500 characters)")
    
    # Remove potentially harmful characters
    sanitized = re.sub(r'[<>"\']', '', query.strip())
    
    return sanitized
```

### Rate Limiting Protection
```python
class RateLimitedMCPManager:
    def __init__(self):
        self.rate_limiter = {}
    
    async def call_tool_with_rate_limit(self, tool_name: str, arguments: Dict[str, Any]):
        """Call MCP tool with rate limiting protection."""
        server_name = tool_name.split('.')[0]
        
        # Check rate limit
        if server_name in self.rate_limiter:
            last_call, call_count = self.rate_limiter[server_name]
            if time.time() - last_call < 60 and call_count >= 100:  # 100 calls per minute
                await asyncio.sleep(60 - (time.time() - last_call))
        
        # Update rate limit tracking
        current_time = time.time()
        if server_name not in self.rate_limiter or current_time - self.rate_limiter[server_name][0] >= 60:
            self.rate_limiter[server_name] = [current_time, 1]
        else:
            self.rate_limiter[server_name][1] += 1
        
        return await self.mcp_manager.call_tool(tool_name, arguments)
```

### Error Handling
```python
async def robust_web_search(query: str, retries: int = 3) -> Optional[Dict[str, Any]]:
    """Perform web search with robust error handling."""
    
    for attempt in range(retries):
        try:
            result = await mcp_manager.call_tool(
                "brave.brave_web_search",
                {"query": validate_search_query(query)}
            )
            return result
            
        except MCPError as e:
            if e.code == -32000 and "rate limit" in str(e).lower():
                wait_time = 2 ** attempt  # Exponential backoff
                logger.warning(f"Rate limited, waiting {wait_time}s before retry {attempt + 1}")
                await asyncio.sleep(wait_time)
            else:
                logger.error(f"MCP error during search: {e}")
                if attempt == retries - 1:
                    raise
        
        except Exception as e:
            logger.error(f"Unexpected error during search attempt {attempt + 1}: {e}")
            if attempt == retries - 1:
                return None
    
    return None
```

---

## Command Reference Quick Guide

### Brave Search Commands
```bash
# Web search
brave.brave_web_search --query "AI development tools" --count 15 --country US

# News search
brave.brave_news_search --query "latest AI news" --freshness pd --count 20

# Local search
brave.brave_local_search --query "restaurants near me" --count 10

# Image search
brave.brave_image_search --query "data visualization" --size large --count 25
```

### MCP Integration Commands
```python
# Initialize MCP manager
mcp_manager = get_mcp_manager()
await mcp_manager.initialize()

# Create context for search operations
context = mcp_manager.create_context("search_session_123")
context.enabled_servers.add("brave")

# Direct tool calls
result = await mcp_manager.call_tool("brave.brave_web_search", {"query": "search term"})

# Enhanced expert consultation with search
result = await mcp_enhanced_manager.consult_experts_with_mcp(
    title="Research Topic",
    content="Detailed research request",
    enable_web_search=True,
    enable_news_search=True
)
```

### Performance Monitoring
```python
# Monitor search performance
search_metrics = {
    "total_searches": context.tool_calls.count(),
    "average_response_time": sum(call.duration_ms for call in context.tool_calls) / len(context.tool_calls),
    "success_rate": sum(1 for call in context.tool_calls if call.success) / len(context.tool_calls)
}
```

---

## Conclusion

The CORE environment provides robust web search and automation capabilities through:

1. **Comprehensive Brave Search Integration**: Full-featured web, news, local, and image search capabilities
2. **Flexible HTTP Transport**: Support for REST APIs and WebSocket connections
3. **Expert System Integration**: Automatic search enhancement for expert consultations
4. **Performance Optimization**: Concurrent operations, caching, and rate limiting
5. **Security Focus**: Input validation, secure authentication, and error handling

The MCP architecture allows for easy extension with additional web automation servers (Puppeteer, Playwright, etc.) following the established patterns.

**Next Steps for Browser Automation**:
- Implement dedicated Puppeteer MCP server
- Add Playwright support for cross-browser testing
- Integrate screenshot and PDF generation capabilities
- Develop web scraping tools with respect for robots.txt

---

*Last Updated: June 14, 2025*  
*Document Version: 1.0*  
*Author: Claude Code Analysis*