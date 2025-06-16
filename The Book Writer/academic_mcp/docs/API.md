# Academic MCP Integration API Documentation

## Overview

The Academic MCP Integration provides seamless access to academic search and citation management within the Hyper Narrative Synthor. This integration follows top 1% developer practices with a modular Rust/Python hybrid architecture.

## Quick Start

```python
from academic_mcp import SynthorAcademicIntegration

# Initialize with your Synthor instance
integration = SynthorAcademicIntegration(synthor_instance)

# Search for papers
results = await integration.search("quantum computing", limit=10)

# Insert citation
await integration.insert_citation(paper_id, style="APA")
```

## Architecture

### Rust Core Components

- **academic_mcp_core**: High-performance MCP client implementations
- **citation_engine**: Fast citation parsing and formatting
- **search_optimizer**: Optimized search query processing

### Python Integration Layer

- **mcp_bridge**: Python-Rust FFI bridge using PyO3
- **synthor_integration**: Seamless integration with Hyper Narrative Synthor
- **academic_assistant**: AI-powered writing assistance

## API Reference

### Search API

#### `search(query: str, limit: int = 10, filters: Optional[Dict] = None) -> List[Paper]`

Search for academic papers across configured MCP servers.

**Parameters:**
- `query`: Search query string
- `limit`: Maximum number of results (default: 10)
- `filters`: Optional filters
  - `year_min`: Minimum publication year
  - `year_max`: Maximum publication year
  - `field`: Academic field filter
  - `author`: Author name filter

**Returns:**
- List of `Paper` objects

**Example:**
```python
papers = await bridge.search(
    "machine learning healthcare",
    limit=20,
    filters={"year_min": 2020, "field": "computer science"}
)
```

### Citation API

#### `format_citation(paper: Paper, style: CitationStyle) -> str`

Format a paper citation in the specified style.

**Parameters:**
- `paper`: Paper object to cite
- `style`: Citation style (APA, MLA, Chicago, IEEE, Harvard, Vancouver)

**Returns:**
- Formatted citation string

### Real-time Integration

The integration provides real-time features:

1. **Text Selection Handler**: Automatically suggests citations based on selected text
2. **Citation Preview**: Shows formatted citation before insertion
3. **Reference Autocomplete**: Suggests references as you type
4. **Duplicate Detection**: Warns about duplicate citations

## MCP Server Configuration

### Supported Servers

| Server | Priority | Capabilities |
|--------|----------|--------------|
| Zotero | Critical | Reference management, citation formatting |
| Google Scholar | Critical | Paper search, citation tracking |
| LaTeX | Critical | Document compilation, formula rendering |
| CrossRef | High | DOI resolution, metadata retrieval |
| ArXiv | High | Preprint search, paper download |
| Semantic Scholar | Medium | AI-powered analysis, recommendations |
| PubMed | Medium | Medical research, clinical studies |
| ORCID | Medium | Researcher identification |
| Mendeley | Low | PDF management, annotations |
| Jupyter | Low | Notebook execution, data analysis |

### Authentication

Different MCP servers use different authentication methods:

```python
# API Key authentication
credentials = APICredentials(
    service="semantic_scholar",
    api_key="your-api-key"
)

# OAuth2 authentication
auth_url = await oauth_manager.get_auth_url(
    "google_scholar",
    redirect_uri="http://localhost:8080/callback"
)
```

## Performance

### Caching

The integration includes multi-level caching:

- **Search Results**: Cached for 1 hour
- **Paper Details**: Cached for 24 hours
- **Citations**: Cached for 1 week

### Rate Limiting

Automatic rate limiting prevents API quota exhaustion:

```python
# Configure custom rate limits
rate_limiter.configure_limits("arxiv", {
    "requests_per_second": 0.2,  # 1 request per 5 seconds
    "burst_size": 1
})
```

## Error Handling

All methods include comprehensive error handling:

```python
try:
    results = await bridge.search("query")
except RateLimitExceeded:
    # Handle rate limit
    await asyncio.sleep(60)
except NetworkError as e:
    # Handle network issues
    logger.error(f"Network error: {e}")
```

## Best Practices

1. **Use caching**: Enable caching for frequently accessed papers
2. **Batch requests**: Group multiple searches when possible
3. **Handle errors gracefully**: Always include error handling
4. **Respect rate limits**: Don't bypass rate limiting
5. **Secure credentials**: Use the secure credential manager

## Troubleshooting

### Common Issues

1. **Rust module not found**
   - Solution: Build the Rust module with `maturin develop`

2. **Rate limit exceeded**
   - Solution: Implement exponential backoff

3. **Authentication failed**
   - Solution: Check credentials and token expiration

### Debug Mode

Enable debug logging:

```python
import logging
logging.getLogger("academic_mcp").setLevel(logging.DEBUG)
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## License

This integration is part of the Hyper Narrative Synthor project.
