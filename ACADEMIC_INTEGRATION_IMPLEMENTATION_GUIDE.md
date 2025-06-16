# SYNTHEX Academic Database Integration - Implementation Guide

## Quick Start Implementation

This guide provides step-by-step instructions for implementing academic database integration with SYNTHEX.

## Files Created

The implementation consists of these key files:

1. **Strategy Document**: `/home/louranicas/projects/claude-optimized-deployment/ACADEMIC_DATABASE_INTEGRATION_STRATEGY.md`
2. **Agent Implementation**: `/home/louranicas/projects/claude-optimized-deployment/src/synthex/academic_agents.py`
3. **Configuration Extension**: `/home/louranicas/projects/claude-optimized-deployment/src/synthex/academic_config.py`
4. **Test Suite**: `/home/louranicas/projects/claude-optimized-deployment/tests/test_academic_agents.py`

## Implementation Steps

### Step 1: Update Dependencies

Add academic database dependencies to your `requirements.txt`:

```bash
# Add to requirements.txt
aiohttp>=3.8.0
asyncpg>=0.28.0
xmltodict>=0.13.0  # For arXiv XML parsing
```

Install dependencies:

```bash
pip install -r requirements.txt
```

### Step 2: Configure Environment Variables

Set up API keys and configuration in your environment:

```bash
# Academic Database API Keys (optional but recommended)
export SEMANTIC_SCHOLAR_API_KEY="your_semantic_scholar_key"
export IEEE_API_KEY="your_ieee_key"  # If you have IEEE access
export NCBI_API_KEY="your_ncbi_key"  # Optional for higher rate limits
export CORE_API_KEY="your_core_key"  # For CORE/DOAJ access

# Contact information for polite pool access
export CROSSREF_CONTACT_EMAIL="your.email@institution.edu"
export OPENALEX_CONTACT_EMAIL="your.email@institution.edu"

# Academic search configuration
export SYNTHEX_ACADEMIC_MAX_CONCURRENT=8
export SYNTHEX_ACADEMIC_TIMEOUT=30
export SYNTHEX_ACADEMIC_PREFER_OPEN_ACCESS=true

# Database enablement (all enabled by default except IEEE)
export SYNTHEX_ENABLE_IEEE=true  # Only if you have subscription
```

### Step 3: Integrate with Existing SYNTHEX Engine

Update your main SYNTHEX engine to include academic agents. Modify `/home/louranicas/projects/claude-optimized-deployment/src/synthex/engine.py`:

```python
# Add imports at the top
from .academic_agents import create_academic_agent
from .academic_config import ExtendedSynthexConfig, AcademicSearchConfig

# Update the SynthexEngine.__init__ method
def __init__(self, config: Optional[ExtendedSynthexConfig] = None):
    self.config = config or ExtendedSynthexConfig()
    # ... existing initialization code ...
    
    # Add academic search capability
    if self.config.enable_academic_search:
        self._academic_config = self.config.academic_search
    else:
        self._academic_config = None

# Update _initialize_default_agents method
async def _initialize_default_agents(self) -> None:
    """Initialize default search agents with academic support"""
    # ... existing agent initialization ...
    
    # Initialize academic agents if enabled
    if self._academic_config:
        await self._initialize_academic_agents()

async def _initialize_academic_agents(self) -> None:
    """Initialize academic database search agents"""
    academic_agents = {
        "arxiv": (self._academic_config.enable_arxiv, self._academic_config.arxiv_config),
        "crossref": (self._academic_config.enable_crossref, self._academic_config.crossref_config),
        "semantic_scholar": (self._academic_config.enable_semantic_scholar, self._academic_config.semantic_scholar_config),
        "pubmed": (self._academic_config.enable_pubmed, self._academic_config.pubmed_config),
        "ieee": (self._academic_config.enable_ieee, self._academic_config.ieee_config),
        "core": (self._academic_config.enable_core, self._academic_config.core_config),
        "openalex": (self._academic_config.enable_openalex, self._academic_config.openalex_config),
        "datacite": (self._academic_config.enable_datacite, self._academic_config.datacite_config),
    }
    
    for agent_name, (enabled, agent_config) in academic_agents.items():
        if enabled:
            try:
                agent = create_academic_agent(agent_name, agent_config)
                await self.register_agent(f"academic_{agent_name}", agent)
                logger.info(f"Successfully initialized {agent_name} academic agent")
            except Exception as e:
                logger.error(f"Failed to initialize {agent_name} academic agent: {e}")
```

### Step 4: Update Configuration Loading

Modify your application's configuration loading to use the extended configuration:

```python
# In your main application file
from synthex.academic_config import ExtendedSynthexConfig

# Replace SynthexConfig.from_env() with:
config = ExtendedSynthexConfig.from_env()

# Validate configuration
errors = config.validate()
if errors:
    logger.error(f"Configuration errors: {errors}")
    raise ValueError("Invalid configuration")

# Initialize engine with academic support
engine = SynthexEngine(config)
```

### Step 5: Test the Implementation

Run the test suite to verify everything works:

```bash
# Run unit tests
python -m pytest tests/test_academic_agents.py -v

# Run integration tests (requires internet)
python -m pytest tests/test_academic_agents.py::TestAcademicIntegration -v -m integration
```

### Step 6: Example Usage

Here's how to use the academic search functionality:

```python
import asyncio
from synthex.engine import SynthexEngine
from synthex.academic_config import ExtendedSynthexConfig

async def academic_search_example():
    # Initialize with academic support
    config = ExtendedSynthexConfig.from_env()
    engine = SynthexEngine(config)
    await engine.initialize()
    
    try:
        # Academic search query
        query = "machine learning neural networks"
        options = {
            "max_results": 50,
            "sources": ["academic_arxiv", "academic_crossref", "academic_semantic_scholar"],
            "open_access_only": True,
            "start_date": "2020-01-01",
            "subjects": ["cs.AI", "cs.LG"]
        }
        
        # Execute search
        results = await engine.search(query, options)
        
        # Process results
        for result in results:
            print(f"Title: {result['title']}")
            print(f"Source: {result['source']}")
            print(f"Citations: {result['metadata'].get('citation_count', 'N/A')}")
            print(f"Open Access: {result['metadata'].get('open_access', False)}")
            print(f"URL: {result['url']}")
            print("-" * 80)
    
    finally:
        await engine.shutdown()

# Run the example
asyncio.run(academic_search_example())
```

## API Key Setup Guide

### Semantic Scholar API Key

1. Visit: https://www.semanticscholar.org/product/api
2. Click "Request API Key"
3. Fill out the form with your research use case
4. Add the key to your environment: `export SEMANTIC_SCHOLAR_API_KEY="your_key"`

### IEEE Xplore API Key

1. Visit: https://developer.ieee.org/
2. Create an account and apply for API access
3. Note: Requires institutional subscription for full access
4. Add the key to your environment: `export IEEE_API_KEY="your_key"`

### NCBI/PubMed API Key

1. Visit: https://ncbiinsights.ncbi.nlm.nih.gov/2017/11/02/new-api-keys-for-the-e-utilities/
2. Create an NCBI account
3. Generate an API key in your account settings
4. Add the key to your environment: `export NCBI_API_KEY="your_key"`

### CORE API Key

1. Visit: https://core.ac.uk/services/api/
2. Register for an account
3. Generate an API key
4. Add the key to your environment: `export CORE_API_KEY="your_key"`

## Monitoring and Performance

### Enable Monitoring

Add academic search metrics to your monitoring setup:

```python
# In your monitoring configuration
ACADEMIC_METRICS = [
    "academic_search_requests_total",
    "academic_search_duration_seconds",
    "academic_search_results_total",
    "academic_api_errors_total",
    "academic_cache_hits_total",
    "academic_rate_limit_hits_total"
]
```

### Performance Tuning

Adjust configuration based on your needs:

```bash
# High-volume research institution
export SYNTHEX_ACADEMIC_MAX_CONCURRENT=16
export SYNTHEX_ACADEMIC_CACHE_SIZE_MB=2048
export SYNTHEX_ACADEMIC_WORKER_THREADS=8

# Individual researcher
export SYNTHEX_ACADEMIC_MAX_CONCURRENT=4
export SYNTHEX_ACADEMIC_CACHE_SIZE_MB=512
export SYNTHEX_ACADEMIC_WORKER_THREADS=2
```

## Troubleshooting

### Common Issues

1. **Rate Limiting Errors**
   ```bash
   # Solution: Get API keys and configure contact emails
   export SEMANTIC_SCHOLAR_API_KEY="your_key"
   export CROSSREF_CONTACT_EMAIL="your.email@institution.edu"
   ```

2. **Timeout Errors**
   ```bash
   # Solution: Increase timeout settings
   export SYNTHEX_ACADEMIC_TIMEOUT=60
   ```

3. **Memory Issues with Large Result Sets**
   ```bash
   # Solution: Increase cache size and limit concurrent queries
   export SYNTHEX_ACADEMIC_CACHE_SIZE_MB=1024
   export SYNTHEX_ACADEMIC_MAX_CONCURRENT=4
   ```

4. **Missing Dependencies**
   ```bash
   # Solution: Install all required packages
   pip install aiohttp asyncpg xmltodict
   ```

### Debug Mode

Enable debug logging for academic agents:

```python
import logging

# Configure logging for academic components
logging.getLogger("synthex.academic_agents").setLevel(logging.DEBUG)
logging.getLogger("synthex.academic_config").setLevel(logging.DEBUG)
```

## Production Deployment

### Docker Configuration

Add to your Dockerfile:

```dockerfile
# Install academic search dependencies
RUN pip install aiohttp asyncpg xmltodict

# Copy academic agent files
COPY src/synthex/academic_agents.py /app/src/synthex/
COPY src/synthex/academic_config.py /app/src/synthex/

# Set environment variables for academic search
ENV SYNTHEX_ENABLE_ACADEMIC_SEARCH=true
ENV SYNTHEX_ACADEMIC_MAX_CONCURRENT=8
ENV SYNTHEX_ACADEMIC_CACHE_SIZE_MB=1024
```

### Kubernetes ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: synthex-academic-config
data:
  SYNTHEX_ENABLE_ACADEMIC_SEARCH: "true"
  SYNTHEX_ACADEMIC_MAX_CONCURRENT: "8"
  SYNTHEX_ACADEMIC_TIMEOUT: "30"
  SYNTHEX_ACADEMIC_PREFER_OPEN_ACCESS: "true"
  SYNTHEX_ACADEMIC_CACHE_SIZE_MB: "1024"
```

### Health Checks

Add academic agent health checks to your monitoring:

```python
async def health_check():
    """Health check including academic agents"""
    status = await engine.get_agent_status()
    
    academic_agents = {
        k: v for k, v in status.items() 
        if k.startswith("academic_")
    }
    
    healthy_academic_agents = sum(
        1 for agent in academic_agents.values() 
        if agent.get("healthy", False)
    )
    
    return {
        "status": "healthy" if healthy_academic_agents > 0 else "degraded",
        "academic_agents": academic_agents,
        "healthy_academic_count": healthy_academic_agents,
        "total_academic_count": len(academic_agents)
    }
```

## Next Steps

1. **Phase 1**: Implement Tier 1 agents (arXiv, Crossref, Semantic Scholar)
2. **Phase 2**: Add remaining databases (PubMed, IEEE, CORE, OpenAlex, DataCite)
3. **Phase 3**: Implement advanced features (citation graphs, result fusion)
4. **Phase 4**: Optimize performance and add monitoring
5. **Phase 5**: Deploy to production with full monitoring

## Support and Resources

- **arXiv API Documentation**: https://info.arxiv.org/help/api/
- **Crossref API Documentation**: https://github.com/CrossRef/rest-api-doc
- **Semantic Scholar API**: https://api.semanticscholar.org/api-docs/
- **PubMed E-utilities**: https://www.ncbi.nlm.nih.gov/books/NBK25501/
- **OpenAlex Documentation**: https://docs.openalex.org/

For questions or issues, please refer to the comprehensive strategy document and test suite for detailed implementation guidance.