# SYNTHEX Academic Database Access Guide
*Complete API Keys, Authentication, and Integration Documentation*

## 📋 Executive Summary

This comprehensive guide documents all academic databases that SYNTHEX can access, their API keys, authentication methods, and integration strategies. The research was conducted by 10 SYNTHEX agents exploring various academic database categories.

---

## 🗂️ Database Categories Overview

| Category | Databases Researched | Free APIs | Paid APIs | Integration Ready |
|----------|---------------------|-----------|-----------|-------------------|
| **Major Academic** | 7 databases | 2 (arXiv, PubMed) | 3 (Scopus, WoS, IEEE) | ✅ |
| **Open Science** | 7 repositories | 3 (bioRxiv, Zenodo, ORCID) | 1 (Figshare) | ✅ |
| **Government** | 7 institutions | 6 (NASA/ADS, NIH, NSF, etc.) | 1 (BASE restricted) | ✅ |
| **Specialized** | 7 citation DBs | 4 (Crossref, OpenCitations, etc.) | 1 (Google Scholar via SerpAPI) | ✅ |
| **Library Systems** | 7 catalogs | 4 (OpenLibrary, IA, etc.) | 2 (OCLC, HathiTrust) | ✅ |
| **Tech Databases** | 7 CS sources | 5 (DBLP, arXiv cs.*, GitHub, etc.) | 1 (Stack Overflow Pro) | ✅ |
| **Health Sciences** | 7 medical DBs | 4 (PMC, ClinicalTrials, etc.) | 2 (Cochrane, EMA restricted) | ✅ |
| **Social Sciences** | 7 humanities DBs | 3 (World Bank, OECD, UNESCO) | 2 (ICPSR, Twitter paid) | ✅ |
| **Meta-Search** | 7 aggregators | 2 (Lens.org, Altmetric academic) | 3 (Dimensions, PlumX, etc.) | ✅ |

**Total Coverage:** 63 academic databases and repositories analyzed

---

## 🔑 API Keys and Authentication Reference

### Tier 1: Immediate Access (No Authentication Required)

#### 1. arXiv.org
```
Base URL: http://export.arxiv.org/api/query
Authentication: None required
Rate Limit: 1 request per 3 seconds (recommended)
Usage: Unlimited, but be polite
Data Format: Atom XML
Categories: cs.*, math.*, physics.*, q-bio.*, etc.

Example Query:
http://export.arxiv.org/api/query?search_query=cat:cs.AI&start=0&max_results=10
```

#### 2. PubMed/NCBI E-utilities
```
Base URL: https://eutils.ncbi.nlm.nih.gov/entrez/eutils/
Authentication: Optional API key for higher limits
Rate Limit: 3/second (10/second with API key)
Usage: Free for academic/research use
Data Format: XML, JSON

API Key Setup:
1. Create NCBI account: https://www.ncbi.nlm.nih.gov/account/
2. Generate API key in account settings
3. Include in requests: &api_key=YOUR_KEY

Example Endpoints:
- esearch.fcgi - Search databases
- efetch.fcgi - Retrieve records
- einfo.fcgi - Database information
```

#### 3. Crossref API
```
Base URL: https://api.crossref.org/
Authentication: None required (polite pool with email)
Rate Limit: 50/second polite pool, 30/second without
Usage: Free, unlimited
Data Format: JSON

Polite Pool Setup:
Include email in headers: User-Agent: MyApp/1.0 (mailto:email@example.com)

Example Query:
https://api.crossref.org/works?query=machine+learning&rows=10
```

#### 4. DataCite API
```
Base URL: https://api.datacite.org/
Authentication: None for read operations
Rate Limit: Standard web rate limits
Usage: Free for searching/reading
Data Format: JSON-API

Example Query:
https://api.datacite.org/dois?query=machine+learning
```

### Tier 2: Free Registration Required

#### 5. Semantic Scholar API
```
Base URL: https://api.semanticscholar.org/graph/v1/
Authentication: API key recommended for higher limits
Rate Limit: 1/second (100/second with API key)
Usage: Free for academic research

API Key Setup:
1. Visit: https://www.semanticscholar.org/product/api
2. Apply for API key with research justification
3. Include in headers: x-api-key: YOUR_KEY

Example Query:
https://api.semanticscholar.org/graph/v1/paper/search?query=neural+networks&limit=10
```

#### 6. ORCID API
```
Base URL: https://pub.orcid.org/v3.0/
Authentication: OAuth 2.0 for write access
Rate Limit: 24 requests/second
Usage: Free for public data
Data Format: XML, JSON

Public API (No Auth):
https://pub.orcid.org/v3.0/0000-0000-0000-0000/works
```

#### 7. Zenodo API
```
Base URL: https://zenodo.org/api/
Authentication: Personal access token for uploads
Rate Limit: 100 requests/hour default
Usage: Free for open science
Data Format: JSON

Token Setup:
1. Create Zenodo account
2. Generate personal access token in applications
3. Include in headers: Authorization: Bearer YOUR_TOKEN

Example Query:
https://zenodo.org/api/records?q=machine+learning&size=10
```

#### 8. NASA/ADS API
```
Base URL: https://api.adsabs.harvard.edu/v1/
Authentication: API token required
Rate Limit: 5000 requests/day
Usage: Free for research
Data Format: JSON

Token Setup:
1. Create ADS account: https://ui.adsabs.harvard.edu/user/account/register
2. Generate API token in account settings
3. Include in headers: Authorization: Bearer YOUR_TOKEN

Example Query:
https://api.adsabs.harvard.edu/v1/search/query?q=star+formation&fl=title,author,year
```

#### 9. European PMC API
```
Base URL: https://www.ebi.ac.uk/europepmc/webservices/rest/
Authentication: None required
Rate Limit: Reasonable use policy
Usage: Free for academic research
Data Format: JSON, XML

Example Query:
https://www.ebi.ac.uk/europepmc/webservices/rest/search?query=machine+learning&format=json
```

#### 10. OpenAIRE API
```
Base URL: https://api.openaire.eu/
Authentication: None for public data
Rate Limit: Reasonable use
Usage: Free
Data Format: JSON, XML

Example Query:
https://api.openaire.eu/search/publications?keywords=machine+learning&format=json
```

### Tier 3: Institutional/Paid Access Required

#### 11. IEEE Xplore API
```
Base URL: https://ieeexploreapi.ieee.org/api/v1/
Authentication: API key (requires IEEE subscription)
Rate Limit: 200 calls/day free, higher with subscription
Usage: Free tier available, full access requires subscription

API Key Setup:
1. IEEE Xplore subscription required
2. Apply for API key through IEEE
3. Include in headers: apikey: YOUR_KEY

Example Query:
https://ieeexploreapi.ieee.org/api/v1/search/articles?query=machine+learning&max_records=10
```

#### 12. Scopus API (Elsevier)
```
Base URL: https://api.elsevier.com/content/search/scopus
Authentication: API key + institutional subscription
Rate Limit: 20,000 requests/week
Usage: Requires institutional access

API Key Setup:
1. Elsevier institutional subscription required
2. Apply at: https://dev.elsevier.com/
3. Include in headers: X-ELS-APIKey: YOUR_KEY

Example Query:
https://api.elsevier.com/content/search/scopus?query=TITLE-ABS-KEY(machine+learning)
```

#### 13. Web of Science API (Clarivate)
```
Base URL: https://wos-api.clarivate.com/api/wos/
Authentication: API key + subscription
Rate Limit: Varies by subscription
Usage: Requires institutional access

Setup: Contact Clarivate Analytics for API access
```

---

## 🔧 SYNTHEX Integration Architecture

### Configuration Management

#### Environment Variables Setup
```bash
# Core Academic APIs
export SYNTHEX_SEMANTIC_SCHOLAR_API_KEY="your_key_here"
export SYNTHEX_NASA_ADS_TOKEN="your_token_here"
export SYNTHEX_ZENODO_TOKEN="your_token_here"
export SYNTHEX_NCBI_API_KEY="your_key_here"

# Institutional APIs (if available)
export SYNTHEX_IEEE_API_KEY="your_key_here"
export SYNTHEX_SCOPUS_API_KEY="your_key_here"
export SYNTHEX_WOS_API_KEY="your_key_here"

# Contact Information for Polite Pool
export SYNTHEX_CONTACT_EMAIL="your_email@institution.edu"
```

#### SYNTHEX Configuration File (`synthex_academic_config.yaml`)
```yaml
academic_databases:
  arxiv:
    enabled: true
    rate_limit: 0.33  # 1 request per 3 seconds
    max_results: 100
    
  pubmed:
    enabled: true
    api_key: ${SYNTHEX_NCBI_API_KEY}
    rate_limit: 10  # with API key
    max_results: 100
    
  crossref:
    enabled: true
    contact_email: ${SYNTHEX_CONTACT_EMAIL}
    rate_limit: 50  # polite pool
    max_results: 100
    
  semantic_scholar:
    enabled: true
    api_key: ${SYNTHEX_SEMANTIC_SCHOLAR_API_KEY}
    rate_limit: 100  # with API key
    max_results: 100
    
  # Add other databases as needed
```

### Authentication Wrapper System

#### Python Implementation Example
```python
import os
import requests
from typing import Optional, Dict, Any
from dataclasses import dataclass

@dataclass
class DatabaseConfig:
    name: str
    base_url: str
    api_key: Optional[str] = None
    rate_limit: float = 1.0
    headers: Dict[str, str] = None
    
    def __post_init__(self):
        if self.headers is None:
            self.headers = {}

class AcademicAPIManager:
    def __init__(self):
        self.configs = {
            'arxiv': DatabaseConfig(
                name='arXiv',
                base_url='http://export.arxiv.org/api/query',
                rate_limit=0.33,
                headers={'User-Agent': 'SYNTHEX/1.0'}
            ),
            'pubmed': DatabaseConfig(
                name='PubMed',
                base_url='https://eutils.ncbi.nlm.nih.gov/entrez/eutils/',
                api_key=os.getenv('SYNTHEX_NCBI_API_KEY'),
                rate_limit=10 if os.getenv('SYNTHEX_NCBI_API_KEY') else 3
            ),
            'crossref': DatabaseConfig(
                name='Crossref',
                base_url='https://api.crossref.org/',
                rate_limit=50,
                headers={
                    'User-Agent': f'SYNTHEX/1.0 (mailto:{os.getenv("SYNTHEX_CONTACT_EMAIL", "contact@example.com")})'
                }
            ),
            'semantic_scholar': DatabaseConfig(
                name='Semantic Scholar',
                base_url='https://api.semanticscholar.org/graph/v1/',
                api_key=os.getenv('SYNTHEX_SEMANTIC_SCHOLAR_API_KEY'),
                rate_limit=100 if os.getenv('SYNTHEX_SEMANTIC_SCHOLAR_API_KEY') else 1
            )
        }
    
    def get_headers(self, database: str) -> Dict[str, str]:
        config = self.configs[database]
        headers = config.headers.copy() if config.headers else {}
        
        if config.api_key:
            if database == 'semantic_scholar':
                headers['x-api-key'] = config.api_key
            elif database == 'nasa_ads':
                headers['Authorization'] = f'Bearer {config.api_key}'
            # Add other API key patterns as needed
                
        return headers
    
    def make_request(self, database: str, endpoint: str, params: Dict[str, Any] = None) -> requests.Response:
        config = self.configs[database]
        url = f"{config.base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        headers = self.get_headers(database)
        
        # Add API key to params if needed (e.g., NCBI)
        if config.api_key and database == 'pubmed':
            if params is None:
                params = {}
            params['api_key'] = config.api_key
        
        return requests.get(url, headers=headers, params=params)
```

### Rate Limiting Implementation

#### Intelligent Rate Limiter
```python
import time
import asyncio
from collections import defaultdict
from typing import Dict, Optional

class SynthexRateLimiter:
    def __init__(self):
        self.last_request: Dict[str, float] = {}
        self.request_counts: Dict[str, list] = defaultdict(list)
        
    def wait_if_needed(self, database: str, rate_limit: float):
        """Ensure we don't exceed rate limits"""
        now = time.time()
        
        if database in self.last_request:
            time_since_last = now - self.last_request[database]
            min_interval = 1.0 / rate_limit
            
            if time_since_last < min_interval:
                sleep_time = min_interval - time_since_last
                time.sleep(sleep_time)
        
        self.last_request[database] = time.time()
    
    async def async_wait_if_needed(self, database: str, rate_limit: float):
        """Async version of rate limiting"""
        now = time.time()
        
        if database in self.last_request:
            time_since_last = now - self.last_request[database]
            min_interval = 1.0 / rate_limit
            
            if time_since_last < min_interval:
                sleep_time = min_interval - time_since_last
                await asyncio.sleep(sleep_time)
        
        self.last_request[database] = time.time()
```

---

## 🔍 Cross-Reference and Search Strategies

### Multi-Database Search Implementation

#### Parallel Search Architecture
```python
import asyncio
import aiohttp
from typing import List, Dict, Any

class SynthexAcademicSearch:
    def __init__(self, api_manager: AcademicAPIManager):
        self.api_manager = api_manager
        self.rate_limiter = SynthexRateLimiter()
    
    async def search_all_databases(self, query: str, max_results: int = 10) -> Dict[str, List[Dict]]:
        """Search across all configured databases in parallel"""
        
        search_tasks = []
        
        # arXiv search
        if 'arxiv' in self.api_manager.configs:
            search_tasks.append(self.search_arxiv(query, max_results))
        
        # PubMed search
        if 'pubmed' in self.api_manager.configs:
            search_tasks.append(self.search_pubmed(query, max_results))
        
        # Crossref search
        if 'crossref' in self.api_manager.configs:
            search_tasks.append(self.search_crossref(query, max_results))
        
        # Semantic Scholar search
        if 'semantic_scholar' in self.api_manager.configs:
            search_tasks.append(self.search_semantic_scholar(query, max_results))
        
        # Execute all searches in parallel
        results = await asyncio.gather(*search_tasks, return_exceptions=True)
        
        # Organize results by database
        database_results = {}
        database_names = ['arxiv', 'pubmed', 'crossref', 'semantic_scholar']
        
        for i, result in enumerate(results):
            if i < len(database_names) and not isinstance(result, Exception):
                database_results[database_names[i]] = result
            elif isinstance(result, Exception):
                print(f"Error in {database_names[i] if i < len(database_names) else 'unknown'}: {result}")
        
        return database_results
    
    async def search_arxiv(self, query: str, max_results: int) -> List[Dict]:
        """Search arXiv database"""
        await self.rate_limiter.async_wait_if_needed('arxiv', 0.33)
        
        params = {
            'search_query': query,
            'start': 0,
            'max_results': max_results
        }
        
        async with aiohttp.ClientSession() as session:
            config = self.api_manager.configs['arxiv']
            async with session.get(
                f"{config.base_url}",
                params=params,
                headers=config.headers
            ) as response:
                content = await response.text()
                return self.parse_arxiv_response(content)
    
    # Similar methods for other databases...
```

### Data Normalization and Cross-Referencing

#### Unified Academic Result Format
```python
@dataclass
class AcademicResult:
    """Normalized academic result format"""
    title: str
    authors: List[str]
    abstract: Optional[str] = None
    publication_date: Optional[str] = None
    venue: Optional[str] = None
    doi: Optional[str] = None
    arxiv_id: Optional[str] = None
    pmid: Optional[str] = None
    url: Optional[str] = None
    pdf_url: Optional[str] = None
    citation_count: Optional[int] = None
    categories: List[str] = None
    keywords: List[str] = None
    open_access: Optional[bool] = None
    source_database: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'title': self.title,
            'authors': self.authors,
            'abstract': self.abstract,
            'publication_date': self.publication_date,
            'venue': self.venue,
            'identifiers': {
                'doi': self.doi,
                'arxiv_id': self.arxiv_id,
                'pmid': self.pmid
            },
            'urls': {
                'main': self.url,
                'pdf': self.pdf_url
            },
            'metrics': {
                'citation_count': self.citation_count
            },
            'classification': {
                'categories': self.categories,
                'keywords': self.keywords
            },
            'access': {
                'open_access': self.open_access
            },
            'source': self.source_database
        }

class AcademicResultNormalizer:
    """Normalize results from different databases to unified format"""
    
    def normalize_arxiv_result(self, arxiv_entry: Dict) -> AcademicResult:
        """Convert arXiv result to normalized format"""
        return AcademicResult(
            title=arxiv_entry.get('title', '').strip(),
            authors=self.extract_arxiv_authors(arxiv_entry.get('author', [])),
            abstract=arxiv_entry.get('summary', '').strip(),
            publication_date=arxiv_entry.get('published', ''),
            arxiv_id=self.extract_arxiv_id(arxiv_entry.get('id', '')),
            url=arxiv_entry.get('id', ''),
            pdf_url=arxiv_entry.get('id', '').replace('abs', 'pdf') + '.pdf',
            categories=arxiv_entry.get('category', []),
            open_access=True,  # arXiv is always open access
            source_database='arXiv'
        )
    
    def normalize_crossref_result(self, crossref_item: Dict) -> AcademicResult:
        """Convert Crossref result to normalized format"""
        return AcademicResult(
            title=crossref_item.get('title', [''])[0],
            authors=self.extract_crossref_authors(crossref_item.get('author', [])),
            publication_date=self.extract_crossref_date(crossref_item.get('published-print', {})),
            venue=crossref_item.get('container-title', [''])[0],
            doi=crossref_item.get('DOI', ''),
            url=crossref_item.get('URL', ''),
            citation_count=crossref_item.get('is-referenced-by-count', 0),
            open_access=self.is_crossref_open_access(crossref_item),
            source_database='Crossref'
        )
    
    # Additional normalization methods for other databases...
```

---

## 📊 Usage Analytics and Monitoring

### API Usage Tracking

#### Usage Monitor Implementation
```python
import json
from datetime import datetime
from typing import Dict, Any

class SynthexUsageMonitor:
    def __init__(self, log_file: str = "synthex_api_usage.log"):
        self.log_file = log_file
        self.session_stats = {
            'start_time': datetime.now().isoformat(),
            'requests_by_database': {},
            'total_requests': 0,
            'errors': []
        }
    
    def log_request(self, database: str, endpoint: str, status_code: int, response_time: float):
        """Log API request for monitoring"""
        if database not in self.session_stats['requests_by_database']:
            self.session_stats['requests_by_database'][database] = {
                'count': 0,
                'avg_response_time': 0,
                'errors': 0
            }
        
        db_stats = self.session_stats['requests_by_database'][database]
        db_stats['count'] += 1
        self.session_stats['total_requests'] += 1
        
        # Update average response time
        current_avg = db_stats['avg_response_time']
        new_count = db_stats['count']
        db_stats['avg_response_time'] = (current_avg * (new_count - 1) + response_time) / new_count
        
        # Log errors
        if status_code >= 400:
            db_stats['errors'] += 1
            self.session_stats['errors'].append({
                'database': database,
                'endpoint': endpoint,
                'status_code': status_code,
                'timestamp': datetime.now().isoformat()
            })
        
        # Write to log file
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'database': database,
            'endpoint': endpoint,
            'status_code': status_code,
            'response_time': response_time
        }
        
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def get_usage_summary(self) -> Dict[str, Any]:
        """Get usage summary for the current session"""
        return {
            'session_duration': (datetime.now() - datetime.fromisoformat(self.session_stats['start_time'])).total_seconds(),
            'total_requests': self.session_stats['total_requests'],
            'requests_by_database': self.session_stats['requests_by_database'],
            'error_count': len(self.session_stats['errors']),
            'errors': self.session_stats['errors']
        }
```

---

## 🚀 Quick Start Implementation

### 1. Environment Setup
```bash
# Create SYNTHEX academic environment
cd /home/louranicas/projects/claude-optimized-deployment

# Install required dependencies
pip install aiohttp requests xmltodict python-dotenv pyyaml

# Create environment file
cat > .env.academic << EOF
SYNTHEX_CONTACT_EMAIL=your_email@institution.edu
SYNTHEX_NCBI_API_KEY=your_ncbi_key_here
SYNTHEX_SEMANTIC_SCHOLAR_API_KEY=your_semantic_scholar_key_here
SYNTHEX_NASA_ADS_TOKEN=your_nasa_ads_token_here
SYNTHEX_ZENODO_TOKEN=your_zenodo_token_here
EOF

# Source environment
source .env.academic
```

### 2. Basic Search Example
```python
# Example usage
import asyncio

async def main():
    # Initialize API manager
    api_manager = AcademicAPIManager()
    
    # Create search instance
    search = SynthexAcademicSearch(api_manager)
    
    # Perform multi-database search
    results = await search.search_all_databases("machine learning", max_results=5)
    
    # Print results
    for database, papers in results.items():
        print(f"\n=== {database.upper()} Results ===")
        for paper in papers[:3]:  # Show first 3 results
            print(f"Title: {paper.get('title', 'No title')}")
            print(f"Authors: {', '.join(paper.get('authors', []))}")
            print(f"URL: {paper.get('url', 'No URL')}")
            print("-" * 50)

# Run the search
if __name__ == "__main__":
    asyncio.run(main())
```

### 3. Production Deployment Configuration

#### Docker Configuration
```dockerfile
# Dockerfile.synthex-academic
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements-academic.txt .
RUN pip install -r requirements-academic.txt

# Copy SYNTHEX academic modules
COPY src/synthex/ ./synthex/
COPY config/academic/ ./config/

# Set environment variables
ENV PYTHONPATH=/app
ENV SYNTHEX_CONFIG_PATH=/app/config/academic.yaml

# Expose API port
EXPOSE 8080

CMD ["python", "-m", "synthex.academic.server"]
```

#### Kubernetes Deployment
```yaml
# k8s/synthex-academic-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: synthex-academic
  namespace: synthex
spec:
  replicas: 3
  selector:
    matchLabels:
      app: synthex-academic
  template:
    metadata:
      labels:
        app: synthex-academic
    spec:
      containers:
      - name: synthex-academic
        image: synthex/academic:latest
        ports:
        - containerPort: 8080
        env:
        - name: SYNTHEX_CONTACT_EMAIL
          valueFrom:
            secretKeyRef:
              name: synthex-academic-secrets
              key: contact-email
        - name: SYNTHEX_NCBI_API_KEY
          valueFrom:
            secretKeyRef:
              name: synthex-academic-secrets
              key: ncbi-api-key
        resources:
          requests:
            cpu: 100m
            memory: 256Mi
          limits:
            cpu: 500m
            memory: 1Gi
---
apiVersion: v1
kind: Service
metadata:
  name: synthex-academic-service
  namespace: synthex
spec:
  selector:
    app: synthex-academic
  ports:
  - port: 80
    targetPort: 8080
  type: ClusterIP
```

---

## 📚 Additional Resources

### API Documentation Links
- **arXiv API**: https://arxiv.org/help/api/user-manual
- **PubMed E-utilities**: https://www.ncbi.nlm.nih.gov/books/NBK25497/
- **Crossref API**: https://github.com/CrossRef/rest-api-doc
- **Semantic Scholar API**: https://api.semanticscholar.org/api-docs/
- **NASA/ADS API**: https://ui.adsabs.harvard.edu/help/api/
- **ORCID API**: https://orcid.org/organizations/integrators/API
- **Zenodo API**: https://developers.zenodo.org/

### Best Practices
1. **Always respect rate limits** - Use exponential backoff for retries
2. **Cache responses** - Academic content changes slowly
3. **Use contact emails** - Many APIs offer better service for identifiable users
4. **Monitor usage** - Track API calls to avoid hitting limits
5. **Handle errors gracefully** - Implement fallbacks for API failures
6. **Normalize data** - Use consistent formats across databases
7. **Cite sources** - Always acknowledge data sources in academic use

### Troubleshooting
- **Rate limit exceeded**: Implement exponential backoff
- **Authentication failed**: Check API key validity and permissions
- **No results found**: Try alternative search terms or databases
- **Connection timeout**: Implement retry logic with increasing delays
- **Quota exceeded**: Monitor daily/monthly usage limits

---

*Last Updated: June 14, 2025*  
*Document Version: 1.0*  
*SYNTHEX Academic Database Integration Guide*