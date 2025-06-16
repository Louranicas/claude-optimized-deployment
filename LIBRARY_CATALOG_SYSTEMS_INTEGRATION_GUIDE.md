# Library and Catalog Systems API Integration Guide

## Overview

This document provides comprehensive documentation of library and catalog systems with API access that can be integrated with SYNTHEX for academic searches. Each system offers unique capabilities, authentication methods, and search features that can enhance research capabilities.

## 1. OCLC WorldCat Search API

### Overview
WorldCat is the world's largest network of library content and services, providing access to metadata for over 500 million bibliographic records.

### Authentication Methods
- **API Key (WSKey)**: Required for all requests
- **OAuth 2.0**: Modern authentication for version 2.0 (current)
- **Client Credential Grant Flow**: Standard OAuth implementation

### Authentication Setup
1. Register at OCLC Developer Network
2. Obtain WSKey credentials
3. Implement OAuth 2.0 client credential flow
4. Use access tokens for API requests

### Search Capabilities
- **Bibliographic Records**: Full MARC records with detailed metadata
- **Holdings Information**: Library ownership and availability data
- **Multi-format Support**: Books, journals, digital resources, audiovisual materials
- **Authority Records**: Name, subject, and title authorities
- **Real-time Availability**: Current library holdings and circulation status

### Integration Points for SYNTHEX
```python
# Example integration pattern
class WorldCatIntegration:
    def __init__(self, wskey, secret):
        self.auth = OAuth2Session(client_id=wskey, client_secret=secret)
        self.base_url = "https://worldcat.org/webservices/catalog"
    
    def search_scholarly_works(self, query, filters=None):
        """Search for academic publications and resources"""
        params = {
            'query': query,
            'format': 'json',
            'recordSchema': 'marcxml',
            'maximumRecords': 100
        }
        if filters:
            params.update(filters)
        
        return self.auth.get(f"{self.base_url}/search", params=params)
```

### Rate Limits and Restrictions
- Requires active OCLC membership or subscription
- Rate limiting enforced (specific limits vary by agreement)
- Version 1.0 deprecated as of December 31, 2024

---

## 2. Library of Congress APIs

### Overview
The Library of Congress provides multiple APIs for accessing the world's largest library collection, including books, manuscripts, maps, photographs, and digital content.

### Authentication Methods
- **Public APIs**: No authentication required for most read operations
- **Congress.gov API**: Requires API key from Data.gov
- **Rate Limiting**: 5,000 requests per hour for Congress.gov API

### Available APIs

#### 2.1 Main loc.gov JSON/YAML API
- **Access**: Public, no authentication required
- **Data Format**: JSON and YAML
- **Collections**: Books, manuscripts, maps, photographs, audio recordings
- **Deep Pagination Limit**: 100,000 items maximum

#### 2.2 Congress.gov API
- **Purpose**: Congressional documents, bills, resolutions, reports
- **Authentication**: API key required
- **Rate Limit**: 5,000 requests/hour
- **Data Types**: Legislative documents, voting records, member information

#### 2.3 Chronicling America API
- **Content**: Historic digitized newspapers
- **Coverage**: 12+ million newspaper pages
- **Authentication**: None required
- **Time Period**: 1690-present

### Search Capabilities
- **Full-text Search**: Comprehensive text searching across collections
- **Faceted Search**: Filter by format, date, subject, language
- **Flexible Querying**: Advanced search parameters and boolean operators
- **Metadata Richness**: Detailed bibliographic and descriptive metadata

### Integration Points for SYNTHEX
```python
class LibraryOfCongressIntegration:
    def __init__(self):
        self.base_url = "https://www.loc.gov"
        self.congress_api_key = os.getenv('CONGRESS_API_KEY')
    
    def search_historical_documents(self, query, date_range=None):
        """Search historical documents and manuscripts"""
        params = {
            'q': query,
            'fo': 'json',
            'c': 250  # Maximum results per page
        }
        if date_range:
            params['dates'] = f"{date_range['start']}-{date_range['end']}"
        
        return requests.get(f"{self.base_url}/search/", params=params)
    
    def search_congressional_documents(self, query, congress_number=None):
        """Search congressional documents and legislation"""
        headers = {'X-API-Key': self.congress_api_key}
        params = {'query': query, 'format': 'json'}
        if congress_number:
            params['congress'] = congress_number
        
        return requests.get(
            "https://api.congress.gov/v3/bill", 
            headers=headers, 
            params=params
        )
```

---

## 3. HathiTrust Digital Library API

### Overview
HathiTrust provides access to over 17 million digitized items from university and research libraries, with sophisticated copyright and access management.

### Authentication Methods
- **One-legged OAuth**: Programmatic access with signed requests
- **Web Authentication**: For individual users (requires institutional affiliation or University of Michigan "Friend" account)
- **Access Keys**: Required for Data API usage

### Available APIs

#### 3.1 Bibliographic API
- **Purpose**: Real-time querying for bibliographic records
- **Identifiers**: ISBN, LCCN, OCLC, HathiTrust IDs
- **Response Types**: Brief or full bibliographic records
- **Batch Support**: Up to 20 records per request

#### 3.2 Data API
- **Content**: Page images, OCR text, METS metadata
- **Access Control**: Respects copyright and access restrictions
- **Authentication**: OAuth-signed requests required
- **Rate Limits**: Restrictions apply for bulk access

### Search Capabilities
- **Multi-identifier Search**: Support for various standard identifiers
- **Rights Information**: Copyright status and access permissions
- **Volume-level Data**: Detailed structural metadata
- **OCR Text Access**: Full-text content where permitted

### Integration Points for SYNTHEX
```python
import oauth2 as oauth

class HathiTrustIntegration:
    def __init__(self, access_key, secret_key):
        self.consumer = oauth.Consumer(key=access_key, secret=secret_key)
        self.base_url = "https://babel.hathitrust.org/cgi/htapi"
    
    def get_bibliographic_data(self, identifiers):
        """Retrieve bibliographic information for multiple identifiers"""
        url = f"{self.base_url}/volumes/brief/json/{';'.join(identifiers)}"
        
        # OAuth signature required
        req = oauth.Request.from_consumer_and_token(
            self.consumer, http_method="GET", http_url=url
        )
        req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), self.consumer, None)
        
        return requests.get(req.to_url())
    
    def search_full_text(self, ht_id):
        """Access OCR text for copyright-cleared materials"""
        url = f"{self.base_url}/volumes/full/{ht_id}.json"
        # Implementation depends on access rights and authentication
        return self._authenticated_request(url)
```

### Important Considerations
- **Copyright Restrictions**: Access varies by copyright status
- **Institutional Access**: Some content requires institutional affiliation
- **Bulk Access**: Use OAI feeds or request datasets for large-scale access
- **Dynamic Collection**: Content and access permissions updated regularly

---

## 4. Internet Archive Scholar API

### Overview
Internet Archive provides APIs for accessing their vast digital collections, including web pages, books, movies, music, and scholarly content.

### Authentication Methods
- **Configuration-based**: Credentials stored in config files or environment variables
- **Archive.org Account**: Required for certain operations (uploading, modifying metadata)
- **No Authentication**: Many read operations are public

### API Capabilities
- **Search API**: Full-text search across collections
- **Metadata API**: Detailed item metadata and descriptions
- **Download API**: Access to digital content files
- **Wayback Machine API**: Historical web page access

### Search Capabilities
- **Full-text Indexing**: Searchable text content from books and documents
- **Metadata Search**: Search across title, creator, subject, description fields
- **Advanced Filtering**: Date ranges, media types, collections, languages
- **Bulk Operations**: Support for large-scale data retrieval

### Integration Points for SYNTHEX
```python
from internetarchive import search, get_item

class InternetArchiveIntegration:
    def __init__(self, access_key=None, secret_key=None):
        if access_key and secret_key:
            internetarchive.configure(access_key, secret_key)
    
    def search_scholarly_texts(self, query, mediatype='texts'):
        """Search for academic texts and documents"""
        search_params = {
            'query': f'({query}) AND mediatype:{mediatype}',
            'fields': ['identifier', 'title', 'creator', 'date', 'subject'],
            'sorts': ['downloads desc']
        }
        
        for result in search(**search_params):
            yield {
                'identifier': result['identifier'],
                'title': result.get('title', ''),
                'creator': result.get('creator', ''),
                'date': result.get('date', ''),
                'url': f"https://archive.org/details/{result['identifier']}"
            }
    
    def get_full_text(self, identifier):
        """Extract full text from digitized books"""
        item = get_item(identifier)
        # Look for text files or OCR data
        for file in item.files:
            if file.name.endswith('_djvu.txt') or file.name.endswith('.txt'):
                return file.download(file_path=f"/tmp/{file.name}")
```

---

## 5. DPLA (Digital Public Library of America) API

### Overview
DPLA aggregates metadata from thousands of libraries, archives, and museums across the United States, providing unified access to millions of cultural heritage items.

### Authentication Methods
- **API Key Required**: 32-character unique identifier
- **Email-based Registration**: Send POST request to obtain key
- **No Rate Limiting**: Generally unrestricted access

### Authentication Setup
```bash
curl -X POST https://api.dp.la/v2/api_key/your_email@example.com
```

### Search Capabilities
- **Unified Search**: Aggregated content from 4,000+ institutions
- **Rich Metadata**: Standardized descriptive information
- **Media Types**: Books, photographs, videos, audio, manuscripts
- **Geographic Coverage**: Comprehensive US cultural heritage

### API Resources

#### 5.1 Items API
- **Content**: Individual digital objects
- **Metadata**: Title, creator, date, subject, description, rights
- **Media Access**: Links to high-resolution images and files
- **Provenance**: Source institution and collection information

#### 5.2 Collections API
- **Purpose**: Conceptual groupings of related items
- **Hierarchy**: Institution → Collection → Items
- **Metadata**: Collection-level descriptions and contexts

### Advanced Search Features
- **Fielded Search**: Target specific metadata fields
- **Date Range Queries**: Temporal filtering with intelligent parsing
- **Boolean Logic**: AND/OR operators for complex queries
- **Faceted Browse**: Filter by type, subject, location, time period

### Integration Points for SYNTHEX
```python
class DPLAIntegration:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://api.dp.la/v2"
    
    def search_cultural_heritage(self, query, filters=None):
        """Search across American cultural heritage collections"""
        params = {
            'q': query,
            'api_key': self.api_key,
            'page_size': 100
        }
        
        if filters:
            for field, value in filters.items():
                params[f"sourceResource.{field}"] = value
        
        response = requests.get(f"{self.base_url}/items", params=params)
        return self._process_results(response.json())
    
    def search_by_date_range(self, query, start_year, end_year):
        """Search with temporal constraints"""
        date_query = f"sourceResource.date:[{start_year} TO {end_year}]"
        params = {
            'q': f"{query} AND {date_query}",
            'api_key': self.api_key
        }
        
        return requests.get(f"{self.base_url}/items", params=params)
```

---

## 6. Europeana API

### Overview
Europeana provides access to over 50 million cultural heritage items from European museums, libraries, archives, and galleries.

### Authentication Methods
- **API Key Required**: Free registration with Europeana account
- **wskey Parameter**: Append to all API requests
- **No Authentication**: Thumbnail API only

### Available APIs

#### 6.1 Search API
- **Content**: Metadata records and media files
- **Coverage**: Books, artworks, artifacts, audiovisual materials
- **Languages**: Multilingual content and metadata
- **Institutions**: 4,000+ European cultural institutions

#### 6.2 Record API
- **Purpose**: Detailed individual item data
- **Formats**: JSON, JSON-LD, RDF/XML
- **Data Model**: Europeana Data Model (EDM)
- **Identifiers**: Unique Europeana IDs

#### 6.3 Entity API
- **Content**: Named entities (people, places, concepts, time periods)
- **Relationships**: Connections between entities and cultural objects
- **Authority Data**: Standardized forms of names and concepts

### Search Capabilities
- **Multilingual Search**: Search across European languages
- **Media Filtering**: Filter by image size, reusability, media presence
- **Rights Filtering**: Focus on openly licensed content
- **Advanced Faceting**: Type, country, language, time period, provider

### Integration Points for SYNTHEX
```python
class EuropeanaIntegration:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://api.europeana.eu/record/v2"
    
    def search_european_heritage(self, query, filters=None):
        """Search European cultural heritage collections"""
        params = {
            'query': query,
            'wskey': self.api_key,
            'rows': 100,
            'profile': 'rich'
        }
        
        if filters:
            if 'reusability' in filters:
                params['reusability'] = filters['reusability']
            if 'media'] in filters:
                params['media'] = 'true'
            if 'thumbnail'] in filters:
                params['thumbnail'] = 'true'
        
        return requests.get(f"{self.base_url}/search.json", params=params)
    
    def get_entity_information(self, entity_id):
        """Retrieve information about people, places, concepts"""
        params = {'wskey': self.api_key}
        return requests.get(
            f"https://api.europeana.eu/entity/{entity_id}.json",
            params=params
        )
```

---

## 7. OpenLibrary API

### Overview
OpenLibrary is an open, editable library catalog building toward a web page for every book ever published, with over 3 million free books available.

### Authentication Methods
- **No Authentication**: Required for read operations (search, book data)
- **Cookie-based**: Required for write operations (editing, creating records)
- **Archive.org Credentials**: For advanced operations and client library

### Available APIs

#### 7.1 Search API
- **Scope**: Books, authors, subjects, works
- **Response Format**: JSON with configurable fields
- **Advanced Features**: Sort options, field selection, edition data

#### 7.2 Books API
- **Purpose**: Retrieve specific books by identifier
- **Identifiers**: ISBN, OCLC, LCCN, OpenLibrary IDs
- **Compatibility**: Google Books Dynamic Links API compatible
- **Bulk Support**: Multiple books per request

#### 7.3 Authors API
- **Content**: Author biographical information
- **Works**: Complete author bibliographies
- **Relationships**: Connected works and editions

### Search Capabilities
- **Comprehensive Coverage**: Books, authors, subjects, publishers
- **Full-text Search**: When available for open books
- **Advanced Filtering**: By author, title, subject, publication date
- **Flexible Output**: Configurable response fields and formats

### Integration Points for SYNTHEX
```python
class OpenLibraryIntegration:
    def __init__(self):
        self.base_url = "https://openlibrary.org"
    
    def search_books(self, query, filters=None):
        """Search for books across OpenLibrary"""
        params = {
            'q': query,
            'format': 'json',
            'limit': 100
        }
        
        if filters:
            if 'author' in filters:
                params['author'] = filters['author']
            if 'subject' in filters:
                params['subject'] = filters['subject']
            if 'publish_year' in filters:
                params['publish_year'] = filters['publish_year']
        
        return requests.get(f"{self.base_url}/search.json", params=params)
    
    def get_book_by_isbn(self, isbn):
        """Retrieve detailed book information by ISBN"""
        url = f"{self.base_url}/api/books"
        params = {
            'bibkeys': f'ISBN:{isbn}',
            'format': 'json',
            'jscmd': 'data'
        }
        
        return requests.get(url, params=params)
    
    def search_authors(self, author_name):
        """Search for author information and works"""
        params = {'q': author_name}
        return requests.get(f"{self.base_url}/search/authors.json", params=params)
```

---

## SYNTHEX Integration Architecture

### Unified Search Interface

```python
class SYNTHEXLibraryIntegrator:
    def __init__(self, config):
        self.integrations = {
            'worldcat': WorldCatIntegration(config['worldcat']['wskey'], config['worldcat']['secret']),
            'loc': LibraryOfCongressIntegration(),
            'hathitrust': HathiTrustIntegration(config['hathitrust']['access_key'], config['hathitrust']['secret_key']),
            'ia': InternetArchiveIntegration(),
            'dpla': DPLAIntegration(config['dpla']['api_key']),
            'europeana': EuropeanaIntegration(config['europeana']['api_key']),
            'openlibrary': OpenLibraryIntegration()
        }
    
    async def comprehensive_search(self, query, filters=None, sources=None):
        """Execute parallel searches across multiple library systems"""
        if sources is None:
            sources = list(self.integrations.keys())
        
        tasks = []
        for source in sources:
            if source in self.integrations:
                task = asyncio.create_task(
                    self._search_source(source, query, filters)
                )
                tasks.append((source, task))
        
        results = {}
        for source, task in tasks:
            try:
                results[source] = await task
            except Exception as e:
                results[source] = {'error': str(e)}
        
        return self._merge_and_rank_results(results)
    
    async def _search_source(self, source, query, filters):
        """Execute search against specific source"""
        integration = self.integrations[source]
        
        # Implement source-specific search logic
        if source == 'worldcat':
            return await integration.search_scholarly_works(query, filters)
        elif source == 'loc':
            return await integration.search_historical_documents(query, filters)
        elif source == 'hathitrust':
            # Convert query to identifiers if needed
            return await integration.get_bibliographic_data([query])
        # ... implement for other sources
    
    def _merge_and_rank_results(self, results):
        """Merge results from multiple sources and apply relevance ranking"""
        merged_results = []
        
        for source, source_results in results.items():
            if 'error' not in source_results:
                for item in source_results.get('items', []):
                    item['source'] = source
                    item['relevance_score'] = self._calculate_relevance(item)
                    merged_results.append(item)
        
        # Sort by relevance and remove duplicates
        merged_results.sort(key=lambda x: x['relevance_score'], reverse=True)
        return self._deduplicate_results(merged_results)
```

### Configuration Management

```yaml
# config/library_apis.yml
worldcat:
  wskey: "${WORLDCAT_WSKEY}"
  secret: "${WORLDCAT_SECRET}"
  base_url: "https://worldcat.org/webservices/catalog"

library_of_congress:
  congress_api_key: "${CONGRESS_API_KEY}"
  base_url: "https://www.loc.gov"

hathitrust:
  access_key: "${HATHITRUST_ACCESS_KEY}"
  secret_key: "${HATHITRUST_SECRET_KEY}"
  base_url: "https://babel.hathitrust.org/cgi/htapi"

internet_archive:
  access_key: "${IA_ACCESS_KEY}"
  secret_key: "${IA_SECRET_KEY}"

dpla:
  api_key: "${DPLA_API_KEY}"
  base_url: "https://api.dp.la/v2"

europeana:
  api_key: "${EUROPEANA_API_KEY}"
  base_url: "https://api.europeana.eu"

openlibrary:
  base_url: "https://openlibrary.org"
```

## Rate Limiting and Best Practices

### Implementation Strategies

```python
import asyncio
import aiohttp
from aiolimiter import AsyncLimiter

class RateLimitedAPIClient:
    def __init__(self, rate_limit_per_second=1):
        self.limiter = AsyncLimiter(rate_limit_per_second, 1.0)
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.session.close()
    
    async def request(self, method, url, **kwargs):
        async with self.limiter:
            async with self.session.request(method, url, **kwargs) as response:
                return await response.json()

# Usage in integration classes
class WorldCatIntegration:
    def __init__(self, wskey, secret):
        self.client = RateLimitedAPIClient(rate_limit_per_second=2)
        # ... rest of initialization
```

### Error Handling and Resilience

```python
import asyncio
from tenacity import retry, stop_after_attempt, wait_exponential

class ResilientAPIIntegration:
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10)
    )
    async def api_request(self, url, params=None):
        """Resilient API request with exponential backoff"""
        try:
            async with self.session.get(url, params=params) as response:
                if response.status == 429:  # Rate limited
                    await asyncio.sleep(30)
                    raise Exception("Rate limited")
                response.raise_for_status()
                return await response.json()
        except Exception as e:
            logger.warning(f"API request failed: {e}")
            raise
```

## Performance Optimization

### Caching Strategy

```python
import redis
import json
from datetime import timedelta

class CachedLibrarySearch:
    def __init__(self, redis_url="redis://localhost:6379"):
        self.redis_client = redis.from_url(redis_url)
        self.cache_ttl = timedelta(hours=24)
    
    def get_cache_key(self, source, query, filters):
        """Generate unique cache key for search parameters"""
        import hashlib
        key_data = json.dumps({
            'source': source,
            'query': query,
            'filters': filters or {}
        }, sort_keys=True)
        return f"library_search:{hashlib.md5(key_data.encode()).hexdigest()}"
    
    async def cached_search(self, source, query, filters=None):
        """Search with caching"""
        cache_key = self.get_cache_key(source, query, filters)
        
        # Try cache first
        cached_result = self.redis_client.get(cache_key)
        if cached_result:
            return json.loads(cached_result)
        
        # Execute search
        result = await self._execute_search(source, query, filters)
        
        # Cache result
        self.redis_client.setex(
            cache_key,
            self.cache_ttl,
            json.dumps(result)
        )
        
        return result
```

## Data Standardization

### Unified Result Format

```python
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from datetime import datetime

@dataclass
class StandardizedResult:
    id: str
    source: str
    title: str
    authors: List[str]
    publication_date: Optional[datetime]
    subjects: List[str]
    description: Optional[str]
    url: str
    thumbnail_url: Optional[str]
    full_text_available: bool
    access_rights: str
    media_type: str
    language: List[str]
    institution: Optional[str]
    collection: Optional[str]
    raw_metadata: Dict[str, Any]
    relevance_score: float = 0.0

class ResultStandardizer:
    """Convert source-specific results to standardized format"""
    
    def standardize_worldcat_result(self, result: Dict) -> StandardizedResult:
        """Convert WorldCat result to standard format"""
        return StandardizedResult(
            id=result.get('oclcNumber', ''),
            source='worldcat',
            title=result.get('title', ''),
            authors=self._extract_authors(result.get('creator', [])),
            publication_date=self._parse_date(result.get('date')),
            subjects=result.get('subject', []),
            description=result.get('summary', ''),
            url=f"https://worldcat.org/oclc/{result.get('oclcNumber')}",
            thumbnail_url=result.get('thumbnail'),
            full_text_available=bool(result.get('digitalResources')),
            access_rights=self._determine_access_rights(result),
            media_type=result.get('itemType', 'unknown'),
            language=result.get('language', []),
            institution=result.get('institution'),
            collection=result.get('collection'),
            raw_metadata=result
        )
    
    def standardize_dpla_result(self, result: Dict) -> StandardizedResult:
        """Convert DPLA result to standard format"""
        source_resource = result.get('sourceResource', {})
        return StandardizedResult(
            id=result.get('id', ''),
            source='dpla',
            title=self._get_first_or_string(source_resource.get('title', '')),
            authors=self._extract_dpla_creators(source_resource.get('creator', [])),
            publication_date=self._parse_dpla_date(source_resource.get('date')),
            subjects=self._extract_dpla_subjects(source_resource.get('subject', [])),
            description=self._get_first_or_string(source_resource.get('description', '')),
            url=result.get('isShownAt', ''),
            thumbnail_url=result.get('object'),
            full_text_available=False,  # DPLA typically provides metadata only
            access_rights=self._extract_rights(result.get('rights')),
            media_type=self._determine_dpla_media_type(source_resource.get('type', [])),
            language=source_resource.get('language', []),
            institution=result.get('dataProvider', ''),
            collection=result.get('provider', ''),
            raw_metadata=result
        )
```

## Monitoring and Analytics

### Search Analytics

```python
import logging
from datetime import datetime
from typing import Dict, List

class LibrarySearchAnalytics:
    def __init__(self, metrics_backend=None):
        self.metrics = metrics_backend
        self.logger = logging.getLogger(__name__)
    
    def track_search(self, query: str, sources: List[str], results_count: Dict[str, int]):
        """Track search metrics"""
        self.logger.info(f"Search executed: query='{query}', sources={sources}")
        
        for source, count in results_count.items():
            if self.metrics:
                self.metrics.increment(f"library_search.{source}.requests")
                self.metrics.histogram(f"library_search.{source}.results", count)
    
    def track_api_performance(self, source: str, response_time: float, status: str):
        """Track API response metrics"""
        if self.metrics:
            self.metrics.histogram(f"library_api.{source}.response_time", response_time)
            self.metrics.increment(f"library_api.{source}.{status}")
    
    def generate_usage_report(self) -> Dict:
        """Generate comprehensive usage analytics"""
        # Implementation depends on metrics backend
        pass
```

## Security Considerations

### API Key Management

```python
import os
from cryptography.fernet import Fernet

class SecureAPIKeyManager:
    def __init__(self, encryption_key=None):
        self.cipher = Fernet(encryption_key or self._generate_key())
    
    def _generate_key(self):
        """Generate encryption key from environment or create new"""
        key = os.getenv('API_ENCRYPTION_KEY')
        if not key:
            key = Fernet.generate_key()
            # Store securely (implementation specific)
        return key
    
    def encrypt_api_key(self, api_key: str) -> bytes:
        """Encrypt API key for storage"""
        return self.cipher.encrypt(api_key.encode())
    
    def decrypt_api_key(self, encrypted_key: bytes) -> str:
        """Decrypt API key for use"""
        return self.cipher.decrypt(encrypted_key).decode()
```

## Testing Framework

### Integration Tests

```python
import pytest
import asyncio
from unittest.mock import AsyncMock, patch

class TestLibraryIntegrations:
    @pytest.fixture
    def mock_config(self):
        return {
            'worldcat': {'wskey': 'test_key', 'secret': 'test_secret'},
            'dpla': {'api_key': 'test_dpla_key'},
            'europeana': {'api_key': 'test_europeana_key'}
        }
    
    @pytest.mark.asyncio
    async def test_comprehensive_search(self, mock_config):
        """Test parallel search across multiple sources"""
        integrator = SYNTHEXLibraryIntegrator(mock_config)
        
        with patch.multiple(
            integrator,
            _search_source=AsyncMock(return_value={'items': [{'title': 'Test'}]})
        ):
            results = await integrator.comprehensive_search("test query")
            assert 'worldcat' in results
            assert 'dpla' in results
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self):
        """Test rate limiting functionality"""
        client = RateLimitedAPIClient(rate_limit_per_second=2)
        start_time = asyncio.get_event_loop().time()
        
        async with client:
            # Execute multiple requests
            tasks = [client.request('GET', 'http://httpbin.org/delay/0') for _ in range(5)]
            await asyncio.gather(*tasks)
        
        elapsed = asyncio.get_event_loop().time() - start_time
        # Should take at least 2 seconds for 5 requests at 2 req/sec
        assert elapsed >= 2.0
```

## Conclusion

This comprehensive integration guide provides the foundation for incorporating multiple library and catalog systems into SYNTHEX. Each API offers unique strengths:

- **WorldCat**: Comprehensive bibliographic data and library holdings
- **Library of Congress**: Authoritative and historical documents
- **HathiTrust**: Large-scale digitized academic collections
- **Internet Archive**: Open access to diverse digital materials
- **DPLA**: Unified access to American cultural heritage
- **Europeana**: European cultural and academic resources
- **OpenLibrary**: Open, collaborative book catalog

The unified integration architecture enables SYNTHEX to provide comprehensive academic search capabilities while maintaining performance, reliability, and respect for each API's terms of service and rate limits.

### Next Steps

1. **API Key Registration**: Obtain necessary API keys for each service
2. **Rate Limiting Implementation**: Implement respectful rate limiting for all APIs
3. **Caching Strategy**: Deploy Redis-based caching for improved performance
4. **Monitoring Setup**: Implement comprehensive logging and metrics collection
5. **Security Hardening**: Implement secure API key management and encryption
6. **Testing Suite**: Develop comprehensive integration and performance tests

This integration will significantly enhance SYNTHEX's ability to provide comprehensive, authoritative academic search results across diverse library and cultural heritage collections.