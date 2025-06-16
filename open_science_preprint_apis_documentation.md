# Open Science and Preprint Repository APIs Documentation

This document provides comprehensive information about API access methods, authentication requirements, data formats, and integration possibilities for major open science and preprint repositories.

## Table of Contents
1. [bioRxiv API](#biorxiv-api)
2. [medRxiv API](#medrxiv-api)
3. [SSRN API](#ssrn-api)
4. [ResearchGate API](#researchgate-api)
5. [Academia.edu API](#academiaede-api)
6. [Zenodo API](#zenodo-api)
7. [Figshare API](#figshare-api)
8. [ORCID API](#orcid-api)
9. [SYNTHEX Integration Strategy](#synthex-integration-strategy)

---

## bioRxiv API

### Overview
bioRxiv is an open-access preprint repository for life sciences operated by Cold Spring Harbor Laboratory.

### API Access Methods
- **Base URL**: `https://api.biorxiv.org/`
- **Endpoint Format**: `https://api.biorxiv.org/pubs/[server]/[interval]/[cursor]` or `https://api.biorxiv.org/pubs/[server]/[DOI]/na/[format]`

### Key Endpoints
1. **Content/Details**: `https://api.biorxiv.org/details/[server]/[interval]/[cursor]/[format]`
2. **Published Papers**: `https://api.biorxiv.org/publisher/[publisher prefix]/[interval]/[cursor]`
3. **Summary Statistics**: For aggregate data about submissions and usage

### Authentication
- **No Authentication Required**: Completely open access with no API keys or tokens needed
- **Rate Limiting**: No official limits specified, but recommended 1-second timeout between calls

### Parameters
- **server**: 'biorxiv' or 'medrxiv'
- **interval**: Date range (YYYY-MM-DD/YYYY-MM-DD), number of recent papers, or days (e.g., '30d')
- **cursor**: Starting point for pagination (defaults to 0)
- **format**: Output format (JSON default, CSV available)

### Data Format
- **Primary**: JSON (default)
- **Alternative**: CSV download available
- **Pagination**: 100 articles per call

### Example API Calls
```
# Get papers between dates
https://api.biorxiv.org/pubs/biorxiv/2020-03-01/2020-03-30/5

# Get details with pagination
https://api.biorxiv.org/details/biorxiv/2018-08-21/2018-08-28/45

# CSV format
https://api.biorxiv.org/pub/2017-08-21/2017-08-28/30/csv
```

### SYNTHEX Integration Notes
- Perfect for automated content harvesting
- No authentication barriers
- Consistent JSON structure for easy parsing
- Supports both bioRxiv and medRxiv from same API

---

## medRxiv API

### Overview
medRxiv is a preprint repository for health sciences, sharing the same API infrastructure as bioRxiv.

### API Access Methods
- **Shared Infrastructure**: Uses the same API as bioRxiv (`https://api.biorxiv.org/`)
- **Server Parameter**: Set to 'medrxiv' instead of 'biorxiv'

### Authentication
- **No Authentication Required**: Same as bioRxiv

### Data Format
- **JSON**: Primary format with metadata fields (title, authors, abstract, DOI, publication date)
- **CSV**: Available for bulk downloads
- **Cleaning Options**: Raw vs. cleaned data available through R packages

### Access via R Packages
1. **medrxivr**: Primary R package for programmatic access
   ```r
   # Get preprint data
   preprint_data <- mx_api_content()
   
   # Access static snapshot
   snapshot_data <- mx_snapshot()
   ```

2. **rbiorxiv**: Alternative R client for bioRxiv/medRxiv API

### Key Features
- DOI assignment for all preprints
- Export to BIB format for reference managers
- PDF download capabilities
- Search functionality with regular expressions

### SYNTHEX Integration Notes
- Health sciences focus makes it valuable for medical AI applications
- Same technical integration as bioRxiv
- Rich metadata suitable for content analysis

---

## SSRN API

### Overview
Social Science Research Network (SSRN) owned by Elsevier, focusing on social sciences, humanities, and economics.

### API Status
- **No Official Public API Available**
- **Access Method**: Web interface only
- **Alternative**: Python web scraping tools exist (GitHub: ssrn-scraper)

### Authentication
- **Account Required**: Free SSRN membership for access
- **No API Authentication**: Since no official API exists

### Data Access Limitations
- No programmatic access endpoints
- Web scraping may violate terms of service
- Content browsing and upload available through web interface only

### SYNTHEX Integration Notes
- **Not Recommended**: Due to lack of official API
- **Alternative Approach**: Manual data export or partnership discussions with Elsevier
- **Content Value**: High-quality social science research but access limited

---

## ResearchGate API

### Overview
Academic social networking platform with research publication sharing.

### API Status
- **No Official Public API Available**
- **Historical Note**: API was in development but never launched publicly
- **Alternative Access**: Third-party scraping solutions exist

### Authentication
- **Not Applicable**: No official API endpoints
- **Account Integration**: Social media connections available (Facebook, Twitter, LinkedIn)

### Alternative Solutions
- Web scraping with tools like Playwright, Selenium
- Third-party services like SerpAPI for structured data extraction
- HTML to JSON proxy scrapers (unofficial)

### Terms of Service Considerations
- Prohibits accessing content at unusually high rates
- Accessing content without permission violates terms
- JavaScript obfuscation makes scraping challenging

### SYNTHEX Integration Notes
- **Not Recommended**: Due to legal and technical barriers
- **Alternative Platforms**: Consider official APIs from Semantic Scholar, CrossRef, PubMed
- **Content Value**: High researcher engagement but access restricted

---

## Academia.edu API

### Overview
Academic platform for sharing research papers and academic profiles.

### API Status
- **No Official Public API Available**
- **Developer Resources**: None found in official documentation
- **GitHub Presence**: 78 repositories available but no public API resources

### Authentication
- **Not Applicable**: No API endpoints available
- **Platform Access**: Free account creation for web interface

### Alternative Access Methods
- **Web Interface Only**: Browse and upload through academia.edu website
- **No Programmatic Access**: Currently not supported

### SYNTHEX Integration Notes
- **Not Viable**: No technical integration path available
- **Contact Approach**: Direct communication with Academia.edu for potential partnerships
- **Content Access**: Manual export only

---

## Zenodo API

### Overview
Open research data repository operated by CERN, supporting FAIR data principles.

### API Access Methods
- **Base URL**: `https://zenodo.org/api/`
- **Architecture**: REST API versioned for backward compatibility
- **Protocol**: HTTPS required for all requests

### Authentication
- **OAuth 2.0**: Primary authentication method
- **Personal Access Tokens**: Alternative to API keys (deprecated)
- **Setup Process**: 
  1. Register Zenodo account
  2. Create token in Applications section
  3. Select appropriate OAuth scopes

### OAuth Scopes
- `deposit:write`: Create and edit depositions
- `deposit:actions`: Publish and edit depositions
- Additional scopes for different permission levels

### Authentication Methods
```bash
# URL parameter method
GET /api/deposit/depositions?access_token=<ACCESS_TOKEN>

# Header method
Authorization: Bearer <ACCESS_TOKEN>
```

### Key Endpoints
- **Depositions**: `/api/deposit/depositions`
- **Records**: `/records/<record_id>`
- **Communities**: `/api/communities` (beta)
- **Funders**: `/api/funders` (testing)
- **Grants**: `/api/grants` (testing)

### Data Formats

#### Metadata Formats
- **JSON Schema**: Internal representation
- **DataCite**: Latest schema compliance
- **Dublin Core**: Minimal metadata (OAI-PMH compliant)
- **DCAT**: DCAT Application Profile for European data portals
- **MARC21**: Legacy support (may be discontinued)

#### File Formats
- **JSON**: Primary API communication format
- **XML**: Available for metadata export
- **Various**: Support for any research data file type

### HTTP Methods
- **GET**: Retrieve data
- **POST**: Create new records
- **PUT**: Update existing records
- **DELETE**: Remove records

### Rate Limiting
- Configurable limits per endpoint based on complexity
- Fair distribution policies to ensure availability

### Additional Features
- **OAI-PMH**: Full repository harvesting at `https://zenodo.org/oai2d`
- **DOI Assignment**: Automatic DOI minting for deposits
- **Version Control**: Support for dataset versioning
- **Communities**: Curated collections and communities

### SYNTHEX Integration Notes
- **Highly Recommended**: Full REST API with comprehensive features
- **FAIR Compliance**: Excellent for research data management
- **Rich Metadata**: JSON Schema with multiple export formats
- **Reliable Infrastructure**: CERN-operated with high availability

---

## Figshare API

### Overview
Commercial research data repository with institutional and individual accounts.

### API Access Methods
- **Base URL**: `https://api.figshare.com/v2`
- **Architecture**: REST API with JSON communication
- **Protocol**: HTTPS required

### Authentication
- **OAuth2**: Primary authentication method
- **Personal Tokens**: Available from applications page
- **Institutional Access**: Enhanced privileges for institutional accounts

### Authentication Headers
```http
Authorization: token ACCESS_TOKEN
```

### Key Endpoints
- **Articles**: Research publications and datasets
- **Collections**: Grouped related items
- **Projects**: Organized research work
- **Files**: Data upload and management
- **Statistics**: Usage metrics and analytics

### Data Format
- **Request**: JSON (`application/json`)
- **Response**: JSON with null fields included
- **Error Handling**: Specific HTTP status codes with JSON error bodies

### Example Request
```http
POST /v2/articles/search HTTP/1.1
Host: api.figshare.com
Authorization: token a287ab8c7ebdbe6
Content-Type: application/json

{
  "search_for": "figshare"
}
```

### Pagination
- **Methods**: 
  - `page` and `page_size` parameters
  - `limit` and `offset` parameters
- **Limits**: Maximum offset of 1000
- **Error Handling**: 422 Unprocessable Entity for exceeded limits

### Creating Records Process
1. Create private record
2. Add file links (optional)
3. Publish record (optional)

### Statistics and Metrics
- Item statistics by category/type
- Author, collection, group, and project metrics
- Institutional scope requires authentication

### SYNTHEX Integration Notes
- **Excellent API**: Well-documented REST interface
- **Flexible Authentication**: Multiple token types supported
- **Rich Features**: Comprehensive research data management
- **Commercial Platform**: May have usage costs for large-scale access

---

## ORCID API

### Overview
Researcher identifier registry providing persistent digital identifiers for researchers.

### API Types
1. **Member API**: Read/write access for ORCID members
2. **Public API**: Read public information (available to anyone)

### API Architecture
- **REST**: RESTful HTTP-based API
- **OAuth 2.0**: Authentication protocol
- **HTTPS**: Required for all communications

### Authentication Endpoints
- **Authorization**: `https://orcid.org/oauth/authorize` (production)
- **Token**: `https://orcid.org/oauth/token` (production)
- **Sandbox**: Replace `orcid.org` with `sandbox.orcid.org` for testing

### OAuth Scopes
- `/authenticate`: Read public data and get authenticated ORCID iD
- `/read-limited`: Read "trusted parties only" data
- `/person/update`: Update personal information
- `/activities/update`: Update professional activities
- `openid`: OpenID Connect integration with id_token

### Data Formats
- **XML**: Primary format for data exchange
- **JSON**: Alternative format supported
- **Transfer**: Bidirectional between ORCID registry and local systems

### Authentication Flow
1. **Authorization URL**: Direct users to ORCID sign-in
2. **User Consent**: User grants permissions
3. **Authorization Code**: Received via redirect URI
4. **Access Token**: Exchange code for token

### Access Token Response
```json
{
  "access_token": "f5af9f51-07e6-4332-8f1a-c0c11c1e3728",
  "token_type": "bearer",
  "refresh_token": "f725f747-3a65-49f6-a231-3e8944ce464d",
  "expires_in": 631138518,
  "scope": "/activities/update /read-limited",
  "name": "Sofia Garcia",
  "orcid": "0000-0001-2345-6789"
}
```

### Key Features
- **Token Longevity**: ~20 years or until revoked
- **Put Codes**: 6-digit identifiers for tracking items
- **Sandbox Environment**: Full testing environment available

### SYNTHEX Integration Notes
- **Essential for Author Identification**: Links researchers across platforms
- **Rich Profile Data**: Professional activities, affiliations, works
- **OAuth Integration**: Standard authentication for research platforms
- **High Adoption**: Widely used across academic institutions

---

## SYNTHEX Integration Strategy

### Recommended Integration Priority

#### Tier 1 - Immediate Integration
1. **bioRxiv/medRxiv**: No authentication, reliable, comprehensive life/health sciences
2. **Zenodo**: Full REST API, FAIR compliance, CERN reliability
3. **ORCID**: Essential for researcher identification and linking

#### Tier 2 - Secondary Integration
4. **Figshare**: Commercial but feature-rich, good for institutional data

#### Tier 3 - Manual/Alternative Approaches
5. **SSRN**: Valuable content but requires alternative access methods
6. **ResearchGate**: High engagement but no official API
7. **Academia.edu**: Consider for future if API becomes available

### Technical Architecture Recommendations

#### API Management Layer
```python
class OpenScienceAPIManager:
    def __init__(self):
        self.apis = {
            'biorxiv': BioRxivClient(),
            'medrxiv': MedRxivClient(), 
            'zenodo': ZenodoClient(),
            'figshare': FigshareClient(),
            'orcid': ORCIDClient()
        }
    
    def unified_search(self, query, sources=None):
        """Unified search across multiple repositories"""
        pass
    
    def cross_reference_authors(self, orcid_id):
        """Link publications across platforms using ORCID"""
        pass
```

#### Data Harmonization
- **Common Schema**: Map different API responses to unified format
- **Metadata Standards**: Align with Dublin Core, DataCite standards
- **Author Linking**: Use ORCID as primary researcher identifier

#### Authentication Management
- **OAuth Centralization**: Single OAuth flow for multiple services
- **Token Storage**: Secure storage for long-lived tokens
- **Scope Management**: Minimal required permissions per service

#### Error Handling and Resilience
- **Rate Limiting**: Respect individual API rate limits
- **Fallback Strategies**: Alternative sources when primary APIs fail
- **Caching**: Local caching to reduce API calls

#### Content Processing Pipeline
1. **Harvest**: Automated content discovery from APIs
2. **Enrich**: Cross-reference with ORCID, citation databases
3. **Process**: Content analysis and extraction
4. **Index**: Full-text search capabilities
5. **Serve**: Unified interface for SYNTHEX applications

### Data Quality Considerations
- **Preprint vs. Published**: Track publication status changes
- **Version Control**: Handle multiple versions of same work
- **Duplicate Detection**: Cross-platform deduplication
- **Metadata Quality**: Validation and enrichment processes

### Legal and Ethical Considerations
- **API Terms**: Comply with each platform's terms of service
- **Attribution**: Proper citation of data sources
- **Privacy**: Respect researcher privacy settings
- **Usage Limits**: Respect rate limits and fair use policies

### Future Integration Opportunities
- **Semantic Scholar API**: Comprehensive citation database
- **CrossRef API**: DOI resolution and metadata
- **PubMed API**: Medical literature database
- **arXiv API**: Physics and mathematics preprints
- **Microsoft Academic**: Research graph data (deprecated but alternatives emerging)

This comprehensive documentation provides the foundation for integrating open science and preprint repositories into the SYNTHEX architecture, enabling robust research content discovery and analysis capabilities.