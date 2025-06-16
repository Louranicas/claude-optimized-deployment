# Academic Database API Documentation

This document provides comprehensive information about major academic databases and repositories that offer API access for programmatic searching and data retrieval.

## Table of Contents
1. [PubMed/NCBI E-utilities](#pubmedncbi-e-utilities)
2. [arXiv.org API](#arxivorg-api)
3. [IEEE Xplore API](#ieee-xplore-api)
4. [ACM Digital Library](#acm-digital-library)
5. [Scopus API (Elsevier)](#scopus-api-elsevier)
6. [Web of Science API (Clarivate)](#web-of-science-api-clarivate)
7. [JSTOR API](#jstor-api)

---

## PubMed/NCBI E-utilities

### API Endpoint URLs
- **Base URL**: `https://eutils.ncbi.nlm.nih.gov/entrez/eutils/`
- **Main Tools**:
  - ESearch: `https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi`
  - EFetch: `https://eutils.ncbi.nlm.nih.gov/entrez/eutils/efetch.fcgi`
  - ESummary: `https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esummary.fcgi`
  - ELink: `https://eutils.ncbi.nlm.nih.gov/entrez/eutils/elink.fcgi`
  - EInfo: `https://eutils.ncbi.nlm.nih.gov/entrez/eutils/einfo.fcgi`

### Authentication Methods
- **API Key**: Optional but recommended for higher rate limits
- **Registration**: Available through NCBI account (free)
- **Parameter**: `api_key={your_key}`

### Rate Limits and Usage Policies
- **Without API Key**: 3 requests per second maximum
- **With API Key**: 10 requests per second by default
- **Large Batches**: Use Entrez History for batch operations
- **Best Practice**: Use EPost for uploading large ID sets

### Data Formats Available
- **Primary Format**: XML
- **Alternative Formats**: JSON (limited), various text formats
- **Content Types**: Abstracts, full metadata, citation data

### Search Capabilities and Query Syntax
- **Boolean Operators**: AND, OR, NOT
- **Field Searches**: `author[au]`, `title[ti]`, `journal[ta]`
- **Date Ranges**: `2020:2023[dp]`
- **MeSH Terms**: `diabetes[mesh]`

### Free Tier/Academic Access
- **Status**: Completely free
- **Limitations**: Rate limits only
- **Commercial Use**: Allowed with proper attribution

### Documentation
- **Main Guide**: https://www.ncbi.nlm.nih.gov/books/NBK25497/
- **Quick Start**: https://www.ncbi.nlm.nih.gov/books/NBK25500/
- **Developer Portal**: https://www.ncbi.nlm.nih.gov/home/develop/api/

---

## arXiv.org API

### API Endpoint URLs
- **Base URL**: `http://export.arxiv.org/api/query`
- **Method**: HTTP GET or POST
- **Query Interface**: `http://export.arxiv.org/api/query?{parameters}`

### Authentication Methods
- **API Key**: Not required
- **Registration**: Not required
- **Access**: Open to all users

### Rate Limits and Usage Policies
- **Rate Limits**: No explicit rate limits specified
- **Terms of Use**: Must review arXiv API Terms of Use
- **Recommended**: Implement reasonable delays between requests

### Data Formats Available
- **Primary Format**: Atom 1.0 XML
- **Content Structure**: Feed with entry elements
- **Metadata**: Title, authors, abstract, categories, publication date

### Search Capabilities and Query Syntax
- **Search Fields**: `all:`, `ti:`, `au:`, `abs:`, `cat:`
- **Boolean Operators**: AND, OR, ANDNOT
- **Example**: `search_query=all:electron AND ti:theory`
- **Sorting**: `sortBy=relevance`, `sortBy=lastUpdatedDate`, `sortBy=submittedDate`

### Free Tier/Academic Access
- **Status**: Completely free and open
- **Limitations**: None
- **Commercial Use**: Allowed under arXiv terms

### Documentation
- **API Basics**: https://info.arxiv.org/help/api/basics.html
- **User Manual**: https://info.arxiv.org/help/api/user-manual.html
- **API Home**: https://info.arxiv.org/help/api/index.html

---

## IEEE Xplore API

### API Endpoint URLs
- **Developer Portal**: https://developer.ieee.org/
- **API Base**: Available through developer portal
- **I/O Docs**: https://developer.ieee.org/io-docs

### Authentication Methods
- **API Key**: Required (register application)
- **Registration**: Required through developer portal
- **IP Authentication**: May be required for institutional access

### Rate Limits and Usage Policies
- **Usage**: Non-commercial educational, research, or scientific activities only
- **Institutional Access**: Must use registered IP ranges
- **Commercial Use**: Contact sales representative

### Data Formats Available
- **Metadata API**: JSON/XML responses
- **Content**: Abstracts, metadata for 6+ million documents
- **Full-Text**: Available for Open Access and subscription content

### Search Capabilities and Query Syntax
- **Simple Search**: Basic keyword queries
- **Boolean Search**: Advanced Boolean operations
- **Content Types**: Journals, conferences, books, courses, standards

### Free Tier/Academic Access
- **Metadata Access**: Available for registered users
- **Full-Text**: Requires subscription or Open Access designation
- **Educational Use**: Allowed under terms

### Documentation
- **Developer Portal**: https://developer.ieee.org/
- **Currently Available APIs**: https://developer.ieee.org/docs
- **Terms of Use**: https://developer.ieee.org/API_Terms_of_Use2

---

## ACM Digital Library

### API Endpoint URLs
- **Status**: No official API available
- **Alternative**: Crossref API (member ID: 320)
- **Crossref URL**: `https://api.crossref.org/members/320/works`

### Authentication Methods
- **API Key**: Not applicable (no API)
- **Institutional Access**: IP authentication or Shibboleth
- **Alternative Access**: Through Crossref (free)

### Rate Limits and Usage Policies
- **API Limits**: Not applicable
- **Crossref Limits**: Standard Crossref rate limits apply
- **Institutional Access**: Based on subscription

### Data Formats Available
- **Direct Access**: Not available via API
- **Crossref**: JSON metadata through Crossref API
- **Web Access**: HTML/PDF through web interface

### Search Capabilities and Query Syntax
- **API Search**: Not available
- **Web Search**: Available through website
- **Crossref Search**: Limited to bibliographic metadata

### Free Tier/Academic Access
- **API Access**: Not available
- **Metadata**: Available through Crossref
- **Full Content**: Subscription or institutional access required
- **Future**: Transitioning to Open Access by 2025

### Documentation
- **User Guide**: https://libraries.acm.org/training-resources/dl-user-guide
- **Search Tools**: https://libraries.acm.org/training-resources/search-tools
- **Authentication**: https://libraries.acm.org/subscriptions-access/authentication

### Alternative Solutions
- **Crossref API**: For bibliographic metadata
- **Community Tools**: GitHub projects for scraping (use with caution)
- **Institutional Access**: Through library subscriptions

---

## Scopus API (Elsevier)

### API Endpoint URLs
- **Developer Portal**: https://dev.elsevier.com/
- **Scopus Search API**: Available through portal
- **ScienceDirect API**: Available through portal

### Authentication Methods
- **API Key**: Required (up to 10 keys per profile)
- **Institutional Subscription**: Required
- **IP Recognition**: Automatic for subscribed institutions
- **InstToken**: Available for remote access (request from Elsevier)

### Rate Limits and Usage Policies
- **Quota Limits**: 20,000 requests per 7 days
- **Search Requests**: 20,000 per week
- **Retrieval Requests**: 5,000 per week
- **Throttling**: Specific requests/second limits
- **Reset**: Weekly quota reset

### Data Formats Available
- **Primary Format**: JSON and XML
- **Content**: Full bibliographic metadata
- **Results Limit**: 200 results per query (ScienceDirect: 6,000)

### Search Capabilities and Query Syntax
- **Field Searches**: Author, title, affiliation, date ranges
- **Boolean Operators**: AND, OR, AND NOT
- **Advanced Syntax**: Complex field combinations

### Free Tier/Academic Access
- **Free Access**: Non-commercial use only
- **Institutional**: Subscription required
- **Commercial**: Separate licensing required

### Documentation
- **Developer Portal**: https://dev.elsevier.com/
- **API Guide**: Scopus API Guide available on portal
- **Support**: apisupport@elsevier.com

---

## Web of Science API (Clarivate)

### API Endpoint URLs
- **Developer Portal**: https://developer.clarivate.com/
- **Web of Science API Expanded**: Available through portal
- **Web of Science Starter API**: Available through portal
- **Journals API**: Available through portal

### Authentication Methods
- **API Key**: Required through developer portal
- **Registration**: Required with Clarivate product credentials
- **Approval Process**: Manual approval (may take several days)

### Rate Limits and Usage Policies
- **Rate Limits**: Specified per API type
- **Subscription**: Web of Science Core Collection minimum required
- **Usage**: Academic and research purposes

### Data Formats Available
- **Formats**: JSON and XML
- **Starter API**: Basic bibliographic metadata, DOI verification, citation counts
- **Expanded API**: Full metadata, contributor addresses, funding data

### Search Capabilities and Query Syntax
- **Rich Search**: Full Web of Science search capabilities
- **Field Searches**: Author, title, source, subject areas
- **Citation Data**: Times cited counts, related records

### Free Tier/Academic Access
- **Subscription Required**: Minimum Web of Science Core Collection
- **Academic Pricing**: Available through institution
- **API Access**: Requires separate approval

### Documentation
- **Developer Portal**: https://developer.clarivate.com/
- **Support**: Available through portal
- **GitHub Examples**: Python and JavaScript clients available

---

## JSTOR API

### API Endpoint URLs
- **Status**: Most APIs deprecated
- **XML Gateway**: Available for eligible participants (SRU-based)
- **Current Platform**: Constellate (https://constellate.org/)

### Authentication Methods
- **API Key**: Required for legacy APIs
- **Institutional License**: Required for XML Gateway
- **Individual Access**: Not available for API
- **Constellate**: Registration required (free)

### Rate Limits and Usage Policies
- **Legacy APIs**: Mostly deprecated
- **XML Gateway**: Based on institutional agreement
- **Constellate**: Standard platform limits
- **Dataset Limits**: 1,000 articles default (contact for larger sets)

### Data Formats Available
- **XML Gateway**: Dublin Core XML format
- **Constellate**: Various formats for text analysis
- **Legacy DfR**: XML and text formats (deprecated)

### Search Capabilities and Query Syntax
- **XML Gateway**: Contextual Query Language (CQL)
- **Constellate**: Modern search interface
- **Content**: Full-text analysis capabilities

### Free Tier/Academic Access
- **XML Gateway**: Institutional licensing required
- **Constellate**: Free with registration
- **Research Tool**: Available on content pages
- **Commercial Use**: Separate licensing

### Documentation
- **XML Gateway**: https://support.jstor.org/hc/en-us/articles/115005075327
- **Constellate**: https://constellate.org/
- **Support**: support@jstor.org

### Current Recommendations
- **Text Mining**: Use Constellate platform
- **Metadata Search**: Limited options, contact JSTOR
- **Research**: Use JSTOR's interactive research tool
- **Legacy Data**: jstor R package for old DfR data

---

## Summary Comparison

| Database | API Available | Authentication | Rate Limits | Data Format | Free Access |
|----------|---------------|----------------|-------------|-------------|-------------|
| PubMed/NCBI | ✅ Full API | Optional API key | 3-10 req/sec | XML, JSON | ✅ Completely free |
| arXiv | ✅ Full API | None required | Reasonable use | Atom XML | ✅ Completely free |
| IEEE Xplore | ✅ Limited API | API key required | TBD | JSON/XML | 🔒 Non-commercial only |
| ACM Digital Library | ❌ No API | N/A | N/A | N/A | 🔒 Subscription required |
| Scopus | ✅ Full API | API key + subscription | 20k/week | JSON/XML | 🔒 Subscription required |
| Web of Science | ✅ Full API | API key + subscription | Varies | JSON/XML | 🔒 Subscription required |
| JSTOR | ⚠️ Deprecated | Institutional license | Varies | XML | 🔒 Mostly restricted |

### Best Options for Open Access Research
1. **PubMed/NCBI**: Best free option for biomedical literature
2. **arXiv**: Best for preprints in physics, mathematics, computer science
3. **Crossref**: Good alternative for general academic metadata
4. **IEEE Xplore**: Limited free access for educational use
5. **Constellate**: Best current option for JSTOR content analysis

*Last updated: June 14, 2025*