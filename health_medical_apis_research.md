# Health and Medical Research Database APIs

## Research Summary

This document provides comprehensive information about health and medical research database APIs, including endpoints, authentication requirements, and data formats for academic research access.

---

## 1. PubMed Central (PMC) API

### Overview
PubMed Central provides free access to full-text biomedical literature through multiple API services. The PMC APIs are part of the NCBI Entrez system and provide programmatic access to research articles.

### Authentication
- **No authentication required** for public APIs
- Content is accessible without any login requirements
- Some third-party services may require API tokens

### API Services and Endpoints

#### E-Utilities API
- **Base URL**: `https://eutils.ncbi.nlm.nih.gov/entrez/eutils/`
- **Description**: Public API to the NCBI Entrez system
- **Databases**: PubMed, PMC, Gene, Nuccore, Protein

#### PMC OA Web Service API
- **Base URL**: `https://www.ncbi.nlm.nih.gov/pmc/utils/oa/oa.fcgi`
- **Methods**: HTTP GET or POST
- **Purpose**: Discover downloadable resources from PMC Open Access Subset

**Key Parameters:**
- `from`: Request records updated on/after specified date
- `until`: Request records between specified dates  
- `format=pdf`: Return only records with PDFs
- `resumptionToken`: Handle pagination for >1000 results

#### BioC API
- **Format Options**: BioC XML or JSON
- **Encoding**: Unicode or ASCII
- **Access**: Via PubMed ID or PMC ID
- **Purpose**: Access PMC Open Access articles in structured format

### Data Formats
- XML (default PMC schema)
- JSON (BioC format)
- PDF (full-text articles)

### Usage Guidelines
- Systematic/bulk retrieval through automated processes is prohibited
- Check license statements for specific reuse terms
- Rate limiting applies to prevent abuse

### Documentation
- Main API docs: `https://www.ncbi.nlm.nih.gov/home/develop/api/`
- PMC developer resources: `https://pmc.ncbi.nlm.nih.gov/tools/developers/`

---

## 2. ClinicalTrials.gov API

### Overview
ClinicalTrials.gov provides a REST API (version 2.0) that follows OpenAPI Specification 3.0 for accessing clinical trial data. The classic API was retired in June 2024.

### Authentication
- **No authentication required**
- Free public access to all clinical trial data
- No API key needed for basic usage

### API Endpoints

#### Studies Endpoint
- **URL**: `https://clinicaltrials.gov/api/v2/studies`
- **Method**: GET
- **Purpose**: Search and retrieve clinical trial studies

**Example Request:**
```
GET https://clinicaltrials.gov/api/v2/studies?query.titles=Diabetes&pageSize=50&pageToken=xyz123
```

**Query Parameters:**
- `query.titles`: Search by study title
- `query.conditions`: Filter by medical condition
- `query.locations`: Filter by geographic location
- `query.interventions`: Filter by intervention type
- `query.status`: Filter by study status
- `pageSize`: Number of results per page
- `pageToken`: Pagination token for next page

### Data Formats
- JSON (primary format)
- CSV (also supported)
- XML (legacy format)

### Key Features
- Pagination support using `pageToken`
- Complex search expressions in URLs
- Support for third-party OpenAPI 3.0 libraries
- Migration guide available for legacy API users

### Documentation
- Main API docs: `https://clinicaltrials.gov/data-api/api`
- Migration guide: `https://clinicaltrials.gov/data-about-studies/api-migration`

---

## 3. Cochrane Library API

### Overview
Cochrane Library provides access to systematic reviews and meta-analyses through the Review Document API. Access is controlled and requires authentication.

### Authentication
- **Authentication required**: HTTP Basic auth or OAuth 2.0 Bearer token
- Contact required for machine access permissions
- Error codes: 401 (unauthorized), 403 (forbidden)

### API Endpoints

#### Review Document API
- **Base URL**: Information available at technical documentation
- **Main endpoint**: `https://archie.cochrane.org/rest/reviews/{Review ID}/metadata`

**Query Parameters:**
- `myPermission`: Filter by user permissions (e.g., `write_authoring`)
- `startSearchDate`: Filter by search date (`yyyy-MM-dd` format)
- `published`: Include unpublished content (`true`/`false`)
- `issueId`: Filter by specific Cochrane Library issue
- `translation`: Find reviews with translations (language code)

### Data Formats
- XML (primary format for review listings)
- Structured metadata for reviews and protocols

### Access Requirements
- Contact Deborah Pentesco-Murphy (cochranelibrary@wiley.com) for machine access
- Permission required for crawling or accessing full-text content
- Different permission levels (view, write_authoring, etc.)

### Documentation
- Technical docs: `https://documentation.cochrane.org/display/API/Review+Document+API`
- Test API: `https://test-api.cochrane.org/api-docs/index.html`

---

## 4. WHO Global Health Observatory (GHO) API

### Overview
WHO GHO provides access to global health statistics through an OData-based API. The service offers comprehensive health indicators and data from WHO member states.

### Authentication
- **No authentication required**
- Publicly accessible API
- Free access to all global health data

### API Endpoints

#### Base URL
- **Production**: `https://ghoapi.azureedge.net/api`

#### Endpoint Structure
- **Dimensions**: `/api/DIMENSION`
- **Dimension values**: `/api/DIMENSION/COUNTRY/DimensionValues`
- **Indicator data**: `/api/INDICATORCODE`

**Example Requests:**
```
GET https://ghoapi.azureedge.net/api/DIMENSION
GET https://ghoapi.azureedge.net/api/WHOSIS_000001
```

### Data Formats
- XML (default Observatory schema)
- JSON (basic support available)
- OData protocol compliance

### Important Notes
- Include trailing slash (/) in API calls
- COVID-19 data not currently available through GHO APIs
- Covers all WHO member state health statistics

### Documentation
- GHO OData API: `https://www.who.int/data/gho/info/gho-odata-api`
- Query interface: `https://apps.who.int/gho/data/node.resources.api`

---

## 5. FDA openFDA API

### Overview
openFDA provides open APIs for accessing FDA public datasets including drug, food, device, and tobacco data.

### Authentication
- **API key recommended** but not required for basic usage
- Free API keys available
- Rate limiting and usage restrictions apply

### API Endpoints

#### Base URL
- **Production**: `https://api.fda.gov/`

#### Available Endpoints
**Drug Endpoints:**
- `/drug/label.json` - Drug labeling information
- `/drug/event.json` - Drug adverse events
- `/drug/enforcement.json` - Drug enforcement reports

**Food Endpoints:**
- `/food/event.json` - Food adverse events
- `/food/enforcement.json` - Food enforcement reports

**Device Endpoints:**
- `/device/event.json` - Device adverse events
- `/device/510k.json` - Device clearance data
- `/device/pma.json` - Device PMA data

**Other Endpoints:**
- `/tobacco/problem.json` - Tobacco problem reports

**Example Request:**
```
GET https://api.fda.gov/drug/event.json?search=receivedate:[20040101+TO+20160601]&count=receivedate&api_key=xxxxxxxxxx
```

### Data Formats
- JSON (primary format)
- Elasticsearch-based queries
- RESTful API structure

### Query Features
- Standard openFDA query syntax
- Date range searches
- Count aggregations
- Field-specific filtering

### Documentation
- Main docs: `https://open.fda.gov/apis/`
- Authentication: `https://open.fda.gov/apis/authentication/`
- GitHub: `https://github.com/FDA/openfda`

---

## 6. European Medicines Agency (EMA) APIs

### Overview
EMA provides several APIs for accessing European medicines data, including electronic product information and product management services.

### Authentication
- **Mixed requirements**: Some APIs public, others require authentication
- Microsoft Azure API Management infrastructure

### API Services

#### ePI (Electronic Product Information) API
- **Authentication**: None required (publicly accessible)
- **Purpose**: Access electronic product information for EU medicines

**Endpoints:**
- `ListBySearchParameter` - Search product information
- `BundleBySearchParameter` - Get product bundles by search
- `ListById` - Get product list by ID  
- `BundleById` - Get specific product bundle

**Data Structure:**
- **Bundle**: Individual documents (SPC, labelling, leaflets)
- **PI List**: FHIR IDs of all bundles in ePI

#### PMS (Product Management Service) API
- **Authentication**: Likely required (specific details not publicly available)
- **Purpose**: Access product data and documents for CAPs and non-CAPs

### Developer Portals
- ePI Portal: `https://epi.developer.ema.europa.eu/api-details`
- PMS Portal: `https://api-dev.pms.developer.ema.europa.eu/apis`

### Data Formats
- FHIR-compliant data structures
- JSON/XML formats
- Document bundles and metadata

### Documentation
- ePI API training sessions available
- EU IDMP Implementation Guide
- Technical specifications for API structure

---

## 7. PharmacoGx (R Package - Not Web API)

### Overview
PharmacoGx is a Bioconductor R package for analyzing large-scale pharmacogenomic data, rather than a traditional web API.

### Authentication
- **No authentication required** (R package installation)
- Works within R environment
- No API keys or tokens needed

### Installation
```r
source("http://www.bioconductor.org/biocLite.R")
biocLite("PharmacoGx")
```

### Key Functions
- `drugInfo()`, `drugNames()` - Drug information management
- `drugDoseResponseCurve()` - Dose-response analysis
- `drugSensitivitySig()` - Drug sensitivity signatures
- AUC and IC50 calculations
- Molecular feature correlation

### Data Sources
- PharmacoDB datasets
- CCLE, GDSC, and other pharmacogenomic studies
- Molecular and pharmacological data integration

### Usage Example
```r
# Download dataset
CCLE <- downloadPSet("CCLE")

# Plot dose-response curves
plotDrugDoseResponseCurve(CCLE, drug="17-AAG", cellline="A549")

# Extract expression data
expression <- summarizeMolecularProfiles(CCLE, "rna")
```

### Related Web Resources
- PharmacoDB: `https://pharmacodb.pmgenomics.ca/`
- Bioconductor page: `https://www.bioconductor.org/packages/release/bioc/html/PharmacoGx.html`

---

## Summary Table

| Database | Authentication | Base URL | Data Format | Access Level |
|----------|----------------|----------|-------------|--------------|
| PMC | None | `eutils.ncbi.nlm.nih.gov` | XML, JSON, PDF | Public |
| ClinicalTrials.gov | None | `clinicaltrials.gov/api/v2` | JSON, CSV | Public |
| Cochrane Library | OAuth 2.0/Basic | `archie.cochrane.org/rest` | XML | Restricted |
| WHO GHO | None | `ghoapi.azureedge.net/api` | XML, JSON | Public |
| openFDA | API Key (optional) | `api.fda.gov` | JSON | Public |
| EMA | Mixed | Multiple portals | JSON, XML, FHIR | Mixed |
| PharmacoGx | None (R package) | N/A (local R) | R objects | Public |

---

## Best Practices for Academic Research

1. **Rate Limiting**: Respect API rate limits and implement exponential backoff
2. **Data Licensing**: Check individual dataset licenses for reuse terms
3. **Authentication Management**: Securely store API keys when required
4. **Error Handling**: Implement robust error handling for network requests
5. **Data Validation**: Validate API responses before processing
6. **Caching**: Cache responses appropriately to reduce API calls
7. **Documentation**: Keep API documentation bookmarked for reference updates

---

## Contact Information for API Access

- **Cochrane Library**: cochranelibrary@wiley.com (Deborah Pentesco-Murphy)
- **FDA openFDA**: Through GitHub issues or official FDA channels
- **EMA**: Through their service desk for specific authentication requirements
- **WHO GHO**: Public access, no contact required
- **PMC/NCBI**: Through NCBI support for technical issues

Last Updated: June 14, 2025