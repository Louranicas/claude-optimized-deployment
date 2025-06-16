# SYNTHEX API Keys and Credentials Reference
*Quick Access Guide for Academic Database Authentication*

## 🔐 API Key Quick Reference

### Free APIs (No Authentication Required)
```bash
# No setup needed - immediate access
arXiv: http://export.arxiv.org/api/query
DataCite: https://api.datacite.org/
European PMC: https://www.ebi.ac.uk/europepmc/webservices/rest/
OpenAIRE: https://api.openaire.eu/
WHO GHO: https://ghoapi.azureedge.net/
```

### Email-Enhanced APIs (Polite Pool Access)
```bash
# Include email in User-Agent header for better performance
Crossref: https://api.crossref.org/
OpenAlex: https://api.openalex.org/
# Header: User-Agent: SYNTHEX/1.0 (mailto:your_email@institution.edu)
```

### Registration Required (Free APIs)
```bash
# 1. PubMed/NCBI
export SYNTHEX_NCBI_API_KEY="your_key_here"
# Get at: https://www.ncbi.nlm.nih.gov/account/

# 2. Semantic Scholar
export SYNTHEX_SEMANTIC_SCHOLAR_API_KEY="your_key_here"  
# Apply at: https://www.semanticscholar.org/product/api

# 3. NASA/ADS
export SYNTHEX_NASA_ADS_TOKEN="your_token_here"
# Get at: https://ui.adsabs.harvard.edu/user/account/register

# 4. Zenodo
export SYNTHEX_ZENODO_TOKEN="your_token_here"
# Generate at: https://zenodo.org/account/settings/applications/

# 5. ORCID (for write operations)
export SYNTHEX_ORCID_CLIENT_ID="your_client_id"
export SYNTHEX_ORCID_CLIENT_SECRET="your_client_secret"
# Get at: https://orcid.org/developer-tools

# 6. DPLA
export SYNTHEX_DPLA_API_KEY="your_key_here"
# Get at: https://dp.la/info/developers/codex/policies/

# 7. Europeana
export SYNTHEX_EUROPEANA_API_KEY="your_key_here"
# Get at: https://pro.europeana.eu/page/get-api
```

### Institutional/Paid APIs
```bash
# IEEE Xplore (requires subscription)
export SYNTHEX_IEEE_API_KEY="your_key_here"
# Contact: IEEE for institutional access

# Scopus (Elsevier)
export SYNTHEX_SCOPUS_API_KEY="your_key_here"
# Apply at: https://dev.elsevier.com/

# Web of Science (Clarivate)
export SYNTHEX_WOS_API_KEY="your_key_here"
# Contact: Clarivate Analytics

# Dimensions API
export SYNTHEX_DIMENSIONS_LOGIN="your_login"
export SYNTHEX_DIMENSIONS_PASSWORD="your_password"
# Contact: Digital Science

# PlumX Metrics (via Scopus)
export SYNTHEX_PLUMX_API_KEY="your_scopus_key"
# Requires Scopus subscription
```

## 🚀 Quick Setup Script

### Environment Configuration
```bash
#!/bin/bash
# setup_synthex_academic.sh

echo "Setting up SYNTHEX Academic Database Access..."

# Create .env file for academic APIs
cat > .env.academic << 'EOF'
# SYNTHEX Academic Database Configuration
# Generated: $(date)

# Contact Information (Required for Polite Pool)
SYNTHEX_CONTACT_EMAIL=your_email@institution.edu

# Free Registration APIs
SYNTHEX_NCBI_API_KEY=your_ncbi_key_here
SYNTHEX_SEMANTIC_SCHOLAR_API_KEY=your_semantic_scholar_key_here
SYNTHEX_NASA_ADS_TOKEN=your_nasa_ads_token_here
SYNTHEX_ZENODO_TOKEN=your_zenodo_token_here
SYNTHEX_ORCID_CLIENT_ID=your_orcid_client_id
SYNTHEX_ORCID_CLIENT_SECRET=your_orcid_client_secret
SYNTHEX_DPLA_API_KEY=your_dpla_key_here
SYNTHEX_EUROPEANA_API_KEY=your_europeana_key_here

# Institutional APIs (if available)
SYNTHEX_IEEE_API_KEY=your_ieee_key_here
SYNTHEX_SCOPUS_API_KEY=your_scopus_key_here
SYNTHEX_WOS_API_KEY=your_wos_key_here
SYNTHEX_DIMENSIONS_LOGIN=your_dimensions_login
SYNTHEX_DIMENSIONS_PASSWORD=your_dimensions_password

# Commercial APIs (if subscribed)
SYNTHEX_SERPAPI_KEY=your_serpapi_key_here
EOF

echo "Created .env.academic file"
echo "Please edit the file and add your actual API keys"
echo ""
echo "To load the environment variables:"
echo "source .env.academic"
```

## 📋 API Registration Checklist

### Priority 1: Essential APIs (Complete First)
- [ ] **Email Contact**: Set SYNTHEX_CONTACT_EMAIL for polite pool access
- [ ] **PubMed/NCBI**: Register at https://www.ncbi.nlm.nih.gov/account/
- [ ] **Semantic Scholar**: Apply at https://www.semanticscholar.org/product/api
- [ ] **NASA/ADS**: Register at https://ui.adsabs.harvard.edu/user/account/register

### Priority 2: Extended Coverage
- [ ] **Zenodo**: Create token at https://zenodo.org/account/settings/applications/
- [ ] **ORCID**: Developer tools at https://orcid.org/developer-tools
- [ ] **DPLA**: Apply at https://dp.la/info/developers/codex/policies/
- [ ] **Europeana**: Get key at https://pro.europeana.eu/page/get-api

### Priority 3: Institutional (If Available)
- [ ] **IEEE Xplore**: Contact your institution's IEEE representative
- [ ] **Scopus**: Apply through your institution at https://dev.elsevier.com/
- [ ] **Web of Science**: Contact Clarivate Analytics through your institution

## 🔧 Rate Limits and Usage Guidelines

### Free APIs
| Database | Rate Limit | Daily Limit | Notes |
|----------|------------|-------------|-------|
| arXiv | 1 req/3 sec | Unlimited | Be polite |
| PubMed | 3/sec (10 with key) | Unlimited | Academic use |
| Crossref | 50/sec (polite) | Unlimited | Include email |
| Semantic Scholar | 1/sec (100 with key) | Unlimited | Apply for key |
| NASA/ADS | Variable | 5,000/day | Token required |
| Zenodo | Variable | 100/hour | Higher with account |

### Paid APIs
| Database | Rate Limit | Weekly/Monthly Limit | Cost |
|----------|------------|---------------------|------|
| IEEE Xplore | 200/day | 200/day (free tier) | Free tier available |
| Scopus | Variable | 20,000/week | Institutional |
| Web of Science | Variable | By subscription | Institutional |
| SerpAPI | 100/month | 100/month (free) | $50-250/month |

## 🔍 Testing Your API Access

### Python Test Script
```python
#!/usr/bin/env python3
# test_api_access.py

import os
import requests
import asyncio
import aiohttp
from dotenv import load_dotenv

# Load environment variables
load_dotenv('.env.academic')

async def test_api_access():
    """Test access to all configured APIs"""
    
    tests = []
    
    # Test arXiv (no auth)
    tests.append(test_arxiv())
    
    # Test PubMed (optional auth)
    if os.getenv('SYNTHEX_NCBI_API_KEY'):
        tests.append(test_pubmed_with_key())
    else:
        tests.append(test_pubmed_no_key())
    
    # Test Crossref (email in header)
    tests.append(test_crossref())
    
    # Test Semantic Scholar (optional auth)
    if os.getenv('SYNTHEX_SEMANTIC_SCHOLAR_API_KEY'):
        tests.append(test_semantic_scholar_with_key())
    else:
        tests.append(test_semantic_scholar_no_key())
    
    # Run all tests
    results = await asyncio.gather(*tests, return_exceptions=True)
    
    # Print results
    test_names = ['arXiv', 'PubMed', 'Crossref', 'Semantic Scholar']
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            print(f"❌ {test_names[i]}: {result}")
        else:
            print(f"✅ {test_names[i]}: {result}")

async def test_arxiv():
    """Test arXiv API access"""
    url = "http://export.arxiv.org/api/query"
    params = {"search_query": "cat:cs.AI", "max_results": 1}
    
    async with aiohttp.ClientSession() as session:
        async with session.get(url, params=params) as response:
            if response.status == 200:
                return f"SUCCESS (Status: {response.status})"
            else:
                return f"FAILED (Status: {response.status})"

async def test_pubmed_with_key():
    """Test PubMed with API key"""
    url = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi"
    params = {
        "db": "pubmed",
        "term": "machine learning",
        "retmax": 1,
        "retmode": "json",
        "api_key": os.getenv('SYNTHEX_NCBI_API_KEY')
    }
    
    async with aiohttp.ClientSession() as session:
        async with session.get(url, params=params) as response:
            if response.status == 200:
                return f"SUCCESS with API key (Status: {response.status})"
            else:
                return f"FAILED (Status: {response.status})"

async def test_pubmed_no_key():
    """Test PubMed without API key"""
    url = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi"
    params = {
        "db": "pubmed",
        "term": "machine learning",
        "retmax": 1,
        "retmode": "json"
    }
    
    async with aiohttp.ClientSession() as session:
        async with session.get(url, params=params) as response:
            if response.status == 200:
                return f"SUCCESS without API key (Status: {response.status})"
            else:
                return f"FAILED (Status: {response.status})"

async def test_crossref():
    """Test Crossref API with polite pool"""
    url = "https://api.crossref.org/works"
    params = {"query": "machine learning", "rows": 1}
    headers = {
        "User-Agent": f"SYNTHEX/1.0 (mailto:{os.getenv('SYNTHEX_CONTACT_EMAIL', 'test@example.com')})"
    }
    
    async with aiohttp.ClientSession() as session:
        async with session.get(url, params=params, headers=headers) as response:
            if response.status == 200:
                return f"SUCCESS with polite pool (Status: {response.status})"
            else:
                return f"FAILED (Status: {response.status})"

async def test_semantic_scholar_with_key():
    """Test Semantic Scholar with API key"""
    url = "https://api.semanticscholar.org/graph/v1/paper/search"
    params = {"query": "machine learning", "limit": 1}
    headers = {"x-api-key": os.getenv('SYNTHEX_SEMANTIC_SCHOLAR_API_KEY')}
    
    async with aiohttp.ClientSession() as session:
        async with session.get(url, params=params, headers=headers) as response:
            if response.status == 200:
                return f"SUCCESS with API key (Status: {response.status})"
            else:
                return f"FAILED (Status: {response.status})"

async def test_semantic_scholar_no_key():
    """Test Semantic Scholar without API key"""
    url = "https://api.semanticscholar.org/graph/v1/paper/search"
    params = {"query": "machine learning", "limit": 1}
    
    async with aiohttp.ClientSession() as session:
        async with session.get(url, params=params) as response:
            if response.status == 200:
                return f"SUCCESS without API key (Status: {response.status})"
            else:
                return f"FAILED (Status: {response.status})"

if __name__ == "__main__":
    print("Testing SYNTHEX Academic Database Access...")
    print("=" * 50)
    asyncio.run(test_api_access())
```

### Run the Test
```bash
# Make script executable and run
chmod +x test_api_access.py
python test_api_access.py
```

## 📊 Usage Monitoring Commands

### Check API Usage
```bash
# Monitor API calls in real-time
tail -f synthex_api_usage.log | grep -E "(ERROR|WARNING|INFO)"

# Count requests by database today
grep "$(date +%Y-%m-%d)" synthex_api_usage.log | cut -d'"' -f4 | sort | uniq -c

# Check rate limit compliance
python -c "
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta

# Load log file
usage = defaultdict(list)
with open('synthex_api_usage.log', 'r') as f:
    for line in f:
        data = json.loads(line)
        db = data['database']
        timestamp = datetime.fromisoformat(data['timestamp'])
        usage[db].append(timestamp)

# Check rate compliance
for db, times in usage.items():
    if len(times) < 2:
        continue
    
    # Check last 10 requests
    recent = sorted(times)[-10:]
    intervals = [(recent[i] - recent[i-1]).total_seconds() for i in range(1, len(recent))]
    avg_interval = sum(intervals) / len(intervals)
    
    print(f'{db}: avg interval {avg_interval:.2f}s, rate ~{1/avg_interval:.2f} req/s')
"
```

## 🔒 Security Best Practices

### Environment Variable Security
```bash
# Secure environment file permissions
chmod 600 .env.academic

# Add to .gitignore
echo ".env.academic" >> .gitignore
echo "*.env" >> .gitignore

# For production, use secret management
# Kubernetes secrets
kubectl create secret generic synthex-academic-secrets \
    --from-literal=ncbi-api-key="$SYNTHEX_NCBI_API_KEY" \
    --from-literal=semantic-scholar-key="$SYNTHEX_SEMANTIC_SCHOLAR_API_KEY"

# Docker secrets
echo "$SYNTHEX_NCBI_API_KEY" | docker secret create ncbi_api_key -
```

### API Key Rotation
```python
#!/usr/bin/env python3
# rotate_api_keys.py

import os
import json
from datetime import datetime, timedelta

class APIKeyRotator:
    def __init__(self, config_file='api_key_config.json'):
        self.config_file = config_file
        self.load_config()
    
    def load_config(self):
        try:
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            self.config = {}
    
    def save_config(self):
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def check_key_expiry(self, api_name, days_ahead=7):
        """Check if API key expires soon"""
        if api_name not in self.config:
            return False
        
        expiry = datetime.fromisoformat(self.config[api_name]['expires'])
        warning_date = datetime.now() + timedelta(days=days_ahead)
        
        return expiry < warning_date
    
    def register_key(self, api_name, key_value, expires_in_days=365):
        """Register new API key with expiry"""
        expiry = datetime.now() + timedelta(days=expires_in_days)
        
        self.config[api_name] = {
            'key': key_value,
            'expires': expiry.isoformat(),
            'created': datetime.now().isoformat()
        }
        
        self.save_config()
    
    def check_all_keys(self):
        """Check expiry for all registered keys"""
        for api_name in self.config:
            if self.check_key_expiry(api_name):
                print(f"⚠️  {api_name} key expires soon!")
            else:
                print(f"✅ {api_name} key is valid")

if __name__ == "__main__":
    rotator = APIKeyRotator()
    rotator.check_all_keys()
```

---

*Last Updated: June 14, 2025*  
*SYNTHEX API Keys and Credentials Reference v1.0*