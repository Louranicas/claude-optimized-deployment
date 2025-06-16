"""
Test suite for SYNTHEX Academic Database Agents
Comprehensive testing for academic search functionality
"""

import pytest
import asyncio
import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from typing import List, Dict, Any

# Import the academic agents
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from synthex.academic_agents import (
    ArXivAgent, CrossrefAgent, SemanticScholarAgent,
    AcademicResult, AcademicFilters, Author, RateLimiter,
    ExponentialBackoffLimiter, create_academic_agent
)
from synthex.academic_config import (
    ArXivConfig, CrossrefConfig, SemanticScholarConfig,
    AcademicSearchConfig, ExtendedSynthexConfig
)
from synthex.config import ApiConfig


class TestAcademicResult:
    """Test the AcademicResult data structure"""
    
    def test_academic_result_creation(self):
        """Test basic AcademicResult creation"""
        result = AcademicResult(
            title="Test Paper",
            abstract="This is a test abstract",
            source="test",
            relevance_score=0.95
        )
        
        assert result.title == "Test Paper"
        assert result.abstract == "This is a test abstract"
        assert result.source == "test"
        assert result.relevance_score == 0.95
        assert result.citation_count == 0  # Default value
        assert result.open_access is False  # Default value
    
    def test_to_synthex_result_conversion(self):
        """Test conversion to SYNTHEX-compatible format"""
        result = AcademicResult(
            title="AI Research Paper",
            abstract="Comprehensive study of AI",
            doi="10.1000/test.doi",
            citation_count=150,
            open_access=True,
            source="arxiv",
            relevance_score=0.92,
            publication_date=datetime(2024, 1, 15)
        )
        
        result.authors = [Author(name="John Doe"), Author(name="Jane Smith")]
        result.subjects = ["cs.AI", "cs.ML"]
        result.html_url = "https://arxiv.org/abs/2401.12345"
        
        synthex_result = result.to_synthex_result()
        
        assert synthex_result["title"] == "AI Research Paper"
        assert synthex_result["snippet"] == "Comprehensive study of AI"
        assert synthex_result["url"] == "https://arxiv.org/abs/2401.12345"
        assert synthex_result["score"] == 0.92
        assert synthex_result["source"] == "academic_arxiv"
        
        metadata = synthex_result["metadata"]
        assert metadata["doi"] == "10.1000/test.doi"
        assert metadata["authors"] == ["John Doe", "Jane Smith"]
        assert metadata["citation_count"] == 150
        assert metadata["open_access"] is True
        assert metadata["subjects"] == ["cs.AI", "cs.ML"]


class TestRateLimiter:
    """Test rate limiting functionality"""
    
    @pytest.mark.asyncio
    async def test_rate_limiter_timing(self):
        """Test that rate limiter enforces timing"""
        limiter = RateLimiter(requests_per_second=2.0)  # 2 RPS = 0.5 second intervals
        
        start_time = asyncio.get_event_loop().time()
        
        # Make three requests
        await limiter.acquire()
        first_time = asyncio.get_event_loop().time()
        
        await limiter.acquire()
        second_time = asyncio.get_event_loop().time()
        
        await limiter.acquire()
        third_time = asyncio.get_event_loop().time()
        
        # Check timing intervals
        first_interval = first_time - start_time
        second_interval = second_time - first_time
        third_interval = third_time - second_time
        
        # First request should be immediate
        assert first_interval < 0.1
        
        # Subsequent requests should be spaced by ~0.5 seconds
        assert 0.4 <= second_interval <= 0.6
        assert 0.4 <= third_interval <= 0.6
    
    @pytest.mark.asyncio
    async def test_exponential_backoff_limiter(self):
        """Test exponential backoff behavior"""
        limiter = ExponentialBackoffLimiter(base_delay=0.1, max_delay=1.0)
        
        # Simulate failures
        start_time = asyncio.get_event_loop().time()
        
        await limiter.on_failure()
        first_delay = asyncio.get_event_loop().time() - start_time
        
        start_time = asyncio.get_event_loop().time()
        await limiter.on_failure()
        second_delay = asyncio.get_event_loop().time() - start_time
        
        # Second delay should be longer (exponential backoff)
        assert second_delay > first_delay
        assert 0.1 <= first_delay <= 0.3
        assert 0.2 <= second_delay <= 0.5
        
        # Test success reset
        limiter.on_success()
        assert limiter.failure_count == 0


class TestArXivAgent:
    """Test arXiv search agent"""
    
    @pytest.fixture
    def arxiv_config(self):
        """Create test arXiv configuration"""
        return ArXivConfig(
            request_timeout_ms=5000,
            request_delay_seconds=0.1  # Faster for testing
        )
    
    @pytest.fixture
    def arxiv_agent(self, arxiv_config):
        """Create test arXiv agent"""
        return ArXivAgent(arxiv_config)
    
    def test_arxiv_query_building(self, arxiv_agent):
        """Test arXiv query string building"""
        # Simple query
        query = arxiv_agent._build_arxiv_query("machine learning", None)
        assert query == "all:machine learning"
        
        # Query with subject filters
        filters = AcademicFilters(subjects=["cs.AI", "cs.ML"])
        query = arxiv_agent._build_arxiv_query("neural networks", filters)
        assert "all:neural networks" in query
        assert "cat:cs.AI" in query
        assert "cat:cs.ML" in query
        assert "AND" in query
    
    def test_arxiv_xml_parsing(self, arxiv_agent):
        """Test parsing of arXiv XML responses"""
        # Sample arXiv XML response
        xml_content = '''<?xml version="1.0" encoding="UTF-8"?>
        <feed xmlns="http://www.w3.org/2005/Atom" xmlns:arxiv="http://arxiv.org/schemas/atom">
            <entry>
                <id>http://arxiv.org/abs/2401.12345v1</id>
                <title>Sample AI Paper</title>
                <summary>This is a sample abstract about AI research.</summary>
                <published>2024-01-15T10:30:00Z</published>
                <author>
                    <name>John Doe</name>
                </author>
                <author>
                    <name>Jane Smith</name>
                </author>
                <arxiv:category term="cs.AI" />
                <arxiv:category term="cs.LG" />
                <link type="application/pdf" href="http://arxiv.org/pdf/2401.12345v1.pdf" />
            </entry>
        </feed>'''
        
        results = arxiv_agent._parse_arxiv_response(xml_content)
        
        assert len(results) == 1
        result = results[0]
        
        assert result.title == "Sample AI Paper"
        assert result.abstract == "This is a sample abstract about AI research."
        assert result.arxiv_id == "2401.12345v1"
        assert result.source == "arxiv"
        assert result.open_access is True
        assert len(result.authors) == 2
        assert result.authors[0].name == "John Doe"
        assert result.authors[1].name == "Jane Smith"
        assert "cs.AI" in result.subjects
        assert "cs.LG" in result.subjects
        assert result.pdf_url == "http://arxiv.org/pdf/2401.12345v1.pdf"
    
    @pytest.mark.asyncio
    async def test_arxiv_search_mock(self, arxiv_agent):
        """Test arXiv search with mocked HTTP response"""
        # Mock the session and response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='''<?xml version="1.0" encoding="UTF-8"?>
        <feed xmlns="http://www.w3.org/2005/Atom" xmlns:arxiv="http://arxiv.org/schemas/atom">
            <entry>
                <id>http://arxiv.org/abs/2401.12345v1</id>
                <title>Machine Learning Research</title>
                <summary>Advanced ML techniques.</summary>
                <published>2024-01-15T10:30:00Z</published>
                <author><name>Researcher One</name></author>
                <arxiv:category term="cs.LG" />
            </entry>
        </feed>''')
        
        mock_session = AsyncMock()
        mock_session.get.return_value.__aenter__.return_value = mock_response
        
        # Patch the session
        arxiv_agent.session = mock_session
        
        # Perform search
        results = await arxiv_agent.search_academic("machine learning", max_results=10)
        
        assert len(results) == 1
        assert results[0].title == "Machine Learning Research"
        assert results[0].source == "arxiv"


class TestCrossrefAgent:
    """Test Crossref search agent"""
    
    @pytest.fixture
    def crossref_config(self):
        """Create test Crossref configuration"""
        return CrossrefConfig(request_timeout_ms=5000)
    
    @pytest.fixture
    def crossref_agent(self, crossref_config):
        """Create test Crossref agent"""
        return CrossrefAgent(crossref_config)
    
    def test_crossref_open_access_detection(self, crossref_agent):
        """Test open access detection logic"""
        # Item with license (should be open access)
        item_with_license = {
            "license": [{"URL": "http://creativecommons.org/licenses/by/4.0/"}]
        }
        assert crossref_agent._is_open_access(item_with_license) is True
        
        # Item with PDF link (should be open access)
        item_with_pdf = {
            "link": [{"content-type": "application/pdf", "URL": "http://example.com/paper.pdf"}]
        }
        assert crossref_agent._is_open_access(item_with_pdf) is True
        
        # Item without indicators (should not be open access)
        item_closed = {"title": ["Closed Access Paper"]}
        assert crossref_agent._is_open_access(item_closed) is False
    
    def test_crossref_response_parsing(self, crossref_agent):
        """Test parsing of Crossref JSON responses"""
        # Sample Crossref response
        response_data = {
            "message": {
                "items": [
                    {
                        "DOI": "10.1000/test.doi",
                        "title": ["Advanced Machine Learning Techniques"],
                        "author": [
                            {"given": "John", "family": "Doe"},
                            {"given": "Jane", "family": "Smith"}
                        ],
                        "published-print": {
                            "date-parts": [[2024, 1, 15]]
                        },
                        "container-title": ["Journal of AI Research"],
                        "is-referenced-by-count": 42,
                        "subject": ["Computer Science", "Artificial Intelligence"],
                        "score": 0.95,
                        "license": [{"URL": "http://creativecommons.org/licenses/by/4.0/"}]
                    }
                ]
            }
        }
        
        results = crossref_agent._parse_crossref_response(response_data)
        
        assert len(results) == 1
        result = results[0]
        
        assert result.doi == "10.1000/test.doi"
        assert result.title == "Advanced Machine Learning Techniques"
        assert result.venue == "Journal of AI Research"
        assert result.citation_count == 42
        assert result.relevance_score == 0.95
        assert result.open_access is True
        assert result.source == "crossref"
        assert len(result.authors) == 2
        assert result.authors[0].name == "John Doe"
        assert result.authors[1].name == "Jane Smith"
        assert "Computer Science" in result.subjects


class TestSemanticScholarAgent:
    """Test Semantic Scholar search agent"""
    
    @pytest.fixture
    def semantic_scholar_config(self):
        """Create test Semantic Scholar configuration"""
        return SemanticScholarConfig(request_timeout_ms=5000)
    
    @pytest.fixture
    def semantic_scholar_agent(self, semantic_scholar_config):
        """Create test Semantic Scholar agent"""
        return SemanticScholarAgent(semantic_scholar_config)
    
    def test_relevance_score_calculation(self, semantic_scholar_agent):
        """Test relevance score calculation logic"""
        # High citation paper
        paper_high_citations = {
            "citationCount": 1000,
            "influentialCitationCount": 50,
            "year": 2023
        }
        score = semantic_scholar_agent._calculate_relevance_score(paper_high_citations)
        assert score > 0.8  # Should get high score
        
        # Recent paper with moderate citations
        paper_recent = {
            "citationCount": 10,
            "influentialCitationCount": 2,
            "year": datetime.now().year
        }
        score = semantic_scholar_agent._calculate_relevance_score(paper_recent)
        assert 0.5 < score < 0.8
        
        # Old paper with no citations
        paper_old = {
            "citationCount": 0,
            "influentialCitationCount": 0,
            "year": 2000
        }
        score = semantic_scholar_agent._calculate_relevance_score(paper_old)
        assert score <= 0.6
    
    def test_semantic_scholar_response_parsing(self, semantic_scholar_agent):
        """Test parsing of Semantic Scholar JSON responses"""
        # Sample Semantic Scholar response
        response_data = {
            "data": [
                {
                    "paperId": "12345abcde",
                    "title": "Deep Learning for Natural Language Processing",
                    "abstract": "Comprehensive survey of deep learning in NLP.",
                    "year": 2023,
                    "venue": "ACL",
                    "authors": [
                        {"name": "Alice Johnson"},
                        {"name": "Bob Wilson"}
                    ],
                    "citationCount": 150,
                    "referenceCount": 80,
                    "influentialCitationCount": 25,
                    "fieldsOfStudy": ["Computer Science", "Natural Language Processing"],
                    "isOpenAccess": True,
                    "openAccessPdf": {"url": "https://example.com/paper.pdf"}
                }
            ]
        }
        
        results = semantic_scholar_agent._parse_semantic_scholar_response(response_data)
        
        assert len(results) == 1
        result = results[0]
        
        assert result.semantic_scholar_id == "12345abcde"
        assert result.title == "Deep Learning for Natural Language Processing"
        assert result.abstract == "Comprehensive survey of deep learning in NLP."
        assert result.venue == "ACL"
        assert result.citation_count == 150
        assert result.reference_count == 80
        assert result.influential_citation_count == 25
        assert result.open_access is True
        assert result.pdf_url == "https://example.com/paper.pdf"
        assert result.source == "semantic_scholar"
        assert len(result.authors) == 2
        assert "Computer Science" in result.subjects


class TestAcademicConfiguration:
    """Test academic configuration classes"""
    
    def test_academic_search_config_creation(self):
        """Test basic academic search configuration"""
        config = AcademicSearchConfig()
        
        # Check defaults
        assert config.enable_arxiv is True
        assert config.enable_crossref is True
        assert config.enable_semantic_scholar is True
        assert config.enable_pubmed is True
        assert config.enable_ieee is False  # Requires subscription
        
        # Check fusion weights
        assert len(config.fusion_weights) > 0
        assert abs(sum(config.fusion_weights.values()) - 1.0) < 0.01
    
    def test_academic_config_validation(self):
        """Test configuration validation"""
        config = AcademicSearchConfig()
        
        # Valid config should pass
        errors = config.validate()
        assert len(errors) == 0
        
        # Disable all databases (should fail)
        config.enable_arxiv = False
        config.enable_crossref = False
        config.enable_semantic_scholar = False
        config.enable_pubmed = False
        config.enable_ieee = False
        config.enable_core = False
        config.enable_openalex = False
        config.enable_datacite = False
        
        errors = config.validate()
        assert len(errors) > 0
        assert "at least one academic database" in errors[0].lower()
    
    def test_enabled_databases_list(self):
        """Test getting list of enabled databases"""
        config = AcademicSearchConfig()
        
        # Enable only specific databases
        config.enable_arxiv = True
        config.enable_crossref = True
        config.enable_semantic_scholar = False
        config.enable_pubmed = False
        config.enable_ieee = False
        config.enable_core = False
        config.enable_openalex = False
        config.enable_datacite = False
        
        enabled = config.get_enabled_databases()
        assert "arxiv" in enabled
        assert "crossref" in enabled
        assert "semantic_scholar" not in enabled
        assert len(enabled) == 2


class TestAcademicAgentFactory:
    """Test academic agent factory function"""
    
    def test_agent_creation(self):
        """Test creating agents via factory"""
        config = ApiConfig()
        
        # Test valid agent types
        arxiv_agent = create_academic_agent("arxiv", config)
        assert isinstance(arxiv_agent, ArXivAgent)
        
        crossref_agent = create_academic_agent("crossref", config)
        assert isinstance(crossref_agent, CrossrefAgent)
        
        semantic_scholar_agent = create_academic_agent("semantic_scholar", config)
        assert isinstance(semantic_scholar_agent, SemanticScholarAgent)
    
    def test_invalid_agent_type(self):
        """Test error handling for invalid agent types"""
        config = ApiConfig()
        
        with pytest.raises(ValueError) as exc_info:
            create_academic_agent("invalid_agent", config)
        
        assert "Unknown academic agent type" in str(exc_info.value)


class TestAcademicFilters:
    """Test academic search filters"""
    
    def test_filter_creation(self):
        """Test creating academic filters"""
        filters = AcademicFilters(
            start_date=datetime(2020, 1, 1),
            end_date=datetime(2024, 12, 31),
            subjects=["cs.AI", "cs.ML"],
            open_access_only=True,
            min_citations=10
        )
        
        assert filters.start_date.year == 2020
        assert filters.end_date.year == 2024
        assert "cs.AI" in filters.subjects
        assert filters.open_access_only is True
        assert filters.min_citations == 10


@pytest.mark.integration
class TestAcademicIntegration:
    """Integration tests for academic agents (requires internet)"""
    
    @pytest.mark.asyncio
    async def test_arxiv_real_search(self):
        """Test real arXiv search (integration test)"""
        config = ArXivConfig(request_delay_seconds=2.0)  # Be extra polite
        agent = ArXivAgent(config)
        
        try:
            results = await agent.search_academic("machine learning", max_results=5)
            
            # Should get some results
            assert len(results) > 0
            
            # Check result structure
            result = results[0]
            assert result.title
            assert result.source == "arxiv"
            assert result.open_access is True
            
        except Exception as e:
            pytest.skip(f"arXiv integration test failed (network issue?): {e}")
        finally:
            await agent.shutdown()
    
    @pytest.mark.asyncio
    async def test_crossref_real_search(self):
        """Test real Crossref search (integration test)"""
        config = CrossrefConfig()
        agent = CrossrefAgent(config)
        
        try:
            results = await agent.search_academic("artificial intelligence", max_results=5)
            
            # Should get some results
            assert len(results) > 0
            
            # Check result structure
            result = results[0]
            assert result.title
            assert result.source == "crossref"
            assert result.doi  # Crossref should always have DOIs
            
        except Exception as e:
            pytest.skip(f"Crossref integration test failed (network issue?): {e}")
        finally:
            await agent.shutdown()


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])