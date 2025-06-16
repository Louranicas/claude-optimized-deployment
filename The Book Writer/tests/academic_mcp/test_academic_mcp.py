"""
Comprehensive test suite for Academic MCP Integration
Following TDD and property-based testing principles
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
import hypothesis.strategies as st
from hypothesis import given, settings
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from academic_mcp import AcademicMCPBridge, SynthorAcademicIntegration
from academic_mcp.bridge import Paper, CitationStyle


class TestAcademicMCPBridge:
    """Test cases for Academic MCP Bridge"""
    
    @pytest.fixture
    async def bridge(self):
        """Create bridge instance"""
        bridge = AcademicMCPBridge(cache_size=100)
        yield bridge
        # Cleanup if needed
    
    @pytest.mark.asyncio
    async def test_search_basic(self, bridge):
        """Test basic search functionality"""
        results = await bridge.search("quantum computing", limit=5)
        
        assert isinstance(results, list)
        assert len(results) <= 5
        
        if results:
            paper = results[0]
            assert isinstance(paper, Paper)
            assert paper.id
            assert paper.title
            assert isinstance(paper.authors, list)
    
    @pytest.mark.asyncio
    async def test_search_with_filters(self, bridge):
        """Test search with filters"""
        filters = {
            "year_min": 2020,
            "year_max": 2023,
            "field": "computer science"
        }
        
        results = await bridge.search("machine learning", limit=10, filters=filters)
        
        for paper in results:
            if paper.year:
                assert 2020 <= paper.year <= 2023
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, bridge):
        """Test rate limiting behavior"""
        # Make multiple rapid requests
        tasks = []
        for i in range(15):
            tasks.append(bridge.search(f"test query {i}", limit=1))
        
        # Some should succeed, some should be rate limited
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        errors = [r for r in results if isinstance(r, Exception)]
        assert len(errors) > 0  # Some requests should be rate limited
    
    @pytest.mark.asyncio
    async def test_citation_formatting(self, bridge):
        """Test citation formatting in different styles"""
        paper = Paper(
            id="test123",
            title="Test Paper: A Comprehensive Study",
            authors=["Smith, John", "Doe, Jane"],
            year=2023,
            doi="10.1234/test.2023",
            abstract=None,
            citations=42
        )
        
        # Test different citation styles
        apa_citation = await bridge.format_citation(paper, CitationStyle.APA)
        assert "Smith, J., & Doe, J. (2023)" in apa_citation
        
        mla_citation = await bridge.format_citation(paper, CitationStyle.MLA)
        assert "Smith" in mla_citation and "Test Paper" in mla_citation
        
        chicago_citation = await bridge.format_citation(paper, CitationStyle.CHICAGO)
        assert paper.title in chicago_citation
    
    @given(st.text(min_size=1, max_size=100))
    @settings(max_examples=10)
    @pytest.mark.asyncio
    async def test_search_property_based(self, bridge, query):
        """Property-based testing for search"""
        try:
            results = await bridge.search(query, limit=5)
            assert isinstance(results, list)
            assert len(results) <= 5
        except Exception as e:
            # Should handle gracefully
            assert str(e)  # Error message should exist


class TestSynthorIntegration:
    """Test cases for Synthor integration"""
    
    @pytest.fixture
    def mock_synthor(self):
        """Create mock Synthor instance"""
        mock = Mock()
        mock.notify_search_started = AsyncMock()
        mock.display_citation_suggestions = AsyncMock()
        mock.insert_text_at_cursor = AsyncMock()
        mock.update_reference_section = AsyncMock()
        return mock
    
    @pytest.fixture
    async def integration(self, mock_synthor):
        """Create integration instance"""
        integration = SynthorAcademicIntegration(mock_synthor)
        yield integration
    
    @pytest.mark.asyncio
    async def test_text_selection_handling(self, integration, mock_synthor):
        """Test handling of text selection"""
        selection = "Recent advances in quantum computing have shown promising results"
        context = {"document_id": "doc123", "position": 100}
        
        await integration.handle_text_selection(selection, context)
        
        # Should start background search
        assert mock_synthor.notify_search_started.called
        
        # Wait for background task
        await asyncio.sleep(0.5)
    
    @pytest.mark.asyncio
    async def test_citation_insertion(self, integration, mock_synthor):
        """Test citation insertion workflow"""
        from academic_mcp.synthor_integration import CitationContext
        
        context = CitationContext(
            selected_text="quantum computing",
            cursor_position=150,
            current_paragraph="Test paragraph",
            document_id="doc123",
            citation_style=CitationStyle.APA
        )
        
        # Mock paper retrieval
        with patch.object(integration.bridge, 'get_paper') as mock_get:
            mock_paper = Paper(
                id="paper123",
                title="Quantum Computing Advances",
                authors=["Johnson, A.", "Smith, B."],
                year=2023,
                doi="10.1234/qc.2023",
                abstract="Abstract text",
                citations=50
            )
            mock_get.return_value = mock_paper
            
            await integration.handle_citation_request("paper123", context)
        
        # Should insert in-text citation
        mock_synthor.insert_text_at_cursor.assert_called_once()
        call_args = mock_synthor.insert_text_at_cursor.call_args[0][0]
        assert "Johnson" in call_args
        assert "2023" in call_args
        
        # Should update reference list
        mock_synthor.update_reference_section.assert_called_once()


class TestEndToEnd:
    """End-to-end integration tests"""
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_complete_citation_workflow(self):
        """Test complete citation workflow from search to insertion"""
        # This would test the full integration
        # Including actual MCP server calls if available
        pass
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_search_performance(self):
        """Test search performance under load"""
        bridge = AcademicMCPBridge()
        
        # Measure time for concurrent searches
        start_time = asyncio.get_event_loop().time()
        
        tasks = []
        for i in range(10):
            tasks.append(bridge.search(f"test query {i}", limit=5))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        end_time = asyncio.get_event_loop().time()
        total_time = end_time - start_time
        
        # Should complete within reasonable time
        assert total_time < 5.0  # 5 seconds for 10 searches
        
        # Most should succeed
        successful = [r for r in results if not isinstance(r, Exception)]
        assert len(successful) >= 8  # At least 80% success rate


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--asyncio-mode=auto"])
