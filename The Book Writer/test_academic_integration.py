#!/usr/bin/env python3
"""
Test script for Academic MCP Integration with Hyper Narrative Synthor
Validates the complete integration and demonstrates usage
"""

import asyncio
import sys
from pathlib import Path
import logging
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from hyper_narrative_synthor import HyperNarrativeSynthor
from academic_mcp import SynthorAcademicIntegration, AcademicAssistant
from academic_mcp.bridge import CitationStyle
from academic_mcp.synthor_integration import CitationContext

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class TestAcademicIntegration:
    """Test the academic MCP integration with Synthor"""
    
    def __init__(self):
        self.synthor = None
        self.academic_integration = None
        self.test_results = []
        
    async def setup(self):
        """Setup test environment"""
        logger.info("🔧 Setting up test environment...")
        
        # Initialize Synthor (mock for testing)
        self.synthor = MockSynthor()
        
        # Initialize academic integration
        self.academic_integration = SynthorAcademicIntegration(self.synthor)
        self.assistant = AcademicAssistant(self.academic_integration)
        
        logger.info("✅ Test environment ready")
        
    async def test_search_functionality(self):
        """Test basic search functionality"""
        logger.info("🔍 Testing search functionality...")
        
        try:
            # Test search
            results = await self.academic_integration.bridge.search(
                "quantum computing applications",
                limit=5
            )
            
            if results:
                logger.info(f"✅ Search returned {len(results)} results")
                for i, paper in enumerate(results[:3], 1):
                    logger.info(f"  {i}. {paper.title[:60]}...")
                self.test_results.append(("search", "PASS"))
            else:
                logger.warning("⚠️ Search returned no results")
                self.test_results.append(("search", "FAIL"))
                
        except Exception as e:
            logger.error(f"❌ Search test failed: {e}")
            self.test_results.append(("search", "ERROR", str(e)))
    
    async def test_citation_formatting(self):
        """Test citation formatting"""
        logger.info("📝 Testing citation formatting...")
        
        try:
            # Create test paper
            from academic_mcp.bridge import Paper
            test_paper = Paper(
                id="test123",
                title="Quantum Computing: A Comprehensive Review",
                authors=["Smith, John", "Doe, Jane", "Johnson, Alice"],
                year=2023,
                doi="10.1234/quantum.2023",
                abstract="This paper reviews quantum computing...",
                citations=150
            )
            
            # Test different citation styles
            styles_tested = 0
            for style in [CitationStyle.APA, CitationStyle.MLA, CitationStyle.CHICAGO]:
                try:
                    citation = await self.academic_integration.bridge.format_citation(
                        test_paper, style
                    )
                    logger.info(f"  {style.value}: {citation}")
                    styles_tested += 1
                except Exception as e:
                    logger.error(f"  {style.value} failed: {e}")
            
            if styles_tested >= 2:
                self.test_results.append(("citation_formatting", "PASS"))
            else:
                self.test_results.append(("citation_formatting", "PARTIAL"))
                
        except Exception as e:
            logger.error(f"❌ Citation formatting test failed: {e}")
            self.test_results.append(("citation_formatting", "ERROR", str(e)))
    
    async def test_text_selection_handling(self):
        """Test handling of text selection"""
        logger.info("📄 Testing text selection handling...")
        
        try:
            # Simulate text selection
            selected_text = "Recent advances in machine learning have revolutionized natural language processing"
            context = {"document_id": "test_doc", "position": 100}
            
            # This should trigger background search
            await self.academic_integration.handle_text_selection(selected_text, context)
            
            # Wait for background task
            await asyncio.sleep(0.5)
            
            # Check if search was initiated
            if self.synthor.search_started_count > 0:
                logger.info("✅ Text selection triggered search")
                self.test_results.append(("text_selection", "PASS"))
            else:
                logger.warning("⚠️ Text selection did not trigger search")
                self.test_results.append(("text_selection", "FAIL"))
                
        except Exception as e:
            logger.error(f"❌ Text selection test failed: {e}")
            self.test_results.append(("text_selection", "ERROR", str(e)))
    
    async def test_citation_insertion(self):
        """Test citation insertion workflow"""
        logger.info("📌 Testing citation insertion...")
        
        try:
            # Create citation context
            context = CitationContext(
                selected_text="quantum computing",
                cursor_position=150,
                current_paragraph="The field of quantum computing has seen rapid growth.",
                document_id="test_doc",
                citation_style=CitationStyle.APA
            )
            
            # Mock paper retrieval
            self.academic_integration.bridge.get_paper = MockGetPaper()
            
            # Request citation insertion
            await self.academic_integration.handle_citation_request("paper123", context)
            
            # Check if citation was inserted
            if self.synthor.inserted_text:
                logger.info(f"✅ Citation inserted: {self.synthor.inserted_text}")
                self.test_results.append(("citation_insertion", "PASS"))
            else:
                logger.warning("⚠️ No citation inserted")
                self.test_results.append(("citation_insertion", "FAIL"))
                
        except Exception as e:
            logger.error(f"❌ Citation insertion test failed: {e}")
            self.test_results.append(("citation_insertion", "ERROR", str(e)))
    
    async def test_academic_assistant(self):
        """Test academic assistant features"""
        logger.info("🎓 Testing academic assistant...")
        
        try:
            # Test citation suggestions
            from academic_mcp.assistant import WritingContext
            
            context = WritingContext(
                current_text="Machine learning algorithms have shown promising results in medical diagnosis.",
                cursor_position=50,
                document_type="paper",
                field="computer_science",
                citation_style=CitationStyle.APA
            )
            
            suggestions = await self.assistant.suggest_citations(context, num_suggestions=3)
            
            if suggestions:
                logger.info(f"✅ Assistant suggested {len(suggestions)} citations")
                for i, sugg in enumerate(suggestions[:2], 1):
                    logger.info(f"  {i}. {sugg['paper'].title[:50]}... (relevance: {sugg['relevance_score']:.2f})")
                self.test_results.append(("assistant_suggestions", "PASS"))
            else:
                logger.warning("⚠️ No suggestions from assistant")
                self.test_results.append(("assistant_suggestions", "FAIL"))
                
        except Exception as e:
            logger.error(f"❌ Academic assistant test failed: {e}")
            self.test_results.append(("assistant_suggestions", "ERROR", str(e)))
    
    async def test_performance(self):
        """Test performance under load"""
        logger.info("⚡ Testing performance...")
        
        try:
            start_time = asyncio.get_event_loop().time()
            
            # Concurrent searches
            search_tasks = []
            for i in range(5):
                task = self.academic_integration.bridge.search(f"test query {i}", limit=3)
                search_tasks.append(task)
            
            results = await asyncio.gather(*search_tasks, return_exceptions=True)
            
            end_time = asyncio.get_event_loop().time()
            duration = end_time - start_time
            
            successful = sum(1 for r in results if not isinstance(r, Exception))
            
            logger.info(f"✅ Completed {successful}/5 searches in {duration:.2f}s")
            
            if successful >= 4 and duration < 3.0:
                self.test_results.append(("performance", "PASS"))
            else:
                self.test_results.append(("performance", "FAIL", f"{successful} succeeded, took {duration:.2f}s"))
                
        except Exception as e:
            logger.error(f"❌ Performance test failed: {e}")
            self.test_results.append(("performance", "ERROR", str(e)))
    
    async def run_all_tests(self):
        """Run all integration tests"""
        logger.info("🚀 Starting Academic MCP Integration Tests")
        logger.info("="*60)
        
        await self.setup()
        
        # Run tests
        tests = [
            self.test_search_functionality,
            self.test_citation_formatting,
            self.test_text_selection_handling,
            self.test_citation_insertion,
            self.test_academic_assistant,
            self.test_performance
        ]
        
        for test in tests:
            logger.info("")  # Blank line for readability
            await test()
            await asyncio.sleep(0.1)  # Small delay between tests
        
        # Summary
        logger.info("")
        logger.info("="*60)
        logger.info("📊 TEST SUMMARY")
        logger.info("="*60)
        
        passed = sum(1 for _, status, *_ in self.test_results if status == "PASS")
        failed = sum(1 for _, status, *_ in self.test_results if status in ["FAIL", "ERROR"])
        partial = sum(1 for _, status, *_ in self.test_results if status == "PARTIAL")
        
        for test_name, status, *details in self.test_results:
            emoji = "✅" if status == "PASS" else "❌" if status in ["FAIL", "ERROR"] else "⚠️"
            detail_str = f" - {details[0]}" if details else ""
            logger.info(f"{emoji} {test_name}: {status}{detail_str}")
        
        logger.info("")
        logger.info(f"Total: {passed} passed, {failed} failed, {partial} partial")
        
        if failed == 0:
            logger.info("🎉 ALL TESTS PASSED!")
        else:
            logger.warning(f"⚠️ {failed} tests failed")
        
        return failed == 0


# Mock classes for testing
class MockSynthor:
    """Mock Synthor for testing"""
    def __init__(self):
        self.search_started_count = 0
        self.inserted_text = None
        self.reference_section = None
        
    async def notify_search_started(self, search_id):
        self.search_started_count += 1
        
    async def display_citation_suggestions(self, search_id, suggestions):
        pass
        
    async def insert_text_at_cursor(self, text):
        self.inserted_text = text
        
    async def update_reference_section(self, text):
        self.reference_section = text
        
    async def notify_search_failed(self, search_id, error):
        pass


class MockGetPaper:
    """Mock paper retrieval"""
    async def __call__(self, paper_id):
        from academic_mcp.bridge import Paper
        return Paper(
            id=paper_id,
            title="Test Paper Title",
            authors=["Test, Author"],
            year=2023,
            doi="10.1234/test",
            abstract="Test abstract",
            citations=100
        )


async def main():
    """Run integration tests"""
    tester = TestAcademicIntegration()
    success = await tester.run_all_tests()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    asyncio.run(main())