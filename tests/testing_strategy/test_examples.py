"""
Comprehensive Test Examples for Each Testing Category
SYNTHEX Agent 8 - Testing Specialist

This module provides concrete pytest examples for all test categories.
"""

import pytest
import asyncio
import json
import time
import random
from pathlib import Path
from typing import Dict, List, Any, Optional
from unittest.mock import Mock, AsyncMock, patch
import aiofiles
import psutil
import gc
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
import hypothesis.strategies as st
from hypothesis import given, settings, example


# ============================================================================
# 1. UNIT TESTS - Chapter Detection Algorithms
# ============================================================================

class TestChapterDetection:
    """Unit tests for chapter detection algorithms."""
    
    @pytest.mark.unit
    def test_detect_chapters_markdown(self, sample_markdown_doc):
        """Test chapter detection in Markdown documents."""
        from src.document_processor.chapter_detector import ChapterDetector
        
        detector = ChapterDetector()
        chapters = detector.detect_chapters(sample_markdown_doc, format="markdown")
        
        assert len(chapters) > 0
        assert all(ch.get("title") for ch in chapters)
        assert all(ch.get("level") in range(1, 7) for ch in chapters)
        assert chapters[0]["level"] == 1  # First chapter should be top-level
        
        # Test nested chapters
        for i, chapter in enumerate(chapters[1:], 1):
            if chapter["level"] > chapters[i-1]["level"]:
                assert chapter["parent_id"] == chapters[i-1]["id"]
    
    @pytest.mark.unit
    @pytest.mark.parametrize("format,sample", [
        ("latex", "\\chapter{Introduction}\n\\section{Background}"),
        ("html", "<h1>Chapter 1</h1><h2>Section 1.1</h2>"),
        ("docx", "test_documents/sample.docx"),
        ("pdf", "test_documents/sample.pdf")
    ])
    def test_detect_chapters_multiple_formats(self, format, sample):
        """Test chapter detection across different document formats."""
        from src.document_processor.chapter_detector import ChapterDetector
        
        detector = ChapterDetector()
        chapters = detector.detect_chapters(sample, format=format)
        
        assert len(chapters) > 0
        assert detector.validate_chapter_structure(chapters)
    
    @pytest.mark.unit
    def test_detect_chapters_edge_cases(self):
        """Test chapter detection with edge cases."""
        from src.document_processor.chapter_detector import ChapterDetector
        
        detector = ChapterDetector()
        
        # Empty document
        assert detector.detect_chapters("", format="markdown") == []
        
        # No chapters
        assert detector.detect_chapters("Just plain text", format="markdown") == []
        
        # Malformed headers
        malformed = "# Chapter 1\n### Subsection (missing H2)\n# Chapter 2"
        chapters = detector.detect_chapters(malformed, format="markdown")
        assert detector.validate_chapter_structure(chapters, strict=False)
    
    @pytest.mark.unit
    @given(
        depth=st.integers(min_value=1, max_value=6),
        count=st.integers(min_value=1, max_value=100)
    )
    def test_detect_chapters_property_based(self, depth, count):
        """Property-based testing for chapter detection."""
        from src.document_processor.chapter_detector import ChapterDetector
        from tests.utils.document_generator import generate_markdown_with_chapters
        
        document = generate_markdown_with_chapters(depth=depth, count=count)
        detector = ChapterDetector()
        chapters = detector.detect_chapters(document, format="markdown")
        
        # Properties that should always hold
        assert len(chapters) <= count * depth
        assert all(1 <= ch["level"] <= depth for ch in chapters)
        assert detector.validate_chapter_structure(chapters)


# ============================================================================
# 2. INTEGRATION TESTS - Format Parsers
# ============================================================================

class TestFormatParserIntegration:
    """Integration tests for format parsers."""
    
    @pytest.mark.integration
    async def test_parser_detector_integration(self, temp_dir):
        """Test integration between parsers and chapter detector."""
        from src.document_processor import DocumentProcessor
        
        processor = DocumentProcessor()
        
        # Create test documents
        test_files = {
            "doc1.md": "# Chapter 1\n## Section 1.1\n# Chapter 2",
            "doc2.tex": "\\chapter{Intro}\\section{Background}",
            "doc3.html": "<h1>Title</h1><h2>Subtitle</h2>"
        }
        
        for filename, content in test_files.items():
            path = temp_dir / filename
            path.write_text(content)
        
        # Process all documents
        results = await processor.process_directory(temp_dir)
        
        assert len(results) == 3
        for result in results:
            assert result["status"] == "success"
            assert "chapters" in result
            assert len(result["chapters"]) > 0
    
    @pytest.mark.integration
    async def test_multi_format_processing_pipeline(self):
        """Test processing pipeline with multiple formats."""
        from src.document_processor import ProcessingPipeline
        
        pipeline = ProcessingPipeline()
        
        # Configure pipeline
        pipeline.add_parser("markdown", "latex", "html", "docx")
        pipeline.add_detector("universal")
        pipeline.add_output_format("json", "xml")
        
        # Process mixed format documents
        test_docs = [
            {"path": "doc1.md", "format": "markdown"},
            {"path": "doc2.tex", "format": "latex"},
            {"path": "doc3.html", "format": "html"}
        ]
        
        results = await pipeline.process_batch(test_docs)
        
        assert all(r["processed"] for r in results)
        assert all("chapters" in r["output"] for r in results)
    
    @pytest.mark.integration
    async def test_parser_error_propagation(self):
        """Test error handling across parser components."""
        from src.document_processor import DocumentProcessor
        
        processor = DocumentProcessor()
        
        # Test with corrupted file
        with pytest.raises(ValueError) as exc_info:
            await processor.process_file("corrupted.pdf")
        
        assert "Failed to parse" in str(exc_info.value)
        assert processor.get_error_count() == 1


# ============================================================================
# 3. END-TO-END TESTS - MCP Protocol
# ============================================================================

class TestMCPProtocolE2E:
    """End-to-end tests for MCP protocol integration."""
    
    @pytest.mark.e2e
    async def test_mcp_document_upload_flow(self, mcp_test_client):
        """Test complete document upload flow through MCP."""
        # Upload document
        with open("test_documents/sample.pdf", "rb") as f:
            response = await mcp_test_client.upload_document(
                file=f,
                metadata={"title": "Test Document", "author": "Test User"}
            )
        
        assert response["status"] == "success"
        document_id = response["document_id"]
        
        # Verify upload
        doc_info = await mcp_test_client.get_document(document_id)
        assert doc_info["title"] == "Test Document"
        assert doc_info["status"] == "uploaded"
    
    @pytest.mark.e2e
    async def test_mcp_chapter_detection_flow(self, mcp_test_client):
        """Test chapter detection through MCP protocol."""
        # Upload and process document
        document_id = await mcp_test_client.upload_test_document()
        
        # Trigger chapter detection
        response = await mcp_test_client.detect_chapters(
            document_id=document_id,
            options={"deep_analysis": True, "format_hints": ["academic"]}
        )
        
        assert response["status"] == "completed"
        chapters = response["chapters"]
        assert len(chapters) > 0
        
        # Verify chapter structure
        for chapter in chapters:
            assert all(key in chapter for key in ["id", "title", "level", "start_page"])
    
    @pytest.mark.e2e
    async def test_mcp_multi_expert_analysis(self, mcp_test_client):
        """Test multi-expert document analysis via MCP."""
        document_id = await mcp_test_client.upload_test_document()
        
        # Request multi-expert analysis
        analysis_request = {
            "document_id": document_id,
            "experts": ["claude-3.5", "gpt-4", "gemini-pro"],
            "analysis_type": "comprehensive",
            "include_chapters": True
        }
        
        response = await mcp_test_client.analyze_document(analysis_request)
        
        assert response["status"] == "success"
        assert len(response["expert_responses"]) == 3
        assert response["consensus_score"] > 0.7
        assert "aggregated_insights" in response
    
    @pytest.mark.e2e
    @pytest.mark.timeout(30)
    async def test_mcp_full_pipeline(self, mcp_test_client):
        """Test complete MCP pipeline from upload to results."""
        start_time = time.time()
        
        # 1. Upload document
        doc_id = await mcp_test_client.upload_test_document("complex_document.pdf")
        
        # 2. Detect chapters
        chapters = await mcp_test_client.detect_chapters(doc_id)
        
        # 3. Analyze with experts
        analysis = await mcp_test_client.analyze_document({
            "document_id": doc_id,
            "chapters": chapters,
            "experts": ["claude-3.5", "gpt-4"]
        })
        
        # 4. Generate summary
        summary = await mcp_test_client.generate_summary(doc_id, analysis)
        
        # Verify complete pipeline
        assert summary["status"] == "completed"
        assert "executive_summary" in summary
        assert "chapter_summaries" in summary
        assert len(summary["chapter_summaries"]) == len(chapters)
        
        # Performance check
        total_time = time.time() - start_time
        assert total_time < 30  # Should complete within 30 seconds


# ============================================================================
# 4. PERFORMANCE TESTS - Benchmarks
# ============================================================================

class TestPerformanceBenchmarks:
    """Performance testing and benchmarking suite."""
    
    @pytest.mark.performance
    @pytest.mark.benchmark
    def test_chapter_detection_speed(self, benchmark, large_document):
        """Benchmark chapter detection speed."""
        from src.document_processor.chapter_detector import ChapterDetector
        
        detector = ChapterDetector()
        
        # Benchmark the detection
        result = benchmark(detector.detect_chapters, large_document, format="markdown")
        
        # Performance assertions
        assert benchmark.stats["mean"] < 0.1  # Average under 100ms
        assert benchmark.stats["max"] < 0.5   # Max under 500ms
        assert len(result) > 0
    
    @pytest.mark.performance
    async def test_parser_throughput(self, performance_monitor):
        """Test parser throughput with various document sizes."""
        from src.document_processor import DocumentParser
        
        parser = DocumentParser()
        sizes = [1, 10, 100]  # MB
        
        results = {}
        for size in sizes:
            document = self.generate_document(size_mb=size)
            
            performance_monitor.start()
            await parser.parse(document)
            performance_monitor.stop()
            
            throughput = size / performance_monitor.metrics["duration"]
            results[f"{size}mb"] = throughput
        
        # Assert minimum throughput
        assert all(throughput > 10 for throughput in results.values())  # >10 MB/s
    
    @pytest.mark.performance
    def test_memory_usage_patterns(self, memory_profiler):
        """Test memory usage patterns during processing."""
        from src.document_processor import DocumentProcessor
        
        processor = DocumentProcessor()
        
        # Monitor memory during processing
        with memory_profiler:
            for i in range(100):
                doc = self.generate_document(size_mb=10)
                processor.process(doc)
                
                if i % 10 == 0:
                    memory_profiler.snapshot()
        
        # Analyze memory patterns
        assert memory_profiler.peak_memory_mb < 1000  # Less than 1GB peak
        assert memory_profiler.memory_growth_rate < 0.01  # Less than 1% growth
        assert memory_profiler.gc_collections > 0  # GC is working
    
    @pytest.mark.performance
    async def test_concurrent_processing_efficiency(self):
        """Test efficiency of concurrent document processing."""
        from src.document_processor import ConcurrentProcessor
        
        processor = ConcurrentProcessor(max_workers=10)
        documents = [self.generate_document(size_mb=1) for _ in range(100)]
        
        # Sequential baseline
        start = time.time()
        for doc in documents[:10]:
            await processor.process_single(doc)
        sequential_time = time.time() - start
        
        # Concurrent processing
        start = time.time()
        await processor.process_batch(documents)
        concurrent_time = time.time() - start
        
        # Calculate speedup
        speedup = (sequential_time * 10) / concurrent_time
        assert speedup > 5  # At least 5x speedup with 10 workers


# ============================================================================
# 5. SECURITY TESTS - Fuzzing & Penetration
# ============================================================================

class TestSecurityFuzzingPenetration:
    """Security testing including fuzzing and penetration tests."""
    
    @pytest.mark.security
    @pytest.mark.fuzz
    @given(document=st.binary(min_size=1, max_size=10000))
    def test_input_fuzzing(self, document):
        """Fuzz test document parser with random input."""
        from src.document_processor import SafeParser
        
        parser = SafeParser()
        
        # Parser should handle any input without crashing
        try:
            result = parser.parse_bytes(document)
            assert result["status"] in ["success", "error", "unsupported"]
        except Exception as e:
            # Only acceptable exceptions
            assert isinstance(e, (ValueError, UnsupportedFormatError))
    
    @pytest.mark.security
    async def test_sql_injection_prevention(self, db_connection):
        """Test SQL injection prevention in queries."""
        from src.database import DocumentRepository
        
        repo = DocumentRepository(db_connection)
        
        # Attempt SQL injection
        malicious_inputs = [
            "'; DROP TABLE documents; --",
            "1' OR '1'='1",
            "admin'--",
            "1; INSERT INTO users VALUES ('hacker', 'password')"
        ]
        
        for payload in malicious_inputs:
            # Should safely handle malicious input
            result = await repo.search_documents(query=payload)
            assert isinstance(result, list)  # Returns empty list, not error
            
            # Verify tables still exist
            tables = await db_connection.get_tables()
            assert "documents" in tables
    
    @pytest.mark.security
    def test_path_traversal_prevention(self, temp_dir):
        """Test path traversal attack prevention."""
        from src.document_processor import FileProcessor
        
        processor = FileProcessor(base_dir=temp_dir)
        
        # Attempt path traversal
        malicious_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "documents/../../../sensitive.txt",
            "/etc/shadow"
        ]
        
        for path in malicious_paths:
            with pytest.raises(SecurityError):
                processor.process_file(path)
    
    @pytest.mark.security
    async def test_api_authentication_bypass(self, api_client):
        """Test for authentication bypass vulnerabilities."""
        # Attempt various bypass techniques
        bypass_attempts = [
            {"headers": {}},  # No auth
            {"headers": {"Authorization": "Bearer invalid"}},  # Invalid token
            {"headers": {"Authorization": "Bearer null"}},  # Null token
            {"headers": {"X-Admin": "true"}},  # Header injection
            {"cookies": {"admin": "1"}},  # Cookie manipulation
        ]
        
        for attempt in bypass_attempts:
            response = await api_client.get("/api/admin/users", **attempt)
            assert response.status_code == 401  # Unauthorized
            assert "error" in response.json()
    
    @pytest.mark.security
    @pytest.mark.slow
    def test_cryptographic_weaknesses(self):
        """Test for cryptographic vulnerabilities."""
        from src.security import CryptoManager
        
        crypto = CryptoManager()
        
        # Test key generation
        key1 = crypto.generate_key()
        key2 = crypto.generate_key()
        assert key1 != key2  # Keys should be unique
        assert len(key1) >= 32  # Adequate key length
        
        # Test encryption randomness
        plaintext = b"sensitive data"
        cipher1 = crypto.encrypt(plaintext)
        cipher2 = crypto.encrypt(plaintext)
        assert cipher1 != cipher2  # Should use random IV/nonce
        
        # Test timing attacks
        valid_token = crypto.generate_token()
        invalid_token = "invalid" * 10
        
        times = []
        for token in [valid_token, invalid_token]:
            start = time.perf_counter()
            crypto.verify_token(token)
            times.append(time.perf_counter() - start)
        
        # Timing should be constant
        assert abs(times[0] - times[1]) < 0.001


# ============================================================================
# 6. LOAD TESTS - Concurrent Operations
# ============================================================================

class TestLoadConcurrentOperations:
    """Load testing for concurrent operations."""
    
    @pytest.mark.load
    async def test_concurrent_document_processing(self, load_generator):
        """Test system under concurrent document processing load."""
        from src.document_processor import LoadBalancedProcessor
        
        processor = LoadBalancedProcessor(max_concurrent=100)
        
        # Generate load pattern
        load_pattern = load_generator.generate_pattern(
            pattern="ramp",
            duration_seconds=60,
            peak_rps=1000
        )
        
        results = []
        errors = []
        
        async def process_document():
            try:
                doc = self.generate_random_document()
                result = await processor.process(doc)
                results.append(result)
            except Exception as e:
                errors.append(e)
        
        # Apply load
        await load_generator.apply_load(process_document, load_pattern)
        
        # Analyze results
        success_rate = len(results) / (len(results) + len(errors))
        avg_response_time = sum(r["processing_time"] for r in results) / len(results)
        
        assert success_rate > 0.99  # 99% success rate
        assert avg_response_time < 1.0  # Under 1 second average
        assert len(errors) < 10  # Less than 10 errors total
    
    @pytest.mark.load
    async def test_mcp_connection_pooling(self):
        """Test MCP connection pool under load."""
        from src.mcp import ConnectionPool
        
        pool = ConnectionPool(
            min_connections=10,
            max_connections=100,
            connection_timeout=5.0
        )
        
        # Simulate concurrent connection requests
        async def use_connection(duration=0.1):
            async with pool.acquire() as conn:
                await asyncio.sleep(duration)
                return await conn.execute("SELECT 1")
        
        # Create high concurrency
        tasks = []
        for _ in range(1000):
            tasks.append(use_connection(random.uniform(0.05, 0.2)))
        
        start = time.time()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        duration = time.time() - start
        
        # Verify pool behavior
        errors = [r for r in results if isinstance(r, Exception)]
        assert len(errors) == 0  # No connection errors
        assert pool.active_connections <= 100  # Respects max limit
        assert duration < 10  # Completes within 10 seconds
    
    @pytest.mark.load
    def test_memory_under_load(self, memory_monitor):
        """Test memory behavior under sustained load."""
        from src.document_processor import MemoryEfficientProcessor
        
        processor = MemoryEfficientProcessor()
        
        initial_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        # Process many documents
        for i in range(1000):
            doc = self.generate_document(size_mb=10)
            processor.process(doc)
            
            if i % 100 == 0:
                gc.collect()
                current_memory = psutil.Process().memory_info().rss / 1024 / 1024
                memory_growth = current_memory - initial_memory
                
                # Memory should stabilize
                assert memory_growth < 500  # Less than 500MB growth
        
        # Final memory check
        gc.collect()
        final_memory = psutil.Process().memory_info().rss / 1024 / 1024
        total_growth = final_memory - initial_memory
        assert total_growth < 200  # Should release most memory


# ============================================================================
# 7. REGRESSION TESTS - Prevention Suite
# ============================================================================

class TestRegressionPrevention:
    """Regression test suite to prevent feature/performance regressions."""
    
    @pytest.mark.regression
    def test_api_compatibility(self, previous_version_api, current_api):
        """Test API backward compatibility."""
        # Test all endpoints from previous version still work
        for endpoint in previous_version_api.get_endpoints():
            old_response = previous_version_api.call(endpoint)
            new_response = current_api.call(endpoint)
            
            # Same status codes
            assert old_response.status_code == new_response.status_code
            
            # Response structure compatibility
            if old_response.status_code == 200:
                old_keys = set(old_response.json().keys())
                new_keys = set(new_response.json().keys())
                
                # New version should have all old keys (can add new ones)
                assert old_keys.issubset(new_keys)
    
    @pytest.mark.regression
    def test_performance_regression(self, benchmark_history):
        """Test for performance regressions."""
        from src.document_processor import ChapterDetector
        
        detector = ChapterDetector()
        test_document = self.load_standard_test_document()
        
        # Current performance
        start = time.time()
        current_result = detector.detect_chapters(test_document)
        current_time = time.time() - start
        
        # Compare with historical baseline
        baseline_time = benchmark_history.get_baseline("chapter_detection")
        
        # Allow 10% degradation tolerance
        assert current_time <= baseline_time * 1.1
        
        # Update baseline if improved
        if current_time < baseline_time:
            benchmark_history.update_baseline("chapter_detection", current_time)
    
    @pytest.mark.regression
    def test_memory_leak_regression(self):
        """Test for memory leak regressions."""
        from src.document_processor import DocumentProcessor
        
        processor = DocumentProcessor()
        
        # Take initial snapshot
        gc.collect()
        initial_objects = len(gc.get_objects())
        
        # Process many documents
        for _ in range(100):
            doc = self.generate_document()
            processor.process(doc)
        
        # Force garbage collection
        gc.collect()
        final_objects = len(gc.get_objects())
        
        # Object count should stabilize
        object_growth = final_objects - initial_objects
        assert object_growth < 1000  # Reasonable growth limit
    
    @pytest.mark.regression
    async def test_integration_regression(self, integration_test_suite):
        """Run full integration regression suite."""
        # Run all integration tests from previous versions
        results = await integration_test_suite.run_all()
        
        failed_tests = [r for r in results if not r["passed"]]
        
        # Generate regression report
        if failed_tests:
            report = integration_test_suite.generate_regression_report(failed_tests)
            pytest.fail(f"Integration regression detected:\n{report}")


# ============================================================================
# Test Data Generation Utilities
# ============================================================================

class TestDataGenerators:
    """Utilities for generating test data."""
    
    @staticmethod
    def generate_document(size_mb: int = 1, format: str = "markdown") -> str:
        """Generate test document of specified size."""
        content_generators = {
            "markdown": TestDataGenerators._generate_markdown,
            "latex": TestDataGenerators._generate_latex,
            "html": TestDataGenerators._generate_html
        }
        
        generator = content_generators.get(format, TestDataGenerators._generate_markdown)
        return generator(size_mb)
    
    @staticmethod
    def _generate_markdown(size_mb: int) -> str:
        """Generate Markdown content."""
        content = []
        current_size = 0
        target_size = size_mb * 1024 * 1024
        
        chapter_num = 1
        while current_size < target_size:
            chapter = f"# Chapter {chapter_num}\n\n"
            chapter += f"This is the content of chapter {chapter_num}.\n\n"
            
            # Add sections
            for section in range(1, random.randint(3, 8)):
                chapter += f"## Section {chapter_num}.{section}\n\n"
                chapter += "Lorem ipsum dolor sit amet, " * random.randint(50, 200)
                chapter += "\n\n"
            
            content.append(chapter)
            current_size += len(chapter.encode('utf-8'))
            chapter_num += 1
        
        return "".join(content)
    
    @staticmethod
    def generate_load_pattern(pattern: str, duration: int, peak: int) -> List[int]:
        """Generate load pattern for testing."""
        patterns = {
            "steady": lambda t: peak,
            "ramp": lambda t: int(peak * t / duration),
            "spike": lambda t: peak if duration/3 < t < 2*duration/3 else peak/10,
            "wave": lambda t: int(peak * (1 + math.sin(t * 2 * math.pi / duration)) / 2)
        }
        
        generator = patterns.get(pattern, patterns["steady"])
        return [generator(t) for t in range(duration)]


# ============================================================================
# Pytest Configuration
# ============================================================================

def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "e2e: End-to-end tests")
    config.addinivalue_line("markers", "performance: Performance tests")
    config.addinivalue_line("markers", "security: Security tests")
    config.addinivalue_line("markers", "load: Load tests")
    config.addinivalue_line("markers", "regression: Regression tests")
    config.addinivalue_line("markers", "fuzz: Fuzzing tests")
    config.addinivalue_line("markers", "slow: Slow running tests")
    config.addinivalue_line("markers", "benchmark: Benchmark tests")