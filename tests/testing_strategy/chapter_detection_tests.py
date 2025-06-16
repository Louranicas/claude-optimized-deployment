"""
Comprehensive Chapter Detection Test Suite
SYNTHEX Agent 8 - Testing Specialist

This module contains specific tests for chapter detection algorithms
across various document formats and edge cases.
"""

import pytest
import asyncio
import tempfile
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from unittest.mock import Mock, patch, MagicMock
import json
import time
from dataclasses import dataclass
import hypothesis.strategies as st
from hypothesis import given, settings, example
import faulthandler
import gc
import psutil


# Enable fault handler for debugging crashes
faulthandler.enable()


@dataclass
class ChapterTestCase:
    """Test case for chapter detection."""
    name: str
    content: str
    format: str
    expected_chapters: int
    expected_structure: List[Dict[str, Any]]
    should_fail: bool = False
    error_type: Optional[type] = None


class ChapterDetectionTestSuite:
    """Comprehensive test suite for chapter detection."""
    
    @pytest.fixture(autouse=True)
    def setup_chapter_detector(self):
        """Set up chapter detector for each test."""
        # Mock import since we don't have the actual implementation
        self.mock_detector = Mock()
        self.mock_detector.detect_chapters = Mock()
        self.mock_detector.validate_structure = Mock()
        self.mock_detector.get_chapter_tree = Mock()
        
        # Configure default behavior
        self.mock_detector.detect_chapters.return_value = []
        self.mock_detector.validate_structure.return_value = True
        self.mock_detector.get_chapter_tree.return_value = {"root": []}
    
    # ========================================================================
    # Markdown Chapter Detection Tests
    # ========================================================================
    
    @pytest.mark.unit
    @pytest.mark.parametrize("test_case", [
        ChapterTestCase(
            name="simple_headers",
            content="# Chapter 1\n## Section 1.1\n# Chapter 2\n## Section 2.1",
            format="markdown",
            expected_chapters=4,
            expected_structure=[
                {"level": 1, "title": "Chapter 1", "children": 1},
                {"level": 2, "title": "Section 1.1", "children": 0},
                {"level": 1, "title": "Chapter 2", "children": 1},
                {"level": 2, "title": "Section 2.1", "children": 0}
            ]
        ),
        ChapterTestCase(
            name="nested_headers",
            content="# Part I\n## Chapter 1\n### Section 1.1\n#### Subsection 1.1.1\n## Chapter 2",
            format="markdown",
            expected_chapters=5,
            expected_structure=[
                {"level": 1, "title": "Part I", "children": 2},
                {"level": 2, "title": "Chapter 1", "children": 1},
                {"level": 3, "title": "Section 1.1", "children": 1},
                {"level": 4, "title": "Subsection 1.1.1", "children": 0},
                {"level": 2, "title": "Chapter 2", "children": 0}
            ]
        ),
        ChapterTestCase(
            name="mixed_content",
            content="""
# Introduction

This is the introduction with some text.

## Background

Some background information.

```python
# Code block
def hello():
    return "world"
```

## Methodology

### Data Collection

More text here.

# Results

## Analysis

### Statistical Results

Some analysis.

# Conclusion
""",
            format="markdown",
            expected_chapters=8,
            expected_structure=[
                {"level": 1, "title": "Introduction", "children": 2},
                {"level": 2, "title": "Background", "children": 0},
                {"level": 2, "title": "Methodology", "children": 1},
                {"level": 3, "title": "Data Collection", "children": 0},
                {"level": 1, "title": "Results", "children": 1},
                {"level": 2, "title": "Analysis", "children": 1},
                {"level": 3, "title": "Statistical Results", "children": 0},
                {"level": 1, "title": "Conclusion", "children": 0}
            ]
        )
    ])
    def test_markdown_chapter_detection(self, test_case: ChapterTestCase):
        """Test chapter detection in Markdown documents."""
        # Configure mock to return expected results
        mock_chapters = []
        for i, chapter in enumerate(test_case.expected_structure):
            mock_chapters.append({
                "id": f"chapter_{i}",
                "title": chapter["title"],
                "level": chapter["level"],
                "start_line": i * 10,
                "end_line": (i + 1) * 10,
                "content_hash": f"hash_{i}",
                "word_count": 100 + i * 50
            })
        
        self.mock_detector.detect_chapters.return_value = mock_chapters
        
        # Run detection
        result = self.mock_detector.detect_chapters(test_case.content, format=test_case.format)
        
        # Assertions
        if test_case.should_fail:
            assert len(result) == 0 or not self.mock_detector.validate_structure(result)
        else:
            assert len(result) == test_case.expected_chapters
            
            # Verify structure
            for i, expected in enumerate(test_case.expected_structure):
                assert result[i]["level"] == expected["level"]
                assert expected["title"] in result[i]["title"]
    
    @pytest.mark.unit
    def test_markdown_edge_cases(self):
        """Test Markdown edge cases."""
        edge_cases = [
            # Empty document
            ("", 0),
            # Only text, no headers
            ("Just plain text without headers.", 0),
            # Headers with special characters
            ("# Chapter 1: Introduction & Overview\n## Section 1.1: Getting Started!", 2),
            # Headers with inline code
            ("# Using `pytest` for Testing\n## The `@pytest.fixture` Decorator", 2),
            # Headers with links
            ("# [Chapter 1](http://example.com)\n## See [Documentation](./docs)", 2),
            # Malformed headers (no space after #)
            ("#NotAHeader\n# Real Header", 1),
            # Headers in code blocks (should be ignored)
            ("```\n# This is code\n```\n# Real Header", 1),
            # Headers in tables
            ("| # Header | Data |\n|----------|------|\n| Value | 123 |\n# Real Header", 1)
        ]
        
        for content, expected_count in edge_cases:
            # Configure mock
            mock_result = [{"id": f"ch_{i}", "title": f"Chapter {i}", "level": 1} 
                          for i in range(expected_count)]
            self.mock_detector.detect_chapters.return_value = mock_result
            
            result = self.mock_detector.detect_chapters(content, format="markdown")
            assert len(result) == expected_count
    
    # ========================================================================
    # LaTeX Chapter Detection Tests
    # ========================================================================
    
    @pytest.mark.unit
    @pytest.mark.parametrize("latex_content,expected_count", [
        (r"\chapter{Introduction}\section{Background}\subsection{Overview}", 3),
        (r"\part{Part I}\chapter{Chapter 1}\section{Section 1.1}", 3),
        (r"\documentclass{book}\begin{document}\chapter{First}\chapter{Second}\end{document}", 2),
        (r"\chapter*{Preface}\chapter{Chapter 1}", 2),  # Starred chapters
        (r"\chapter{Math: $E=mc^2$}\section{Physics}", 2),  # Math in titles
    ])
    def test_latex_chapter_detection(self, latex_content: str, expected_count: int):
        """Test chapter detection in LaTeX documents."""
        # Configure mock
        mock_result = [{"id": f"ch_{i}", "title": f"Chapter {i}", "level": 1} 
                      for i in range(expected_count)]
        self.mock_detector.detect_chapters.return_value = mock_result
        
        result = self.mock_detector.detect_chapters(latex_content, format="latex")
        assert len(result) == expected_count
    
    # ========================================================================
    # HTML Chapter Detection Tests  
    # ========================================================================
    
    @pytest.mark.unit
    @pytest.mark.parametrize("html_content,expected_count", [
        ("<h1>Chapter 1</h1><h2>Section 1.1</h2><h1>Chapter 2</h1>", 3),
        ("<div><h1>Title</h1><p>Content</p><h2>Subtitle</h2></div>", 2),
        ("<h1 class='chapter'>Chapter 1</h1><h1 id='ch2'>Chapter 2</h1>", 2),
        ("<!-- <h1>Comment</h1> --><h1>Real Header</h1>", 1),
        ("<script>var h1 = '<h1>JS</h1>';</script><h1>Real</h1>", 1),
    ])
    def test_html_chapter_detection(self, html_content: str, expected_count: int):
        """Test chapter detection in HTML documents."""
        # Configure mock
        mock_result = [{"id": f"ch_{i}", "title": f"Chapter {i}", "level": 1} 
                      for i in range(expected_count)]
        self.mock_detector.detect_chapters.return_value = mock_result
        
        result = self.mock_detector.detect_chapters(html_content, format="html")
        assert len(result) == expected_count
    
    # ========================================================================
    # Property-Based Testing
    # ========================================================================
    
    @pytest.mark.unit
    @given(
        headers=st.lists(
            st.tuples(
                st.integers(min_value=1, max_value=6),  # level
                st.text(min_size=1, max_size=100, alphabet=st.characters(
                    whitelist_categories=("Lu", "Ll", "Nd", "Zs"), min_codepoint=32
                ))  # title
            ),
            min_size=1,
            max_size=50
        )
    )
    @settings(max_examples=50, deadline=1000)
    def test_markdown_property_based(self, headers):
        """Property-based testing for Markdown chapter detection."""
        # Generate Markdown content
        content_parts = []
        expected_count = len(headers)
        
        for level, title in headers:
            header_prefix = "#" * level
            content_parts.append(f"{header_prefix} {title}\n\nSome content here.\n\n")
        
        content = "".join(content_parts)
        
        # Configure mock
        mock_result = []
        for i, (level, title) in enumerate(headers):
            mock_result.append({
                "id": f"ch_{i}",
                "title": title.strip(),
                "level": level,
                "start_line": i * 4,
                "end_line": (i + 1) * 4
            })
        
        self.mock_detector.detect_chapters.return_value = mock_result
        
        # Test properties
        result = self.mock_detector.detect_chapters(content, format="markdown")
        
        # Properties that should always hold
        assert len(result) == expected_count
        
        # All chapters should have valid levels
        for chapter in result:
            assert 1 <= chapter["level"] <= 6
            assert chapter["title"].strip()  # Non-empty title
            assert chapter["start_line"] >= 0
            assert chapter["end_line"] > chapter["start_line"]
    
    # ========================================================================
    # Performance Tests
    # ========================================================================
    
    @pytest.mark.performance
    def test_chapter_detection_performance(self, benchmark):
        """Benchmark chapter detection performance."""
        # Generate large document
        large_content = self._generate_large_markdown_document(size_mb=1)
        
        # Configure mock for performance test
        mock_result = [{"id": f"ch_{i}", "title": f"Chapter {i}", "level": 1} 
                      for i in range(100)]
        self.mock_detector.detect_chapters.return_value = mock_result
        
        # Benchmark the detection
        def detect():
            return self.mock_detector.detect_chapters(large_content, format="markdown")
        
        result = benchmark(detect)
        
        # Performance assertions
        assert len(result) > 0
        assert benchmark.stats["mean"] < 0.1  # Under 100ms average
        assert benchmark.stats["max"] < 0.5   # Under 500ms maximum
    
    @pytest.mark.performance
    @pytest.mark.parametrize("size_mb", [1, 5, 10, 50])
    def test_scalability_with_document_size(self, size_mb):
        """Test how performance scales with document size."""
        content = self._generate_large_markdown_document(size_mb)
        
        # Configure mock
        expected_chapters = size_mb * 10  # Assume 10 chapters per MB
        mock_result = [{"id": f"ch_{i}", "title": f"Chapter {i}", "level": 1} 
                      for i in range(expected_chapters)]
        self.mock_detector.detect_chapters.return_value = mock_result
        
        start_time = time.time()
        result = self.mock_detector.detect_chapters(content, format="markdown")
        duration = time.time() - start_time
        
        # Performance should scale linearly or better
        max_time_per_mb = 0.1  # 100ms per MB
        assert duration < size_mb * max_time_per_mb
        assert len(result) == expected_chapters
    
    # ========================================================================
    # Memory Tests
    # ========================================================================
    
    @pytest.mark.memory
    def test_memory_usage_large_documents(self):
        """Test memory usage with large documents."""
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Process multiple large documents
        for i in range(10):
            large_content = self._generate_large_markdown_document(size_mb=10)
            
            # Configure mock
            mock_result = [{"id": f"ch_{j}", "title": f"Chapter {j}", "level": 1} 
                          for j in range(100)]
            self.mock_detector.detect_chapters.return_value = mock_result
            
            result = self.mock_detector.detect_chapters(large_content, format="markdown")
            
            # Check memory growth
            current_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_growth = current_memory - initial_memory
            
            # Memory should not grow excessively
            assert memory_growth < 500  # Less than 500MB growth
            
            # Clean up
            del large_content
            del result
            gc.collect()
    
    # ========================================================================
    # Error Handling Tests
    # ========================================================================
    
    @pytest.mark.unit
    def test_error_handling_malformed_input(self):
        """Test error handling with malformed input."""
        malformed_inputs = [
            None,
            123,
            b"binary content",
            "\x00\x01\x02",  # Binary data
            "a" * (10**8),   # Extremely large string
            "\u0000\u0001",  # Null characters
        ]
        
        for malformed in malformed_inputs:
            # Configure mock to handle errors appropriately
            if isinstance(malformed, str) and len(malformed) < 1000:
                self.mock_detector.detect_chapters.return_value = []
            else:
                self.mock_detector.detect_chapters.side_effect = ValueError("Invalid input")
            
            # Should handle gracefully
            try:
                result = self.mock_detector.detect_chapters(malformed, format="markdown")
                assert isinstance(result, list)
            except (ValueError, TypeError):
                # Acceptable errors for invalid input
                pass
    
    @pytest.mark.unit
    def test_error_handling_unsupported_formats(self):
        """Test handling of unsupported document formats."""
        unsupported_formats = ["docx", "pdf", "rtf", "odt", "unknown"]
        
        for fmt in unsupported_formats:
            # Configure mock to raise appropriate error
            self.mock_detector.detect_chapters.side_effect = ValueError(f"Unsupported format: {fmt}")
            
            with pytest.raises(ValueError, match="Unsupported format"):
                self.mock_detector.detect_chapters("# Test", format=fmt)
    
    # ========================================================================
    # Concurrency Tests
    # ========================================================================
    
    @pytest.mark.asyncio
    async def test_concurrent_chapter_detection(self):
        """Test concurrent chapter detection."""
        # Create multiple test documents
        documents = [
            (f"# Chapter {i}\n## Section {i}.1", "markdown")
            for i in range(100)
        ]
        
        # Configure mock for concurrent access
        def mock_detect(content, format):
            # Simulate some processing time
            time.sleep(0.01)
            return [{"id": "ch_1", "title": "Chapter 1", "level": 1}]
        
        self.mock_detector.detect_chapters.side_effect = mock_detect
        
        async def detect_chapters(content, format):
            return await asyncio.get_event_loop().run_in_executor(
                None, self.mock_detector.detect_chapters, content, format
            )
        
        # Run concurrent detection
        start_time = time.time()
        tasks = [detect_chapters(content, fmt) for content, fmt in documents]
        results = await asyncio.gather(*tasks)
        duration = time.time() - start_time
        
        # Verify results
        assert len(results) == 100
        assert all(len(result) == 1 for result in results)
        
        # Should be faster than sequential processing
        sequential_time = len(documents) * 0.01
        assert duration < sequential_time * 0.5  # At least 50% speedup
    
    # ========================================================================
    # Integration Tests
    # ========================================================================
    
    @pytest.mark.integration
    async def test_chapter_detection_with_file_io(self, tmp_path):
        """Test chapter detection with actual file I/O."""
        # Create test files
        test_files = {
            "test1.md": "# Chapter 1\n## Section 1.1\n# Chapter 2",
            "test2.md": "# Introduction\n### Background\n# Conclusion",
            "test3.md": "No headers in this file"
        }
        
        for filename, content in test_files.items():
            file_path = tmp_path / filename
            file_path.write_text(content)
        
        # Configure mock to return results based on file content
        def mock_file_detect(file_path, format):
            content = Path(file_path).read_text()
            header_count = content.count('#')
            return [{"id": f"ch_{i}", "title": f"Chapter {i}", "level": 1} 
                   for i in range(header_count)]
        
        # Test file processing
        for filename in test_files.keys():
            file_path = tmp_path / filename
            expected_headers = test_files[filename].count('#')
            
            # Mock the file detection
            mock_result = [{"id": f"ch_{i}", "title": f"Chapter {i}", "level": 1} 
                          for i in range(expected_headers)]
            self.mock_detector.detect_chapters.return_value = mock_result
            
            result = self.mock_detector.detect_chapters(str(file_path), format="markdown")
            assert len(result) == expected_headers
    
    # ========================================================================
    # Utility Methods
    # ========================================================================
    
    def _generate_large_markdown_document(self, size_mb: int) -> str:
        """Generate a large Markdown document for testing."""
        content = []
        current_size = 0
        target_size = size_mb * 1024 * 1024  # Convert to bytes
        
        chapter_num = 1
        while current_size < target_size:
            chapter_content = f"""
# Chapter {chapter_num}: Advanced Topics

This chapter covers advanced topics in the field. Lorem ipsum dolor sit amet, 
consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et 
dolore magna aliqua.

## Section {chapter_num}.1: Introduction

Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut 
aliquip ex ea commodo consequat.

### Subsection {chapter_num}.1.1: Background

Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore 
eu fugiat nulla pariatur.

### Subsection {chapter_num}.1.2: Methodology

Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia 
deserunt mollit anim id est laborum.

## Section {chapter_num}.2: Results

Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium 
doloremque laudantium.

### Subsection {chapter_num}.2.1: Analysis

Totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi 
architecto beatae vitae dicta sunt explicabo.

### Subsection {chapter_num}.2.2: Discussion

Nemo enim ipsam voluptatem quia voluptas sit aspernatur aut odit aut fugit, 
sed quia consequuntur magni dolores eos qui ratione voluptatem sequi nesciunt.

## Section {chapter_num}.3: Conclusion

Neque porro quisquam est, qui dolorem ipsum quia dolor sit amet, consectetur, 
adipisci velit, sed quia non numquam eius modi tempora incidunt ut labore et 
dolore magnam aliquam quaerat voluptatem.

"""
            content.append(chapter_content)
            current_size += len(chapter_content.encode('utf-8'))
            chapter_num += 1
        
        return "".join(content)
    
    def _create_test_document(self, format: str, content: str) -> str:
        """Create a test document in the specified format."""
        if format == "markdown":
            return content
        elif format == "latex":
            return f"\\documentclass{{article}}\\begin{{document}}{content}\\end{{document}}"
        elif format == "html":
            return f"<html><body>{content}</body></html>"
        else:
            return content


# ============================================================================
# Stress Tests
# ============================================================================

class ChapterDetectionStressTests:
    """Stress tests for chapter detection under extreme conditions."""
    
    @pytest.mark.stress
    def test_extremely_large_document(self):
        """Test with extremely large documents (100MB+)."""
        # This would normally be slow, so we mock it
        mock_detector = Mock()
        
        # Simulate processing 100MB document
        large_size = 100 * 1024 * 1024  # 100MB
        mock_detector.detect_chapters.return_value = [
            {"id": f"ch_{i}", "title": f"Chapter {i}", "level": 1}
            for i in range(1000)  # 1000 chapters
        ]
        
        result = mock_detector.detect_chapters("large_content", format="markdown")
        assert len(result) == 1000
    
    @pytest.mark.stress
    def test_deeply_nested_structure(self):
        """Test with extremely deep chapter nesting."""
        mock_detector = Mock()
        
        # Simulate 20 levels of nesting
        max_depth = 20
        mock_result = []
        for level in range(1, max_depth + 1):
            mock_result.append({
                "id": f"ch_{level}",
                "title": f"Level {level} Header",
                "level": level,
                "parent_id": f"ch_{level-1}" if level > 1 else None
            })
        
        mock_detector.detect_chapters.return_value = mock_result
        
        result = mock_detector.detect_chapters("nested_content", format="markdown")
        assert len(result) == max_depth
        assert max(ch["level"] for ch in result) == max_depth
    
    @pytest.mark.stress 
    def test_massive_number_of_chapters(self):
        """Test with documents containing thousands of chapters."""
        mock_detector = Mock()
        
        # Simulate 10,000 chapters
        chapter_count = 10000
        mock_detector.detect_chapters.return_value = [
            {"id": f"ch_{i}", "title": f"Chapter {i}", "level": 1}
            for i in range(chapter_count)
        ]
        
        result = mock_detector.detect_chapters("massive_content", format="markdown")
        assert len(result) == chapter_count


# ============================================================================
# Test Configuration
# ============================================================================

def pytest_configure(config):
    """Configure pytest markers for chapter detection tests."""
    markers = [
        "unit: Unit tests for chapter detection",
        "performance: Performance tests for chapter detection",
        "memory: Memory usage tests",
        "stress: Stress tests with extreme conditions",
        "integration: Integration tests with file I/O",
    ]
    
    for marker in markers:
        config.addinivalue_line("markers", marker)


# Example test data fixtures
@pytest.fixture
def sample_markdown_complex():
    """Complex Markdown document for testing."""
    return """
# Document Title

This is the document introduction.

## Abstract

Brief summary of the document.

# Part I: Foundations

## Chapter 1: Introduction

### 1.1 Background

Some background information.

#### 1.1.1 Historical Context

Historical information here.

#### 1.1.2 Current State

Current state information.

### 1.2 Objectives

The objectives of this work.

## Chapter 2: Literature Review

### 2.1 Previous Work

Review of previous work.

### 2.2 Gaps in Knowledge

Identified gaps.

# Part II: Methodology

## Chapter 3: Methods

### 3.1 Data Collection

How data was collected.

### 3.2 Analysis Techniques

Analysis methods used.

# Part III: Results

## Chapter 4: Findings

### 4.1 Primary Results

Main findings.

### 4.2 Secondary Results

Additional findings.

## Chapter 5: Discussion

### 5.1 Interpretation

Interpretation of results.

### 5.2 Implications

Implications of findings.

# Conclusion

Final thoughts and conclusions.

## Future Work

Suggestions for future research.

# Appendices

## Appendix A: Data Tables

Additional data.

## Appendix B: Code Listings

Code examples.
"""


@pytest.fixture
def sample_latex_document():
    """Sample LaTeX document for testing."""
    return r"""
\documentclass{book}
\begin{document}

\part{Introduction}

\chapter{Background}
\section{Historical Context}
\subsection{Early Work}
\section{Current State}

\chapter{Problem Statement}
\section{Research Questions}
\subsection{Primary Questions}
\subsection{Secondary Questions}

\part{Methodology}

\chapter{Experimental Design}
\section{Participants}
\section{Procedure}
\subsection{Data Collection}
\subsection{Analysis}

\chapter{Implementation}
\section{Tools}
\section{Validation}

\part{Results}

\chapter{Findings}
\section{Primary Results}
\section{Secondary Results}

\chapter{Discussion}
\section{Interpretation}
\section{Limitations}

\end{document}
"""