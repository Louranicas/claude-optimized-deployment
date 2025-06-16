#!/usr/bin/env python3
"""
Comprehensive test suite for chapter detection algorithms
Tests various document types and edge cases
"""

import pytest
import json
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from synthex.chapter_detection_engine import (
    UniversalChapterDetector,
    DocumentType,
    TraditionalBookDetector,
    AcademicPaperDetector,
    MarkdownDetector,
    TechnicalDocDetector
)
from synthex.advanced_text_patterns import (
    AdvancedChapterDetector,
    EdgeCaseHandler,
    UnicodeNormalizer,
    AmbiguityResolver
)


class TestDocumentSamples:
    """Test document samples for various formats"""
    
    TRADITIONAL_BOOK = """
PART I: THE BEGINNING

Chapter 1: The Dark Night
It was a dark and stormy night when everything began. The old mansion 
creaked in the wind, and shadows danced across the walls.

Chapter 2: The Mystery Deepens
As dawn broke, new clues emerged. Detective Sarah Chen examined the scene
with careful attention to detail.

Chapter III: Revelations
The truth was more complex than anyone had imagined. Ancient secrets
were about to be revealed.

PART II: THE MIDDLE

Chapter 4: The Chase
Through the winding streets of the old city, the pursuit continued.
Time was running out.

Chapter 5: Confrontation
Face to face at last, the hunter and the hunted met in the abandoned
warehouse district.
"""

    ACADEMIC_PAPER = """
Abstract

This paper presents a comprehensive analysis of natural language processing
techniques for document structure detection. We propose a novel approach
that combines pattern matching with machine learning.

1. Introduction

Natural language processing has evolved significantly in recent years.
Document structure detection remains a challenging problem in the field.

1.1. Background

Previous research has focused primarily on simple pattern matching
approaches with limited success in complex documents.

1.2. Motivation

The need for accurate document structure detection has grown with the
increasing volume of digital documents.

2. Methodology

Our approach combines multiple techniques to achieve better accuracy.

2.1. Data Collection

We collected a diverse dataset of documents from various sources
including academic papers, books, and technical documentation.

2.2. Feature Extraction

Key features were extracted using both statistical and linguistic methods.

3. Results

Our experiments show significant improvements over baseline methods.

4. Conclusion

The proposed approach demonstrates superior performance across different
document types and languages.

References

[1] Smith, J. (2023). Advanced Text Processing. Journal of AI Research.
[2] Jones, M. (2022). Document Structure Analysis. Computational Linguistics.
"""

    MARKDOWN_DOC = """
# Complete Developer Guide

## 1. Getting Started

### 1.1. Installation

First, install the required dependencies:

```bash
pip install chapter-detector
```

### 1.2. Basic Usage

Here's a simple example:

```python
from chapter_detector import detect_chapters
result = detect_chapters(content)
```

## 2. Advanced Features

### 2.1. Custom Patterns

You can define custom detection patterns:

#### 2.1.1. Pattern Syntax

Patterns use regular expressions with special markers.

#### 2.1.2. Configuration Options

Several configuration options are available:

- Pattern matching sensitivity
- Hierarchy validation rules
- Output format preferences

### 2.2. Performance Optimization

For large documents, consider these optimizations:

- Chunked processing
- Parallel execution
- Result caching

## 3. API Reference

### 3.1. Core Classes

#### ChapterDetector

Main detection class with the following methods:

- `detect(content)` - Detect chapter structure
- `validate(structure)` - Validate detected structure
- `export(format)` - Export results in various formats

### 3.2. Utility Functions

Helper functions for common tasks.

## 4. Examples

Complete examples for different use cases.

### 4.1. Book Processing

Example for processing traditional books.

### 4.2. Academic Papers

Example for academic document processing.
"""

    TECHNICAL_DOC = """
1. System Architecture

The chapter detection system consists of multiple components working together
to provide accurate structure recognition.

1.1. Core Components

The main components include pattern matchers, hierarchy builders, and validators.

1.2. Data Flow

Data flows through the system in the following stages:
- Input processing
- Pattern matching
- Structure building
- Validation and enhancement

2. API Documentation

2.1. Classes

Class ChapterDetector

The main detection class provides the following functionality:

Function detect_chapters(content: str) -> Dict[str, Any]

Detects chapter structure in the given content.

Parameters:
- content: The document content as a string

Returns:
- Dictionary containing detected structure and metadata

Function validate_structure(structure: List[Dict]) -> bool

Validates the detected structure for consistency.

Parameters:
- structure: List of detected structure elements

Returns:
- Boolean indicating whether structure is valid

2.2. Configuration

Configuration options can be set through the config module.

Example:

```python
from chapter_detector import config
config.set_sensitivity(0.8)
config.enable_unicode_normalization(True)
```

3. Error Handling

The system provides comprehensive error handling for various edge cases.

Note: Always validate input before processing large documents.

Warning: Unicode normalization may affect performance with very large files.

4. Performance Considerations

For optimal performance, consider the following guidelines:

4.1. Memory Usage

Large documents may require chunked processing to manage memory usage.

4.2. Processing Time

Complex patterns may increase processing time significantly.
"""

    LEGAL_DOCUMENT = """
TITLE I: GENERAL PROVISIONS

Article 1: Scope and Application

Section 1.1 - Definitions

§ 1.1.1 Terms used in this document shall have the following meanings:
(a) "Document" means any written or electronic text
(b) "Structure" means the hierarchical organization of content

§ 1.1.2 Additional definitions may be found in Appendix A.

Section 1.2 - Applicability

This framework applies to all document types specified in Schedule 1.

Article 2: Implementation Requirements

Section 2.1 - Mandatory Provisions

All systems implementing this framework must:
1. Support Unicode normalization
2. Provide hierarchy validation
3. Handle edge cases gracefully

Section 2.2 - Optional Features

Systems may optionally provide:
- Custom pattern definition
- Performance optimization
- Export capabilities

TITLE II: TECHNICAL SPECIFICATIONS

Article 3: Pattern Matching

Section 3.1 - Basic Patterns

Pattern matching follows established conventions.

Article 4: Validation Rules

Section 4.1 - Hierarchy Validation

Structure hierarchy must be logically consistent.
"""

    MIXED_FORMAT = """
# Mixed Format Document

This document contains multiple formatting styles to test edge case handling.

## Chapter 1: Traditional Start

Regular paragraph text follows here.

### Section 1.1: Subsection

More content.

<h2>HTML Section</h2>

<p>This is HTML formatted content within the document.</p>

<h3>HTML Subsection</h3>

Back to markdown:

## Chapter 2: LaTeX Integration

Some normal text, then:

\\section{LaTeX Section}

This is LaTeX formatted content.

\\subsection{LaTeX Subsection}

More LaTeX content here.

## Chapter 3: Mixed Numbering

3.1. Numbered subsection
3.2. Another numbered subsection

A. Alphabetic section
B. Another alphabetic section

Back to regular formatting:

## Chapter 4: Unicode Examples

① First item with circled number
② Second item with circled number

Ⅰ. Roman numeral section
Ⅱ. Another Roman section

## Chapter 5: Edge Cases

Chapter with "quotes" and special—dashes

§ 5.1 Legal-style section marker

5.1.a) Mixed numbering style
5.1.b) Another mixed style
"""

    EPUB_NAV = """<?xml version="1.0" encoding="UTF-8"?>
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:epub="http://www.idpf.org/2007/ops">
<head>
    <title>Navigation</title>
</head>
<body>
    <nav epub:type="toc">
        <h1>Table of Contents</h1>
        <ol>
            <li><a href="chapter1.xhtml">Chapter 1: The Beginning</a></li>
            <li><a href="chapter2.xhtml">Chapter 2: The Journey</a>
                <ol>
                    <li><a href="chapter2.xhtml#section1">Section 2.1: Preparation</a></li>
                    <li><a href="chapter2.xhtml#section2">Section 2.2: Departure</a></li>
                </ol>
            </li>
            <li><a href="chapter3.xhtml">Chapter 3: The Destination</a></li>
        </ol>
    </nav>
</body>
</html>"""

    POETRY = """
The Canterbury Tales

Prologue

Whan that Aprille with his shoures soote
The droghte of March hath perced to the roote...

Canto I: The Knight's Tale

In ancient times, there lived a duke named Theseus
Who ruled Athens with wisdom and justice...

Canto II: The Miller's Tale

A carpenter once lived in Oxford town
With his young wife and a student lodger...

Canto III: The Reeve's Tale

At Trumpington, not far from Cambridge,
There stands a bridge where waters flow...

Epilogue

Thus ends our collection of tales told
By pilgrims on their journey to Canterbury...
"""


class TestChapterDetection:
    """Test suite for chapter detection functionality"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.detector = UniversalChapterDetector()
        self.advanced_detector = AdvancedChapterDetector()
    
    def test_traditional_book_detection(self):
        """Test detection of traditional book structure"""
        result = self.detector.detect_chapters(TestDocumentSamples.TRADITIONAL_BOOK)
        
        # Check document type detection
        assert result['document_type'] == DocumentType.TRADITIONAL_BOOK.value
        
        # Check structure detection
        structure = result['structure']
        assert len(structure) >= 2  # Should detect both parts
        
        # Check part detection
        parts = [elem for elem in structure if elem['type'] == 'part']
        assert len(parts) == 2
        assert parts[0]['number'] == 'I'
        assert parts[1]['number'] == 'II'
        
        # Check chapter detection within parts
        part1_chapters = parts[0]['children']
        assert len(part1_chapters) >= 2
        
        # Verify chapter numbering
        chapter_numbers = [ch['number'] for ch in part1_chapters if ch['type'] == 'chapter']
        assert '1' in chapter_numbers
        assert '2' in chapter_numbers
    
    def test_academic_paper_detection(self):
        """Test detection of academic paper structure"""
        result = self.detector.detect_chapters(TestDocumentSamples.ACADEMIC_PAPER)
        
        # Check document type
        assert result['document_type'] == DocumentType.ACADEMIC_PAPER.value
        
        # Check for standard academic sections
        structure = result['structure']
        section_types = [elem['type'] for elem in structure]
        
        expected_sections = ['abstract', 'introduction', 'methodology', 'results', 'conclusion']
        for section in expected_sections:
            assert section in section_types or any(section in st for st in section_types)
        
        # Check numbered sections
        numbered_sections = [elem for elem in structure if elem['number'] is not None]
        assert len(numbered_sections) >= 3  # Should find numbered sections
        
        # Check subsection hierarchy
        intro_section = next((elem for elem in structure if 'introduction' in elem['type']), None)
        if intro_section and intro_section['children']:
            assert len(intro_section['children']) >= 1  # Should have subsections
    
    def test_markdown_detection(self):
        """Test detection of Markdown structure"""
        result = self.detector.detect_chapters(TestDocumentSamples.MARKDOWN_DOC)
        
        # Check document type
        assert result['document_type'] == DocumentType.MARKDOWN.value
        
        # Check header levels
        structure = result['structure']
        assert len(structure) >= 1
        
        # Check H1 detection
        h1_elements = [elem for elem in structure if elem['type'] == 'h1']
        assert len(h1_elements) >= 1
        
        # Check hierarchy
        main_section = structure[0]
        assert len(main_section['children']) >= 2  # Should have subsections
        
        # Check numbered sections
        numbered_elements = [elem for elem in structure 
                           if elem.get('number') is not None]
        assert len(numbered_elements) >= 2
    
    def test_technical_doc_detection(self):
        """Test detection of technical documentation structure"""
        result = self.detector.detect_chapters(TestDocumentSamples.TECHNICAL_DOC)
        
        # Check document type
        assert result['document_type'] == DocumentType.TECHNICAL_DOCUMENTATION.value
        
        # Check numbered sections
        structure = result['structure']
        numbered_sections = [elem for elem in structure if elem['number'] is not None]
        assert len(numbered_sections) >= 3
        
        # Check API documentation elements
        api_elements = [elem for elem in self._flatten_structure(structure) 
                       if elem['type'] in ['class', 'function', 'parameters']]
        assert len(api_elements) >= 2
        
        # Check code examples
        example_elements = [elem for elem in self._flatten_structure(structure) 
                          if elem['type'] == 'example']
        assert len(example_elements) >= 1
    
    def test_edge_case_handling(self):
        """Test handling of edge cases and special formats"""
        # Test legal document
        legal_result = self.detector.detect_chapters(TestDocumentSamples.LEGAL_DOCUMENT)
        
        # Should detect articles and sections
        flat_structure = self._flatten_structure(legal_result['structure'])
        article_elements = [elem for elem in flat_structure if elem['type'] == 'article']
        assert len(article_elements) >= 2
        
        # Test edge case detection
        edge_cases = self.advanced_detector.edge_case_handler.detect_edge_cases(
            TestDocumentSamples.LEGAL_DOCUMENT
        )
        assert len(edge_cases) > 0
        
        # Should detect legal patterns
        legal_patterns = [case for case in edge_cases if case['category'] == 'legal_documents']
        assert len(legal_patterns) > 0
    
    def test_mixed_format_detection(self):
        """Test detection in documents with mixed formatting"""
        result = self.detector.detect_chapters(TestDocumentSamples.MIXED_FORMAT)
        
        # Should detect basic structure despite mixed formats
        structure = result['structure']
        assert len(structure) >= 1
        
        # Test format region detection
        format_regions = self.advanced_detector.multi_format_parser.detect_mixed_formats(
            TestDocumentSamples.MIXED_FORMAT
        )
        
        # Should detect HTML and LaTeX regions
        assert 'html' in format_regions or 'latex' in format_regions
    
    def test_unicode_normalization(self):
        """Test Unicode character handling"""
        normalizer = UnicodeNormalizer()
        
        # Test special dash normalization
        text_with_dashes = "Chapter 1—The Beginning"
        normalized = normalizer.normalize(text_with_dashes)
        assert '—' in normalized  # Should preserve em dash
        
        # Test special numbering detection
        unicode_text = "① First chapter"
        special_num = normalizer.detect_special_numbering(unicode_text)
        assert special_num is not None
        assert special_num['type'] == 'circled'
        assert special_num['number'] == 1
    
    def test_ambiguity_resolution(self):
        """Test ambiguity resolution"""
        resolver = AmbiguityResolver()
        
        # Create ambiguous candidates
        candidates = [
            {'confidence': 0.7, 'numbering_system': 'arabic', 'number': '1'},
            {'confidence': 0.6, 'numbering_system': 'roman', 'number': 'I'},
            {'confidence': 0.8, 'numbering_system': 'arabic', 'number': '2'}
        ]
        
        context = {'prev_numbering_system': 'arabic', 'prev_number': '1'}
        
        best = resolver.resolve_ambiguity(candidates, context)
        assert best is not None
        assert best['number'] == '2'  # Should pick sequential number
    
    def test_hierarchy_validation(self):
        """Test hierarchy validation"""
        analyzer = self.advanced_detector.hierarchy_analyzer
        
        # Valid hierarchy
        valid_elements = [
            {'level': 1, 'type': 'chapter', 'number': '1'},
            {'level': 2, 'type': 'section', 'number': '1.1'},
            {'level': 2, 'type': 'section', 'number': '1.2'},
            {'level': 1, 'type': 'chapter', 'number': '2'}
        ]
        
        is_valid, issues = analyzer.validate_hierarchy(valid_elements)
        assert is_valid
        assert len(issues) == 0
        
        # Invalid hierarchy (orphaned element)
        invalid_elements = [
            {'level': 1, 'type': 'chapter', 'number': '1'},
            {'level': 3, 'type': 'subsection', 'number': '1.1.1'},  # Orphaned
            {'level': 1, 'type': 'chapter', 'number': '2'}
        ]
        
        is_valid, issues = analyzer.validate_hierarchy(invalid_elements)
        assert not is_valid
        assert len(issues) > 0
    
    def test_table_of_contents_generation(self):
        """Test table of contents generation"""
        result = self.detector.detect_chapters(TestDocumentSamples.TRADITIONAL_BOOK)
        
        toc = result['table_of_contents']
        assert len(toc) > 0
        
        # Check TOC structure
        for entry in toc:
            assert 'level' in entry
            assert 'type' in entry
            assert 'title' in entry
        
        # Check numbering in TOC
        numbered_entries = [entry for entry in toc if entry.get('number')]
        assert len(numbered_entries) > 0
    
    def test_statistics_calculation(self):
        """Test statistics calculation"""
        result = self.detector.detect_chapters(TestDocumentSamples.TRADITIONAL_BOOK)
        
        stats = result['statistics']
        assert 'total_chapters' in stats
        assert 'total_sections' in stats
        assert 'total_parts' in stats
        assert stats['total_chapters'] >= 4  # Should find at least 4 chapters
        assert stats['total_parts'] >= 2     # Should find 2 parts
    
    def test_export_functionality(self):
        """Test structure export in different formats"""
        result = self.detector.detect_chapters(TestDocumentSamples.ACADEMIC_PAPER)
        
        # Test JSON export
        json_export = self.detector.export_structure(result, 'json')
        assert json_export is not None
        
        # Verify it's valid JSON
        parsed = json.loads(json_export)
        assert 'document_type' in parsed
        
        # Test Markdown export
        md_export = self.detector.export_structure(result, 'markdown')
        assert md_export is not None
        assert '# Document Structure' in md_export
        assert '## Table of Contents' in md_export
    
    def test_performance_with_large_document(self):
        """Test performance with larger documents"""
        # Create a large document by repeating patterns
        large_doc = ""
        for i in range(100):
            large_doc += f"\nChapter {i+1}: Test Chapter {i+1}\n\n"
            large_doc += "This is content for the chapter. " * 50
            large_doc += f"\n\nSection {i+1}.1: First Section\n\n"
            large_doc += "Section content here. " * 30
            large_doc += f"\n\nSection {i+1}.2: Second Section\n\n"
            large_doc += "More section content. " * 30
        
        # Should complete within reasonable time
        import time
        start_time = time.time()
        
        result = self.detector.detect_chapters(large_doc)
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        # Should process within 10 seconds (adjust based on system)
        assert processing_time < 10.0
        
        # Should detect reasonable number of chapters
        stats = result['statistics']
        assert stats['total_chapters'] >= 50  # Should find most chapters
    
    def test_error_handling(self):
        """Test error handling for malformed input"""
        # Test empty input
        result = self.detector.detect_chapters("")
        assert result is not None
        assert result['statistics']['total_chapters'] == 0
        
        # Test malformed input
        malformed = "Random text\nwith no structure\nat all\njust words"
        result = self.detector.detect_chapters(malformed)
        assert result is not None
        # Should still return valid structure, even if empty
    
    def test_custom_patterns(self):
        """Test custom pattern detection"""
        # Test with custom document type
        custom_doc = """
        Scene 1: The Opening
        
        CHARACTER enters stage left.
        
        DIALOGUE: Hello, world!
        
        Scene 2: The Conflict
        
        CHARACTER 2 enters.
        
        DIALOGUE: We meet again!
        """
        
        # Should still detect some structure
        result = self.detector.detect_chapters(custom_doc)
        assert result is not None
    
    def _flatten_structure(self, structure):
        """Helper method to flatten hierarchical structure"""
        flat = []
        
        def flatten(elements):
            for element in elements:
                flat.append(element)
                if 'children' in element:
                    flatten(element['children'])
        
        flatten(structure)
        return flat


class TestSpecializedDetectors:
    """Test individual detector components"""
    
    def test_traditional_book_detector(self):
        """Test traditional book detector specifically"""
        detector = TraditionalBookDetector()
        structure = detector.detect_structure(TestDocumentSamples.TRADITIONAL_BOOK)
        
        assert len(structure) >= 2  # Parts
        
        # Check part numbering
        part_numbers = [elem.number for elem in structure if elem.type == 'part']
        assert 'I' in part_numbers
        assert 'II' in part_numbers
    
    def test_academic_detector(self):
        """Test academic paper detector specifically"""
        detector = AcademicPaperDetector()
        structure = detector.detect_structure(TestDocumentSamples.ACADEMIC_PAPER)
        
        # Should find academic sections
        types = [elem.type for elem in structure]
        assert 'abstract' in types
        assert 'introduction' in types or 'section' in types
    
    def test_markdown_detector(self):
        """Test Markdown detector specifically"""
        detector = MarkdownDetector()
        structure = detector.detect_structure(TestDocumentSamples.MARKDOWN_DOC)
        
        # Should find headers
        header_types = [elem.type for elem in structure]
        assert any(ht.startswith('h') for ht in header_types)
    
    def test_technical_detector(self):
        """Test technical documentation detector specifically"""
        detector = TechnicalDocDetector()
        structure = detector.detect_structure(TestDocumentSamples.TECHNICAL_DOC)
        
        # Should find numbered sections
        numbered = [elem for elem in structure if elem.number is not None]
        assert len(numbered) >= 2


def run_comprehensive_tests():
    """Run all tests and generate report"""
    import pytest
    
    # Run tests with verbose output
    pytest.main([__file__, '-v', '--tb=short'])


if __name__ == "__main__":
    run_comprehensive_tests()