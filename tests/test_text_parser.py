"""
Tests for SYNTHEX text parsing module
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import json

from src.synthex.text_parser import (
    UnifiedTextParser, PDFParser, DOCXParser, PlainTextParser,
    EPUBParser, HTMLParser, MarkdownParser, TextParsingError
)


class TestPlainTextParser:
    """Test plain text parsing functionality"""
    
    def test_parse_simple_text(self, tmp_path):
        """Test parsing a simple text file"""
        # Create test file
        test_file = tmp_path / "test.txt"
        test_content = "Line 1\nLine 2\nLine 3\n"
        test_file.write_text(test_content)
        
        parser = PlainTextParser()
        results = list(parser.parse(test_file))
        
        assert len(results) == 1
        assert results[0]['text'] == test_content
        assert results[0]['type'] == 'text_chunk'
        assert 'encoding' in results[0]
        
    def test_parse_large_text_chunks(self, tmp_path):
        """Test chunking of large text files"""
        # Create large test file
        test_file = tmp_path / "large.txt"
        content = "Line content\n" * 1000  # Create large content
        test_file.write_text(content)
        
        parser = PlainTextParser(chunk_size=1000)  # Small chunk size
        results = list(parser.parse(test_file))
        
        assert len(results) > 1  # Should be chunked
        for result in results:
            assert len(result['text'].encode('utf-8')) <= 1000 + 100  # Some tolerance
            
    def test_encoding_detection(self, tmp_path):
        """Test encoding detection with different encodings"""
        test_file = tmp_path / "encoded.txt"
        
        # Test UTF-8
        test_file.write_text("Test content", encoding='utf-8')
        parser = PlainTextParser()
        
        encoding = parser._detect_encoding(test_file)
        assert encoding == 'utf-8'
        
    def test_extract_metadata(self, tmp_path):
        """Test metadata extraction"""
        test_file = tmp_path / "test.txt"
        test_file.write_text("Test content")
        
        parser = PlainTextParser()
        metadata = parser.extract_metadata(test_file)
        
        assert metadata['format'] == 'text'
        assert 'size' in metadata
        assert 'encoding' in metadata


class TestPDFParser:
    """Test PDF parsing functionality"""
    
    @patch('src.synthex.text_parser.fitz')
    def test_parse_with_pymupdf(self, mock_fitz, tmp_path):
        """Test PDF parsing with PyMuPDF backend"""
        # Mock PyMuPDF objects
        mock_doc = Mock()
        mock_page = Mock()
        mock_page.get_text.return_value = "Test PDF content"
        mock_doc.__len__.return_value = 1
        mock_doc.__getitem__.return_value = mock_page
        mock_doc.__iter__.return_value = iter([mock_page])
        mock_fitz.open.return_value = mock_doc
        
        test_file = tmp_path / "test.pdf"
        test_file.write_bytes(b"fake pdf content")
        
        parser = PDFParser(backend='pymupdf')
        results = list(parser.parse(test_file))
        
        assert len(results) == 1
        assert results[0]['text'] == "Test PDF content"
        assert results[0]['type'] == 'pdf_page'
        assert results[0]['page'] == 1
        
    def test_backend_detection(self, tmp_path):
        """Test automatic backend detection"""
        test_file = tmp_path / "test.pdf"
        test_file.write_bytes(b"fake pdf content")
        
        parser = PDFParser(backend='auto')
        
        # Test file size based detection
        backend = parser._detect_optimal_backend(test_file)
        assert backend in ['pymupdf', 'pdfplumber', 'pypdf2']
        
    def test_invalid_backend(self, tmp_path):
        """Test handling of invalid backend"""
        test_file = tmp_path / "test.pdf"
        test_file.write_bytes(b"fake pdf content")
        
        parser = PDFParser(backend='invalid')
        
        with pytest.raises(TextParsingError):
            list(parser.parse(test_file))


class TestEPUBParser:
    """Test EPUB parsing functionality"""
    
    @patch('src.synthex.text_parser.epub')
    @patch('src.synthex.text_parser.ebooklib')
    def test_parse_epub(self, mock_ebooklib, mock_epub, tmp_path):
        """Test EPUB parsing"""
        # Mock EPUB objects
        mock_book = Mock()
        mock_item = Mock()
        mock_item.get_type.return_value = mock_ebooklib.ITEM_DOCUMENT
        mock_item.get_name.return_value = "chapter1.html"
        mock_item.get_id.return_value = "ch1"
        mock_item.get_content.return_value = b"<html><body>Chapter content</body></html>"
        mock_book.get_items.return_value = [mock_item]
        mock_epub.read_epub.return_value = mock_book
        
        test_file = tmp_path / "test.epub"
        test_file.write_bytes(b"fake epub content")
        
        parser = EPUBParser()
        results = list(parser.parse(test_file))
        
        assert len(results) == 1
        assert results[0]['chapter'] == "chapter1.html"
        assert results[0]['type'] == 'epub_chapter'
        assert "Chapter content" in results[0]['text']


class TestHTMLParser:
    """Test HTML parsing functionality"""
    
    def test_parse_html(self, tmp_path):
        """Test HTML parsing"""
        test_file = tmp_path / "test.html"
        html_content = """
        <html>
        <head><title>Test Page</title></head>
        <body>
            <h1>Main Heading</h1>
            <p>This is a paragraph.</p>
            <div>Another section</div>
        </body>
        </html>
        """
        test_file.write_text(html_content)
        
        parser = HTMLParser()
        results = list(parser.parse(test_file))
        
        assert len(results) == 1
        text = results[0]['text']
        assert "Main Heading" in text
        assert "This is a paragraph." in text
        assert results[0]['type'] == 'html_content'
        
    def test_html_chunking(self, tmp_path):
        """Test HTML content chunking"""
        test_file = tmp_path / "large.html"
        # Create large HTML content
        large_content = "<html><body>" + "<p>Large content</p>" * 1000 + "</body></html>"
        test_file.write_text(large_content)
        
        parser = HTMLParser(chunk_size=1000)
        results = list(parser.parse(test_file))
        
        assert len(results) > 1  # Should be chunked
        
    def test_extract_html_metadata(self, tmp_path):
        """Test HTML metadata extraction"""
        test_file = tmp_path / "test.html"
        html_content = """
        <html>
        <head>
            <title>Test Page Title</title>
            <meta name="author" content="Test Author">
            <meta name="description" content="Test description">
        </head>
        <body>Content</body>
        </html>
        """
        test_file.write_text(html_content)
        
        parser = HTMLParser()
        metadata = parser.extract_metadata(test_file)
        
        assert metadata['format'] == 'html'
        assert metadata['title'] == 'Test Page Title'
        assert metadata['author'] == 'Test Author'
        assert metadata['description'] == 'Test description'


class TestMarkdownParser:
    """Test Markdown parsing functionality"""
    
    def test_parse_markdown_sections(self, tmp_path):
        """Test Markdown parsing by sections"""
        test_file = tmp_path / "test.md"
        markdown_content = """# Main Title

This is the introduction.

## Section 1

Content of section 1.

## Section 2

Content of section 2.
"""
        test_file.write_text(markdown_content)
        
        parser = MarkdownParser()
        results = list(parser.parse(test_file))
        
        # Should parse into sections based on headings
        assert len(results) >= 1
        
        # Check that headings are captured
        headings = [r.get('heading', '') for r in results]
        assert any('Main Title' in h for h in headings)
        
    def test_markdown_frontmatter(self, tmp_path):
        """Test YAML frontmatter extraction"""
        test_file = tmp_path / "frontmatter.md"
        markdown_content = """---
title: Test Document
author: Test Author
date: 2024-01-01
---

# Content

This is the main content.
"""
        test_file.write_text(markdown_content)
        
        with patch('yaml.safe_load') as mock_yaml:
            mock_yaml.return_value = {
                'title': 'Test Document',
                'author': 'Test Author',
                'date': '2024-01-01'
            }
            
            parser = MarkdownParser()
            metadata = parser.extract_metadata(test_file)
            
            assert metadata['title'] == 'Test Document'
            assert metadata['author'] == 'Test Author'


class TestUnifiedTextParser:
    """Test unified parser functionality"""
    
    def test_format_detection(self, tmp_path):
        """Test automatic format detection"""
        parser = UnifiedTextParser()
        
        # Test PDF detection
        pdf_file = tmp_path / "test.pdf"
        pdf_file.write_bytes(b"fake content")
        parser_class = parser._get_parser_class(pdf_file)
        assert parser_class == PDFParser
        
        # Test text detection
        txt_file = tmp_path / "test.txt"
        txt_file.write_text("content")
        parser_class = parser._get_parser_class(txt_file)
        assert parser_class == PlainTextParser
        
        # Test HTML detection
        html_file = tmp_path / "test.html"
        html_file.write_text("<html></html>")
        parser_class = parser._get_parser_class(html_file)
        assert parser_class == HTMLParser
        
    def test_cache_functionality(self, tmp_path):
        """Test caching functionality"""
        cache_dir = tmp_path / "cache"
        parser = UnifiedTextParser(cache_dir=cache_dir)
        
        test_file = tmp_path / "test.txt"
        test_file.write_text("Test content")
        
        # First parse - should create cache
        results1 = list(parser.parse(test_file, use_cache=True))
        assert len(results1) == 1
        
        # Check cache was created
        assert len(list(cache_dir.glob("*.json"))) == 1
        
        # Second parse - should use cache
        with patch.object(PlainTextParser, 'parse') as mock_parse:
            results2 = list(parser.parse(test_file, use_cache=True))
            mock_parse.assert_not_called()  # Should not parse again
            
    def test_batch_processing_sequential(self, tmp_path):
        """Test sequential batch processing"""
        parser = UnifiedTextParser()
        
        # Create multiple test files
        files = []
        for i in range(3):
            file_path = tmp_path / f"test_{i}.txt"
            file_path.write_text(f"Content {i}")
            files.append(file_path)
            
        results = list(parser.parse_batch(files, parallel=False))
        
        assert len(results) == 3
        for result in results:
            assert 'file' in result
            assert 'chunk' in result
            
    @patch('src.synthex.text_parser.ProcessPoolExecutor')
    def test_batch_processing_parallel(self, mock_executor, tmp_path):
        """Test parallel batch processing"""
        # Mock the executor
        mock_future = Mock()
        mock_future.result.return_value = [{'text': 'content', 'type': 'test'}]
        mock_executor.return_value.__enter__.return_value.submit.return_value = mock_future
        
        parser = UnifiedTextParser(max_workers=2)
        
        files = [tmp_path / f"test_{i}.txt" for i in range(2)]
        for file_path in files:
            file_path.write_text("content")
            
        results = list(parser.parse_batch(files, parallel=True))
        
        assert len(results) == 2
        
    def test_error_handling(self, tmp_path):
        """Test error handling for invalid files"""
        parser = UnifiedTextParser()
        
        # Test non-existent file
        with pytest.raises(TextParsingError):
            list(parser.parse(tmp_path / "nonexistent.txt"))
            
    def test_missing_dependencies(self, tmp_path):
        """Test handling of missing optional dependencies"""
        test_file = tmp_path / "test.pdf"
        test_file.write_bytes(b"fake pdf")
        
        with patch('src.synthex.text_parser.fitz', None):
            parser = PDFParser(backend='pymupdf')
            with pytest.raises(TextParsingError, match="PyMuPDF not installed"):
                list(parser.parse(test_file))


@pytest.fixture
def sample_files(tmp_path):
    """Create sample files for testing"""
    files = {}
    
    # Text file
    text_file = tmp_path / "sample.txt"
    text_file.write_text("This is a sample text file.\nWith multiple lines.")
    files['text'] = text_file
    
    # HTML file
    html_file = tmp_path / "sample.html"
    html_file.write_text("""
    <html>
    <head><title>Sample HTML</title></head>
    <body><p>Sample content</p></body>
    </html>
    """)
    files['html'] = html_file
    
    # Markdown file
    md_file = tmp_path / "sample.md"
    md_file.write_text("""# Sample Markdown

This is a sample markdown file.

## Section

With some content.
""")
    files['markdown'] = md_file
    
    return files


class TestIntegration:
    """Integration tests for the text parser"""
    
    def test_unified_parser_integration(self, sample_files):
        """Test unified parser with different file types"""
        parser = UnifiedTextParser()
        
        # Test each file type
        for file_type, file_path in sample_files.items():
            results = list(parser.parse(file_path))
            assert len(results) >= 1
            assert all('text' in result for result in results)
            assert all('type' in result for result in results)
            
    def test_metadata_extraction_integration(self, sample_files):
        """Test metadata extraction for different formats"""
        parsers = {
            'text': PlainTextParser(),
            'html': HTMLParser(),
            'markdown': MarkdownParser()
        }
        
        for file_type, file_path in sample_files.items():
            if file_type in parsers:
                parser = parsers[file_type]
                metadata = parser.extract_metadata(file_path)
                assert 'format' in metadata
                assert metadata['format'] == file_type
                
    def test_performance_monitoring(self, sample_files):
        """Test that parsing completes within reasonable time"""
        import time
        
        parser = UnifiedTextParser()
        
        for file_path in sample_files.values():
            start_time = time.time()
            results = list(parser.parse(file_path))
            end_time = time.time()
            
            # Should complete within 1 second for small files
            assert end_time - start_time < 1.0
            assert len(results) >= 1