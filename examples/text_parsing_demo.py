#!/usr/bin/env python3
"""
SYNTHEX Text Parser Demonstration

This script demonstrates the capabilities of the SYNTHEX text parsing system
including various file formats, performance optimization, and error handling.
"""

import sys
import time
import tempfile
from pathlib import Path
from typing import List, Dict, Any

# Add the src directory to the path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from synthex.text_parser import (
    UnifiedTextParser, PDFParser, DOCXParser, PlainTextParser,
    EPUBParser, HTMLParser, MarkdownParser, TextParsingError
)


def create_sample_files(temp_dir: Path) -> Dict[str, Path]:
    """Create sample files for demonstration"""
    files = {}
    
    # Create a text file
    text_file = temp_dir / "sample.txt"
    text_content = """This is a sample text file for demonstration.
It contains multiple lines of text.
Each line will be processed by the text parser.

The parser can handle various encodings and chunk sizes.
It also supports streaming for large files."""
    text_file.write_text(text_content)
    files['text'] = text_file
    
    # Create an HTML file
    html_file = temp_dir / "sample.html"
    html_content = """<!DOCTYPE html>
<html>
<head>
    <title>Sample HTML Document</title>
    <meta name="author" content="SYNTHEX Demo">
    <meta name="description" content="Sample HTML for text parsing demo">
</head>
<body>
    <h1>Main Heading</h1>
    <p>This is a paragraph with <strong>bold</strong> and <em>italic</em> text.</p>
    
    <h2>Section 1</h2>
    <p>Sample content in section 1.</p>
    <ul>
        <li>List item 1</li>
        <li>List item 2</li>
        <li>List item 3</li>
    </ul>
    
    <h2>Section 2</h2>
    <p>More content in section 2.</p>
    <table>
        <tr><th>Column 1</th><th>Column 2</th></tr>
        <tr><td>Data 1</td><td>Data 2</td></tr>
        <tr><td>Data 3</td><td>Data 4</td></tr>
    </table>
</body>
</html>"""
    html_file.write_text(html_content)
    files['html'] = html_file
    
    # Create a Markdown file
    md_file = temp_dir / "sample.md"
    md_content = """---
title: Sample Markdown Document
author: SYNTHEX Demo
date: 2024-01-01
tags: [demo, markdown, parsing]
---

# Sample Markdown Document

This is a sample markdown document for demonstration purposes.

## Introduction

The SYNTHEX text parser can handle markdown files with:

- **Bold text**
- *Italic text*
- `Code snippets`
- [Links](https://example.com)

## Code Example

```python
def hello_world():
    print("Hello, World!")
```

## Lists

### Ordered List
1. First item
2. Second item
3. Third item

### Unordered List
- Item A
- Item B
- Item C

## Tables

| Feature | Support | Notes |
|---------|---------|-------|
| Parsing | ✅ | Full support |
| Metadata | ✅ | Including frontmatter |
| Chunking | ✅ | Memory efficient |

## Conclusion

This demonstrates the markdown parsing capabilities of SYNTHEX.
"""
    md_file.write_text(md_content)
    files['markdown'] = md_file
    
    # Create a large text file for performance testing
    large_file = temp_dir / "large_sample.txt"
    with open(large_file, 'w') as f:
        for i in range(10000):
            f.write(f"Line {i+1}: This is a test line with some content to demonstrate chunking.\n")
    files['large_text'] = large_file
    
    return files


def demonstrate_basic_parsing(parser: UnifiedTextParser, files: Dict[str, Path]):
    """Demonstrate basic parsing functionality"""
    print("=" * 60)
    print("BASIC PARSING DEMONSTRATION")
    print("=" * 60)
    
    for file_type, file_path in files.items():
        if file_type == 'large_text':  # Skip large file for basic demo
            continue
            
        print(f"\n📄 Parsing {file_type.upper()} file: {file_path.name}")
        print("-" * 40)
        
        try:
            # Parse the file
            chunks = list(parser.parse(file_path))
            
            print(f"Number of chunks: {len(chunks)}")
            
            for i, chunk in enumerate(chunks):
                print(f"\nChunk {i+1}:")
                print(f"  Type: {chunk['type']}")
                print(f"  Length: {len(chunk['text'])} characters")
                
                # Show preview of content
                preview = chunk['text'][:200]
                if len(chunk['text']) > 200:
                    preview += "..."
                print(f"  Preview: {repr(preview)}")
                
                # Show additional metadata if available
                for key, value in chunk.items():
                    if key not in ['text', 'type']:
                        print(f"  {key}: {value}")
                        
        except Exception as e:
            print(f"❌ Error parsing {file_type}: {e}")


def demonstrate_metadata_extraction(parser: UnifiedTextParser, files: Dict[str, Path]):
    """Demonstrate metadata extraction"""
    print("\n" + "=" * 60)
    print("METADATA EXTRACTION DEMONSTRATION")
    print("=" * 60)
    
    for file_type, file_path in files.items():
        if file_type == 'large_text':  # Skip large file
            continue
            
        print(f"\n📋 Extracting metadata from {file_type.upper()}: {file_path.name}")
        print("-" * 40)
        
        try:
            metadata = parser._get_parser_class(file_path)().extract_metadata(file_path)
            
            for key, value in metadata.items():
                print(f"  {key}: {value}")
                
        except Exception as e:
            print(f"❌ Error extracting metadata: {e}")


def demonstrate_performance_features(parser: UnifiedTextParser, files: Dict[str, Path]):
    """Demonstrate performance and memory efficiency"""
    print("\n" + "=" * 60)
    print("PERFORMANCE FEATURES DEMONSTRATION")
    print("=" * 60)
    
    large_file = files['large_text']
    
    print(f"\n⚡ Testing chunking with large file: {large_file.name}")
    print(f"File size: {large_file.stat().st_size / 1024:.1f} KB")
    print("-" * 40)
    
    # Test different chunk sizes
    chunk_sizes = [1024, 10240, 102400]  # 1KB, 10KB, 100KB
    
    for chunk_size in chunk_sizes:
        print(f"\nTesting with {chunk_size//1024}KB chunks:")
        
        # Create parser with specific chunk size
        test_parser = PlainTextParser(chunk_size=chunk_size)
        
        start_time = time.time()
        chunks = list(test_parser.parse(large_file))
        end_time = time.time()
        
        print(f"  Chunks created: {len(chunks)}")
        print(f"  Processing time: {end_time - start_time:.3f} seconds")
        print(f"  Average chunk size: {sum(len(c['text']) for c in chunks) / len(chunks):.0f} chars")


def demonstrate_batch_processing(parser: UnifiedTextParser, files: Dict[str, Path]):
    """Demonstrate batch processing capabilities"""
    print("\n" + "=" * 60)
    print("BATCH PROCESSING DEMONSTRATION")
    print("=" * 60)
    
    file_list = [files['text'], files['html'], files['markdown']]
    
    print(f"\n🔄 Processing {len(file_list)} files in batch")
    print("-" * 40)
    
    # Sequential processing
    print("\nSequential processing:")
    start_time = time.time()
    seq_results = list(parser.parse_batch(file_list, parallel=False))
    seq_time = time.time() - start_time
    
    print(f"  Processed {len(seq_results)} files in {seq_time:.3f} seconds")
    
    # Parallel processing
    print("\nParallel processing:")
    start_time = time.time()
    par_results = list(parser.parse_batch(file_list, parallel=True))
    par_time = time.time() - start_time
    
    print(f"  Processed {len(par_results)} files in {par_time:.3f} seconds")
    
    if seq_time > 0 and par_time > 0:
        speedup = seq_time / par_time
        print(f"  Speedup: {speedup:.2f}x")
    
    # Show results summary
    print(f"\nResults summary:")
    for result in par_results:
        if 'error' in result:
            print(f"  ❌ {result['file']}: {result['error']}")
        else:
            chunk_count = len([result['chunk']]) if 'chunk' in result else 0
            print(f"  ✅ {Path(result['file']).name}: {chunk_count} chunks")


def demonstrate_caching(temp_dir: Path, files: Dict[str, Path]):
    """Demonstrate caching functionality"""
    print("\n" + "=" * 60)
    print("CACHING DEMONSTRATION")
    print("=" * 60)
    
    cache_dir = temp_dir / "cache"
    parser_with_cache = UnifiedTextParser(cache_dir=cache_dir)
    
    test_file = files['text']
    
    print(f"\n💾 Testing cache with file: {test_file.name}")
    print("-" * 40)
    
    # First parse - creates cache
    print("First parse (creates cache):")
    start_time = time.time()
    results1 = list(parser_with_cache.parse(test_file, use_cache=True))
    first_time = time.time() - start_time
    print(f"  Time: {first_time:.3f} seconds")
    print(f"  Chunks: {len(results1)}")
    
    # Check cache
    cache_files = list(cache_dir.glob("*.json"))
    print(f"  Cache files created: {len(cache_files)}")
    
    # Second parse - uses cache
    print("\nSecond parse (uses cache):")
    start_time = time.time()
    results2 = list(parser_with_cache.parse(test_file, use_cache=True))
    second_time = time.time() - start_time
    print(f"  Time: {second_time:.3f} seconds")
    print(f"  Chunks: {len(results2)}")
    
    if first_time > 0 and second_time > 0:
        speedup = first_time / second_time
        print(f"  Cache speedup: {speedup:.2f}x")


def demonstrate_error_handling(temp_dir: Path):
    """Demonstrate error handling"""
    print("\n" + "=" * 60)
    print("ERROR HANDLING DEMONSTRATION")
    print("=" * 60)
    
    parser = UnifiedTextParser()
    
    # Test non-existent file
    print("\n🚫 Testing non-existent file:")
    try:
        list(parser.parse(temp_dir / "nonexistent.txt"))
    except TextParsingError as e:
        print(f"  ✅ Caught expected error: {e}")
    
    # Test invalid encoding
    print("\n🚫 Testing file with encoding issues:")
    bad_file = temp_dir / "bad_encoding.txt"
    with open(bad_file, 'wb') as f:
        f.write(b'\xff\xfe\x00Invalid encoding test')
    
    try:
        # This should still work due to fallback encoding handling
        results = list(parser.parse(bad_file))
        print(f"  ✅ Handled encoding gracefully: {len(results)} chunks")
    except Exception as e:
        print(f"  ⚠️  Encoding error: {e}")


def main():
    """Main demonstration function"""
    print("🚀 SYNTHEX Text Parser Demonstration")
    print("This demo showcases the capabilities of the SYNTHEX text parsing system.")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create sample files
        print("\n📁 Creating sample files...")
        files = create_sample_files(temp_path)
        print(f"Created {len(files)} sample files")
        
        # Initialize parser
        parser = UnifiedTextParser(cache_dir=temp_path / "cache")
        
        # Run demonstrations
        demonstrate_basic_parsing(parser, files)
        demonstrate_metadata_extraction(parser, files)
        demonstrate_performance_features(parser, files)
        demonstrate_batch_processing(parser, files)
        demonstrate_caching(temp_path, files)
        demonstrate_error_handling(temp_path)
        
        print("\n" + "=" * 60)
        print("✅ DEMONSTRATION COMPLETE")
        print("=" * 60)
        print("\nThe SYNTHEX text parser successfully demonstrated:")
        print("  • Multi-format support (TXT, HTML, Markdown)")
        print("  • Memory-efficient chunking")
        print("  • Metadata extraction")
        print("  • Performance optimization")
        print("  • Batch processing with parallelization")
        print("  • Intelligent caching")
        print("  • Robust error handling")
        print("\nFor production use, install the required dependencies:")
        print("  pip install -r requirements-text-parsing.txt")


if __name__ == "__main__":
    main()