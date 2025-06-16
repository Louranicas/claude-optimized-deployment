#!/usr/bin/env python3
"""
SYNTHEX Chapter Detection Demo
Demonstrates robust chapter detection algorithms across various formats
"""

import sys
import json
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich.progress import Progress, SpinnerColumn, TextColumn

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from synthex.chapter_detection_engine import UniversalChapterDetector, DocumentType
from synthex.advanced_text_patterns import AdvancedChapterDetector

console = Console()


def demo_traditional_book():
    """Demonstrate traditional book detection"""
    console.print("\n[bold blue]📚 Traditional Book Detection Demo[/bold blue]")
    
    book_content = """
PART I: THE MYSTERY BEGINS

Chapter 1: A Dark and Stormy Night
It was indeed a dark and stormy night when Professor Margaret Chen 
received the mysterious package. Inside, ancient symbols glowed with 
an otherworldly light.

Chapter 2: The First Clue
The symbols led to a hidden chamber beneath the university library. 
What Margaret found there would change everything she thought she 
knew about reality.

Chapter III: Ancient Secrets
The chamber contained artifacts from a civilization that shouldn't 
have existed. Each piece told a story of knowledge beyond human 
understanding.

PART II: THE REVELATION

Chapter 4: The Truth Unveiled
As Margaret decoded the symbols, a terrifying truth emerged. The 
ancient civilization had left a warning about the future.

Chapter 5: Race Against Time
With only days remaining, Margaret must find a way to prevent the 
catastrophe foretold by the ancient texts.
"""
    
    detector = UniversalChapterDetector()
    result = detector.detect_chapters(book_content)
    
    # Display results
    _display_detection_results(result, "Traditional Book")
    
    return result


def demo_academic_paper():
    """Demonstrate academic paper detection"""
    console.print("\n[bold green]🎓 Academic Paper Detection Demo[/bold green]")
    
    paper_content = """
Abstract

This paper presents a novel approach to automated document structure 
detection using advanced pattern recognition algorithms. We demonstrate 
significant improvements over existing methods across multiple document types.

1. Introduction

Document structure detection is a fundamental problem in natural language 
processing and information retrieval. Traditional approaches have relied 
on simple pattern matching with limited success.

1.1. Problem Statement

Current methods fail to handle the complexity and variability found in 
real-world documents, particularly those with mixed formatting styles.

1.2. Our Contribution

We propose a hybrid approach that combines rule-based pattern matching 
with machine learning techniques to achieve robust structure detection.

2. Related Work

Previous research in this area can be broadly categorized into three 
approaches: rule-based, statistical, and hybrid methods.

2.1. Rule-Based Approaches

Early work focused on manually crafted rules for specific document types.

2.2. Statistical Methods

Recent advances have employed machine learning for pattern recognition.

3. Methodology

Our approach consists of multiple phases: preprocessing, pattern detection, 
hierarchy building, and validation.

3.1. Preprocessing Phase

Documents are normalized and cleaned to handle encoding issues and 
special characters.

3.2. Pattern Detection

Multiple specialized detectors analyze different aspects of document structure.

4. Experimental Results

We evaluated our approach on a dataset of 1,000 documents across five 
different types, achieving 94.7% accuracy.

5. Conclusion

The proposed method demonstrates superior performance and robustness 
compared to existing approaches.

References

[1] Smith, J. et al. (2023). "Advanced Text Processing Techniques." 
    Journal of Computational Linguistics, 45(2), 123-145.
[2] Johnson, M. (2022). "Document Structure Analysis: A Survey." 
    ACM Computing Surveys, 54(3), 1-28.
"""
    
    detector = UniversalChapterDetector()
    result = detector.detect_chapters(paper_content)
    
    _display_detection_results(result, "Academic Paper")
    
    return result


def demo_markdown_document():
    """Demonstrate Markdown detection"""
    console.print("\n[bold magenta]📝 Markdown Document Detection Demo[/bold magenta]")
    
    markdown_content = """
# SYNTHEX Documentation

## 1. Quick Start Guide

### 1.1. Installation

Install SYNTHEX using pip:

```bash
pip install synthex
```

### 1.2. Basic Configuration

Create a configuration file:

```yaml
detection:
  sensitivity: 0.8
  enable_unicode: true
```

#### 1.2.1. Advanced Options

Additional configuration options are available for power users.

## 2. Chapter Detection

### 2.1. Supported Formats

SYNTHEX supports multiple document formats:

- Traditional books with numbered chapters
- Academic papers with section hierarchies  
- Technical documentation
- Mixed-format documents

### 2.2. Detection Algorithms

#### 2.2.1. Pattern Matching Engine

The core pattern matching engine uses regular expressions with contextual validation.

#### 2.2.2. Hierarchy Builder

Detected elements are organized into a logical hierarchy.

### 2.3. Edge Case Handling

Special handling for:

- Unicode characters and special numbering
- Mixed formatting styles
- Ambiguous structural elements

## 3. Advanced Features

### 3.1. Custom Pattern Definition

Users can define custom patterns for specialized document types.

### 3.2. Performance Optimization

- Parallel processing for large documents
- Incremental updates for real-time applications
- Intelligent caching strategies

## 4. API Reference

### 4.1. Core Classes

Complete API documentation for all classes and methods.

### 4.2. Configuration Options

Detailed description of all available configuration parameters.
"""
    
    detector = UniversalChapterDetector()
    result = detector.detect_chapters(markdown_content, filename="demo.md")
    
    _display_detection_results(result, "Markdown Document")
    
    return result


def demo_technical_documentation():
    """Demonstrate technical documentation detection"""
    console.print("\n[bold cyan]⚙️ Technical Documentation Detection Demo[/bold cyan]")
    
    tech_content = """
1. System Architecture

The SYNTHEX chapter detection system is built using a modular architecture 
that allows for easy extension and customization.

1.1. Core Components

The system consists of several key components working together:

1.1.1. Pattern Matching Engine

Responsible for identifying structural elements using regular expressions.

1.1.2. Hierarchy Builder

Constructs logical document structure from detected elements.

1.2. Data Flow

Data processing follows a pipeline architecture with the following stages:

2. API Documentation

2.1. Classes

Class UniversalChapterDetector

The main detection class providing comprehensive chapter detection capabilities.

Function detect_chapters(content: str, document_type: Optional[DocumentType] = None) -> Dict[str, Any]

Detects chapter structure in the provided content.

Parameters:
- content: The document content as a string
- document_type: Optional document type override

Returns:
- Dictionary containing detected structure, table of contents, and statistics

Example:

```python
detector = UniversalChapterDetector()
result = detector.detect_chapters(content)
print(result['statistics']['total_chapters'])
```

Function export_structure(structure_data: Dict[str, Any], format: str = 'json') -> str

Exports detected structure in the specified format.

Parameters:
- structure_data: Structure data from detect_chapters()
- format: Export format ('json', 'markdown', 'xml')

Returns:
- Formatted string representation of the structure

2.2. Configuration

The system can be configured through various parameters:

Class DetectionPattern

Represents a pattern configuration for detecting structural elements.

Parameters:
- pattern: Regular expression pattern
- level: Hierarchy level (0 for top-level)
- type: Element type ('chapter', 'section', etc.)
- numbering_system: Expected numbering system

3. Error Handling

The system provides comprehensive error handling for various scenarios.

Note: Always validate input parameters before processing.

Warning: Large documents may require significant memory and processing time.

Important: Unicode normalization is enabled by default but can be disabled for performance.

4. Performance Considerations

For optimal performance with large documents:

4.1. Memory Management

Use streaming processing for documents larger than 10MB.

4.2. Parallel Processing

Enable multi-threading for documents with complex structure.
"""
    
    detector = UniversalChapterDetector()
    result = detector.detect_chapters(tech_content)
    
    _display_detection_results(result, "Technical Documentation")
    
    return result


def demo_edge_cases():
    """Demonstrate edge case handling"""
    console.print("\n[bold red]🔍 Edge Case Detection Demo[/bold red]")
    
    edge_case_content = """
TITLE I: LEGAL DOCUMENT

Article 1: General Provisions

Section 1.1 - Definitions and Scope

§ 1.1.1 The following terms shall apply:
(a) "System" means the chapter detection system
(b) "Document" means any text-based content

§ 1.1.2 This document applies to all supported formats.

Article II: Implementation Details

Section 2.1 - Unicode Handling

① First requirement: Support circled numbers
② Second requirement: Handle special dashes—like these
③ Third requirement: Process quotes "correctly"

Section 2.2 - Mixed Numbering Systems

A. Alphabetic numbering
B. More alphabetic content

1-A. Mixed style numbering
1-B. Another mixed style

I. Roman numerals
II. More Roman numerals

Canto I: Poetry-Style Headers

Some poetic content here...

Canto II: Another Poetic Section

More verse...

INT. SCREENPLAY FORMAT - DAY

A different formatting style entirely.

EXT. OUTDOOR SCENE - NIGHT

Another screenplay element.
"""
    
    detector = UniversalChapterDetector()
    advanced_detector = AdvancedChapterDetector()
    
    # Basic detection
    result = detector.detect_chapters(edge_case_content)
    
    # Advanced edge case analysis
    enhanced = advanced_detector.enhance_detection(result['structure'], edge_case_content)
    
    console.print("\n[bold]Basic Detection Results:[/bold]")
    _display_detection_results(result, "Edge Cases")
    
    console.print("\n[bold]Edge Case Analysis:[/bold]")
    edge_cases = enhanced['edge_cases']
    
    if edge_cases:
        edge_table = Table(title="Detected Edge Cases")
        edge_table.add_column("Category", style="cyan")
        edge_table.add_column("Line", style="yellow")
        edge_table.add_column("Pattern", style="green")
        edge_table.add_column("Confidence", style="magenta")
        
        for case in edge_cases:
            edge_table.add_row(
                case['category'],
                str(case['line_number']),
                case['pattern'][:50] + "..." if len(case['pattern']) > 50 else case['pattern'],
                f"{case['confidence']:.2f}"
            )
        
        console.print(edge_table)
    
    # Display format regions
    format_regions = enhanced['format_regions']
    if format_regions:
        console.print("\n[bold]Mixed Format Regions:[/bold]")
        for format_type, regions in format_regions.items():
            console.print(f"  {format_type}: {len(regions)} regions detected")
    
    # Display hierarchy validation
    validation = enhanced['hierarchy_validation']
    console.print(f"\n[bold]Hierarchy Validation:[/bold] {'✅ Valid' if validation['is_valid'] else '❌ Issues found'}")
    
    if validation['issues']:
        for issue in validation['issues']:
            console.print(f"  ⚠️ {issue}")
    
    return result, enhanced


def demo_performance():
    """Demonstrate performance with large document"""
    console.print("\n[bold yellow]⚡ Performance Demo[/bold yellow]")
    
    # Generate a large document
    console.print("Generating large test document...")
    
    large_content = ""
    for i in range(50):
        large_content += f"\nChapter {i+1}: Test Chapter {i+1}\n\n"
        large_content += "This is the content for chapter {i+1}. " * 100
        large_content += f"\n\nSection {i+1}.1: First Section\n\n"
        large_content += "This is section content. " * 50
        large_content += f"\n\nSection {i+1}.2: Second Section\n\n"
        large_content += "This is more section content. " * 50
    
    console.print(f"Document size: {len(large_content):,} characters")
    
    # Time the detection
    import time
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Processing large document...", total=100)
        
        start_time = time.time()
        detector = UniversalChapterDetector()
        result = detector.detect_chapters(large_content)
        end_time = time.time()
        
        progress.update(task, completed=100)
    
    processing_time = end_time - start_time
    
    stats = result['statistics']
    
    perf_table = Table(title="Performance Results")
    perf_table.add_column("Metric", style="cyan")
    perf_table.add_column("Value", style="yellow")
    
    perf_table.add_row("Processing Time", f"{processing_time:.2f} seconds")
    perf_table.add_row("Document Size", f"{len(large_content):,} characters")
    perf_table.add_row("Chapters Detected", str(stats['total_chapters']))
    perf_table.add_row("Sections Detected", str(stats['total_sections']))
    perf_table.add_row("Processing Rate", f"{len(large_content)/processing_time:,.0f} chars/sec")
    
    console.print(perf_table)
    
    return result


def _display_detection_results(result, title):
    """Display detection results in a formatted way"""
    
    # Main info panel
    info_text = f"""[bold]Document Type:[/bold] {result['document_type']}
[bold]Total Elements:[/bold] {result['metadata']['total_elements']}
[bold]Max Depth:[/bold] {result['metadata']['max_depth']} levels
[bold]Has Numbering:[/bold] {'Yes' if result['metadata']['has_numbering'] else 'No'}"""
    
    console.print(Panel(info_text, title=f"{title} - Detection Summary", border_style="blue"))
    
    # Statistics table
    stats = result['statistics']
    stats_table = Table(title="Structure Statistics")
    stats_table.add_column("Element Type", style="cyan")
    stats_table.add_column("Count", style="yellow")
    
    stats_table.add_row("Chapters", str(stats.get('total_chapters', 0)))
    stats_table.add_row("Sections", str(stats.get('total_sections', 0)))
    stats_table.add_row("Parts/Books", str(stats.get('total_parts', 0)))
    
    console.print(stats_table)
    
    # Table of contents
    toc = result['table_of_contents']
    if toc:
        console.print("\n[bold]Table of Contents:[/bold]")
        toc_tree = Tree("📖 Document Structure")
        
        for item in toc[:10]:  # Show first 10 items
            indent = "  " * (item['level'] - 1)
            number = f"{item['number']}. " if item.get('number') else ""
            title = item['title'] or f"Untitled {item['type']}"
            
            if item['level'] == 1:
                toc_tree.add(f"[bold]{number}{title}[/bold]")
            else:
                # Find parent and add as child (simplified for demo)
                toc_tree.add(f"{number}{title}")
        
        console.print(toc_tree)
        
        if len(toc) > 10:
            console.print(f"[dim]... and {len(toc) - 10} more items[/dim]")
    
    console.print()


def main():
    """Run all demos"""
    console.print(Panel.fit(
        "[bold cyan]SYNTHEX Chapter Detection Engine Demo[/bold cyan]\n\n"
        "Demonstrating robust algorithms for detecting document structure\n"
        "across various formats and handling edge cases",
        border_style="cyan"
    ))
    
    demos = [
        ("Traditional Book", demo_traditional_book),
        ("Academic Paper", demo_academic_paper),
        ("Markdown Document", demo_markdown_document),
        ("Technical Documentation", demo_technical_documentation),
        ("Edge Cases", demo_edge_cases),
        ("Performance Test", demo_performance)
    ]
    
    results = {}
    
    for demo_name, demo_func in demos:
        try:
            console.print(f"\n{'='*60}")
            result = demo_func()
            results[demo_name] = result
            console.print("[green]✅ Demo completed successfully[/green]")
        except Exception as e:
            console.print(f"[red]❌ Demo failed: {e}[/red]")
    
    # Summary
    console.print(f"\n{'='*60}")
    console.print("[bold green]🎉 All Demos Completed![/bold green]")
    console.print(f"\nSuccessfully demonstrated detection across {len(results)} document types")
    
    # Offer to save results
    save_choice = input("\nSave detailed results to file? (y/n): ")
    if save_choice.lower() == 'y':
        output_file = Path("chapter_detection_demo_results.json")
        with open(output_file, 'w') as f:
            # Convert results to JSON-serializable format
            serializable_results = {}
            for key, value in results.items():
                if isinstance(value, tuple):
                    serializable_results[key] = value[0]  # Take first element for tuples
                else:
                    serializable_results[key] = value
            
            json.dump(serializable_results, f, indent=2)
        
        console.print(f"[green]Results saved to {output_file}[/green]")


if __name__ == "__main__":
    main()