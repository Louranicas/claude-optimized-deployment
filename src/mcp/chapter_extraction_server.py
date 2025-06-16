"""
MCP Server for Chapter Extraction
SYNTHEX Agent 7 - MCP Tool Definitions

This module provides MCP (Model Context Protocol) tools for chapter extraction
with secure, standardized interfaces for AI model integration.
"""

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from mcp.server import MCPServer
from mcp.server.models import Tool, TextContent
from mcp.types import JSONSchema

from src.api.chapter_extraction_api import (
    ChapterExtractor, ExtractionConfig, ExportFormat,
    ChapterSearcher, SearchQuery
)
from src.core.exceptions import ValidationError
from src.core.security.input_validation import validate_file_path, sanitize_content

logger = logging.getLogger(__name__)

class ChapterExtractionMCPServer:
    """MCP Server for chapter extraction tools."""
    
    def __init__(self):
        self.server = MCPServer("chapter-extraction")
        self.extractor = ChapterExtractor()
        self.searcher = ChapterSearcher()
        self._register_tools()
    
    def _register_tools(self):
        """Register all MCP tools."""
        
        # Chapter extraction tool
        @self.server.tool(
            name="extract_chapters",
            description="Extract chapters from documents with configurable patterns and filters",
            parameters=JSONSchema(
                type="object",
                properties={
                    "source": {
                        "type": "string",
                        "description": "File path, URL, or direct text content to extract chapters from"
                    },
                    "source_type": {
                        "type": "string",
                        "enum": ["file", "url", "text"],
                        "default": "text",
                        "description": "Type of source content"
                    },
                    "chapter_pattern": {
                        "type": "string",
                        "default": "^(Chapter|CHAPTER)\\s+(\\d+)",
                        "description": "Regex pattern to identify chapter headings"
                    },
                    "section_pattern": {
                        "type": "string",
                        "description": "Optional regex pattern to identify sections within chapters"
                    },
                    "min_chapter_length": {
                        "type": "integer",
                        "default": 100,
                        "minimum": 1,
                        "description": "Minimum length in characters for a valid chapter"
                    },
                    "max_chapter_length": {
                        "type": "integer",
                        "description": "Maximum length in characters for a chapter"
                    },
                    "include_metadata": {
                        "type": "boolean",
                        "default": True,
                        "description": "Include chapter metadata (word count, line numbers, etc.)"
                    },
                    "extract_subsections": {
                        "type": "boolean",
                        "default": True,
                        "description": "Extract and nest subsections within chapters"
                    },
                    "output_format": {
                        "type": "string",
                        "enum": ["json", "markdown", "html"],
                        "default": "json",
                        "description": "Format for the extracted output"
                    },
                    "custom_patterns": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Additional regex patterns for custom chapter detection"
                    }
                },
                required=["source"]
            )
        )
        async def extract_chapters_tool(
            source: str,
            source_type: str = "text",
            chapter_pattern: str = "^(Chapter|CHAPTER)\\s+(\\d+)",
            section_pattern: Optional[str] = None,
            min_chapter_length: int = 100,
            max_chapter_length: Optional[int] = None,
            include_metadata: bool = True,
            extract_subsections: bool = True,
            output_format: str = "json",
            custom_patterns: Optional[List[str]] = None
        ):
            """Extract chapters from a document source."""
            try:
                # Validate and sanitize inputs
                if source_type == "file":
                    source = validate_file_path(source)
                elif source_type == "text":
                    source = sanitize_content(source)
                
                # Validate regex patterns
                try:
                    re.compile(chapter_pattern)
                    if section_pattern:
                        re.compile(section_pattern)
                    if custom_patterns:
                        for pattern in custom_patterns:
                            re.compile(pattern)
                except re.error as e:
                    raise ValidationError(f"Invalid regex pattern: {e}")
                
                # Create extraction configuration
                config = ExtractionConfig(
                    chapter_pattern=chapter_pattern,
                    section_pattern=section_pattern,
                    min_chapter_length=min_chapter_length,
                    max_chapter_length=max_chapter_length,
                    include_metadata=include_metadata,
                    extract_subsections=extract_subsections,
                    custom_patterns=custom_patterns or []
                )
                
                # Extract chapters
                chapters = await self.extractor.extract(source, config)
                
                # Export in requested format
                result = await self.extractor.export(chapters, ExportFormat(output_format))
                
                return [TextContent(
                    type="text",
                    text=json.dumps({
                        "success": True,
                        "total_chapters": len(chapters),
                        "format": output_format,
                        "result": result if output_format == "json" else {"content": result}
                    }, indent=2)
                )]
                
            except Exception as e:
                logger.error(f"Chapter extraction failed: {str(e)}")
                return [TextContent(
                    type="text",
                    text=json.dumps({
                        "success": False,
                        "error": str(e),
                        "error_type": type(e).__name__
                    }, indent=2)
                )]
        
        # Chapter search tool
        @self.server.tool(
            name="search_chapters",
            description="Search through extracted chapters with advanced filtering capabilities",
            parameters=JSONSchema(
                type="object",
                properties={
                    "query": {
                        "type": "string",
                        "description": "Search query text"
                    },
                    "job_id": {
                        "type": "string",
                        "description": "Job ID to search within (optional)"
                    },
                    "min_words": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Minimum word count for chapters"
                    },
                    "max_words": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Maximum word count for chapters"
                    },
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Filter by specific tags"
                    },
                    "limit": {
                        "type": "integer",
                        "default": 10,
                        "minimum": 1,
                        "maximum": 100,
                        "description": "Maximum number of results to return"
                    },
                    "offset": {
                        "type": "integer",
                        "default": 0,
                        "minimum": 0,
                        "description": "Number of results to skip (for pagination)"
                    },
                    "sort_by": {
                        "type": "string",
                        "enum": ["relevance", "word_count", "title"],
                        "default": "relevance",
                        "description": "Sort order for results"
                    },
                    "include_content": {
                        "type": "boolean",
                        "default": False,
                        "description": "Include full chapter content in results"
                    }
                },
                required=["query"]
            )
        )
        async def search_chapters_tool(
            query: str,
            job_id: Optional[str] = None,
            min_words: Optional[int] = None,
            max_words: Optional[int] = None,
            tags: Optional[List[str]] = None,
            limit: int = 10,
            offset: int = 0,
            sort_by: str = "relevance",
            include_content: bool = False
        ):
            """Search through extracted chapters."""
            try:
                # Build filters
                filters = {}
                if job_id:
                    filters["job_id"] = job_id
                if min_words is not None:
                    filters["min_words"] = min_words
                if max_words is not None:
                    filters["max_words"] = max_words
                if tags:
                    filters["tags"] = tags
                
                # Create search query
                search_query = SearchQuery(
                    query=sanitize_content(query),
                    filters=filters,
                    limit=limit,
                    offset=offset,
                    sort_by=sort_by,
                    include_content=include_content
                )
                
                # Perform search
                results = await self.searcher.search(search_query)
                
                return [TextContent(
                    type="text",
                    text=json.dumps({
                        "success": True,
                        "query": query,
                        "total_results": results["total"],
                        "returned_results": len(results["chapters"]),
                        "results": results["chapters"],
                        "facets": results.get("facets", {})
                    }, indent=2)
                )]
                
            except Exception as e:
                logger.error(f"Chapter search failed: {str(e)}")
                return [TextContent(
                    type="text",
                    text=json.dumps({
                        "success": False,
                        "error": str(e),
                        "error_type": type(e).__name__
                    }, indent=2)
                )]
        
        # Chapter analysis tool
        @self.server.tool(
            name="analyze_chapter_structure",
            description="Analyze the structure and characteristics of extracted chapters",
            parameters=JSONSchema(
                type="object",
                properties={
                    "source": {
                        "type": "string",
                        "description": "File path, URL, or text content to analyze"
                    },
                    "source_type": {
                        "type": "string",
                        "enum": ["file", "url", "text"],
                        "default": "text",
                        "description": "Type of source content"
                    },
                    "include_statistics": {
                        "type": "boolean",
                        "default": True,
                        "description": "Include detailed statistics about chapters"
                    },
                    "detect_patterns": {
                        "type": "boolean",
                        "default": True,
                        "description": "Automatically detect chapter patterns"
                    }
                },
                required=["source"]
            )
        )
        async def analyze_chapter_structure_tool(
            source: str,
            source_type: str = "text",
            include_statistics: bool = True,
            detect_patterns: bool = True
        ):
            """Analyze chapter structure and suggest extraction patterns."""
            try:
                # Validate and sanitize inputs
                if source_type == "file":
                    source = validate_file_path(source)
                elif source_type == "text":
                    source = sanitize_content(source)
                
                # Load content
                content = await self.extractor._load_content(source)
                lines = content.split('
')
                
                analysis = {
                    "total_lines": len(lines),
                    "total_characters": len(content),
                    "total_words": len(content.split()),
                    "suggested_patterns": [],
                    "detected_headings": [],
                    "statistics": {}
                }
                
                if detect_patterns:
                    # Detect potential chapter patterns
                    chapter_patterns = [
                        r"^Chapter\s+(\d+)",
                        r"^CHAPTER\s+(\d+)",
                        r"^(\d+)\.\s+",
                        r"^#\s+",
                        r"^##\s+",
                        r"^\d+\s+[A-Z]",
                    ]
                    
                    for pattern in chapter_patterns:
                        matches = []
                        for i, line in enumerate(lines):
                            if re.match(pattern, line.strip()):
                                matches.append({
                                    "line": i + 1,
                                    "text": line.strip()[:100]
                                })
                        
                        if matches:
                            analysis["suggested_patterns"].append({
                                "pattern": pattern,
                                "matches": len(matches),
                                "examples": matches[:5]
                            })
                
                # Find all potential headings
                heading_patterns = [
                    r"^#+ ",           # Markdown headers
                    r"^[A-Z][^a-z]*$", # All caps lines
                    r"^\d+\.",         # Numbered sections
                    r"^Chapter\s+",    # Chapter keywords
                    r"^Section\s+",    # Section keywords
                ]
                
                for pattern in heading_patterns:
                    for i, line in enumerate(lines):
                        if re.match(pattern, line.strip()) and len(line.strip()) < 200:
                            analysis["detected_headings"].append({
                                "line": i + 1,
                                "text": line.strip(),
                                "pattern": pattern
                            })
                
                if include_statistics:
                    # Calculate content statistics
                    paragraphs = [p for p in content.split('\n
') if p.strip()]
                    analysis["statistics"] = {
                        "paragraphs": len(paragraphs),
                        "avg_paragraph_length": sum(len(p) for p in paragraphs) / len(paragraphs) if paragraphs else 0,
                        "lines_with_content": len([l for l in lines if l.strip()]),
                        "empty_lines": len([l for l in lines if not l.strip()]),
                        "potential_headings": len(analysis["detected_headings"]),
                        "suggested_patterns_count": len(analysis["suggested_patterns"])
                    }
                
                return [TextContent(
                    type="text",
                    text=json.dumps({
                        "success": True,
                        "analysis": analysis
                    }, indent=2)
                )]
                
            except Exception as e:
                logger.error(f"Chapter analysis failed: {str(e)}")
                return [TextContent(
                    type="text",
                    text=json.dumps({
                        "success": False,
                        "error": str(e),
                        "error_type": type(e).__name__
                    }, indent=2)
                )]
        
        # Batch extraction tool
        @self.server.tool(
            name="batch_extract_chapters",
            description="Extract chapters from multiple documents in a single operation",
            parameters=JSONSchema(
                type="object",
                properties={
                    "sources": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string"},
                                "source_type": {
                                    "type": "string",
                                    "enum": ["file", "url", "text"],
                                    "default": "file"
                                }
                            },
                            "required": ["path"]
                        },
                        "description": "List of sources to process"
                    },
                    "config": {
                        "type": "object",
                        "properties": {
                            "chapter_pattern": {"type": "string"},
                            "min_chapter_length": {"type": "integer"},
                            "max_chapter_length": {"type": "integer"},
                            "include_metadata": {"type": "boolean"}
                        },
                        "description": "Common extraction configuration for all sources"
                    },
                    "parallel_processing": {
                        "type": "boolean",
                        "default": True,
                        "description": "Process sources in parallel"
                    },
                    "max_concurrent": {
                        "type": "integer",
                        "default": 3,
                        "minimum": 1,
                        "maximum": 10,
                        "description": "Maximum concurrent extractions"
                    }
                },
                required=["sources"]
            )
        )
        async def batch_extract_chapters_tool(
            sources: List[Dict[str, Any]],
            config: Optional[Dict[str, Any]] = None,
            parallel_processing: bool = True,
            max_concurrent: int = 3
        ):
            """Extract chapters from multiple sources."""
            try:
                # Create extraction configuration
                extraction_config = ExtractionConfig()
                if config:
                    extraction_config = ExtractionConfig(**config)
                
                results = []
                
                if parallel_processing:
                    # Process with concurrency limit
                    semaphore = asyncio.Semaphore(max_concurrent)
                    
                    async def process_source(source_info):
                        async with semaphore:
                            try:
                                source = source_info["path"]
                                source_type = source_info.get("source_type", "file")
                                
                                # Validate source
                                if source_type == "file":
                                    source = validate_file_path(source)
                                elif source_type == "text":
                                    source = sanitize_content(source)
                                
                                chapters = await self.extractor.extract(source, extraction_config)
                                
                                return {
                                    "source": source_info["path"],
                                    "success": True,
                                    "chapters": [ch.dict() for ch in chapters],
                                    "total_chapters": len(chapters)
                                }
                                
                            except Exception as e:
                                return {
                                    "source": source_info["path"],
                                    "success": False,
                                    "error": str(e)
                                }
                    
                    # Process all sources
                    tasks = [process_source(source) for source in sources]
                    results = await asyncio.gather(*tasks)
                    
                else:
                    # Process sequentially
                    for source_info in sources:
                        try:
                            source = source_info["path"]
                            source_type = source_info.get("source_type", "file")
                            
                            # Validate source
                            if source_type == "file":
                                source = validate_file_path(source)
                            elif source_type == "text":
                                source = sanitize_content(source)
                            
                            chapters = await self.extractor.extract(source, extraction_config)
                            
                            results.append({
                                "source": source_info["path"],
                                "success": True,
                                "chapters": [ch.dict() for ch in chapters],
                                "total_chapters": len(chapters)
                            })
                            
                        except Exception as e:
                            results.append({
                                "source": source_info["path"],
                                "success": False,
                                "error": str(e)
                            })
                
                # Calculate summary statistics
                successful = [r for r in results if r["success"]]
                failed = [r for r in results if not r["success"]]
                total_chapters = sum(r.get("total_chapters", 0) for r in successful)
                
                return [TextContent(
                    type="text",
                    text=json.dumps({
                        "success": True,
                        "summary": {
                            "total_sources": len(sources),
                            "successful": len(successful),
                            "failed": len(failed),
                            "total_chapters_extracted": total_chapters
                        },
                        "results": results
                    }, indent=2)
                )]
                
            except Exception as e:
                logger.error(f"Batch extraction failed: {str(e)}")
                return [TextContent(
                    type="text",
                    text=json.dumps({
                        "success": False,
                        "error": str(e),
                        "error_type": type(e).__name__
                    }, indent=2)
                )]
        
        # Export tool
        @self.server.tool(
            name="export_chapters",
            description="Export extracted chapters in various formats",
            parameters=JSONSchema(
                type="object",
                properties={
                    "chapters": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "Chapters data to export (JSON format)"
                    },
                    "format": {
                        "type": "string",
                        "enum": ["json", "markdown", "html"],
                        "default": "markdown",
                        "description": "Export format"
                    },
                    "include_metadata": {
                        "type": "boolean",
                        "default": True,
                        "description": "Include chapter metadata in export"
                    },
                    "title": {
                        "type": "string",
                        "description": "Document title for HTML export"
                    }
                },
                required=["chapters"]
            )
        )
        async def export_chapters_tool(
            chapters: List[Dict[str, Any]],
            format: str = "markdown",
            include_metadata: bool = True,
            title: Optional[str] = None
        ):
            """Export chapters in specified format."""
            try:
                # Convert dict chapters back to Chapter objects
                from src.api.chapter_extraction_api import Chapter, ChapterMetadata
                
                chapter_objects = []
                for ch_data in chapters:
                    metadata = ChapterMetadata(**ch_data["metadata"])
                    chapter = Chapter(
                        metadata=metadata,
                        content=ch_data["content"],
                        subsections=ch_data.get("subsections", []),
                        parent_id=ch_data.get("parent_id")
                    )
                    chapter_objects.append(chapter)
                
                # Export in requested format
                exported = await self.extractor.export(
                    chapter_objects, 
                    ExportFormat(format)
                )
                
                return [TextContent(
                    type="text",
                    text=json.dumps({
                        "success": True,
                        "format": format,
                        "content": exported,
                        "chapter_count": len(chapter_objects)
                    }, indent=2)
                )]
                
            except Exception as e:
                logger.error(f"Chapter export failed: {str(e)}")
                return [TextContent(
                    type="text",
                    text=json.dumps({
                        "success": False,
                        "error": str(e),
                        "error_type": type(e).__name__
                    }, indent=2)
                )]
    
    async def run(self, host: str = "localhost", port: int = 8001):
        """Run the MCP server."""
        logger.info(f"Starting Chapter Extraction MCP Server on {host}:{port}")
        await self.server.run(host=host, port=port)

# MCP Server configuration
def create_mcp_server_config():
    """Create MCP server configuration."""
    return {
        "name": "chapter-extraction",
        "description": "Advanced chapter extraction and analysis tools",
        "version": "1.0.0",
        "capabilities": {
            "tools": [
                {
                    "name": "extract_chapters",
                    "description": "Extract chapters from documents with configurable patterns"
                },
                {
                    "name": "search_chapters", 
                    "description": "Search through extracted chapters"
                },
                {
                    "name": "analyze_chapter_structure",
                    "description": "Analyze document structure and suggest extraction patterns"
                },
                {
                    "name": "batch_extract_chapters",
                    "description": "Extract chapters from multiple documents"
                },
                {
                    "name": "export_chapters",
                    "description": "Export chapters in various formats"
                }
            ]
        },
        "security": {
            "input_validation": True,
            "output_sanitization": True,
            "rate_limiting": True,
            "authentication_required": False
        }
    }

# Server instance
server_instance = ChapterExtractionMCPServer()

if __name__ == "__main__":
    import asyncio
    asyncio.run(server_instance.run())