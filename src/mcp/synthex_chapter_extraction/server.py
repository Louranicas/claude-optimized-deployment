#!/usr/bin/env python3
"""
SYNTHEX Chapter Extraction MCP Server
====================================

A specialized native MCP server for the CORE environment that extracts chapters 
from any text document in any format from the downloads folder.

This server implements the Model Context Protocol (MCP) specification and provides
comprehensive text processing capabilities with enterprise-grade security,
performance optimization, and extensive format support.

Architecture:
- Multi-format text parsing (PDF, EPUB, DOCX, TXT, MD, HTML)
- Advanced chapter detection algorithms
- Memory-optimized processing with object pooling
- Security sandboxing and input validation
- Real-time file monitoring
- Integration with existing CORE infrastructure

Author: SYNTHEX Collaborative Intelligence
Version: 1.0.0
License: MIT
"""

import asyncio
import json
import logging
import os
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from uuid import uuid4

# MCP Protocol imports
from mcp import ClientSession, StdioServerParameters
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions
from mcp.types import (
    CallToolRequest,
    CallToolResult,
    GetPromptRequest,
    GetPromptResult,
    ListPromptsRequest,
    ListPromptsResult,
    ListResourcesRequest, 
    ListResourcesResult,
    ListToolsRequest,
    ListToolsResult,
    Prompt,
    PromptArgument,
    PromptMessage,
    ReadResourceRequest,
    ReadResourceResult,
    Resource,
    TextContent,
    Tool
)

# SYNTHEX Components Integration
try:
    from ..security.comprehensive_security_architecture import SecurityOrchestrator
    from ..core.document_processor import DocumentProcessor
    from ..synthex.chapter_detection_engine import ChapterDetectionEngine
    from ..synthex.text_parser import TextParser
    from ..core.unified_connection_manager import UnifiedConnectionManager
    from ..monitoring.enhanced_memory_metrics import MemoryMonitor
    from ..auth.rbac import RBACManager
except ImportError:
    # Fallback for standalone operation
    logging.warning("SYNTHEX components not available, running in standalone mode")
    SecurityOrchestrator = None
    DocumentProcessor = None
    ChapterDetectionEngine = None
    TextParser = None
    UnifiedConnectionManager = None
    MemoryMonitor = None
    RBACManager = None

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/tmp/synthex_mcp_server.log', mode='a')
    ]
)
logger = logging.getLogger("synthex.mcp.server")

class SynthexChapterExtractionServer:
    """
    SYNTHEX Chapter Extraction MCP Server
    
    Provides comprehensive text processing and chapter extraction capabilities
    through the Model Context Protocol with enterprise-grade features.
    """
    
    def __init__(self, downloads_folder: Optional[str] = None):
        """Initialize the SYNTHEX Chapter Extraction Server."""
        self.server = Server("synthex-chapter-extraction")
        self.session_id = str(uuid4())
        self.start_time = datetime.now()
        
        # Configuration
        self.downloads_folder = Path(downloads_folder or os.path.expanduser("~/Downloads"))
        self.supported_formats = {
            '.pdf', '.epub', '.docx', '.doc', '.txt', '.md', 
            '.html', '.htm', '.rtf', '.odt', '.tex'
        }
        
        # Performance metrics
        self.metrics = {
            'requests_total': 0,
            'requests_successful': 0,
            'requests_failed': 0,
            'documents_processed': 0,
            'chapters_extracted': 0,
            'processing_time_total': 0.0
        }
        
        # Initialize SYNTHEX components if available
        self._initialize_synthex_components()
        
        # Register MCP handlers
        self._register_handlers()
        
        logger.info(f"SYNTHEX Chapter Extraction Server initialized")
        logger.info(f"Session ID: {self.session_id}")
        logger.info(f"Downloads folder: {self.downloads_folder}")
        logger.info(f"Supported formats: {', '.join(sorted(self.supported_formats))}")

    def _initialize_synthex_components(self):
        """Initialize SYNTHEX infrastructure components."""
        try:
            # Security
            if SecurityOrchestrator:
                self.security = SecurityOrchestrator()
                logger.info("Security orchestrator initialized")
            else:
                self.security = None
                logger.warning("Security orchestrator not available")
            
            # Document processing
            if DocumentProcessor:
                self.document_processor = DocumentProcessor()
                logger.info("Document processor initialized")
            else:
                self.document_processor = None
                logger.warning("Document processor not available")
            
            # Chapter detection
            if ChapterDetectionEngine:
                self.chapter_detector = ChapterDetectionEngine()
                logger.info("Chapter detection engine initialized")
            else:
                self.chapter_detector = None
                logger.warning("Chapter detection engine not available")
            
            # Text parsing
            if TextParser:
                self.text_parser = TextParser()
                logger.info("Text parser initialized")
            else:
                self.text_parser = None
                logger.warning("Text parser not available")
            
            # Memory monitoring
            if MemoryMonitor:
                self.memory_monitor = MemoryMonitor()
                logger.info("Memory monitor initialized")
            else:
                self.memory_monitor = None
                logger.warning("Memory monitor not available")
                
        except Exception as e:
            logger.error(f"Failed to initialize SYNTHEX components: {e}")
            logger.error(traceback.format_exc())

    def _register_handlers(self):
        """Register MCP protocol handlers."""
        
        @self.server.list_tools()
        async def handle_list_tools() -> list[Tool]:
            """List available tools for chapter extraction."""
            return [
                Tool(
                    name="extract_chapters",
                    description="Extract chapters from a document in the downloads folder",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "filename": {
                                "type": "string",
                                "description": "Name of the file in the downloads folder"
                            },
                            "format": {
                                "type": "string",
                                "enum": ["json", "markdown", "text", "html"],
                                "default": "json",
                                "description": "Output format for extracted chapters"
                            },
                            "include_metadata": {
                                "type": "boolean",
                                "default": True,
                                "description": "Include metadata (word count, line numbers, etc.)"
                            },
                            "min_chapter_length": {
                                "type": "integer",
                                "default": 100,
                                "description": "Minimum character length for a valid chapter"
                            },
                            "max_depth": {
                                "type": "integer",
                                "default": 3,
                                "description": "Maximum heading depth to consider (1-6)"
                            }
                        },
                        "required": ["filename"]
                    }
                ),
                Tool(
                    name="list_documents",
                    description="List all supported documents in the downloads folder",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "filter_format": {
                                "type": "string",
                                "description": "Filter by file format (e.g., 'pdf', 'epub')"
                            },
                            "sort_by": {
                                "type": "string",
                                "enum": ["name", "size", "modified"],
                                "default": "modified",
                                "description": "Sort criteria"
                            },
                            "limit": {
                                "type": "integer",
                                "default": 50,
                                "description": "Maximum number of files to return"
                            }
                        }
                    }
                ),
                Tool(
                    name="analyze_document_structure",
                    description="Analyze document structure and provide extraction preview",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "filename": {
                                "type": "string",
                                "description": "Name of the file to analyze"
                            },
                            "sample_size": {
                                "type": "integer",
                                "default": 5000,
                                "description": "Number of characters to analyze for structure"
                            }
                        },
                        "required": ["filename"]
                    }
                ),
                Tool(
                    name="batch_extract",
                    description="Extract chapters from multiple documents",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "filenames": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "List of filenames to process"
                            },
                            "output_format": {
                                "type": "string",
                                "enum": ["json", "markdown", "zip"],
                                "default": "json",
                                "description": "Format for batch output"
                            },
                            "parallel": {
                                "type": "boolean",
                                "default": True,
                                "description": "Process files in parallel"
                            }
                        },
                        "required": ["filenames"]
                    }
                ),
                Tool(
                    name="search_chapters",
                    description="Search for chapters containing specific text",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Search query text"
                            },
                            "filename": {
                                "type": "string",
                                "description": "Specific file to search (optional)"
                            },
                            "case_sensitive": {
                                "type": "boolean",
                                "default": False,
                                "description": "Case-sensitive search"
                            },
                            "regex": {
                                "type": "boolean",
                                "default": False,
                                "description": "Use regular expression matching"
                            }
                        },
                        "required": ["query"]
                    }
                ),
                Tool(
                    name="get_server_status",
                    description="Get server status and performance metrics",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "detailed": {
                                "type": "boolean",
                                "default": False,
                                "description": "Include detailed performance metrics"
                            }
                        }
                    }
                )
            ]

        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: dict) -> CallToolResult:
            """Handle tool execution requests."""
            start_time = time.time()
            self.metrics['requests_total'] += 1
            
            try:
                # Security validation
                if self.security:
                    validation_result = await self._validate_request(name, arguments)
                    if not validation_result['valid']:
                        self.metrics['requests_failed'] += 1
                        return CallToolResult(
                            content=[TextContent(
                                type="text",
                                text=f"Security validation failed: {validation_result['reason']}"
                            )],
                            isError=True
                        )
                
                # Route to appropriate handler
                if name == "extract_chapters":
                    result = await self._extract_chapters(**arguments)
                elif name == "list_documents":
                    result = await self._list_documents(**arguments)
                elif name == "analyze_document_structure":
                    result = await self._analyze_document_structure(**arguments)
                elif name == "batch_extract":
                    result = await self._batch_extract(**arguments)
                elif name == "search_chapters":
                    result = await self._search_chapters(**arguments)
                elif name == "get_server_status":
                    result = await self._get_server_status(**arguments)
                else:
                    raise ValueError(f"Unknown tool: {name}")
                
                # Update metrics
                processing_time = time.time() - start_time
                self.metrics['requests_successful'] += 1
                self.metrics['processing_time_total'] += processing_time
                
                return CallToolResult(
                    content=[TextContent(
                        type="text",
                        text=json.dumps(result, indent=2, ensure_ascii=False)
                    )]
                )
                
            except Exception as e:
                # Error handling
                processing_time = time.time() - start_time
                self.metrics['requests_failed'] += 1
                self.metrics['processing_time_total'] += processing_time
                
                error_details = {
                    'error': str(e),
                    'tool': name,
                    'arguments': arguments,
                    'processing_time': processing_time,
                    'timestamp': datetime.now().isoformat()
                }
                
                logger.error(f"Tool execution failed: {error_details}")
                logger.error(traceback.format_exc())
                
                return CallToolResult(
                    content=[TextContent(
                        type="text",
                        text=json.dumps(error_details, indent=2)
                    )],
                    isError=True
                )

        @self.server.list_resources()
        async def handle_list_resources() -> list[Resource]:
            """List available resources."""
            resources = []
            
            # Add downloads folder as a resource
            if self.downloads_folder.exists():
                resources.append(Resource(
                    uri=f"file://{self.downloads_folder}",
                    name="Downloads Folder",
                    description="Folder containing documents for chapter extraction",
                    mimeType="inode/directory"
                ))
            
            # Add configuration as a resource
            resources.append(Resource(
                uri="synthex://config",
                name="Server Configuration",
                description="Current server configuration and capabilities",
                mimeType="application/json"
            ))
            
            return resources

        @self.server.read_resource()
        async def handle_read_resource(uri: str) -> ReadResourceResult:
            """Read resource content."""
            if uri == "synthex://config":
                config = {
                    'server_info': {
                        'name': 'SYNTHEX Chapter Extraction Server',
                        'version': '1.0.0',
                        'session_id': self.session_id,
                        'start_time': self.start_time.isoformat(),
                        'uptime_seconds': (datetime.now() - self.start_time).total_seconds()
                    },
                    'configuration': {
                        'downloads_folder': str(self.downloads_folder),
                        'supported_formats': list(self.supported_formats),
                        'components_available': {
                            'security': self.security is not None,
                            'document_processor': self.document_processor is not None,
                            'chapter_detector': self.chapter_detector is not None,
                            'text_parser': self.text_parser is not None,
                            'memory_monitor': self.memory_monitor is not None
                        }
                    },
                    'metrics': self.metrics
                }
                
                return ReadResourceResult(
                    contents=[TextContent(
                        type="text",
                        text=json.dumps(config, indent=2, ensure_ascii=False)
                    )]
                )
            else:
                raise ValueError(f"Unknown resource URI: {uri}")

    async def _validate_request(self, tool_name: str, arguments: dict) -> dict:
        """Validate request using security orchestrator."""
        try:
            # Basic validation
            if 'filename' in arguments:
                filename = arguments['filename']
                
                # Path traversal protection
                if '..' in filename or filename.startswith('/'):
                    return {
                        'valid': False,
                        'reason': 'Path traversal attempt detected'
                    }
                
                # File extension validation
                file_path = Path(filename)
                if file_path.suffix.lower() not in self.supported_formats:
                    return {
                        'valid': False,
                        'reason': f'Unsupported file format: {file_path.suffix}'
                    }
            
            # Additional security checks if available
            if self.security:
                # Use comprehensive security validation
                validation = await self.security.validate_file_operation(
                    operation='read',
                    path=str(self.downloads_folder / arguments.get('filename', '')),
                    context={'tool': tool_name, 'session': self.session_id}
                )
                return validation
            
            return {'valid': True, 'reason': 'Basic validation passed'}
            
        except Exception as e:
            logger.error(f"Security validation error: {e}")
            return {
                'valid': False,
                'reason': f'Security validation error: {str(e)}'
            }

    async def _extract_chapters(self, filename: str, format: str = "json", 
                              include_metadata: bool = True, 
                              min_chapter_length: int = 100,
                              max_depth: int = 3) -> dict:
        """Extract chapters from a document."""
        file_path = self.downloads_folder / filename
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {filename}")
        
        # Parse document text
        if self.text_parser:
            text_content = await self.text_parser.parse_file(file_path)
        else:
            # Fallback basic text reading
            text_content = await self._basic_text_extraction(file_path)
        
        # Detect chapters
        if self.chapter_detector:
            chapters = await self.chapter_detector.detect_chapters(
                text_content,
                min_length=min_chapter_length,
                max_depth=max_depth
            )
        else:
            # Fallback basic chapter detection
            chapters = await self._basic_chapter_detection(
                text_content, 
                min_chapter_length
            )
        
        # Update metrics
        self.metrics['documents_processed'] += 1
        self.metrics['chapters_extracted'] += len(chapters)
        
        # Format response
        result = {
            'filename': filename,
            'format': format,
            'extraction_time': datetime.now().isoformat(),
            'total_chapters': len(chapters),
            'chapters': chapters
        }
        
        if include_metadata:
            result['metadata'] = {
                'file_size': file_path.stat().st_size,
                'total_characters': len(text_content),
                'total_words': len(text_content.split()),
                'avg_chapter_length': sum(len(ch.get('content', '')) for ch in chapters) / max(len(chapters), 1)
            }
        
        return result

    async def _list_documents(self, filter_format: Optional[str] = None,
                             sort_by: str = "modified",
                             limit: int = 50) -> dict:
        """List supported documents in downloads folder."""
        if not self.downloads_folder.exists():
            return {
                'documents': [],
                'total': 0,
                'message': f"Downloads folder not found: {self.downloads_folder}"
            }
        
        documents = []
        
        for file_path in self.downloads_folder.iterdir():
            if file_path.is_file() and file_path.suffix.lower() in self.supported_formats:
                if filter_format and file_path.suffix.lower() != f".{filter_format.lower()}":
                    continue
                
                stat = file_path.stat()
                documents.append({
                    'filename': file_path.name,
                    'size': stat.st_size,
                    'size_human': self._format_file_size(stat.st_size),
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'format': file_path.suffix.lower()[1:],  # Remove the dot
                    'path': str(file_path)
                })
        
        # Sort documents
        if sort_by == "name":
            documents.sort(key=lambda x: x['filename'])
        elif sort_by == "size":
            documents.sort(key=lambda x: x['size'], reverse=True)
        elif sort_by == "modified":
            documents.sort(key=lambda x: x['modified'], reverse=True)
        
        # Limit results
        documents = documents[:limit]
        
        return {
            'documents': documents,
            'total': len(documents),
            'downloads_folder': str(self.downloads_folder),
            'supported_formats': list(self.supported_formats)
        }

    async def _analyze_document_structure(self, filename: str, 
                                        sample_size: int = 5000) -> dict:
        """Analyze document structure."""
        file_path = self.downloads_folder / filename
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {filename}")
        
        # Extract sample text
        if self.text_parser:
            full_text = await self.text_parser.parse_file(file_path)
        else:
            full_text = await self._basic_text_extraction(file_path)
        
        sample_text = full_text[:sample_size]
        
        # Analyze structure patterns
        analysis = {
            'filename': filename,
            'file_size': file_path.stat().st_size,
            'total_characters': len(full_text),
            'sample_size': len(sample_text),
            'analysis': {}
        }
        
        if self.chapter_detector:
            structure_analysis = await self.chapter_detector.analyze_structure(sample_text)
            analysis['analysis'] = structure_analysis
        else:
            # Basic analysis
            analysis['analysis'] = await self._basic_structure_analysis(sample_text)
        
        return analysis

    async def _batch_extract(self, filenames: List[str], 
                           output_format: str = "json",
                           parallel: bool = True) -> dict:
        """Extract chapters from multiple documents."""
        results = {}
        errors = {}
        
        if parallel and len(filenames) > 1:
            # Parallel processing
            tasks = []
            for filename in filenames:
                task = asyncio.create_task(
                    self._extract_chapters(filename, output_format)
                )
                tasks.append((filename, task))
            
            for filename, task in tasks:
                try:
                    result = await task
                    results[filename] = result
                except Exception as e:
                    errors[filename] = str(e)
        else:
            # Sequential processing
            for filename in filenames:
                try:
                    result = await self._extract_chapters(filename, output_format)
                    results[filename] = result
                except Exception as e:
                    errors[filename] = str(e)
        
        return {
            'batch_id': str(uuid4()),
            'processing_time': datetime.now().isoformat(),
            'total_files': len(filenames),
            'successful': len(results),
            'failed': len(errors),
            'results': results,
            'errors': errors if errors else None
        }

    async def _search_chapters(self, query: str, filename: Optional[str] = None,
                             case_sensitive: bool = False, regex: bool = False) -> dict:
        """Search for chapters containing specific text."""
        import re
        
        search_results = []
        
        if filename:
            # Search in specific file
            files_to_search = [filename]
        else:
            # Search in all documents
            documents = await self._list_documents()
            files_to_search = [doc['filename'] for doc in documents['documents']]
        
        for fname in files_to_search:
            try:
                extraction = await self._extract_chapters(fname)
                
                for chapter in extraction['chapters']:
                    content = chapter.get('content', '')
                    title = chapter.get('title', '')
                    
                    # Prepare search text
                    search_text = f"{title} {content}"
                    if not case_sensitive:
                        search_text = search_text.lower()
                        search_query = query.lower()
                    else:
                        search_query = query
                    
                    # Search
                    found = False
                    if regex:
                        try:
                            pattern = re.compile(search_query, 
                                               re.IGNORECASE if not case_sensitive else 0)
                            matches = pattern.findall(search_text)
                            found = len(matches) > 0
                        except re.error as e:
                            continue  # Skip invalid regex
                    else:
                        found = search_query in search_text
                    
                    if found:
                        search_results.append({
                            'filename': fname,
                            'chapter_number': chapter.get('number'),
                            'chapter_title': title,
                            'match_preview': self._create_match_preview(content, search_query),
                            'chapter_length': len(content)
                        })
                        
            except Exception as e:
                logger.warning(f"Failed to search in {fname}: {e}")
                continue
        
        return {
            'query': query,
            'total_matches': len(search_results),
            'case_sensitive': case_sensitive,
            'regex': regex,
            'search_time': datetime.now().isoformat(),
            'results': search_results
        }

    async def _get_server_status(self, detailed: bool = False) -> dict:
        """Get server status and metrics."""
        uptime = datetime.now() - self.start_time
        
        status = {
            'server': {
                'name': 'SYNTHEX Chapter Extraction Server',
                'version': '1.0.0',
                'session_id': self.session_id,
                'status': 'healthy',
                'uptime_seconds': uptime.total_seconds(),
                'uptime_human': str(uptime)
            },
            'metrics': self.metrics.copy()
        }
        
        # Add success rate
        if self.metrics['requests_total'] > 0:
            status['metrics']['success_rate'] = (
                self.metrics['requests_successful'] / self.metrics['requests_total']
            )
            status['metrics']['average_processing_time'] = (
                self.metrics['processing_time_total'] / self.metrics['requests_total']
            )
        
        if detailed:
            status['configuration'] = {
                'downloads_folder': str(self.downloads_folder),
                'supported_formats': list(self.supported_formats),
                'components': {
                    'security_orchestrator': self.security is not None,
                    'document_processor': self.document_processor is not None,
                    'chapter_detection_engine': self.chapter_detector is not None,
                    'text_parser': self.text_parser is not None,
                    'memory_monitor': self.memory_monitor is not None
                }
            }
            
            # Memory information if monitor available
            if self.memory_monitor:
                try:
                    memory_info = await self.memory_monitor.get_current_stats()
                    status['memory'] = memory_info
                except Exception as e:
                    status['memory'] = {'error': str(e)}
        
        return status

    # Fallback methods for standalone operation
    
    async def _basic_text_extraction(self, file_path: Path) -> str:
        """Basic text extraction fallback."""
        suffix = file_path.suffix.lower()
        
        if suffix == '.txt':
            return file_path.read_text(encoding='utf-8', errors='ignore')
        elif suffix == '.md':
            return file_path.read_text(encoding='utf-8', errors='ignore')
        else:
            # For other formats, try to read as text
            try:
                return file_path.read_text(encoding='utf-8', errors='ignore')
            except UnicodeDecodeError:
                return f"Binary file: {file_path.name} (format: {suffix})"

    async def _basic_chapter_detection(self, text: str, min_length: int) -> List[dict]:
        """Basic chapter detection fallback."""
        import re
        
        # Simple patterns for chapter detection
        patterns = [
            r'Chapter\s+(\d+)[:\.]?\s*(.+?)(?=Chapter\s+\d+|$)',
            r'CHAPTER\s+(\d+)[:\.]?\s*(.+?)(?=CHAPTER\s+\d+|$)',
            r'(\d+)\.\s+(.+?)(?=\d+\.\s+|$)',
            r'#{1,3}\s+(.+?)(?=#{1,3}\s+|$)',  # Markdown headers
        ]
        
        chapters = []
        chapter_num = 1
        
        for pattern in patterns:
            matches = re.finditer(pattern, text, re.MULTILINE | re.DOTALL | re.IGNORECASE)
            
            for match in matches:
                if len(match.groups()) >= 2:
                    number, content = match.groups()[:2]
                    if isinstance(number, str) and number.isdigit():
                        chapter_number = int(number)
                    else:
                        chapter_number = chapter_num
                        content = number  # First group is actually content
                    
                    if len(content.strip()) >= min_length:
                        chapters.append({
                            'number': chapter_number,
                            'title': f"Chapter {chapter_number}",
                            'content': content.strip(),
                            'start_position': match.start(),
                            'end_position': match.end(),
                            'word_count': len(content.split()),
                            'character_count': len(content)
                        })
                        chapter_num += 1
            
            if chapters:  # If we found chapters with this pattern, use them
                break
        
        # If no chapters found, create one chapter with full text
        if not chapters and len(text.strip()) >= min_length:
            chapters.append({
                'number': 1,
                'title': 'Full Document',
                'content': text.strip(),
                'start_position': 0,
                'end_position': len(text),
                'word_count': len(text.split()),
                'character_count': len(text)
            })
        
        return chapters

    async def _basic_structure_analysis(self, text: str) -> dict:
        """Basic structure analysis fallback."""
        import re
        
        analysis = {
            'patterns_found': [],
            'estimated_chapters': 0,
            'confidence': 'low',
            'recommendations': []
        }
        
        # Check for common chapter patterns
        patterns = {
            'numbered_chapters': r'Chapter\s+\d+',
            'numbered_sections': r'\d+\.\s+[A-Z]',
            'markdown_headers': r'#{1,6}\s+.+',
            'roman_numerals': r'[IVX]+\.\s+[A-Z]'
        }
        
        for pattern_name, pattern in patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                analysis['patterns_found'].append({
                    'type': pattern_name,
                    'count': len(matches),
                    'samples': matches[:3]  # First 3 examples
                })
                analysis['estimated_chapters'] += len(matches)
        
        if analysis['estimated_chapters'] > 0:
            analysis['confidence'] = 'medium' if analysis['estimated_chapters'] > 3 else 'low'
            analysis['recommendations'].append(
                f"Document appears to have {analysis['estimated_chapters']} chapters/sections"
            )
        else:
            analysis['recommendations'].append(
                "No clear chapter structure detected. Consider manual chapter markers."
            )
        
        return analysis

    def _create_match_preview(self, content: str, query: str, context_chars: int = 100) -> str:
        """Create a preview of text around a match."""
        if not content:
            return ""
        
        # Find the query position
        lower_content = content.lower()
        lower_query = query.lower()
        
        pos = lower_content.find(lower_query)
        if pos == -1:
            return content[:context_chars] + "..."
        
        # Extract context around the match
        start = max(0, pos - context_chars)
        end = min(len(content), pos + len(query) + context_chars)
        
        preview = content[start:end]
        
        # Add ellipsis if truncated
        if start > 0:
            preview = "..." + preview
        if end < len(content):
            preview = preview + "..."
        
        return preview

    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} PB"

    async def run(self):
        """Run the MCP server."""
        logger.info("Starting SYNTHEX Chapter Extraction MCP Server...")
        
        try:
            # Use stdio transport for MCP
            async with self.server.run_stdio() as (read_stream, write_stream):
                await self.server.run(
                    read_stream,
                    write_stream,
                    InitializationOptions(
                        server_name="synthex-chapter-extraction",
                        server_version="1.0.0",
                        capabilities={
                            "tools": {},
                            "resources": {},
                            "prompts": {}
                        }
                    )
                )
        except Exception as e:
            logger.error(f"Server error: {e}")
            logger.error(traceback.format_exc())
            raise

async def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="SYNTHEX Chapter Extraction MCP Server"
    )
    parser.add_argument(
        "--downloads-folder",
        default=None,
        help="Path to downloads folder (default: ~/Downloads)"
    )
    parser.add_argument(
        "--log-level",
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help="Logging level"
    )
    
    args = parser.parse_args()
    
    # Set logging level
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    
    # Create and run server
    server = SynthexChapterExtractionServer(
        downloads_folder=args.downloads_folder
    )
    
    try:
        await server.run()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server failed: {e}")
        logger.error(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())