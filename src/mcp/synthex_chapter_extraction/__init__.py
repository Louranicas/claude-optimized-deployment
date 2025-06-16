"""
SYNTHEX Chapter Extraction MCP Server
====================================

A specialized native MCP server for the CORE environment that extracts chapters 
from any text document in any format from the downloads folder.

This package provides comprehensive text processing capabilities with:
- Multi-format support (PDF, EPUB, DOCX, TXT, MD, HTML)
- Advanced chapter detection algorithms
- Enterprise-grade security and performance optimization
- Integration with existing CORE infrastructure
- Real-time file monitoring and processing

Components:
-----------
- server.py: Main MCP server implementation
- config.py: Configuration management
- utils.py: Utility functions and helpers
- __main__.py: CLI entry point

Usage:
------
    python -m src.mcp.synthex_chapter_extraction

Or import as library:
    from src.mcp.synthex_chapter_extraction import SynthexChapterExtractionServer

Author: SYNTHEX Collaborative Intelligence
Version: 1.0.0
License: MIT
"""

from .server import SynthexChapterExtractionServer

__version__ = "1.0.0"
__author__ = "SYNTHEX Collaborative Intelligence"
__email__ = "synthex@claude-optimized-deployment.ai"
__license__ = "MIT"

__all__ = [
    'SynthexChapterExtractionServer'
]

# Package metadata
PACKAGE_INFO = {
    'name': 'synthex-chapter-extraction',
    'version': __version__,
    'description': 'SYNTHEX Chapter Extraction MCP Server for CORE Environment',
    'author': __author__,
    'license': __license__,
    'supported_formats': [
        'pdf', 'epub', 'docx', 'doc', 'txt', 'md', 
        'html', 'htm', 'rtf', 'odt', 'tex'
    ],
    'capabilities': [
        'chapter_extraction',
        'document_analysis', 
        'batch_processing',
        'search_functionality',
        'real_time_monitoring',
        'security_validation',
        'performance_optimization'
    ]
}

def get_package_info():
    """Get package information."""
    return PACKAGE_INFO.copy()

def get_supported_formats():
    """Get list of supported document formats."""
    return PACKAGE_INFO['supported_formats'].copy()

def get_capabilities():
    """Get list of server capabilities."""
    return PACKAGE_INFO['capabilities'].copy()