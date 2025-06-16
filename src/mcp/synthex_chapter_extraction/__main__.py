#!/usr/bin/env python3
"""
SYNTHEX Chapter Extraction MCP Server - CLI Entry Point
======================================================

Command-line interface for the SYNTHEX Chapter Extraction MCP Server.

Usage:
    python -m src.mcp.synthex_chapter_extraction [options]

Examples:
    # Start server with default settings
    python -m src.mcp.synthex_chapter_extraction
    
    # Specify custom downloads folder
    python -m src.mcp.synthex_chapter_extraction --downloads-folder /path/to/documents
    
    # Enable debug logging
    python -m src.mcp.synthex_chapter_extraction --log-level DEBUG
    
    # Show version information
    python -m src.mcp.synthex_chapter_extraction --version

Author: SYNTHEX Collaborative Intelligence
Version: 1.0.0
"""

import asyncio
import argparse
import logging
import sys
from pathlib import Path

from . import __version__, PACKAGE_INFO
from .server import SynthexChapterExtractionServer


def create_parser():
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog='synthex-chapter-extraction',
        description='SYNTHEX Chapter Extraction MCP Server for CORE Environment',
        epilog=f'Version {__version__} - SYNTHEX Collaborative Intelligence',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Server configuration
    parser.add_argument(
        '--downloads-folder',
        type=str,
        default=None,
        help='Path to downloads folder (default: ~/Downloads)'
    )
    
    # Logging configuration
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help='Set logging level (default: INFO)'
    )
    
    parser.add_argument(
        '--log-file',
        type=str,
        default=None,
        help='Log file path (default: logs to stdout and /tmp/synthex_mcp_server.log)'
    )
    
    # Development options
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode (equivalent to --log-level DEBUG)'
    )
    
    parser.add_argument(
        '--validate-config',
        action='store_true',
        help='Validate configuration and exit'
    )
    
    # Information options
    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {__version__}'
    )
    
    parser.add_argument(
        '--info',
        action='store_true',
        help='Show package information and capabilities'
    )
    
    parser.add_argument(
        '--test-connection',
        action='store_true',
        help='Test MCP connection and exit'
    )
    
    return parser


def setup_logging(level: str, log_file: str = None, debug: bool = False):
    """Set up logging configuration."""
    if debug:
        level = 'DEBUG'
    
    log_level = getattr(logging, level.upper())
    
    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(log_level)
    
    # Clear existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Create formatter
    formatter = logging.Formatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        file_handler = logging.FileHandler(log_file, mode='a')
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    else:
        # Default file handler
        try:
            default_file_handler = logging.FileHandler('/tmp/synthex_mcp_server.log', mode='a')
            default_file_handler.setLevel(log_level)
            default_file_handler.setFormatter(formatter)
            logger.addHandler(default_file_handler)
        except (PermissionError, OSError):
            # Ignore if can't write to /tmp
            pass


def validate_configuration(args):
    """Validate configuration settings."""
    errors = []
    warnings = []
    
    # Validate downloads folder
    if args.downloads_folder:
        downloads_path = Path(args.downloads_folder)
        if not downloads_path.exists():
            errors.append(f"Downloads folder does not exist: {downloads_path}")
        elif not downloads_path.is_dir():
            errors.append(f"Downloads folder is not a directory: {downloads_path}")
        elif not os.access(downloads_path, os.R_OK):
            errors.append(f"No read permission for downloads folder: {downloads_path}")
    else:
        # Check default downloads folder
        default_downloads = Path.home() / "Downloads"
        if not default_downloads.exists():
            warnings.append(f"Default downloads folder does not exist: {default_downloads}")
    
    # Validate log file
    if args.log_file:
        log_path = Path(args.log_file)
        log_dir = log_path.parent
        if not log_dir.exists():
            try:
                log_dir.mkdir(parents=True, exist_ok=True)
            except OSError as e:
                errors.append(f"Cannot create log directory {log_dir}: {e}")
        elif not os.access(log_dir, os.W_OK):
            errors.append(f"No write permission for log directory: {log_dir}")
    
    return errors, warnings


def show_package_info():
    """Display package information and capabilities."""
    print(f"\n{PACKAGE_INFO['name']} v{PACKAGE_INFO['version']}")\n    print("=" * 50)\n    print(f"Description: {PACKAGE_INFO['description']}")\n    print(f"Author: {PACKAGE_INFO['author']}")\n    print(f"License: {PACKAGE_INFO['license']}")\n\n    print(f"\nSupported Formats ({len(PACKAGE_INFO['supported_formats'])}):")\n    for fmt in PACKAGE_INFO['supported_formats']:\n        print(f"  • {fmt.upper()}")\n\n    print(f"\nCapabilities ({len(PACKAGE_INFO['capabilities'])}):")\n    for capability in PACKAGE_INFO['capabilities']:\n        print(f"  • {capability.replace('_', ' ').title()}")\n\n    print(f"\nMCP Tools:")\n    tools = [\n        "extract_chapters - Extract chapters from documents",\n        "list_documents - List all supported documents",\n        "analyze_document_structure - Analyze document structure",\n        "batch_extract - Process multiple documents",\n        "search_chapters - Search within extracted chapters",\n        "get_server_status - Get server status and metrics"\n    ]\n    for tool in tools:\n        print(f"  • {tool}")\n\n    print()\n\n\nasync def test_mcp_connection():\n    """Test MCP connection functionality."""\n    print("Testing MCP connection...")\n\n    try:\n        # Create server instance\n        server = SynthexChapterExtractionServer()\n\n        # Test basic functionality\n        print("✓ Server instance created successfully")\n\n        # Test downloads folder access\n        if server.downloads_folder.exists():\n            print(f"✓ Downloads folder accessible: {server.downloads_folder}")\n        else:\n            print(f"⚠ Downloads folder not found: {server.downloads_folder}")\n\n        # Test component initialization\n        components = [\n            ('Security Orchestrator', server.security),\n            ('Document Processor', server.document_processor),\n            ('Chapter Detector', server.chapter_detector),\n            ('Text Parser', server.text_parser),\n            ('Memory Monitor', server.memory_monitor)\n        ]\n\n        for name, component in components:\n            if component:\n                print(f"✓ {name}: Available")\n            else:\n                print(f"⚠ {name}: Not available (fallback mode)")\n\n        print("✓ MCP connection test completed successfully")\n        return True\n\n    except Exception as e:\n        print(f"✗ MCP connection test failed: {e}")\n        import traceback\n        traceback.print_exc()\n        return False\n\n\nasync def main():\n    """Main entry point."""\n    parser = create_parser()\n    args = parser.parse_args()\n\n    # Setup logging early\n    setup_logging(args.log_level, args.log_file, args.debug)\n    logger = logging.getLogger(__name__)\n\n    try:\n        # Handle information requests\n        if args.info:\n            show_package_info()\n            return 0\n\n        # Validate configuration\n        if args.validate_config or args.test_connection:\n            errors, warnings = validate_configuration(args)\n\n            if warnings:\n                for warning in warnings:\n                    print(f"WARNING: {warning}")\n\n            if errors:\n                for error in errors:\n                    print(f"ERROR: {error}")\n                return 1\n\n            print("✓ Configuration validation passed")\n\n            if args.validate_config:\n                return 0\n\n        # Test connection\n        if args.test_connection:\n            success = await test_mcp_connection()\n            return 0 if success else 1\n\n        # Start the server\n        logger.info(f"Starting SYNTHEX Chapter Extraction MCP Server v{__version__}")\n\n        server = SynthexChapterExtractionServer(\n            downloads_folder=args.downloads_folder\n        )\n\n        await server.run()\n\n    except KeyboardInterrupt:\n        logger.info("Server stopped by user (Ctrl+C)")\n        return 0\n    except Exception as e:\n        logger.error(f"Server failed to start: {e}")\n        if args.debug:\n            import traceback\n            traceback.print_exc()\n        return 1\n\n\ndef cli_main():\n    """CLI entry point for setuptools."""\n    import os\n\n    # Ensure we can import the module\n    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))\n\n    try:\n        exit_code = asyncio.run(main())\n        sys.exit(exit_code)\n    except Exception as e:\n        print(f"Failed to start server: {e}")\n        sys.exit(1)\n\n\nif __name__ == "__main__":\n    cli_main()