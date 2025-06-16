#!/usr/bin/env python3
'''
SYNTHEX Chapter Extraction MCP Server Launcher
'''

import sys
import os
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

try:
    from src.mcp.synthex_chapter_extraction.server import SynthexChapterExtractionServer
    
    if __name__ == "__main__":
        print("🚀 Starting SYNTHEX Chapter Extraction MCP Server...")
        server = SynthexChapterExtractionServer()
        print(f"📁 Monitoring: {server.downloads_folder}")
        print(f"🎯 Session ID: {server.session_id}")
        print("✅ Server ready for MCP connections")
        
        # Keep server running
        import asyncio
        asyncio.run(server.run())
        
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("💡 Try running: python deploy_synthex_server.py")
    sys.exit(1)
except Exception as e:
    print(f"❌ Server error: {e}")
    sys.exit(1)
