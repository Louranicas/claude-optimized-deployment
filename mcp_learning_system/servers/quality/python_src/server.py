#!/usr/bin/env python3
"""Quality MCP Server - Simple stub for testing"""

import asyncio
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class QualityMCPServer:
    """Simple Quality MCP Server stub"""
    
    def __init__(self):
        self.name = "quality"
        self.port = 8003
        
    async def start(self):
        """Start the server"""
        logger.info(f"Quality MCP Server starting on port {self.port}")
        # Keep running
        while True:
            await asyncio.sleep(1)

async def main():
    server = QualityMCPServer()
    await server.start()

if __name__ == "__main__":
    asyncio.run(main())