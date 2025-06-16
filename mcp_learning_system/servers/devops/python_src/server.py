#!/usr/bin/env python3
"""DevOps MCP Server - Simple stub for testing"""

import asyncio
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DevOpsMCPServer:
    """Simple DevOps MCP Server stub"""
    
    def __init__(self):
        self.name = "devops"
        self.port = 8002
        
    async def start(self):
        """Start the server"""
        logger.info(f"DevOps MCP Server starting on port {self.port}")
        # Keep running
        while True:
            await asyncio.sleep(1)

async def main():
    server = DevOpsMCPServer()
    await server.start()

if __name__ == "__main__":
    asyncio.run(main())