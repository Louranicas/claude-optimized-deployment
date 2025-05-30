"""
MCP Client implementation for connecting to MCP servers.
"""

from __future__ import annotations
import asyncio
import json
import logging
from typing import Dict, Any, Optional, List, Callable
import aiohttp
from abc import ABC, abstractmethod

from .protocols import (
    MCPRequest, MCPResponse, MCPNotification, MCPError,
    MCPMethod, MCPServerInfo, MCPCapabilities
)

logger = logging.getLogger(__name__)


class MCPTransport(ABC):
    """Abstract base class for MCP transport mechanisms."""
    
    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to MCP server."""
        pass
    
    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection to MCP server."""
        pass
    
    @abstractmethod
    async def send_request(self, request: MCPRequest) -> MCPResponse:
        """Send request and wait for response."""
        pass
    
    @abstractmethod
    async def send_notification(self, notification: MCPNotification) -> None:
        """Send notification (no response expected)."""
        pass


class HTTPTransport(MCPTransport):
    """HTTP/HTTPS transport for MCP."""
    
    def __init__(self, base_url: str, headers: Optional[Dict[str, str]] = None):
        self.base_url = base_url.rstrip('/')
        self.headers = headers or {}
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def connect(self) -> None:
        """Create HTTP session."""
        if not self.session:
            self.session = aiohttp.ClientSession(headers=self.headers)
    
    async def disconnect(self) -> None:
        """Close HTTP session."""
        if self.session:
            await self.session.close()
            self.session = None
    
    async def send_request(self, request: MCPRequest) -> MCPResponse:
        """Send HTTP request to MCP server."""
        if not self.session:
            await self.connect()
        
        url = f"{self.base_url}/mcp"
        
        async with self.session.post(url, json=request.dict()) as resp:
            if resp.status != 200:
                raise MCPError(
                    code=-32000,
                    message=f"HTTP error {resp.status}",
                    data=await resp.text()
                )
            
            data = await resp.json()
            return MCPResponse(**data)
    
    async def send_notification(self, notification: MCPNotification) -> None:
        """Send notification via HTTP POST."""
        if not self.session:
            await self.connect()
        
        url = f"{self.base_url}/mcp"
        
        async with self.session.post(url, json=notification.dict()) as resp:
            # Notifications don't expect responses
            pass


class WebSocketTransport(MCPTransport):
    """WebSocket transport for MCP."""
    
    def __init__(self, ws_url: str, headers: Optional[Dict[str, str]] = None):
        self.ws_url = ws_url
        self.headers = headers or {}
        self.ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self.session: Optional[aiohttp.ClientSession] = None
        self._response_handlers: Dict[str, asyncio.Future] = {}
        self._notification_handler: Optional[Callable] = None
        self._receive_task: Optional[asyncio.Task] = None
    
    async def connect(self) -> None:
        """Establish WebSocket connection."""
        if not self.session:
            self.session = aiohttp.ClientSession()
        
        self.ws = await self.session.ws_connect(self.ws_url, headers=self.headers)
        self._receive_task = asyncio.create_task(self._receive_loop())
    
    async def disconnect(self) -> None:
        """Close WebSocket connection."""
        if self._receive_task:
            self._receive_task.cancel()
        
        if self.ws:
            await self.ws.close()
        
        if self.session:
            await self.session.close()
    
    async def send_request(self, request: MCPRequest) -> MCPResponse:
        """Send request via WebSocket."""
        if not self.ws:
            raise MCPError(-32000, "WebSocket not connected")
        
        # Create future for response
        future = asyncio.Future()
        self._response_handlers[str(request.id)] = future
        
        # Send request
        await self.ws.send_str(json.dumps(request.dict()))
        
        # Wait for response
        try:
            response_data = await asyncio.wait_for(future, timeout=30.0)
            return MCPResponse(**response_data)
        except asyncio.TimeoutError:
            del self._response_handlers[str(request.id)]
            raise MCPError(-32000, "Request timeout")
    
    async def send_notification(self, notification: MCPNotification) -> None:
        """Send notification via WebSocket."""
        if not self.ws:
            raise MCPError(-32000, "WebSocket not connected")
        
        await self.ws.send_str(json.dumps(notification.dict()))
    
    async def _receive_loop(self) -> None:
        """Receive messages from WebSocket."""
        while self.ws and not self.ws.closed:
            try:
                msg = await self.ws.receive()
                
                if msg.type == aiohttp.WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    
                    # Handle response
                    if "id" in data and str(data["id"]) in self._response_handlers:
                        future = self._response_handlers.pop(str(data["id"]))
                        future.set_result(data)
                    
                    # Handle notification
                    elif "method" in data and not "id" in data:
                        if self._notification_handler:
                            await self._notification_handler(MCPNotification(**data))
                
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    logger.error(f"WebSocket error: {msg.data}")
                    break
                
                elif msg.type == aiohttp.WSMsgType.CLOSED:
                    break
                    
            except Exception as e:
                logger.error(f"Error in receive loop: {e}")
                break
    
    def set_notification_handler(self, handler: Callable) -> None:
        """Set handler for notifications."""
        self._notification_handler = handler


class MCPClient:
    """MCP client for communicating with MCP servers."""
    
    def __init__(self, transport: MCPTransport):
        """
        Initialize MCP client.
        
        Args:
            transport: Transport mechanism for MCP communication
        """
        self.transport = transport
        self.server_info: Optional[MCPServerInfo] = None
        self._tools_cache: Optional[List[Dict[str, Any]]] = None
    
    async def connect(self) -> None:
        """Connect to MCP server and initialize."""
        await self.transport.connect()
        
        # Send initialize request
        request = MCPRequest(
            method=MCPMethod.INITIALIZE,
            params={
                "protocolVersion": "1.0",
                "clientInfo": {
                    "name": "CODE-MCP-Client",
                    "version": "0.1.0"
                }
            }
        )
        
        response = await self.transport.send_request(request)
        response.raise_for_error()
        
        # Store server info
        if response.result:
            self.server_info = MCPServerInfo(**response.result.get("serverInfo", {}))
            logger.info(f"Connected to MCP server: {self.server_info.name}")
    
    async def disconnect(self) -> None:
        """Disconnect from MCP server."""
        try:
            # Send shutdown notification
            notification = MCPNotification(method=MCPMethod.SHUTDOWN)
            await self.transport.send_notification(notification)
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
        
        await self.transport.disconnect()
    
    async def list_tools(self) -> List[Dict[str, Any]]:
        """List available tools from MCP server."""
        if self._tools_cache is not None:
            return self._tools_cache
        
        request = MCPRequest(method=MCPMethod.TOOLS_LIST)
        response = await self.transport.send_request(request)
        response.raise_for_error()
        
        self._tools_cache = response.result.get("tools", [])
        return self._tools_cache
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """
        Call a tool on the MCP server.
        
        Args:
            tool_name: Name of the tool to call
            arguments: Arguments to pass to the tool
            
        Returns:
            Tool execution result
        """
        request = MCPRequest(
            method=MCPMethod.TOOLS_CALL,
            params={
                "name": tool_name,
                "arguments": arguments
            }
        )
        
        response = await self.transport.send_request(request)
        response.raise_for_error()
        
        return response.result
    
    async def ping(self) -> bool:
        """Ping the MCP server to check connectivity."""
        try:
            request = MCPRequest(method=MCPMethod.PING)
            response = await self.transport.send_request(request)
            return not response.is_error
        except Exception:
            return False
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.disconnect()
