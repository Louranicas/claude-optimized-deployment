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
from datetime import datetime, timedelta
import weakref
from collections import defaultdict

from src.mcp.protocols import (
    MCPRequest, MCPResponse, MCPNotification, MCPError,
    MCPMethod, MCPServerInfo, MCPCapabilities
)
from src.core.retry import retry_network, RetryConfig

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
        return await self._send_request_with_retry(request)
    
    @retry_network(max_attempts=3, timeout=30)
    async def _send_request_with_retry(self, request: MCPRequest) -> MCPResponse:
        """Send HTTP request with retry logic."""
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
        await self._send_notification_with_retry(notification)
    
    @retry_network(max_attempts=3, timeout=30)
    async def _send_notification_with_retry(self, notification: MCPNotification) -> None:
        """Send notification with retry logic."""
        if not self.session:
            await self.connect()
        
        url = f"{self.base_url}/mcp"
        
        async with self.session.post(url, json=notification.dict()) as resp:
            # Notifications don't expect responses
            pass


class WebSocketTransport(MCPTransport):
    """WebSocket transport for MCP."""
    
    def __init__(self, ws_url: str, headers: Optional[Dict[str, str]] = None,
                 handler_timeout_seconds: int = 300,
                 max_response_handlers: int = 1000):
        self.ws_url = ws_url
        self.headers = headers or {}
        self.ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Response handlers with timeout-based cleanup
        self._response_handlers: Dict[str, asyncio.Future] = {}
        self._handler_timestamps: Dict[str, datetime] = {}
        self.handler_timeout_seconds = handler_timeout_seconds
        self.max_response_handlers = max_response_handlers
        
        # Notification handler with weak reference
        self._notification_handler: Optional[weakref.ref] = None
        self._receive_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        self._is_connected = False
    
    async def _cleanup_expired_handlers(self) -> None:
        """Clean up expired response handlers to prevent memory leaks."""
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.handler_timeout_seconds)
        
        expired_ids = [
            request_id for request_id, timestamp in self._handler_timestamps.items()
            if timestamp < cutoff_time
        ]
        
        for request_id in expired_ids:
            future = self._response_handlers.pop(request_id, None)
            if future and not future.done():
                future.cancel()
            self._handler_timestamps.pop(request_id, None)
        
        if expired_ids:
            logger.warning(f"Cleaned up {len(expired_ids)} expired response handlers")
    
    async def _force_cleanup_handlers(self) -> None:
        """Force cleanup of oldest handlers when limit is reached."""
        if len(self._response_handlers) >= self.max_response_handlers:
            # Sort by timestamp and remove oldest 25%
            sorted_handlers = sorted(
                self._handler_timestamps.items(),
                key=lambda x: x[1]
            )
            cleanup_count = len(sorted_handlers) // 4
            
            for request_id, _ in sorted_handlers[:cleanup_count]:
                future = self._response_handlers.pop(request_id, None)
                if future and not future.done():
                    future.cancel()
                self._handler_timestamps.pop(request_id, None)
            
            logger.warning(f"Force cleaned up {cleanup_count} response handlers due to limit")
    
    async def _start_periodic_cleanup(self) -> None:
        """Start periodic cleanup of expired handlers."""
        async def cleanup_loop():
            while self._is_connected:
                try:
                    await asyncio.sleep(60)  # Clean up every minute
                    await self._cleanup_expired_handlers()
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Handler cleanup error: {e}")
        
        self._cleanup_task = asyncio.create_task(cleanup_loop())
    
    async def connect(self) -> None:
        """Establish WebSocket connection."""
        await self._connect_with_retry()
    
    @retry_network(max_attempts=3, timeout=30)
    async def _connect_with_retry(self) -> None:
        """Establish WebSocket connection with retry logic."""
        if not self.session:
            self.session = aiohttp.ClientSession()
        
        self.ws = await self.session.ws_connect(self.ws_url, headers=self.headers)
        self._receive_task = asyncio.create_task(self._receive_loop())
        await self._start_periodic_cleanup()
    
    async def disconnect(self) -> None:
        """Close WebSocket connection and clean up handlers."""
        self._is_connected = False
        
        # Cancel background tasks
        if self._receive_task:
            self._receive_task.cancel()
            try:
                await self._receive_task
            except asyncio.CancelledError:
                pass
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        # Clean up all pending handlers
        for future in self._response_handlers.values():
            if not future.done():
                future.cancel()
        self._response_handlers.clear()
        self._handler_timestamps.clear()
        
        # Close connections
        if self.ws:
            await self.ws.close()
        
        if self.session:
            await self.session.close()
    
    async def send_request(self, request: MCPRequest) -> MCPResponse:
        """Send request via WebSocket with handler cleanup."""
        if not self.ws:
            raise MCPError(-32000, "WebSocket not connected")
        
        # Clean up expired handlers before adding new one
        await self._cleanup_expired_handlers()
        
        # Check if we have too many handlers
        if len(self._response_handlers) >= self.max_response_handlers:
            # Force cleanup of oldest handlers
            await self._force_cleanup_handlers()
        
        # Create future for response
        future = asyncio.Future()
        request_id = str(request.id)
        self._response_handlers[request_id] = future
        self._handler_timestamps[request_id] = datetime.now()
        
        # Send request
        await self.ws.send_str(json.dumps(request.dict()))
        
        # Wait for response
        try:
            response_data = await asyncio.wait_for(future, timeout=30.0)
            return MCPResponse(**response_data)
        except asyncio.TimeoutError:
            # Clean up on timeout
            self._response_handlers.pop(request_id, None)
            self._handler_timestamps.pop(request_id, None)
            raise MCPError(-32000, "Request timeout")
        finally:
            # Always clean up after response
            self._response_handlers.pop(request_id, None)
            self._handler_timestamps.pop(request_id, None)
    
    async def send_notification(self, notification: MCPNotification) -> None:
        """Send notification via WebSocket."""
        if not self.ws:
            raise MCPError(-32000, "WebSocket not connected")
        
        await self.ws.send_str(json.dumps(notification.dict()))
    
    async def _receive_loop(self) -> None:
        """Receive messages from WebSocket with memory management."""
        self._is_connected = True
        while self._is_connected and self.ws and not self.ws.closed:
            try:
                msg = await self.ws.receive()
                
                if msg.type == aiohttp.WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    
                    # Handle response
                    if "id" in data and str(data["id"]) in self._response_handlers:
                        request_id = str(data["id"])
                        future = self._response_handlers.pop(request_id, None)
                        self._handler_timestamps.pop(request_id, None)
                        if future and not future.done():
                            future.set_result(data)
                    
                    # Handle notification
                    elif "method" in data and not "id" in data:
                        if self._notification_handler:
                            handler = self._notification_handler()
                            if handler:
                                await handler(MCPNotification(**data))
                            else:
                                # Clean up dead weak reference
                                self._notification_handler = None
                
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    logger.error(f"WebSocket error: {msg.data}")
                    break
                
                elif msg.type == aiohttp.WSMsgType.CLOSED:
                    break
                    
            except Exception as e:
                logger.error(f"Error in receive loop: {e}")
                break
        
        self._is_connected = False
    
    def set_notification_handler(self, handler: Callable) -> None:
        """Set handler for notifications using weak reference."""
        if hasattr(handler, '__self__'):
            self._notification_handler = weakref.ref(handler)
        else:
            # For functions without self, store directly
            self._notification_handler = lambda: handler


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
