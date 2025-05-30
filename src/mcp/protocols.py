"""
MCP Protocol definitions and data models.

Based on the Model Context Protocol specification for tool integration.
"""

from __future__ import annotations
from typing import Dict, Any, List, Optional, Union
from enum import Enum
from pydantic import BaseModel, Field
from datetime import datetime
import uuid


class MCPMessageType(str, Enum):
    """MCP message types."""
    REQUEST = "request"
    RESPONSE = "response"
    NOTIFICATION = "notification"
    ERROR = "error"


class MCPMethod(str, Enum):
    """Standard MCP methods."""
    # Tool methods
    TOOLS_LIST = "tools/list"
    TOOLS_CALL = "tools/call"
    
    # Resource methods
    RESOURCES_LIST = "resources/list"
    RESOURCES_READ = "resources/read"
    
    # Prompt methods
    PROMPTS_LIST = "prompts/list"
    PROMPTS_GET = "prompts/get"
    
    # Server methods
    INITIALIZE = "initialize"
    SHUTDOWN = "shutdown"
    PING = "ping"


class MCPToolParameter(BaseModel):
    """Parameter definition for MCP tools."""
    name: str
    type: str = "string"
    description: Optional[str] = None
    required: bool = True
    enum: Optional[List[str]] = None
    default: Optional[Any] = None


class MCPTool(BaseModel):
    """MCP tool definition."""
    name: str
    description: str
    parameters: List[MCPToolParameter] = Field(default_factory=list)
    returns: Optional[Dict[str, Any]] = None
    examples: Optional[List[Dict[str, Any]]] = None
    
    def to_claude_format(self) -> Dict[str, Any]:
        """Convert to Claude tool format."""
        properties = {}
        required = []
        
        for param in self.parameters:
            properties[param.name] = {
                "type": param.type,
                "description": param.description or ""
            }
            if param.enum:
                properties[param.name]["enum"] = param.enum
            if param.default is not None:
                properties[param.name]["default"] = param.default
            
            if param.required:
                required.append(param.name)
        
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": {
                "type": "object",
                "properties": properties,
                "required": required
            }
        }


class MCPRequest(BaseModel):
    """MCP request message."""
    jsonrpc: str = "2.0"
    id: Union[str, int] = Field(default_factory=lambda: str(uuid.uuid4()))
    method: str
    params: Optional[Dict[str, Any]] = None
    
    class Config:
        use_enum_values = True


class MCPResponse(BaseModel):
    """MCP response message."""
    jsonrpc: str = "2.0"
    id: Union[str, int]
    result: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None
    
    @property
    def is_error(self) -> bool:
        """Check if response is an error."""
        return self.error is not None
    
    def raise_for_error(self) -> None:
        """Raise exception if response contains error."""
        if self.error:
            raise MCPError(
                code=self.error.get("code", -1),
                message=self.error.get("message", "Unknown error"),
                data=self.error.get("data")
            )


class MCPNotification(BaseModel):
    """MCP notification message."""
    jsonrpc: str = "2.0"
    method: str
    params: Optional[Dict[str, Any]] = None


class MCPError(Exception):
    """MCP protocol error."""
    def __init__(self, code: int, message: str, data: Optional[Any] = None):
        self.code = code
        self.message = message
        self.data = data
        super().__init__(f"MCP Error {code}: {message}")


class MCPCapabilities(BaseModel):
    """Server capabilities."""
    tools: bool = True
    resources: bool = False
    prompts: bool = False
    experimental: Dict[str, Any] = Field(default_factory=dict)


class MCPServerInfo(BaseModel):
    """MCP server information."""
    name: str
    version: str
    description: Optional[str] = None
    capabilities: MCPCapabilities = Field(default_factory=MCPCapabilities)


class BraveSearchResult(BaseModel):
    """Brave search result model."""
    title: str
    url: str
    description: str
    snippet: Optional[str] = None
    date: Optional[datetime] = None
    thumbnail: Optional[str] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class BraveSearchResponse(BaseModel):
    """Brave search response model."""
    query: str
    results: List[BraveSearchResult]
    total_results: Optional[int] = None
    search_time: Optional[float] = None
    
    def to_mcp_response(self, request_id: Union[str, int]) -> MCPResponse:
        """Convert to MCP response format."""
        return MCPResponse(
            id=request_id,
            result={
                "query": self.query,
                "results": [r.dict() for r in self.results],
                "metadata": {
                    "total_results": self.total_results,
                    "search_time": self.search_time
                }
            }
        )
