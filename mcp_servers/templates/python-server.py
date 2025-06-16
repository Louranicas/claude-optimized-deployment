"""
Python MCP Server Template

This template provides a complete example of how to implement
an MCP server using the standardized Python base class.
"""

import asyncio
import json
import uuid
import time
from datetime import datetime
from typing import Any, Dict, Optional, List
from dataclasses import dataclass, field

from mcp import Tool, Resource
from ..src.core.base_server import BaseMCPServer, MCPServerOptions, HealthCheck, CheckStatus


@dataclass
class TemplateServerConfig:
    """Server-specific configuration options"""
    api_endpoint: str = "https://api.example.com"
    api_key: str = ""
    max_retries: int = 3
    cache_enabled: bool = True


class TemplateServer(BaseMCPServer):
    """
    Template MCP Server
    
    Replace 'TemplateServer' with your actual server name and implement
    the required abstract methods with your specific business logic.
    """
    
    def __init__(self, options: MCPServerOptions, server_config: Optional[TemplateServerConfig] = None):
        super().__init__(options)
        
        # Load server-specific configuration
        self.config = server_config or TemplateServerConfig()
        
        # Override with environment variables
        import os
        self.config.api_key = os.getenv('TEMPLATE_API_KEY', self.config.api_key)
        self.config.api_endpoint = os.getenv('TEMPLATE_API_ENDPOINT', self.config.api_endpoint)
        
        self.logger.info(f"Template server initialized", extra={
            "config": {
                "api_endpoint": self.config.api_endpoint,
                "api_key": "***" if self.config.api_key else "",
                "max_retries": self.config.max_retries,
                "cache_enabled": self.config.cache_enabled,
            }
        })
    
    async def setup_tools(self) -> None:
        """
        Setup server-specific tools
        
        Register all tools that this server provides.
        Each tool should have a clear name, description, and input schema.
        """
        
        # Example tool: Echo
        echo_tool = Tool(
            name="echo",
            description="Echo back the provided message",
            inputSchema={
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "The message to echo back",
                    },
                    "uppercase": {
                        "type": "boolean",
                        "description": "Whether to convert the message to uppercase",
                        "default": False,
                    },
                },
                "required": ["message"],
            },
        )
        self.register_tool(echo_tool)
        
        # Example tool: API Call
        api_call_tool = Tool(
            name="api_call",
            description="Make a call to the configured API endpoint",
            inputSchema={
                "type": "object",
                "properties": {
                    "endpoint": {
                        "type": "string",
                        "description": "API endpoint path (relative to base URL)",
                    },
                    "method": {
                        "type": "string",
                        "enum": ["GET", "POST", "PUT", "DELETE"],
                        "default": "GET",
                        "description": "HTTP method to use",
                    },
                    "data": {
                        "type": "object",
                        "description": "Request body data for POST/PUT requests",
                    },
                },
                "required": ["endpoint"],
            },
        )
        self.register_tool(api_call_tool)
        
        # Example tool: Generate UUID
        generate_uuid_tool = Tool(
            name="generate_uuid",
            description="Generate a random UUID",
            inputSchema={
                "type": "object",
                "properties": {
                    "version": {
                        "type": "number",
                        "enum": [1, 4],
                        "default": 4,
                        "description": "UUID version to generate",
                    },
                },
            },
        )
        self.register_tool(generate_uuid_tool)
        
        self.logger.info(f"Registered {len(self.tools)} tools")
    
    async def setup_resources(self) -> None:
        """
        Setup server-specific resources
        
        Register all resources that this server provides.
        Resources can be files, data endpoints, or any readable content.
        """
        
        # Example resource: Server info
        server_info_resource = Resource(
            uri="template://server/info",
            name="Server Information",
            description="Information about this server instance",
            mimeType="application/json",
        )
        self.register_resource(server_info_resource)
        
        # Example resource: Configuration
        config_resource = Resource(
            uri="template://server/config",
            name="Server Configuration",
            description="Current server configuration (sanitized)",
            mimeType="application/json",
        )
        self.register_resource(config_resource)
        
        # Example resource: Logs
        logs_resource = Resource(
            uri="template://server/logs",
            name="Server Logs",
            description="Recent server log entries",
            mimeType="text/plain",
        )
        self.register_resource(logs_resource)
        
        self.logger.info(f"Registered {len(self.resources)} resources")
    
    async def execute_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        """
        Execute a tool with the given arguments
        
        This method is called when a client wants to execute one of
        the tools registered by this server.
        """
        start_time = time.time()
        
        try:
            if name == "echo":
                return await self._execute_echo_tool(arguments)
            elif name == "api_call":
                return await self._execute_api_call_tool(arguments)
            elif name == "generate_uuid":
                return await self._execute_generate_uuid_tool(arguments)
            else:
                raise ValueError(f"Unknown tool: {name}")
        finally:
            duration = (time.time() - start_time) * 1000  # Convert to milliseconds
            self.logger.info(f"Tool execution completed", extra={
                "tool_name": name,
                "duration": duration,
                "arguments": arguments,
            })
    
    async def read_resource_content(self, uri: str) -> Dict[str, Any]:
        """
        Read resource content
        
        This method is called when a client wants to read the content
        of one of the resources registered by this server.
        """
        start_time = time.time()
        
        try:
            if uri == "template://server/info":
                return {
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": json.dumps({
                        "name": self.options.name,
                        "version": self.options.version,
                        "description": self.options.description,
                        "uptime": self.metrics.uptime,
                        "request_count": self.metrics.request_count,
                        "tool_count": len(self.tools),
                        "resource_count": len(self.resources),
                    }, indent=2),
                }
            
            elif uri == "template://server/config":
                return {
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": json.dumps({
                        "api_endpoint": self.config.api_endpoint,
                        "api_key": "***" if self.config.api_key else "",
                        "max_retries": self.config.max_retries,
                        "cache_enabled": self.config.cache_enabled,
                    }, indent=2),
                }
            
            elif uri == "template://server/logs":
                return {
                    "uri": uri,
                    "mimeType": "text/plain",
                    "text": "Log entries would be retrieved from your logging system here...",
                }
            
            else:
                raise ValueError(f"Unknown resource: {uri}")
        
        finally:
            duration = (time.time() - start_time) * 1000  # Convert to milliseconds
            self.logger.info(f"Resource read completed", extra={
                "uri": uri,
                "duration": duration,
            })
    
    async def cleanup(self) -> None:
        """
        Cleanup resources before shutdown
        
        Perform any necessary cleanup operations before the server shuts down.
        """
        self.logger.info("Performing cleanup...")
        
        # Close database connections, file handles, etc.
        # Cancel ongoing operations
        # Save state if necessary
        
        self.logger.info("Cleanup completed")
    
    # ========================================================================
    # Tool Implementation Methods
    # ========================================================================
    
    async def _execute_echo_tool(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the echo tool"""
        message = args.get("message", "")
        uppercase = args.get("uppercase", False)
        
        self.logger.info("Executing echo tool", extra={
            "message_length": len(message),
            "uppercase": uppercase,
        })
        
        processed_message = message.upper() if uppercase else message
        
        return {
            "echo": processed_message,
            "original_length": len(message),
            "processed_at": datetime.now().isoformat(),
        }
    
    async def _execute_api_call_tool(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the API call tool"""
        endpoint = args.get("endpoint", "")
        method = args.get("method", "GET")
        data = args.get("data")
        
        self.logger.info("Executing API call tool", extra={
            "endpoint": endpoint,
            "method": method,
        })
        
        # Validate API key
        if not self.config.api_key:
            raise ValueError("API key not configured")
        
        url = f"{self.config.api_endpoint}{endpoint}"
        
        # Simulate API call (replace with actual HTTP client)
        response = {
            "url": url,
            "method": method,
            "data": data,
            "timestamp": datetime.now().isoformat(),
            "simulated": True,
            "message": "This is a simulated API response. Replace with actual HTTP client implementation.",
        }
        
        self.logger.info("API call completed", extra={
            "url": url,
            "method": method,
            "response_size": len(json.dumps(response)),
        })
        
        return response
    
    async def _execute_generate_uuid_tool(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the UUID generation tool"""
        version = args.get("version", 4)
        
        self.logger.info("Generating UUID", extra={"version": version})
        
        if version == 4:
            # Generate UUID v4 (random)
            generated_uuid = str(uuid.uuid4())
        elif version == 1:
            # Generate UUID v1 (timestamp-based)
            generated_uuid = str(uuid.uuid1())
        else:
            raise ValueError(f"Unsupported UUID version: {version}")
        
        return {
            "uuid": generated_uuid,
            "version": version,
            "generated_at": datetime.now().isoformat(),
        }
    
    # ========================================================================
    # Custom Health Checks
    # ========================================================================
    
    def setup_custom_health_checks(self) -> None:
        """Add custom health checks specific to this server"""
        
        def api_connectivity_check() -> HealthCheck:
            """Check API connectivity"""
            try:
                # Simulate API health check
                healthy = bool(self.config.api_key)
                
                return HealthCheck(
                    name="api_connectivity",
                    status=CheckStatus.PASS if healthy else CheckStatus.FAIL,
                    message="API is accessible" if healthy else "API key not configured",
                )
            except Exception as e:
                return HealthCheck(
                    name="api_connectivity",
                    status=CheckStatus.FAIL,
                    message=f"API health check failed: {str(e)}",
                )
        
        def configuration_check() -> HealthCheck:
            """Check configuration validity"""
            issues = []
            
            if not self.config.api_endpoint:
                issues.append("API endpoint not configured")
            
            if not self.config.api_key:
                issues.append("API key not configured")
            
            status = CheckStatus.PASS if not issues else CheckStatus.WARN
            message = "Configuration is valid" if not issues else f"Configuration issues: {', '.join(issues)}"
            
            return HealthCheck(
                name="configuration",
                status=status,
                message=message,
            )
        
        self.add_health_check("api_connectivity", api_connectivity_check)
        self.add_health_check("configuration", configuration_check)


# ============================================================================
# Server Factory and Startup
# ============================================================================

async def create_template_server(config: Optional[TemplateServerConfig] = None) -> TemplateServer:
    """Create and configure a template server instance"""
    
    # Create server instance
    server = TemplateServer(
        options=MCPServerOptions(
            name="template-server",
            version="1.0.0",
            description="A template MCP server demonstrating best practices",
        ),
        server_config=config,
    )
    
    # Setup custom health checks
    server.setup_custom_health_checks()
    
    return server


async def main() -> None:
    """Main entry point for the server"""
    try:
        server = await create_template_server()
        
        # Setup graceful shutdown
        import signal
        
        def signal_handler(signum, frame):
            asyncio.create_task(server.graceful_shutdown())
        
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        
        # Start the server
        await server.start()
        
        print("Template MCP Server started successfully")
        
    except Exception as error:
        print(f"Failed to start Template MCP Server: {error}")
        import sys
        sys.exit(1)


# Run the server if this file is executed directly
if __name__ == "__main__":
    asyncio.run(main())