# MCP Server Authentication Implementation

## Overview

This document describes the authentication implementation added to the MCP (Model Context Protocol) server base class in `src/mcp/protocols.py`. The implementation provides:

1. **Authentication requirement** for tool execution via `@require_auth` decorator
2. **Fine-grained permission checking** for different operations (list, read, execute)
3. **Resource-based access control** with tool-specific permissions
4. **Comprehensive error handling** for unauthorized access
5. **Audit logging** for security monitoring

## Key Components

### 1. Enhanced MCPServer Base Class

The `MCPServer` class in `src/mcp/protocols.py` now includes:

```python
class MCPServer:
    """Base class for MCP servers with built-in authentication."""
    
    def __init__(self, name: str, version: str = "1.0.0", 
                 permission_checker: Optional[PermissionChecker] = None):
        # ... initialization with permission checker
```

### 2. Authentication Decorators

- `@require_auth`: Ensures user authentication before tool execution
- Permission checking integrated into all operations

### 3. Permission Structure

Default permissions for each MCP server:
- `mcp.{server_name}:list` - List available tools
- `mcp.{server_name}:read` - Get server information
- `mcp.{server_name}:execute` - Execute tools

Tool-specific permissions:
- `mcp.{server_name}.{tool_name}:execute` - Execute specific tool

### 4. Method Changes

#### get_server_info(user: Optional[User] = None)
- Now accepts optional user parameter
- Checks read permission if user provided

#### get_tools(user: Optional[User] = None)
- Accepts optional user parameter
- Filters tools based on user permissions

#### call_tool(tool_name, arguments, user, context)
- **Requires authentication** via `@require_auth` decorator
- Checks execution permissions at server and tool level
- Logs all operations for auditing
- Passes user context to tool implementation

## Implementation Details

### Permission Checking Flow

1. **Authentication Check**: Ensures user is provided
2. **Server-level Permission**: Checks `mcp.{server}:execute`
3. **Tool-level Permission**: Checks tool-specific permission
4. **Context Validation**: Applies contextual rules (IP, environment, etc.)
5. **Execution**: Calls `_call_tool_impl` with user context
6. **Audit Logging**: Records success/failure

### Error Handling

- `AuthenticationError`: No user provided when required
- `PermissionDeniedError`: User lacks necessary permissions
- Detailed error messages include permission requirements

### Backward Compatibility

- Servers can operate without permission checker (logs warning)
- Optional user parameter maintains compatibility
- Existing implementations need minimal changes

## Usage Example

```python
# Initialize with permission checker
permission_checker = PermissionChecker(rbac_manager)
server = BraveMCPServer(permission_checker=permission_checker)

# Register permissions
server.register_resource_permissions()

# Call tool with authentication
result = await server.call_tool(
    "brave_web_search",
    {"query": "test"},
    user=authenticated_user,
    context={"client_ip": "192.168.1.1"}
)
```

## Security Benefits

1. **Access Control**: Fine-grained permissions for each operation
2. **Audit Trail**: All operations logged with user context
3. **Context-Aware**: Supports IP restrictions, environment checks
4. **Role-Based**: Integrates with RBAC system
5. **Tool Isolation**: Different permissions for different tools

## Migration Guide

To update existing MCP servers:

1. Update constructor to accept `permission_checker`
2. Call `super().__init__()` with server name and permission checker
3. Rename `get_tools()` to `_get_all_tools()`
4. Rename `call_tool()` to `_call_tool_impl()` and add user parameter
5. Set up tool-specific permissions in `__init__`
6. Call `register_resource_permissions()` if permission checker available

## Testing

Run the test script to verify authentication:

```bash
python test_mcp_auth.py
```

This demonstrates:
- Authentication requirements
- Permission checking
- Admin vs user access
- Context-based permissions
- Error handling