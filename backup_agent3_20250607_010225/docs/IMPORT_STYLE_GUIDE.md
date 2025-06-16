# Import Style Guide for CODE Project

[Last Updated: 2025-05-31]
[Status: Active]

## Overview

This guide defines the import conventions for the Claude-Optimized Deployment Engine (CODE) project to ensure consistency and prevent import errors.

## Import Rules

### 1. Always Use Absolute Imports from `src/`

**✅ Correct:**
```python
from src.mcp.manager import get_mcp_manager
from src.circle_of_experts.core.expert_manager import EnhancedExpertManager
from src.platform.wsl_integration import WSLEnvironment
```

**❌ Incorrect:**
```python
from mcp.manager import get_mcp_manager  # Missing src prefix
from ..core.expert_manager import EnhancedExpertManager  # Relative import
from .utils import helper  # Relative import
```

### 2. Import Order

Follow this standard order (enforced by isort):

1. Standard library imports
2. Third-party imports
3. Local application imports (from src.*)

**Example:**
```python
# Standard library
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

# Third-party
import aiohttp
import pytest
from pydantic import BaseModel

# Local application
from src.mcp.manager import get_mcp_manager
from src.circle_of_experts.models.query import ExpertQuery
```

### 3. Module Organization

#### Required `__init__.py` Files

Every directory that contains Python modules must have an `__init__.py` file:

```
src/
├── __init__.py
├── mcp/
│   ├── __init__.py
│   ├── base/
│   │   └── __init__.py
│   └── servers.py
└── circle_of_experts/
    ├── __init__.py
    └── core/
        └── __init__.py
```

#### `__init__.py` Content

Define `__all__` to specify public API:

```python
# src/mcp/__init__.py
"""Model Context Protocol implementation."""

from src.mcp.manager import get_mcp_manager, MCPManager
from src.mcp.protocols import MCPTool, MCPError

__all__ = [
    "get_mcp_manager",
    "MCPManager", 
    "MCPTool",
    "MCPError",
]
```

### 4. Handling Import Errors

#### Optional Dependencies

For optional features, use try/except blocks:

```python
# Optional integration
try:
    from src.circle_of_experts.models.query import ExpertQuery
    CIRCLE_OF_EXPERTS_AVAILABLE = True
except ImportError:
    CIRCLE_OF_EXPERTS_AVAILABLE = False
    # Define placeholder if needed
    class ExpertQuery:
        pass
```

#### Test Imports

In test files, add src to path if needed:

```python
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.mcp.manager import get_mcp_manager
```

### 5. Cross-Module Imports

When importing between major modules (mcp, circle_of_experts, platform):

```python
# In src/circle_of_experts/mcp_integration.py
from src.mcp.manager import get_mcp_manager  # Cross-module import
from src.circle_of_experts.core.expert_manager import EnhancedExpertManager  # Same module
```

### 6. Circular Import Prevention

#### Problem Example:
```python
# src/mcp/manager.py
from src.circle_of_experts.core.expert_manager import ExpertManager

# src/circle_of_experts/core/expert_manager.py  
from src.mcp.manager import MCPManager  # Circular!
```

#### Solution:
- Use TYPE_CHECKING for type hints only
- Import inside functions/methods
- Restructure to remove circular dependency

```python
from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.mcp.manager import MCPManager

class ExpertManager:
    def get_mcp_manager(self) -> MCPManager:
        # Import here to avoid circular import
        from src.mcp.manager import get_mcp_manager
        return get_mcp_manager()
```

### 7. Import Validation

Run these commands to check imports:

```bash
# Check for import errors
python scripts/verify_imports.py

# Fix common import issues
python scripts/fix_all_imports.py

# Format imports with isort
make format
```

## Common Import Patterns

### 1. MCP Server Development
```python
from src.mcp.protocols import MCPTool, MCPToolParameter, MCPServerInfo, MCPCapabilities, MCPError
from src.mcp.servers import MCPServer

class MyCustomMCPServer(MCPServer):
    """Custom MCP server implementation."""
    pass
```

### 2. Circle of Experts Integration
```python
from src.circle_of_experts.core.expert_manager import EnhancedExpertManager
from src.circle_of_experts.models.query import ExpertQuery
from src.circle_of_experts.models.response import ExpertResponse
```

### 3. Cross-Feature Integration
```python
# Integrating MCP with Circle of Experts
from src.mcp.manager import get_mcp_manager
from src.circle_of_experts.mcp_integration import MCPEnhancedExpertManager
```

## Enforcement

These rules are enforced by:

1. **isort**: Automatic import sorting
2. **ruff**: Import linting
3. **mypy**: Type checking imports
4. **CI/CD**: Automated checks on pull requests

Run `make quality` to check all import rules before committing.

## Migration from Old Imports

If you encounter old-style imports:

1. Replace `from mcp.` with `from src.mcp.`
2. Replace `from circle_of_experts.` with `from src.circle_of_experts.`
3. Replace relative imports (`from ..module`) with absolute imports
4. Run `python scripts/fix_all_imports.py` to automatically fix most issues

## Troubleshooting

### ModuleNotFoundError

If you get `ModuleNotFoundError: No module named 'src'`:

1. Ensure you're running from the project root
2. Check that PYTHONPATH includes the project root
3. For scripts, add: `sys.path.insert(0, str(Path(__file__).parent.parent))`

### ImportError in Tests

For test files:
```python
# At the top of test file
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
```

### Circular Import Detected

1. Use TYPE_CHECKING for type hints
2. Move imports inside functions
3. Consider restructuring modules to break the cycle