#!/usr/bin/env python3
"""
Script to update MCP modules to use centralized error handling.
"""

import re
import logging
from pathlib import Path
from typing import List, Tuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def update_mcp_modules():
    """Update MCP modules to use centralized error handling."""
    mcp_files = [
        "/home/louranicas/projects/claude-optimized-deployment/src/mcp/client.py",
        "/home/louranicas/projects/claude-optimized-deployment/src/mcp/manager.py",
        "/home/louranicas/projects/claude-optimized-deployment/src/mcp/servers.py",
        "/home/louranicas/projects/claude-optimized-deployment/src/mcp/protocols.py",
        "/home/louranicas/projects/claude-optimized-deployment/src/mcp/devops_servers.py",
        "/home/louranicas/projects/claude-optimized-deployment/src/mcp/infrastructure_servers.py",
        "/home/louranicas/projects/claude-optimized-deployment/src/mcp/communication/hub_server.py",
        "/home/louranicas/projects/claude-optimized-deployment/src/mcp/communication/slack_server.py",
        "/home/louranicas/projects/claude-optimized-deployment/src/mcp/monitoring/prometheus_server.py",
        "/home/louranicas/projects/claude-optimized-deployment/src/mcp/storage/cloud_storage_server.py",
        "/home/louranicas/projects/claude-optimized-deployment/src/mcp/storage/s3_server.py",
        "/home/louranicas/projects/claude-optimized-deployment/src/mcp/infrastructure/commander_server.py",
        "/home/louranicas/projects/claude-optimized-deployment/src/mcp/security/auth_middleware.py",
        "/home/louranicas/projects/claude-optimized-deployment/src/mcp/security/sast_server.py"
    ]
    
    for file_path in mcp_files:
        path = Path(file_path)
        if path.exists():
            logger.info(f"Updating {path.name} to use centralized error handling...")
            update_file_with_error_handler(path)


def update_file_with_error_handler(file_path: Path):
    """Update a file to use the centralized error handler."""
    content = file_path.read_text()
    
    # Check if already using error handler
    if "from src.core.error_handler import" in content:
        logger.debug(f"{file_path.name} already uses error handler")
        return
    
    # Find where to insert the import
    lines = content.split('\n')
    import_index = -1
    
    # Look for the last import statement
    for i, line in enumerate(lines):
        if line.strip() and (line.startswith('import ') or line.startswith('from ')):
            import_index = i
    
    # If no imports found, insert after module docstring
    if import_index == -1:
        for i, line in enumerate(lines):
            if line.strip() and not line.startswith('"""') and not line.startswith('#'):
                import_index = i - 1
                break
    
    # Determine which error types are needed based on file content
    error_imports = ["handle_errors", "async_handle_errors", "log_error"]
    
    if "service" in content.lower() or "server" in file_path.name:
        error_imports.extend(["ServiceUnavailableError", "ExternalServiceError"])
    
    if "validation" in content.lower() or "validate" in content.lower():
        error_imports.append("ValidationError")
    
    if "config" in content.lower():
        error_imports.append("ConfigurationError")
    
    if "circuit" in content.lower() and "breaker" in content.lower():
        error_imports.append("CircuitBreakerError")
    
    if "rate" in content.lower() and "limit" in content.lower():
        error_imports.append("RateLimitError")
    
    # Build import statement
    error_handler_import = f"\nfrom src.core.error_handler import (\n    {',\\n    '.join(error_imports)}\n)"
    
    # Insert the import
    if import_index >= 0:
        lines.insert(import_index + 1, error_handler_import)
    
    # Write back
    file_path.write_text('\n'.join(lines))
    logger.info(f"Updated {file_path.name} with error handler")


def main():
    """Main function."""
    logger.info("Updating MCP modules to use centralized error handling...")
    update_mcp_modules()
    logger.info("Completed updating MCP modules!")


if __name__ == "__main__":
    main()