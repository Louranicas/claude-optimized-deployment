#!/usr/bin/env python3
"""
Script to update auth modules to use centralized error handling.
"""

import re
import logging
from pathlib import Path
from typing import List, Tuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def update_auth_modules():
    """Update auth modules to use centralized error handling."""
    auth_files = [
        "/home/louranicas/projects/claude-optimized-deployment/src/auth/api.py",
        "/home/louranicas/projects/claude-optimized-deployment/src/auth/audit.py",
        "/home/louranicas/projects/claude-optimized-deployment/src/auth/middleware.py",
        "/home/louranicas/projects/claude-optimized-deployment/src/auth/models.py",
        "/home/louranicas/projects/claude-optimized-deployment/src/auth/tokens.py",
        "/home/louranicas/projects/claude-optimized-deployment/src/auth/user_manager.py",
        "/home/louranicas/projects/claude-optimized-deployment/src/auth/permissions.py",
        "/home/louranicas/projects/claude-optimized-deployment/src/auth/rbac.py",
        "/home/louranicas/projects/claude-optimized-deployment/src/auth/mcp_integration.py",
        "/home/louranicas/projects/claude-optimized-deployment/src/auth/experts_integration.py"
    ]
    
    for file_path in auth_files:
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
    error_imports = ["handle_errors", "async_handle_errors"]
    
    if "authentication" in content.lower() or "auth" in file_path.name:
        error_imports.extend(["AuthenticationError", "AuthorizationError"])
    
    if "validation" in content.lower() or "validate" in content.lower():
        error_imports.append("ValidationError")
    
    if "database" in content.lower() or "db" in content.lower():
        error_imports.append("DatabaseError")
    
    if "not found" in content.lower() or "404" in content:
        error_imports.append("ResourceNotFoundError")
    
    if "rate" in content.lower() and "limit" in content.lower():
        error_imports.append("RateLimitError")
    
    # Always include logging function
    error_imports.append("log_error")
    
    # Build import statement
    error_handler_import = f"\nfrom src.core.error_handler import (\n    {',\\n    '.join(error_imports)}\n)"
    
    # Insert the import
    if import_index >= 0:
        lines.insert(import_index + 1, error_handler_import)
    
    # Replace common exception patterns
    updated_content = '\n'.join(lines)
    
    # Replace HTTPException with appropriate custom exceptions
    if "HTTPException" in updated_content:
        updated_content = updated_content.replace(
            "from fastapi import HTTPException",
            "from fastapi import HTTPException  # Consider using custom error classes"
        )
    
    # Replace generic Exception raises with custom ones
    updated_content = re.sub(
        r'raise Exception\("([^"]+)"\)',
        r'raise ValidationError("\1")',
        updated_content
    )
    
    # Add @handle_errors decorator to functions that might benefit
    # This is a conservative approach - only add to functions with try/except
    lines = updated_content.split('\n')
    updated_lines = []
    
    for i, line in enumerate(lines):
        updated_lines.append(line)
        
        # Look for function definitions followed by try/except
        if line.strip().startswith('def ') and not line.strip().startswith('def __'):
            # Check if the next few lines contain try/except
            has_try_except = False
            for j in range(i + 1, min(i + 20, len(lines))):
                if lines[j].strip().startswith('try:'):
                    has_try_except = True
                    break
                elif lines[j].strip().startswith('def '):
                    break
            
            # Add decorator if function has try/except and doesn't already have it
            if has_try_except:
                # Check if previous line is already a decorator
                prev_line_idx = i - 1
                while prev_line_idx >= 0 and not lines[prev_line_idx].strip():
                    prev_line_idx -= 1
                
                if prev_line_idx >= 0 and not lines[prev_line_idx].strip().startswith('@'):
                    # Add the decorator with proper indentation
                    indent = len(line) - len(line.lstrip())
                    updated_lines.insert(len(updated_lines) - 1, ' ' * indent + '@handle_errors()')
    
    # Write back
    file_path.write_text('\n'.join(updated_lines))
    logger.info(f"Updated {file_path.name} with error handler")


def main():
    """Main function."""
    logger.info("Updating auth modules to use centralized error handling...")
    update_auth_modules()
    logger.info("Completed updating auth modules!")


if __name__ == "__main__":
    main()