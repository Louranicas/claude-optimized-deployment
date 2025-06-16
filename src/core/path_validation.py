"""
Path validation utilities for secure file operations.

Provides functions to validate file paths and prevent directory traversal attacks.
"""

import os
from pathlib import Path
from typing import Optional, Union
import logging

from src.core.exceptions import ValidationError

__all__ = [
    "validate_file_path",
    "is_safe_path",
    "sanitize_filename"
]


logger = logging.getLogger(__name__)


def validate_file_path(
    file_path: Union[str, Path],
    base_directory: Optional[Union[str, Path]] = None,
    allow_absolute: bool = False,
    allow_symlinks: bool = False
) -> Path:
    """
    Validate a file path to prevent directory traversal attacks.
    
    Args:
        file_path: The file path to validate
        base_directory: Optional base directory to restrict access to
        allow_absolute: Whether to allow absolute paths
        allow_symlinks: Whether to allow symbolic links
        
    Returns:
        Path: The validated path object
        
    Raises:
        ValidationError: If the path is invalid or potentially malicious
    """
    # Convert to Path object
    path = Path(file_path)
    
    # Check for null bytes
    if '\0' in str(file_path):
        raise ValidationError(
            "Invalid path: contains null bytes",
            field="file_path",
            value=str(file_path)
        )
    
    # Check for directory traversal patterns
    path_str = str(file_path)
    dangerous_patterns = [
        '..',  # Parent directory
        '..\\',  # Windows parent directory
        '../',  # Unix parent directory
        '\\..\\',  # Windows traversal
        '/../',  # Unix traversal
        '%2e%2e',  # URL encoded ..
        '%252e%252e',  # Double URL encoded ..
        '..%2f',  # Partial URL encoding
        '..%5c',  # URL encoded backslash
    ]
    
    for pattern in dangerous_patterns:
        if pattern in path_str.lower():
            raise ValidationError(
                f"Invalid path: contains directory traversal pattern '{pattern}'",
                field="file_path",
                value=str(file_path)
            )
    
    # Resolve the path (follows symlinks and makes it absolute)
    try:
        # Use os.path.realpath to get the real path
        resolved_path = Path(os.path.realpath(str(path)))
    except (OSError, RuntimeError) as e:
        raise ValidationError(
            f"Invalid path: cannot resolve path - {str(e)}",
            field="file_path",
            value=str(file_path)
        )
    
    # Check if path is absolute when not allowed
    if not allow_absolute and path.is_absolute():
        raise ValidationError(
            "Invalid path: absolute paths are not allowed",
            field="file_path",
            value=str(file_path)
        )
    
    # Check symlinks if not allowed
    if not allow_symlinks and path.exists() and path.is_symlink():
        raise ValidationError(
            "Invalid path: symbolic links are not allowed",
            field="file_path",
            value=str(file_path)
        )
    
    # If base directory is specified, ensure the path is within it
    if base_directory:
        # Use os.path.realpath for base directory too
        base_path = Path(os.path.realpath(str(base_directory)))
        
        # Make sure base directory exists
        if not base_path.exists():
            raise ValidationError(
                f"Base directory does not exist: {base_directory}",
                field="base_directory",
                value=str(base_directory)
            )
        
        # Check if resolved path starts with base directory
        resolved_str = str(resolved_path)
        base_str = str(base_path)
        if not resolved_str.startswith(base_str):
            raise ValidationError(
                f"Invalid path: must be within base directory '{base_path}'",
                field="file_path",
                value=str(file_path)
            )
    
    # Additional security checks
    
    # Check for special file names that might be dangerous
    dangerous_names = [
        'con', 'prn', 'aux', 'nul',  # Windows reserved names
        'com1', 'com2', 'com3', 'com4', 'com5', 'com6', 'com7', 'com8', 'com9',
        'lpt1', 'lpt2', 'lpt3', 'lpt4', 'lpt5', 'lpt6', 'lpt7', 'lpt8', 'lpt9',
    ]
    
    name_lower = path.name.lower()
    stem_lower = path.stem.lower() if path.stem else ""
    
    if name_lower in dangerous_names or stem_lower in dangerous_names:
        raise ValidationError(
            f"Invalid path: contains reserved system name '{path.name}'",
            field="file_path",
            value=str(file_path)
        )
    
    # Check for hidden files (optional - could be a parameter)
    if path.name.startswith('.') and path.name != '.':
        logger.warning(f"Path validation: hidden file requested: {path.name}")
    
    # Log successful validation for security auditing
    logger.debug(f"Path validated successfully: {resolved_path}")
    
    return resolved_path


def is_safe_path(file_path: Union[str, Path], base_directory: Optional[Union[str, Path]] = None) -> bool:
    """
    Check if a path is safe without raising exceptions.
    
    Args:
        file_path: The file path to check
        base_directory: Optional base directory to restrict access to
        
    Returns:
        bool: True if the path is safe, False otherwise
    """
    try:
        validate_file_path(file_path, base_directory)
        return True
    except ValidationError:
        return False


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to remove potentially dangerous characters.
    
    Args:
        filename: The filename to sanitize
        
    Returns:
        str: The sanitized filename
    """
    # Remove any path components
    filename = os.path.basename(filename)
    
    # Remove dangerous characters
    dangerous_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|', '\0', '
', '\r', '\t']
    for char in dangerous_chars:
        filename = filename.replace(char, '_')
    
    # Remove leading/trailing dots and spaces
    filename = filename.strip('. ')
    
    # If filename is empty or just dots, provide a default
    if not filename or filename == '.' or filename == '..':
        filename = 'unnamed_file'
    
    # Limit length
    max_length = 255
    if len(filename) > max_length:
        # Preserve extension if possible
        parts = filename.rsplit('.', 1)
        if len(parts) == 2 and len(parts[1]) < 10:  # Reasonable extension length
            name_part = parts[0][:max_length - len(parts[1]) - 1]
            filename = f"{name_part}.{parts[1]}"
        else:
            filename = filename[:max_length]
    
    return filename