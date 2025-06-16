"""
Command Input Sanitization Module for CODE Project.

Provides comprehensive input sanitization for command execution with:
- Path validation and normalization
- Argument sanitization
- Special character escaping
- Injection prevention
- Type validation
"""

import re
import os
import shlex
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union
from urllib.parse import urlparse
import ipaddress
import logging

from src.core.exceptions import ValidationError, SecurityError

logger = logging.getLogger(__name__)


class CommandSanitizer:
    """
    Comprehensive command input sanitization.
    
    Provides multiple layers of input validation and sanitization
    to prevent command injection and other security issues.
    """
    
    # Allowed characters in different contexts
    ALLOWED_PATH_CHARS = re.compile(r'^[a-zA-Z0-9._\-/\\:~]+$')
    ALLOWED_FILENAME_CHARS = re.compile(r'^[a-zA-Z0-9._\-]+$')
    ALLOWED_IDENTIFIER_CHARS = re.compile(r'^[a-zA-Z0-9_\-]+$')
    ALLOWED_ENV_VAR_NAME = re.compile(r'^[A-Z_][A-Z0-9_]*$')
    
    # Dangerous path patterns
    DANGEROUS_PATHS = [
        '/etc/passwd', '/etc/shadow', '/etc/sudoers',
        '/proc/', '/sys/', '/dev/',
        '~/.ssh/', '~/.aws/', '~/.kube/',
        '/root/', '/boot/', '/var/log/secure'
    ]
    
    # Special characters that need escaping in different contexts
    SHELL_SPECIAL_CHARS = set(';&|<>()$`\\\"\'{}[]!#*?~')
    SQL_SPECIAL_CHARS = set('\'"\\;--')
    
    # Maximum lengths for different input types
    MAX_PATH_LENGTH = 4096
    MAX_FILENAME_LENGTH = 255
    MAX_ARG_LENGTH = 1024
    MAX_ENV_VALUE_LENGTH = 4096
    
    @classmethod
    def sanitize_command_args(cls, args: List[str]) -> List[str]:
        """
        Sanitize a list of command arguments.
        
        Args:
            args: List of command arguments
            
        Returns:
            List of sanitized arguments
            
        Raises:
            ValidationError: If any argument is invalid
        """
        sanitized = []
        
        for i, arg in enumerate(args):
            if not isinstance(arg, str):
                raise ValidationError(
                    f"Argument {i} is not a string",
                    field=f"args[{i}]",
                    value=repr(arg)
                )
            
            # Check length
            if len(arg) > cls.MAX_ARG_LENGTH:
                raise ValidationError(
                    f"Argument {i} exceeds maximum length",
                    field=f"args[{i}]",
                    value=f"{arg[:50]}..."
                )
            
            # Sanitize the argument
            sanitized_arg = cls._sanitize_single_arg(arg)
            sanitized.append(sanitized_arg)
        
        return sanitized
    
    @classmethod
    def _sanitize_single_arg(cls, arg: str) -> str:
        """Sanitize a single command argument."""
        # Remove null bytes
        arg = arg.replace('\x00', '')
        
        # Check for command substitution attempts
        if any(pattern in arg for pattern in ['$(', '`', '${', '<(', '>(', '|', ';', '&']):
            # Quote the entire argument to prevent interpretation
            return shlex.quote(arg)
        
        # Check if argument looks like a path
        if arg.startswith('/') or arg.startswith('~') or '..' in arg:
            # Validate as path
            try:
                safe_path = cls.sanitize_path(arg, allow_relative=True)
                return safe_path
            except ValidationError:
                # Not a valid path, quote it
                return shlex.quote(arg)
        
        # Check if argument contains special characters
        if any(char in arg for char in cls.SHELL_SPECIAL_CHARS):
            return shlex.quote(arg)
        
        return arg
    
    @classmethod
    def sanitize_path(
        cls,
        path: str,
        base_dir: Optional[Path] = None,
        allow_relative: bool = False,
        must_exist: bool = False,
        allow_symlinks: bool = False
    ) -> str:
        """
        Sanitize and validate a file path.
        
        Args:
            path: Path to sanitize
            base_dir: Base directory to restrict paths to
            allow_relative: Allow relative paths
            must_exist: Path must exist
            allow_symlinks: Allow symbolic links
            
        Returns:
            Sanitized path string
            
        Raises:
            ValidationError: If path is invalid
            SecurityError: If path is dangerous
        """
        if not path:
            raise ValidationError("Empty path", field="path", value="")
        
        # Remove null bytes
        path = path.replace('\x00', '')
        
        # Check length
        if len(path) > cls.MAX_PATH_LENGTH:
            raise ValidationError(
                f"Path exceeds maximum length of {cls.MAX_PATH_LENGTH}",
                field="path",
                value=f"{path[:50]}..."
            )
        
        # Expand user and variables
        path = os.path.expanduser(path)
        path = os.path.expandvars(path)
        
        # Convert to Path object
        path_obj = Path(path)
        
        # Check for dangerous patterns
        for dangerous in cls.DANGEROUS_PATHS:
            if dangerous in str(path_obj):
                raise SecurityError(
                    f"Path contains dangerous pattern: {dangerous}",
                    context={"path": path}
                )
        
        # Handle relative paths
        if not path_obj.is_absolute():
            if not allow_relative:
                raise ValidationError(
                    "Relative paths not allowed",
                    field="path",
                    value=path
                )
            
            if base_dir:
                path_obj = base_dir / path_obj
            else:
                path_obj = Path.cwd() / path_obj
        
        # Resolve path (removes .. and symlinks)
        try:
            if allow_symlinks:
                resolved_path = path_obj.absolute()
            else:
                resolved_path = path_obj.resolve()
        except Exception as e:
            raise ValidationError(
                f"Invalid path: {str(e)}",
                field="path",
                value=path
            )
        
        # Check if path is within base directory
        if base_dir:
            base_dir = base_dir.resolve()
            try:
                resolved_path.relative_to(base_dir)
            except ValueError:
                raise SecurityError(
                    "Path is outside allowed directory",
                    context={"path": str(resolved_path), "base_dir": str(base_dir)}
                )
        
        # Check existence if required
        if must_exist and not resolved_path.exists():
            raise ValidationError(
                "Path does not exist",
                field="path",
                value=str(resolved_path)
            )
        
        # Check for symlink if not allowed
        if not allow_symlinks and resolved_path.is_symlink():
            raise SecurityError(
                "Symbolic links not allowed",
                context={"path": str(resolved_path)}
            )
        
        return str(resolved_path)
    
    @classmethod
    def sanitize_filename(cls, filename: str, allow_extensions: Optional[List[str]] = None) -> str:
        """
        Sanitize a filename.
        
        Args:
            filename: Filename to sanitize
            allow_extensions: List of allowed file extensions
            
        Returns:
            Sanitized filename
            
        Raises:
            ValidationError: If filename is invalid
        """
        if not filename:
            raise ValidationError("Empty filename", field="filename", value="")
        
        # Remove path components
        filename = os.path.basename(filename)
        
        # Remove null bytes
        filename = filename.replace('\x00', '')
        
        # Check length
        if len(filename) > cls.MAX_FILENAME_LENGTH:
            raise ValidationError(
                f"Filename exceeds maximum length of {cls.MAX_FILENAME_LENGTH}",
                field="filename",
                value=f"{filename[:50]}..."
            )
        
        # Check for directory traversal
        if '..' in filename or '/' in filename or '\\' in filename:
            raise ValidationError(
                "Filename contains path traversal characters",
                field="filename",
                value=filename
            )
        
        # Check allowed characters
        if not cls.ALLOWED_FILENAME_CHARS.match(filename):
            # Remove disallowed characters
            filename = re.sub(r'[^a-zA-Z0-9._\-]', '_', filename)
        
        # Check extension if specified
        if allow_extensions:
            ext = Path(filename).suffix.lower()
            if ext and ext not in allow_extensions:
                raise ValidationError(
                    f"File extension {ext} not allowed",
                    field="filename",
                    value=filename
                )
        
        # Prevent hidden files
        if filename.startswith('.'):
            filename = '_' + filename[1:]
        
        return filename
    
    @classmethod
    def sanitize_identifier(cls, identifier: str, allow_dash: bool = True) -> str:
        """
        Sanitize an identifier (e.g., container name, resource name).
        
        Args:
            identifier: Identifier to sanitize
            allow_dash: Allow dashes in identifier
            
        Returns:
            Sanitized identifier
            
        Raises:
            ValidationError: If identifier is invalid
        """
        if not identifier:
            raise ValidationError("Empty identifier", field="identifier", value="")
        
        # Remove null bytes
        identifier = identifier.replace('\x00', '')
        
        # Check length
        if len(identifier) > 253:  # DNS label limit
            raise ValidationError(
                "Identifier exceeds maximum length of 253",
                field="identifier",
                value=f"{identifier[:50]}..."
            )
        
        # Apply character restrictions
        if allow_dash:
            pattern = r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$'
        else:
            pattern = r'^[a-z0-9]+$'
        
        if not re.match(pattern, identifier.lower()):
            # Try to fix it
            identifier = identifier.lower()
            identifier = re.sub(r'[^a-z0-9\-]', '-' if allow_dash else '', identifier)
            identifier = re.sub(r'^-+|-+$', '', identifier)  # Remove leading/trailing dashes
            identifier = re.sub(r'-+', '-', identifier)  # Collapse multiple dashes
            
            if not identifier:
                raise ValidationError(
                    "Identifier contains only invalid characters",
                    field="identifier",
                    value=identifier
                )
        
        return identifier
    
    @classmethod
    def sanitize_environment_var(cls, name: str, value: str) -> Tuple[str, str]:
        """
        Sanitize environment variable name and value.
        
        Args:
            name: Variable name
            value: Variable value
            
        Returns:
            Tuple of (sanitized_name, sanitized_value)
            
        Raises:
            ValidationError: If name or value is invalid
        """
        # Sanitize name
        if not name:
            raise ValidationError("Empty environment variable name", field="name", value="")
        
        name = name.upper()
        if not cls.ALLOWED_ENV_VAR_NAME.match(name):
            raise ValidationError(
                "Invalid environment variable name",
                field="name",
                value=name
            )
        
        if len(name) > 64:
            raise ValidationError(
                "Environment variable name too long",
                field="name",
                value=name
            )
        
        # Sanitize value
        if len(value) > cls.MAX_ENV_VALUE_LENGTH:
            raise ValidationError(
                f"Environment variable value exceeds maximum length of {cls.MAX_ENV_VALUE_LENGTH}",
                field="value",
                value=f"{value[:50]}..."
            )
        
        # Remove null bytes
        value = value.replace('\x00', '')
        
        # Check for dangerous patterns in value
        dangerous_patterns = ['$(', '`', '${', '<(', '>(',]
        for pattern in dangerous_patterns:
            if pattern in value:
                # Escape the value
                value = shlex.quote(value)
                break
        
        return name, value
    
    @classmethod
    def sanitize_url(cls, url: str, allowed_schemes: Optional[List[str]] = None) -> str:
        """
        Sanitize and validate a URL.
        
        Args:
            url: URL to sanitize
            allowed_schemes: List of allowed URL schemes
            
        Returns:
            Sanitized URL
            
        Raises:
            ValidationError: If URL is invalid
        """
        if not url:
            raise ValidationError("Empty URL", field="url", value="")
        
        # Default allowed schemes
        if allowed_schemes is None:
            allowed_schemes = ['http', 'https', 'ftp', 'sftp']
        
        # Parse URL
        try:
            parsed = urlparse(url)
        except Exception as e:
            raise ValidationError(
                f"Invalid URL: {str(e)}",
                field="url",
                value=url
            )
        
        # Check scheme
        if parsed.scheme not in allowed_schemes:
            raise ValidationError(
                f"URL scheme '{parsed.scheme}' not allowed",
                field="url",
                value=url
            )
        
        # Check for localhost/private IPs
        if parsed.hostname:
            try:
                # Check if it's an IP address
                ip = ipaddress.ip_address(parsed.hostname)
                if ip.is_private or ip.is_loopback or ip.is_link_local:
                    raise SecurityError(
                        "URL points to private/local address",
                        context={"url": url, "ip": str(ip)}
                    )
            except ValueError:
                # Not an IP, check for localhost
                if parsed.hostname in ['localhost', '127.0.0.1', '::1']:
                    raise SecurityError(
                        "URL points to localhost",
                        context={"url": url}
                    )
        
        # Rebuild URL with only allowed components
        safe_url = f"{parsed.scheme}://"
        if parsed.username:
            # Don't include passwords in URLs
            safe_url += parsed.username + "@"
        safe_url += parsed.hostname or ""
        if parsed.port:
            safe_url += f":{parsed.port}"
        safe_url += parsed.path or "/"
        if parsed.query:
            safe_url += f"?{parsed.query}"
        
        return safe_url
    
    @classmethod
    def sanitize_docker_image(cls, image: str) -> str:
        """
        Sanitize Docker image name.
        
        Args:
            image: Docker image name
            
        Returns:
            Sanitized image name
            
        Raises:
            ValidationError: If image name is invalid
        """
        if not image:
            raise ValidationError("Empty image name", field="image", value="")
        
        # Docker image pattern
        pattern = re.compile(
            r'^(?:(?=[^:\/]{1,253})(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*(?::[0-9]{1,5})?/)?' +
            r'(?![._-])(?:[a-z0-9._-]*)(?<![._-])(?:/(?![._-])[a-z0-9._-]*(?<![._-]))*' +
            r'(?::(?![.-])[a-zA-Z0-9_.-]{1,128})?$'
        )
        
        if not pattern.match(image):
            raise ValidationError(
                "Invalid Docker image name",
                field="image",
                value=image
            )
        
        # Check for latest tag
        if image.endswith(':latest'):
            logger.warning(f"Using 'latest' tag for image: {image}")
        
        return image
    
    @classmethod
    def sanitize_k8s_name(cls, name: str, kind: str = "resource") -> str:
        """
        Sanitize Kubernetes resource name.
        
        Args:
            name: Resource name
            kind: Resource kind (for validation)
            
        Returns:
            Sanitized name
            
        Raises:
            ValidationError: If name is invalid
        """
        if not name:
            raise ValidationError(f"Empty {kind} name", field="name", value="")
        
        # Kubernetes DNS-1123 subdomain
        pattern = re.compile(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$')
        
        name = name.lower()
        
        if not pattern.match(name):
            # Try to fix it
            name = re.sub(r'[^a-z0-9\-.]', '-', name)
            name = re.sub(r'^[\-.]|[\-.]$', '', name)
            name = re.sub(r'[\-\.]+', '-', name)
            
            if not pattern.match(name):
                raise ValidationError(
                    f"Invalid Kubernetes {kind} name",
                    field="name",
                    value=name
                )
        
        # Check length
        if len(name) > 253:
            raise ValidationError(
                f"Kubernetes {kind} name exceeds 253 characters",
                field="name",
                value=f"{name[:50]}..."
            )
        
        return name
    
    @classmethod
    def escape_for_shell(cls, value: str) -> str:
        """
        Escape a value for safe shell usage.
        
        Args:
            value: Value to escape
            
        Returns:
            Escaped value
        """
        # Use shlex.quote for proper shell escaping
        return shlex.quote(value)
    
    @classmethod
    def escape_for_sql(cls, value: str) -> str:
        """
        Escape a value for SQL usage.
        
        Note: This is a basic escape. Use parameterized queries instead!
        
        Args:
            value: Value to escape
            
        Returns:
            Escaped value
        """
        # Basic SQL escaping - prefer parameterized queries!
        value = value.replace("'", "''")
        value = value.replace("\\", "\\\\")
        value = value.replace("\x00", "")
        value = value.replace("\n", "\
")
        value = value.replace("\r", "\\r")
        value = value.replace("\x1a", "\\Z")
        
        return value
    
    @classmethod
    def validate_command_context(
        cls,
        command: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Validate and sanitize command execution context.
        
        Args:
            command: Command being executed
            context: Execution context
            
        Returns:
            Sanitized context
            
        Raises:
            ValidationError: If context is invalid
        """
        sanitized_context = {}
        
        # Validate working directory
        if 'working_directory' in context:
            sanitized_context['working_directory'] = cls.sanitize_path(
                context['working_directory'],
                allow_relative=False,
                must_exist=True
            )
        
        # Validate environment variables
        if 'environment' in context:
            if not isinstance(context['environment'], dict):
                raise ValidationError(
                    "Environment must be a dictionary",
                    field="environment",
                    value=type(context['environment']).__name__
                )
            
            sanitized_env = {}
            for name, value in context['environment'].items():
                san_name, san_value = cls.sanitize_environment_var(str(name), str(value))
                sanitized_env[san_name] = san_value
            
            sanitized_context['environment'] = sanitized_env
        
        # Validate timeout
        if 'timeout' in context:
            timeout = context['timeout']
            if not isinstance(timeout, (int, float)) or timeout <= 0 or timeout > 3600:
                raise ValidationError(
                    "Timeout must be between 0 and 3600 seconds",
                    field="timeout",
                    value=timeout
                )
            sanitized_context['timeout'] = float(timeout)
        
        # Validate user
        if 'user' in context:
            user = str(context['user'])
            if not re.match(r'^[a-zA-Z0-9_\-@.]+$', user):
                raise ValidationError(
                    "Invalid username format",
                    field="user",
                    value=user
                )
            sanitized_context['user'] = user[:64]  # Limit length
        
        return sanitized_context


# Convenience functions
def sanitize_command_input(
    command: str,
    args: Optional[List[str]] = None,
    working_directory: Optional[str] = None,
    environment: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """
    Sanitize all inputs for command execution.
    
    Args:
        command: Command to execute
        args: Command arguments
        working_directory: Working directory
        environment: Environment variables
        
    Returns:
        Dictionary with sanitized inputs
        
    Raises:
        ValidationError: If any input is invalid
    """
    result = {
        'command': command  # Command itself is validated by executor
    }
    
    # Sanitize arguments
    if args:
        result['args'] = CommandSanitizer.sanitize_command_args(args)
    
    # Build context and validate
    context = {}
    if working_directory:
        context['working_directory'] = working_directory
    if environment:
        context['environment'] = environment
    
    if context:
        sanitized_context = CommandSanitizer.validate_command_context(command, context)
        result.update(sanitized_context)
    
    return result