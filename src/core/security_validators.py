"""
Security Validators Module - Comprehensive Input Validation for CODE
By: The Greatest Synthetic Distinguished Cybersecurity Synthetic Being in History

This module provides centralized, reusable validation functions to prevent:
- Command injection
- SQL/NoSQL injection  
- XSS attacks
- Path traversal
- SSRF attacks
- File upload vulnerabilities
- API parameter tampering
"""

import re
import os
import ipaddress
import mimetypes
import hashlib
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional, Union, Set
from urllib.parse import urlparse, quote
import json
import yaml
from functools import lru_cache
import logging

logger = logging.getLogger(__name__)


class SecurityValidators:
    """Comprehensive security validation utilities"""
    
    # Safe command whitelist for execution
    SAFE_COMMANDS = {
        'ls', 'pwd', 'date', 'echo', 'cat', 'grep', 'find', 'df', 'du',
        'ps', 'top', 'whoami', 'hostname', 'uname', 'id', 'env'
    }
    
    # Dangerous command patterns
    DANGEROUS_PATTERNS = [
        r'[;&|`$]',  # Command separators and substitution
        r'\$\(',      # Command substitution
        r'\$\{',      # Variable expansion
        r'&&|\|\|',   # Command chaining
        r'>|<|>>',    # Redirection
        r'\\\n',      # Line continuation
        r'[\x00-\x1f\x7f-\x9f]',  # Control characters
    ]
    
    # SQL injection patterns
    SQL_INJECTION_PATTERNS = [
        r"(\b(union|select|insert|update|delete|drop|create|alter|exec|execute|script|javascript)\b)",
        r"(--|#|\/\*|\*\/|@@|@)",
        r"(\bor\b\s*\d+\s*=\s*\d+)",
        r"(\band\b\s*\d+\s*=\s*\d+)",
        r"(\'|\"|;|\\x[0-9a-fA-F]{2})",
        r"(\b(char|nchar|varchar|nvarchar|concat|cast|convert)\b\s*\()",
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'on\w+\s*=',
        r'<iframe[^>]*>',
        r'<object[^>]*>',
        r'<embed[^>]*>',
        r'<img[^>]*src[^>]*javascript:',
        r'<svg[^>]*onload\s*=',
    ]
    
    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r'\.\.[/\\]',
        r'\.\.%2[fF]',
        r'\.\.%5[cC]',
        r'%2[eE]%2[eE][%2[fF]%5[cC]]',
        r'/etc/passwd',
        r'c:\\windows',
        r'c:\\winnt',
    ]
    
    # Safe file extensions
    SAFE_FILE_EXTENSIONS = {
        '.txt', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.png', '.jpg', 
        '.jpeg', '.gif', '.csv', '.json', '.xml', '.zip', '.gz', '.tar'
    }
    
    # Maximum file sizes (in bytes)
    MAX_FILE_SIZES = {
        'default': 10 * 1024 * 1024,      # 10MB
        'image': 5 * 1024 * 1024,         # 5MB
        'document': 20 * 1024 * 1024,     # 20MB
        'archive': 50 * 1024 * 1024,      # 50MB
    }
    
    # Private IP ranges
    PRIVATE_IP_RANGES = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('169.254.0.0/16'),
        ipaddress.ip_network('fc00::/7'),
        ipaddress.ip_network('fe80::/10'),
    ]
    
    @classmethod
    def validate_command_injection(cls, command: str, allow_args: bool = False) -> Optional[str]:
        """
        Validate command to prevent injection attacks
        
        Args:
            command: Command string to validate
            allow_args: Whether to allow command arguments
            
        Returns:
            Sanitized command or None if invalid
        """
        if not command or not isinstance(command, str):
            return None
            
        # Remove leading/trailing whitespace
        command = command.strip()
        
        # Check for dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                logger.warning(f"Dangerous pattern detected in command: {pattern}")
                return None
        
        # Split command and arguments
        parts = command.split()
        if not parts:
            return None
            
        base_command = parts[0]
        
        # Check if command is in whitelist
        if base_command not in cls.SAFE_COMMANDS:
            logger.warning(f"Command not in whitelist: {base_command}")
            return None
            
        # If args not allowed, return just the command
        if not allow_args:
            return base_command
            
        # Validate arguments
        safe_args = []
        for arg in parts[1:]:
            # Check each argument for dangerous patterns
            if any(re.search(p, arg) for p in cls.DANGEROUS_PATTERNS):
                logger.warning(f"Dangerous pattern in argument: {arg}")
                return None
            safe_args.append(quote(arg))
            
        return f"{base_command} {' '.join(safe_args)}"
    
    @classmethod
    def validate_sql_injection(cls, query_param: str) -> bool:
        """
        Check if input contains SQL injection patterns
        
        Args:
            query_param: Query parameter to validate
            
        Returns:
            True if safe, False if injection detected
        """
        if not query_param:
            return True
            
        query_lower = query_param.lower()
        
        # Check for SQL injection patterns
        for pattern in cls.SQL_INJECTION_PATTERNS:
            if re.search(pattern, query_lower, re.IGNORECASE):
                logger.warning(f"SQL injection pattern detected: {pattern}")
                return False
                
        # Check for encoded characters
        if '%' in query_param and any(x in query_param.lower() for x in ['%27', '%22', '%3b']):
            logger.warning("Encoded SQL injection attempt detected")
            return False
            
        return True
    
    @classmethod
    def sanitize_sql_value(cls, value: str) -> str:
        """
        Sanitize value for SQL queries (use parameterized queries instead when possible)
        
        Args:
            value: Value to sanitize
            
        Returns:
            Sanitized value
        """
        if not value:
            return ''
            
        # Remove SQL special characters
        sanitized = re.sub(r'[\'";\\-]', '', value)
        
        # Remove SQL keywords
        sql_keywords = ['select', 'insert', 'update', 'delete', 'drop', 'union', 'exec']
        for keyword in sql_keywords:
            sanitized = re.sub(rf'\b{keyword}\b', '', sanitized, flags=re.IGNORECASE)
            
        return sanitized.strip()
    
    @classmethod
    def validate_xss(cls, input_string: str) -> bool:
        """
        Check if input contains XSS patterns
        
        Args:
            input_string: String to validate
            
        Returns:
            True if safe, False if XSS detected
        """
        if not input_string:
            return True
            
        # Check for XSS patterns
        for pattern in cls.XSS_PATTERNS:
            if re.search(pattern, input_string, re.IGNORECASE):
                logger.warning(f"XSS pattern detected: {pattern}")
                return False
                
        # Check for encoded XSS
        decoded = input_string
        try:
            import html
            decoded = html.unescape(decoded)
        except:
            pass
            
        if decoded != input_string:
            # Re-check decoded string
            for pattern in cls.XSS_PATTERNS:
                if re.search(pattern, decoded, re.IGNORECASE):
                    logger.warning("Encoded XSS pattern detected")
                    return False
                    
        return True
    
    @classmethod
    def sanitize_html(cls, html_string: str) -> str:
        """
        Sanitize HTML to prevent XSS
        
        Args:
            html_string: HTML string to sanitize
            
        Returns:
            Sanitized HTML
        """
        if not html_string:
            return ''
            
        # Basic HTML escaping
        import html
        sanitized = html.escape(html_string)
        
        # Additional sanitization
        sanitized = re.sub(r'javascript:', 'javascript-', sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(r'on\w+\s*=', 'on-event=', sanitized, flags=re.IGNORECASE)
        
        return sanitized
    
    @classmethod
    def validate_path_traversal(cls, file_path: str, base_dir: str) -> Optional[Path]:
        """
        Validate file path to prevent directory traversal attacks
        
        Args:
            file_path: File path to validate
            base_dir: Base directory that should contain the file
            
        Returns:
            Safe Path object or None if invalid
        """
        if not file_path or not base_dir:
            return None
            
        # Check for path traversal patterns
        for pattern in cls.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, file_path, re.IGNORECASE):
                logger.warning(f"Path traversal pattern detected: {pattern}")
                return None
                
        try:
            # Resolve to absolute paths
            base = Path(base_dir).resolve()
            requested = Path(os.path.join(base_dir, file_path)).resolve()
            
            # Check if requested path is within base directory
            if not str(requested).startswith(str(base)):
                logger.warning(f"Path traversal attempt: {requested} not in {base}")
                return None
                
            # Check if path exists and is a file
            if requested.exists() and not requested.is_file():
                logger.warning(f"Path is not a file: {requested}")
                return None
                
            return requested
            
        except Exception as e:
            logger.error(f"Path validation error: {e}")
            return None
    
    @classmethod
    def validate_file_upload(cls, filename: str, content: bytes, 
                           allowed_types: Optional[Set[str]] = None,
                           max_size: Optional[int] = None) -> Dict[str, Any]:
        """
        Validate file upload for security
        
        Args:
            filename: Original filename
            content: File content
            allowed_types: Set of allowed MIME types
            max_size: Maximum file size in bytes
            
        Returns:
            Validation result dict
        """
        result = {
            'valid': True,
            'errors': [],
            'safe_filename': None,
            'mime_type': None,
            'size': len(content)
        }
        
        # Check filename
        if not filename or '..' in filename or '/' in filename or '\\' in filename:
            result['valid'] = False
            result['errors'].append('Invalid filename')
            return result
            
        # Sanitize filename
        safe_filename = re.sub(r'[^\w\s.-]', '', filename)
        safe_filename = safe_filename.strip()
        result['safe_filename'] = safe_filename
        
        # Check extension
        ext = os.path.splitext(safe_filename)[1].lower()
        if ext not in cls.SAFE_FILE_EXTENSIONS:
            result['valid'] = False
            result['errors'].append(f'File extension {ext} not allowed')
            
        # Check file size
        file_type = 'default'
        if ext in ['.png', '.jpg', '.jpeg', '.gif']:
            file_type = 'image'
        elif ext in ['.doc', '.docx', '.pdf']:
            file_type = 'document'
        elif ext in ['.zip', '.gz', '.tar']:
            file_type = 'archive'
            
        max_allowed = max_size or cls.MAX_FILE_SIZES.get(file_type, cls.MAX_FILE_SIZES['default'])
        if len(content) > max_allowed:
            result['valid'] = False
            result['errors'].append(f'File too large: {len(content)} > {max_allowed}')
            
        # Check MIME type
        mime_type = mimetypes.guess_type(safe_filename)[0]
        result['mime_type'] = mime_type
        
        if allowed_types and mime_type not in allowed_types:
            result['valid'] = False
            result['errors'].append(f'MIME type {mime_type} not allowed')
            
        # Check file content (basic magic number check)
        if content:
            # Check for executable headers
            if content.startswith(b'MZ') or content.startswith(b'\x7fELF'):
                result['valid'] = False
                result['errors'].append('Executable file detected')
                
            # Check for script content in text files
            if mime_type and mime_type.startswith('text/'):
                try:
                    text_content = content.decode('utf-8', errors='ignore')
                    if not cls.validate_xss(text_content):
                        result['valid'] = False
                        result['errors'].append('Potentially malicious script content')
                except:
                    pass
                    
        return result
    
    @classmethod
    def validate_url(cls, url: str, allow_private: bool = False, 
                     allowed_schemes: Optional[Set[str]] = None) -> Dict[str, Any]:
        """
        Validate URL to prevent SSRF attacks
        
        Args:
            url: URL to validate
            allow_private: Whether to allow private IP addresses
            allowed_schemes: Set of allowed URL schemes
            
        Returns:
            Validation result dict
        """
        result = {
            'valid': True,
            'errors': [],
            'parsed': None,
            'is_private': False
        }
        
        if not url:
            result['valid'] = False
            result['errors'].append('Empty URL')
            return result
            
        try:
            parsed = urlparse(url)
            result['parsed'] = parsed
            
            # Check scheme
            allowed = allowed_schemes or {'http', 'https'}
            if parsed.scheme not in allowed:
                result['valid'] = False
                result['errors'].append(f'Scheme {parsed.scheme} not allowed')
                
            # Check for empty host
            if not parsed.hostname:
                result['valid'] = False
                result['errors'].append('No hostname specified')
                return result
                
            # Check for local file access
            if parsed.scheme == 'file':
                result['valid'] = False
                result['errors'].append('File URLs not allowed')
                return result
                
            # Check IP address
            try:
                ip = ipaddress.ip_address(parsed.hostname)
                
                # Check if private
                for private_range in cls.PRIVATE_IP_RANGES:
                    if ip in private_range:
                        result['is_private'] = True
                        if not allow_private:
                            result['valid'] = False
                            result['errors'].append(f'Private IP {ip} not allowed')
                        break
                        
            except ValueError:
                # Not an IP address, check hostname
                if parsed.hostname.lower() in ['localhost', '127.0.0.1', '::1']:
                    result['is_private'] = True
                    if not allow_private:
                        result['valid'] = False
                        result['errors'].append('Localhost access not allowed')
                        
            # Check for suspicious patterns
            suspicious_patterns = [
                r'@',  # Username in URL
                r'\\x',  # Hex encoding
                r'%00',  # Null byte
                r'\.\./',  # Path traversal
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, url):
                    result['valid'] = False
                    result['errors'].append(f'Suspicious pattern detected: {pattern}')
                    
        except Exception as e:
            result['valid'] = False
            result['errors'].append(f'Invalid URL: {str(e)}')
            
        return result
    
    @classmethod
    def validate_api_parameter(cls, param_name: str, param_value: Any, 
                             param_type: type, constraints: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Validate API parameter with type and constraint checking
        
        Args:
            param_name: Parameter name
            param_value: Parameter value
            param_type: Expected type
            constraints: Optional constraints dict
            
        Returns:
            Validation result dict
        """
        result = {
            'valid': True,
            'errors': [],
            'sanitized_value': param_value
        }
        
        # Type checking
        if not isinstance(param_value, param_type):
            result['valid'] = False
            result['errors'].append(f'{param_name} must be {param_type.__name__}')
            return result
            
        # Apply constraints
        if constraints:
            # String constraints
            if param_type == str:
                if 'min_length' in constraints and len(param_value) < constraints['min_length']:
                    result['valid'] = False
                    result['errors'].append(f'{param_name} too short')
                    
                if 'max_length' in constraints and len(param_value) > constraints['max_length']:
                    result['valid'] = False
                    result['errors'].append(f'{param_name} too long')
                    
                if 'pattern' in constraints:
                    if not re.match(constraints['pattern'], param_value):
                        result['valid'] = False
                        result['errors'].append(f'{param_name} format invalid')
                        
                if 'choices' in constraints and param_value not in constraints['choices']:
                    result['valid'] = False
                    result['errors'].append(f'{param_name} not in allowed values')
                    
            # Numeric constraints
            elif param_type in [int, float]:
                if 'min_value' in constraints and param_value < constraints['min_value']:
                    result['valid'] = False
                    result['errors'].append(f'{param_name} too small')
                    
                if 'max_value' in constraints and param_value > constraints['max_value']:
                    result['valid'] = False
                    result['errors'].append(f'{param_name} too large')
                    
            # List constraints
            elif param_type == list:
                if 'min_items' in constraints and len(param_value) < constraints['min_items']:
                    result['valid'] = False
                    result['errors'].append(f'{param_name} too few items')
                    
                if 'max_items' in constraints and len(param_value) > constraints['max_items']:
                    result['valid'] = False
                    result['errors'].append(f'{param_name} too many items')
                    
        # Additional security checks for strings
        if param_type == str and result['valid']:
            # Check for injection attacks
            if not cls.validate_sql_injection(param_value):
                result['valid'] = False
                result['errors'].append('SQL injection detected')
                
            if not cls.validate_xss(param_value):
                result['valid'] = False
                result['errors'].append('XSS detected')
                
        return result
    
    @classmethod
    def generate_secure_filename(cls, original_filename: str) -> str:
        """
        Generate a secure filename from user input
        
        Args:
            original_filename: Original filename
            
        Returns:
            Secure filename
        """
        # Get extension
        name, ext = os.path.splitext(original_filename)
        ext = ext.lower()
        
        # Sanitize name
        safe_name = re.sub(r'[^\w\s-]', '', name)
        safe_name = re.sub(r'[-\s]+', '-', safe_name)
        safe_name = safe_name.strip('-_')[:50]  # Limit length
        
        # Generate unique suffix
        timestamp = hashlib.md5(str(os.urandom(16)).encode()).hexdigest()[:8]
        
        return f"{safe_name}_{timestamp}{ext}"
    
    @classmethod
    @lru_cache(maxsize=1000)
    def is_valid_json(cls, json_string: str) -> bool:
        """
        Validate JSON string
        
        Args:
            json_string: JSON string to validate
            
        Returns:
            True if valid JSON
        """
        try:
            json.loads(json_string)
            return True
        except:
            return False
    
    @classmethod
    @lru_cache(maxsize=1000)
    def is_valid_yaml(cls, yaml_string: str) -> bool:
        """
        Validate YAML string
        
        Args:
            yaml_string: YAML string to validate
            
        Returns:
            True if valid YAML
        """
        try:
            yaml.safe_load(yaml_string)
            return True
        except:
            return False


class SecureCommandExecutor:
    """Secure command execution with sandboxing"""
    
    @staticmethod
    def execute(command: List[str], timeout: int = 30, 
                cwd: Optional[str] = None) -> Dict[str, Any]:
        """
        Execute command securely with timeout and sandboxing
        
        Args:
            command: Command as list of arguments
            timeout: Execution timeout in seconds
            cwd: Working directory
            
        Returns:
            Execution result dict
        """
        result = {
            'success': False,
            'stdout': '',
            'stderr': '',
            'returncode': None,
            'error': None
        }
        
        try:
            # Validate command
            if not command or not isinstance(command, list):
                raise ValueError("Command must be a non-empty list")
                
            # Validate first element is in whitelist
            base_cmd = os.path.basename(command[0])
            if base_cmd not in SecurityValidators.SAFE_COMMANDS:
                raise ValueError(f"Command {base_cmd} not allowed")
                
            # Execute with restrictions
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                shell=False,  # Never use shell
                env={
                    'PATH': '/usr/local/bin:/usr/bin:/bin',
                    'HOME': '/tmp',
                    'USER': 'nobody'
                }
            )
            
            result['success'] = proc.returncode == 0
            result['stdout'] = proc.stdout
            result['stderr'] = proc.stderr
            result['returncode'] = proc.returncode
            
        except subprocess.TimeoutExpired:
            result['error'] = f"Command timed out after {timeout} seconds"
        except Exception as e:
            result['error'] = str(e)
            
        return result


# Export main validator instance
validator = SecurityValidators()