"""
Comprehensive input validation and sanitization framework for MCP Learning System
"""

import re
import html
import json
import logging
from typing import Any, Dict, List, Union, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
import urllib.parse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    """Result of input validation"""
    is_valid: bool
    sanitized_input: Any
    warnings: List[str]
    errors: List[str]
    
    def __bool__(self) -> bool:
        return self.is_valid


class InputValidator:
    """Comprehensive input validation and sanitization for security"""
    
    def __init__(self):
        # SQL injection patterns
        self.sql_injection_patterns = [
            r"(?i)(union|select|insert|delete|update|drop|create|alter|exec|execute)\s",
            r"['\";]",
            r"--",
            r"/\*.*\*/",
            r"\bor\b.*\b1\s*=\s*1\b",
            r"\band\b.*\b1\s*=\s*1\b",
        ]
        
        # XSS patterns
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe[^>]*>.*?</iframe>",
            r"<object[^>]*>.*?</object>",
            r"<embed[^>]*>.*?</embed>",
            r"<link[^>]*>.*?</link>",
            r"<meta[^>]*>.*?</meta>",
            r"vbscript:",
            r"data:text/html",
        ]
        
        # Path traversal patterns
        self.path_traversal_patterns = [
            r"\.\./",
            r"\.\.[/\\]",
            r"/etc/passwd",
            r"/proc/",
            r"C:\\Windows",
            r"\.\.[\\/]",
            r"~[\\/]",
            r"\%2e\%2e[\\/]",
        ]
        
        # Command injection patterns
        self.command_injection_patterns = [
            r"[;&|`$\(\)]",
            r"(?i)(rm|del|format|shutdown|reboot)\s",
            r"\||\&\&|\|\|",
            r"`.*`",
            r"\$\(.*\)",
            r"nc\s+-l",
            r"curl\s+.*\|",
            r"wget\s+.*\|",
        ]
        
        # File path validation
        self.allowed_file_extensions = {
            '.txt', '.log', '.json', '.yaml', '.yml', '.csv', '.xml',
            '.py', '.js', '.html', '.css', '.md', '.rst'
        }
        
        # Maximum input sizes
        self.max_string_length = 10000
        self.max_json_size = 1000000  # 1MB
        self.max_file_size = 50000000  # 50MB
    
    def validate_string(
        self, 
        input_str: str, 
        max_length: Optional[int] = None,
        allow_html: bool = False,
        strict_mode: bool = True
    ) -> ValidationResult:
        """Validate and sanitize string input"""
        warnings = []
        errors = []
        
        if max_length is None:
            max_length = self.max_string_length
        
        # Basic type check
        if not isinstance(input_str, str):
            input_str = str(input_str)
            warnings.append("Input converted to string")
        
        # Length check
        if len(input_str) > max_length:
            errors.append(f"Input exceeds maximum length of {max_length}")
            input_str = input_str[:max_length]
            warnings.append("Input truncated to maximum length")
        
        # SQL injection check
        for pattern in self.sql_injection_patterns:
            if re.search(pattern, input_str, re.IGNORECASE):
                if strict_mode:
                    errors.append("Potential SQL injection detected")
                else:
                    warnings.append("Potential SQL injection pattern found")
                break
        
        # XSS check
        for pattern in self.xss_patterns:
            if re.search(pattern, input_str, re.IGNORECASE):
                if not allow_html:
                    errors.append("Potential XSS detected")
                    # Sanitize HTML
                    input_str = html.escape(input_str)
                    warnings.append("HTML entities escaped")
                else:
                    warnings.append("HTML content detected but allowed")
                break
        
        # Path traversal check
        for pattern in self.path_traversal_patterns:
            if re.search(pattern, input_str, re.IGNORECASE):
                errors.append("Potential path traversal detected")
                break
        
        # Command injection check
        for pattern in self.command_injection_patterns:
            if re.search(pattern, input_str, re.IGNORECASE):
                if strict_mode:
                    errors.append("Potential command injection detected")
                else:
                    warnings.append("Potential command injection pattern found")
                break
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            sanitized_input=input_str,
            warnings=warnings,
            errors=errors
        )
    
    def validate_json(
        self, 
        json_data: Union[str, dict], 
        max_size: Optional[int] = None
    ) -> ValidationResult:
        """Validate JSON input"""
        warnings = []
        errors = []
        
        if max_size is None:
            max_size = self.max_json_size
        
        # Convert to string if dict
        if isinstance(json_data, dict):
            try:
                json_str = json.dumps(json_data)
            except (TypeError, ValueError) as e:
                errors.append(f"Failed to serialize JSON: {e}")
                return ValidationResult(False, None, warnings, errors)
        else:
            json_str = str(json_data)
        
        # Size check
        if len(json_str) > max_size:
            errors.append(f"JSON size exceeds maximum of {max_size} bytes")
            return ValidationResult(False, None, warnings, errors)
        
        # Parse JSON
        try:
            if isinstance(json_data, str):
                parsed_data = json.loads(json_data)
            else:
                parsed_data = json_data
        except json.JSONDecodeError as e:
            errors.append(f"Invalid JSON: {e}")
            return ValidationResult(False, None, warnings, errors)
        
        # Validate JSON structure and content
        sanitized_data = self._sanitize_data(parsed_data)
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            sanitized_input=sanitized_data,
            warnings=warnings,
            errors=errors
        )
    
    def validate_file_path(
        self, 
        file_path: str,
        allowed_dirs: Optional[List[str]] = None,
        check_exists: bool = False
    ) -> ValidationResult:
        """Validate file path for security"""
        warnings = []
        errors = []
        
        # Basic validation
        result = self.validate_string(file_path, strict_mode=True)
        if not result.is_valid:
            return result
        
        sanitized_path = result.sanitized_input
        
        try:
            path_obj = Path(sanitized_path).resolve()
        except (OSError, ValueError) as e:
            errors.append(f"Invalid path: {e}")
            return ValidationResult(False, None, warnings, errors)
        
        # Check if path is within allowed directories
        if allowed_dirs:
            is_allowed = any(
                str(path_obj).startswith(str(Path(allowed_dir).resolve()))
                for allowed_dir in allowed_dirs
            )
            if not is_allowed:
                errors.append("Path not in allowed directories")
        
        # Check file extension
        if path_obj.suffix and path_obj.suffix.lower() not in self.allowed_file_extensions:
            warnings.append(f"File extension {path_obj.suffix} not in whitelist")
        
        # Check if file exists (if required)
        if check_exists and not path_obj.exists():
            errors.append("File does not exist")
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            sanitized_input=str(path_obj),
            warnings=warnings,
            errors=errors
        )
    
    def validate_url(self, url: str) -> ValidationResult:
        """Validate URL for security"""
        warnings = []
        errors = []
        
        # Basic string validation
        result = self.validate_string(url, max_length=2048, strict_mode=True)
        if not result.is_valid:
            return result
        
        sanitized_url = result.sanitized_input
        
        try:
            parsed = urllib.parse.urlparse(sanitized_url)
        except Exception as e:
            errors.append(f"Invalid URL: {e}")
            return ValidationResult(False, None, warnings, errors)
        
        # Check scheme
        allowed_schemes = {'http', 'https', 'ftp', 'ftps'}
        if parsed.scheme.lower() not in allowed_schemes:
            errors.append(f"Scheme '{parsed.scheme}' not allowed")
        
        # Check for localhost/private IPs
        if parsed.hostname:
            if parsed.hostname.lower() in ['localhost', '127.0.0.1', '::1']:
                warnings.append("Localhost URL detected")
            
            # Check for private IP ranges
            if self._is_private_ip(parsed.hostname):
                warnings.append("Private IP address detected")
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            sanitized_input=sanitized_url,
            warnings=warnings,
            errors=errors
        )
    
    def validate_email(self, email: str) -> ValidationResult:
        """Validate email address"""
        warnings = []
        errors = []
        
        # Basic string validation
        result = self.validate_string(email, max_length=254, strict_mode=True)
        if not result.is_valid:
            return result
        
        sanitized_email = result.sanitized_input.lower().strip()
        
        # Email regex (basic but secure)
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, sanitized_email):
            errors.append("Invalid email format")
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            sanitized_input=sanitized_email,
            warnings=warnings,
            errors=errors
        )
    
    def validate_batch(
        self, 
        inputs: List[Tuple[str, Any, str]]
    ) -> Dict[str, ValidationResult]:
        """Validate multiple inputs in batch
        
        Args:
            inputs: List of (name, value, validation_type) tuples
        """
        results = {}
        
        for name, value, validation_type in inputs:
            if validation_type == 'string':
                results[name] = self.validate_string(value)
            elif validation_type == 'json':
                results[name] = self.validate_json(value)
            elif validation_type == 'file_path':
                results[name] = self.validate_file_path(value)
            elif validation_type == 'url':
                results[name] = self.validate_url(value)
            elif validation_type == 'email':
                results[name] = self.validate_email(value)
            else:
                results[name] = ValidationResult(
                    is_valid=False,
                    sanitized_input=None,
                    warnings=[],
                    errors=[f"Unknown validation type: {validation_type}"]
                )
        
        return results
    
    def _sanitize_data(self, data: Any) -> Any:
        """Sanitize any type of data"""
        if isinstance(data, dict):
            return self._sanitize_dict(data)
        elif isinstance(data, list):
            return [self._sanitize_data(item) for item in data[:100]]  # Limit list size
        elif isinstance(data, str):
            result = self.validate_string(data, strict_mode=False)
            return result.sanitized_input
        elif isinstance(data, (int, float, bool, type(None))):
            return data
        else:
            # Convert unknown types to string
            return str(data)[:1000]  # Limit string length
    
    def _sanitize_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively sanitize dictionary data"""
        sanitized = {}
        
        for key, value in data.items():
            # Sanitize key
            clean_key = re.sub(r'[^a-zA-Z0-9_.-]', '', str(key))
            if not clean_key:
                clean_key = 'sanitized_key'
            
            # Sanitize value based on type
            if isinstance(value, str):
                result = self.validate_string(value, strict_mode=False)
                sanitized[clean_key] = result.sanitized_input
            elif isinstance(value, dict):
                sanitized[clean_key] = self._sanitize_data(value)
            elif isinstance(value, list):
                sanitized[clean_key] = [
                    self.validate_string(item, strict_mode=False).sanitized_input 
                    if isinstance(item, str) else item
                    for item in value[:100]  # Limit list size
                ]
            elif isinstance(value, (int, float, bool)):
                sanitized[clean_key] = value
            else:
                # Convert unknown types to string
                sanitized[clean_key] = str(value)[:1000]  # Limit string length
        
        return sanitized
    
    def _is_private_ip(self, hostname: str) -> bool:
        """Check if hostname is a private IP address"""
        try:
            import ipaddress
            ip = ipaddress.ip_address(hostname)
            return ip.is_private
        except (ValueError, ipaddress.AddressValueError):
            return False


# Global validator instance
validator = InputValidator()


def validate_input(
    input_data: Any, 
    validation_type: str = 'string',
    **kwargs
) -> ValidationResult:
    """Convenience function for input validation"""
    if validation_type == 'string':
        return validator.validate_string(input_data, **kwargs)
    elif validation_type == 'json':
        return validator.validate_json(input_data, **kwargs)
    elif validation_type == 'file_path':
        return validator.validate_file_path(input_data, **kwargs)
    elif validation_type == 'url':
        return validator.validate_url(input_data, **kwargs)
    elif validation_type == 'email':
        return validator.validate_email(input_data, **kwargs)
    else:
        return ValidationResult(
            is_valid=False,
            sanitized_input=None,
            warnings=[],
            errors=[f"Unknown validation type: {validation_type}"]
        )


# Example usage and testing
if __name__ == "__main__":
    # Test string validation
    test_inputs = [
        "normal string",
        "<script>alert('xss')</script>",
        "'; DROP TABLE users; --",
        "../../../etc/passwd",
        "valid@email.com",
        "http://example.com",
    ]
    
    validator = InputValidator()
    
    for test_input in test_inputs:
        result = validator.validate_string(test_input)
        print(f"Input: {test_input}")
        print(f"Valid: {result.is_valid}")
        print(f"Sanitized: {result.sanitized_input}")
        print(f"Warnings: {result.warnings}")
        print(f"Errors: {result.errors}")
        print("-" * 50)