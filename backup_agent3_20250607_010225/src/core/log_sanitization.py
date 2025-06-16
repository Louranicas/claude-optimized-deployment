"""
Log injection prevention utilities for Claude-Optimized Deployment Engine.

This module provides comprehensive input sanitization to prevent log poisoning attacks,
including CRLF injection, log forging, and other log-based attacks.

Security Features:
- CRLF injection prevention (\\r\\n sequences)
- Log forging prevention (fake log entries)
- Control character filtering
- Size limits for log entries
- Unicode normalization
- Pattern-based attack detection
"""

import re
import unicodedata
from typing import Any, Dict, List, Optional, Union
from enum import Enum
import logging


class SanitizationLevel(Enum):
    """Sanitization strictness levels."""
    PERMISSIVE = "permissive"    # Basic CRLF and control char removal
    STANDARD = "standard"        # Standard security filtering
    STRICT = "strict"           # Aggressive filtering for high-security


class LogSanitizerConfig:
    """Configuration for log sanitization."""
    
    def __init__(
        self,
        level: SanitizationLevel = SanitizationLevel.STANDARD,
        max_length: int = 8192,
        preserve_unicode: bool = True,
        detect_patterns: bool = True,
        truncate_marker: str = "...[TRUNCATED]"
    ):
        """
        Initialize sanitizer configuration.
        
        Args:
            level: Sanitization strictness level
            max_length: Maximum length for log entries
            preserve_unicode: Whether to preserve Unicode characters
            detect_patterns: Whether to detect and flag suspicious patterns
            truncate_marker: Marker to append when truncating long entries
        """
        self.level = level
        self.max_length = max_length
        self.preserve_unicode = preserve_unicode
        self.detect_patterns = detect_patterns
        self.truncate_marker = truncate_marker


class LogSanitizer:
    """
    Comprehensive log sanitizer to prevent injection attacks.
    
    Prevents:
    - CRLF injection (\\r\\n sequences that can forge log entries)
    - Control character injection
    - Log forging attempts
    - Oversized log entries
    - Unicode-based attacks
    """
    
    # Dangerous patterns that could indicate log injection attempts
    DANGEROUS_PATTERNS = [
        # Log timestamp patterns that could forge entries
        r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}',
        # Common log level patterns
        r'\b(DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\b',
        # HTTP log patterns
        r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b.*?"[A-Z]+ /',
        # Syslog patterns
        r'<\d+>',
        # JSON log start patterns
        r'^\s*\{.*"level".*:',
        # Script injection patterns
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'data:text/html',
        # Common injection patterns
        r'eval\s*\(',
        r'exec\s*\(',
        r'system\s*\(',
        # Path traversal
        r'\.\./',
        r'\.\.\\',
    ]
    
    # Control characters to remove (except tab, newline, carriage return which we handle specially)
    CONTROL_CHARS = [chr(i) for i in range(32) if i not in (9, 10, 13)]
    
    def __init__(self, config: Optional[LogSanitizerConfig] = None):
        """Initialize sanitizer with configuration."""
        self.config = config or LogSanitizerConfig()
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile regex patterns for performance."""
        if self.config.detect_patterns:
            self.dangerous_pattern_regex = re.compile(
                '|'.join(self.DANGEROUS_PATTERNS),
                re.IGNORECASE | re.MULTILINE
            )
        else:
            self.dangerous_pattern_regex = None
    
    def sanitize(self, value: Any, context: Optional[str] = None) -> str:
        """
        Sanitize a value for safe logging.
        
        Args:
            value: Value to sanitize (will be converted to string)
            context: Optional context for more specific sanitization
            
        Returns:
            Sanitized string safe for logging
        """
        if value is None:
            return "None"
        
        # Convert to string
        if isinstance(value, (dict, list)):
            import json
            try:
                text = json.dumps(value, default=str, ensure_ascii=False)
            except (TypeError, ValueError):
                text = str(value)
        else:
            text = str(value)
        
        # Apply sanitization steps
        text = self._remove_crlf_injection(text)
        text = self._remove_control_characters(text)
        text = self._normalize_unicode(text)
        text = self._apply_length_limit(text)
        
        # Pattern detection and flagging
        if self.config.detect_patterns and self.dangerous_pattern_regex:
            text = self._flag_dangerous_patterns(text, context)
        
        return text
    
    def _remove_crlf_injection(self, text: str) -> str:
        """Remove CRLF injection attempts."""
        # Remove carriage return and line feed combinations
        text = text.replace('\\r\\n', ' ')
        text = text.replace('\\n', ' ')
        text = text.replace('\\r', ' ')
        text = text.replace('\r\n', ' ')
        text = text.replace('\n', ' ')
        text = text.replace('\r', ' ')
        
        # Remove encoded versions
        text = text.replace('%0D%0A', ' ')
        text = text.replace('%0A', ' ')
        text = text.replace('%0D', ' ')
        text = text.replace('%0d%0a', ' ')
        text = text.replace('%0a', ' ')
        text = text.replace('%0d', ' ')
        
        return text
    
    def _remove_control_characters(self, text: str) -> str:
        """Remove dangerous control characters."""
        for char in self.CONTROL_CHARS:
            text = text.replace(char, '')
        
        # Handle specific sanitization levels
        if self.config.level == SanitizationLevel.STRICT:
            # Remove all non-printable characters except space
            text = ''.join(char for char in text if char.isprintable() or char.isspace())
        
        return text
    
    def _normalize_unicode(self, text: str) -> str:
        """Normalize Unicode to prevent Unicode-based attacks."""
        if not self.config.preserve_unicode:
            # Convert to ASCII, replacing non-ASCII characters
            text = text.encode('ascii', errors='replace').decode('ascii')
        else:
            # Normalize Unicode to prevent normalization attacks
            text = unicodedata.normalize('NFKC', text)
        
        return text
    
    def _apply_length_limit(self, text: str) -> str:
        """Apply length limits to prevent log flooding."""
        if len(text) > self.config.max_length:
            truncate_length = self.config.max_length - len(self.config.truncate_marker)
            text = text[:truncate_length] + self.config.truncate_marker
        
        return text
    
    def _flag_dangerous_patterns(self, text: str, context: Optional[str]) -> str:
        """Flag text containing dangerous patterns."""
        if self.dangerous_pattern_regex and self.dangerous_pattern_regex.search(text):
            # Add warning prefix to flagged content
            warning = f"[SUSPICIOUS_PATTERN_DETECTED{':' + context if context else ''}]"
            # Also sanitize the flagged content more aggressively
            text = self._aggressive_sanitize(text)
            return f"{warning} {text}"
        
        return text
    
    def _aggressive_sanitize(self, text: str) -> str:
        """Apply aggressive sanitization for suspicious content."""
        # Replace potentially dangerous characters with safe equivalents
        replacements = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '/': '&#x2F;',
            '{': '&#123;',
            '}': '&#125;',
            '(': '&#40;',
            ')': '&#41;',
            '=': '&#61;',
            ';': '&#59;',
            ':': '&#58;',
        }
        
        for char, replacement in replacements.items():
            text = text.replace(char, replacement)
        
        return text
    
    def sanitize_dict(self, data: Dict[str, Any], context: Optional[str] = None) -> Dict[str, Any]:
        """
        Recursively sanitize a dictionary for logging.
        
        Args:
            data: Dictionary to sanitize
            context: Optional context for sanitization
            
        Returns:
            Sanitized dictionary safe for logging
        """
        sanitized = {}
        
        for key, value in data.items():
            # Sanitize the key
            safe_key = self.sanitize(key, f"{context}.key" if context else "key")
            
            # Sanitize the value based on type
            if isinstance(value, dict):
                safe_value = self.sanitize_dict(value, f"{context}.{key}" if context else key)
            elif isinstance(value, list):
                safe_value = [self.sanitize(item, f"{context}.{key}[]" if context else f"{key}[]") 
                            for item in value]
            else:
                safe_value = self.sanitize(value, f"{context}.{key}" if context else key)
            
            sanitized[safe_key] = safe_value
        
        return sanitized


# Global sanitizer instances for different use cases
_standard_sanitizer = LogSanitizer(LogSanitizerConfig(SanitizationLevel.STANDARD))
_strict_sanitizer = LogSanitizer(LogSanitizerConfig(SanitizationLevel.STRICT))
_permissive_sanitizer = LogSanitizer(LogSanitizerConfig(SanitizationLevel.PERMISSIVE))


def sanitize_for_logging(
    value: Any, 
    level: SanitizationLevel = SanitizationLevel.STANDARD,
    context: Optional[str] = None
) -> str:
    """
    Convenience function to sanitize a value for logging.
    
    Args:
        value: Value to sanitize
        level: Sanitization level to apply
        context: Optional context for more specific sanitization
        
    Returns:
        Sanitized string safe for logging
    """
    sanitizer_map = {
        SanitizationLevel.PERMISSIVE: _permissive_sanitizer,
        SanitizationLevel.STANDARD: _standard_sanitizer,
        SanitizationLevel.STRICT: _strict_sanitizer,
    }
    
    sanitizer = sanitizer_map.get(level, _standard_sanitizer)
    return sanitizer.sanitize(value, context)


def sanitize_dict_for_logging(
    data: Dict[str, Any],
    level: SanitizationLevel = SanitizationLevel.STANDARD,
    context: Optional[str] = None
) -> Dict[str, Any]:
    """
    Convenience function to sanitize a dictionary for logging.
    
    Args:
        data: Dictionary to sanitize
        level: Sanitization level to apply
        context: Optional context for sanitization
        
    Returns:
        Sanitized dictionary safe for logging
    """
    sanitizer_map = {
        SanitizationLevel.PERMISSIVE: _permissive_sanitizer,
        SanitizationLevel.STANDARD: _standard_sanitizer,
        SanitizationLevel.STRICT: _strict_sanitizer,
    }
    
    sanitizer = sanitizer_map.get(level, _standard_sanitizer)
    return sanitizer.sanitize_dict(data, context)


class LogInjectionFilter(logging.Filter):
    """
    Logging filter that automatically sanitizes all log messages.
    
    This filter intercepts log records and sanitizes the message and any
    additional arguments to prevent log injection attacks.
    """
    
    def __init__(self, sanitization_level: SanitizationLevel = SanitizationLevel.STANDARD):
        """Initialize with sanitization level."""
        super().__init__()
        self.sanitizer = LogSanitizer(LogSanitizerConfig(sanitization_level))
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Filter and sanitize log record."""
        # Sanitize the main message
        if hasattr(record, 'msg'):
            record.msg = self.sanitizer.sanitize(record.msg, "log.message")
        
        # Sanitize args if present
        if hasattr(record, 'args') and record.args:
            sanitized_args = tuple(
                self.sanitizer.sanitize(arg, f"log.args[{i}]") 
                for i, arg in enumerate(record.args)
            )
            record.args = sanitized_args
        
        # Sanitize structured data if present
        if hasattr(record, 'structured_data'):
            record.structured_data = self.sanitizer.sanitize_dict(
                record.structured_data, "log.structured_data"
            )
        
        # Sanitize extra fields if present
        if hasattr(record, 'extra_fields'):
            record.extra_fields = self.sanitizer.sanitize_dict(
                record.extra_fields, "log.extra_fields"
            )
        
        return True


def create_safe_log_record(
    logger: logging.Logger,
    level: int,
    msg: str,
    args: tuple = (),
    extra: Optional[Dict[str, Any]] = None,
    sanitization_level: SanitizationLevel = SanitizationLevel.STANDARD
) -> logging.LogRecord:
    """
    Create a sanitized log record.
    
    Args:
        logger: Logger instance
        level: Log level
        msg: Log message
        args: Message arguments
        extra: Extra fields
        sanitization_level: Sanitization level to apply
        
    Returns:
        Sanitized log record
    """
    sanitizer = LogSanitizer(LogSanitizerConfig(sanitization_level))
    
    # Sanitize message and args
    safe_msg = sanitizer.sanitize(msg, "log.message")
    safe_args = tuple(
        sanitizer.sanitize(arg, f"log.args[{i}]") 
        for i, arg in enumerate(args)
    ) if args else ()
    
    # Create record
    record = logger.makeRecord(
        logger.name,
        level,
        "(sanitized)",
        0,
        safe_msg,
        safe_args,
        None
    )
    
    # Add sanitized extra fields
    if extra:
        sanitized_extra = sanitizer.sanitize_dict(extra, "log.extra")
        for key, value in sanitized_extra.items():
            setattr(record, key, value)
    
    return record