"""
Logging utilities for Circle of Experts.

Provides structured logging with context and log injection prevention.
"""

import logging
import sys
from typing import Optional, Dict, Any
from datetime import datetime
import json
from pathlib import Path

__all__ = [
    "StructuredFormatter",
    "LogContext",
    "setup_logging",
    "get_logger"
]


# Import log sanitization from core
try:
    from ...core.log_sanitization import (
        sanitize_for_logging, 
        sanitize_dict_for_logging,
        SanitizationLevel,
        LogInjectionFilter
    )
    HAS_SANITIZATION = True
except ImportError:
    # Fallback if core module not available
    HAS_SANITIZATION = False
    
    def sanitize_for_logging(value, level=None, context=None):
        return str(value)
    
    def sanitize_dict_for_logging(data, level=None, context=None):
        return data


class StructuredFormatter(logging.Formatter):
    """
    Custom formatter that outputs structured JSON logs with sanitization.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON with sanitization."""
        # Sanitize the message
        safe_message = sanitize_for_logging(
            record.getMessage(), 
            SanitizationLevel.STANDARD if HAS_SANITIZATION else None,
            "circle_experts.message"
        )
        
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": safe_message,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add extra fields if present (sanitized)
        if hasattr(record, 'extra_fields'):
            safe_extra = sanitize_dict_for_logging(
                record.extra_fields,
                SanitizationLevel.STANDARD if HAS_SANITIZATION else None,
                "circle_experts.extra"
            )
            log_data.update(safe_extra)
        
        # Add exception info if present (sanitized)
        if record.exc_info:
            safe_exception = sanitize_for_logging(
                self.formatException(record.exc_info),
                SanitizationLevel.STANDARD if HAS_SANITIZATION else None,
                "circle_experts.exception"
            )
            log_data["exception"] = safe_exception
        
        return json.dumps(log_data)


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[Path] = None,
    structured: bool = True,
    sanitization_level: Optional['SanitizationLevel'] = None
) -> None:
    """
    Set up logging configuration for the application.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path for log output
        structured: Whether to use structured JSON logging
        sanitization_level: Level of log injection protection to apply
    """
    # Clear existing handlers
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Set log level
    root_logger.setLevel(getattr(logging, log_level.upper()))
    
    # Create formatter
    if structured:
        formatter = StructuredFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    # Create filters
    filters = []
    if HAS_SANITIZATION and sanitization_level:
        injection_filter = LogInjectionFilter(sanitization_level)
        filters.append(injection_filter)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    for filter_obj in filters:
        console_handler.addFilter(filter_obj)
    root_logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        for filter_obj in filters:
            file_handler.addFilter(filter_obj)
        root_logger.addHandler(file_handler)


class LogContext:
    """
    Context manager for adding context to log messages with sanitization.
    
    Example:
        with LogContext(query_id="12345", expert="gpt4"):
            logger.info("Processing query")  # Will include sanitized context fields
    """
    
    def __init__(self, **kwargs):
        """Initialize with context fields."""
        # Sanitize context data
        self.context = sanitize_dict_for_logging(
            kwargs,
            SanitizationLevel.STANDARD if HAS_SANITIZATION else None,
            "log_context"
        )
        self._original_factory = None
    
    def __enter__(self):
        """Enter context - add fields to log records."""
        self._original_factory = logging.getLogRecordFactory()
        
        def record_factory(*args, **kwargs):
            record = self._original_factory(*args, **kwargs)
            record.extra_fields = self.context
            return record
        
        logging.setLogRecordFactory(record_factory)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context - restore original factory."""
        if self._original_factory:
            logging.setLogRecordFactory(self._original_factory)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance with the given name.
    
    Args:
        name: Logger name (usually __name__)
        
    Returns:
        Configured logger instance
    """
    return logging.getLogger(name)
