"""
Comprehensive logging configuration for Claude-Optimized Deployment Engine.

This module provides:
- Structured JSON logging for production
- Log rotation and retention policies
- Performance and security audit logging
- Correlation ID tracking
- Environment-based configuration
"""

import json
import logging
import logging.handlers
import os
import sys
import time
import uuid
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Union
from functools import wraps

# Log levels by environment
ENV_LOG_LEVELS = {
    "development": "DEBUG",
    "staging": "INFO", 
    "production": "WARNING",
    "test": "DEBUG"
}

# Sensitive field patterns to redact
SENSITIVE_PATTERNS = [
    "password", "token", "key", "secret", "credential", 
    "api_key", "auth", "authorization", "bearer"
]


class CorrelationFilter(logging.Filter):
    """Add correlation ID to all log records."""
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Add correlation ID to record."""
        if not hasattr(record, 'correlation_id'):
            record.correlation_id = self.get_correlation_id()
        return True
    
    @staticmethod
    def get_correlation_id() -> str:
        """Get current correlation ID from context or generate new one."""
        return getattr(_correlation_context, 'id', str(uuid.uuid4()))


class SensitiveDataFilter(logging.Filter):
    """Filter to redact sensitive data from logs."""
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Redact sensitive data from log message and args."""
        # Redact message
        if hasattr(record, 'msg'):
            record.msg = self._redact_sensitive(str(record.msg))
        
        # Redact structured data
        if hasattr(record, 'structured_data'):
            record.structured_data = self._redact_dict(record.structured_data)
        
        return True
    
    def _redact_sensitive(self, text: str) -> str:
        """Redact sensitive patterns from text."""
        for pattern in SENSITIVE_PATTERNS:
            if pattern.lower() in text.lower():
                # Simple redaction - can be enhanced with regex
                text = text.replace(pattern, f"{pattern[:3]}***")
        return text
    
    def _redact_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively redact sensitive data from dictionary."""
        redacted = {}
        for key, value in data.items():
            # Check if key contains sensitive pattern
            is_sensitive = any(p in key.lower() for p in SENSITIVE_PATTERNS)
            
            if is_sensitive:
                redacted[key] = "***REDACTED***"
            elif isinstance(value, dict):
                redacted[key] = self._redact_dict(value)
            elif isinstance(value, str):
                redacted[key] = self._redact_sensitive(value)
            else:
                redacted[key] = value
        
        return redacted


class StructuredFormatter(logging.Formatter):
    """JSON formatter with performance tracking and structured data."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as structured JSON."""
        # Base log structure
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": getattr(record, 'correlation_id', None),
            "environment": os.getenv("ENVIRONMENT", "development"),
            "service": "claude-optimized-deployment",
            "version": os.getenv("SERVICE_VERSION", "unknown"),
        }
        
        # Add location info
        log_data["location"] = {
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "path": record.pathname
        }
        
        # Add performance data if present
        if hasattr(record, 'performance'):
            log_data["performance"] = record.performance
        
        # Add security audit data if present
        if hasattr(record, 'security_audit'):
            log_data["security_audit"] = record.security_audit
        
        # Add any structured data
        if hasattr(record, 'structured_data'):
            log_data["data"] = record.structured_data
        
        # Add exception info
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": self.formatException(record.exc_info)
            }
        
        return json.dumps(log_data, default=str)


class PerformanceLogger:
    """Logger for performance metrics."""
    
    def __init__(self, logger: logging.Logger):
        """Initialize with base logger."""
        self.logger = logger
    
    @contextmanager
    def track_operation(self, operation: str, **extra_data):
        """Track operation performance."""
        start_time = time.time()
        
        try:
            yield
        finally:
            duration_ms = (time.time() - start_time) * 1000
            
            # Create performance record
            record = self.logger.makeRecord(
                self.logger.name,
                logging.INFO,
                "(performance)",
                0,
                f"Operation completed: {operation}",
                (),
                None
            )
            
            record.performance = {
                "operation": operation,
                "duration_ms": round(duration_ms, 2),
                "status": "success",
                **extra_data
            }
            
            self.logger.handle(record)
    
    def log_metric(self, metric_name: str, value: float, unit: str = "ms", **tags):
        """Log a specific metric."""
        record = self.logger.makeRecord(
            self.logger.name,
            logging.INFO,
            "(metric)",
            0,
            f"Metric: {metric_name}",
            (),
            None
        )
        
        record.performance = {
            "metric": metric_name,
            "value": value,
            "unit": unit,
            "tags": tags
        }
        
        self.logger.handle(record)


class SecurityAuditLogger:
    """Logger for security audit events."""
    
    def __init__(self, logger: logging.Logger):
        """Initialize with base logger."""
        self.logger = logger
    
    def log_access(self, resource: str, action: str, user: str, result: str, **extra):
        """Log access attempt."""
        record = self.logger.makeRecord(
            self.logger.name,
            logging.INFO,
            "(security)",
            0,
            f"Security audit: {action} on {resource}",
            (),
            None
        )
        
        record.security_audit = {
            "event_type": "access",
            "resource": resource,
            "action": action,
            "user": user,
            "result": result,
            "timestamp": datetime.utcnow().isoformat(),
            **extra
        }
        
        self.logger.handle(record)
    
    def log_authentication(self, user: str, method: str, success: bool, **extra):
        """Log authentication attempt."""
        level = logging.INFO if success else logging.WARNING
        
        record = self.logger.makeRecord(
            self.logger.name,
            level,
            "(security)",
            0,
            f"Authentication {'succeeded' if success else 'failed'} for {user}",
            (),
            None
        )
        
        record.security_audit = {
            "event_type": "authentication",
            "user": user,
            "method": method,
            "success": success,
            "timestamp": datetime.utcnow().isoformat(),
            **extra
        }
        
        self.logger.handle(record)


# Thread-local storage for correlation context
import threading
_correlation_context = threading.local()


@contextmanager
def correlation_context(correlation_id: Optional[str] = None):
    """Set correlation ID for all logs in context."""
    if correlation_id is None:
        correlation_id = str(uuid.uuid4())
    
    old_id = getattr(_correlation_context, 'id', None)
    _correlation_context.id = correlation_id
    
    try:
        yield correlation_id
    finally:
        if old_id is not None:
            _correlation_context.id = old_id
        else:
            delattr(_correlation_context, 'id')


def setup_logging(
    log_level: Optional[str] = None,
    log_dir: Optional[Path] = None,
    enable_rotation: bool = True,
    max_bytes: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5,
    structured: bool = True,
    enable_console: bool = True,
    enable_file: bool = True
) -> None:
    """
    Configure comprehensive logging for the application.
    
    Args:
        log_level: Override log level (uses environment-based default if None)
        log_dir: Directory for log files (uses 'logs' if None)
        enable_rotation: Enable log file rotation
        max_bytes: Maximum bytes per log file before rotation
        backup_count: Number of backup files to keep
        structured: Use structured JSON logging
        enable_console: Enable console output
        enable_file: Enable file output
    """
    # Determine log level
    environment = os.getenv("ENVIRONMENT", "development")
    if log_level is None:
        log_level = os.getenv("LOG_LEVEL", ENV_LOG_LEVELS.get(environment, "INFO"))
    
    # Set up root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Create formatter
    if structured:
        formatter = StructuredFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(correlation_id)s] - %(message)s'
        )
    
    # Add correlation filter
    correlation_filter = CorrelationFilter()
    sensitive_filter = SensitiveDataFilter()
    
    # Console handler
    if enable_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        console_handler.addFilter(correlation_filter)
        console_handler.addFilter(sensitive_filter)
        root_logger.addHandler(console_handler)
    
    # File handler with rotation
    if enable_file:
        if log_dir is None:
            log_dir = Path("logs")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        log_file = log_dir / f"{environment}.log"
        
        if enable_rotation:
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count
            )
        else:
            file_handler = logging.FileHandler(log_file)
        
        file_handler.setFormatter(formatter)
        file_handler.addFilter(correlation_filter)
        file_handler.addFilter(sensitive_filter)
        root_logger.addHandler(file_handler)
    
    # Set up specialized loggers
    _configure_specialized_loggers()
    
    # Log startup
    logger = get_logger(__name__)
    logger.info(
        "Logging initialized",
        extra={
            "structured_data": {
                "environment": environment,
                "log_level": log_level,
                "structured": structured,
                "rotation_enabled": enable_rotation
            }
        }
    )


def _configure_specialized_loggers():
    """Configure specialized loggers with appropriate levels."""
    # Reduce noise from third-party libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    
    # Set appropriate levels for our modules
    logging.getLogger("src.mcp").setLevel(logging.INFO)
    logging.getLogger("src.circle_of_experts").setLevel(logging.INFO)
    logging.getLogger("src.core").setLevel(logging.INFO)


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with enhanced capabilities."""
    return logging.getLogger(name)


def get_performance_logger(name: str) -> PerformanceLogger:
    """Get a performance logger instance."""
    return PerformanceLogger(get_logger(name))


def get_security_logger(name: str) -> SecurityAuditLogger:
    """Get a security audit logger instance."""
    return SecurityAuditLogger(get_logger(name))


def log_with_context(logger: logging.Logger, level: int, msg: str, **context):
    """Log message with structured context data."""
    record = logger.makeRecord(
        logger.name,
        level,
        "(context)",
        0,
        msg,
        (),
        None
    )
    record.structured_data = context
    logger.handle(record)


def performance_logged(operation_name: Optional[str] = None):
    """Decorator to automatically log function performance."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            nonlocal operation_name
            if operation_name is None:
                operation_name = f"{func.__module__}.{func.__name__}"
            
            logger = get_performance_logger(func.__module__)
            
            with logger.track_operation(operation_name):
                return func(*args, **kwargs)
        
        return wrapper
    return decorator


# Specialized loggers for different components
class MCPOperationLogger:
    """Logger for MCP operations."""
    
    def __init__(self):
        """Initialize MCP logger."""
        self.logger = get_logger("mcp.operations")
        self.perf_logger = get_performance_logger("mcp.performance")
    
    def log_tool_call(self, server: str, tool: str, params: Dict[str, Any], 
                     correlation_id: Optional[str] = None):
        """Log MCP tool call."""
        with correlation_context(correlation_id):
            log_with_context(
                self.logger,
                logging.INFO,
                f"MCP tool call: {server}.{tool}",
                server=server,
                tool=tool,
                params=params
            )
    
    def log_tool_result(self, server: str, tool: str, success: bool,
                       duration_ms: float, error: Optional[str] = None):
        """Log MCP tool result."""
        level = logging.INFO if success else logging.ERROR
        log_with_context(
            self.logger,
            level,
            f"MCP tool result: {server}.{tool}",
            server=server,
            tool=tool,
            success=success,
            duration_ms=duration_ms,
            error=error
        )


class AIRequestLogger:
    """Logger for AI provider requests."""
    
    def __init__(self):
        """Initialize AI logger."""
        self.logger = get_logger("ai.requests")
        self.perf_logger = get_performance_logger("ai.performance")
    
    def log_request(self, provider: str, model: str, prompt_tokens: int,
                   correlation_id: Optional[str] = None):
        """Log AI request."""
        with correlation_context(correlation_id):
            log_with_context(
                self.logger,
                logging.INFO,
                f"AI request: {provider}/{model}",
                provider=provider,
                model=model,
                prompt_tokens=prompt_tokens
            )
    
    def log_response(self, provider: str, model: str, response_tokens: int,
                    duration_ms: float, success: bool, cost: Optional[float] = None):
        """Log AI response."""
        level = logging.INFO if success else logging.ERROR
        log_with_context(
            self.logger,
            level,
            f"AI response: {provider}/{model}",
            provider=provider,
            model=model,
            response_tokens=response_tokens,
            duration_ms=duration_ms,
            success=success,
            cost=cost
        )


class InfrastructureChangeLogger:
    """Logger for infrastructure changes."""
    
    def __init__(self):
        """Initialize infrastructure logger."""
        self.logger = get_logger("infrastructure.changes")
        self.security_logger = get_security_logger("infrastructure.security")
    
    def log_deployment(self, service: str, version: str, environment: str,
                      user: str, success: bool):
        """Log deployment event."""
        level = logging.INFO if success else logging.ERROR
        log_with_context(
            self.logger,
            level,
            f"Deployment: {service} v{version} to {environment}",
            service=service,
            version=version,
            environment=environment,
            user=user,
            success=success
        )
        
        # Also log as security audit
        self.security_logger.log_access(
            resource=f"{service}:{environment}",
            action="deploy",
            user=user,
            result="success" if success else "failure",
            version=version
        )


# Export specialized logger instances
mcp_logger = MCPOperationLogger()
ai_logger = AIRequestLogger()
infra_logger = InfrastructureChangeLogger()


# Convenience function for quick setup
def quick_setup(debug: bool = False):
    """Quick logging setup for scripts and tests."""
    setup_logging(
        log_level="DEBUG" if debug else None,
        enable_file=False,
        structured=False
    )