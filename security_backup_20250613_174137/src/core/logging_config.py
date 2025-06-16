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

__all__ = [
    "CorrelationFilter",
    "SensitiveDataFilter",
    "StructuredFormatter",
    "PerformanceLogger",
    "SecurityAuditLogger",
    "MCPOperationLogger",
    "AIRequestLogger",
    "InfrastructureChangeLogger",
    "correlation_context",
    "setup_logging",
    "get_logger",
    "get_performance_logger",
    "get_security_logger",
    "log_with_context",
    "performance_logged",
    "quick_setup"
]

from .log_sanitization import (
    LogInjectionFilter, 
    LogSanitizer, 
    LogSanitizerConfig, 
    SanitizationLevel,
    sanitize_for_logging,
    sanitize_dict_for_logging
)

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
    """Filter to redact sensitive data and prevent log injection attacks."""
    
    def __init__(self, sanitization_level: SanitizationLevel = SanitizationLevel.STANDARD):
        """Initialize with log sanitizer."""
        super().__init__()
        self.sanitizer = LogSanitizer(LogSanitizerConfig(sanitization_level))
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Redact sensitive data and sanitize log message and args."""
        # Sanitize and redact message
        if hasattr(record, 'msg'):
            sanitized_msg = self.sanitizer.sanitize(str(record.msg), "log.message")
            record.msg = self._redact_sensitive(sanitized_msg)
        
        # Sanitize args if present
        if hasattr(record, 'args') and record.args:
            sanitized_args = tuple(
                self._redact_sensitive(self.sanitizer.sanitize(arg, f"log.args[{i}]"))
                for i, arg in enumerate(record.args)
            )
            record.args = sanitized_args
        
        # Sanitize and redact structured data
        if hasattr(record, 'structured_data'):
            sanitized_data = self.sanitizer.sanitize_dict(record.structured_data, "log.structured_data")
            record.structured_data = self._redact_dict(sanitized_data)
        
        # Sanitize extra fields if present
        if hasattr(record, 'extra_fields'):
            sanitized_extra = self.sanitizer.sanitize_dict(record.extra_fields, "log.extra_fields")
            record.extra_fields = self._redact_dict(sanitized_extra)
        
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
    """JSON formatter with performance tracking, structured data, and injection protection."""
    
    def __init__(self, sanitization_level: SanitizationLevel = SanitizationLevel.STANDARD):
        """Initialize with sanitizer."""
        super().__init__()
        self.sanitizer = LogSanitizer(LogSanitizerConfig(sanitization_level))
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as structured JSON with sanitization."""
        # Base log structure
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": self.sanitizer.sanitize(record.getMessage(), "formatter.message"),
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
            log_data["performance"] = self.sanitizer.sanitize_dict(record.performance, "formatter.performance")
        
        # Add security audit data if present
        if hasattr(record, 'security_audit'):
            log_data["security_audit"] = self.sanitizer.sanitize_dict(record.security_audit, "formatter.security_audit")
        
        # Add any structured data
        if hasattr(record, 'structured_data'):
            log_data["data"] = self.sanitizer.sanitize_dict(record.structured_data, "formatter.structured_data")
        
        # Add exception info
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": self.sanitizer.sanitize(str(record.exc_info[1]), "formatter.exception.message"),
                "traceback": self.sanitizer.sanitize(self.formatException(record.exc_info), "formatter.exception.traceback")
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
        """Log access attempt with sanitization."""
        # Sanitize all inputs for security logging
        safe_resource = sanitize_for_logging(resource, SanitizationLevel.STRICT, "security.access.resource")
        safe_action = sanitize_for_logging(action, SanitizationLevel.STRICT, "security.access.action")
        safe_user = sanitize_for_logging(user, SanitizationLevel.STRICT, "security.access.user")
        safe_result = sanitize_for_logging(result, SanitizationLevel.STRICT, "security.access.result")
        safe_extra = sanitize_dict_for_logging(extra, SanitizationLevel.STRICT, "security.access.extra")
        
        record = self.logger.makeRecord(
            self.logger.name,
            logging.INFO,
            "(security)",
            0,
            f"Security audit: {safe_action} on {safe_resource}",
            (),
            None
        )
        
        record.security_audit = {
            "event_type": "access",
            "resource": safe_resource,
            "action": safe_action,
            "user": safe_user,
            "result": safe_result,
            "timestamp": datetime.utcnow().isoformat(),
            **safe_extra
        }
        
        self.logger.handle(record)
    
    def log_authentication(self, user: str, method: str, success: bool, **extra):
        """Log authentication attempt with sanitization."""
        level = logging.INFO if success else logging.WARNING
        
        # Sanitize inputs for security logging - use STRICT level for auth events
        safe_user = sanitize_for_logging(user, SanitizationLevel.STRICT, "security.auth.user")
        safe_method = sanitize_for_logging(method, SanitizationLevel.STRICT, "security.auth.method")
        safe_extra = sanitize_dict_for_logging(extra, SanitizationLevel.STRICT, "security.auth.extra")
        
        record = self.logger.makeRecord(
            self.logger.name,
            level,
            "(security)",
            0,
            f"Authentication {'succeeded' if success else 'failed'} for {safe_user}",
            (),
            None
        )
        
        record.security_audit = {
            "event_type": "authentication",
            "user": safe_user,
            "method": safe_method,
            "success": success,
            "timestamp": datetime.utcnow().isoformat(),
            **safe_extra
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
    enable_file: bool = True,
    sanitization_level: SanitizationLevel = SanitizationLevel.STANDARD
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
        sanitization_level: Level of log injection protection to apply
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
        formatter = StructuredFormatter(sanitization_level)
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(correlation_id)s] - %(message)s'
        )
    
    # Add correlation filter and log injection protection
    correlation_filter = CorrelationFilter()
    sensitive_filter = SensitiveDataFilter(sanitization_level)
    injection_filter = LogInjectionFilter(sanitization_level)
    
    # Console handler
    if enable_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        console_handler.addFilter(correlation_filter)
        console_handler.addFilter(injection_filter)
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
        file_handler.addFilter(injection_filter)
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
    """Log message with structured context data (automatically sanitized)."""
    # Sanitize the message and context
    sanitized_msg = sanitize_for_logging(msg, context="log_with_context.message")
    sanitized_context = sanitize_dict_for_logging(context, context="log_with_context.context")
    
    record = logger.makeRecord(
        logger.name,
        level,
        "(context)",
        0,
        sanitized_msg,
        (),
        None
    )
    record.structured_data = sanitized_context
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
        """Log MCP tool call with sanitization."""
        with correlation_context(correlation_id):
            # Sanitize input parameters before logging
            safe_server = sanitize_for_logging(server, context="mcp.server")
            safe_tool = sanitize_for_logging(tool, context="mcp.tool") 
            safe_params = sanitize_dict_for_logging(params, context="mcp.params")
            
            log_with_context(
                self.logger,
                logging.INFO,
                f"MCP tool call: {safe_server}.{safe_tool}",
                server=safe_server,
                tool=safe_tool,
                params=safe_params
            )
    
    def log_tool_result(self, server: str, tool: str, success: bool,
                       duration_ms: float, error: Optional[str] = None):
        """Log MCP tool result with sanitization."""
        level = logging.INFO if success else logging.ERROR
        
        # Sanitize inputs
        safe_server = sanitize_for_logging(server, context="mcp.result.server")
        safe_tool = sanitize_for_logging(tool, context="mcp.result.tool")
        safe_error = sanitize_for_logging(error, context="mcp.result.error") if error else None
        
        log_with_context(
            self.logger,
            level,
            f"MCP tool result: {safe_server}.{safe_tool}",
            server=safe_server,
            tool=safe_tool,
            success=success,
            duration_ms=duration_ms,
            error=safe_error
        )


class AIRequestLogger:
    """Logger for AI provider requests."""
    
    def __init__(self):
        """Initialize AI logger."""
        self.logger = get_logger("ai.requests")
        self.perf_logger = get_performance_logger("ai.performance")
    
    def log_request(self, provider: str, model: str, prompt_tokens: int,
                   correlation_id: Optional[str] = None):
        """Log AI request with sanitization."""
        with correlation_context(correlation_id):
            # Sanitize inputs
            safe_provider = sanitize_for_logging(provider, context="ai.request.provider")
            safe_model = sanitize_for_logging(model, context="ai.request.model")
            
            log_with_context(
                self.logger,
                logging.INFO,
                f"AI request: {safe_provider}/{safe_model}",
                provider=safe_provider,
                model=safe_model,
                prompt_tokens=prompt_tokens
            )
    
    def log_response(self, provider: str, model: str, response_tokens: int,
                    duration_ms: float, success: bool, cost: Optional[float] = None):
        """Log AI response with sanitization."""
        level = logging.INFO if success else logging.ERROR
        
        # Sanitize inputs
        safe_provider = sanitize_for_logging(provider, context="ai.response.provider")
        safe_model = sanitize_for_logging(model, context="ai.response.model")
        
        log_with_context(
            self.logger,
            level,
            f"AI response: {safe_provider}/{safe_model}",
            provider=safe_provider,
            model=safe_model,
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
        """Log deployment event with sanitization."""
        level = logging.INFO if success else logging.ERROR
        
        # Sanitize inputs
        safe_service = sanitize_for_logging(service, context="infra.deployment.service")
        safe_version = sanitize_for_logging(version, context="infra.deployment.version")
        safe_environment = sanitize_for_logging(environment, context="infra.deployment.environment")
        safe_user = sanitize_for_logging(user, context="infra.deployment.user")
        
        log_with_context(
            self.logger,
            level,
            f"Deployment: {safe_service} v{safe_version} to {safe_environment}",
            service=safe_service,
            version=safe_version,
            environment=safe_environment,
            user=safe_user,
            success=success
        )
        
        # Also log as security audit
        self.security_logger.log_access(
            resource=f"{safe_service}:{safe_environment}",
            action="deploy",
            user=safe_user,
            result="success" if success else "failure",
            version=safe_version
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