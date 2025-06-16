"""
Centralized error handling system with correlation IDs and structured logging.

Provides:
- Custom exception classes with context
- Error correlation IDs for distributed tracing
- Pydantic models for error responses
- Structured error logging
- Error recovery strategies
"""

import sys
import uuid
import traceback
import logging
from typing import Dict, Any, Optional, List, Type, Union, Callable
from datetime import datetime
from enum import Enum
from contextlib import contextmanager
from functools import wraps
import asyncio

from pydantic import BaseModel, Field, ConfigDict

from src.core.logging_config import get_logger

__all__ = [
    # Base exceptions
    "BaseError",
    "ValidationError",
    "AuthenticationError",
    "AuthorizationError",
    "ResourceNotFoundError",
    "ConflictError",
    "RateLimitError",
    "ServiceUnavailableError",
    "ExternalServiceError",
    "ConfigurationError",
    "DatabaseError",
    "CircuitBreakerError",
    
    # Error models
    "ErrorSeverity",
    "ErrorCategory",
    "ErrorDetail",
    "ErrorResponse",
    "ErrorContext",
    
    # Error handling utilities
    "ErrorHandler",
    "get_error_handler",
    "handle_errors",
    "async_handle_errors",
    "with_correlation_id",
    "log_error",
    "create_error_response"
]

logger = get_logger(__name__)


class ErrorSeverity(str, Enum):
    """Error severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ErrorCategory(str, Enum):
    """Error categories for classification."""
    VALIDATION = "validation"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    BUSINESS_LOGIC = "business_logic"
    SYSTEM = "system"
    EXTERNAL_SERVICE = "external_service"
    DATABASE = "database"
    CONFIGURATION = "configuration"
    RATE_LIMIT = "rate_limit"
    CIRCUIT_BREAKER = "circuit_breaker"


class ErrorDetail(BaseModel):
    """Detailed error information."""
    model_config = ConfigDict(use_enum_values=True)
    
    field: Optional[str] = Field(None, description="Field that caused the error")
    message: str = Field(..., description="Human-readable error message")
    code: Optional[str] = Field(None, description="Machine-readable error code")
    context: Optional[Dict[str, Any]] = Field(None, description="Additional context")


class ErrorContext(BaseModel):
    """Error context information."""
    model_config = ConfigDict(use_enum_values=True)
    
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    service: str = Field(default="claude-deployment-engine")
    environment: Optional[str] = None
    user_id: Optional[str] = None
    request_id: Optional[str] = None
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    
    def to_logging_context(self) -> Dict[str, Any]:
        """Convert to logging context."""
        return {
            "correlation_id": self.correlation_id,
            "timestamp": self.timestamp.isoformat(),
            "service": self.service,
            "environment": self.environment,
            "user_id": self.user_id,
            "request_id": self.request_id,
            "trace_id": self.trace_id,
            "span_id": self.span_id
        }


class ErrorResponse(BaseModel):
    """Standardized error response model."""
    model_config = ConfigDict(use_enum_values=True)
    
    error: str = Field(..., description="Error type/name")
    message: str = Field(..., description="Human-readable error message")
    correlation_id: str = Field(..., description="Unique error correlation ID")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    severity: ErrorSeverity = Field(ErrorSeverity.MEDIUM)
    category: ErrorCategory = Field(ErrorCategory.SYSTEM)
    details: Optional[List[ErrorDetail]] = Field(None, description="Detailed error information")
    context: Optional[Dict[str, Any]] = Field(None, description="Additional error context")
    stack_trace: Optional[str] = Field(None, description="Stack trace (only in debug mode)")
    recovery_suggestions: Optional[List[str]] = Field(None, description="Suggested recovery actions")
    
    def to_dict(self, include_stack_trace: bool = False) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = self.model_dump(exclude_none=True)
        if not include_stack_trace:
            data.pop("stack_trace", None)
        return data


# Base exception classes

class BaseError(Exception):
    """Base exception class for all custom exceptions."""
    
    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        category: ErrorCategory = ErrorCategory.SYSTEM,
        context: Optional[Dict[str, Any]] = None,
        details: Optional[List[ErrorDetail]] = None,
        recovery_suggestions: Optional[List[str]] = None,
        correlation_id: Optional[str] = None
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.severity = severity
        self.category = category
        self.context = context or {}
        self.details = details or []
        self.recovery_suggestions = recovery_suggestions or []
        self.correlation_id = correlation_id or str(uuid.uuid4())
        self.timestamp = datetime.utcnow()
        
        # Capture stack trace
        self.stack_trace = traceback.format_exc()
    
    def to_error_response(self, include_stack_trace: bool = False) -> ErrorResponse:
        """Convert exception to ErrorResponse model."""
        return ErrorResponse(
            error=self.error_code,
            message=self.message,
            correlation_id=self.correlation_id,
            timestamp=self.timestamp,
            severity=self.severity,
            category=self.category,
            details=self.details,
            context=self.context,
            stack_trace=self.stack_trace if include_stack_trace else None,
            recovery_suggestions=self.recovery_suggestions
        )


class ValidationError(BaseError):
    """Validation error exception."""
    
    def __init__(self, message: str, field: Optional[str] = None, **kwargs):
        kwargs.setdefault("severity", ErrorSeverity.LOW)
        kwargs.setdefault("category", ErrorCategory.VALIDATION)
        
        if field:
            kwargs.setdefault("details", []).append(
                ErrorDetail(field=field, message=message)
            )
        
        super().__init__(message, **kwargs)


class AuthenticationError(BaseError):
    """Authentication error exception."""
    
    def __init__(self, message: str = "Authentication failed", **kwargs):
        kwargs.setdefault("severity", ErrorSeverity.HIGH)
        kwargs.setdefault("category", ErrorCategory.AUTHENTICATION)
        kwargs.setdefault("recovery_suggestions", []).extend([
            "Check your credentials",
            "Ensure your token is valid and not expired",
            "Try logging in again"
        ])
        super().__init__(message, **kwargs)


class AuthorizationError(BaseError):
    """Authorization error exception."""
    
    def __init__(self, message: str = "Access denied", **kwargs):
        kwargs.setdefault("severity", ErrorSeverity.HIGH)
        kwargs.setdefault("category", ErrorCategory.AUTHORIZATION)
        kwargs.setdefault("recovery_suggestions", []).extend([
            "Check your permissions",
            "Contact an administrator for access",
            "Ensure you're accessing the correct resource"
        ])
        super().__init__(message, **kwargs)


class ResourceNotFoundError(BaseError):
    """Resource not found error exception."""
    
    def __init__(self, resource_type: str, resource_id: str, **kwargs):
        message = f"{resource_type} with ID '{resource_id}' not found"
        kwargs.setdefault("severity", ErrorSeverity.LOW)
        kwargs.setdefault("category", ErrorCategory.BUSINESS_LOGIC)
        kwargs.setdefault("context", {}).update({
            "resource_type": resource_type,
            "resource_id": resource_id
        })
        super().__init__(message, **kwargs)


class ConflictError(BaseError):
    """Conflict error exception."""
    
    def __init__(self, message: str, **kwargs):
        kwargs.setdefault("severity", ErrorSeverity.MEDIUM)
        kwargs.setdefault("category", ErrorCategory.BUSINESS_LOGIC)
        super().__init__(message, **kwargs)


class RateLimitError(BaseError):
    """Rate limit error exception."""
    
    def __init__(self, message: str = "Rate limit exceeded", retry_after: Optional[int] = None, **kwargs):
        kwargs.setdefault("severity", ErrorSeverity.MEDIUM)
        kwargs.setdefault("category", ErrorCategory.RATE_LIMIT)
        
        if retry_after:
            kwargs.setdefault("context", {})["retry_after"] = retry_after
            kwargs.setdefault("recovery_suggestions", []).append(
                f"Retry after {retry_after} seconds"
            )
        
        super().__init__(message, **kwargs)


class ServiceUnavailableError(BaseError):
    """Service unavailable error exception."""
    
    def __init__(self, message: str = "Service temporarily unavailable", **kwargs):
        kwargs.setdefault("severity", ErrorSeverity.HIGH)
        kwargs.setdefault("category", ErrorCategory.SYSTEM)
        kwargs.setdefault("recovery_suggestions", []).extend([
            "Try again in a few moments",
            "Check service status",
            "Contact support if the issue persists"
        ])
        super().__init__(message, **kwargs)


class ExternalServiceError(BaseError):
    """External service error exception."""
    
    def __init__(self, service_name: str, message: str, **kwargs):
        kwargs.setdefault("severity", ErrorSeverity.HIGH)
        kwargs.setdefault("category", ErrorCategory.EXTERNAL_SERVICE)
        kwargs.setdefault("context", {})["service_name"] = service_name
        super().__init__(f"External service error ({service_name}): {message}", **kwargs)


class ConfigurationError(BaseError):
    """Configuration error exception."""
    
    def __init__(self, message: str, config_key: Optional[str] = None, **kwargs):
        kwargs.setdefault("severity", ErrorSeverity.CRITICAL)
        kwargs.setdefault("category", ErrorCategory.CONFIGURATION)
        
        if config_key:
            kwargs.setdefault("context", {})["config_key"] = config_key
        
        super().__init__(message, **kwargs)


class DatabaseError(BaseError):
    """Database error exception."""
    
    def __init__(self, message: str, operation: Optional[str] = None, **kwargs):
        kwargs.setdefault("severity", ErrorSeverity.HIGH)
        kwargs.setdefault("category", ErrorCategory.DATABASE)
        
        if operation:
            kwargs.setdefault("context", {})["operation"] = operation
        
        super().__init__(message, **kwargs)


class CircuitBreakerError(BaseError):
    """Circuit breaker error exception."""
    
    def __init__(self, service_name: str, message: str = "Circuit breaker is open", **kwargs):
        kwargs.setdefault("severity", ErrorSeverity.HIGH)
        kwargs.setdefault("category", ErrorCategory.CIRCUIT_BREAKER)
        kwargs.setdefault("context", {})["service_name"] = service_name
        kwargs.setdefault("recovery_suggestions", []).append(
            f"Service '{service_name}' is temporarily disabled due to failures"
        )
        super().__init__(message, **kwargs)


# Error handling utilities

class ErrorHandler:
    """Centralized error handler with logging and tracking."""
    
    def __init__(self):
        self.error_history: List[ErrorResponse] = []
        self.error_callbacks: List[Callable] = []
        self._context_stack: List[ErrorContext] = []
    
    def push_context(self, context: ErrorContext):
        """Push error context to stack."""
        self._context_stack.append(context)
    
    def pop_context(self) -> Optional[ErrorContext]:
        """Pop error context from stack."""
        return self._context_stack.pop() if self._context_stack else None
    
    def get_current_context(self) -> Optional[ErrorContext]:
        """Get current error context."""
        return self._context_stack[-1] if self._context_stack else None
    
    def register_callback(self, callback: Callable):
        """Register error callback."""
        self.error_callbacks.append(callback)
    
    def handle_error(
        self,
        error: Union[BaseError, Exception],
        include_stack_trace: bool = False,
        log_error: bool = True,
        context: Optional[Dict[str, Any]] = None
    ) -> ErrorResponse:
        """Handle and log error."""
        # Create error response
        if isinstance(error, BaseError):
            error_response = error.to_error_response(include_stack_trace)
        else:
            # Convert standard exceptions
            error_response = ErrorResponse(
                error=error.__class__.__name__,
                message=str(error),
                correlation_id=str(uuid.uuid4()),
                severity=ErrorSeverity.MEDIUM,
                category=ErrorCategory.SYSTEM,
                stack_trace=traceback.format_exc() if include_stack_trace else None,
                context=context
            )
        
        # Add current context
        current_context = self.get_current_context()
        if current_context:
            error_response.context = error_response.context or {}
            error_response.context.update(current_context.to_logging_context())
        
        # Log error
        if log_error:
            self._log_error(error_response)
        
        # Store in history
        self.error_history.append(error_response)
        if len(self.error_history) > 1000:  # Limit history size
            self.error_history = self.error_history[-1000:]
        
        # Call callbacks
        for callback in self.error_callbacks:
            try:
                callback(error_response)
            except Exception as e:
                logger.error(f"Error callback failed: {e}")
        
        return error_response
    
    def _log_error(self, error_response: ErrorResponse):
        """Log error with structured data."""
        log_data = {
            "correlation_id": error_response.correlation_id,
            "error": error_response.error,
            "severity": error_response.severity,
            "category": error_response.category,
            "timestamp": error_response.timestamp.isoformat(),
            "context": error_response.context
        }
        
        # Choose log level based on severity
        if error_response.severity == ErrorSeverity.CRITICAL:
            logger.critical(error_response.message, extra=log_data)
        elif error_response.severity == ErrorSeverity.HIGH:
            logger.error(error_response.message, extra=log_data)
        elif error_response.severity == ErrorSeverity.MEDIUM:
            logger.warning(error_response.message, extra=log_data)
        else:
            logger.info(error_response.message, extra=log_data)
    
    def get_error_stats(self) -> Dict[str, Any]:
        """Get error statistics."""
        if not self.error_history:
            return {
                "total_errors": 0,
                "by_severity": {},
                "by_category": {},
                "recent_errors": []
            }
        
        stats = {
            "total_errors": len(self.error_history),
            "by_severity": {},
            "by_category": {},
            "recent_errors": []
        }
        
        for error in self.error_history:
            # Count by severity
            stats["by_severity"][error.severity] = stats["by_severity"].get(error.severity, 0) + 1
            
            # Count by category
            stats["by_category"][error.category] = stats["by_category"].get(error.category, 0) + 1
        
        # Get recent errors
        stats["recent_errors"] = [
            {
                "correlation_id": e.correlation_id,
                "error": e.error,
                "message": e.message,
                "timestamp": e.timestamp.isoformat(),
                "severity": e.severity,
                "category": e.category
            }
            for e in self.error_history[-10:]
        ]
        
        return stats


# Global error handler instance
_error_handler: Optional[ErrorHandler] = None


def get_error_handler() -> ErrorHandler:
    """Get global error handler instance."""
    global _error_handler
    if _error_handler is None:
        _error_handler = ErrorHandler()
    return _error_handler


# Context managers and decorators

@contextmanager
def with_correlation_id(correlation_id: Optional[str] = None):
    """Context manager to set correlation ID for errors."""
    handler = get_error_handler()
    context = ErrorContext(correlation_id=correlation_id or str(uuid.uuid4()))
    
    handler.push_context(context)
    try:
        yield context.correlation_id
    finally:
        handler.pop_context()


def handle_errors(
    reraise: bool = True,
    include_stack_trace: bool = False,
    default_return: Any = None,
    error_mapping: Optional[Dict[Type[Exception], Type[BaseError]]] = None
):
    """Decorator to handle errors in functions."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except BaseError:
                raise  # Re-raise our custom errors
            except Exception as e:
                # Map to custom error if mapping provided
                if error_mapping and type(e) in error_mapping:
                    mapped_error = error_mapping[type(e)](str(e))
                    handler = get_error_handler()
                    handler.handle_error(mapped_error, include_stack_trace)
                    if reraise:
                        raise mapped_error
                    return default_return
                else:
                    # Handle as generic error
                    handler = get_error_handler()
                    handler.handle_error(e, include_stack_trace)
                    if reraise:
                        raise
                    return default_return
        
        return wrapper
    return decorator


def async_handle_errors(
    reraise: bool = True,
    include_stack_trace: bool = False,
    default_return: Any = None,
    error_mapping: Optional[Dict[Type[Exception], Type[BaseError]]] = None
):
    """Decorator to handle errors in async functions."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except BaseError:
                raise  # Re-raise our custom errors
            except Exception as e:
                # Map to custom error if mapping provided
                if error_mapping and type(e) in error_mapping:
                    mapped_error = error_mapping[type(e)](str(e))
                    handler = get_error_handler()
                    handler.handle_error(mapped_error, include_stack_trace)
                    if reraise:
                        raise mapped_error
                    return default_return
                else:
                    # Handle as generic error
                    handler = get_error_handler()
                    handler.handle_error(e, include_stack_trace)
                    if reraise:
                        raise
                    return default_return
        
        return wrapper
    return decorator


# Utility functions

def log_error(
    error: Union[BaseError, Exception],
    include_stack_trace: bool = False,
    context: Optional[Dict[str, Any]] = None
) -> ErrorResponse:
    """Log an error and return error response."""
    handler = get_error_handler()
    return handler.handle_error(error, include_stack_trace, True, context)


def create_error_response(
    error_type: str,
    message: str,
    severity: ErrorSeverity = ErrorSeverity.MEDIUM,
    category: ErrorCategory = ErrorCategory.SYSTEM,
    details: Optional[List[ErrorDetail]] = None,
    context: Optional[Dict[str, Any]] = None,
    recovery_suggestions: Optional[List[str]] = None
) -> ErrorResponse:
    """Create an error response manually."""
    return ErrorResponse(
        error=error_type,
        message=message,
        correlation_id=str(uuid.uuid4()),
        severity=severity,
        category=category,
        details=details,
        context=context,
        recovery_suggestions=recovery_suggestions
    )