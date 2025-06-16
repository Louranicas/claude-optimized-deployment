"""
Comprehensive exception hierarchy for Claude-Optimized Deployment Engine.

This module provides a complete exception hierarchy with:
- Base exceptions for major error categories
- Specific exceptions for common failure modes
- Error codes for programmatic handling
- Context preservation for debugging
- Serialization support for API responses
"""

from __future__ import annotations
import traceback
from typing import Dict, Any, Optional, List, Union
from datetime import datetime
from enum import Enum
import json


class ErrorCode(str, Enum):
    """Standard error codes for categorizing exceptions."""
    
    # Infrastructure errors (1xxx)
    INFRASTRUCTURE_GENERAL = "1000"
    INFRASTRUCTURE_DOCKER = "1001"
    INFRASTRUCTURE_KUBERNETES = "1002"
    INFRASTRUCTURE_CLOUD = "1003"
    INFRASTRUCTURE_COMMAND = "1004"
    INFRASTRUCTURE_RESOURCE = "1005"
    
    # AI/Expert errors (2xxx)
    AI_GENERAL = "2000"
    AI_API_ERROR = "2001"
    AI_RATE_LIMIT = "2002"
    AI_INVALID_RESPONSE = "2003"
    AI_TIMEOUT = "2004"
    AI_CONSENSUS_FAILURE = "2005"
    
    # MCP errors (3xxx)
    MCP_GENERAL = "3000"
    MCP_SERVER_NOT_FOUND = "3001"
    MCP_TOOL_NOT_FOUND = "3002"
    MCP_TOOL_EXECUTION = "3003"
    MCP_PROTOCOL_ERROR = "3004"
    MCP_INITIALIZATION = "3005"
    
    # Validation errors (4xxx)
    VALIDATION_GENERAL = "4000"
    VALIDATION_TYPE = "4001"
    VALIDATION_RANGE = "4002"
    VALIDATION_FORMAT = "4003"
    VALIDATION_REQUIRED = "4004"
    VALIDATION_CONSTRAINT = "4005"
    
    # Network errors (5xxx)
    NETWORK_GENERAL = "5000"
    NETWORK_CONNECTION = "5001"
    NETWORK_TIMEOUT = "5002"
    NETWORK_DNS = "5003"
    NETWORK_SSL = "5004"
    DATABASE_CONNECTION = "5005"
    DATABASE_GENERAL = "5006"
    
    # Authentication errors (6xxx)
    AUTH_GENERAL = "6000"
    AUTH_INVALID_CREDENTIALS = "6001"
    AUTH_TOKEN_EXPIRED = "6002"
    AUTH_PERMISSION_DENIED = "6003"
    AUTH_MFA_REQUIRED = "6004"
    
    # Configuration errors (7xxx)
    CONFIG_GENERAL = "7000"
    CONFIG_MISSING = "7001"
    CONFIG_INVALID = "7002"
    CONFIG_ENVIRONMENT = "7003"
    CONFIG_FILE_ERROR = "7004"


class BaseDeploymentError(Exception):
    """
    Base exception for all deployment engine errors.
    
    Features:
    - Error code for categorization
    - Context dictionary for debugging
    - Timestamp for tracking
    - Serialization support
    - Stack trace preservation
    """
    
    def __init__(
        self,
        message: str,
        error_code: ErrorCode = ErrorCode.INFRASTRUCTURE_GENERAL,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None
    ):
        """
        Initialize base exception.
        
        Args:
            message: Human-readable error message
            error_code: Categorization code
            context: Additional context information
            cause: Original exception that caused this error
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.context = context or {}
        self.cause = cause
        self.timestamp = datetime.utcnow()
        self.stack_trace = traceback.format_exc()
        
        # Add cause information to context
        if cause:
            self.context['cause_type'] = type(cause).__name__
            self.context['cause_message'] = str(cause)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for serialization."""
        return {
            'error_type': self.__class__.__name__,
            'message': self.message,
            'error_code': self.error_code.value,
            'context': self.context,
            'timestamp': self.timestamp.isoformat(),
            'stack_trace': self.stack_trace if self._include_stack_trace() else None
        }
    
    def to_json(self) -> str:
        """Convert exception to JSON string."""
        return json.dumps(self.to_dict())
    
    def _include_stack_trace(self) -> bool:
        """Determine if stack trace should be included in serialization."""
        # Include in development, exclude in production
        import os
        return os.getenv('ENVIRONMENT', 'development') == 'development'
    
    def __str__(self) -> str:
        """String representation with error code."""
        return f"[{self.error_code.value}] {self.message}"


# Infrastructure Exceptions

class InfrastructureError(BaseDeploymentError):
    """Base class for infrastructure-related errors."""
    
    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None, cause: Optional[Exception] = None):
        super().__init__(message, ErrorCode.INFRASTRUCTURE_GENERAL, context, cause)


class DockerError(InfrastructureError):
    """Docker-specific infrastructure errors."""
    
    def __init__(self, message: str, container_id: Optional[str] = None, image: Optional[str] = None, **kwargs):
        context = kwargs.get('context', {})
        if container_id:
            context['container_id'] = container_id
        if image:
            context['image'] = image
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        self.error_code = ErrorCode.INFRASTRUCTURE_DOCKER


class KubernetesError(InfrastructureError):
    """Kubernetes-specific infrastructure errors."""
    
    def __init__(self, message: str, namespace: Optional[str] = None, resource: Optional[str] = None, **kwargs):
        context = kwargs.get('context', {})
        if namespace:
            context['namespace'] = namespace
        if resource:
            context['resource'] = resource
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        self.error_code = ErrorCode.INFRASTRUCTURE_KUBERNETES


class CloudProviderError(InfrastructureError):
    """Cloud provider-specific errors (AWS, Azure, GCP)."""
    
    def __init__(self, message: str, provider: str, service: Optional[str] = None, **kwargs):
        context = kwargs.get('context', {})
        context['provider'] = provider
        if service:
            context['service'] = service
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        self.error_code = ErrorCode.INFRASTRUCTURE_CLOUD


class CommandExecutionError(InfrastructureError):
    """Command execution failures."""
    
    def __init__(self, message: str, command: str, exit_code: Optional[int] = None, stderr: Optional[str] = None, **kwargs):
        context = kwargs.get('context', {})
        context['command'] = command
        if exit_code is not None:
            context['exit_code'] = exit_code
        if stderr:
            context['stderr'] = stderr
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        self.error_code = ErrorCode.INFRASTRUCTURE_COMMAND


class ResourceError(InfrastructureError):
    """Resource limitation or availability errors."""
    
    def __init__(self, message: str, resource_type: str, available: Optional[Any] = None, required: Optional[Any] = None, **kwargs):
        context = kwargs.get('context', {})
        context['resource_type'] = resource_type
        if available is not None:
            context['available'] = available
        if required is not None:
            context['required'] = required
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        self.error_code = ErrorCode.INFRASTRUCTURE_RESOURCE


# AI/Expert Exceptions

class AIError(BaseDeploymentError):
    """Base class for AI/Expert-related errors."""
    
    def __init__(self, message: str, expert_type: Optional[str] = None, context: Optional[Dict[str, Any]] = None, cause: Optional[Exception] = None):
        context = context or {}
        if expert_type:
            context['expert_type'] = expert_type
        super().__init__(message, ErrorCode.AI_GENERAL, context, cause)


class AIAPIError(AIError):
    """AI provider API errors."""
    
    def __init__(self, message: str, provider: str, status_code: Optional[int] = None, response_body: Optional[str] = None, **kwargs):
        context = kwargs.get('context', {})
        context['provider'] = provider
        if status_code:
            context['status_code'] = status_code
        if response_body:
            context['response_body'] = response_body
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        self.error_code = ErrorCode.AI_API_ERROR


class AIRateLimitError(AIError):
    """AI provider rate limit errors."""
    
    def __init__(self, message: str, provider: str, retry_after: Optional[int] = None, **kwargs):
        context = kwargs.get('context', {})
        context['provider'] = provider
        if retry_after:
            context['retry_after_seconds'] = retry_after
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        self.error_code = ErrorCode.AI_RATE_LIMIT


class AIResponseError(AIError):
    """Invalid or malformed AI responses."""
    
    def __init__(self, message: str, response: Any, expected_format: Optional[str] = None, **kwargs):
        context = kwargs.get('context', {})
        context['response'] = str(response)
        if expected_format:
            context['expected_format'] = expected_format
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        self.error_code = ErrorCode.AI_INVALID_RESPONSE


class AITimeoutError(AIError):
    """AI request timeout errors."""
    
    def __init__(self, message: str, timeout_seconds: float, **kwargs):
        context = kwargs.get('context', {})
        context['timeout_seconds'] = timeout_seconds
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        self.error_code = ErrorCode.AI_TIMEOUT


class ConsensusError(AIError):
    """Expert consensus failures."""
    
    def __init__(self, message: str, num_experts: int, responses: Optional[List[Dict[str, Any]]] = None, **kwargs):
        context = kwargs.get('context', {})
        context['num_experts'] = num_experts
        if responses:
            context['response_summary'] = [
                {'expert': r.get('expert_type'), 'confidence': r.get('confidence')}
                for r in responses
            ]
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        self.error_code = ErrorCode.AI_CONSENSUS_FAILURE


# MCP Exceptions

class MCPError(BaseDeploymentError):
    """Base class for MCP-related errors."""
    
    def __init__(self, message: str, server_name: Optional[str] = None, context: Optional[Dict[str, Any]] = None, cause: Optional[Exception] = None):
        context = context or {}
        if server_name:
            context['server_name'] = server_name
        super().__init__(message, ErrorCode.MCP_GENERAL, context, cause)


class MCPServerNotFoundError(MCPError):
    """MCP server not found or not registered."""
    
    def __init__(self, server_name: str, available_servers: Optional[List[str]] = None, **kwargs):
        message = f"MCP server '{server_name}' not found"
        context = kwargs.get('context', {})
        if available_servers:
            context['available_servers'] = available_servers
        kwargs['context'] = context
        super().__init__(message, server_name=server_name, **kwargs)
        self.error_code = ErrorCode.MCP_SERVER_NOT_FOUND


class MCPToolNotFoundError(MCPError):
    """MCP tool not found on server."""
    
    def __init__(self, tool_name: str, server_name: str, available_tools: Optional[List[str]] = None, **kwargs):
        message = f"Tool '{tool_name}' not found on server '{server_name}'"
        context = kwargs.get('context', {})
        context['tool_name'] = tool_name
        if available_tools:
            context['available_tools'] = available_tools
        kwargs['context'] = context
        super().__init__(message, server_name=server_name, **kwargs)
        self.error_code = ErrorCode.MCP_TOOL_NOT_FOUND


class MCPToolExecutionError(MCPError):
    """MCP tool execution failures."""
    
    def __init__(self, message: str, tool_name: str, server_name: str, arguments: Optional[Dict[str, Any]] = None, **kwargs):
        context = kwargs.get('context', {})
        context['tool_name'] = tool_name
        if arguments:
            context['arguments'] = arguments
        kwargs['context'] = context
        super().__init__(message, server_name=server_name, **kwargs)
        self.error_code = ErrorCode.MCP_TOOL_EXECUTION


class MCPProtocolError(MCPError):
    """MCP protocol violations or communication errors."""
    
    def __init__(self, message: str, method: Optional[str] = None, **kwargs):
        context = kwargs.get('context', {})
        if method:
            context['method'] = method
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        self.error_code = ErrorCode.MCP_PROTOCOL_ERROR


class MCPInitializationError(MCPError):
    """MCP server initialization failures."""
    
    def __init__(self, message: str, server_name: str, **kwargs):
        super().__init__(message, server_name=server_name, **kwargs)
        self.error_code = ErrorCode.MCP_INITIALIZATION


# Validation Exceptions

class ValidationError(BaseDeploymentError):
    """Base class for validation errors."""
    
    def __init__(self, message: str, field: str, value: Any, context: Optional[Dict[str, Any]] = None, cause: Optional[Exception] = None):
        context = context or {}
        context['field'] = field
        context['value'] = str(value)
        context['value_type'] = type(value).__name__
        super().__init__(message, ErrorCode.VALIDATION_GENERAL, context, cause)
        self.field = field
        self.value = value


class TypeValidationError(ValidationError):
    """Type validation failures."""
    
    def __init__(self, field: str, value: Any, expected_type: Union[type, str], **kwargs):
        expected = expected_type.__name__ if isinstance(expected_type, type) else str(expected_type)
        message = f"Field '{field}' expected type {expected}, got {type(value).__name__}"
        context = kwargs.get('context', {})
        context['expected_type'] = expected
        kwargs['context'] = context
        super().__init__(message, field, value, **kwargs)
        self.error_code = ErrorCode.VALIDATION_TYPE


class RangeValidationError(ValidationError):
    """Range validation failures."""
    
    def __init__(self, field: str, value: Any, min_value: Optional[Any] = None, max_value: Optional[Any] = None, **kwargs):
        parts = []
        context = kwargs.get('context', {})
        if min_value is not None:
            parts.append(f"minimum {min_value}")
            context['min_value'] = min_value
        if max_value is not None:
            parts.append(f"maximum {max_value}")
            context['max_value'] = max_value
        message = f"Field '{field}' value {value} outside allowed range: {', '.join(parts)}"
        kwargs['context'] = context
        super().__init__(message, field, value, **kwargs)
        self.error_code = ErrorCode.VALIDATION_RANGE


class FormatValidationError(ValidationError):
    """Format validation failures."""
    
    def __init__(self, field: str, value: Any, expected_format: str, **kwargs):
        message = f"Field '{field}' value does not match expected format: {expected_format}"
        context = kwargs.get('context', {})
        context['expected_format'] = expected_format
        kwargs['context'] = context
        super().__init__(message, field, value, **kwargs)
        self.error_code = ErrorCode.VALIDATION_FORMAT


class RequiredFieldError(ValidationError):
    """Required field missing."""
    
    def __init__(self, field: str, **kwargs):
        message = f"Required field '{field}' is missing or None"
        super().__init__(message, field, None, **kwargs)
        self.error_code = ErrorCode.VALIDATION_REQUIRED


class ConstraintValidationError(ValidationError):
    """Custom constraint validation failures."""
    
    def __init__(self, field: str, value: Any, constraint: str, **kwargs):
        message = f"Field '{field}' failed constraint: {constraint}"
        context = kwargs.get('context', {})
        context['constraint'] = constraint
        kwargs['context'] = context
        super().__init__(message, field, value, **kwargs)
        self.error_code = ErrorCode.VALIDATION_CONSTRAINT


# Network Exceptions

class NetworkError(BaseDeploymentError):
    """Base class for network-related errors."""
    
    def __init__(self, message: str, url: Optional[str] = None, context: Optional[Dict[str, Any]] = None, cause: Optional[Exception] = None):
        context = context or {}
        if url:
            context['url'] = url
        super().__init__(message, ErrorCode.NETWORK_GENERAL, context, cause)


class ConnectionError(NetworkError):
    """Network connection failures."""
    
    def __init__(self, message: str, host: str, port: Optional[int] = None, **kwargs):
        context = kwargs.get('context', {})
        context['host'] = host
        if port:
            context['port'] = port
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        self.error_code = ErrorCode.NETWORK_CONNECTION


class DatabaseConnectionError(ConnectionError):
    """Database connection failures."""
    
    def __init__(self, message: str, database: str, **kwargs):
        super().__init__(message, host=database, **kwargs)
        self.error_code = ErrorCode.DATABASE_CONNECTION


class NotFoundError(BaseDeploymentError):
    """Resource not found error."""
    
    def __init__(self, message: str, resource_type: str, resource_id: Optional[str] = None, **kwargs):
        context = kwargs.get('context', {})
        context['resource_type'] = resource_type
        if resource_id:
            context['resource_id'] = resource_id
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        self.error_code = ErrorCode.VALIDATION_GENERAL




class ConflictError(BaseDeploymentError):
    """Resource conflict error."""
    
    def __init__(self, message: str, resource_type: str, conflict_reason: str, **kwargs):
        context = kwargs.get('context', {})
        context['resource_type'] = resource_type
        context['conflict_reason'] = conflict_reason
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        self.error_code = ErrorCode.VALIDATION_GENERAL


class DatabaseError(BaseDeploymentError):
    """General database error."""
    
    def __init__(self, message: str, operation: str, **kwargs):
        context = kwargs.get('context', {})
        context['operation'] = operation
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        self.error_code = ErrorCode.DATABASE_GENERAL


class AuthorizationError(BaseDeploymentError):
    """Authorization failed error."""
    
    def __init__(self, message: str, action: str, resource: Optional[str] = None, **kwargs):
        context = kwargs.get('context', {})
        context['action'] = action
        if resource:
            context['resource'] = resource
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        self.error_code = ErrorCode.AUTH_PERMISSION_DENIED


class TimeoutError(NetworkError):
    """Network timeout errors."""
    
    def __init__(self, message: str, timeout_seconds: float, operation: Optional[str] = None, **kwargs):
        context = kwargs.get('context', {})
        context['timeout_seconds'] = timeout_seconds
        if operation:
            context['operation'] = operation
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        self.error_code = ErrorCode.NETWORK_TIMEOUT


class DNSError(NetworkError):
    """DNS resolution failures."""
    
    def __init__(self, message: str, hostname: str, **kwargs):
        context = kwargs.get('context', {})
        context['hostname'] = hostname
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        self.error_code = ErrorCode.NETWORK_DNS


class SSLError(NetworkError):
    """SSL/TLS errors."""
    
    def __init__(self, message: str, certificate_error: Optional[str] = None, **kwargs):
        context = kwargs.get('context', {})
        if certificate_error:
            context['certificate_error'] = certificate_error
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        self.error_code = ErrorCode.NETWORK_SSL


# Authentication Exceptions

class AuthenticationError(BaseDeploymentError):
    """Base class for authentication errors."""
    
    def __init__(self, message: str, auth_method: Optional[str] = None, context: Optional[Dict[str, Any]] = None, cause: Optional[Exception] = None):
        context = context or {}
        if auth_method:
            context['auth_method'] = auth_method
        super().__init__(message, ErrorCode.AUTH_GENERAL, context, cause)


class InvalidCredentialsError(AuthenticationError):
    """Invalid credentials provided."""
    
    def __init__(self, message: str = "Invalid credentials provided", username: Optional[str] = None, **kwargs):
        context = kwargs.get('context', {})
        if username:
            context['username'] = username
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        self.error_code = ErrorCode.AUTH_INVALID_CREDENTIALS


class TokenExpiredError(AuthenticationError):
    """Authentication token expired."""
    
    def __init__(self, message: str = "Authentication token has expired", token_type: Optional[str] = None, **kwargs):
        context = kwargs.get('context', {})
        if token_type:
            context['token_type'] = token_type
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        self.error_code = ErrorCode.AUTH_TOKEN_EXPIRED


class PermissionDeniedError(AuthenticationError):
    """Permission denied for requested operation."""
    
    def __init__(self, message: str, operation: str, required_permission: Optional[str] = None, **kwargs):
        context = kwargs.get('context', {})
        context['operation'] = operation
        if required_permission:
            context['required_permission'] = required_permission
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        self.error_code = ErrorCode.AUTH_PERMISSION_DENIED


class MFARequiredError(AuthenticationError):
    """Multi-factor authentication required."""
    
    def __init__(self, message: str = "Multi-factor authentication required", mfa_type: Optional[str] = None, **kwargs):
        context = kwargs.get('context', {})
        if mfa_type:
            context['mfa_type'] = mfa_type
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        self.error_code = ErrorCode.AUTH_MFA_REQUIRED


# Configuration Exceptions

class ConfigurationError(BaseDeploymentError):
    """Base class for configuration errors."""
    
    def __init__(self, message: str, config_key: Optional[str] = None, context: Optional[Dict[str, Any]] = None, cause: Optional[Exception] = None):
        context = context or {}
        if config_key:
            context['config_key'] = config_key
        super().__init__(message, ErrorCode.CONFIG_GENERAL, context, cause)


class MissingConfigError(ConfigurationError):
    """Required configuration missing."""
    
    def __init__(self, config_key: str, config_source: Optional[str] = None, **kwargs):
        message = f"Required configuration '{config_key}' is missing"
        context = kwargs.get('context', {})
        if config_source:
            context['config_source'] = config_source
            message += f" from {config_source}"
        kwargs['context'] = context
        super().__init__(message, config_key=config_key, **kwargs)
        self.error_code = ErrorCode.CONFIG_MISSING


class InvalidConfigError(ConfigurationError):
    """Invalid configuration value."""
    
    def __init__(self, config_key: str, value: Any, reason: str, **kwargs):
        message = f"Invalid configuration for '{config_key}': {reason}"
        context = kwargs.get('context', {})
        context['value'] = str(value)
        context['reason'] = reason
        kwargs['context'] = context
        super().__init__(message, config_key=config_key, **kwargs)
        self.error_code = ErrorCode.CONFIG_INVALID


class EnvironmentError(ConfigurationError):
    """Environment-specific configuration errors."""
    
    def __init__(self, message: str, env_var: Optional[str] = None, **kwargs):
        context = kwargs.get('context', {})
        if env_var:
            context['env_var'] = env_var
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        self.error_code = ErrorCode.CONFIG_ENVIRONMENT


class ConfigFileError(ConfigurationError):
    """Configuration file errors."""
    
    def __init__(self, message: str, file_path: str, **kwargs):
        context = kwargs.get('context', {})
        context['file_path'] = file_path
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        self.error_code = ErrorCode.CONFIG_FILE_ERROR


# API Integration Exceptions

class APIError(BaseDeploymentError):
    """General API error."""
    
    def __init__(self, message: str, api_name: Optional[str] = None, status_code: Optional[int] = None, **kwargs):
        context = kwargs.get('context', {})
        if api_name:
            context['api_name'] = api_name
        if status_code:
            context['status_code'] = status_code
        kwargs['context'] = context
        super().__init__(message, ErrorCode.AI_API_ERROR, **kwargs)


class RateLimitError(APIError):
    """API rate limit exceeded."""
    
    def __init__(self, message: str, retry_after: Optional[int] = None, **kwargs):
        context = kwargs.get('context', {})
        if retry_after:
            context['retry_after'] = retry_after
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        self.error_code = ErrorCode.AI_RATE_LIMIT


# Helper functions for error handling

def wrap_exception(func):
    """
    Decorator to wrap exceptions with deployment-specific errors.
    
    Usage:
        @wrap_exception
        def my_function():
            # code that might raise exceptions
    """
    import functools
    
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except BaseDeploymentError:
            # Re-raise deployment errors as-is
            raise
        except Exception as e:
            # Wrap other exceptions
            raise BaseDeploymentError(
                f"Unexpected error in {func.__name__}: {str(e)}",
                cause=e
            )
    
    return wrapper


def handle_error(error: BaseDeploymentError, logger: Optional[Any] = None, reraise: bool = True):
    """
    Standard error handling with logging.
    
    Args:
        error: The deployment error to handle
        logger: Optional logger instance
        reraise: Whether to re-raise the error after handling
    """
    if logger:
        logger.error(
            f"{error.__class__.__name__}: {error.message}",
            extra={
                'error_code': error.error_code.value,
                'context': error.context,
                'stack_trace': error.stack_trace
            }
        )
    
    if reraise:
        raise error


# Export all exception classes
__all__ = [
    # Base
    'BaseDeploymentError',
    'ErrorCode',
    
    # Infrastructure
    'InfrastructureError',
    'DockerError',
    'KubernetesError',
    'CloudProviderError',
    'CommandExecutionError',
    'ResourceError',
    
    # AI/Expert
    'AIError',
    'AIAPIError',
    'AIRateLimitError',
    'AIResponseError',
    'AITimeoutError',
    'ConsensusError',
    
    # MCP
    'MCPError',
    'MCPServerNotFoundError',
    'MCPToolNotFoundError',
    'MCPToolExecutionError',
    'MCPProtocolError',
    'MCPInitializationError',
    
    # Validation
    'ValidationError',
    'TypeValidationError',
    'RangeValidationError',
    'FormatValidationError',
    'RequiredFieldError',
    'ConstraintValidationError',
    
    # Network
    'NetworkError',
    'ConnectionError',
    'TimeoutError',
    'DNSError',
    'SSLError',
    
    # Authentication
    'AuthenticationError',
    'InvalidCredentialsError',
    'TokenExpiredError',
    'PermissionDeniedError',
    'MFARequiredError',
    
    # Configuration
    'ConfigurationError',
    'MissingConfigError',
    'InvalidConfigError',
    'EnvironmentError',
    'ConfigFileError',
    
    # API Integration
    'APIError',
    'RateLimitError',
    
    # Helpers
    'wrap_exception',
    'handle_error'
]