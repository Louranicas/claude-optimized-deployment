"""
SYNTHEX Security Module
Handles input validation, sanitization, and security controls
"""

import re
import logging
import hashlib
import time
from typing import Dict, Any, List, Optional, Union
from functools import wraps
from collections import defaultdict
from datetime import datetime, timedelta
import urllib.parse

try:
    import bleach
    BLEACH_AVAILABLE = True
except ImportError:
    BLEACH_AVAILABLE = False

try:
    from sqlalchemy.sql import text
    SQLALCHEMY_AVAILABLE = True
except ImportError:
    SQLALCHEMY_AVAILABLE = False

logger = logging.getLogger(__name__)

# Rate limiting storage
rate_limit_storage: Dict[str, List[float]] = defaultdict(list)

# Input validation patterns
SAFE_QUERY_PATTERN = re.compile(r'^[\w\s\-\.\,\!\?\:\;\'"]+$', re.UNICODE)
MAX_QUERY_LENGTH = 500
MAX_FILTER_VALUE_LENGTH = 100
ALLOWED_FILTER_KEYS = {'date_from', 'date_to', 'source', 'type', 'language', 'domain'}

# SQL injection prevention patterns
SQL_INJECTION_PATTERNS = [
    re.compile(r'(union|select|insert|update|delete|drop|create|alter|exec|execute)', re.IGNORECASE),
    re.compile(r'(script|javascript|vbscript|onload|onerror|onclick)', re.IGNORECASE),
    re.compile(r'[;\'"\\\x00\x1a]'),  # Common SQL injection characters
]

# XSS prevention
ALLOWED_HTML_TAGS = []  # No HTML tags allowed in search queries
ALLOWED_HTML_ATTRIBUTES = {}


class SecurityError(Exception):
    """Security-related error"""
    pass


class RateLimitError(SecurityError):
    """Rate limit exceeded error"""
    pass


def sanitize_query(query: str) -> str:
    """
    Sanitize search query input
    
    Args:
        query: Raw query string
        
    Returns:
        Sanitized query string
        
    Raises:
        SecurityError: If query contains malicious content
    """
    if not query:
        raise SecurityError("Query cannot be empty")
    
    # Check length
    if len(query) > MAX_QUERY_LENGTH:
        raise SecurityError(f"Query exceeds maximum length of {MAX_QUERY_LENGTH} characters")
    
    # Remove any HTML/script tags
    if BLEACH_AVAILABLE:
        query = bleach.clean(query, tags=ALLOWED_HTML_TAGS, attributes=ALLOWED_HTML_ATTRIBUTES, strip=True)
    else:
        # Basic HTML tag removal fallback
        query = re.sub(r'<[^>]+>', '', query)
    
    # Check for SQL injection patterns
    for pattern in SQL_INJECTION_PATTERNS:
        if pattern.search(query):
            logger.warning(f"Potential SQL injection attempt detected: {query[:50]}...")
            raise SecurityError("Query contains prohibited patterns")
    
    # URL decode to catch encoded attacks
    try:
        decoded_query = urllib.parse.unquote(query)
        if decoded_query != query:
            # Check decoded version for attacks
            for pattern in SQL_INJECTION_PATTERNS:
                if pattern.search(decoded_query):
                    logger.warning(f"Encoded SQL injection attempt detected: {query[:50]}...")
                    raise SecurityError("Query contains prohibited encoded patterns")
    except Exception:
        # If decoding fails, reject the query
        raise SecurityError("Query contains invalid encoding")
    
    # Normalize whitespace
    query = ' '.join(query.split())
    
    return query


def validate_filters(filters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate and sanitize filter parameters
    
    Args:
        filters: Raw filter dictionary
        
    Returns:
        Validated and sanitized filters
        
    Raises:
        SecurityError: If filters contain invalid data
    """
    if not isinstance(filters, dict):
        raise SecurityError("Filters must be a dictionary")
    
    validated_filters = {}
    
    for key, value in filters.items():
        # Only allow whitelisted filter keys
        if key not in ALLOWED_FILTER_KEYS:
            logger.warning(f"Rejected unknown filter key: {key}")
            continue
        
        # Validate filter values
        if isinstance(value, str):
            if len(value) > MAX_FILTER_VALUE_LENGTH:
                raise SecurityError(f"Filter value for '{key}' exceeds maximum length")
            
            # Sanitize string values
            if BLEACH_AVAILABLE:
                value = bleach.clean(value, tags=[], strip=True)
            else:
                value = re.sub(r'<[^>]+>', '', value)
            
            # Additional validation for specific filters
            if key in ['date_from', 'date_to']:
                # Validate date format (YYYY-MM-DD)
                if not re.match(r'^\d{4}-\d{2}-\d{2}$', value):
                    raise SecurityError(f"Invalid date format for '{key}'")
            
            elif key == 'language':
                # Validate language code (ISO 639-1)
                if not re.match(r'^[a-z]{2}$', value.lower()):
                    raise SecurityError(f"Invalid language code: {value}")
            
            elif key == 'domain':
                # Validate domain format
                if not re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', value):
                    raise SecurityError(f"Invalid domain format: {value}")
        
        elif isinstance(value, (list, tuple)):
            # Validate list values
            if len(value) > 10:
                raise SecurityError(f"Too many values for filter '{key}'")
            
            validated_list = []
            for item in value:
                if not isinstance(item, str):
                    raise SecurityError(f"Filter list items must be strings for '{key}'")
                if len(item) > MAX_FILTER_VALUE_LENGTH:
                    raise SecurityError(f"Filter list item exceeds maximum length for '{key}'")
                validated_list.append(bleach.clean(item, tags=[], strip=True) if BLEACH_AVAILABLE else re.sub(r"<[^>]+>", "", item))
            value = validated_list
        
        else:
            raise SecurityError(f"Invalid filter value type for '{key}'")
        
        validated_filters[key] = value
    
    return validated_filters


def validate_options(options: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate search options
    
    Args:
        options: Raw options dictionary
        
    Returns:
        Validated options
        
    Raises:
        SecurityError: If options contain invalid data
    """
    validated_options = {}
    
    # Validate max_results
    if 'max_results' in options:
        max_results = options['max_results']
        if not isinstance(max_results, int) or max_results < 1 or max_results > 1000:
            raise SecurityError("max_results must be between 1 and 1000")
        validated_options['max_results'] = max_results
    
    # Validate timeout_ms
    if 'timeout_ms' in options:
        timeout_ms = options['timeout_ms']
        if not isinstance(timeout_ms, int) or timeout_ms < 100 or timeout_ms > 30000:
            raise SecurityError("timeout_ms must be between 100 and 30000")
        validated_options['timeout_ms'] = timeout_ms
    
    # Validate sources
    if 'sources' in options:
        sources = options['sources']
        if not isinstance(sources, list):
            raise SecurityError("sources must be a list")
        if len(sources) > 10:
            raise SecurityError("Too many sources specified")
        
        allowed_sources = {'all', 'web', 'database', 'api', 'file', 'knowledge_base'}
        validated_sources = []
        for source in sources:
            if not isinstance(source, str):
                raise SecurityError("Source names must be strings")
            if source not in allowed_sources:
                raise SecurityError(f"Unknown source: {source}")
            validated_sources.append(source)
        validated_options['sources'] = validated_sources
    
    return validated_options


def rate_limit(max_requests: int = 100, window_seconds: int = 60):
    """
    Rate limiting decorator
    
    Args:
        max_requests: Maximum requests allowed in window
        window_seconds: Time window in seconds
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(self, *args, **kwargs):
            # Get client identifier (could be enhanced with IP address, API key, etc.)
            client_id = kwargs.get('client_id', 'default')
            
            current_time = time.time()
            window_start = current_time - window_seconds
            
            # Clean old entries
            rate_limit_storage[client_id] = [
                t for t in rate_limit_storage[client_id] 
                if t > window_start
            ]
            
            # Check rate limit
            if len(rate_limit_storage[client_id]) >= max_requests:
                logger.warning(f"Rate limit exceeded for client: {client_id}")
                raise RateLimitError(f"Rate limit exceeded: {max_requests} requests per {window_seconds} seconds")
            
            # Record this request
            rate_limit_storage[client_id].append(current_time)
            
            # Execute function
            return await func(self, *args, **kwargs)
        
        return wrapper
    return decorator


def build_safe_query(base_query: str, parameters: Dict[str, Any]) -> tuple:
    """
    Build a safe parameterized query
    
    Args:
        base_query: Base SQL query with placeholders
        parameters: Query parameters
        
    Returns:
        Tuple of (query, parameters) for safe execution
    """
    # Use SQLAlchemy's text() for safe parameterized queries
    query = text(base_query)
    
    # Validate all parameters
    safe_params = {}
    for key, value in parameters.items():
        if isinstance(value, str):
            # Sanitize string parameters
            value = bleach.clean(value, tags=[], strip=True) if BLEACH_AVAILABLE else re.sub(r"<[^>]+>", "", value)
        safe_params[key] = value
    
    return query, safe_params


def hash_query(query: str, options: Dict[str, Any]) -> str:
    """
    Generate a hash for query caching
    
    Args:
        query: Search query
        options: Query options
        
    Returns:
        Hash string for cache key
    """
    # Create a deterministic string representation
    cache_data = f"{query}:{sorted(options.items())}"
    return hashlib.sha256(cache_data.encode()).hexdigest()


def validate_api_key(api_key: str) -> bool:
    """
    Validate API key format
    
    Args:
        api_key: API key to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not api_key:
        return False
    
    # API keys should be alphanumeric with hyphens, 32-64 characters
    if not re.match(r'^[a-zA-Z0-9\-]{32,64}$', api_key):
        return False
    
    return True


def sanitize_url(url: str) -> str:
    """
    Sanitize and validate URLs
    
    Args:
        url: URL to sanitize
        
    Returns:
        Sanitized URL
        
    Raises:
        SecurityError: If URL is invalid or contains suspicious patterns
    """
    if not url:
        raise SecurityError("URL cannot be empty")
    
    # Parse URL
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        raise SecurityError("Invalid URL format")
    
    # Only allow HTTP(S) protocols
    if parsed.scheme not in ['http', 'https']:
        raise SecurityError("Only HTTP(S) URLs are allowed")
    
    # Check for suspicious patterns
    suspicious_patterns = [
        'javascript:', 'data:', 'vbscript:', 'file:', 'about:',
        '127.0.0.1', 'localhost', '0.0.0.0', '[::1]'
    ]
    
    url_lower = url.lower()
    for pattern in suspicious_patterns:
        if pattern in url_lower:
            raise SecurityError(f"URL contains prohibited pattern: {pattern}")
    
    # Reconstruct clean URL
    clean_url = urllib.parse.urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        parsed.query,
        ''  # Remove fragment
    ))
    
    return clean_url


def validate_subscription_params(query: str, interval_ms: int) -> tuple:
    """
    Validate subscription parameters
    
    Args:
        query: Subscription query
        interval_ms: Update interval in milliseconds
        
    Returns:
        Tuple of (sanitized_query, validated_interval)
        
    Raises:
        SecurityError: If parameters are invalid
    """
    # Sanitize query
    sanitized_query = sanitize_query(query)
    
    # Validate interval
    if not isinstance(interval_ms, int):
        raise SecurityError("interval_ms must be an integer")
    
    # Minimum 10 seconds, maximum 1 hour
    if interval_ms < 10000 or interval_ms > 3600000:
        raise SecurityError("interval_ms must be between 10000 and 3600000")
    
    return sanitized_query, interval_ms


# Export security utilities
__all__ = [
    'SecurityError',
    'RateLimitError',
    'sanitize_query',
    'validate_filters',
    'validate_options',
    'rate_limit',
    'build_safe_query',
    'hash_query',
    'validate_api_key',
    'sanitize_url',
    'validate_subscription_params',
]