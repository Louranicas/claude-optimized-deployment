"""Test utilities for auth module.

Provides test fixtures and helpers for auth-related tests.
"""

import secrets
from typing import Optional
from .audit import AuditLogger
from .audit_config import audit_config


def get_test_signing_key() -> str:
    """Generate a secure test signing key.
    
    Returns:
        str: A secure random signing key for testing
    """
    return secrets.token_urlsafe(64)


def get_test_audit_logger(signing_key: Optional[str] = None) -> AuditLogger:
    """Create an AuditLogger instance for testing.
    
    Args:
        signing_key: Optional signing key. If not provided, generates a random one.
        
    Returns:
        AuditLogger: Configured audit logger for testing
    """
    if not signing_key:
        signing_key = get_test_signing_key()
    
    return AuditLogger(signing_key=signing_key)


def setup_test_audit_config():
    """Set up audit configuration for testing."""
    # Generate and set a test signing key
    test_key = get_test_signing_key()
    audit_config.signing_key = test_key
    return test_key