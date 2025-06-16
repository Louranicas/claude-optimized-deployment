"""
Security Policy Enforcement Module
Implements comprehensive security policies across the application
"""

import os
import re
import hashlib
import secrets
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class SecurityPolicy:
    """Central security policy enforcement"""
    
    # Password requirements
    PASSWORD_MIN_LENGTH = 12
    PASSWORD_REQUIRE_UPPERCASE = True
    PASSWORD_REQUIRE_LOWERCASE = True
    PASSWORD_REQUIRE_NUMBERS = True
    PASSWORD_REQUIRE_SPECIAL = True
    PASSWORD_SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # Token settings
    TOKEN_LENGTH = 32
    TOKEN_EXPIRY_HOURS = 24
    SESSION_TIMEOUT_MINUTES = 30
    
    # Rate limiting
    RATE_LIMIT_REQUESTS = 100
    RATE_LIMIT_WINDOW_SECONDS = 60
    
    # Security headers
    SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
    }
    
    @classmethod
    def validate_password(cls, password: str) -> Tuple[bool, List[str]]:
        """Validate password against policy"""
        errors = []
        
        if len(password) < cls.PASSWORD_MIN_LENGTH:
            errors.append(f"Password must be at least {cls.PASSWORD_MIN_LENGTH} characters")
        
        if cls.PASSWORD_REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            errors.append("Password must contain uppercase letters")
        
        if cls.PASSWORD_REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            errors.append("Password must contain lowercase letters")
        
        if cls.PASSWORD_REQUIRE_NUMBERS and not re.search(r'[0-9]', password):
            errors.append("Password must contain numbers")
        
        if cls.PASSWORD_REQUIRE_SPECIAL and not re.search(f'[{re.escape(cls.PASSWORD_SPECIAL_CHARS)}]', password):
            errors.append("Password must contain special characters")
        
        # Check for common passwords
        if password.lower() in cls._get_common_passwords():
            errors.append("Password is too common")
        
        return len(errors) == 0, errors
    
    @classmethod
    def generate_secure_token(cls, length: Optional[int] = None) -> str:
        """Generate cryptographically secure token"""
        token_length = length or cls.TOKEN_LENGTH
        return secrets.token_urlsafe(token_length)
    
    @classmethod
    def hash_password(cls, password: str) -> str:
        """Hash password using secure algorithm"""
        # Use bcrypt or argon2 in production
        import hashlib
        salt = secrets.token_hex(16)
        return hashlib.pbkdf2_hmac('sha256', 
                                   password.encode('utf-8'), 
                                   salt.encode('utf-8'), 
                                   100000).hex() + ':' + salt
    
    @classmethod
    def verify_password(cls, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        try:
            stored_hash, salt = password_hash.split(':')
            test_hash = hashlib.pbkdf2_hmac('sha256',
                                           password.encode('utf-8'),
                                           salt.encode('utf-8'),
                                           100000).hex()
            return stored_hash == test_hash
        except Exception:
            return False
    
    @classmethod
    def sanitize_input(cls, user_input: str) -> str:
        """Sanitize user input to prevent injection attacks"""
        # Remove potential SQL injection patterns
        sql_patterns = [
            r'(union|select|insert|update|delete|drop|create|alter|exec|execute)',
            r'(script|javascript|vbscript|onload|onerror|onclick)',
            r'[;'"\-\-\/\*\*\/]'
        ]
        
        sanitized = user_input
        for pattern in sql_patterns:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)
        
        # HTML escape
        html_escape_table = {
            "&": "&amp;",
            '"': "&quot;",
            "'": "&#x27;",
            ">": "&gt;",
            "<": "&lt;",
        }
        
        for char, escape in html_escape_table.items():
            sanitized = sanitized.replace(char, escape)
        
        return sanitized.strip()
    
    @classmethod
    def validate_file_upload(cls, filename: str, content: bytes, 
                           max_size: int = 10 * 1024 * 1024) -> Tuple[bool, Optional[str]]:
        """Validate file uploads for security"""
        # Check file size
        if len(content) > max_size:
            return False, f"File size exceeds {max_size} bytes"
        
        # Check file extension
        allowed_extensions = {'.pdf', '.txt', '.png', '.jpg', '.jpeg', '.doc', '.docx'}
        ext = os.path.splitext(filename)[1].lower()
        if ext not in allowed_extensions:
            return False, f"File type {ext} not allowed"
        
        # Check for malicious content patterns
        malicious_patterns = [
            b'<%',  # ASP
            b'<?php',  # PHP
            b'<script',  # JavaScript
            b'\x00',  # Null bytes
        ]
        
        for pattern in malicious_patterns:
            if pattern in content[:1024]:  # Check first 1KB
                return False, "Potentially malicious content detected"
        
        return True, None
    
    @classmethod
    def get_security_headers(cls) -> Dict[str, str]:
        """Get security headers for HTTP responses"""
        return cls.SECURITY_HEADERS.copy()
    
    @classmethod
    def _get_common_passwords(cls) -> set:
        """Get list of common passwords to block"""
        return {
            'password', '123456', 'password123', 'admin', 'letmein',
            'welcome', 'monkey', '1234567890', 'qwerty', 'abc123',
            'Password1', 'password1', '123456789', 'welcome123',
            'admin123', 'root', 'toor', 'pass', 'test', 'guest'
        }

# Export policy instance
security_policy = SecurityPolicy()
