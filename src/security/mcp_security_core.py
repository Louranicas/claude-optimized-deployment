"""
MCP Security Core Module
Comprehensive security hardening framework for MCP servers.

This module provides:
1. Authentication and authorization layer
2. Input validation and sanitization
3. Rate limiting and DDoS protection
4. Encryption and secrets management
5. Security monitoring and audit logging
6. Vulnerability management
"""

import asyncio
import hashlib
import hmac
import json
import jwt
import time
import re
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
from contextlib import asynccontextmanager
import secrets
import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

logger = logging.getLogger(__name__)


class SecurityLevel(Enum):
    """Security level classifications."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuthenticationMethod(Enum):
    """Supported authentication methods."""
    API_KEY = "api_key"
    JWT_TOKEN = "jwt_token"
    MUTUAL_TLS = "mutual_tls"
    OAUTH2 = "oauth2"


class RateLimitType(Enum):
    """Rate limit types."""
    PER_CLIENT = "per_client"
    GLOBAL = "global"
    PER_ENDPOINT = "per_endpoint"
    ADAPTIVE = "adaptive"


@dataclass
class SecurityConfig:
    """Security configuration for MCP servers."""
    # Authentication
    auth_methods: List[AuthenticationMethod] = field(default_factory=lambda: [AuthenticationMethod.API_KEY])
    jwt_secret: Optional[str] = None
    jwt_algorithm: str = "HS256"
    jwt_expiry_hours: int = 24
    api_key_length: int = 64
    
    # Rate limiting
    rate_limit_enabled: bool = True
    requests_per_minute: int = 100
    burst_capacity: int = 150
    adaptive_rate_limiting: bool = True
    ddos_protection: bool = True
    
    # Input validation
    input_validation_enabled: bool = True
    max_request_size: int = 10 * 1024 * 1024  # 10MB
    allowed_content_types: List[str] = field(default_factory=lambda: ["application/json", "text/plain"])
    
    # Encryption
    encryption_enabled: bool = True
    encryption_key: Optional[str] = None
    tls_enabled: bool = True
    tls_cert_path: Optional[str] = None
    tls_key_path: Optional[str] = None
    
    # Security monitoring
    audit_logging: bool = True
    intrusion_detection: bool = True
    anomaly_detection: bool = True
    security_metrics: bool = True
    
    # Session management
    session_timeout_minutes: int = 30
    max_concurrent_sessions: int = 100
    session_encryption: bool = True


@dataclass
class SecurityContext:
    """Security context for requests."""
    user_id: str
    session_id: str
    roles: List[str]
    permissions: List[str]
    auth_method: AuthenticationMethod
    client_ip: str
    user_agent: str
    timestamp: datetime
    risk_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RateLimitBucket:
    """Rate limiting bucket for tracking request counts."""
    capacity: int
    tokens: float
    last_refill: float
    
    def consume(self, tokens: int = 1) -> bool:
        """Consume tokens from bucket."""
        now = time.time()
        # Refill tokens based on time elapsed
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed)
        self.last_refill = now
        
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False


class SecurityValidator:
    """Input validation and sanitization."""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        
        # Compile regex patterns for common attacks
        self.sql_injection_patterns = [
            re.compile(r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC(UTE)?|UNION|SCRIPT)\b)", re.IGNORECASE),
            re.compile(r"('|(\\\\');|--|\*|\*/|/\*)", re.IGNORECASE),
            re.compile(r"(\b(OR|AND)\s+\d+\s*=\s*\d+)", re.IGNORECASE)
        ]
        
        self.xss_patterns = [
            re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
            re.compile(r"javascript:", re.IGNORECASE),
            re.compile(r"on\w+\s*=", re.IGNORECASE),
            re.compile(r"<iframe[^>]*>.*?</iframe>", re.IGNORECASE | re.DOTALL)
        ]
        
        self.command_injection_patterns = [
            re.compile(r"[;&|`$(){}[\]\\]"),
            re.compile(r"\b(rm|del|format|shutdown|reboot|kill|exec|eval|system)\b", re.IGNORECASE)
        ]
        
        self.path_traversal_patterns = [
            re.compile(r"\.\./"),
            re.compile(r"\.\.\\\\"),
            re.compile(r"%2e%2e%2f", re.IGNORECASE),
            re.compile(r"%2e%2e%5c", re.IGNORECASE)
        ]
    
    def validate_input(self, data: Any, context: SecurityContext) -> bool:
        """Validate input data for security threats."""
        if not self.config.input_validation_enabled:
            return True
        
        try:
            # Convert to string for analysis
            if isinstance(data, dict):
                data_str = json.dumps(data)
            elif isinstance(data, (list, tuple)):
                data_str = str(data)
            else:
                data_str = str(data)
            
            # Check for SQL injection
            if any(pattern.search(data_str) for pattern in self.sql_injection_patterns):
                logger.warning(f"SQL injection attempt detected from {context.client_ip}")
                return False
            
            # Check for XSS
            if any(pattern.search(data_str) for pattern in self.xss_patterns):
                logger.warning(f"XSS attempt detected from {context.client_ip}")
                return False
            
            # Check for command injection
            if any(pattern.search(data_str) for pattern in self.command_injection_patterns):
                logger.warning(f"Command injection attempt detected from {context.client_ip}")
                return False
            
            # Check for path traversal
            if any(pattern.search(data_str) for pattern in self.path_traversal_patterns):
                logger.warning(f"Path traversal attempt detected from {context.client_ip}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Input validation error: {e}")
            return False
    
    def sanitize_input(self, data: Any) -> Any:
        """Sanitize input data."""
        if isinstance(data, str):
            # Remove potentially dangerous characters
            data = re.sub(r"[<>\"'&]", "", data)
            # Limit length
            if len(data) > 10000:
                data = data[:10000]
        elif isinstance(data, dict):
            return {k: self.sanitize_input(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.sanitize_input(item) for item in data]
        
        return data


class RateLimiter:
    """Rate limiting and DDoS protection."""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.buckets: Dict[str, RateLimitBucket] = {}
        self.global_bucket = RateLimitBucket(
            capacity=config.requests_per_minute,
            tokens=config.requests_per_minute,
            last_refill=time.time()
        )
        self.blocked_ips: Dict[str, float] = {}  # IP -> block_until_timestamp
        
    def is_allowed(self, context: SecurityContext, endpoint: str = "") -> bool:
        """Check if request is allowed based on rate limits."""
        if not self.config.rate_limit_enabled:
            return True
        
        client_key = f"{context.client_ip}:{context.user_id}"
        now = time.time()
        
        # Check if IP is blocked
        if context.client_ip in self.blocked_ips:
            if now < self.blocked_ips[context.client_ip]:
                return False
            else:
                del self.blocked_ips[context.client_ip]
        
        # Global rate limit
        if not self.global_bucket.consume():
            logger.warning(f"Global rate limit exceeded")
            return False
        
        # Per-client rate limit
        if client_key not in self.buckets:
            self.buckets[client_key] = RateLimitBucket(
                capacity=self.config.burst_capacity,
                tokens=self.config.burst_capacity,
                last_refill=now
            )
        
        bucket = self.buckets[client_key]
        if not bucket.consume():
            # Check for potential DDoS
            if self.config.ddos_protection:
                self._check_ddos_pattern(context)
            return False
        
        return True
    
    def _check_ddos_pattern(self, context: SecurityContext):
        """Check for DDoS patterns and block if necessary."""
        client_key = f"{context.client_ip}:{context.user_id}"
        bucket = self.buckets.get(client_key)
        
        if bucket and bucket.tokens <= 0:
            # Block IP for 15 minutes
            block_until = time.time() + (15 * 60)
            self.blocked_ips[context.client_ip] = block_until
            logger.warning(f"Potential DDoS detected, blocking IP {context.client_ip} until {datetime.fromtimestamp(block_until)}")


class SecurityEncryption:
    """Encryption and secrets management."""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.fernet = None
        
        if config.encryption_enabled:
            self._initialize_encryption()
    
    def _initialize_encryption(self):
        """Initialize encryption system."""
        if self.config.encryption_key:
            key = self.config.encryption_key.encode()
        else:
            # Generate a key from a password (in production, use proper key management)
            password = secrets.token_bytes(32)
            salt = secrets.token_bytes(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
        
        self.fernet = Fernet(key)
    
    def encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data."""
        if not self.fernet:
            return data
        
        return self.fernet.encrypt(data.encode()).decode()
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data."""
        if not self.fernet:
            return encrypted_data
        
        return self.fernet.decrypt(encrypted_data.encode()).decode()
    
    def hash_password(self, password: str) -> str:
        """Hash password securely."""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode(), salt).decode()
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash."""
        return bcrypt.checkpw(password.encode(), hashed.encode())
    
    def generate_api_key(self) -> str:
        """Generate secure API key."""
        return secrets.token_urlsafe(self.config.api_key_length)
    
    def generate_session_token(self) -> str:
        """Generate secure session token."""
        return secrets.token_urlsafe(32)


class SecurityAuthenticator:
    """Authentication and authorization manager."""
    
    def __init__(self, config: SecurityConfig, encryption: SecurityEncryption):
        self.config = config
        self.encryption = encryption
        self.api_keys: Dict[str, Dict[str, Any]] = {}  # api_key -> user_info
        self.sessions: Dict[str, Dict[str, Any]] = {}  # session_id -> session_info
        
    def generate_jwt_token(self, user_id: str, roles: List[str], permissions: List[str]) -> str:
        """Generate JWT token."""
        if not self.config.jwt_secret:
            raise ValueError("JWT secret not configured")
        
        payload = {
            "user_id": user_id,
            "roles": roles,
            "permissions": permissions,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(hours=self.config.jwt_expiry_hours)
        }
        
        return jwt.encode(payload, self.config.jwt_secret, algorithm=self.config.jwt_algorithm)
    
    def verify_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode JWT token."""
        try:
            if not self.config.jwt_secret:
                return None
            
            payload = jwt.decode(token, self.config.jwt_secret, algorithms=[self.config.jwt_algorithm])
            return payload
        except jwt.InvalidTokenError:
            return None
    
    def create_api_key(self, user_id: str, roles: List[str], permissions: List[str]) -> str:
        """Create API key for user."""
        api_key = self.encryption.generate_api_key()
        
        self.api_keys[api_key] = {
            "user_id": user_id,
            "roles": roles,
            "permissions": permissions,
            "created_at": datetime.utcnow(),
            "last_used": None
        }
        
        return api_key
    
    def verify_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Verify API key and return user info."""
        if api_key in self.api_keys:
            user_info = self.api_keys[api_key]
            user_info["last_used"] = datetime.utcnow()
            return user_info
        return None
    
    def create_session(self, user_id: str, roles: List[str], permissions: List[str], client_ip: str) -> str:
        """Create user session."""
        session_id = self.encryption.generate_session_token()
        
        # Check concurrent session limit
        user_sessions = [s for s in self.sessions.values() if s["user_id"] == user_id]
        if len(user_sessions) >= self.config.max_concurrent_sessions:
            # Remove oldest session
            oldest_session = min(user_sessions, key=lambda s: s["created_at"])
            self.sessions = {k: v for k, v in self.sessions.items() if v != oldest_session}
        
        self.sessions[session_id] = {
            "user_id": user_id,
            "roles": roles,
            "permissions": permissions,
            "client_ip": client_ip,
            "created_at": datetime.utcnow(),
            "last_activity": datetime.utcnow()
        }
        
        return session_id
    
    def verify_session(self, session_id: str, client_ip: str) -> Optional[Dict[str, Any]]:
        """Verify session and return session info."""
        if session_id not in self.sessions:
            return None
        
        session = self.sessions[session_id]
        now = datetime.utcnow()
        
        # Check timeout
        timeout_threshold = now - timedelta(minutes=self.config.session_timeout_minutes)
        if session["last_activity"] < timeout_threshold:
            del self.sessions[session_id]
            return None
        
        # Check IP consistency (basic session hijacking protection)
        if session["client_ip"] != client_ip:
            logger.warning(f"Session IP mismatch: expected {session['client_ip']}, got {client_ip}")
            del self.sessions[session_id]
            return None
        
        # Update last activity
        session["last_activity"] = now
        
        return session
    
    def revoke_session(self, session_id: str) -> bool:
        """Revoke session."""
        if session_id in self.sessions:
            del self.sessions[session_id]
            return True
        return False
    
    def revoke_api_key(self, api_key: str) -> bool:
        """Revoke API key."""
        if api_key in self.api_keys:
            del self.api_keys[api_key]
            return True
        return False
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions."""
        now = datetime.utcnow()
        timeout_threshold = now - timedelta(minutes=self.config.session_timeout_minutes)
        
        expired_sessions = [
            sid for sid, session in self.sessions.items()
            if session["last_activity"] < timeout_threshold
        ]
        
        for session_id in expired_sessions:
            del self.sessions[session_id]
        
        if expired_sessions:
            logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")


class SecurityAuditor:
    """Security monitoring and audit logging."""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.audit_log: List[Dict[str, Any]] = []
        self.security_events: List[Dict[str, Any]] = []
        self.anomaly_scores: Dict[str, float] = {}
        
    def log_security_event(self, event_type: str, context: SecurityContext, details: Dict[str, Any]):
        """Log security event for audit trail."""
        if not self.config.audit_logging:
            return
        
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "user_id": context.user_id,
            "session_id": context.session_id,
            "client_ip": context.client_ip,
            "user_agent": context.user_agent,
            "risk_score": context.risk_score,
            "details": details
        }
        
        self.audit_log.append(event)
        self.security_events.append(event)
        
        # Keep only recent events in memory
        if len(self.security_events) > 10000:
            self.security_events = self.security_events[-5000:]
        
        logger.info(f"Security event logged: {event_type} by {context.user_id} from {context.client_ip}")
    
    def detect_anomalies(self, context: SecurityContext) -> float:
        """Detect anomalous behavior and return risk score."""
        if not self.config.anomaly_detection:
            return 0.0
        
        risk_score = 0.0
        user_key = f"{context.user_id}:{context.client_ip}"
        
        # Check for unusual access patterns
        recent_events = [
            e for e in self.security_events[-1000:]
            if e["user_id"] == context.user_id
            and datetime.fromisoformat(e["timestamp"]) > datetime.utcnow() - timedelta(hours=1)
        ]
        
        # Frequency anomaly
        if len(recent_events) > 100:  # More than 100 events in 1 hour
            risk_score += 0.3
        
        # IP change anomaly
        recent_ips = set(e["client_ip"] for e in recent_events)
        if len(recent_ips) > 3:  # More than 3 different IPs
            risk_score += 0.4
        
        # Time pattern anomaly (accessing at unusual hours)
        current_hour = datetime.utcnow().hour
        if current_hour < 6 or current_hour > 22:  # Late night/early morning
            risk_score += 0.2
        
        # Update and track anomaly score
        self.anomaly_scores[user_key] = risk_score
        
        return risk_score
    
    def get_security_metrics(self) -> Dict[str, Any]:
        """Get security metrics for monitoring."""
        now = datetime.utcnow()
        last_hour = now - timedelta(hours=1)
        
        recent_events = [
            e for e in self.security_events
            if datetime.fromisoformat(e["timestamp"]) > last_hour
        ]
        
        metrics = {
            "total_events_last_hour": len(recent_events),
            "unique_users_last_hour": len(set(e["user_id"] for e in recent_events)),
            "unique_ips_last_hour": len(set(e["client_ip"] for e in recent_events)),
            "high_risk_events_last_hour": len([e for e in recent_events if e["risk_score"] > 0.7]),
            "event_types_last_hour": {},
            "average_risk_score": 0.0
        }
        
        # Count event types
        for event in recent_events:
            event_type = event["event_type"]
            metrics["event_types_last_hour"][event_type] = metrics["event_types_last_hour"].get(event_type, 0) + 1
        
        # Calculate average risk score
        if recent_events:
            metrics["average_risk_score"] = sum(e["risk_score"] for e in recent_events) / len(recent_events)
        
        return metrics


class MCPSecurityCore:
    """Main security core for MCP servers."""
    
    def __init__(self, config: Optional[SecurityConfig] = None):
        self.config = config or SecurityConfig()
        self.encryption = SecurityEncryption(self.config)
        self.authenticator = SecurityAuthenticator(self.config, self.encryption)
        self.validator = SecurityValidator(self.config)
        self.rate_limiter = RateLimiter(self.config)
        self.auditor = SecurityAuditor(self.config)
        
        # Background cleanup task
        self._cleanup_task: Optional[asyncio.Task] = None
        self._is_running = False
    
    async def initialize(self):
        """Initialize security core."""
        self._is_running = True
        
        # Start background cleanup task
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        
        logger.info("MCP Security Core initialized with security level: HIGH")
    
    async def authenticate_request(
        self, 
        auth_header: Optional[str], 
        client_ip: str, 
        user_agent: str
    ) -> Optional[SecurityContext]:
        """Authenticate incoming request."""
        if not auth_header:
            return None
        
        try:
            auth_type, credentials = auth_header.split(" ", 1)
            
            if auth_type.lower() == "bearer":
                # JWT token authentication
                if AuthenticationMethod.JWT_TOKEN in self.config.auth_methods:
                    payload = self.authenticator.verify_jwt_token(credentials)
                    if payload:
                        context = SecurityContext(
                            user_id=payload["user_id"],
                            session_id="jwt_session",
                            roles=payload["roles"],
                            permissions=payload["permissions"],
                            auth_method=AuthenticationMethod.JWT_TOKEN,
                            client_ip=client_ip,
                            user_agent=user_agent,
                            timestamp=datetime.utcnow()
                        )
                        
                        # Calculate risk score
                        context.risk_score = self.auditor.detect_anomalies(context)
                        
                        return context
            
            elif auth_type.lower() == "apikey":
                # API key authentication
                if AuthenticationMethod.API_KEY in self.config.auth_methods:
                    user_info = self.authenticator.verify_api_key(credentials)
                    if user_info:
                        context = SecurityContext(
                            user_id=user_info["user_id"],
                            session_id=f"apikey_{credentials[:8]}",
                            roles=user_info["roles"],
                            permissions=user_info["permissions"],
                            auth_method=AuthenticationMethod.API_KEY,
                            client_ip=client_ip,
                            user_agent=user_agent,
                            timestamp=datetime.utcnow()
                        )
                        
                        # Calculate risk score
                        context.risk_score = self.auditor.detect_anomalies(context)
                        
                        return context
            
            return None
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return None
    
    async def authorize_request(self, context: SecurityContext, resource: str, action: str) -> bool:
        """Authorize request based on user permissions."""
        # Check if user has required permission
        required_permission = f"{resource}:{action}"
        
        # Admin users have full access
        if "admin" in context.roles:
            return True
        
        # Check specific permission
        if required_permission in context.permissions:
            return True
        
        # Check wildcard permission
        wildcard_permission = f"{resource}:*"
        if wildcard_permission in context.permissions:
            return True
        
        return False
    
    async def validate_and_process_request(
        self, 
        context: SecurityContext, 
        endpoint: str, 
        data: Any
    ) -> tuple[bool, Any]:
        """Validate and process incoming request."""
        # Rate limiting check
        if not self.rate_limiter.is_allowed(context, endpoint):
            self.auditor.log_security_event(
                "rate_limit_exceeded",
                context,
                {"endpoint": endpoint}
            )
            return False, "Rate limit exceeded"
        
        # Input validation
        if not self.validator.validate_input(data, context):
            self.auditor.log_security_event(
                "malicious_input_detected",
                context,
                {"endpoint": endpoint, "data_type": type(data).__name__}
            )
            return False, "Invalid input detected"
        
        # Sanitize input
        sanitized_data = self.validator.sanitize_input(data)
        
        # Log successful validation
        self.auditor.log_security_event(
            "request_validated",
            context,
            {"endpoint": endpoint, "risk_score": context.risk_score}
        )
        
        return True, sanitized_data
    
    def create_user_credentials(self, user_id: str, roles: List[str], permissions: List[str]) -> Dict[str, str]:
        """Create credentials for a user."""
        credentials = {}
        
        # Generate API key if enabled
        if AuthenticationMethod.API_KEY in self.config.auth_methods:
            api_key = self.authenticator.create_api_key(user_id, roles, permissions)
            credentials["api_key"] = api_key
        
        # Generate JWT token if enabled
        if AuthenticationMethod.JWT_TOKEN in self.config.auth_methods:
            jwt_token = self.authenticator.generate_jwt_token(user_id, roles, permissions)
            credentials["jwt_token"] = jwt_token
        
        return credentials
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get current security status and metrics."""
        return {
            "security_level": "HIGH",
            "auth_methods": [method.value for method in self.config.auth_methods],
            "rate_limiting_enabled": self.config.rate_limit_enabled,
            "encryption_enabled": self.config.encryption_enabled,
            "audit_logging_enabled": self.config.audit_logging,
            "active_sessions": len(self.authenticator.sessions),
            "active_api_keys": len(self.authenticator.api_keys),
            "blocked_ips": len(self.rate_limiter.blocked_ips),
            "security_metrics": self.auditor.get_security_metrics()
        }
    
    async def _cleanup_loop(self):
        """Background cleanup of expired sessions and security data."""
        while self._is_running:
            try:
                await asyncio.sleep(300)  # Run every 5 minutes
                
                # Clean up expired sessions
                self.authenticator.cleanup_expired_sessions()
                
                # Clean up old security events
                cutoff = datetime.utcnow() - timedelta(hours=24)
                self.auditor.security_events = [
                    e for e in self.auditor.security_events
                    if datetime.fromisoformat(e["timestamp"]) > cutoff
                ]
                
                # Clean up old rate limiting buckets
                now = time.time()
                self.rate_limiter.buckets = {
                    k: v for k, v in self.rate_limiter.buckets.items()
                    if now - v.last_refill < 3600  # Keep buckets for 1 hour
                }
                
                # Clean up expired IP blocks
                self.rate_limiter.blocked_ips = {
                    ip: block_until for ip, block_until in self.rate_limiter.blocked_ips.items()
                    if block_until > now
                }
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Security cleanup error: {e}")
    
    async def shutdown(self):
        """Shutdown security core."""
        self._is_running = False
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        logger.info("MCP Security Core shutdown complete")


# Global security instance
_security_core: Optional[MCPSecurityCore] = None


async def get_security_core() -> MCPSecurityCore:
    """Get global security core instance."""
    global _security_core
    if _security_core is None:
        _security_core = MCPSecurityCore()
        await _security_core.initialize()
    return _security_core


__all__ = [
    "SecurityLevel",
    "AuthenticationMethod", 
    "RateLimitType",
    "SecurityConfig",
    "SecurityContext",
    "SecurityValidator",
    "RateLimiter",
    "SecurityEncryption",
    "SecurityAuthenticator",
    "SecurityAuditor",
    "MCPSecurityCore",
    "get_security_core"
]