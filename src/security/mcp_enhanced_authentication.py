"""
Enhanced MCP Authentication and Authorization System

This module provides a comprehensive authentication and authorization system
specifically designed for MCP (Model Context Protocol) clients, implementing
security best practices and defense-in-depth principles.

Features:
- Multi-factor authentication (MFA)
- Role-based access control (RBAC)
- Attribute-based access control (ABAC)
- OAuth 2.0 / JWT integration
- Rate limiting and DDoS protection
- Session management with secure tokens
- Certificate-based authentication
- API key authentication with scopes
- Real-time security monitoring
- Zero-trust security model

Author: SYNTHEX Agent 4
Version: 1.0.0
"""

import os
import asyncio
import hashlib
import hmac
import secrets
import time
import json
import jwt
import pyotp
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import logging
import ipaddress
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID
import asyncpg
import aioredis

from ..core.security_policy import SecurityPolicy
from ..auth.models import User
from ..auth.rbac import RBACManager
from ..core.log_sanitization import sanitize_for_logging

__all__ = [
    "MCPAuthenticationProvider",
    "MCPAuthorizationManager", 
    "MCPSecurityContext",
    "MCPSecurityMonitor",
    "MCPCertificateValidator",
    "SecurityPolicy",
    "AuthenticationResult",
    "AuthorizationResult"
]

logger = logging.getLogger(__name__)


class AuthenticationMethod(Enum):
    """Supported authentication methods"""
    API_KEY = "api_key"
    JWT_TOKEN = "jwt_token"
    CERTIFICATE = "certificate"
    MFA_TOTP = "mfa_totp"
    OAUTH2 = "oauth2"
    MUTUAL_TLS = "mutual_tls"


class AuthorizationModel(Enum):
    """Authorization models"""
    RBAC = "rbac"  # Role-Based Access Control
    ABAC = "abac"  # Attribute-Based Access Control
    ZBAC = "zbac"  # Zone-Based Access Control


@dataclass
class MCPSecurityContext:
    """Security context for MCP operations"""
    client_id: str
    user_id: Optional[str]
    session_id: str
    ip_address: str
    user_agent: str
    authentication_method: AuthenticationMethod
    permissions: List[str]
    attributes: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_activity: datetime = field(default_factory=datetime.utcnow)
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = datetime.utcnow()
    
    def is_expired(self, timeout_minutes: int = 30) -> bool:
        """Check if context is expired"""
        return (datetime.utcnow() - self.last_activity).total_seconds() > (timeout_minutes * 60)


@dataclass
class AuthenticationResult:
    """Result of authentication attempt"""
    success: bool
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    context: Optional[MCPSecurityContext] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    requires_mfa: bool = False
    mfa_methods: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthorizationResult:
    """Result of authorization check"""
    granted: bool
    reason: str
    required_permissions: List[str] = field(default_factory=list)
    missing_permissions: List[str] = field(default_factory=list)
    policy_violations: List[str] = field(default_factory=list)


class MCPCertificateValidator:
    """Certificate validation for mutual TLS authentication"""
    
    def __init__(self, 
                 ca_cert_path: Path,
                 crl_path: Optional[Path] = None,
                 ocsp_responder: Optional[str] = None):
        """
        Initialize certificate validator.
        
        Args:
            ca_cert_path: Path to CA certificate
            crl_path: Path to Certificate Revocation List
            ocsp_responder: OCSP responder URL
        """
        self.ca_cert_path = ca_cert_path
        self.crl_path = crl_path
        self.ocsp_responder = ocsp_responder
        
        # Load CA certificate
        with open(ca_cert_path, 'rb') as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read())
    
    async def validate_certificate(self, client_cert: x509.Certificate) -> Tuple[bool, str]:
        """
        Validate client certificate.
        
        Args:
            client_cert: Client certificate to validate
            
        Returns:
            Tuple of (is_valid, reason)
        """
        try:
            # Check certificate chain
            if not self._verify_certificate_chain(client_cert):
                return False, "Certificate chain validation failed"
            
            # Check expiration
            if not self._check_certificate_validity(client_cert):
                return False, "Certificate is expired or not yet valid"
            
            # Check revocation
            if not await self._check_certificate_revocation(client_cert):
                return False, "Certificate is revoked"
            
            # Check key usage
            if not self._check_key_usage(client_cert):
                return False, "Certificate key usage is invalid"
            
            return True, "Certificate is valid"
            
        except Exception as e:
            logger.error(f"Certificate validation error: {e}")
            return False, f"Validation error: {str(e)}"
    
    def _verify_certificate_chain(self, client_cert: x509.Certificate) -> bool:
        """Verify certificate chain against CA"""
        try:
            # Verify signature
            ca_public_key = self.ca_cert.public_key()
            ca_public_key.verify(
                client_cert.signature,
                client_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                client_cert.signature_hash_algorithm
            )
            return True
        except Exception:
            return False
    
    def _check_certificate_validity(self, client_cert: x509.Certificate) -> bool:
        """Check certificate validity period"""
        now = datetime.utcnow()
        return client_cert.not_valid_before <= now <= client_cert.not_valid_after
    
    async def _check_certificate_revocation(self, client_cert: x509.Certificate) -> bool:
        """Check certificate revocation status"""
        # Check CRL if available
        if self.crl_path and self.crl_path.exists():
            with open(self.crl_path, 'rb') as f:
                crl = x509.load_pem_x509_crl(f.read())
            
            for revoked_cert in crl:
                if revoked_cert.serial_number == client_cert.serial_number:
                    return False
        
        # TODO: Implement OCSP checking
        if self.ocsp_responder:
            # OCSP validation would go here
            pass
        
        return True
    
    def _check_key_usage(self, client_cert: x509.Certificate) -> bool:
        """Check certificate key usage"""
        try:
            key_usage = client_cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.KEY_USAGE
            ).value
            
            # Require digital signature and key encipherment
            return key_usage.digital_signature and key_usage.key_encipherment
        except x509.ExtensionNotFound:
            return False


class MCPAuthenticationProvider:
    """
    Comprehensive authentication provider for MCP clients.
    
    Supports multiple authentication methods with security best practices.
    """
    
    def __init__(self,
                 secret_key: str,
                 database_pool: Optional[asyncpg.Pool] = None,
                 redis_pool: Optional[aioredis.Redis] = None,
                 cert_validator: Optional[MCPCertificateValidator] = None):
        """
        Initialize authentication provider.
        
        Args:
            secret_key: Secret key for JWT signing
            database_pool: Database connection pool
            redis_pool: Redis connection pool for caching
            cert_validator: Certificate validator for mTLS
        """
        self.secret_key = secret_key
        self.database_pool = database_pool
        self.redis_pool = redis_pool
        self.cert_validator = cert_validator
        
        # Security policies
        self.security_policy = SecurityPolicy()
        
        # Rate limiting
        self.rate_limiter = MCPRateLimiter(redis_pool)
        
        # Active sessions
        self.active_sessions: Dict[str, MCPSecurityContext] = {}
        
        # Failed authentication tracking
        self.failed_attempts: Dict[str, List[datetime]] = {}
        
        # Trusted client registry
        self.trusted_clients: Dict[str, Dict[str, Any]] = {}
        
    async def authenticate_api_key(self,
                                 api_key: str,
                                 client_ip: str,
                                 user_agent: str) -> AuthenticationResult:
        """
        Authenticate using API key.
        
        Args:
            api_key: API key to validate
            client_ip: Client IP address
            user_agent: Client user agent
            
        Returns:
            AuthenticationResult
        """
        try:
            # Rate limiting check
            if not await self.rate_limiter.check_rate_limit(client_ip, "auth_attempt"):
                return AuthenticationResult(
                    success=False,
                    error_code="RATE_LIMITED",
                    error_message="Too many authentication attempts"
                )
            
            # Parse API key
            key_parts = api_key.split('.')
            if len(key_parts) != 3:
                return AuthenticationResult(
                    success=False,
                    error_code="INVALID_KEY_FORMAT",
                    error_message="Invalid API key format"
                )
            
            key_id, key_secret, key_signature = key_parts
            
            # Verify signature
            expected_signature = hmac.new(
                self.secret_key.encode(),
                f"{key_id}.{key_secret}".encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(key_signature, expected_signature):
                await self._record_failed_attempt(client_ip)
                return AuthenticationResult(
                    success=False,
                    error_code="INVALID_SIGNATURE",
                    error_message="Invalid API key signature"
                )
            
            # Look up API key in database
            api_key_info = await self._get_api_key_info(key_id)
            if not api_key_info:
                await self._record_failed_attempt(client_ip)
                return AuthenticationResult(
                    success=False,
                    error_code="KEY_NOT_FOUND",
                    error_message="API key not found"
                )
            
            # Check if key is active
            if not api_key_info.get('is_active', False):
                return AuthenticationResult(
                    success=False,
                    error_code="KEY_DISABLED",
                    error_message="API key is disabled"
                )
            
            # Check expiration
            expires_at = api_key_info.get('expires_at')
            if expires_at and datetime.utcnow() > expires_at:
                return AuthenticationResult(
                    success=False,
                    error_code="KEY_EXPIRED",
                    error_message="API key is expired"
                )
            
            # Check IP restrictions
            allowed_ips = api_key_info.get('allowed_ips', [])
            if allowed_ips and not self._check_ip_allowed(client_ip, allowed_ips):
                return AuthenticationResult(
                    success=False,
                    error_code="IP_NOT_ALLOWED",
                    error_message="Client IP not allowed for this API key"
                )
            
            # Create security context
            session_id = secrets.token_urlsafe(32)
            context = MCPSecurityContext(
                client_id=api_key_info['client_id'],
                user_id=api_key_info.get('user_id'),
                session_id=session_id,
                ip_address=client_ip,
                user_agent=user_agent,
                authentication_method=AuthenticationMethod.API_KEY,
                permissions=api_key_info.get('permissions', []),
                attributes={'api_key_id': key_id}
            )
            
            # Store session
            self.active_sessions[session_id] = context
            
            # Update last used
            await self._update_api_key_usage(key_id, client_ip)
            
            return AuthenticationResult(
                success=True,
                user_id=context.user_id,
                session_id=session_id,
                context=context
            )
            
        except Exception as e:
            logger.error(f"API key authentication error: {e}")
            return AuthenticationResult(
                success=False,
                error_code="INTERNAL_ERROR",
                error_message="Internal authentication error"
            )
    
    async def authenticate_jwt(self,
                             jwt_token: str,
                             client_ip: str,
                             user_agent: str) -> AuthenticationResult:
        """
        Authenticate using JWT token.
        
        Args:
            jwt_token: JWT token to validate
            client_ip: Client IP address
            user_agent: Client user agent
            
        Returns:
            AuthenticationResult
        """
        try:
            # Rate limiting check
            if not await self.rate_limiter.check_rate_limit(client_ip, "auth_attempt"):
                return AuthenticationResult(
                    success=False,
                    error_code="RATE_LIMITED",
                    error_message="Too many authentication attempts"
                )
            
            # Decode and verify JWT
            try:
                payload = jwt.decode(
                    jwt_token,
                    self.secret_key,
                    algorithms=['HS256'],
                    options={'verify_exp': True}
                )
            except jwt.ExpiredSignatureError:
                return AuthenticationResult(
                    success=False,
                    error_code="TOKEN_EXPIRED",
                    error_message="JWT token is expired"
                )
            except jwt.InvalidTokenError:
                await self._record_failed_attempt(client_ip)
                return AuthenticationResult(
                    success=False,
                    error_code="INVALID_TOKEN",
                    error_message="Invalid JWT token"
                )
            
            # Check token blacklist
            jti = payload.get('jti')
            if jti and await self._is_token_blacklisted(jti):
                return AuthenticationResult(
                    success=False,
                    error_code="TOKEN_REVOKED",
                    error_message="JWT token has been revoked"
                )
            
            # Validate issuer
            iss = payload.get('iss')
            if not self._validate_issuer(iss):
                return AuthenticationResult(
                    success=False,
                    error_code="INVALID_ISSUER",
                    error_message="Invalid token issuer"
                )
            
            # Extract claims
            user_id = payload.get('sub')
            client_id = payload.get('client_id')
            permissions = payload.get('permissions', [])
            
            # Check if user is still valid
            user_info = await self._get_user_info(user_id)
            if not user_info or not user_info.get('is_active', False):
                return AuthenticationResult(
                    success=False,
                    error_code="USER_DISABLED",
                    error_message="User account is disabled"
                )
            
            # Create security context
            session_id = secrets.token_urlsafe(32)
            context = MCPSecurityContext(
                client_id=client_id,
                user_id=user_id,
                session_id=session_id,
                ip_address=client_ip,
                user_agent=user_agent,
                authentication_method=AuthenticationMethod.JWT_TOKEN,
                permissions=permissions,
                attributes={'jwt_claims': payload}
            )
            
            # Store session
            self.active_sessions[session_id] = context
            
            return AuthenticationResult(
                success=True,
                user_id=user_id,
                session_id=session_id,
                context=context
            )
            
        except Exception as e:
            logger.error(f"JWT authentication error: {e}")
            return AuthenticationResult(
                success=False,
                error_code="INTERNAL_ERROR",
                error_message="Internal authentication error"
            )
    
    async def authenticate_certificate(self,
                                     client_cert: x509.Certificate,
                                     client_ip: str,
                                     user_agent: str) -> AuthenticationResult:
        """
        Authenticate using client certificate (mTLS).
        
        Args:
            client_cert: Client certificate
            client_ip: Client IP address
            user_agent: Client user agent
            
        Returns:
            AuthenticationResult
        """
        if not self.cert_validator:
            return AuthenticationResult(
                success=False,
                error_code="CERT_AUTH_DISABLED",
                error_message="Certificate authentication is not configured"
            )
        
        try:
            # Validate certificate
            is_valid, reason = await self.cert_validator.validate_certificate(client_cert)
            if not is_valid:
                return AuthenticationResult(
                    success=False,
                    error_code="INVALID_CERTIFICATE",
                    error_message=reason
                )
            
            # Extract client information from certificate
            subject = client_cert.subject
            client_id = None
            user_id = None
            
            # Look for client ID in certificate subject
            for attribute in subject:
                if attribute.oid == NameOID.COMMON_NAME:
                    client_id = attribute.value
                elif attribute.oid == NameOID.USER_ID:
                    user_id = attribute.value
            
            if not client_id:
                return AuthenticationResult(
                    success=False,
                    error_code="NO_CLIENT_ID",
                    error_message="No client ID found in certificate"
                )
            
            # Look up client permissions
            client_info = await self._get_client_info(client_id)
            if not client_info:
                return AuthenticationResult(
                    success=False,
                    error_code="CLIENT_NOT_FOUND",
                    error_message="Client not found"
                )
            
            # Create security context
            session_id = secrets.token_urlsafe(32)
            context = MCPSecurityContext(
                client_id=client_id,
                user_id=user_id,
                session_id=session_id,
                ip_address=client_ip,
                user_agent=user_agent,
                authentication_method=AuthenticationMethod.CERTIFICATE,
                permissions=client_info.get('permissions', []),
                attributes={'certificate_subject': str(subject)}
            )
            
            # Store session
            self.active_sessions[session_id] = context
            
            return AuthenticationResult(
                success=True,
                user_id=user_id,
                session_id=session_id,
                context=context
            )
            
        except Exception as e:
            logger.error(f"Certificate authentication error: {e}")
            return AuthenticationResult(
                success=False,
                error_code="INTERNAL_ERROR",
                error_message="Internal authentication error"
            )
    
    async def authenticate_mfa(self,
                             primary_token: str,
                             mfa_code: str,
                             client_ip: str,
                             user_agent: str) -> AuthenticationResult:
        """
        Authenticate with multi-factor authentication.
        
        Args:
            primary_token: Primary authentication token (JWT/API key)
            mfa_code: TOTP/SMS code
            client_ip: Client IP address
            user_agent: Client user agent
            
        Returns:
            AuthenticationResult
        """
        try:
            # First, authenticate with primary method
            primary_result = await self.authenticate_jwt(primary_token, client_ip, user_agent)
            if not primary_result.success:
                return primary_result
            
            # Get user MFA settings
            user_id = primary_result.user_id
            mfa_settings = await self._get_user_mfa_settings(user_id)
            
            if not mfa_settings or not mfa_settings.get('enabled', False):
                return AuthenticationResult(
                    success=False,
                    error_code="MFA_NOT_ENABLED",
                    error_message="MFA is not enabled for this user"
                )
            
            # Verify TOTP code
            totp_secret = mfa_settings.get('totp_secret')
            if not totp_secret:
                return AuthenticationResult(
                    success=False,
                    error_code="NO_TOTP_SECRET",
                    error_message="No TOTP secret configured"
                )
            
            totp = pyotp.TOTP(totp_secret)
            if not totp.verify(mfa_code, valid_window=1):
                await self._record_failed_attempt(client_ip)
                return AuthenticationResult(
                    success=False,
                    error_code="INVALID_MFA_CODE",
                    error_message="Invalid MFA code"
                )
            
            # Update context with MFA authentication
            context = primary_result.context
            context.authentication_method = AuthenticationMethod.MFA_TOTP
            context.attributes['mfa_verified'] = True
            
            return AuthenticationResult(
                success=True,
                user_id=user_id,
                session_id=primary_result.session_id,
                context=context
            )
            
        except Exception as e:
            logger.error(f"MFA authentication error: {e}")
            return AuthenticationResult(
                success=False,
                error_code="INTERNAL_ERROR",
                error_message="Internal authentication error"
            )
    
    async def validate_session(self, session_id: str) -> Optional[MCPSecurityContext]:
        """Validate and return session context"""
        context = self.active_sessions.get(session_id)
        
        if not context:
            return None
        
        # Check if session is expired
        if context.is_expired():
            self.active_sessions.pop(session_id, None)
            return None
        
        # Update activity
        context.update_activity()
        
        return context
    
    async def revoke_session(self, session_id: str) -> bool:
        """Revoke a session"""
        return bool(self.active_sessions.pop(session_id, None))
    
    async def _get_api_key_info(self, key_id: str) -> Optional[Dict[str, Any]]:
        """Get API key information from database"""
        if not self.database_pool:
            return None
        
        async with self.database_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM api_keys WHERE key_id = $1",
                key_id
            )
            return dict(row) if row else None
    
    async def _get_user_info(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user information from database"""
        if not self.database_pool:
            return None
        
        async with self.database_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM users WHERE id = $1",
                user_id
            )
            return dict(row) if row else None
    
    async def _get_client_info(self, client_id: str) -> Optional[Dict[str, Any]]:
        """Get client information from database"""
        if not self.database_pool:
            return None
        
        async with self.database_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM clients WHERE id = $1",
                client_id
            )
            return dict(row) if row else None
    
    async def _get_user_mfa_settings(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user MFA settings"""
        if not self.database_pool:
            return None
        
        async with self.database_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM user_mfa_settings WHERE user_id = $1",
                user_id
            )
            return dict(row) if row else None
    
    async def _update_api_key_usage(self, key_id: str, client_ip: str):
        """Update API key last used timestamp"""
        if not self.database_pool:
            return
        
        async with self.database_pool.acquire() as conn:
            await conn.execute(
                "UPDATE api_keys SET last_used_at = $1, last_used_ip = $2 WHERE key_id = $3",
                datetime.utcnow(), client_ip, key_id
            )
    
    async def _is_token_blacklisted(self, jti: str) -> bool:
        """Check if JWT token is blacklisted"""
        if not self.redis_pool:
            return False
        
        return await self.redis_pool.exists(f"blacklist:jwt:{jti}")
    
    def _validate_issuer(self, issuer: Optional[str]) -> bool:
        """Validate JWT issuer"""
        valid_issuers = ['claude-optimized-deployment', 'mcp-server']
        return issuer in valid_issuers
    
    def _check_ip_allowed(self, client_ip: str, allowed_ips: List[str]) -> bool:
        """Check if client IP is in allowed list"""
        try:
            client_addr = ipaddress.ip_address(client_ip)
            
            for allowed in allowed_ips:
                if '/' in allowed:
                    # CIDR notation
                    network = ipaddress.ip_network(allowed)
                    if client_addr in network:
                        return True
                else:
                    # Single IP
                    if client_addr == ipaddress.ip_address(allowed):
                        return True
            
            return False
            
        except ValueError:
            return False
    
    async def _record_failed_attempt(self, identifier: str):
        """Record failed authentication attempt"""
        now = datetime.utcnow()
        
        if identifier not in self.failed_attempts:
            self.failed_attempts[identifier] = []
        
        self.failed_attempts[identifier].append(now)
        
        # Clean old attempts (older than 1 hour)
        cutoff = now - timedelta(hours=1)
        self.failed_attempts[identifier] = [
            attempt for attempt in self.failed_attempts[identifier]
            if attempt > cutoff
        ]


class MCPRateLimiter:
    """Rate limiter for MCP operations"""
    
    def __init__(self, redis_pool: Optional[aioredis.Redis]):
        self.redis_pool = redis_pool
        
        # Rate limiting rules
        self.limits = {
            'auth_attempt': {'requests': 10, 'window': 60},  # 10 attempts per minute
            'api_request': {'requests': 1000, 'window': 3600},  # 1000 requests per hour
            'file_upload': {'requests': 50, 'window': 3600},  # 50 uploads per hour
        }
    
    async def check_rate_limit(self, identifier: str, operation: str) -> bool:
        """Check if operation is within rate limit"""
        if not self.redis_pool or operation not in self.limits:
            return True
        
        limit_config = self.limits[operation]
        key = f"rate_limit:{operation}:{identifier}"
        
        try:
            current_count = await self.redis_pool.get(key)
            current_count = int(current_count) if current_count else 0
            
            if current_count >= limit_config['requests']:
                return False
            
            # Increment counter
            pipe = self.redis_pool.pipeline()
            pipe.incr(key)
            pipe.expire(key, limit_config['window'])
            await pipe.execute()
            
            return True
            
        except Exception as e:
            logger.error(f"Rate limiting error: {e}")
            return True  # Allow on error


class MCPAuthorizationManager:
    """
    Comprehensive authorization manager for MCP operations.
    
    Implements RBAC, ABAC, and custom authorization policies.
    """
    
    def __init__(self,
                 rbac_manager: RBACManager,
                 database_pool: Optional[asyncpg.Pool] = None):
        """
        Initialize authorization manager.
        
        Args:
            rbac_manager: RBAC manager instance
            database_pool: Database connection pool
        """
        self.rbac_manager = rbac_manager
        self.database_pool = database_pool
        
        # Authorization policies
        self.policies: Dict[str, Callable] = {}
        
        # Setup default policies
        self._setup_default_policies()
    
    def _setup_default_policies(self):
        """Setup default authorization policies"""
        self.policies['mcp_server_access'] = self._policy_mcp_server_access
        self.policies['file_operations'] = self._policy_file_operations
        self.policies['admin_operations'] = self._policy_admin_operations
        self.policies['time_based_access'] = self._policy_time_based_access
        self.policies['ip_based_access'] = self._policy_ip_based_access
    
    async def authorize(self,
                       context: MCPSecurityContext,
                       resource: str,
                       action: str,
                       resource_attributes: Optional[Dict[str, Any]] = None) -> AuthorizationResult:
        """
        Authorize an operation.
        
        Args:
            context: Security context
            resource: Resource being accessed
            action: Action being performed
            resource_attributes: Additional resource attributes
            
        Returns:
            AuthorizationResult
        """
        try:
            # Check basic RBAC permissions
            rbac_result = await self._check_rbac_permission(context, resource, action)
            if not rbac_result.granted:
                return rbac_result
            
            # Apply additional policies
            policy_results = []
            
            for policy_name, policy_func in self.policies.items():
                try:
                    policy_result = await policy_func(context, resource, action, resource_attributes)
                    policy_results.append((policy_name, policy_result))
                    
                    if not policy_result.granted:
                        return policy_result
                        
                except Exception as e:
                    logger.error(f"Policy {policy_name} error: {e}")
                    # Continue with other policies
            
            return AuthorizationResult(
                granted=True,
                reason="All authorization checks passed",
                required_permissions=[f"{resource}:{action}"]
            )
            
        except Exception as e:
            logger.error(f"Authorization error: {e}")
            return AuthorizationResult(
                granted=False,
                reason=f"Authorization error: {str(e)}"
            )
    
    async def _check_rbac_permission(self,
                                   context: MCPSecurityContext,
                                   resource: str,
                                   action: str) -> AuthorizationResult:
        """Check RBAC permissions"""
        required_permission = f"{resource}:{action}"
        
        # Check direct permissions
        if required_permission in context.permissions:
            return AuthorizationResult(
                granted=True,
                reason="Direct permission granted",
                required_permissions=[required_permission]
            )
        
        # Check wildcard permissions
        wildcard_permissions = [
            f"{resource}:*",
            f"*:{action}",
            "*:*"
        ]
        
        for perm in wildcard_permissions:
            if perm in context.permissions:
                return AuthorizationResult(
                    granted=True,
                    reason=f"Wildcard permission granted: {perm}",
                    required_permissions=[required_permission]
                )
        
        return AuthorizationResult(
            granted=False,
            reason="Insufficient permissions",
            required_permissions=[required_permission],
            missing_permissions=[required_permission]
        )
    
    async def _policy_mcp_server_access(self,
                                      context: MCPSecurityContext,
                                      resource: str,
                                      action: str,
                                      resource_attributes: Optional[Dict[str, Any]]) -> AuthorizationResult:
        """Policy for MCP server access"""
        # Check if user is accessing their own resources
        if resource_attributes and resource_attributes.get('owner_id') == context.user_id:
            return AuthorizationResult(
                granted=True,
                reason="User accessing own resources"
            )
        
        # Check for shared access
        if resource_attributes and context.user_id in resource_attributes.get('shared_with', []):
            return AuthorizationResult(
                granted=True,
                reason="Resource shared with user"
            )
        
        # Require explicit permission for other resources
        return AuthorizationResult(
            granted=False,
            reason="Access to resource not allowed",
            policy_violations=["mcp_server_access"]
        )
    
    async def _policy_file_operations(self,
                                    context: MCPSecurityContext,
                                    resource: str,
                                    action: str,
                                    resource_attributes: Optional[Dict[str, Any]]) -> AuthorizationResult:
        """Policy for file operations"""
        if resource != 'file':
            return AuthorizationResult(granted=True, reason="Not a file operation")
        
        # Check file size limits for uploads
        if action == 'upload' and resource_attributes:
            file_size = resource_attributes.get('size', 0)
            max_size = 100 * 1024 * 1024  # 100MB
            
            if file_size > max_size:
                return AuthorizationResult(
                    granted=False,
                    reason=f"File size {file_size} exceeds limit {max_size}",
                    policy_violations=["file_size_limit"]
                )
        
        # Check file type restrictions
        if resource_attributes:
            file_type = resource_attributes.get('type')
            forbidden_types = ['executable', 'script', 'binary']
            
            if file_type in forbidden_types:
                return AuthorizationResult(
                    granted=False,
                    reason=f"File type {file_type} is forbidden",
                    policy_violations=["file_type_restriction"]
                )
        
        return AuthorizationResult(granted=True, reason="File operation allowed")
    
    async def _policy_admin_operations(self,
                                     context: MCPSecurityContext,
                                     resource: str,
                                     action: str,
                                     resource_attributes: Optional[Dict[str, Any]]) -> AuthorizationResult:
        """Policy for administrative operations"""
        admin_resources = ['user', 'role', 'permission', 'system']
        admin_actions = ['create', 'delete', 'modify', 'configure']
        
        if resource in admin_resources or action in admin_actions:
            # Require admin role
            if 'admin' not in context.permissions and 'administrator' not in context.permissions:
                return AuthorizationResult(
                    granted=False,
                    reason="Administrative privileges required",
                    policy_violations=["admin_required"]
                )
            
            # Require MFA for admin operations
            if not context.attributes.get('mfa_verified', False):
                return AuthorizationResult(
                    granted=False,
                    reason="MFA required for administrative operations",
                    policy_violations=["mfa_required"]
                )
        
        return AuthorizationResult(granted=True, reason="Admin policy passed")
    
    async def _policy_time_based_access(self,
                                      context: MCPSecurityContext,
                                      resource: str,
                                      action: str,
                                      resource_attributes: Optional[Dict[str, Any]]) -> AuthorizationResult:
        """Policy for time-based access restrictions"""
        # Get user's time restrictions
        if context.user_id:
            time_restrictions = await self._get_user_time_restrictions(context.user_id)
            
            if time_restrictions:
                current_time = datetime.utcnow().time()
                allowed_start = time_restrictions.get('start_time')
                allowed_end = time_restrictions.get('end_time')
                
                if allowed_start and allowed_end:
                    if not (allowed_start <= current_time <= allowed_end):
                        return AuthorizationResult(
                            granted=False,
                            reason="Access not allowed at this time",
                            policy_violations=["time_restriction"]
                        )
        
        return AuthorizationResult(granted=True, reason="Time-based access allowed")
    
    async def _policy_ip_based_access(self,
                                    context: MCPSecurityContext,
                                    resource: str,
                                    action: str,
                                    resource_attributes: Optional[Dict[str, Any]]) -> AuthorizationResult:
        """Policy for IP-based access restrictions"""
        # Get user's IP restrictions
        if context.user_id:
            ip_restrictions = await self._get_user_ip_restrictions(context.user_id)
            
            if ip_restrictions:
                allowed_ips = ip_restrictions.get('allowed_ips', [])
                blocked_ips = ip_restrictions.get('blocked_ips', [])
                
                # Check blocked IPs first
                if self._ip_in_list(context.ip_address, blocked_ips):
                    return AuthorizationResult(
                        granted=False,
                        reason="IP address is blocked",
                        policy_violations=["ip_blocked"]
                    )
                
                # Check allowed IPs
                if allowed_ips and not self._ip_in_list(context.ip_address, allowed_ips):
                    return AuthorizationResult(
                        granted=False,
                        reason="IP address not in allowed list",
                        policy_violations=["ip_not_allowed"]
                    )
        
        return AuthorizationResult(granted=True, reason="IP-based access allowed")
    
    def _ip_in_list(self, ip_address: str, ip_list: List[str]) -> bool:
        """Check if IP address is in the given list"""
        try:
            client_addr = ipaddress.ip_address(ip_address)
            
            for ip_spec in ip_list:
                if '/' in ip_spec:
                    # CIDR notation
                    network = ipaddress.ip_network(ip_spec)
                    if client_addr in network:
                        return True
                else:
                    # Single IP
                    if client_addr == ipaddress.ip_address(ip_spec):
                        return True
            
            return False
            
        except ValueError:
            return False
    
    async def _get_user_time_restrictions(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user time restrictions from database"""
        if not self.database_pool:
            return None
        
        async with self.database_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM user_time_restrictions WHERE user_id = $1",
                user_id
            )
            return dict(row) if row else None
    
    async def _get_user_ip_restrictions(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user IP restrictions from database"""
        if not self.database_pool:
            return None
        
        async with self.database_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM user_ip_restrictions WHERE user_id = $1",
                user_id
            )
            return dict(row) if row else None


class MCPSecurityMonitor:
    """Real-time security monitoring for MCP operations"""
    
    def __init__(self,
                 redis_pool: Optional[aioredis.Redis] = None,
                 alert_handlers: Optional[List[Callable]] = None):
        """
        Initialize security monitor.
        
        Args:
            redis_pool: Redis connection for real-time data
            alert_handlers: List of alert handler functions
        """
        self.redis_pool = redis_pool
        self.alert_handlers = alert_handlers or []
        
        # Security metrics
        self.metrics = {
            'failed_auth_attempts': 0,
            'successful_auths': 0,
            'blocked_requests': 0,
            'suspicious_activities': 0
        }
        
        # Anomaly detection thresholds
        self.thresholds = {
            'failed_auth_rate': 0.3,  # 30% failure rate
            'new_ip_threshold': 10,   # Alert on 10+ new IPs per hour
            'high_volume_threshold': 1000  # Alert on 1000+ requests per minute
        }
    
    async def record_auth_attempt(self,
                                context: MCPSecurityContext,
                                success: bool,
                                method: AuthenticationMethod):
        """Record authentication attempt"""
        timestamp = datetime.utcnow()
        
        # Update metrics
        if success:
            self.metrics['successful_auths'] += 1
        else:
            self.metrics['failed_auth_attempts'] += 1
        
        # Store in Redis for real-time analysis
        if self.redis_pool:
            event = {
                'timestamp': timestamp.isoformat(),
                'ip_address': context.ip_address,
                'user_agent': context.user_agent,
                'method': method.value,
                'success': success,
                'client_id': context.client_id
            }
            
            await self.redis_pool.lpush(
                'auth_events',
                json.dumps(event)
            )
            
            # Keep only last 1000 events
            await self.redis_pool.ltrim('auth_events', 0, 999)
        
        # Check for anomalies
        await self._check_auth_anomalies(context, success)
    
    async def record_security_event(self,
                                  event_type: str,
                                  context: MCPSecurityContext,
                                  details: Dict[str, Any]):
        """Record security event"""
        timestamp = datetime.utcnow()
        
        # Store event
        if self.redis_pool:
            event = {
                'timestamp': timestamp.isoformat(),
                'type': event_type,
                'ip_address': context.ip_address,
                'user_id': context.user_id,
                'client_id': context.client_id,
                'details': details
            }
            
            await self.redis_pool.lpush(
                'security_events',
                json.dumps(event)
            )
            
            # Keep only last 10000 events
            await self.redis_pool.ltrim('security_events', 0, 9999)
        
        # Check if event requires immediate attention
        await self._evaluate_security_event(event_type, context, details)
    
    async def _check_auth_anomalies(self,
                                  context: MCPSecurityContext,
                                  success: bool):
        """Check for authentication anomalies"""
        if not self.redis_pool:
            return
        
        # Get recent auth attempts for this IP
        recent_events = await self.redis_pool.lrange('auth_events', 0, 99)
        
        ip_events = []
        for event_json in recent_events:
            event = json.loads(event_json)
            if event['ip_address'] == context.ip_address:
                ip_events.append(event)
        
        if len(ip_events) >= 10:
            # Calculate failure rate
            failures = sum(1 for e in ip_events if not e['success'])
            failure_rate = failures / len(ip_events)
            
            if failure_rate >= self.thresholds['failed_auth_rate']:
                await self._trigger_alert(
                    'high_failure_rate',
                    f"High authentication failure rate: {failure_rate:.2%} from IP {context.ip_address}",
                    {'ip_address': context.ip_address, 'failure_rate': failure_rate}
                )
    
    async def _evaluate_security_event(self,
                                     event_type: str,
                                     context: MCPSecurityContext,
                                     details: Dict[str, Any]):
        """Evaluate security event for immediate response"""
        critical_events = [
            'admin_access_attempt',
            'privilege_escalation',
            'data_exfiltration',
            'malware_detected',
            'brute_force_attack'
        ]
        
        if event_type in critical_events:
            await self._trigger_alert(
                'critical_security_event',
                f"Critical security event: {event_type}",
                {
                    'event_type': event_type,
                    'ip_address': context.ip_address,
                    'user_id': context.user_id,
                    'details': details
                }
            )
    
    async def _trigger_alert(self,
                           alert_type: str,
                           message: str,
                           metadata: Dict[str, Any]):
        """Trigger security alert"""
        alert = {
            'timestamp': datetime.utcnow().isoformat(),
            'type': alert_type,
            'message': message,
            'metadata': metadata,
            'severity': self._get_alert_severity(alert_type)
        }
        
        # Call alert handlers
        for handler in self.alert_handlers:
            try:
                await handler(alert)
            except Exception as e:
                logger.error(f"Alert handler error: {e}")
        
        # Log alert
        logger.warning(f"Security alert: {alert_type} - {message}")
    
    def _get_alert_severity(self, alert_type: str) -> str:
        """Get alert severity level"""
        critical_alerts = ['critical_security_event', 'brute_force_attack']
        high_alerts = ['high_failure_rate', 'privilege_escalation']
        
        if alert_type in critical_alerts:
            return 'critical'
        elif alert_type in high_alerts:
            return 'high'
        else:
            return 'medium'


# Example usage and integration
async def example_mcp_security_integration():
    """Example of MCP security system integration"""
    
    # Initialize components
    auth_provider = MCPAuthenticationProvider(
        secret_key="your-secret-key",
        # database_pool=db_pool,
        # redis_pool=redis_pool
    )
    
    # Create certificate validator
    cert_validator = MCPCertificateValidator(
        ca_cert_path=Path("./ca.pem")
    )
    
    # Initialize authorization manager
    rbac_manager = RBACManager()
    auth_manager = MCPAuthorizationManager(rbac_manager)
    
    # Initialize security monitor
    security_monitor = MCPSecurityMonitor()
    
    # Example authentication
    api_key = "key_id.key_secret.signature"
    auth_result = await auth_provider.authenticate_api_key(
        api_key=api_key,
        client_ip="192.168.1.100",
        user_agent="MCP-Client/1.0"
    )
    
    if auth_result.success:
        # Example authorization
        authz_result = await auth_manager.authorize(
            context=auth_result.context,
            resource="file",
            action="read",
            resource_attributes={'owner_id': 'user123'}
        )
        
        print(f"Authorization: {authz_result.granted}")
        
        # Record security event
        await security_monitor.record_auth_attempt(
            auth_result.context,
            True,
            AuthenticationMethod.API_KEY
        )
    
    print(f"Authentication: {auth_result.success}")


if __name__ == "__main__":
    asyncio.run(example_mcp_security_integration())