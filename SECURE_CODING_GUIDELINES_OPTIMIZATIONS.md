# Secure Coding Guidelines for Performance Optimizations

## Version 1.0 - June 2025

## Table of Contents
1. [Introduction](#introduction)
2. [Object Pooling Security](#object-pooling-security)
3. [Connection Pooling Security](#connection-pooling-security)
4. [Memory Monitoring Security](#memory-monitoring-security)
5. [OWASP Compliance](#owasp-compliance)
6. [Code Examples](#code-examples)
7. [Security Checklist](#security-checklist)

## Introduction

These guidelines provide security best practices for implementing and maintaining performance optimization features in the Claude Optimized Deployment system. All developers must follow these guidelines to prevent security vulnerabilities.

## Object Pooling Security

### Principle 1: Complete State Isolation

**REQUIREMENT**: All pooled objects MUST completely reset their state before reuse.

✅ **SECURE IMPLEMENTATION**:
```python
class SecurePooledObject(PooledObject):
    def __init__(self):
        super().__init__()
        self._security_context = SecurityContext()
        self._sensitive_data = None
        self._user_context = None
        self._init_timestamp = time.time()
    
    def reset(self):
        """Complete state reset with verification"""
        # Step 1: Clear all data
        self._clear_sensitive_data()
        
        # Step 2: Reset security context
        self._security_context = SecurityContext()
        
        # Step 3: Clear user context
        self._user_context = None
        
        # Step 4: Verify reset completion
        assert self._verify_clean_state(), "Reset verification failed"
        
        # Step 5: Update parent
        super().reset()
    
    def _clear_sensitive_data(self):
        """Securely clear sensitive data"""
        if self._sensitive_data is not None:
            # Overwrite memory if possible
            if isinstance(self._sensitive_data, (str, bytes)):
                # Use secure deletion
                secure_delete(self._sensitive_data)
            self._sensitive_data = None
    
    def _verify_clean_state(self) -> bool:
        """Verify object is in clean state"""
        return (
            self._sensitive_data is None and
            self._user_context is None and
            len([attr for attr in dir(self) 
                 if not attr.startswith('_') and 
                 getattr(self, attr) is not None]) == 0
        )
```

❌ **INSECURE IMPLEMENTATION**:
```python
class InsecurePooledObject:
    def reset(self):
        # DON'T: Incomplete reset
        self.data = None  # Other fields may still contain data
        # Missing: verification, security context reset, memory clearing
```

### Principle 2: Object Validation

**REQUIREMENT**: Objects MUST be validated before entering and after leaving the pool.

✅ **SECURE IMPLEMENTATION**:
```python
class ValidatedObjectPool(ObjectPool):
    def __init__(self, factory, validator=None):
        super().__init__(factory)
        self._validator = validator or self._default_validator
        self._rejected_count = 0
    
    def release(self, obj: Any):
        """Release with validation"""
        # Pre-release validation
        if not self._validate_object(obj):
            self._rejected_count += 1
            self._handle_invalid_object(obj)
            return
        
        # Reset the object
        if hasattr(obj, 'reset'):
            try:
                obj.reset()
            except Exception as e:
                logger.error(f"Reset failed: {e}")
                self._handle_invalid_object(obj)
                return
        
        # Post-reset validation
        if not self._validate_object(obj):
            self._handle_invalid_object(obj)
            return
        
        # Safe to return to pool
        super().release(obj)
    
    def _validate_object(self, obj: Any) -> bool:
        """Validate object safety"""
        try:
            # Check object type
            if not isinstance(obj, self._expected_type):
                return False
            
            # Check for malicious attributes
            suspicious_attrs = ['__code__', '__globals__', 'eval', 'exec']
            for attr in suspicious_attrs:
                if hasattr(obj, attr):
                    return False
            
            # Custom validation
            return self._validator(obj)
        except Exception:
            return False
    
    def _handle_invalid_object(self, obj: Any):
        """Handle invalid/malicious objects"""
        logger.warning(f"Invalid object rejected: {type(obj)}")
        # Secure disposal
        del obj
```

### Principle 3: Tenant Isolation

**REQUIREMENT**: Multi-tenant systems MUST maintain strict isolation between tenants.

✅ **SECURE IMPLEMENTATION**:
```python
class TenantIsolatedPool:
    def __init__(self, factory):
        self._tenant_pools = {}
        self._factory = factory
        self._lock = threading.RLock()
    
    def acquire(self, tenant_id: str, user_context: Dict) -> Any:
        """Acquire object with tenant isolation"""
        # Validate tenant ID
        if not self._validate_tenant_id(tenant_id):
            raise SecurityException("Invalid tenant ID")
        
        with self._lock:
            # Get or create tenant-specific pool
            if tenant_id not in self._tenant_pools:
                self._tenant_pools[tenant_id] = ObjectPool(
                    factory=self._factory,
                    max_size=self._get_tenant_quota(tenant_id)
                )
            
            pool = self._tenant_pools[tenant_id]
        
        # Acquire from tenant pool
        obj = pool.acquire()
        
        # Set security context
        if hasattr(obj, 'set_security_context'):
            obj.set_security_context({
                'tenant_id': tenant_id,
                'user_id': user_context.get('user_id'),
                'permissions': user_context.get('permissions', []),
                'timestamp': time.time()
            })
        
        return obj
    
    def _validate_tenant_id(self, tenant_id: str) -> bool:
        """Validate tenant ID format and authorization"""
        # Check format
        if not re.match(r'^[a-zA-Z0-9\-]{1,64}$', tenant_id):
            return False
        
        # Check authorization (implement your logic)
        return True
```

## Connection Pooling Security

### Principle 4: Credential Protection

**REQUIREMENT**: Connection credentials MUST be encrypted at rest and in transit.

✅ **SECURE IMPLEMENTATION**:
```python
import keyring
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2

class SecureCredentialManager:
    def __init__(self, app_id: str):
        self._app_id = app_id
        self._fernet = self._initialize_encryption()
        self._credential_cache = TTLCache(maxsize=100, ttl=300)  # 5 min TTL
    
    def _initialize_encryption(self) -> Fernet:
        """Initialize encryption with app-specific key"""
        # Get or create master key
        master_key = keyring.get_password(self._app_id, "master_key")
        if not master_key:
            master_key = Fernet.generate_key().decode()
            keyring.set_password(self._app_id, "master_key", master_key)
        
        return Fernet(master_key.encode())
    
    def store_connection_string(self, identifier: str, connection_string: str):
        """Store encrypted connection string"""
        # Validate connection string
        if not self._validate_connection_string(connection_string):
            raise ValueError("Invalid connection string format")
        
        # Extract and encrypt sensitive parts
        parsed = self._parse_connection_string(connection_string)
        parsed['password'] = self._fernet.encrypt(
            parsed['password'].encode()
        ).decode()
        
        # Store securely
        keyring.set_password(
            self._app_id,
            f"conn_{identifier}",
            json.dumps(parsed)
        )
    
    def get_connection_string(self, identifier: str) -> str:
        """Retrieve and decrypt connection string"""
        # Check cache first
        cache_key = f"conn_{identifier}"
        if cache_key in self._credential_cache:
            return self._credential_cache[cache_key]
        
        # Retrieve from secure storage
        stored = keyring.get_password(self._app_id, cache_key)
        if not stored:
            raise KeyError(f"Connection string not found: {identifier}")
        
        # Decrypt password
        parsed = json.loads(stored)
        parsed['password'] = self._fernet.decrypt(
            parsed['password'].encode()
        ).decode()
        
        # Reconstruct connection string
        conn_str = self._reconstruct_connection_string(parsed)
        
        # Cache for performance
        self._credential_cache[cache_key] = conn_str
        
        return conn_str
    
    def _validate_connection_string(self, conn_str: str) -> bool:
        """Validate connection string safety"""
        # Check for injection attempts
        dangerous_patterns = [
            r';\s*DROP\s+',
            r';\s*DELETE\s+',
            r';\s*UPDATE\s+',
            r'--',
            r'/\*.*\*/',
            r'\$\{.*\}',
            r'\$\(.*\)'
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, conn_str, re.IGNORECASE):
                return False
        
        return True
```

### Principle 5: Connection Validation

**REQUIREMENT**: All connections MUST be validated before use.

✅ **SECURE IMPLEMENTATION**:
```python
class SecureConnectionPool(HTTPConnectionPool):
    def __init__(self, config: ConnectionPoolConfig):
        super().__init__(config)
        self._trusted_hosts = set()
        self._certificate_store = CertificateStore()
    
    async def get_session(self, url: str) -> aiohttp.ClientSession:
        """Get validated session"""
        # Validate URL
        parsed_url = self._validate_url(url)
        
        # Check if host is trusted
        if not self._is_trusted_host(parsed_url.hostname):
            raise SecurityException(f"Untrusted host: {parsed_url.hostname}")
        
        # Get or create session
        session = await super().get_session(url)
        
        # Validate SSL/TLS
        await self._validate_tls(session, parsed_url)
        
        return session
    
    def _validate_url(self, url: str) -> ParseResult:
        """Validate and parse URL"""
        parsed = urlparse(url)
        
        # Enforce HTTPS for external hosts
        if parsed.hostname not in ['localhost', '127.0.0.1']:
            if parsed.scheme != 'https':
                raise SecurityException("HTTPS required for external hosts")
        
        # Validate hostname format
        if not self._is_valid_hostname(parsed.hostname):
            raise SecurityException(f"Invalid hostname: {parsed.hostname}")
        
        # Check for suspicious ports
        suspicious_ports = [22, 23, 135, 139, 445, 3389]
        if parsed.port in suspicious_ports:
            raise SecurityException(f"Suspicious port: {parsed.port}")
        
        return parsed
    
    async def _validate_tls(self, session: aiohttp.ClientSession, url: ParseResult):
        """Validate TLS configuration"""
        connector = session.connector
        
        # Get peer certificate
        transport = connector._transports.get((url.hostname, url.port))
        if transport:
            ssl_obj = transport.get_extra_info('ssl_object')
            if ssl_obj:
                # Verify certificate
                cert = ssl_obj.getpeercert()
                
                # Check expiration
                not_after = datetime.strptime(
                    cert['notAfter'], 
                    '%b %d %H:%M:%S %Y %Z'
                )
                if datetime.now() > not_after:
                    raise SecurityException("Certificate expired")
                
                # Verify certificate pinning if configured
                if self._certificate_store.has_pin(url.hostname):
                    if not self._certificate_store.verify_pin(url.hostname, cert):
                        raise SecurityException("Certificate pin mismatch")
```

### Principle 6: Connection Lifecycle Management

**REQUIREMENT**: Connections MUST have defined lifecycles with security checks.

✅ **SECURE IMPLEMENTATION**:
```python
class LifecycleManagedPool:
    def __init__(self, config: PoolConfig):
        self.config = config
        self._connections = {}
        self._metadata = {}
        self._health_checker = HealthChecker()
    
    async def acquire_connection(self, identifier: str) -> Connection:
        """Acquire connection with lifecycle management"""
        conn_key = self._get_connection_key(identifier)
        
        # Check if connection exists and is healthy
        if conn_key in self._connections:
            conn = self._connections[conn_key]
            metadata = self._metadata[conn_key]
            
            # Check age
            if self._is_connection_expired(metadata):
                await self._close_connection(conn_key)
            # Check health
            elif not await self._health_checker.check(conn):
                await self._close_connection(conn_key)
            else:
                # Update usage
                metadata['last_used'] = datetime.now()
                metadata['use_count'] += 1
                return conn
        
        # Create new connection
        conn = await self._create_secure_connection(identifier)
        self._connections[conn_key] = conn
        self._metadata[conn_key] = {
            'created': datetime.now(),
            'last_used': datetime.now(),
            'use_count': 1,
            'identifier': identifier
        }
        
        return conn
    
    def _is_connection_expired(self, metadata: Dict) -> bool:
        """Check if connection exceeded lifetime"""
        age = (datetime.now() - metadata['created']).total_seconds()
        return age > self.config.max_connection_lifetime
    
    async def _create_secure_connection(self, identifier: str) -> Connection:
        """Create new connection with security hardening"""
        # Get credentials securely
        creds = await self._get_secure_credentials(identifier)
        
        # Create connection with security options
        conn = await create_connection(
            host=creds['host'],
            port=creds['port'],
            user=creds['user'],
            password=creds['password'],
            ssl_mode='require',
            ssl_cert=self.config.client_cert,
            ssl_key=self.config.client_key,
            ssl_ca=self.config.ca_cert,
            connect_timeout=self.config.connect_timeout,
            application_name=f"claude_opt_{identifier}"
        )
        
        # Post-connection security setup
        await self._setup_connection_security(conn)
        
        return conn
```

## Memory Monitoring Security

### Principle 7: Metric Sanitization

**REQUIREMENT**: All metrics MUST be sanitized before exposure.

✅ **SECURE IMPLEMENTATION**:
```python
class SecureMetricsCollector:
    def __init__(self):
        self._noise_generator = NoiseGenerator()
        self._sanitizer = MetricSanitizer()
        self._rate_limiter = RateLimiter(
            max_requests_per_minute=60,
            max_requests_per_hour=1000
        )
    
    def collect_metrics(self, requester_id: str) -> Dict[str, Any]:
        """Collect sanitized metrics"""
        # Rate limiting
        if not self._rate_limiter.check_limit(requester_id):
            raise RateLimitExceeded("Metric collection rate limit exceeded")
        
        # Collect raw metrics
        raw_metrics = self._collect_raw_metrics()
        
        # Sanitize sensitive data
        sanitized = self._sanitizer.sanitize(raw_metrics)
        
        # Add noise to prevent information leakage
        with_noise = self._add_privacy_noise(sanitized)
        
        # Round values to prevent precise measurements
        rounded = self._round_metrics(with_noise)
        
        return rounded
    
    def _add_privacy_noise(self, metrics: Dict) -> Dict:
        """Add differential privacy noise"""
        noisy_metrics = metrics.copy()
        
        # Add Laplacian noise to numeric values
        for key, value in metrics.items():
            if isinstance(value, (int, float)):
                # Scale noise based on sensitivity
                sensitivity = self._get_metric_sensitivity(key)
                noise = self._noise_generator.laplacian(
                    scale=sensitivity,
                    epsilon=0.1  # Privacy parameter
                )
                noisy_metrics[key] = value + noise
        
        return noisy_metrics
    
    def _round_metrics(self, metrics: Dict) -> Dict:
        """Round metrics to prevent precise measurements"""
        rounded = {}
        
        for key, value in metrics.items():
            if key.endswith('_mb'):
                # Round memory to nearest 10MB
                rounded[key] = round(value, -1)
            elif key.endswith('_percent'):
                # Round percentages to nearest 5%
                rounded[key] = round(value / 5) * 5
            elif key.endswith('_ms'):
                # Round times to nearest 10ms
                rounded[key] = round(value, -1)
            else:
                rounded[key] = value
        
        return rounded
```

### Principle 8: Access Control for Monitoring

**REQUIREMENT**: Monitoring endpoints MUST implement proper access control.

✅ **SECURE IMPLEMENTATION**:
```python
class SecureMonitoringEndpoint:
    def __init__(self):
        self._acl = AccessControlList()
        self._audit_logger = AuditLogger()
        self._metric_filter = MetricFilter()
    
    async def get_metrics(self, request: Request) -> Response:
        """Get metrics with access control"""
        # Authentication
        user = await self._authenticate_request(request)
        if not user:
            return Response(status=401, text="Unauthorized")
        
        # Authorization
        if not self._acl.check_permission(user, 'metrics:read'):
            self._audit_logger.log_unauthorized_access(user, 'metrics:read')
            return Response(status=403, text="Forbidden")
        
        # Get metrics based on user role
        metrics = await self._get_filtered_metrics(user)
        
        # Audit log
        self._audit_logger.log_metric_access(user, metrics.keys())
        
        return Response(
            status=200,
            content_type='application/json',
            text=json.dumps(metrics)
        )
    
    async def _get_filtered_metrics(self, user: User) -> Dict:
        """Get metrics filtered by user permissions"""
        all_metrics = await self._collect_all_metrics()
        
        # Filter based on user role
        if user.role == 'admin':
            return all_metrics
        elif user.role == 'developer':
            return self._metric_filter.filter_for_developer(all_metrics)
        elif user.role == 'operator':
            return self._metric_filter.filter_for_operator(all_metrics)
        else:
            return self._metric_filter.filter_for_basic(all_metrics)
    
    def _authenticate_request(self, request: Request) -> Optional[User]:
        """Authenticate request using secure methods"""
        # Check API key
        api_key = request.headers.get('X-API-Key')
        if api_key:
            return self._authenticate_api_key(api_key)
        
        # Check JWT token
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header[7:]
            return self._authenticate_jwt(token)
        
        return None
```

## OWASP Compliance

### A01:2021 – Broken Access Control

**Prevention in Object Pools**:
```python
# Implement role-based pool access
class RBACObjectPool:
    def acquire(self, user_context: Dict) -> Any:
        if not self._check_permission(user_context, 'pool:acquire'):
            raise PermissionDenied("Insufficient permissions for pool access")
        return super().acquire()
```

### A02:2021 – Cryptographic Failures

**Prevention in Connection Pools**:
```python
# Enforce strong cryptography
class CryptoSecurePool:
    MIN_TLS_VERSION = ssl.TLSVersion.TLSv1_3
    ALLOWED_CIPHERS = [
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256',
        'TLS_AES_128_GCM_SHA256'
    ]
```

### A03:2021 – Injection

**Prevention in All Components**:
```python
# Input validation for all user inputs
class InputValidator:
    @staticmethod
    def validate_identifier(identifier: str) -> str:
        if not re.match(r'^[a-zA-Z0-9_\-]{1,64}$', identifier):
            raise ValueError("Invalid identifier format")
        return identifier
```

### A04:2021 – Insecure Design

**Prevention Through Threat Modeling**:
```python
# Design with security in mind
class SecureByDesignPool:
    def __init__(self):
        self._threat_model = ThreatModel()
        self._security_controls = self._threat_model.get_required_controls()
        self._implement_controls()
```

### A07:2021 – Identification and Authentication Failures

**Prevention in Credential Management**:
```python
# Multi-factor authentication for sensitive operations
class MFAProtectedPool:
    async def perform_sensitive_operation(self, user: User, mfa_token: str):
        if not await self._verify_mfa(user, mfa_token):
            raise AuthenticationError("MFA verification failed")
```

## Code Examples

### Complete Secure Pool Implementation

```python
import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import threading
import time
from typing import Any, Dict, Optional, List, Callable
from datetime import datetime, timedelta
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

class SecurePooledObject(ABC):
    """Base class for secure pooled objects"""
    
    def __init__(self):
        self._id = secrets.token_hex(16)
        self._created_at = datetime.now()
        self._reset_count = 0
        self._hmac_key = secrets.token_bytes(32)
        self._tenant_id: Optional[str] = None
        self._security_context: Dict[str, Any] = {}
        self._compute_checksum()
    
    def _compute_checksum(self) -> str:
        """Compute integrity checksum"""
        data = json.dumps({
            'id': self._id,
            'created_at': self._created_at.isoformat(),
            'reset_count': self._reset_count,
            'tenant_id': self._tenant_id
        }, sort_keys=True)
        
        return hmac.new(
            self._hmac_key,
            data.encode(),
            hashlib.sha256
        ).hexdigest()
    
    def verify_integrity(self) -> bool:
        """Verify object integrity"""
        expected = self._checksum
        actual = self._compute_checksum()
        return hmac.compare_digest(expected, actual)
    
    @abstractmethod
    def reset(self):
        """Reset object state - must be implemented by subclasses"""
        pass
    
    def secure_reset(self):
        """Perform secure reset with verification"""
        # Clear user data
        self.reset()
        
        # Clear security context
        self._security_context.clear()
        self._tenant_id = None
        
        # Increment reset count
        self._reset_count += 1
        
        # Recompute checksum
        self._checksum = self._compute_checksum()
        
        # Verify clean state
        assert self._is_clean_state(), "Object not in clean state after reset"
    
    def _is_clean_state(self) -> bool:
        """Check if object is in clean state"""
        # Check all non-private attributes are cleared
        for attr in dir(self):
            if not attr.startswith('_'):
                value = getattr(self, attr, None)
                if value is not None and not callable(value):
                    return False
        return True

class SecureObjectPool:
    """Thread-safe object pool with security features"""
    
    def __init__(
        self,
        factory: Callable[[], Any],
        max_size: int = 100,
        tenant_aware: bool = False,
        enable_audit: bool = True
    ):
        self._factory = factory
        self._max_size = max_size
        self._tenant_aware = tenant_aware
        self._enable_audit = enable_audit
        
        # Pool storage
        self._available: List[Any] = []
        self._in_use: Dict[str, Any] = {}
        self._tenant_pools: Dict[str, List[Any]] = {}
        
        # Security
        self._lock = threading.RLock()
        self._audit_log: List[Dict] = []
        self._rejected_objects: List[Any] = []
        
        # Metrics
        self._created_count = 0
        self._reused_count = 0
        self._rejected_count = 0
    
    def acquire(self, tenant_id: Optional[str] = None) -> Any:
        """Acquire object from pool with security checks"""
        with self._lock:
            # Audit
            if self._enable_audit:
                self._audit_log.append({
                    'action': 'acquire',
                    'tenant_id': tenant_id,
                    'timestamp': datetime.now()
                })
            
            # Get from appropriate pool
            if self._tenant_aware and tenant_id:
                pool = self._tenant_pools.get(tenant_id, [])
            else:
                pool = self._available
            
            # Try to reuse existing object
            while pool:
                obj = pool.pop()
                
                # Validate object
                if self._validate_for_reuse(obj):
                    # Set up for new use
                    obj_id = self._prepare_for_use(obj, tenant_id)
                    self._in_use[obj_id] = obj
                    self._reused_count += 1
                    return obj
                else:
                    # Reject invalid object
                    self._rejected_objects.append(obj)
                    self._rejected_count += 1
            
            # Create new object
            try:
                obj = self._create_new_object(tenant_id)
                obj_id = self._prepare_for_use(obj, tenant_id)
                self._in_use[obj_id] = obj
                self._created_count += 1
                return obj
            except Exception as e:
                logger.error(f"Failed to create object: {e}")
                raise
    
    def release(self, obj: Any):
        """Release object back to pool with security validation"""
        with self._lock:
            # Find and remove from in-use
            obj_id = None
            for id, in_use_obj in self._in_use.items():
                if in_use_obj is obj:
                    obj_id = id
                    break
            
            if obj_id:
                del self._in_use[obj_id]
            
            # Audit
            if self._enable_audit:
                self._audit_log.append({
                    'action': 'release',
                    'object_id': obj_id,
                    'timestamp': datetime.now()
                })
            
            # Validate before returning to pool
            if not self._validate_for_release(obj):
                self._rejected_objects.append(obj)
                self._rejected_count += 1
                return
            
            # Secure reset
            try:
                if hasattr(obj, 'secure_reset'):
                    obj.secure_reset()
                elif hasattr(obj, 'reset'):
                    obj.reset()
            except Exception as e:
                logger.error(f"Failed to reset object: {e}")
                self._rejected_objects.append(obj)
                self._rejected_count += 1
                return
            
            # Return to appropriate pool
            tenant_id = getattr(obj, '_tenant_id', None)
            if self._tenant_aware and tenant_id:
                if tenant_id not in self._tenant_pools:
                    self._tenant_pools[tenant_id] = []
                pool = self._tenant_pools[tenant_id]
            else:
                pool = self._available
            
            # Check pool size limit
            if len(pool) < self._max_size:
                pool.append(obj)
            else:
                # Pool full, discard object
                del obj
    
    def _validate_for_reuse(self, obj: Any) -> bool:
        """Validate object is safe for reuse"""
        try:
            # Check object type
            expected_type = type(self._factory())
            if not isinstance(obj, expected_type):
                return False
            
            # Check integrity if supported
            if hasattr(obj, 'verify_integrity'):
                if not obj.verify_integrity():
                    return False
            
            # Check age
            if hasattr(obj, '_created_at'):
                age = (datetime.now() - obj._created_at).total_seconds()
                if age > 3600:  # 1 hour max age
                    return False
            
            # Check reset count
            if hasattr(obj, '_reset_count'):
                if obj._reset_count > 100:  # Max 100 reuses
                    return False
            
            return True
        except Exception:
            return False
    
    def _validate_for_release(self, obj: Any) -> bool:
        """Validate object is safe to return to pool"""
        try:
            # Basic type check
            if obj is None:
                return False
            
            # Check for dangerous attributes
            dangerous_attrs = [
                '__setattr__', '__delattr__', '__getattribute__',
                'eval', 'exec', '__import__', '__code__'
            ]
            
            for attr in dangerous_attrs:
                if hasattr(obj, attr) and not hasattr(type(obj), attr):
                    # Object has been modified with dangerous attribute
                    return False
            
            return True
        except Exception:
            return False
    
    def _prepare_for_use(self, obj: Any, tenant_id: Optional[str]) -> str:
        """Prepare object for use"""
        obj_id = secrets.token_hex(16)
        
        if hasattr(obj, '_tenant_id'):
            obj._tenant_id = tenant_id
        
        if hasattr(obj, '_last_used'):
            obj._last_used = datetime.now()
        
        return obj_id
    
    def _create_new_object(self, tenant_id: Optional[str]) -> Any:
        """Create new object with security initialization"""
        obj = self._factory()
        
        # Initialize security attributes if supported
        if hasattr(obj, '_tenant_id'):
            obj._tenant_id = tenant_id
        
        return obj
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get pool statistics"""
        with self._lock:
            total_available = len(self._available)
            if self._tenant_aware:
                for pool in self._tenant_pools.values():
                    total_available += len(pool)
            
            return {
                'created_count': self._created_count,
                'reused_count': self._reused_count,
                'rejected_count': self._rejected_count,
                'available_count': total_available,
                'in_use_count': len(self._in_use),
                'hit_rate': self._reused_count / max(1, self._created_count + self._reused_count),
                'rejection_rate': self._rejected_count / max(1, self._rejected_count + self._reused_count)
            }
```

## Security Checklist

### Development Phase
- [ ] All pooled objects implement secure reset
- [ ] Object validation implemented for pool entry/exit
- [ ] Tenant isolation verified in multi-tenant scenarios
- [ ] Connection strings encrypted at rest
- [ ] TLS 1.3 or higher enforced
- [ ] Input validation on all user inputs
- [ ] Metrics sanitized before exposure
- [ ] Rate limiting implemented
- [ ] Audit logging enabled

### Code Review Phase
- [ ] No hardcoded credentials
- [ ] No sensitive data in logs
- [ ] Error messages don't leak information
- [ ] All exceptions handled securely
- [ ] Security headers configured
- [ ] CORS properly configured
- [ ] Authentication required for sensitive operations
- [ ] Authorization checks in place

### Testing Phase
- [ ] Security unit tests pass
- [ ] Integration security tests pass
- [ ] Penetration testing completed
- [ ] Performance impact measured
- [ ] Stress testing completed
- [ ] Fuzzing performed
- [ ] Static analysis clean

### Deployment Phase
- [ ] Secrets management configured
- [ ] Network segmentation in place
- [ ] Monitoring and alerting enabled
- [ ] Incident response plan ready
- [ ] Backup and recovery tested
- [ ] Security patches applied
- [ ] Documentation updated

### Operations Phase
- [ ] Regular security audits scheduled
- [ ] Vulnerability scanning automated
- [ ] Log analysis ongoing
- [ ] Metrics monitored for anomalies
- [ ] Access reviews conducted
- [ ] Security training completed
- [ ] Compliance verified

## Conclusion

Following these secure coding guidelines is mandatory for all code dealing with performance optimizations. Regular security reviews and updates to these guidelines ensure ongoing protection against evolving threats.

Remember: **Security is not optional** - it's a fundamental requirement for production systems.