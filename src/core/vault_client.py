"""
Enhanced HashiCorp Vault Client with Advanced Features

This module provides a comprehensive Vault client with automatic rotation,
high availability, and advanced caching capabilities.
"""

import os
import json
import asyncio
import threading
from typing import Any, Dict, Optional, List, Set, Tuple, Callable
from datetime import datetime, timedelta
from functools import wraps
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
import hashlib
import hmac
import secrets

import hvac
from hvac.exceptions import VaultError, InvalidRequest, Forbidden
import backoff
from cachetools import TTLCache, LRUCache
from prometheus_client import Counter, Histogram, Gauge

from src.core.exceptions import ConfigurationError, SecurityError
from src.core.logging_config import get_logger
from src.core.log_sanitization import sanitize_log_data
from src.monitoring.metrics import MetricsCollector

logger = get_logger(__name__)

# Metrics
vault_operations = Counter('vault_operations_total', 'Total Vault operations', ['operation', 'status'])
vault_operation_duration = Histogram('vault_operation_duration_seconds', 'Vault operation duration', ['operation'])
vault_cache_hits = Counter('vault_cache_hits_total', 'Vault cache hits')
vault_cache_misses = Counter('vault_cache_misses_total', 'Vault cache misses')
vault_active_connections = Gauge('vault_active_connections', 'Active Vault connections')
vault_rotation_operations = Counter('vault_rotation_operations_total', 'Secret rotation operations', ['status'])


@dataclass
class VaultConfig:
    """Configuration for Vault client."""
    url: str = field(default_factory=lambda: os.getenv("VAULT_ADDR", "http://localhost:8200"))
    token: Optional[str] = field(default_factory=lambda: os.getenv("VAULT_TOKEN"))
    namespace: Optional[str] = field(default_factory=lambda: os.getenv("VAULT_NAMESPACE"))
    mount_point: str = "secret"
    kv_version: int = 2
    max_retries: int = 3
    retry_delay: float = 1.0
    connection_timeout: int = 30
    read_timeout: int = 30
    enable_cache: bool = True
    cache_ttl: int = 300  # 5 minutes
    cache_size: int = 1000
    enable_ha: bool = True
    ha_discover_nodes: bool = True
    tls_verify: bool = True
    tls_ca_cert: Optional[str] = field(default_factory=lambda: os.getenv("VAULT_CACERT"))
    tls_client_cert: Optional[str] = field(default_factory=lambda: os.getenv("VAULT_CLIENT_CERT"))
    tls_client_key: Optional[str] = field(default_factory=lambda: os.getenv("VAULT_CLIENT_KEY"))


@dataclass
class SecretMetadata:
    """Metadata for a secret."""
    path: str
    version: int
    created_time: datetime
    updated_time: datetime
    deletion_time: Optional[datetime] = None
    destroyed: bool = False
    custom_metadata: Dict[str, Any] = field(default_factory=dict)


class VaultConnectionPool:
    """Connection pool for Vault clients."""
    
    def __init__(self, config: VaultConfig, pool_size: int = 10):
        self.config = config
        self.pool_size = pool_size
        self._pool: List[hvac.Client] = []
        self._available: Set[hvac.Client] = set()
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        self._closed = False
        
        # Initialize pool
        self._initialize_pool()
    
    def _initialize_pool(self):
        """Initialize the connection pool."""
        for _ in range(self.pool_size):
            client = self._create_client()
            self._pool.append(client)
            self._available.add(client)
    
    def _create_client(self) -> hvac.Client:
        """Create a new Vault client."""
        client = hvac.Client(
            url=self.config.url,
            token=self.config.token,
            namespace=self.config.namespace,
            timeout=(self.config.connection_timeout, self.config.read_timeout),
            verify=self.config.tls_verify
        )
        
        # Configure TLS if certificates are provided
        if self.config.tls_ca_cert:
            client.session.verify = self.config.tls_ca_cert
        
        if self.config.tls_client_cert and self.config.tls_client_key:
            client.session.cert = (self.config.tls_client_cert, self.config.tls_client_key)
        
        # Verify authentication
        if not client.is_authenticated():
            raise SecurityError("Failed to authenticate with Vault")
        
        vault_active_connections.inc()
        return client
    
    @contextmanager
    def acquire(self):
        """Acquire a client from the pool."""
        if self._closed:
            raise RuntimeError("Connection pool is closed")
        
        client = None
        try:
            with self._condition:
                while not self._available:
                    self._condition.wait()
                
                client = self._available.pop()
            
            yield client
            
        finally:
            if client:
                with self._condition:
                    self._available.add(client)
                    self._condition.notify()
    
    def close(self):
        """Close all connections in the pool."""
        with self._lock:
            self._closed = True
            for client in self._pool:
                try:
                    # Revoke token if possible
                    if client.is_authenticated():
                        client.auth.token.revoke_self()
                except Exception as e:
                    logger.error(f"Error closing Vault client: {e}")
                finally:
                    vault_active_connections.dec()
            
            self._pool.clear()
            self._available.clear()


class EnhancedVaultClient:
    """Enhanced Vault client with advanced features."""
    
    def __init__(self, config: Optional[VaultConfig] = None):
        """Initialize the enhanced Vault client.
        
        Args:
            config: Vault configuration
        """
        self.config = config or VaultConfig()
        self._pool = VaultConnectionPool(self.config)
        self._cache = TTLCache(maxsize=self.config.cache_size, ttl=self.config.cache_ttl)
        self._permanent_cache = LRUCache(maxsize=100)  # For critical secrets
        self._rotation_tasks: Dict[str, asyncio.Task] = {}
        self._metrics_collector = MetricsCollector()
        
        # Start token renewal
        self._token_renewal_thread = threading.Thread(
            target=self._token_renewal_loop,
            daemon=True
        )
        self._token_renewal_thread.start()
        
        logger.info("Enhanced Vault client initialized")
    
    def _token_renewal_loop(self):
        """Background thread for token renewal."""
        while True:
            try:
                with self._pool.acquire() as client:
                    # Get token info
                    token_info = client.auth.token.lookup_self()
                    ttl = token_info['data'].get('ttl', 0)
                    
                    if ttl > 0 and ttl < 3600:  # Renew if less than 1 hour left
                        client.auth.token.renew_self()
                        logger.info("Vault token renewed successfully")
                
                time.sleep(1800)  # Check every 30 minutes
                
            except Exception as e:
                logger.error(f"Error in token renewal: {e}")
                time.sleep(60)  # Retry after 1 minute on error
    
    @backoff.on_exception(
        backoff.expo,
        (VaultError, ConnectionError),
        max_tries=3,
        max_time=30
    )
    def read_secret(
        self,
        path: str,
        version: Optional[int] = None,
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """Read a secret from Vault.
        
        Args:
            path: Secret path
            version: Specific version to read (None for latest)
            use_cache: Whether to use cache
            
        Returns:
            Secret data
        """
        cache_key = f"{path}:{version}" if version else path
        
        # Check cache first
        if use_cache and self.config.enable_cache:
            if cache_key in self._cache:
                vault_cache_hits.inc()
                return self._cache[cache_key]
            vault_cache_misses.inc()
        
        with vault_operation_duration.labels(operation='read').time():
            try:
                with self._pool.acquire() as client:
                    if self.config.kv_version == 2:
                        response = client.secrets.kv.v2.read_secret_version(
                            path=path,
                            version=version,
                            mount_point=self.config.mount_point
                        )
                        data = response['data']['data']
                        metadata = response['data']['metadata']
                    else:
                        response = client.secrets.kv.v1.read_secret(
                            path=path,
                            mount_point=self.config.mount_point
                        )
                        data = response['data']
                        metadata = {}
                    
                    # Cache the result
                    if use_cache and self.config.enable_cache:
                        self._cache[cache_key] = data
                    
                    vault_operations.labels(operation='read', status='success').inc()
                    
                    # Store metadata
                    self._store_metadata(path, metadata)
                    
                    return data
                    
            except Exception as e:
                vault_operations.labels(operation='read', status='failure').inc()
                logger.error(f"Failed to read secret {path}: {e}")
                raise
    
    @backoff.on_exception(
        backoff.expo,
        (VaultError, ConnectionError),
        max_tries=3,
        max_time=30
    )
    def write_secret(
        self,
        path: str,
        data: Dict[str, Any],
        cas: Optional[int] = None
    ) -> Dict[str, Any]:
        """Write a secret to Vault.
        
        Args:
            path: Secret path
            data: Secret data
            cas: Check-and-set version for atomic updates
            
        Returns:
            Write response with version info
        """
        with vault_operation_duration.labels(operation='write').time():
            try:
                with self._pool.acquire() as client:
                    if self.config.kv_version == 2:
                        response = client.secrets.kv.v2.create_or_update_secret(
                            path=path,
                            secret=data,
                            cas=cas,
                            mount_point=self.config.mount_point
                        )
                    else:
                        response = client.secrets.kv.v1.create_or_update_secret(
                            path=path,
                            secret=data,
                            mount_point=self.config.mount_point
                        )
                    
                    # Invalidate cache
                    self._invalidate_cache(path)
                    
                    vault_operations.labels(operation='write', status='success').inc()
                    
                    return response
                    
            except Exception as e:
                vault_operations.labels(operation='write', status='failure').inc()
                logger.error(f"Failed to write secret {path}: {e}")
                raise
    
    def delete_secret(self, path: str, versions: Optional[List[int]] = None) -> None:
        """Delete a secret from Vault.
        
        Args:
            path: Secret path
            versions: Specific versions to delete (None for all)
        """
        with vault_operation_duration.labels(operation='delete').time():
            try:
                with self._pool.acquire() as client:
                    if self.config.kv_version == 2:
                        if versions:
                            client.secrets.kv.v2.delete_secret_versions(
                                path=path,
                                versions=versions,
                                mount_point=self.config.mount_point
                            )
                        else:
                            client.secrets.kv.v2.delete_metadata_and_all_versions(
                                path=path,
                                mount_point=self.config.mount_point
                            )
                    else:
                        client.secrets.kv.v1.delete_secret(
                            path=path,
                            mount_point=self.config.mount_point
                        )
                    
                    # Invalidate cache
                    self._invalidate_cache(path)
                    
                    vault_operations.labels(operation='delete', status='success').inc()
                    
            except Exception as e:
                vault_operations.labels(operation='delete', status='failure').inc()
                logger.error(f"Failed to delete secret {path}: {e}")
                raise
    
    def list_secrets(self, path: str = "") -> List[str]:
        """List secrets at a given path.
        
        Args:
            path: Path to list
            
        Returns:
            List of secret names
        """
        try:
            with self._pool.acquire() as client:
                if self.config.kv_version == 2:
                    response = client.secrets.kv.v2.list_secrets(
                        path=path,
                        mount_point=self.config.mount_point
                    )
                else:
                    response = client.secrets.kv.v1.list_secrets(
                        path=path,
                        mount_point=self.config.mount_point
                    )
                
                return response.get('data', {}).get('keys', [])
                
        except Exception as e:
            logger.error(f"Failed to list secrets at {path}: {e}")
            return []
    
    async def rotate_secret(
        self,
        path: str,
        rotation_func: Callable[[Dict[str, Any]], Dict[str, Any]],
        pre_rotation_hook: Optional[Callable] = None,
        post_rotation_hook: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """Rotate a secret with custom rotation logic.
        
        Args:
            path: Secret path
            rotation_func: Function to generate new secret value
            pre_rotation_hook: Hook to call before rotation
            post_rotation_hook: Hook to call after rotation
            
        Returns:
            New secret data
        """
        try:
            # Pre-rotation hook
            if pre_rotation_hook:
                await pre_rotation_hook(path)
            
            # Read current secret
            current_data = self.read_secret(path)
            
            # Generate new secret
            new_data = rotation_func(current_data)
            
            # Add rotation metadata
            new_data['_rotated_at'] = datetime.utcnow().isoformat()
            new_data['_rotation_version'] = current_data.get('_rotation_version', 0) + 1
            
            # Write new secret
            self.write_secret(path, new_data)
            
            # Post-rotation hook
            if post_rotation_hook:
                await post_rotation_hook(path, new_data)
            
            vault_rotation_operations.labels(status='success').inc()
            logger.info(f"Successfully rotated secret: {path}")
            
            return new_data
            
        except Exception as e:
            vault_rotation_operations.labels(status='failure').inc()
            logger.error(f"Failed to rotate secret {path}: {e}")
            raise
    
    def enable_automatic_rotation(
        self,
        path: str,
        interval: timedelta,
        rotation_func: Callable[[Dict[str, Any]], Dict[str, Any]],
        pre_rotation_hook: Optional[Callable] = None,
        post_rotation_hook: Optional[Callable] = None
    ):
        """Enable automatic rotation for a secret.
        
        Args:
            path: Secret path
            interval: Rotation interval
            rotation_func: Function to generate new secret value
            pre_rotation_hook: Hook to call before rotation
            post_rotation_hook: Hook to call after rotation
        """
        async def rotation_task():
            while True:
                try:
                    await asyncio.sleep(interval.total_seconds())
                    await self.rotate_secret(
                        path,
                        rotation_func,
                        pre_rotation_hook,
                        post_rotation_hook
                    )
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Error in automatic rotation for {path}: {e}")
                    await asyncio.sleep(60)  # Retry after 1 minute on error
        
        # Cancel existing task if any
        if path in self._rotation_tasks:
            self._rotation_tasks[path].cancel()
        
        # Create new task
        loop = asyncio.get_event_loop()
        task = loop.create_task(rotation_task())
        self._rotation_tasks[path] = task
        
        logger.info(f"Enabled automatic rotation for {path} with interval {interval}")
    
    def disable_automatic_rotation(self, path: str):
        """Disable automatic rotation for a secret.
        
        Args:
            path: Secret path
        """
        if path in self._rotation_tasks:
            self._rotation_tasks[path].cancel()
            del self._rotation_tasks[path]
            logger.info(f"Disabled automatic rotation for {path}")
    
    def get_secret_metadata(self, path: str) -> Optional[SecretMetadata]:
        """Get metadata for a secret.
        
        Args:
            path: Secret path
            
        Returns:
            Secret metadata or None
        """
        try:
            with self._pool.acquire() as client:
                if self.config.kv_version == 2:
                    response = client.secrets.kv.v2.read_secret_metadata(
                        path=path,
                        mount_point=self.config.mount_point
                    )
                    
                    data = response['data']
                    return SecretMetadata(
                        path=path,
                        version=data['current_version'],
                        created_time=datetime.fromisoformat(data['created_time'].replace('Z', '+00:00')),
                        updated_time=datetime.fromisoformat(data['updated_time'].replace('Z', '+00:00')),
                        deletion_time=datetime.fromisoformat(data['deletion_time'].replace('Z', '+00:00'))
                        if data.get('deletion_time') else None,
                        destroyed=data.get('destroyed', False),
                        custom_metadata=data.get('custom_metadata', {})
                    )
                else:
                    # KV v1 doesn't have metadata
                    return None
                    
        except Exception as e:
            logger.error(f"Failed to get metadata for {path}: {e}")
            return None
    
    def _invalidate_cache(self, path: str):
        """Invalidate cache entries for a path."""
        keys_to_remove = [k for k in self._cache if k.startswith(path)]
        for key in keys_to_remove:
            del self._cache[key]
    
    def _store_metadata(self, path: str, metadata: Dict[str, Any]):
        """Store secret metadata for tracking."""
        # This could be extended to store in a database for compliance
        pass
    
    @asynccontextmanager
    async def batch_operation(self):
        """Context manager for batch operations."""
        # This could be extended to support transactions
        yield self
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on Vault connection.
        
        Returns:
            Health status
        """
        try:
            with self._pool.acquire() as client:
                # Check if authenticated
                is_auth = client.is_authenticated()
                
                # Get seal status
                seal_status = client.sys.read_seal_status()
                
                # Check leader status if HA is enabled
                leader_status = {}
                if self.config.enable_ha:
                    try:
                        leader_status = client.sys.read_leader_status()
                    except:
                        pass
                
                return {
                    'status': 'healthy' if is_auth and not seal_status['sealed'] else 'unhealthy',
                    'authenticated': is_auth,
                    'sealed': seal_status['sealed'],
                    'version': seal_status.get('version', 'unknown'),
                    'cluster_name': seal_status.get('cluster_name'),
                    'cluster_id': seal_status.get('cluster_id'),
                    'is_leader': leader_status.get('is_self', False),
                    'leader_address': leader_status.get('leader_address'),
                    'cache_stats': {
                        'size': len(self._cache),
                        'max_size': self.config.cache_size,
                        'ttl': self.config.cache_ttl
                    }
                }
                
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {
                'status': 'unhealthy',
                'error': str(e)
            }
    
    def close(self):
        """Close the Vault client and clean up resources."""
        # Cancel all rotation tasks
        for task in self._rotation_tasks.values():
            task.cancel()
        
        # Close connection pool
        self._pool.close()
        
        logger.info("Enhanced Vault client closed")


# Utility functions for common secret types

def generate_api_key(length: int = 32) -> str:
    """Generate a secure API key."""
    return secrets.token_urlsafe(length)


def generate_password(length: int = 24, special_chars: bool = True) -> str:
    """Generate a secure password."""
    import string
    
    alphabet = string.ascii_letters + string.digits
    if special_chars:
        alphabet += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def generate_database_credentials() -> Dict[str, str]:
    """Generate database credentials."""
    return {
        'username': f"user_{secrets.token_hex(4)}",
        'password': generate_password(32, special_chars=True)
    }


def generate_jwt_secret() -> str:
    """Generate a JWT signing secret."""
    return secrets.token_urlsafe(64)


def generate_encryption_key(bits: int = 256) -> str:
    """Generate an encryption key."""
    return secrets.token_hex(bits // 8)


# Rotation functions for different secret types

def rotate_api_key(current: Dict[str, Any]) -> Dict[str, Any]:
    """Rotate an API key."""
    new_data = current.copy()
    new_data['key'] = generate_api_key()
    new_data['old_key'] = current.get('key')  # Keep old key for grace period
    new_data['rotated_at'] = datetime.utcnow().isoformat()
    return new_data


def rotate_database_password(current: Dict[str, Any]) -> Dict[str, Any]:
    """Rotate database password."""
    new_data = current.copy()
    new_data['password'] = generate_password(32)
    new_data['old_password'] = current.get('password')
    new_data['username'] = current.get('username')  # Keep username
    new_data['rotated_at'] = datetime.utcnow().isoformat()
    return new_data


def rotate_jwt_secret(current: Dict[str, Any]) -> Dict[str, Any]:
    """Rotate JWT secret."""
    new_data = current.copy()
    new_data['secret'] = generate_jwt_secret()
    new_data['kid'] = secrets.token_urlsafe(8)  # Key ID for rotation
    new_data['old_secret'] = current.get('secret')
    new_data['old_kid'] = current.get('kid')
    new_data['rotated_at'] = datetime.utcnow().isoformat()
    return new_data