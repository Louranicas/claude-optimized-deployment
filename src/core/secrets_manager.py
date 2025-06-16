"""
Secrets Manager with HashiCorp Vault Integration

This module provides a unified interface for managing secrets using HashiCorp Vault
with fallback to environment variables for development environments.
"""

import os
import json
import logging
from typing import Any, Dict, Optional, Union, List
from functools import lru_cache
from datetime import datetime, timedelta
from contextlib import contextmanager
import threading
from pathlib import Path

import hvac
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

from src.core.exceptions import ConfigurationError, SecurityError
from src.core.logging_config import get_logger
from src.core.vault_client import EnhancedVaultClient, VaultConfig
from src.core.secret_rotation_manager import RotationManager
from src.core.secrets_audit import get_secret_audit_logger, SecretOperation

logger = get_logger(__name__)


class VaultConnectionError(SecurityError):
    """Raised when unable to connect to Vault"""
    pass


class SecretNotFoundError(SecurityError):
    """Raised when a secret is not found"""
    pass


class SecretsManager:
    """
    Manages secrets using HashiCorp Vault with environment variable fallback.
    
    Features:
    - HashiCorp Vault integration
    - Environment variable fallback
    - Local caching with TTL
    - Encryption at rest for cached secrets
    - Thread-safe operations
    - Automatic token renewal
    """
    
    def __init__(
        self,
        vault_url: Optional[str] = None,
        vault_token: Optional[str] = None,
        vault_namespace: Optional[str] = None,
        mount_point: str = "secret",
        cache_ttl: int = 300,  # 5 minutes
        enable_cache: bool = True,
        enable_fallback: bool = True,
        enable_rotation: bool = True,
        use_enhanced_client: bool = True
    ):
        """
        Initialize the secrets manager.
        
        Args:
            vault_url: Vault server URL
            vault_token: Vault authentication token
            vault_namespace: Vault namespace (for Vault Enterprise)
            mount_point: Secret engine mount point
            cache_ttl: Cache time-to-live in seconds
            enable_cache: Enable local caching of secrets
            enable_fallback: Enable fallback to environment variables
        """
        self.vault_url = vault_url or os.getenv("VAULT_ADDR", "http://localhost:8200")
        self.vault_token = vault_token or os.getenv("VAULT_TOKEN")
        self.vault_namespace = vault_namespace or os.getenv("VAULT_NAMESPACE")
        self.mount_point = mount_point
        self.cache_ttl = cache_ttl
        self.enable_cache = enable_cache
        self.enable_fallback = enable_fallback
        self.enable_rotation = enable_rotation
        self.use_enhanced_client = use_enhanced_client
        
        self._client: Optional[hvac.Client] = None
        self._enhanced_client: Optional[EnhancedVaultClient] = None
        self._rotation_manager: Optional[RotationManager] = None
        self._audit_logger = get_secret_audit_logger()
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._cache_lock = threading.Lock()
        self._encryption_key = self._generate_encryption_key()
        
        # Initialize clients if credentials are available
        if self.vault_token:
            if self.use_enhanced_client:
                self._initialize_enhanced_client()
            else:
                self._initialize_vault_client()
    
    def _generate_encryption_key(self) -> bytes:
        """Generate encryption key for cache."""
        # Use machine-specific data for key derivation
        machine_id = f"{os.uname().nodename}-{os.getuid()}"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=machine_id.encode(),
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(b"cache-encryption-key"))
        return key
    
    def _initialize_vault_client(self) -> None:
        """Initialize the basic Vault client."""
        try:
            self._client = hvac.Client(
                url=self.vault_url,
                token=self.vault_token,
                namespace=self.vault_namespace
            )
            
            # Verify authentication
            if not self._client.is_authenticated():
                raise VaultConnectionError("Failed to authenticate with Vault")
            
            logger.info("Successfully connected to Vault")
            
            # Start token renewal thread
            self._start_token_renewal()
            
        except Exception as e:
            logger.error(f"Failed to initialize Vault client: {e}")
            if not self.enable_fallback:
                raise VaultConnectionError(f"Cannot connect to Vault: {e}")
            self._client = None
    
    def _initialize_enhanced_client(self) -> None:
        """Initialize the enhanced Vault client with rotation support."""
        try:
            # Create Vault config
            config = VaultConfig(
                url=self.vault_url,
                token=self.vault_token,
                namespace=self.vault_namespace,
                mount_point=self.mount_point,
                enable_cache=self.enable_cache,
                cache_ttl=self.cache_ttl
            )
            
            # Initialize enhanced client
            self._enhanced_client = EnhancedVaultClient(config)
            
            # Initialize rotation manager if enabled
            if self.enable_rotation:
                self._rotation_manager = RotationManager(
                    vault_client=self._enhanced_client,
                    audit_logger=self._audit_logger
                )
                
                # Start rotation manager asynchronously
                import asyncio
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.create_task(self._rotation_manager.initialize())
            
            logger.info("Successfully initialized enhanced Vault client")
            
        except Exception as e:
            logger.error(f"Failed to initialize enhanced Vault client: {e}")
            if not self.enable_fallback:
                raise VaultConnectionError(f"Cannot connect to Vault: {e}")
            self._enhanced_client = None
    
    def _start_token_renewal(self) -> None:
        """Start background thread for token renewal."""
        def renew_token():
            while self._client and self._client.is_authenticated():
                try:
                    self._client.auth.token.renew_self()
                    logger.debug("Vault token renewed successfully")
                    threading.Event().wait(3600)  # Renew every hour
                except Exception as e:
                    logger.error(f"Failed to renew Vault token: {e}")
                    break
        
        renewal_thread = threading.Thread(target=renew_token, daemon=True)
        renewal_thread.start()
    
    def _encrypt_value(self, value: str) -> str:
        """Encrypt a value for caching."""
        f = Fernet(self._encryption_key)
        return f.encrypt(value.encode()).decode()
    
    def _decrypt_value(self, encrypted_value: str) -> str:
        """Decrypt a cached value."""
        f = Fernet(self._encryption_key)
        return f.decrypt(encrypted_value.encode()).decode()
    
    def _get_from_cache(self, key: str) -> Optional[Any]:
        """Get a value from cache if valid."""
        if not self.enable_cache:
            return None
        
        with self._cache_lock:
            if key in self._cache:
                entry = self._cache[key]
                if datetime.now() < entry["expires"]:
                    decrypted = self._decrypt_value(entry["value"])
                    return json.loads(decrypted)
                else:
                    del self._cache[key]
        
        return None
    
    def _set_cache(self, key: str, value: Any) -> None:
        """Set a value in cache."""
        if not self.enable_cache:
            return
        
        with self._cache_lock:
            encrypted = self._encrypt_value(json.dumps(value))
            self._cache[key] = {
                "value": encrypted,
                "expires": datetime.now() + timedelta(seconds=self.cache_ttl)
            }
    
    def get_secret(self, path: str, key: Optional[str] = None) -> Union[str, Dict[str, Any]]:
        """
        Get a secret from Vault or environment variables.
        
        Args:
            path: Secret path in Vault or environment variable prefix
            key: Specific key within the secret (optional)
            
        Returns:
            Secret value (string or dict)
            
        Raises:
            SecretNotFoundError: If secret is not found
        """
        cache_key = f"{path}:{key}" if key else path
        
        # Check cache first
        cached_value = self._get_from_cache(cache_key)
        if cached_value is not None:
            return cached_value
        
        # Try enhanced client first if available
        if self._enhanced_client:
            try:
                # Note: Audit logging would be done asynchronously in production
                logger.debug(f"Accessing secret: {path}")
                
                data = self._enhanced_client.read_secret(path, use_cache=self.enable_cache)
                
                if key:
                    if key in data:
                        value = data[key]
                        self._set_cache(cache_key, value)
                        return value
                    else:
                        raise SecretNotFoundError(f"Key '{key}' not found in secret '{path}'")
                else:
                    self._set_cache(cache_key, data)
                    return data
                    
            except Exception as e:
                logger.debug(f"Enhanced client failed, trying basic client: {e}")
        
        # Try basic Vault client
        if self._client and self._client.is_authenticated():
            try:
                response = self._client.secrets.kv.v2.read_secret_version(
                    path=path,
                    mount_point=self.mount_point
                )
                
                if response and "data" in response:
                    data = response["data"]["data"]
                    
                    if key:
                        if key in data:
                            value = data[key]
                            self._set_cache(cache_key, value)
                            return value
                        else:
                            raise SecretNotFoundError(f"Key '{key}' not found in secret '{path}'")
                    else:
                        self._set_cache(cache_key, data)
                        return data
                        
            except hvac.exceptions.InvalidPath:
                logger.debug(f"Secret not found in Vault: {path}")
            except Exception as e:
                logger.error(f"Error reading from Vault: {e}")
        
        # Fallback to environment variables
        if self.enable_fallback:
            env_key = path.upper().replace("/", "_").replace("-", "_")
            if key:
                env_key = f"{env_key}_{key.upper()}"
            
            value = os.getenv(env_key)
            if value:
                # Try to parse JSON for complex values
                try:
                    parsed_value = json.loads(value)
                    self._set_cache(cache_key, parsed_value)
                    return parsed_value
                except json.JSONDecodeError:
                    self._set_cache(cache_key, value)
                    return value
        
        raise SecretNotFoundError(f"Secret not found: {path}")
    
    def set_secret(self, path: str, data: Dict[str, Any]) -> None:
        """
        Set a secret in Vault.
        
        Args:
            path: Secret path in Vault
            data: Secret data as a dictionary
            
        Raises:
            VaultConnectionError: If unable to connect to Vault
        """
        # Try enhanced client first
        if self._enhanced_client:
            try:
                # Note: Audit logging would be done asynchronously in production
                logger.debug(f"Setting secret: {path}")
                
                self._enhanced_client.write_secret(path, data)
                
                # Invalidate cache
                with self._cache_lock:
                    keys_to_remove = [k for k in self._cache if k.startswith(path)]
                    for k in keys_to_remove:
                        del self._cache[k]
                        
                logger.info(f"Secret created/updated: {path}")
                return
                
            except Exception as e:
                logger.debug(f"Enhanced client failed, trying basic client: {e}")
        
        # Fallback to basic client
        if not self._client or not self._client.is_authenticated():
            raise VaultConnectionError("Not connected to Vault")
        
        try:
            self._client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret=data,
                mount_point=self.mount_point
            )
            
            # Invalidate cache
            with self._cache_lock:
                keys_to_remove = [k for k in self._cache if k.startswith(path)]
                for k in keys_to_remove:
                    del self._cache[k]
                    
            logger.info(f"Secret created/updated: {path}")
            
        except Exception as e:
            logger.error(f"Failed to set secret: {e}")
            raise VaultConnectionError(f"Failed to set secret: {e}")
    
    def delete_secret(self, path: str) -> None:
        """
        Delete a secret from Vault.
        
        Args:
            path: Secret path in Vault
            
        Raises:
            VaultConnectionError: If unable to connect to Vault
        """
        if not self._client or not self._client.is_authenticated():
            raise VaultConnectionError("Not connected to Vault")
        
        try:
            self._client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=path,
                mount_point=self.mount_point
            )
            
            # Invalidate cache
            with self._cache_lock:
                keys_to_remove = [k for k in self._cache if k.startswith(path)]
                for k in keys_to_remove:
                    del self._cache[k]
                    
            logger.info(f"Secret deleted: {path}")
            
        except Exception as e:
            logger.error(f"Failed to delete secret: {e}")
            raise VaultConnectionError(f"Failed to delete secret: {e}")
    
    def list_secrets(self, path: str = "") -> List[str]:
        """
        List secrets at a given path.
        
        Args:
            path: Path to list (empty for root)
            
        Returns:
            List of secret names
        """
        if not self._client or not self._client.is_authenticated():
            return []
        
        try:
            response = self._client.secrets.kv.v2.list_secrets(
                path=path,
                mount_point=self.mount_point
            )
            
            if response and "data" in response and "keys" in response["data"]:
                return response["data"]["keys"]
                
        except Exception as e:
            logger.error(f"Failed to list secrets: {e}")
        
        return []
    
    @contextmanager
    def temporary_secret(self, path: str, data: Dict[str, Any], ttl: int = 3600):
        """
        Context manager for temporary secrets.
        
        Args:
            path: Secret path
            data: Secret data
            ttl: Time-to-live in seconds
        """
        # Create secret with TTL
        if self._client and self._client.is_authenticated():
            data["ttl"] = f"{ttl}s"
            
        self.set_secret(path, data)
        
        try:
            yield
        finally:
            # Clean up
            try:
                self.delete_secret(path)
            except Exception as e:
                logger.warning(f"Failed to clean up temporary secret: {e}")


# Global instance
_secrets_manager: Optional[SecretsManager] = None
_lock = threading.Lock()


def get_secrets_manager() -> SecretsManager:
    """Get or create the global secrets manager instance."""
    global _secrets_manager
    
    if _secrets_manager is None:
        with _lock:
            if _secrets_manager is None:
                _secrets_manager = SecretsManager()
    
    return _secrets_manager


def get_secret(path: str, key: Optional[str] = None) -> Union[str, Dict[str, Any]]:
    """Convenience function to get a secret."""
    return get_secrets_manager().get_secret(path, key)


def set_secret(path: str, data: Dict[str, Any]) -> None:
    """Convenience function to set a secret."""
    get_secrets_manager().set_secret(path, data)


@lru_cache(maxsize=128)
def get_database_url() -> str:
    """Get database URL from secrets."""
    try:
        return get_secret("database/connection", "url")
    except SecretNotFoundError:
        # Fallback to constructed URL
        host = get_secret("database/connection", "host")
        port = get_secret("database/connection", "port")
        user = get_secret("database/connection", "user")
        password = get_secret("database/connection", "password")
        name = get_secret("database/connection", "name")
        
        return f"postgresql://{user}:{password}@{host}:{port}/{name}"


@lru_cache(maxsize=128)
def get_api_key(service: str) -> str:
    """Get API key for a service."""
    return get_secret(f"api-keys/{service}", "key")


@lru_cache(maxsize=128)
def get_jwt_secret() -> str:
    """Get JWT secret key."""
    return get_secret("auth/jwt", "secret")


def clear_secret_cache() -> None:
    """Clear all cached secrets."""
    get_database_url.cache_clear()
    get_api_key.cache_clear()
    get_jwt_secret.cache_clear()
    
    manager = get_secrets_manager()
    with manager._cache_lock:
        manager._cache.clear()


async def enable_secret_rotation(path: str, interval: timedelta, rotation_func: Optional[Callable] = None) -> None:
    """Enable automatic rotation for a secret.
    
    Args:
        path: Secret path
        interval: Rotation interval
        rotation_func: Optional custom rotation function
    """
    manager = get_secrets_manager()
    
    if not manager._enhanced_client:
        raise ConfigurationError("Enhanced Vault client not initialized")
    
    if not manager.enable_rotation:
        raise ConfigurationError("Secret rotation is disabled")
    
    # Use default rotation function based on secret type if not provided
    if not rotation_func:
        from src.core.vault_client import (
            rotate_api_key, rotate_database_password,
            rotate_jwt_secret, detect_secret_type
        )
        
        secret_type = detect_secret_type(path)
        rotation_funcs = {
            'api_key': rotate_api_key,
            'database': rotate_database_password,
            'jwt': rotate_jwt_secret
        }
        
        rotation_func = rotation_funcs.get(secret_type, rotate_api_key)
    
    manager._enhanced_client.enable_automatic_rotation(
        path, interval, rotation_func
    )


async def get_rotation_status() -> Dict[str, Any]:
    """Get current secret rotation status.
    
    Returns:
        Rotation status summary
    """
    manager = get_secrets_manager()
    
    if not manager._rotation_manager:
        return {'error': 'Rotation manager not initialized'}
    
    return await manager._rotation_manager.get_rotation_status()


# Add access level enum
class SecretAccessLevel(Enum):
    """Security levels for secrets."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    CRITICAL = "critical"