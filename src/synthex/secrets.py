"""
SYNTHEX Secret Manager
Secure handling of sensitive configuration and API keys
"""

import os
import logging
import json
from typing import Dict, Any, Optional
from pathlib import Path
try:
    import keyring
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

logger = logging.getLogger(__name__)


class SecretManager:
    """
    Manages secrets and sensitive configuration
    
    Supports multiple backends:
    - Environment variables (default)
    - System keyring
    - Encrypted file storage
    """
    
    def __init__(self, backend: str = "env", encryption_key: Optional[str] = None):
        """
        Initialize secret manager
        
        Args:
            backend: Storage backend ('env', 'keyring', 'file')
            encryption_key: Encryption key for file backend
        """
        self.backend = backend
        self._cache: Dict[str, Any] = {}
        
        # Check backend availability
        if backend == "keyring" and not KEYRING_AVAILABLE:
            logger.warning("Keyring backend requested but not available, falling back to env")
            self.backend = "env"
        
        if backend == "file":
            if not CRYPTOGRAPHY_AVAILABLE:
                logger.warning("Cryptography library not available, falling back to env backend")
                self.backend = "env"
            else:
                if not encryption_key:
                    # Try to get from environment
                    encryption_key = os.getenv("SYNTHEX_ENCRYPTION_KEY")
                    if not encryption_key:
                        raise ValueError("Encryption key required for file backend")
                
                # Derive encryption key from password
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=b'synthex-salt-v1',  # Should be random in production
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(encryption_key.encode()))
                self._cipher = Fernet(key)
            
            # Ensure secrets directory exists
            self._secrets_path = Path.home() / ".synthex" / "secrets"
            self._secrets_path.mkdir(parents=True, exist_ok=True)
            self._secrets_file = self._secrets_path / "secrets.enc"
    
    def get_secret(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """
        Get a secret value
        
        Args:
            key: Secret key
            default: Default value if not found
            
        Returns:
            Secret value or default
        """
        # Check cache first
        if key in self._cache:
            return self._cache[key]
        
        value = None
        
        if self.backend == "env":
            value = os.getenv(key, default)
        
        elif self.backend == "keyring":
            if not KEYRING_AVAILABLE:
                logger.warning("Keyring not available, falling back to environment")
                value = os.getenv(key, default)
            else:
                try:
                    value = keyring.get_password("synthex", key)
                    if not value:
                        value = default
                except Exception as e:
                    logger.error(f"Failed to get secret from keyring: {e}")
                    value = default
        
        elif self.backend == "file":
            value = self._get_from_file(key, default)
        
        # Cache the value
        if value is not None:
            self._cache[key] = value
        
        return value
    
    def set_secret(self, key: str, value: str) -> None:
        """
        Set a secret value
        
        Args:
            key: Secret key
            value: Secret value
        """
        if self.backend == "env":
            os.environ[key] = value
        
        elif self.backend == "keyring":
            if not KEYRING_AVAILABLE:
                logger.warning("Keyring not available, setting in environment")
                os.environ[key] = value
            else:
                try:
                    keyring.set_password("synthex", key, value)
                except Exception as e:
                    logger.error(f"Failed to set secret in keyring: {e}")
                    raise
        
        elif self.backend == "file":
            self._set_in_file(key, value)
        
        # Update cache
        self._cache[key] = value
    
    def _get_from_file(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get secret from encrypted file"""
        if not self._secrets_file.exists():
            return default
        
        try:
            # Read and decrypt file
            encrypted_data = self._secrets_file.read_bytes()
            decrypted_data = self._cipher.decrypt(encrypted_data)
            secrets = json.loads(decrypted_data.decode())
            
            return secrets.get(key, default)
        
        except Exception as e:
            logger.error(f"Failed to read secret from file: {e}")
            return default
    
    def _set_in_file(self, key: str, value: str) -> None:
        """Set secret in encrypted file"""
        # Read existing secrets
        secrets = {}
        if self._secrets_file.exists():
            try:
                encrypted_data = self._secrets_file.read_bytes()
                decrypted_data = self._cipher.decrypt(encrypted_data)
                secrets = json.loads(decrypted_data.decode())
            except Exception as e:
                logger.warning(f"Failed to read existing secrets: {e}")
        
        # Update secret
        secrets[key] = value
        
        # Encrypt and write
        encrypted_data = self._cipher.encrypt(json.dumps(secrets).encode())
        self._secrets_file.write_bytes(encrypted_data)
        
        # Set restrictive permissions
        self._secrets_file.chmod(0o600)
    
    def get_api_keys(self) -> Dict[str, Optional[str]]:
        """
        Get all API keys for SYNTHEX
        
        Returns:
            Dictionary of API keys
        """
        return {
            'brave_api_key': self.get_secret('BRAVE_API_KEY'),
            'openai_api_key': self.get_secret('OPENAI_API_KEY'),
            'anthropic_api_key': self.get_secret('ANTHROPIC_API_KEY'),
            'google_api_key': self.get_secret('GOOGLE_API_KEY'),
            'perplexity_api_key': self.get_secret('PERPLEXITY_API_KEY'),
            'cohere_api_key': self.get_secret('COHERE_API_KEY'),
            'huggingface_api_key': self.get_secret('HUGGINGFACE_API_KEY'),
        }
    
    def get_database_config(self) -> Dict[str, Optional[str]]:
        """
        Get database configuration
        
        Returns:
            Database configuration dict
        """
        return {
            'url': self.get_secret('DATABASE_URL'),
            'username': self.get_secret('DATABASE_USERNAME'),
            'password': self.get_secret('DATABASE_PASSWORD'),
            'host': self.get_secret('DATABASE_HOST', 'localhost'),
            'port': self.get_secret('DATABASE_PORT', '5432'),
            'name': self.get_secret('DATABASE_NAME', 'synthex'),
        }
    
    def validate_required_secrets(self, required: list) -> Dict[str, bool]:
        """
        Validate that required secrets are present
        
        Args:
            required: List of required secret keys
            
        Returns:
            Dictionary of key: is_present mappings
        """
        results = {}
        for key in required:
            value = self.get_secret(key)
            results[key] = value is not None and value != ""
        
        return results


# Global secret manager instance
_secret_manager: Optional[SecretManager] = None


def get_secret_manager() -> SecretManager:
    """
    Get the global secret manager instance
    
    Returns:
        SecretManager instance
    """
    global _secret_manager
    
    if _secret_manager is None:
        # Initialize from environment
        backend = os.getenv('SYNTHEX_SECRET_BACKEND', 'env')
        _secret_manager = SecretManager(backend=backend)
    
    return _secret_manager


def init_secret_manager(backend: str = "env", encryption_key: Optional[str] = None) -> SecretManager:
    """
    Initialize the global secret manager
    
    Args:
        backend: Storage backend
        encryption_key: Encryption key for file backend
        
    Returns:
        SecretManager instance
    """
    global _secret_manager
    _secret_manager = SecretManager(backend=backend, encryption_key=encryption_key)
    return _secret_manager


# Convenience functions
def get_secret(key: str, default: Optional[str] = None) -> Optional[str]:
    """Get a secret value"""
    return get_secret_manager().get_secret(key, default)


def set_secret(key: str, value: str) -> None:
    """Set a secret value"""
    get_secret_manager().set_secret(key, value)


def get_api_keys() -> Dict[str, Optional[str]]:
    """Get all API keys"""
    return get_secret_manager().get_api_keys()


def get_database_config() -> Dict[str, Optional[str]]:
    """Get database configuration"""
    return get_secret_manager().get_database_config()


# Export public interface
__all__ = [
    'SecretManager',
    'get_secret_manager',
    'init_secret_manager',
    'get_secret',
    'set_secret',
    'get_api_keys',
    'get_database_config',
]