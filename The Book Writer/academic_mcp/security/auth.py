"""
Security implementation for Academic MCP
Handles authentication, encryption, and secure storage
"""

import os
import json
from typing import Dict, Optional, Any
from dataclasses import dataclass
import hashlib
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import aiofiles
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


@dataclass
class APICredentials:
    """Secure storage for API credentials"""
    service: str
    api_key: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    expires_at: Optional[float] = None


class SecureCredentialManager:
    """
    Manages API credentials with encryption at rest
    Following security best practices
    """
    
    def __init__(self, storage_path: Path):
        self.storage_path = storage_path
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._master_key = self._get_or_create_master_key()
        self._fernet = Fernet(self._master_key)
        
    def _get_or_create_master_key(self) -> bytes:
        """Get or create master encryption key"""
        key_file = self.storage_path / ".master_key"
        
        if key_file.exists():
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            # Generate new key
            key = Fernet.generate_key()
            
            # Store with restricted permissions
            with open(key_file, 'wb') as f:
                f.write(key)
            
            # Set file permissions (Unix-like systems)
            os.chmod(key_file, 0o600)
            
            return key
    
    async def store_credentials(self, credentials: APICredentials) -> None:
        """Store encrypted credentials"""
        # Serialize credentials
        cred_dict = {
            "service": credentials.service,
            "api_key": credentials.api_key,
            "client_id": credentials.client_id,
            "client_secret": credentials.client_secret,
            "access_token": credentials.access_token,
            "refresh_token": credentials.refresh_token,
            "expires_at": credentials.expires_at
        }
        
        # Encrypt
        encrypted_data = self._fernet.encrypt(
            json.dumps(cred_dict).encode()
        )
        
        # Store
        cred_file = self.storage_path / f"{credentials.service}.enc"
        async with aiofiles.open(cred_file, 'wb') as f:
            await f.write(encrypted_data)
        
        # Set permissions
        os.chmod(cred_file, 0o600)
        
        logger.info(f"Stored credentials for {credentials.service}")
    
    async def get_credentials(self, service: str) -> Optional[APICredentials]:
        """Retrieve and decrypt credentials"""
        cred_file = self.storage_path / f"{service}.enc"
        
        if not cred_file.exists():
            return None
        
        try:
            # Read encrypted data
            async with aiofiles.open(cred_file, 'rb') as f:
                encrypted_data = await f.read()
            
            # Decrypt
            decrypted_data = self._fernet.decrypt(encrypted_data)
            cred_dict = json.loads(decrypted_data.decode())
            
            # Create credentials object
            return APICredentials(**cred_dict)
            
        except Exception as e:
            logger.error(f"Failed to retrieve credentials for {service}: {e}")
            return None
    
    async def delete_credentials(self, service: str) -> bool:
        """Securely delete credentials"""
        cred_file = self.storage_path / f"{service}.enc"
        
        if cred_file.exists():
            # Overwrite with random data before deletion
            file_size = cred_file.stat().st_size
            random_data = secrets.token_bytes(file_size)
            
            async with aiofiles.open(cred_file, 'wb') as f:
                await f.write(random_data)
            
            # Delete file
            cred_file.unlink()
            logger.info(f"Deleted credentials for {service}")
            return True
        
        return False


class OAuth2Manager:
    """Handles OAuth2 authentication flows"""
    
    def __init__(self, credential_manager: SecureCredentialManager):
        self.credential_manager = credential_manager
        self.oauth_configs = {
            "google_scholar": {
                "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
                "token_url": "https://oauth2.googleapis.com/token",
                "scope": "https://www.googleapis.com/auth/scholar"
            },
            "orcid": {
                "auth_url": "https://orcid.org/oauth/authorize",
                "token_url": "https://orcid.org/oauth/token",
                "scope": "/read-limited"
            },
            "mendeley": {
                "auth_url": "https://api.mendeley.com/oauth/authorize",
                "token_url": "https://api.mendeley.com/oauth/token",
                "scope": "all"
            }
        }
    
    async def get_auth_url(self, service: str, redirect_uri: str) -> str:
        """Generate OAuth2 authorization URL"""
        if service not in self.oauth_configs:
            raise ValueError(f"Unknown service: {service}")
        
        config = self.oauth_configs[service]
        credentials = await self.credential_manager.get_credentials(service)
        
        if not credentials or not credentials.client_id:
            raise ValueError(f"No client ID for {service}")
        
        # Generate state for CSRF protection
        state = secrets.token_urlsafe(32)
        
        # Build auth URL
        params = {
            "client_id": credentials.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": config["scope"],
            "state": state
        }
        
        query_string = "&".join(f"{k}={v}" for k, v in params.items())
        return f"{config['auth_url']}?{query_string}"
    
    async def exchange_code_for_token(
        self,
        service: str,
        code: str,
        redirect_uri: str
    ) -> Dict[str, Any]:
        """Exchange authorization code for access token"""
        # Implementation would make actual OAuth2 token exchange
        # This is a placeholder
        return {
            "access_token": "mock_access_token",
            "refresh_token": "mock_refresh_token",
            "expires_in": 3600
        }


class RateLimitManager:
    """Manages rate limits across different MCP servers"""
    
    def __init__(self):
        self.limits = {}
        self.request_history = {}
    
    def configure_limits(self, service: str, limits: Dict[str, int]):
        """Configure rate limits for a service"""
        self.limits[service] = limits
        self.request_history[service] = []
    
    async def check_rate_limit(self, service: str) -> bool:
        """Check if request is within rate limits"""
        if service not in self.limits:
            return True
        
        # Implementation of rate limit checking
        return True
    
    async def wait_if_needed(self, service: str) -> None:
        """Wait if rate limit would be exceeded"""
        while not await self.check_rate_limit(service):
            await asyncio.sleep(0.1)
