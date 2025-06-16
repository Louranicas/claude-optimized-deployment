"""
Test suite for the secrets manager functionality.
"""

import os
import pytest
import asyncio
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta

from src.core.secrets_manager import (
    SecretsManager,
    get_secrets_manager,
    get_secret,
    set_secret,
    get_database_url,
    get_api_key,
    get_jwt_secret,
    clear_secret_cache,
    VaultConnectionError,
    SecretNotFoundError
)


class TestSecretsManager:
    """Test the SecretsManager class."""
    
    @pytest.fixture
    def mock_hvac_client(self):
        """Create a mock HVAC client."""
        client = Mock()
        client.is_authenticated.return_value = True
        client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {
                "data": {
                    "key": "test-value",
                    "nested": {"subkey": "subvalue"}
                }
            }
        }
        return client
    
    @pytest.fixture
    def secrets_manager(self, mock_hvac_client):
        """Create a SecretsManager instance with mocked Vault client."""
        with patch('src.core.secrets_manager.hvac.Client', return_value=mock_hvac_client):
            manager = SecretsManager(
                vault_url="http://test:8200",
                vault_token="test-token",
                cache_ttl=60,
                enable_cache=True,
                enable_fallback=True
            )
            manager._client = mock_hvac_client
            return manager
    
    def test_initialization(self):
        """Test SecretsManager initialization."""
        # Test with environment variables
        with patch.dict(os.environ, {
            "VAULT_ADDR": "http://env-vault:8200",
            "VAULT_TOKEN": "env-token"
        }):
            manager = SecretsManager()
            assert manager.vault_url == "http://env-vault:8200"
            assert manager.vault_token == "env-token"
    
    def test_get_secret_from_vault(self, secrets_manager, mock_hvac_client):
        """Test getting a secret from Vault."""
        # Test getting a specific key
        result = secrets_manager.get_secret("test/path", "key")
        assert result == "test-value"
        
        # Test getting all data
        result = secrets_manager.get_secret("test/path")
        assert result == {"key": "test-value", "nested": {"subkey": "subvalue"}}
        
        # Verify Vault was called
        mock_hvac_client.secrets.kv.v2.read_secret_version.assert_called_with(
            path="test/path",
            mount_point="secret"
        )
    
    def test_get_secret_with_cache(self, secrets_manager, mock_hvac_client):
        """Test secret caching functionality."""
        # First call should hit Vault
        result1 = secrets_manager.get_secret("cached/path", "key")
        assert mock_hvac_client.secrets.kv.v2.read_secret_version.call_count == 1
        
        # Second call should use cache
        result2 = secrets_manager.get_secret("cached/path", "key")
        assert mock_hvac_client.secrets.kv.v2.read_secret_version.call_count == 1
        assert result1 == result2
    
    def test_get_secret_fallback_to_env(self, secrets_manager):
        """Test fallback to environment variables."""
        # Mock Vault failure
        secrets_manager._client.is_authenticated.return_value = False
        
        # Set environment variable
        with patch.dict(os.environ, {"TEST_PATH_KEY": "env-value"}):
            result = secrets_manager.get_secret("test/path", "key")
            assert result == "env-value"
    
    def test_get_secret_not_found(self, secrets_manager, mock_hvac_client):
        """Test secret not found error."""
        # Mock Vault returning empty
        mock_hvac_client.secrets.kv.v2.read_secret_version.side_effect = Exception("Not found")
        
        with pytest.raises(SecretNotFoundError):
            secrets_manager.get_secret("nonexistent/path", "key")
    
    def test_set_secret(self, secrets_manager, mock_hvac_client):
        """Test setting a secret in Vault."""
        data = {"key1": "value1", "key2": "value2"}
        secrets_manager.set_secret("new/path", data)
        
        mock_hvac_client.secrets.kv.v2.create_or_update_secret.assert_called_once_with(
            path="new/path",
            secret=data,
            mount_point="secret"
        )
    
    def test_delete_secret(self, secrets_manager, mock_hvac_client):
        """Test deleting a secret from Vault."""
        secrets_manager.delete_secret("delete/path")
        
        mock_hvac_client.secrets.kv.v2.delete_metadata_and_all_versions.assert_called_once_with(
            path="delete/path",
            mount_point="secret"
        )
    
    def test_list_secrets(self, secrets_manager, mock_hvac_client):
        """Test listing secrets."""
        mock_hvac_client.secrets.kv.v2.list_secrets.return_value = {
            "data": {"keys": ["secret1/", "secret2/", "file.txt"]}
        }
        
        result = secrets_manager.list_secrets("test/")
        assert result == ["secret1/", "secret2/", "file.txt"]
    
    def test_cache_encryption(self, secrets_manager):
        """Test that cached values are encrypted."""
        # Set a value in cache
        test_value = {"sensitive": "data"}
        secrets_manager._set_cache("test/key", test_value)
        
        # Check that the cached value is encrypted
        cached_entry = secrets_manager._cache.get("test/key")
        assert cached_entry is not None
        assert cached_entry["value"] != str(test_value)  # Should be encrypted
        
        # Verify we can decrypt it
        decrypted = secrets_manager._get_from_cache("test/key")
        assert decrypted == test_value
    
    def test_cache_expiration(self, secrets_manager):
        """Test cache expiration."""
        # Set cache TTL to 1 second for testing
        secrets_manager.cache_ttl = 1
        
        # Set a value
        secrets_manager._set_cache("expiring/key", "value")
        
        # Should be in cache
        assert secrets_manager._get_from_cache("expiring/key") == "value"
        
        # Wait for expiration
        import time
        time.sleep(2)
        
        # Should be expired
        assert secrets_manager._get_from_cache("expiring/key") is None
    
    @pytest.mark.asyncio
    async def test_temporary_secret(self, secrets_manager, mock_hvac_client):
        """Test temporary secret context manager."""
        temp_data = {"temp": "secret"}
        
        with secrets_manager.temporary_secret("temp/path", temp_data, ttl=60):
            # Verify secret was created
            mock_hvac_client.secrets.kv.v2.create_or_update_secret.assert_called()
        
        # Verify secret was deleted
        mock_hvac_client.secrets.kv.v2.delete_metadata_and_all_versions.assert_called_with(
            path="temp/path",
            mount_point="secret"
        )


class TestConvenienceFunctions:
    """Test the convenience functions."""
    
    def test_get_database_url(self):
        """Test get_database_url function."""
        with patch('src.core.secrets_manager.get_secret') as mock_get:
            # Test direct URL
            mock_get.return_value = "postgresql://user:pass@host:5432/db"
            url = get_database_url()
            assert url == "postgresql://user:pass@host:5432/db"
            
            # Test constructed URL
            mock_get.side_effect = [
                SecretNotFoundError("Not found"),
                "localhost",
                "5432",
                "user",
                "password",
                "database"
            ]
            url = get_database_url()
            assert url == "postgresql://user:password@localhost:5432/database"
    
    def test_get_api_key(self):
        """Test get_api_key function."""
        with patch('src.core.secrets_manager.get_secret') as mock_get:
            mock_get.return_value = "test-api-key"
            
            key = get_api_key("openai")
            assert key == "test-api-key"
            mock_get.assert_called_with("api-keys/openai", "key")
    
    def test_get_jwt_secret(self):
        """Test get_jwt_secret function."""
        with patch('src.core.secrets_manager.get_secret') as mock_get:
            mock_get.return_value = "jwt-secret-key"
            
            secret = get_jwt_secret()
            assert secret == "jwt-secret-key"
            mock_get.assert_called_with("auth/jwt", "secret")
    
    def test_clear_secret_cache(self):
        """Test clear_secret_cache function."""
        # Mock the cache clear methods
        with patch('src.core.secrets_manager.get_database_url.cache_clear') as mock_db_clear:
            with patch('src.core.secrets_manager.get_api_key.cache_clear') as mock_api_clear:
                with patch('src.core.secrets_manager.get_jwt_secret.cache_clear') as mock_jwt_clear:
                    with patch('src.core.secrets_manager.get_secrets_manager') as mock_get_manager:
                        mock_manager = Mock()
                        mock_manager._cache = {"test": "value"}
                        mock_manager._cache_lock = MagicMock()
                        mock_get_manager.return_value = mock_manager
                        
                        clear_secret_cache()
                        
                        # Verify all caches were cleared
                        mock_db_clear.assert_called_once()
                        mock_api_clear.assert_called_once()
                        mock_jwt_clear.assert_called_once()
                        assert mock_manager._cache == {}


class TestIntegration:
    """Integration tests with real Vault (requires Vault to be running)."""
    
    @pytest.mark.integration
    @pytest.mark.skipif(
        not os.getenv("VAULT_ADDR") or not os.getenv("VAULT_TOKEN"),
        reason="Vault not configured"
    )
    def test_real_vault_operations(self):
        """Test real Vault operations."""
        manager = SecretsManager()
        
        # Test data
        test_path = "test/integration"
        test_data = {
            "key1": "value1",
            "key2": "value2",
            "nested": {"subkey": "subvalue"}
        }
        
        try:
            # Set secret
            manager.set_secret(test_path, test_data)
            
            # Get secret
            retrieved = manager.get_secret(test_path)
            assert retrieved == test_data
            
            # Get specific key
            value = manager.get_secret(test_path, "key1")
            assert value == "value1"
            
            # List secrets
            secrets = manager.list_secrets("test/")
            assert any("integration" in s for s in secrets)
            
        finally:
            # Cleanup
            try:
                manager.delete_secret(test_path)
            except:
                pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])