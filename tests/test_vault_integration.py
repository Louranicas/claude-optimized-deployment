#!/usr/bin/env python3
"""
Test HashiCorp Vault Integration

This script tests the complete Vault integration including:
- Connection and authentication
- Secret management
- Automatic rotation
- Caching and performance
- Error handling and fallback
"""

import os
import sys
import asyncio
import time
import json
from datetime import datetime, timedelta
from typing import Dict, Any
import pytest
import hvac

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.vault_client import EnhancedVaultClient, VaultConfig
from src.core.secrets_manager import SecretsManager, get_secrets_manager
from src.core.secret_rotation_manager import RotationManager
from src.core.secrets_audit import get_secret_audit_logger
from src.core.exceptions import VaultConnectionError, SecretNotFoundError


class TestVaultIntegration:
    """Test Vault integration functionality."""
    
    @pytest.fixture
    def vault_config(self):
        """Create test Vault configuration."""
        return VaultConfig(
            url=os.getenv("VAULT_ADDR", "http://localhost:8200"),
            token=os.getenv("VAULT_TOKEN", "dev-only-token"),
            enable_cache=True,
            cache_ttl=60
        )
    
    @pytest.fixture
    def enhanced_client(self, vault_config):
        """Create enhanced Vault client."""
        return EnhancedVaultClient(vault_config)
    
    @pytest.fixture
    def secrets_manager(self):
        """Create secrets manager."""
        return SecretsManager(
            vault_url=os.getenv("VAULT_ADDR", "http://localhost:8200"),
            vault_token=os.getenv("VAULT_TOKEN", "dev-only-token"),
            enable_cache=True,
            enable_fallback=True,
            enable_rotation=True,
            use_enhanced_client=True
        )
    
    def test_vault_connection(self, enhanced_client):
        """Test Vault connection and authentication."""
        # Test basic connectivity
        health = asyncio.run(enhanced_client.health_check())
        assert health['status'] == 'healthy'
        assert health['authenticated'] is True
        assert not health['sealed']
        
        print(f"✓ Vault connection successful: {health}")
    
    def test_secret_crud_operations(self, enhanced_client):
        """Test secret CRUD operations."""
        test_path = "test/integration/crud"
        test_data = {
            "username": "test_user",
            "password": "test_password",
            "api_key": "test_key_12345",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Create
        enhanced_client.write_secret(test_path, test_data)
        print(f"✓ Secret created at {test_path}")
        
        # Read
        read_data = enhanced_client.read_secret(test_path)
        assert read_data["username"] == test_data["username"]
        assert read_data["password"] == test_data["password"]
        print(f"✓ Secret read successfully")
        
        # Update
        test_data["password"] = "updated_password"
        enhanced_client.write_secret(test_path, test_data)
        
        updated_data = enhanced_client.read_secret(test_path)
        assert updated_data["password"] == "updated_password"
        print(f"✓ Secret updated successfully")
        
        # List
        secrets = enhanced_client.list_secrets("test/integration")
        assert "crud" in secrets or "crud/" in secrets
        print(f"✓ Secret listing successful: {secrets}")
        
        # Delete
        enhanced_client.delete_secret(test_path)
        print(f"✓ Secret deleted successfully")
    
    def test_secret_versioning(self, enhanced_client):
        """Test secret versioning capabilities."""
        test_path = "test/integration/versioning"
        
        # Create multiple versions
        versions = []
        for i in range(3):
            data = {"version": i + 1, "value": f"value_{i + 1}"}
            enhanced_client.write_secret(test_path, data)
            versions.append(data)
            time.sleep(0.1)  # Small delay between versions
        
        # Read latest version
        latest = enhanced_client.read_secret(test_path)
        assert latest["version"] == 3
        print(f"✓ Latest version read: {latest}")
        
        # Read specific version
        version_1 = enhanced_client.read_secret(test_path, version=1)
        assert version_1["version"] == 1
        print(f"✓ Version 1 read: {version_1}")
        
        # Get metadata
        metadata = enhanced_client.get_secret_metadata(test_path)
        assert metadata is not None
        assert metadata.version == 3
        print(f"✓ Metadata retrieved: versions={metadata.version}")
        
        # Clean up
        enhanced_client.delete_secret(test_path)
    
    def test_caching_performance(self, enhanced_client):
        """Test caching and performance."""
        test_path = "test/integration/cache"
        test_data = {"cached": True, "value": "test_cache"}
        
        # Write secret
        enhanced_client.write_secret(test_path, test_data)
        
        # First read (cache miss)
        start_time = time.time()
        data1 = enhanced_client.read_secret(test_path, use_cache=True)
        first_read_time = time.time() - start_time
        
        # Second read (cache hit)
        start_time = time.time()
        data2 = enhanced_client.read_secret(test_path, use_cache=True)
        second_read_time = time.time() - start_time
        
        assert data1 == data2
        assert second_read_time < first_read_time * 0.5  # Should be at least 2x faster
        
        print(f"✓ Cache performance: first={first_read_time:.4f}s, cached={second_read_time:.4f}s")
        
        # Test cache invalidation
        enhanced_client.write_secret(test_path, {"cached": False})
        data3 = enhanced_client.read_secret(test_path, use_cache=True)
        assert data3["cached"] is False
        print(f"✓ Cache invalidation successful")
        
        # Clean up
        enhanced_client.delete_secret(test_path)
    
    @pytest.mark.asyncio
    async def test_automatic_rotation(self, enhanced_client):
        """Test automatic secret rotation."""
        test_path = "test/integration/rotation"
        initial_data = {
            "api_key": "initial_key_12345",
            "created_at": datetime.utcnow().isoformat()
        }
        
        # Write initial secret
        enhanced_client.write_secret(test_path, initial_data)
        
        # Define rotation function
        def rotate_test_secret(current: Dict[str, Any]) -> Dict[str, Any]:
            new_data = current.copy()
            new_data["api_key"] = f"rotated_key_{int(time.time())}"
            new_data["rotated_at"] = datetime.utcnow().isoformat()
            new_data["old_key"] = current.get("api_key")
            return new_data
        
        # Test manual rotation
        rotated = await enhanced_client.rotate_secret(test_path, rotate_test_secret)
        assert rotated["api_key"] != initial_data["api_key"]
        assert rotated["old_key"] == initial_data["api_key"]
        print(f"✓ Manual rotation successful: {rotated['api_key']}")
        
        # Enable automatic rotation
        enhanced_client.enable_automatic_rotation(
            test_path,
            timedelta(seconds=5),  # Rotate every 5 seconds for testing
            rotate_test_secret
        )
        
        # Wait for automatic rotation
        await asyncio.sleep(6)
        
        # Check if rotated
        auto_rotated = enhanced_client.read_secret(test_path)
        assert auto_rotated["api_key"] != rotated["api_key"]
        print(f"✓ Automatic rotation successful: {auto_rotated['api_key']}")
        
        # Disable rotation
        enhanced_client.disable_automatic_rotation(test_path)
        
        # Clean up
        enhanced_client.delete_secret(test_path)
    
    def test_secrets_manager_integration(self, secrets_manager):
        """Test SecretsManager integration with Vault."""
        # Test get_secret with Vault
        test_path = "test/manager/integration"
        test_data = {"key": "test_value", "number": 42}
        
        # Set secret via manager
        secrets_manager.set_secret(test_path, test_data)
        print(f"✓ Secret set via SecretsManager")
        
        # Get full secret
        retrieved = secrets_manager.get_secret(test_path)
        assert retrieved["key"] == test_data["key"]
        assert retrieved["number"] == test_data["number"]
        print(f"✓ Full secret retrieved: {retrieved}")
        
        # Get specific key
        key_value = secrets_manager.get_secret(test_path, "key")
        assert key_value == "test_value"
        print(f"✓ Specific key retrieved: {key_value}")
        
        # Test fallback to environment
        os.environ["TEST_MANAGER_FALLBACK"] = "env_value"
        env_value = secrets_manager.get_secret("test/manager/fallback")
        assert env_value == "env_value"
        print(f"✓ Environment fallback successful")
        
        # Clean up
        secrets_manager.delete_secret(test_path)
        del os.environ["TEST_MANAGER_FALLBACK"]
    
    def test_error_handling_and_recovery(self, enhanced_client):
        """Test error handling and recovery mechanisms."""
        # Test reading non-existent secret
        with pytest.raises(Exception):
            enhanced_client.read_secret("test/non/existent")
        print(f"✓ Non-existent secret error handled")
        
        # Test invalid path
        with pytest.raises(Exception):
            enhanced_client.write_secret("", {"invalid": "path"})
        print(f"✓ Invalid path error handled")
        
        # Test connection recovery (simulate by using invalid token)
        original_token = enhanced_client.config.token
        enhanced_client.config.token = "invalid-token"
        
        try:
            enhanced_client.read_secret("test/any")
        except Exception as e:
            print(f"✓ Invalid token error caught: {type(e).__name__}")
        
        # Restore token
        enhanced_client.config.token = original_token
    
    def test_batch_operations(self, enhanced_client):
        """Test batch secret operations."""
        base_path = "test/batch"
        secrets = {
            f"{base_path}/secret1": {"value": "one"},
            f"{base_path}/secret2": {"value": "two"},
            f"{base_path}/secret3": {"value": "three"}
        }
        
        # Batch write
        start_time = time.time()
        for path, data in secrets.items():
            enhanced_client.write_secret(path, data)
        write_time = time.time() - start_time
        
        print(f"✓ Batch write completed in {write_time:.4f}s")
        
        # Batch read
        start_time = time.time()
        read_secrets = {}
        for path in secrets:
            read_secrets[path] = enhanced_client.read_secret(path)
        read_time = time.time() - start_time
        
        assert len(read_secrets) == len(secrets)
        print(f"✓ Batch read completed in {read_time:.4f}s")
        
        # Clean up
        for path in secrets:
            enhanced_client.delete_secret(path)
    
    @pytest.mark.asyncio
    async def test_rotation_manager(self, enhanced_client):
        """Test rotation manager functionality."""
        audit_logger = get_secret_audit_logger()
        rotation_manager = RotationManager(
            vault_client=enhanced_client,
            audit_logger=audit_logger
        )
        
        # Initialize rotation manager
        await rotation_manager.initialize()
        
        # Get rotation status
        status = await rotation_manager.get_rotation_status()
        print(f"✓ Rotation manager status: {status}")
        
        assert status["scheduler_running"] is True
    
    def test_compliance_features(self, enhanced_client):
        """Test compliance and audit features."""
        test_path = "test/compliance/audit"
        sensitive_data = {
            "credit_card": "****-****-****-1234",
            "ssn": "***-**-6789",
            "api_key": "sk_test_*****"
        }
        
        # Write sensitive data
        enhanced_client.write_secret(test_path, sensitive_data)
        
        # Verify data is stored
        retrieved = enhanced_client.read_secret(test_path)
        assert retrieved["credit_card"] == sensitive_data["credit_card"]
        
        # Test metadata tracking
        metadata = enhanced_client.get_secret_metadata(test_path)
        assert metadata is not None
        assert metadata.created_time is not None
        
        print(f"✓ Compliance features validated")
        
        # Clean up
        enhanced_client.delete_secret(test_path)


def run_integration_tests():
    """Run all integration tests."""
    print("🔐 HashiCorp Vault Integration Tests\n")
    
    # Check if Vault is available
    try:
        client = hvac.Client(
            url=os.getenv("VAULT_ADDR", "http://localhost:8200"),
            token=os.getenv("VAULT_TOKEN", "dev-only-token")
        )
        
        if not client.is_authenticated():
            print("❌ Vault is not authenticated. Please check your VAULT_TOKEN.")
            return False
        
        if client.sys.read_seal_status()['sealed']:
            print("❌ Vault is sealed. Please unseal it first.")
            return False
        
    except Exception as e:
        print(f"❌ Cannot connect to Vault: {e}")
        print("\nPlease ensure Vault is running:")
        print("  docker-compose -f docker-compose.vault.yml up -d")
        return False
    
    # Run tests
    test_suite = TestVaultIntegration()
    config = VaultConfig(
        url=os.getenv("VAULT_ADDR", "http://localhost:8200"),
        token=os.getenv("VAULT_TOKEN", "dev-only-token")
    )
    
    enhanced_client = EnhancedVaultClient(config)
    secrets_manager = SecretsManager()
    
    try:
        print("1. Testing Vault connection...")
        test_suite.test_vault_connection(enhanced_client)
        
        print("\n2. Testing secret CRUD operations...")
        test_suite.test_secret_crud_operations(enhanced_client)
        
        print("\n3. Testing secret versioning...")
        test_suite.test_secret_versioning(enhanced_client)
        
        print("\n4. Testing caching performance...")
        test_suite.test_caching_performance(enhanced_client)
        
        print("\n5. Testing automatic rotation...")
        asyncio.run(test_suite.test_automatic_rotation(enhanced_client))
        
        print("\n6. Testing SecretsManager integration...")
        test_suite.test_secrets_manager_integration(secrets_manager)
        
        print("\n7. Testing error handling...")
        test_suite.test_error_handling_and_recovery(enhanced_client)
        
        print("\n8. Testing batch operations...")
        test_suite.test_batch_operations(enhanced_client)
        
        print("\n9. Testing rotation manager...")
        asyncio.run(test_suite.test_rotation_manager(enhanced_client))
        
        print("\n10. Testing compliance features...")
        test_suite.test_compliance_features(enhanced_client)
        
        print("\n✅ All tests passed!")
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        # Clean up
        enhanced_client.close()


if __name__ == "__main__":
    success = run_integration_tests()
    sys.exit(0 if success else 1)