"""Audit logging configuration.

This module provides secure configuration for the audit logging system,
including signing key management and environment-based configuration.
"""

import os
import secrets
from typing import Optional
from pathlib import Path

__all__ = [
    "AuditConfig",
    "get_audit_logger",
    "setup_audit_signing_key"
]



class AuditConfig:
    """Configuration for audit logging system."""
    
    def __init__(self):
        """Initialize audit configuration."""
        self._signing_key: Optional[str] = None
        self._storage_backend = None
        self._buffer_size = 100
        self._flush_interval = 5
        
    @property
    def signing_key(self) -> str:
        """Get the audit log signing key.
        
        The signing key is used to create HMAC signatures for audit events
        to ensure tamper detection. In production, this should be loaded
        from a secure source like environment variables or a secrets manager.
        
        Returns:
            str: The signing key for audit log integrity
            
        Raises:
            ValueError: If no secure signing key is configured
        """
        if not self._signing_key:
            # Try to load from environment
            key = os.environ.get('AUDIT_SIGNING_KEY')
            
            if not key:
                # Try to load from file (for development)
                key_file = Path.home() / '.claude_deployment' / 'audit_signing_key'
                if key_file.exists():
                    key = key_file.read_text().strip()
            
            if not key:
                raise ValueError(
                    "No audit signing key configured. Set AUDIT_SIGNING_KEY environment variable "
                    "or create ~/.claude_deployment/audit_signing_key file"
                )
            
            # Validate key security
            if len(key) < 32:
                raise ValueError("Audit signing key must be at least 32 characters")
            
            self._signing_key = key
            
        return self._signing_key
    
    @signing_key.setter
    def signing_key(self, value: str) -> None:
        """Set the signing key (for testing only)."""
        if len(value) < 32:
            raise ValueError("Signing key must be at least 32 characters")
        self._signing_key = value
    
    def generate_signing_key(self) -> str:
        """Generate a secure random signing key.
        
        This should be used to generate initial keys that are then
        stored securely and loaded through environment variables.
        
        Returns:
            str: A cryptographically secure random key
        """
        return secrets.token_urlsafe(64)
    
    @property
    def storage_backend(self):
        """Get the configured storage backend."""
        return self._storage_backend
    
    @storage_backend.setter
    def storage_backend(self, backend) -> None:
        """Set the storage backend."""
        self._storage_backend = backend
    
    @property
    def buffer_size(self) -> int:
        """Get the audit buffer size."""
        return int(os.environ.get('AUDIT_BUFFER_SIZE', self._buffer_size))
    
    @property
    def flush_interval(self) -> int:
        """Get the audit flush interval in seconds."""
        return int(os.environ.get('AUDIT_FLUSH_INTERVAL', self._flush_interval))


# Global configuration instance
audit_config = AuditConfig()


def get_audit_logger():
    """Factory function to create properly configured AuditLogger.
    
    This ensures all AuditLogger instances use the same secure configuration.
    
    Returns:
        AuditLogger: Configured audit logger instance
    """
    from .audit import AuditLogger
    
    return AuditLogger(
        storage_backend=audit_config.storage_backend,
        signing_key=audit_config.signing_key
    )


def setup_audit_signing_key():
    """Interactive setup for audit signing key.
    
    This function helps set up the audit signing key for development
    or initial deployment.
    """
    print("Setting up audit signing key...")
    print("=" * 50)
    
    # Check if key already exists
    key_file = Path.home() / '.claude_deployment' / 'audit_signing_key'
    
    if key_file.exists():
        print(f"Signing key already exists at: {key_file}")
        response = input("Generate new key? (y/N): ").lower()
        if response != 'y':
            print("Using existing key.")
            return
    
    # Generate new key
    new_key = audit_config.generate_signing_key()
    
    # Create directory if needed
    key_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Save key
    key_file.write_text(new_key)
    key_file.chmod(0o600)  # Restrict permissions
    
    print(f"New signing key generated and saved to: {key_file}")
    print("For production use, set the AUDIT_SIGNING_KEY environment variable:")
    print(f"export AUDIT_SIGNING_KEY='{new_key}'")
    print("\nNever commit this key to version control!")


if __name__ == "__main__":
    # If run directly, set up signing key
    setup_audit_signing_key()