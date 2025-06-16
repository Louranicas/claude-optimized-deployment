#!/usr/bin/env python3
"""
Setup script for audit signing key configuration.

This script helps configure the audit signing key for the Claude Optimized Deployment
authentication system.
"""

import os
import sys
import secrets
from pathlib import Path


def main():
    """Main setup function."""
    print("🔐 Claude Optimized Deployment - Audit Key Setup")
    print("=" * 50)
    
    # Check if running in production
    if os.environ.get('PRODUCTION') == 'true':
        print("\n⚠️  Production Environment Detected!")
        print("In production, you should set the AUDIT_SIGNING_KEY environment variable")
        print("with a securely generated key from your secrets management system.")
        print("\nExample:")
        print("export AUDIT_SIGNING_KEY='your-secure-key-here'")
        return
    
    # Check existing configuration
    env_key = os.environ.get('AUDIT_SIGNING_KEY')
    key_file = Path.home() / '.claude_deployment' / 'audit_signing_key'
    
    if env_key:
        print("\n✅ Audit signing key already configured via environment variable")
        print(f"   Key length: {len(env_key)} characters")
        if len(env_key) < 32:
            print("   ⚠️  Warning: Key should be at least 32 characters for security")
        return
    
    if key_file.exists():
        print(f"\n✅ Audit signing key already configured in: {key_file}")
        response = input("\nGenerate new key? (y/N): ").lower()
        if response != 'y':
            print("Using existing key.")
            return
    
    # Generate new key
    print("\n🔑 Generating new audit signing key...")
    new_key = secrets.token_urlsafe(64)
    
    # Create directory if needed
    key_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Save key
    key_file.write_text(new_key)
    key_file.chmod(0o600)  # Restrict permissions
    
    print(f"\n✅ New signing key generated and saved to: {key_file}")
    print("\n📋 For production deployment, add this to your environment:")
    print(f"\nexport AUDIT_SIGNING_KEY='{new_key}'")
    print("\n⚠️  Security Notes:")
    print("- Never commit this key to version control")
    print("- Store production keys in a secure secrets management system")
    print("- Rotate keys regularly according to your security policy")
    print("- The key file has been restricted to owner-only access (600)")
    
    # Test the configuration
    print("\n🧪 Testing configuration...")
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
        from src.auth.audit_config import get_audit_logger
        
        logger = get_audit_logger()
        print("✅ Audit logger initialized successfully!")
        
    except Exception as e:
        print(f"❌ Error testing configuration: {e}")
        print("\nPlease ensure you're running this from the project root directory")


if __name__ == "__main__":
    main()