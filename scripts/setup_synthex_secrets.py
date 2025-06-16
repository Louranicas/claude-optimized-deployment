#!/usr/bin/env python3
"""
SYNTHEX Secret Setup Script
Helps configure API keys and secrets securely
"""

import sys
import os
import getpass
import argparse
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.synthex.secrets import init_secret_manager, SecretManager


def setup_secrets(backend: str = "env", encryption_key: str = None):
    """Interactive setup for SYNTHEX secrets"""
    
    print("SYNTHEX Secret Configuration")
    print("=" * 50)
    
    # Initialize secret manager
    if backend == "file" and not encryption_key:
        encryption_key = getpass.getpass("Enter encryption key for file backend: ")
    
    manager = init_secret_manager(backend=backend, encryption_key=encryption_key)
    
    print(f"\nUsing backend: {backend}")
    print("\nLet's configure your API keys and secrets...")
    print("(Press Enter to skip any secret you don't want to set)\n")
    
    # API Keys
    secrets_to_configure = [
        ("BRAVE_API_KEY", "Brave Search API Key", True),
        ("OPENAI_API_KEY", "OpenAI API Key", True),
        ("ANTHROPIC_API_KEY", "Anthropic API Key", True),
        ("GOOGLE_API_KEY", "Google API Key", True),
        ("PERPLEXITY_API_KEY", "Perplexity API Key", True),
        ("COHERE_API_KEY", "Cohere API Key", True),
        ("HUGGINGFACE_API_KEY", "HuggingFace API Key", True),
        ("SEARXNG_URL", "SearXNG Instance URL", False),
        ("DATABASE_URL", "Database Connection URL", True),
        ("DATABASE_USERNAME", "Database Username", False),
        ("DATABASE_PASSWORD", "Database Password", True),
        ("DATABASE_HOST", "Database Host", False),
        ("DATABASE_PORT", "Database Port", False),
        ("DATABASE_NAME", "Database Name", False),
        ("SYNTHEX_ENCRYPTION_KEY", "SYNTHEX Encryption Key", True),
    ]
    
    configured_count = 0
    
    for key, description, is_secret in secrets_to_configure:
        current_value = manager.get_secret(key)
        
        if current_value:
            if is_secret:
                display_value = "*" * 8 + current_value[-4:]
            else:
                display_value = current_value
            prompt = f"{description} (current: {display_value}): "
        else:
            prompt = f"{description}: "
        
        if is_secret:
            value = getpass.getpass(prompt)
        else:
            value = input(prompt)
        
        if value:
            manager.set_secret(key, value)
            configured_count += 1
            print(f"✓ {key} configured")
        elif current_value:
            print(f"✓ {key} unchanged")
        else:
            print(f"- {key} skipped")
    
    print(f"\n{configured_count} secrets configured successfully!")
    
    # Validate required secrets
    print("\nValidating configuration...")
    required_secrets = ["DATABASE_URL", "SYNTHEX_ENCRYPTION_KEY"]
    validation_results = manager.validate_required_secrets(required_secrets)
    
    all_valid = True
    for key, is_present in validation_results.items():
        if is_present:
            print(f"✓ {key} is configured")
        else:
            print(f"✗ {key} is missing (required)")
            all_valid = False
    
    if not all_valid:
        print("\n⚠️  Some required secrets are missing!")
        print("SYNTHEX may not function properly without them.")
    else:
        print("\n✅ All required secrets are configured!")
    
    # Save backend preference
    if backend != "env":
        env_file = Path.home() / ".synthex" / "config"
        env_file.parent.mkdir(parents=True, exist_ok=True)
        env_file.write_text(f"SYNTHEX_SECRET_BACKEND={backend}\n")
        print(f"\nBackend preference saved to: {env_file}")
    
    print("\nSetup complete! You can now use SYNTHEX securely.")


def main():
    parser = argparse.ArgumentParser(description="Configure SYNTHEX secrets")
    parser.add_argument(
        "--backend",
        choices=["env", "keyring", "file"],
        default="env",
        help="Secret storage backend (default: env)"
    )
    parser.add_argument(
        "--encryption-key",
        help="Encryption key for file backend (will prompt if not provided)"
    )
    
    args = parser.parse_args()
    
    try:
        setup_secrets(backend=args.backend, encryption_key=args.encryption_key)
    except KeyboardInterrupt:
        print("\n\nSetup cancelled.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()