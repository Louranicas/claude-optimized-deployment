#!/usr/bin/env python3
"""
Migrate environment variables to HashiCorp Vault.

This script helps migrate existing environment variables and secrets
to HashiCorp Vault for centralized secret management.
"""

import os
import sys
import json
import argparse
import getpass
from typing import Dict, Any, List, Optional
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.secrets_manager import SecretsManager, VaultConnectionError
from src.core.logging_config import get_logger

logger = get_logger(__name__)


class SecretsMigrator:
    """Handles migration of secrets to Vault."""
    
    def __init__(self, vault_url: str, vault_token: str, dry_run: bool = False):
        """
        Initialize the migrator.
        
        Args:
            vault_url: Vault server URL
            vault_token: Vault authentication token
            dry_run: If True, only show what would be migrated
        """
        self.dry_run = dry_run
        self.secrets_manager = SecretsManager(
            vault_url=vault_url,
            vault_token=vault_token,
            enable_fallback=False  # Don't fallback during migration
        )
        
    def migrate_environment_variables(self, env_mapping: Dict[str, str]) -> None:
        """
        Migrate environment variables to Vault.
        
        Args:
            env_mapping: Mapping of env var names to Vault paths
        """
        migrated = 0
        skipped = 0
        
        for env_var, vault_path in env_mapping.items():
            value = os.getenv(env_var)
            
            if not value:
                logger.warning(f"Environment variable {env_var} not found, skipping")
                skipped += 1
                continue
            
            # Parse the vault path to extract the key
            path_parts = vault_path.split("/")
            if len(path_parts) < 2:
                logger.error(f"Invalid vault path: {vault_path}")
                skipped += 1
                continue
                
            # The last part is the key, everything else is the path
            key = path_parts[-1]
            path = "/".join(path_parts[:-1])
            
            if self.dry_run:
                logger.info(f"[DRY RUN] Would migrate {env_var} to {path} with key {key}")
            else:
                try:
                    # Get existing secrets at this path
                    existing_data = {}
                    try:
                        existing_data = self.secrets_manager.get_secret(path)
                        if isinstance(existing_data, str):
                            existing_data = {}
                    except Exception:
                        pass
                    
                    # Add new key
                    existing_data[key] = value
                    
                    # Set the secret
                    self.secrets_manager.set_secret(path, existing_data)
                    logger.info(f"Migrated {env_var} to {path}/{key}")
                    migrated += 1
                    
                except Exception as e:
                    logger.error(f"Failed to migrate {env_var}: {e}")
                    skipped += 1
        
        logger.info(f"Migration complete: {migrated} migrated, {skipped} skipped")
    
    def migrate_from_env_file(self, env_file: str) -> None:
        """
        Migrate secrets from a .env file to Vault.
        
        Args:
            env_file: Path to .env file
        """
        env_path = Path(env_file)
        
        if not env_path.exists():
            logger.error(f"Environment file not found: {env_file}")
            return
        
        # Read and parse the env file
        env_vars = {}
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    env_vars[key.strip()] = value.strip().strip('"').strip("'")
        
        # Map env vars to Vault paths
        env_mapping = self._create_env_mapping(env_vars.keys())
        
        # Set environment variables temporarily for migration
        for key, value in env_vars.items():
            os.environ[key] = value
        
        # Migrate
        self.migrate_environment_variables(env_mapping)
    
    def _create_env_mapping(self, env_vars: List[str]) -> Dict[str, str]:
        """Create mapping of environment variables to Vault paths."""
        mapping = {}
        
        for var in env_vars:
            # Database related
            if var.startswith("DB_") or var == "DATABASE_URL":
                if var == "DATABASE_URL":
                    mapping[var] = "database/connection/url"
                elif var == "DB_HOST":
                    mapping[var] = "database/connection/host"
                elif var == "DB_PORT":
                    mapping[var] = "database/connection/port"
                elif var == "DB_USER":
                    mapping[var] = "database/connection/user"
                elif var == "DB_PASSWORD":
                    mapping[var] = "database/connection/password"
                elif var == "DB_NAME":
                    mapping[var] = "database/connection/name"
                elif var.startswith("DB_POOL_"):
                    key = var.replace("DB_POOL_", "").lower()
                    mapping[var] = f"database/pool/{key}"
                else:
                    mapping[var] = f"database/config/{var.lower()}"
            
            # JWT and Auth related
            elif var in ["JWT_SECRET_KEY", "JWT_SECRET"]:
                mapping[var] = "auth/jwt/secret"
            elif var.startswith("JWT_"):
                key = var.replace("JWT_", "").lower()
                mapping[var] = f"auth/jwt/{key}"
            elif var == "SECRET_KEY":
                mapping[var] = "auth/app/secret"
            
            # API Keys
            elif var.endswith("_API_KEY"):
                service = var.replace("_API_KEY", "").lower()
                mapping[var] = f"api-keys/{service}/key"
            elif var == "ANTHROPIC_API_KEY":
                mapping[var] = "api-keys/anthropic/key"
            elif var == "OPENAI_API_KEY":
                mapping[var] = "api-keys/openai/key"
            elif var == "GOOGLE_API_KEY":
                mapping[var] = "api-keys/google/key"
            
            # Vault related
            elif var.startswith("VAULT_"):
                logger.info(f"Skipping Vault configuration variable: {var}")
                continue
            
            # AWS/Cloud
            elif var.startswith("AWS_"):
                key = var.replace("AWS_", "").lower()
                mapping[var] = f"cloud/aws/{key}"
            elif var.startswith("AZURE_"):
                key = var.replace("AZURE_", "").lower()
                mapping[var] = f"cloud/azure/{key}"
            elif var.startswith("GCP_"):
                key = var.replace("GCP_", "").lower()
                mapping[var] = f"cloud/gcp/{key}"
            
            # Redis
            elif var.startswith("REDIS_"):
                key = var.replace("REDIS_", "").lower()
                mapping[var] = f"cache/redis/{key}"
            
            # Monitoring
            elif var.startswith("PROMETHEUS_"):
                key = var.replace("PROMETHEUS_", "").lower()
                mapping[var] = f"monitoring/prometheus/{key}"
            elif var.startswith("GRAFANA_"):
                key = var.replace("GRAFANA_", "").lower()
                mapping[var] = f"monitoring/grafana/{key}"
            
            # Default mapping
            else:
                mapping[var] = f"app/config/{var.lower()}"
        
        return mapping
    
    def export_mapping(self, output_file: str) -> None:
        """Export the environment variable mapping to a file."""
        # Get all environment variables
        env_vars = [key for key in os.environ.keys()]
        
        # Create mapping
        mapping = self._create_env_mapping(env_vars)
        
        # Save to file
        with open(output_file, 'w') as f:
            json.dump(mapping, f, indent=2)
        
        logger.info(f"Exported mapping to {output_file}")


def main():
    """Main migration function."""
    parser = argparse.ArgumentParser(description="Migrate secrets to HashiCorp Vault")
    parser.add_argument(
        "--vault-url",
        default=os.getenv("VAULT_ADDR", "http://localhost:8200"),
        help="Vault server URL"
    )
    parser.add_argument(
        "--vault-token",
        help="Vault authentication token (will prompt if not provided)"
    )
    parser.add_argument(
        "--env-file",
        help="Path to .env file to migrate"
    )
    parser.add_argument(
        "--mapping-file",
        help="Path to JSON file with custom env var to Vault path mapping"
    )
    parser.add_argument(
        "--export-mapping",
        help="Export current environment variable mapping to file"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be migrated without actually migrating"
    )
    parser.add_argument(
        "--include",
        nargs="+",
        help="Only migrate these environment variables"
    )
    parser.add_argument(
        "--exclude",
        nargs="+",
        help="Exclude these environment variables from migration"
    )
    
    args = parser.parse_args()
    
    # Get Vault token
    vault_token = args.vault_token
    if not vault_token:
        vault_token = os.getenv("VAULT_TOKEN")
    if not vault_token and not args.export_mapping:
        vault_token = getpass.getpass("Enter Vault token: ")
    
    # Initialize migrator
    migrator = SecretsMigrator(
        vault_url=args.vault_url,
        vault_token=vault_token,
        dry_run=args.dry_run
    )
    
    # Export mapping if requested
    if args.export_mapping:
        migrator.export_mapping(args.export_mapping)
        return
    
    # Load custom mapping if provided
    env_mapping = {}
    if args.mapping_file:
        with open(args.mapping_file, 'r') as f:
            env_mapping = json.load(f)
    
    # Migrate from env file
    if args.env_file:
        migrator.migrate_from_env_file(args.env_file)
    else:
        # Get environment variables to migrate
        if not env_mapping:
            env_vars = list(os.environ.keys())
            
            # Apply filters
            if args.include:
                env_vars = [v for v in env_vars if v in args.include]
            if args.exclude:
                env_vars = [v for v in env_vars if v not in args.exclude]
            
            # Create mapping
            env_mapping = migrator._create_env_mapping(env_vars)
        
        # Migrate
        migrator.migrate_environment_variables(env_mapping)


if __name__ == "__main__":
    main()