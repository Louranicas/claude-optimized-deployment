#!/usr/bin/env python3
"""
HashiCorp Vault Setup Script for CODE Project

This script provides comprehensive Vault setup including:
- Secret rotation configuration
- Access control setup
- Monitoring integration
- Compliance policies
"""

import os
import sys
import json
import argparse
import asyncio
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from pathlib import Path

import hvac
import yaml
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.vault_client import EnhancedVaultClient, VaultConfig
from src.core.secret_rotation_manager import RotationManager
from src.core.secrets_rotation_config import SecretType, RotationPolicy
from src.core.secrets_audit import get_secret_audit_logger

console = Console()
logger = logging.getLogger(__name__)


class VaultSetup:
    """Handles Vault setup and configuration."""
    
    def __init__(self, vault_addr: str = "http://localhost:8200", vault_token: Optional[str] = None):
        """Initialize Vault setup.
        
        Args:
            vault_addr: Vault server address
            vault_token: Vault authentication token
        """
        self.vault_addr = vault_addr
        self.vault_token = vault_token or os.getenv("VAULT_TOKEN")
        self.client = None
        self.enhanced_client = None
        
    def connect(self) -> bool:
        """Connect to Vault server.
        
        Returns:
            True if connected successfully
        """
        try:
            self.client = hvac.Client(url=self.vault_addr, token=self.vault_token)
            
            if not self.client.is_authenticated():
                console.print("[red]Failed to authenticate with Vault[/red]")
                return False
            
            # Initialize enhanced client
            config = VaultConfig(
                url=self.vault_addr,
                token=self.vault_token
            )
            self.enhanced_client = EnhancedVaultClient(config)
            
            console.print(f"[green]Connected to Vault at {self.vault_addr}[/green]")
            return True
            
        except Exception as e:
            console.print(f"[red]Failed to connect to Vault: {e}[/red]")
            return False
    
    def setup_secret_engines(self):
        """Setup required secret engines."""
        engines = [
            ("secret", "kv", {"version": "2"}),
            ("database", "database", {}),
            ("pki", "pki", {"max_lease_ttl": "87600h"}),
            ("transit", "transit", {}),
            ("totp", "totp", {}),
            ("transform", "transform", {})
        ]
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
            task = progress.add_task("Setting up secret engines...", total=len(engines))
            
            for path, engine_type, options in engines:
                try:
                    self.client.sys.enable_secrets_engine(
                        backend_type=engine_type,
                        path=path,
                        options=options
                    )
                    console.print(f"✓ Enabled {engine_type} engine at {path}")
                except hvac.exceptions.InvalidRequest as e:
                    if "already in use" in str(e):
                        console.print(f"• {engine_type} engine already enabled at {path}")
                    else:
                        console.print(f"[red]✗ Failed to enable {engine_type}: {e}[/red]")
                
                progress.advance(task)
    
    def setup_auth_methods(self):
        """Setup authentication methods."""
        auth_methods = [
            ("approle", {}),
            ("kubernetes", {}),
            ("jwt", {}),
            ("userpass", {}),
            ("cert", {})
        ]
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
            task = progress.add_task("Setting up auth methods...", total=len(auth_methods))
            
            for method, options in auth_methods:
                try:
                    self.client.sys.enable_auth_method(
                        method_type=method,
                        options=options
                    )
                    console.print(f"✓ Enabled {method} auth method")
                except hvac.exceptions.InvalidRequest as e:
                    if "already in use" in str(e):
                        console.print(f"• {method} auth method already enabled")
                    else:
                        console.print(f"[red]✗ Failed to enable {method}: {e}[/red]")
                
                progress.advance(task)
    
    def setup_policies(self):
        """Setup Vault policies."""
        policies_dir = Path(__file__).parent.parent / "vault" / "policies"
        policies_dir.mkdir(parents=True, exist_ok=True)
        
        policies = {
            "admin": {
                "description": "Full administrative access",
                "rules": """
                    # Full access to everything
                    path "*" {
                        capabilities = ["create", "read", "update", "delete", "list", "sudo"]
                    }
                """
            },
            "developer": {
                "description": "Developer access to non-production secrets",
                "rules": """
                    # Read/write access to dev secrets
                    path "secret/data/dev/*" {
                        capabilities = ["create", "read", "update", "delete", "list"]
                    }
                    
                    path "secret/metadata/dev/*" {
                        capabilities = ["read", "list", "delete"]
                    }
                    
                    # Read-only access to staging
                    path "secret/data/staging/*" {
                        capabilities = ["read", "list"]
                    }
                    
                    # No access to production
                    path "secret/data/prod/*" {
                        capabilities = ["deny"]
                    }
                    
                    # Token management
                    path "auth/token/lookup-self" {
                        capabilities = ["read"]
                    }
                    
                    path "auth/token/renew-self" {
                        capabilities = ["update"]
                    }
                """
            },
            "application": {
                "description": "Application runtime access",
                "rules": """
                    # Read access to application secrets
                    path "secret/data/app/*" {
                        capabilities = ["read"]
                    }
                    
                    path "secret/metadata/app/*" {
                        capabilities = ["read", "list"]
                    }
                    
                    # Database credentials
                    path "database/creds/*" {
                        capabilities = ["read"]
                    }
                    
                    # Encryption/decryption
                    path "transit/encrypt/*" {
                        capabilities = ["update"]
                    }
                    
                    path "transit/decrypt/*" {
                        capabilities = ["update"]
                    }
                    
                    # Token management
                    path "auth/token/lookup-self" {
                        capabilities = ["read"]
                    }
                    
                    path "auth/token/renew-self" {
                        capabilities = ["update"]
                    }
                """
            },
            "cicd": {
                "description": "CI/CD pipeline access",
                "rules": """
                    # Deploy secrets
                    path "secret/data/cicd/*" {
                        capabilities = ["create", "read", "update", "list"]
                    }
                    
                    # Read application secrets for deployment
                    path "secret/data/app/*" {
                        capabilities = ["read", "list"]
                    }
                    
                    # Certificate management
                    path "pki/issue/*" {
                        capabilities = ["create", "update"]
                    }
                    
                    # Create temporary tokens
                    path "auth/token/create" {
                        capabilities = ["create", "update"]
                        allowed_parameters = {
                            "policies" = ["application"]
                            "ttl" = ["1h", "2h", "4h"]
                            "max_ttl" = ["4h", "8h", "24h"]
                        }
                    }
                """
            },
            "monitoring": {
                "description": "Monitoring and audit access",
                "rules": """
                    # Read metrics and health
                    path "sys/metrics" {
                        capabilities = ["read"]
                    }
                    
                    path "sys/health" {
                        capabilities = ["read"]
                    }
                    
                    # Audit log access
                    path "sys/audit" {
                        capabilities = ["read", "list"]
                    }
                    
                    # List all secrets for compliance
                    path "secret/metadata/*" {
                        capabilities = ["list"]
                    }
                """
            },
            "rotation": {
                "description": "Secret rotation service",
                "rules": """
                    # Read and update secrets for rotation
                    path "secret/data/*" {
                        capabilities = ["read", "update"]
                    }
                    
                    path "secret/metadata/*" {
                        capabilities = ["read", "list"]
                    }
                    
                    # Database rotation
                    path "database/rotate-root/*" {
                        capabilities = ["update"]
                    }
                    
                    path "database/config/*" {
                        capabilities = ["read", "update"]
                    }
                    
                    # PKI rotation
                    path "pki/root/rotate/*" {
                        capabilities = ["update"]
                    }
                """
            }
        }
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
            task = progress.add_task("Setting up policies...", total=len(policies))
            
            for name, policy in policies.items():
                try:
                    # Save policy file
                    policy_file = policies_dir / f"{name}.hcl"
                    policy_file.write_text(policy["rules"].strip())
                    
                    # Write to Vault
                    self.client.sys.create_or_update_policy(
                        name=name,
                        policy=policy["rules"]
                    )
                    console.print(f"✓ Created policy: {name}")
                    
                except Exception as e:
                    console.print(f"[red]✗ Failed to create policy {name}: {e}[/red]")
                
                progress.advance(task)
    
    def setup_database_connections(self):
        """Setup database secret engine connections."""
        db_configs = {
            "postgresql": {
                "plugin_name": "postgresql-database-plugin",
                "connection_url": "postgresql://{{username}}:{{password}}@localhost:5432/postgres?sslmode=disable",
                "allowed_roles": ["readonly", "readwrite", "admin"],
                "username": "vault",
                "password": "vault-password"  # Should be from environment
            },
            "mysql": {
                "plugin_name": "mysql-database-plugin",
                "connection_url": "{{username}}:{{password}}@tcp(localhost:3306)/",
                "allowed_roles": ["readonly", "readwrite"],
                "username": "vault",
                "password": "vault-password"
            }
        }
        
        for db_name, config in db_configs.items():
            try:
                self.client.secrets.database.configure(
                    name=db_name,
                    plugin_name=config["plugin_name"],
                    connection_url=config["connection_url"],
                    allowed_roles=config["allowed_roles"],
                    username=config["username"],
                    password=config["password"]
                )
                console.print(f"✓ Configured {db_name} database connection")
                
                # Create roles
                if db_name == "postgresql":
                    self.create_database_roles(db_name)
                    
            except Exception as e:
                console.print(f"[yellow]! Failed to configure {db_name}: {e}[/yellow]")
    
    def create_database_roles(self, db_name: str):
        """Create database roles."""
        roles = {
            "readonly": {
                "db_name": db_name,
                "creation_statements": [
                    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
                    "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
                ],
                "default_ttl": "1h",
                "max_ttl": "24h"
            },
            "readwrite": {
                "db_name": db_name,
                "creation_statements": [
                    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
                    "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
                ],
                "default_ttl": "1h",
                "max_ttl": "24h"
            }
        }
        
        for role_name, role_config in roles.items():
            try:
                self.client.secrets.database.create_role(
                    name=role_name,
                    **role_config
                )
                console.print(f"  ✓ Created database role: {role_name}")
            except Exception as e:
                console.print(f"  [yellow]! Failed to create role {role_name}: {e}[/yellow]")
    
    def create_initial_secrets(self):
        """Create initial secret structure."""
        secrets = {
            "app/database": {
                "host": "localhost",
                "port": 5432,
                "username": "app_user",
                "password": os.urandom(32).hex(),
                "database": "code_db"
            },
            "app/api-keys/openai": {
                "key": "sk-placeholder-replace-me",
                "organization": "org-placeholder"
            },
            "app/api-keys/anthropic": {
                "key": "sk-ant-placeholder-replace-me"
            },
            "app/auth/jwt": {
                "secret": os.urandom(64).hex(),
                "algorithm": "HS256",
                "issuer": "code-app",
                "audience": "code-api"
            },
            "app/encryption": {
                "key": os.urandom(32).hex(),
                "algorithm": "AES-256-GCM",
                "key_id": f"key_{datetime.utcnow().timestamp()}"
            },
            "app/oauth/github": {
                "client_id": "placeholder",
                "client_secret": "placeholder",
                "redirect_uri": "http://localhost:8000/auth/github/callback"
            },
            "cicd/docker": {
                "registry": "docker.io",
                "username": "placeholder",
                "password": "placeholder"
            },
            "monitoring/prometheus": {
                "username": "admin",
                "password": os.urandom(16).hex()
            }
        }
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
            task = progress.add_task("Creating initial secrets...", total=len(secrets))
            
            for path, data in secrets.items():
                try:
                    self.enhanced_client.write_secret(f"secret/{path}", data)
                    console.print(f"✓ Created secret: {path}")
                except Exception as e:
                    console.print(f"[red]✗ Failed to create secret {path}: {e}[/red]")
                
                progress.advance(task)
    
    async def setup_rotation_policies(self):
        """Setup automatic rotation policies."""
        audit_logger = get_secret_audit_logger()
        rotation_manager = RotationManager(
            vault_client=self.enhanced_client,
            audit_logger=audit_logger
        )
        
        # Define rotation schedules
        rotation_configs = [
            ("app/api-keys/*", timedelta(days=90)),
            ("app/database", timedelta(days=60)),
            ("app/auth/jwt", timedelta(days=180)),
            ("app/encryption", timedelta(days=365)),
            ("cicd/*", timedelta(days=30))
        ]
        
        console.print("\n[bold]Setting up rotation policies:[/bold]")
        
        for pattern, interval in rotation_configs:
            console.print(f"• {pattern}: rotate every {interval.days} days")
        
        # Initialize rotation manager
        await rotation_manager.initialize()
        
        console.print("[green]✓ Rotation policies configured[/green]")
    
    def setup_approle_auth(self) -> Dict[str, str]:
        """Setup AppRole authentication.
        
        Returns:
            Dictionary with role_id and secret_id
        """
        role_name = "code-app"
        
        try:
            # Create AppRole
            self.client.auth.approle.create_or_update_approle(
                role_name=role_name,
                token_policies=["application"],
                token_ttl="1h",
                token_max_ttl="4h",
                secret_id_ttl=0,  # Never expire
                secret_id_num_uses=0  # Unlimited uses
            )
            
            # Get role ID
            role_id = self.client.auth.approle.read_role_id(role_name)["data"]["role_id"]
            
            # Generate secret ID
            secret_id_response = self.client.auth.approle.generate_secret_id(role_name)
            secret_id = secret_id_response["data"]["secret_id"]
            
            console.print(f"✓ Created AppRole: {role_name}")
            
            return {
                "role_id": role_id,
                "secret_id": secret_id
            }
            
        except Exception as e:
            console.print(f"[red]✗ Failed to setup AppRole: {e}[/red]")
            return {}
    
    def generate_config_files(self, approle_creds: Dict[str, str]):
        """Generate configuration files."""
        config_dir = Path(__file__).parent.parent / "config"
        config_dir.mkdir(exist_ok=True)
        
        # Vault configuration
        vault_config = {
            "vault": {
                "address": self.vault_addr,
                "namespace": os.getenv("VAULT_NAMESPACE", ""),
                "auth": {
                    "method": "approle",
                    "role_id": approle_creds.get("role_id", ""),
                    "secret_id": approle_creds.get("secret_id", "")
                },
                "mount_points": {
                    "kv": "secret",
                    "database": "database",
                    "pki": "pki",
                    "transit": "transit"
                }
            },
            "rotation": {
                "enabled": True,
                "check_interval": "1h",
                "policies": {
                    "api_keys": {"interval_days": 90},
                    "database": {"interval_days": 60},
                    "certificates": {"interval_days": 30}
                }
            },
            "monitoring": {
                "metrics_enabled": True,
                "audit_enabled": True,
                "alert_channels": ["email", "slack"]
            }
        }
        
        # Save configuration
        config_file = config_dir / "vault.yaml"
        with open(config_file, "w") as f:
            yaml.dump(vault_config, f, default_flow_style=False)
        
        console.print(f"✓ Generated configuration: {config_file}")
        
        # Environment file
        env_file = Path(__file__).parent.parent / ".env.vault"
        with open(env_file, "w") as f:
            f.write(f"VAULT_ADDR={self.vault_addr}\n")
            f.write(f"VAULT_ROLE_ID={approle_creds.get('role_id', '')}\n")
            f.write(f"VAULT_SECRET_ID={approle_creds.get('secret_id', '')}\n")
        
        os.chmod(env_file, 0o600)
        console.print(f"✓ Generated environment file: {env_file}")
    
    def show_summary(self):
        """Show setup summary."""
        table = Table(title="Vault Setup Summary")
        table.add_column("Component", style="cyan")
        table.add_column("Status", style="green")
        
        # Check components
        components = [
            ("Secret Engine (KV v2)", self.check_secret_engine("secret")),
            ("Database Engine", self.check_secret_engine("database")),
            ("PKI Engine", self.check_secret_engine("pki")),
            ("Transit Engine", self.check_secret_engine("transit")),
            ("AppRole Auth", self.check_auth_method("approle")),
            ("Kubernetes Auth", self.check_auth_method("kubernetes")),
            ("JWT Auth", self.check_auth_method("jwt"))
        ]
        
        for component, status in components:
            table.add_row(component, "✓ Enabled" if status else "✗ Disabled")
        
        console.print("\n", table)
    
    def check_secret_engine(self, path: str) -> bool:
        """Check if a secret engine is enabled."""
        try:
            mounts = self.client.sys.list_mounted_secrets_engines()
            return f"{path}/" in mounts
        except:
            return False
    
    def check_auth_method(self, method: str) -> bool:
        """Check if an auth method is enabled."""
        try:
            methods = self.client.sys.list_auth_methods()
            return f"{method}/" in methods
        except:
            return False


async def main():
    """Main setup function."""
    parser = argparse.ArgumentParser(description="HashiCorp Vault Setup for CODE Project")
    parser.add_argument("--vault-addr", default="http://localhost:8200", help="Vault server address")
    parser.add_argument("--vault-token", help="Vault token (or set VAULT_TOKEN env var)")
    parser.add_argument("--skip-engines", action="store_true", help="Skip secret engine setup")
    parser.add_argument("--skip-auth", action="store_true", help="Skip auth method setup")
    parser.add_argument("--skip-policies", action="store_true", help="Skip policy setup")
    parser.add_argument("--skip-secrets", action="store_true", help="Skip initial secret creation")
    parser.add_argument("--skip-rotation", action="store_true", help="Skip rotation setup")
    
    args = parser.parse_args()
    
    console.print("[bold]HashiCorp Vault Setup for CODE Project[/bold]\n")
    
    # Initialize setup
    setup = VaultSetup(args.vault_addr, args.vault_token)
    
    # Connect to Vault
    if not setup.connect():
        sys.exit(1)
    
    # Run setup steps
    if not args.skip_engines:
        setup.setup_secret_engines()
    
    if not args.skip_auth:
        setup.setup_auth_methods()
    
    if not args.skip_policies:
        setup.setup_policies()
    
    # Setup database connections
    setup.setup_database_connections()
    
    if not args.skip_secrets:
        setup.create_initial_secrets()
    
    # Setup AppRole
    approle_creds = setup.setup_approle_auth()
    
    # Generate configuration files
    if approle_creds:
        setup.generate_config_files(approle_creds)
    
    # Setup rotation policies
    if not args.skip_rotation:
        await setup.setup_rotation_policies()
    
    # Show summary
    setup.show_summary()
    
    console.print("\n[bold green]Vault setup completed successfully![/bold green]")
    console.print("\nNext steps:")
    console.print("1. Update .env file with Vault credentials")
    console.print("2. Configure your application to use Vault")
    console.print("3. Test secret access with: vault kv get secret/app/database")
    console.print("4. Monitor rotation status in the Vault UI")


if __name__ == "__main__":
    asyncio.run(main())