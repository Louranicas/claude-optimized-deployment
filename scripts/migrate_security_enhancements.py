#!/usr/bin/env python3
"""
Security Enhancement Migration Script

This script automates the migration to enhanced security features including:
- JWT migration from HMAC to RSA
- API key generation for services
- Certificate generation for mTLS
- RBAC configuration updates
"""

import asyncio
import os
import sys
import json
import secrets
from pathlib import Path
from datetime import datetime, timedelta
import logging
import argparse
from typing import Dict, Any, List, Optional

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.auth.security_enhancements import (
    SecurityConfig,
    EnhancedJWTManager,
    EnhancedAPIKeyManager,
    EnhancedRBACEnforcer,
    MutualTLSAuthenticator,
    SecurityAuditLogger,
    initialize_security_components,
    get_security_components
)

from src.mcp.security.enhanced_auth_integration import (
    initialize_mcp_authentication,
    get_mcp_authenticator,
    get_service_registry
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SecurityMigrator:
    """Handles migration to enhanced security features."""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or "security_config.json"
        self.backup_dir = Path("security_backup")
        self.backup_dir.mkdir(exist_ok=True)
        
        # Service definitions
        self.services = {
            "docker-server": {
                "roles": ["mcp_service"],
                "permissions": ["mcp.docker:*", "infrastructure:execute"],
                "common_name": "docker.mcp.local"
            },
            "kubernetes-server": {
                "roles": ["mcp_service"],
                "permissions": ["mcp.kubernetes:*", "infrastructure:execute"],
                "common_name": "kubernetes.mcp.local"
            },
            "prometheus-server": {
                "roles": ["monitoring_service"],
                "permissions": ["mcp.prometheus:*", "monitoring:*"],
                "common_name": "prometheus.mcp.local"
            },
            "security-scanner": {
                "roles": ["mcp_service"],
                "permissions": ["mcp.security:*", "security:scan"],
                "common_name": "security.mcp.local"
            },
            "slack-server": {
                "roles": ["mcp_service"],
                "permissions": ["mcp.slack:*", "communication:send"],
                "common_name": "slack.mcp.local"
            },
            "cicd-pipeline": {
                "roles": ["ci_cd_service"],
                "permissions": ["deployment:*", "mcp.docker:*", "mcp.kubernetes:*"],
                "common_name": "cicd.mcp.local"
            }
        }
    
    async def run_migration(self, steps: List[str]):
        """Run the migration process."""
        logger.info("Starting security enhancement migration...")
        
        # Initialize security components
        await self.initialize_components()
        
        # Run requested migration steps
        for step in steps:
            if step == "backup":
                await self.backup_existing_config()
            elif step == "jwt":
                await self.migrate_jwt_keys()
            elif step == "apikeys":
                await self.generate_service_api_keys()
            elif step == "certs":
                await self.generate_service_certificates()
            elif step == "rbac":
                await self.configure_rbac()
            elif step == "validate":
                await self.validate_migration()
            else:
                logger.warning(f"Unknown migration step: {step}")
        
        logger.info("Migration completed successfully!")
    
    async def initialize_components(self):
        """Initialize security components."""
        logger.info("Initializing security components...")
        
        # Create security configuration
        config = SecurityConfig(
            jwt_algorithm="RS256",
            jwt_key_rotation_days=30,
            jwt_max_age_minutes=15,
            api_key_rotation_days=90,
            api_key_max_age_days=365,
            mtls_required_for_services=True,
            max_concurrent_sessions=3,
            session_timeout_minutes=30
        )
        
        # Initialize components
        await initialize_security_components(config)
        
        # Get components
        self.components = get_security_components()
        
        # Initialize MCP authentication
        await initialize_mcp_authentication(
            self.components["jwt_manager"],
            self.components["api_key_manager"],
            self.components["rbac_enforcer"],
            self.components["mtls_authenticator"],
            self.components["audit_logger"]
        )
        
        logger.info("Security components initialized")
    
    async def backup_existing_config(self):
        """Backup existing security configuration."""
        logger.info("Backing up existing configuration...")
        
        backup_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "environment": {
                "JWT_SECRET": os.environ.get("JWT_SECRET", ""),
                "API_KEYS": {},
                "SERVICE_ACCOUNTS": {}
            }
        }
        
        # Backup existing API keys if any
        api_keys_file = Path("api_keys.json")
        if api_keys_file.exists():
            with open(api_keys_file) as f:
                backup_data["environment"]["API_KEYS"] = json.load(f)
        
        # Save backup
        backup_file = self.backup_dir / f"security_backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        with open(backup_file, 'w') as f:
            json.dump(backup_data, f, indent=2)
        
        logger.info(f"Backup saved to: {backup_file}")
    
    async def migrate_jwt_keys(self):
        """Migrate from HMAC to RSA JWT keys."""
        logger.info("Migrating JWT keys from HMAC to RSA...")
        
        jwt_manager = self.components["jwt_manager"]
        
        # Generate new RSA keys (already done in initialization)
        logger.info("Generated new RSA key pair for JWT signing")
        
        # Get public key for distribution
        public_key = jwt_manager.current_key_pair[1]
        
        # Save public key for services
        public_key_file = Path("jwt_public_key.pem")
        with open(public_key_file, 'w') as f:
            f.write(public_key)
        
        logger.info(f"JWT public key saved to: {public_key_file}")
        
        # Create example tokens for testing
        test_payload = {
            "sub": "test_user",
            "username": "testuser",
            "roles": ["operator"],
            "permissions": ["mcp.docker:read", "mcp.kubernetes:read"]
        }
        
        access_token = jwt_manager.create_token(test_payload, "access")
        refresh_token = jwt_manager.create_token(test_payload, "refresh")
        
        logger.info("Sample tokens generated for testing:")
        logger.info(f"Access Token (15 min): {access_token[:50]}...")
        logger.info(f"Refresh Token (7 days): {refresh_token[:50]}...")
    
    async def generate_service_api_keys(self):
        """Generate API keys for all services."""
        logger.info("Generating API keys for services...")
        
        api_key_manager = self.components["api_key_manager"]
        service_keys = {}
        
        for service_name, service_info in self.services.items():
            # Generate API key
            key_id, api_key = api_key_manager.generate_api_key(
                user_id=f"service:{service_name}",
                service_name=service_name
            )
            
            service_keys[service_name] = {
                "key_id": key_id,
                "api_key": api_key,
                "roles": service_info["roles"],
                "permissions": service_info["permissions"],
                "created_at": datetime.utcnow().isoformat()
            }
            
            logger.info(f"Generated API key for {service_name}: {key_id}")
        
        # Save API keys securely
        api_keys_file = Path("service_api_keys.json")
        with open(api_keys_file, 'w') as f:
            json.dump(service_keys, f, indent=2)
        
        # Set restrictive permissions
        api_keys_file.chmod(0o600)
        
        logger.info(f"API keys saved to: {api_keys_file}")
        logger.warning("IMPORTANT: Store these API keys securely and delete this file after distribution!")
    
    async def generate_service_certificates(self):
        """Generate mTLS certificates for services."""
        logger.info("Generating mTLS certificates for services...")
        
        mtls_auth = self.components["mtls_authenticator"]
        cert_dir = Path("mcp_certificates")
        cert_dir.mkdir(exist_ok=True)
        
        for service_name, service_info in self.services.items():
            # Generate certificate
            private_key, certificate = mtls_auth.create_service_certificate(
                service_name=service_name,
                common_name=service_info["common_name"],
                organization="Claude Optimized Deployment"
            )
            
            # Save certificate and key
            key_file = cert_dir / f"{service_name}.key"
            cert_file = cert_dir / f"{service_name}.crt"
            
            with open(key_file, 'w') as f:
                f.write(private_key)
            key_file.chmod(0o600)
            
            with open(cert_file, 'w') as f:
                f.write(certificate)
            cert_file.chmod(0o644)
            
            logger.info(f"Generated certificate for {service_name}")
        
        logger.info(f"Certificates saved to: {cert_dir}")
    
    async def configure_rbac(self):
        """Configure RBAC with enhanced permissions."""
        logger.info("Configuring RBAC with enhanced permissions...")
        
        rbac_enforcer = self.components["rbac_enforcer"]
        
        # Define enhanced role permissions
        role_updates = {
            "mcp_service": {
                "description": "MCP service account with tool execution rights",
                "permissions": [
                    "mcp.*:execute",
                    "infrastructure:execute",
                    "monitoring:write",
                    "logs:write"
                ]
            },
            "ci_cd_service": {
                "description": "CI/CD service with deployment rights",
                "permissions": [
                    "deployment:*",
                    "mcp.docker:*",
                    "mcp.kubernetes:*",
                    "mcp.azure_devops:*",
                    "security.scan:execute"
                ]
            },
            "monitoring_service": {
                "description": "Monitoring service with metrics access",
                "permissions": [
                    "monitoring:*",
                    "mcp.prometheus:*",
                    "mcp.slack:execute",
                    "logs:read",
                    "metrics:write"
                ]
            },
            "security_scanner": {
                "description": "Security scanning service",
                "permissions": [
                    "security:*",
                    "mcp.security_scanner:*",
                    "audit:write",
                    "vulnerabilities:write"
                ]
            }
        }
        
        # Save RBAC configuration
        rbac_config = {
            "roles": role_updates,
            "service_accounts": {}
        }
        
        # Map services to roles
        for service_name, service_info in self.services.items():
            rbac_config["service_accounts"][service_name] = {
                "roles": service_info["roles"],
                "permissions": service_info["permissions"]
            }
        
        rbac_file = Path("rbac_config.json")
        with open(rbac_file, 'w') as f:
            json.dump(rbac_config, f, indent=2)
        
        logger.info(f"RBAC configuration saved to: {rbac_file}")
    
    async def validate_migration(self):
        """Validate the migration was successful."""
        logger.info("Validating migration...")
        
        validations = []
        
        # Check JWT manager
        jwt_manager = self.components["jwt_manager"]
        if jwt_manager.current_key_pair:
            validations.append(("JWT RSA keys", True, "RSA key pair generated"))
        else:
            validations.append(("JWT RSA keys", False, "No RSA keys found"))
        
        # Check API keys
        api_keys_file = Path("service_api_keys.json")
        if api_keys_file.exists():
            with open(api_keys_file) as f:
                keys = json.load(f)
                validations.append(("API keys", True, f"{len(keys)} service keys generated"))
        else:
            validations.append(("API keys", False, "No API keys file found"))
        
        # Check certificates
        cert_dir = Path("mcp_certificates")
        if cert_dir.exists():
            cert_count = len(list(cert_dir.glob("*.crt")))
            validations.append(("mTLS certificates", True, f"{cert_count} certificates generated"))
        else:
            validations.append(("mTLS certificates", False, "No certificates found"))
        
        # Check RBAC configuration
        rbac_file = Path("rbac_config.json")
        if rbac_file.exists():
            validations.append(("RBAC configuration", True, "Configuration saved"))
        else:
            validations.append(("RBAC configuration", False, "No RBAC config found"))
        
        # Print validation results
        logger.info("\n" + "="*50)
        logger.info("MIGRATION VALIDATION RESULTS")
        logger.info("="*50)
        
        all_passed = True
        for component, passed, message in validations:
            status = "✓ PASS" if passed else "✗ FAIL"
            logger.info(f"{status} | {component}: {message}")
            if not passed:
                all_passed = False
        
        logger.info("="*50)
        
        if all_passed:
            logger.info("All validations passed! Migration successful.")
        else:
            logger.error("Some validations failed. Please check the logs.")
            sys.exit(1)
    
    async def generate_deployment_config(self):
        """Generate deployment configuration for services."""
        logger.info("Generating deployment configuration...")
        
        # Load generated resources
        api_keys = {}
        if Path("service_api_keys.json").exists():
            with open("service_api_keys.json") as f:
                api_keys = json.load(f)
        
        # Create environment variables for each service
        for service_name in self.services:
            env_file = Path(f".env.{service_name}")
            
            env_vars = [
                f"# Environment variables for {service_name}",
                f"SERVICE_NAME={service_name}",
                f"MCP_AUTH_ENABLED=true",
                f"MCP_JWT_PUBLIC_KEY_FILE=/etc/mcp/jwt_public_key.pem",
                f"MCP_CERT_FILE=/etc/mcp/certs/{service_name}.crt",
                f"MCP_KEY_FILE=/etc/mcp/certs/{service_name}.key",
            ]
            
            if service_name in api_keys:
                env_vars.append(f"MCP_API_KEY={api_keys[service_name]['api_key']}")
            
            with open(env_file, 'w') as f:
                f.write('\n'.join(env_vars))
            
            env_file.chmod(0o600)
            logger.info(f"Created environment file: {env_file}")


async def main():
    """Main migration function."""
    parser = argparse.ArgumentParser(
        description="Migrate to enhanced security features"
    )
    parser.add_argument(
        "--steps",
        nargs="+",
        choices=["backup", "jwt", "apikeys", "certs", "rbac", "validate", "all"],
        default=["all"],
        help="Migration steps to run"
    )
    parser.add_argument(
        "--config",
        help="Path to security configuration file"
    )
    
    args = parser.parse_args()
    
    # Determine steps to run
    if "all" in args.steps:
        steps = ["backup", "jwt", "apikeys", "certs", "rbac", "validate"]
    else:
        steps = args.steps
    
    # Run migration
    migrator = SecurityMigrator(args.config)
    await migrator.run_migration(steps)
    
    # Generate deployment config if all steps completed
    if "validate" in steps:
        await migrator.generate_deployment_config()
    
    logger.info("\nMigration completed! Next steps:")
    logger.info("1. Securely distribute API keys to services")
    logger.info("2. Deploy certificates to service containers")
    logger.info("3. Update service configurations with new auth settings")
    logger.info("4. Delete sensitive files after distribution")
    logger.info("5. Monitor audit logs for authentication events")


if __name__ == "__main__":
    asyncio.run(main())