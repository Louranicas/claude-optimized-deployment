"""
Secret rotation configuration and policies for different secret types.

This module defines rotation policies and schedules for various types of secrets,
including API keys, database passwords, and service tokens.
"""

from datetime import timedelta
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from enum import Enum
import re

from src.core.secrets_manager import SecretAccessLevel

__all__ = [
    "RotationPolicy",
    "SecretType",
    "RotationSchedule",
    "get_rotation_config",
    "DEFAULT_ROTATION_POLICIES"
]


class SecretType(Enum):
    """Types of secrets with different rotation requirements."""
    API_KEY = "api_key"
    DATABASE_PASSWORD = "database_password"
    SERVICE_TOKEN = "service_token"
    ENCRYPTION_KEY = "encryption_key"
    WEBHOOK_SECRET = "webhook_secret"
    OAUTH_SECRET = "oauth_secret"
    SSH_KEY = "ssh_key"
    TLS_CERT = "tls_cert"
    SIGNING_KEY = "signing_key"
    OTHER = "other"


@dataclass
class RotationPolicy:
    """Defines rotation policy for a specific type of secret."""
    secret_type: SecretType
    rotation_interval: timedelta
    grace_period: timedelta = timedelta(days=1)
    notification_channels: List[str] = field(default_factory=lambda: ["email", "slack"])
    pre_rotation_hook: Optional[Callable[[str, Any], None]] = None
    post_rotation_hook: Optional[Callable[[str, str, Any], None]] = None
    validation_func: Optional[Callable[[str], bool]] = None
    auto_rotate: bool = True
    requires_approval: bool = False
    approvers: List[str] = field(default_factory=list)
    max_versions: int = 3  # Number of old versions to keep


@dataclass
class RotationSchedule:
    """Rotation schedule configuration."""
    enabled: bool = True
    blackout_windows: List[Dict[str, Any]] = field(default_factory=list)  # Times when rotation is blocked
    maintenance_windows: List[Dict[str, Any]] = field(default_factory=list)  # Preferred rotation times
    immediate_patterns: List[str] = field(default_factory=list)  # Patterns that trigger immediate rotation
    excluded_patterns: List[str] = field(default_factory=list)  # Patterns to never rotate


# Default rotation policies for different secret types
DEFAULT_ROTATION_POLICIES = {
    SecretType.API_KEY: RotationPolicy(
        secret_type=SecretType.API_KEY,
        rotation_interval=timedelta(days=90),
        grace_period=timedelta(days=7),
        auto_rotate=True,
        max_versions=2
    ),
    SecretType.DATABASE_PASSWORD: RotationPolicy(
        secret_type=SecretType.DATABASE_PASSWORD,
        rotation_interval=timedelta(days=60),
        grace_period=timedelta(days=3),
        auto_rotate=False,  # Requires coordination
        requires_approval=True,
        approvers=["dba", "security"],
        max_versions=3
    ),
    SecretType.SERVICE_TOKEN: RotationPolicy(
        secret_type=SecretType.SERVICE_TOKEN,
        rotation_interval=timedelta(days=30),
        grace_period=timedelta(days=1),
        auto_rotate=True,
        max_versions=2
    ),
    SecretType.ENCRYPTION_KEY: RotationPolicy(
        secret_type=SecretType.ENCRYPTION_KEY,
        rotation_interval=timedelta(days=365),
        grace_period=timedelta(days=30),
        auto_rotate=False,
        requires_approval=True,
        approvers=["security", "cto"],
        max_versions=5  # Keep more versions for decryption
    ),
    SecretType.WEBHOOK_SECRET: RotationPolicy(
        secret_type=SecretType.WEBHOOK_SECRET,
        rotation_interval=timedelta(days=180),
        grace_period=timedelta(days=7),
        auto_rotate=True,
        max_versions=2
    ),
    SecretType.OAUTH_SECRET: RotationPolicy(
        secret_type=SecretType.OAUTH_SECRET,
        rotation_interval=timedelta(days=365),
        grace_period=timedelta(days=14),
        auto_rotate=False,
        requires_approval=True,
        approvers=["security"],
        max_versions=2
    ),
    SecretType.SSH_KEY: RotationPolicy(
        secret_type=SecretType.SSH_KEY,
        rotation_interval=timedelta(days=365),
        grace_period=timedelta(days=30),
        auto_rotate=False,
        requires_approval=True,
        approvers=["security", "devops"],
        max_versions=2
    ),
    SecretType.TLS_CERT: RotationPolicy(
        secret_type=SecretType.TLS_CERT,
        rotation_interval=timedelta(days=365),
        grace_period=timedelta(days=30),
        auto_rotate=True,  # Can auto-renew with Let's Encrypt
        notification_channels=["email", "slack", "pagerduty"],
        max_versions=2
    ),
    SecretType.SIGNING_KEY: RotationPolicy(
        secret_type=SecretType.SIGNING_KEY,
        rotation_interval=timedelta(days=730),  # 2 years
        grace_period=timedelta(days=60),
        auto_rotate=False,
        requires_approval=True,
        approvers=["security", "cto"],
        max_versions=3
    )
}


# Path patterns to secret type mapping
PATH_TO_SECRET_TYPE = [
    (r".*api[_-]key.*", SecretType.API_KEY),
    (r".*database.*password.*", SecretType.DATABASE_PASSWORD),
    (r".*db.*password.*", SecretType.DATABASE_PASSWORD),
    (r".*token.*", SecretType.SERVICE_TOKEN),
    (r".*encryption[_-]key.*", SecretType.ENCRYPTION_KEY),
    (r".*webhook.*", SecretType.WEBHOOK_SECRET),
    (r".*oauth.*", SecretType.OAUTH_SECRET),
    (r".*ssh[_-]key.*", SecretType.SSH_KEY),
    (r".*\.pem$", SecretType.TLS_CERT),
    (r".*\.crt$", SecretType.TLS_CERT),
    (r".*signing[_-]key.*", SecretType.SIGNING_KEY),
]


def detect_secret_type(path: str) -> SecretType:
    """Detect secret type from path."""
    path_lower = path.lower()
    
    for pattern, secret_type in PATH_TO_SECRET_TYPE:
        if re.match(pattern, path_lower):
            return secret_type
    
    return SecretType.OTHER


def get_rotation_config() -> Dict[str, Any]:
    """Get rotation configuration for the secret manager.
    
    Returns:
        Dictionary with rotation configuration including:
        - policies: Rotation policies by secret type
        - schedule: Rotation schedule configuration
        - callbacks: Rotation callback functions
    """
    return {
        "policies": DEFAULT_ROTATION_POLICIES,
        "schedule": RotationSchedule(
            enabled=True,
            blackout_windows=[
                # No rotations during peak hours
                {"weekday": "mon-fri", "hours": "09:00-17:00", "timezone": "UTC"},
                # No rotations during holidays
                {"dates": ["2025-12-24", "2025-12-25", "2025-12-31", "2026-01-01"]}
            ],
            maintenance_windows=[
                # Prefer rotations during maintenance windows
                {"weekday": "sun", "hours": "02:00-06:00", "timezone": "UTC"}
            ],
            immediate_patterns=[
                # Patterns that trigger immediate rotation
                "compromised",
                "leaked",
                "exposed"
            ],
            excluded_patterns=[
                # Never rotate these
                "vault_token",  # Vault's own token
                "master_key",   # Master encryption keys
                "root_"         # Root credentials
            ]
        ),
        "callbacks": {
            "pre_rotation": pre_rotation_callback,
            "post_rotation": post_rotation_callback,
            "notification": rotation_notification_callback
        }
    }


async def pre_rotation_callback(secret_path: str, metadata: Any) -> None:
    """Called before rotating a secret.
    
    Args:
        secret_path: Path of the secret being rotated
        metadata: Secret metadata
    """
    # Log rotation start
    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"Starting rotation for secret: {secret_path}")
    
    # Could implement additional checks here
    # - Verify no active transactions using the secret
    # - Create backup of current secret
    # - Notify dependent services


async def post_rotation_callback(secret_path: str, new_value: str, metadata: Any) -> None:
    """Called after rotating a secret.
    
    Args:
        secret_path: Path of the secret that was rotated
        new_value: New secret value
        metadata: Secret metadata
    """
    import logging
    logger = logging.getLogger(__name__)
    
    # Detect secret type
    secret_type = detect_secret_type(secret_path)
    
    # Type-specific post-rotation actions
    if secret_type == SecretType.DATABASE_PASSWORD:
        # Update database user password
        logger.info(f"Updating database password for: {secret_path}")
        # Implementation would update the actual database
        
    elif secret_type == SecretType.API_KEY:
        # Notify API consumers
        logger.info(f"Notifying API consumers about key rotation: {secret_path}")
        # Implementation would send notifications
        
    elif secret_type == SecretType.TLS_CERT:
        # Reload services using the certificate
        logger.info(f"Reloading services for new certificate: {secret_path}")
        # Implementation would reload web servers, etc.
    
    logger.info(f"Completed rotation for secret: {secret_path}")


async def rotation_notification_callback(
    event_type: str,
    secret_path: str,
    details: Dict[str, Any]
) -> None:
    """Send notifications about rotation events.
    
    Args:
        event_type: Type of rotation event
        secret_path: Path of the affected secret
        details: Event details
    """
    import logging
    from src.mcp.communication.slack_server import SlackNotificationMCPServer
    
    logger = logging.getLogger(__name__)
    
    # Prepare notification message
    if event_type == "rotation_due":
        message = f"Secret rotation due soon: {secret_path}\nDue date: {details.get('due_date')}"
        priority = "medium"
    elif event_type == "rotation_overdue":
        message = f"URGENT: Secret rotation overdue: {secret_path}\nDue date: {details.get('due_date')}"
        priority = "high"
    elif event_type == "rotation_completed":
        message = f"Secret rotated successfully: {secret_path}\nRotated at: {details.get('rotated_at')}"
        priority = "low"
    elif event_type == "rotation_failed":
        message = f"ERROR: Secret rotation failed: {secret_path}\nError: {details.get('error')}"
        priority = "critical"
    else:
        message = f"Secret rotation event: {event_type} for {secret_path}"
        priority = "low"
    
    # Send notifications through configured channels
    channels = details.get("notification_channels", ["email", "slack"])
    
    if "slack" in channels:
        # Send Slack notification
        try:
            # Would use actual Slack integration
            logger.info(f"Sending Slack notification: {message}")
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
    
    if "email" in channels:
        # Send email notification
        try:
            # Would use actual email integration
            logger.info(f"Sending email notification: {message}")
        except Exception as e:
            logger.error(f"Failed to send email notification: {e}")
    
    if "pagerduty" in channels and priority in ["high", "critical"]:
        # Send PagerDuty alert for high priority
        try:
            # Would use actual PagerDuty integration
            logger.info(f"Sending PagerDuty alert: {message}")
        except Exception as e:
            logger.error(f"Failed to send PagerDuty alert: {e}")


# Validation functions for different secret types
def validate_api_key(value: str) -> bool:
    """Validate API key format."""
    # Check minimum length and character set
    return len(value) >= 32 and value.replace("-", "").replace("_", "").isalnum()


def validate_database_password(value: str) -> bool:
    """Validate database password strength."""
    # Check password complexity
    import re
    if len(value) < 16:
        return False
    if not re.search(r"[A-Z]", value):
        return False
    if not re.search(r"[a-z]", value):
        return False
    if not re.search(r"[0-9]", value):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", value):
        return False
    return True


# Add validation functions to policies
DEFAULT_ROTATION_POLICIES[SecretType.API_KEY].validation_func = validate_api_key
DEFAULT_ROTATION_POLICIES[SecretType.DATABASE_PASSWORD].validation_func = validate_database_password