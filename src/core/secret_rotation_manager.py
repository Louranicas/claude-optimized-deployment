"""
Automatic Secret Rotation Manager

This module manages automatic secret rotation based on policies,
schedules, and compliance requirements.
"""

import asyncio
import json
from typing import Dict, List, Optional, Any, Callable, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict
import threading

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger
from prometheus_client import Counter, Gauge, Histogram

from src.core.vault_client import EnhancedVaultClient, VaultConfig
from src.core.secrets_rotation_config import (
    RotationPolicy, SecretType, RotationSchedule,
    get_rotation_config, detect_secret_type
)
from src.core.secrets_audit import SecretAuditLogger, SecretOperation
from src.core.logging_config import get_logger
from src.core.exceptions import SecurityError
from src.monitoring.alerts import AlertManager

logger = get_logger(__name__)

# Metrics
rotation_scheduled = Gauge('secret_rotation_scheduled_total', 'Number of secrets scheduled for rotation')
rotation_completed = Counter('secret_rotation_completed_total', 'Number of completed rotations', ['secret_type', 'status'])
rotation_duration = Histogram('secret_rotation_duration_seconds', 'Secret rotation duration', ['secret_type'])
rotation_overdue = Gauge('secret_rotation_overdue_total', 'Number of overdue rotations')
rotation_errors = Counter('secret_rotation_errors_total', 'Number of rotation errors', ['secret_type', 'error_type'])


@dataclass
class RotationState:
    """State of a secret rotation."""
    secret_path: str
    secret_type: SecretType
    last_rotation: Optional[datetime] = None
    next_rotation: Optional[datetime] = None
    rotation_count: int = 0
    failure_count: int = 0
    last_failure: Optional[datetime] = None
    last_error: Optional[str] = None
    is_overdue: bool = False
    approval_status: Optional[str] = None
    approvers: List[str] = field(default_factory=list)


@dataclass
class RotationRequest:
    """Request for secret rotation approval."""
    request_id: str
    secret_path: str
    secret_type: SecretType
    requested_by: str
    requested_at: datetime
    reason: str
    approved_by: List[str] = field(default_factory=list)
    rejected_by: List[str] = field(default_factory=list)
    status: str = "pending"  # pending, approved, rejected, expired
    expires_at: Optional[datetime] = None


class RotationManager:
    """Manages automatic secret rotation."""
    
    def __init__(
        self,
        vault_client: EnhancedVaultClient,
        audit_logger: SecretAuditLogger,
        alert_manager: Optional[AlertManager] = None,
        config: Optional[Dict[str, Any]] = None
    ):
        """Initialize rotation manager.
        
        Args:
            vault_client: Enhanced Vault client
            audit_logger: Secret audit logger
            alert_manager: Alert manager for notifications
            config: Rotation configuration
        """
        self.vault_client = vault_client
        self.audit_logger = audit_logger
        self.alert_manager = alert_manager
        self.config = config or get_rotation_config()
        
        # Rotation state tracking
        self._rotation_states: Dict[str, RotationState] = {}
        self._rotation_requests: Dict[str, RotationRequest] = {}
        self._state_lock = threading.RLock()
        
        # Scheduler for automatic rotations
        self.scheduler = AsyncIOScheduler()
        
        # Rotation functions registry
        self._rotation_functions: Dict[SecretType, Callable] = {
            SecretType.API_KEY: self._rotate_api_key,
            SecretType.DATABASE_PASSWORD: self._rotate_database_password,
            SecretType.SERVICE_TOKEN: self._rotate_service_token,
            SecretType.ENCRYPTION_KEY: self._rotate_encryption_key,
            SecretType.WEBHOOK_SECRET: self._rotate_webhook_secret,
            SecretType.OAUTH_SECRET: self._rotate_oauth_secret,
            SecretType.SSH_KEY: self._rotate_ssh_key,
            SecretType.TLS_CERT: self._rotate_tls_cert,
            SecretType.SIGNING_KEY: self._rotate_signing_key
        }
        
        # Initialize rotation tracking
        self._initialized = False
        
    async def initialize(self):
        """Initialize rotation manager and start scheduler."""
        if self._initialized:
            return
        
        # Discover existing secrets and their rotation state
        await self._discover_secrets()
        
        # Schedule rotations based on policies
        await self._schedule_rotations()
        
        # Start scheduler
        self.scheduler.start()
        
        # Start monitoring task
        asyncio.create_task(self._monitor_rotations())
        
        self._initialized = True
        logger.info("Rotation manager initialized")
    
    async def _discover_secrets(self):
        """Discover existing secrets and their rotation state."""
        try:
            # List all secrets recursively
            secrets = await self._list_all_secrets()
            
            for secret_path in secrets:
                # Detect secret type
                secret_type = detect_secret_type(secret_path)
                
                # Skip if in excluded patterns
                if self._is_excluded(secret_path):
                    continue
                
                # Get secret metadata
                metadata = self.vault_client.get_secret_metadata(secret_path)
                
                # Initialize rotation state
                state = RotationState(
                    secret_path=secret_path,
                    secret_type=secret_type,
                    last_rotation=metadata.updated_time if metadata else None
                )
                
                # Calculate next rotation
                policy = self.config['policies'].get(secret_type)
                if policy and policy.auto_rotate:
                    if state.last_rotation:
                        state.next_rotation = state.last_rotation + policy.rotation_interval
                        state.is_overdue = datetime.utcnow() > state.next_rotation
                    else:
                        # Never rotated, schedule immediately
                        state.next_rotation = datetime.utcnow()
                        state.is_overdue = True
                
                with self._state_lock:
                    self._rotation_states[secret_path] = state
            
            rotation_scheduled.set(len(self._rotation_states))
            rotation_overdue.set(sum(1 for s in self._rotation_states.values() if s.is_overdue))
            
            logger.info(f"Discovered {len(secrets)} secrets for rotation tracking")
            
        except Exception as e:
            logger.error(f"Error discovering secrets: {e}")
            rotation_errors.labels(secret_type='unknown', error_type='discovery').inc()
    
    async def _list_all_secrets(self, path: str = "") -> List[str]:
        """Recursively list all secrets."""
        secrets = []
        
        try:
            items = self.vault_client.list_secrets(path)
            
            for item in items:
                full_path = f"{path}/{item}" if path else item
                
                if item.endswith('/'):
                    # Directory, recurse
                    secrets.extend(await self._list_all_secrets(full_path.rstrip('/')))
                else:
                    # Secret
                    secrets.append(full_path)
            
        except Exception as e:
            logger.error(f"Error listing secrets at {path}: {e}")
        
        return secrets
    
    async def _schedule_rotations(self):
        """Schedule automatic rotations based on policies."""
        schedule = self.config['schedule']
        
        if not schedule.enabled:
            logger.info("Automatic rotation is disabled")
            return
        
        with self._state_lock:
            for secret_path, state in self._rotation_states.items():
                policy = self.config['policies'].get(state.secret_type)
                
                if not policy or not policy.auto_rotate:
                    continue
                
                # Calculate rotation time considering maintenance windows
                next_rotation = self._calculate_next_rotation_time(
                    state,
                    policy,
                    schedule
                )
                
                if next_rotation:
                    # Schedule rotation job
                    job_id = f"rotate_{secret_path}"
                    
                    self.scheduler.add_job(
                        self._execute_rotation,
                        trigger=IntervalTrigger(seconds=(next_rotation - datetime.utcnow()).total_seconds()),
                        id=job_id,
                        args=[secret_path],
                        replace_existing=True,
                        misfire_grace_time=3600  # 1 hour grace time
                    )
                    
                    state.next_rotation = next_rotation
                    
                    logger.info(f"Scheduled rotation for {secret_path} at {next_rotation}")
    
    def _calculate_next_rotation_time(
        self,
        state: RotationState,
        policy: RotationPolicy,
        schedule: RotationSchedule
    ) -> Optional[datetime]:
        """Calculate next rotation time considering maintenance windows."""
        if state.last_rotation:
            base_time = state.last_rotation + policy.rotation_interval
        else:
            base_time = datetime.utcnow()
        
        # Check if immediate rotation is needed
        for pattern in schedule.immediate_patterns:
            if pattern in state.secret_path:
                return datetime.utcnow()
        
        # Adjust for maintenance windows
        if schedule.maintenance_windows:
            # Find next maintenance window
            for window in schedule.maintenance_windows:
                # This is simplified; real implementation would parse window spec
                # and find the next occurrence
                pass
        
        # Check blackout windows
        if schedule.blackout_windows:
            # Adjust if rotation falls in blackout window
            for blackout in schedule.blackout_windows:
                # This is simplified; real implementation would check blackouts
                pass
        
        return base_time
    
    async def _execute_rotation(self, secret_path: str):
        """Execute rotation for a secret."""
        with self._state_lock:
            state = self._rotation_states.get(secret_path)
            
        if not state:
            logger.error(f"No rotation state found for {secret_path}")
            return
        
        policy = self.config['policies'].get(state.secret_type)
        if not policy:
            logger.error(f"No rotation policy found for {state.secret_type}")
            return
        
        # Check if approval is required
        if policy.requires_approval and state.approval_status != "approved":
            await self._request_approval(state, policy)
            return
        
        # Execute rotation
        try:
            with rotation_duration.labels(secret_type=state.secret_type.value).time():
                # Pre-rotation hook
                if policy.pre_rotation_hook:
                    await policy.pre_rotation_hook(secret_path, state)
                
                # Get rotation function
                rotation_func = self._rotation_functions.get(state.secret_type)
                if not rotation_func:
                    raise ValueError(f"No rotation function for {state.secret_type}")
                
                # Execute rotation
                new_secret = await rotation_func(secret_path, state, policy)
                
                # Validate new secret
                if policy.validation_func and not policy.validation_func(new_secret):
                    raise ValueError("New secret failed validation")
                
                # Post-rotation hook
                if policy.post_rotation_hook:
                    await policy.post_rotation_hook(secret_path, new_secret, state)
                
                # Update state
                with self._state_lock:
                    state.last_rotation = datetime.utcnow()
                    state.rotation_count += 1
                    state.failure_count = 0
                    state.last_failure = None
                    state.last_error = None
                    state.is_overdue = False
                    state.approval_status = None
                
                # Log success
                await self.audit_logger.log_rotation_event(
                    secret_path=secret_path,
                    rotation_type="automatic",
                    success=True,
                    new_version=state.rotation_count
                )
                
                rotation_completed.labels(secret_type=state.secret_type.value, status='success').inc()
                
                # Schedule next rotation
                await self._schedule_next_rotation(secret_path, state, policy)
                
                logger.info(f"Successfully rotated secret: {secret_path}")
                
        except Exception as e:
            # Update failure state
            with self._state_lock:
                state.failure_count += 1
                state.last_failure = datetime.utcnow()
                state.last_error = str(e)
            
            # Log failure
            await self.audit_logger.log_rotation_event(
                secret_path=secret_path,
                rotation_type="automatic",
                success=False,
                error=str(e)
            )
            
            rotation_completed.labels(secret_type=state.secret_type.value, status='failure').inc()
            rotation_errors.labels(secret_type=state.secret_type.value, error_type=type(e).__name__).inc()
            
            # Send alert
            if self.alert_manager:
                await self.alert_manager.send_alert(
                    severity="error",
                    title=f"Secret rotation failed: {secret_path}",
                    description=f"Error: {e}
Failure count: {state.failure_count}",
                    labels={
                        "secret_type": state.secret_type.value,
                        "secret_path": secret_path
                    }
                )
            
            logger.error(f"Failed to rotate secret {secret_path}: {e}")
            
            # Retry with exponential backoff
            retry_delay = min(300 * (2 ** (state.failure_count - 1)), 3600)  # Max 1 hour
            self.scheduler.add_job(
                self._execute_rotation,
                trigger=IntervalTrigger(seconds=retry_delay),
                id=f"retry_rotate_{secret_path}",
                args=[secret_path],
                replace_existing=True
            )
    
    async def _schedule_next_rotation(
        self,
        secret_path: str,
        state: RotationState,
        policy: RotationPolicy
    ):
        """Schedule the next rotation for a secret."""
        next_rotation = datetime.utcnow() + policy.rotation_interval
        
        # Adjust for maintenance windows
        schedule = self.config['schedule']
        next_rotation = self._calculate_next_rotation_time(state, policy, schedule)
        
        if next_rotation:
            job_id = f"rotate_{secret_path}"
            
            self.scheduler.add_job(
                self._execute_rotation,
                trigger=IntervalTrigger(
                    seconds=(next_rotation - datetime.utcnow()).total_seconds()
                ),
                id=job_id,
                args=[secret_path],
                replace_existing=True
            )
            
            state.next_rotation = next_rotation
    
    async def _request_approval(self, state: RotationState, policy: RotationPolicy):
        """Request approval for rotation."""
        request_id = f"rot_req_{state.secret_path}_{datetime.utcnow().timestamp()}"
        
        request = RotationRequest(
            request_id=request_id,
            secret_path=state.secret_path,
            secret_type=state.secret_type,
            requested_by="system",
            requested_at=datetime.utcnow(),
            reason="Scheduled rotation",
            expires_at=datetime.utcnow() + timedelta(days=7)
        )
        
        with self._state_lock:
            self._rotation_requests[request_id] = request
        
        # Send approval request notifications
        if self.alert_manager:
            for approver in policy.approvers:
                await self.alert_manager.send_alert(
                    severity="info",
                    title=f"Secret rotation approval required: {state.secret_path}",
                    description=f"Secret type: {state.secret_type.value}
"
                               f"Request ID: {request_id}
"
                               f"Expires: {request.expires_at}",
                    labels={
                        "approver": approver,
                        "secret_type": state.secret_type.value,
                        "request_id": request_id
                    }
                )
        
        logger.info(f"Approval requested for rotation of {state.secret_path}")
    
    async def approve_rotation(
        self,
        request_id: str,
        approver: str,
        comment: Optional[str] = None
    ) -> bool:
        """Approve a rotation request.
        
        Args:
            request_id: Rotation request ID
            approver: Approver identifier
            comment: Optional approval comment
            
        Returns:
            True if approved successfully
        """
        with self._state_lock:
            request = self._rotation_requests.get(request_id)
            
        if not request:
            logger.error(f"Rotation request not found: {request_id}")
            return False
        
        if request.status != "pending":
            logger.error(f"Rotation request {request_id} is not pending: {request.status}")
            return False
        
        if datetime.utcnow() > request.expires_at:
            request.status = "expired"
            logger.error(f"Rotation request {request_id} has expired")
            return False
        
        # Record approval
        request.approved_by.append(approver)
        
        # Check if we have enough approvals
        state = self._rotation_states.get(request.secret_path)
        policy = self.config['policies'].get(request.secret_type)
        
        if policy and len(request.approved_by) >= len(policy.approvers):
            request.status = "approved"
            state.approval_status = "approved"
            
            # Log approval
            await self.audit_logger.log_secret_access(
                user_id=approver,
                secret_path=request.secret_path,
                operation=SecretOperation.APPROVE,
                access_level="critical",
                success=True,
                details={
                    "request_id": request_id,
                    "comment": comment
                }
            )
            
            # Execute rotation
            asyncio.create_task(self._execute_rotation(request.secret_path))
            
            logger.info(f"Rotation approved for {request.secret_path} by {approver}")
            return True
        
        return False
    
    async def _monitor_rotations(self):
        """Monitor rotation states and send alerts."""
        while True:
            try:
                overdue_count = 0
                
                with self._state_lock:
                    for secret_path, state in self._rotation_states.items():
                        if state.next_rotation and datetime.utcnow() > state.next_rotation:
                            state.is_overdue = True
                            overdue_count += 1
                            
                            # Send overdue alert
                            if self.alert_manager:
                                await self.alert_manager.send_alert(
                                    severity="warning",
                                    title=f"Secret rotation overdue: {secret_path}",
                                    description=f"Due: {state.next_rotation}
"
                                               f"Type: {state.secret_type.value}",
                                    labels={
                                        "secret_type": state.secret_type.value,
                                        "secret_path": secret_path
                                    }
                                )
                
                rotation_overdue.set(overdue_count)
                
                # Check every 5 minutes
                await asyncio.sleep(300)
                
            except Exception as e:
                logger.error(f"Error in rotation monitoring: {e}")
                await asyncio.sleep(60)
    
    def _is_excluded(self, secret_path: str) -> bool:
        """Check if secret is excluded from rotation."""
        schedule = self.config['schedule']
        
        for pattern in schedule.excluded_patterns:
            if pattern in secret_path:
                return True
        
        return False
    
    # Rotation functions for different secret types
    
    async def _rotate_api_key(
        self,
        secret_path: str,
        state: RotationState,
        policy: RotationPolicy
    ) -> Dict[str, Any]:
        """Rotate an API key."""
        from src.core.vault_client import rotate_api_key
        
        current_secret = self.vault_client.read_secret(secret_path)
        new_secret = rotate_api_key(current_secret)
        
        # Keep old versions based on policy
        versions_to_keep = policy.max_versions - 1
        if versions_to_keep > 0:
            new_secret['previous_keys'] = current_secret.get('previous_keys', [])[-versions_to_keep:]
            new_secret['previous_keys'].append(current_secret.get('key'))
        
        self.vault_client.write_secret(secret_path, new_secret)
        
        return new_secret
    
    async def _rotate_database_password(
        self,
        secret_path: str,
        state: RotationState,
        policy: RotationPolicy
    ) -> Dict[str, Any]:
        """Rotate database password."""
        from src.core.vault_client import rotate_database_password
        
        current_secret = self.vault_client.read_secret(secret_path)
        new_secret = rotate_database_password(current_secret)
        
        # Update database with new password
        # This would integrate with database management
        
        self.vault_client.write_secret(secret_path, new_secret)
        
        return new_secret
    
    async def _rotate_service_token(
        self,
        secret_path: str,
        state: RotationState,
        policy: RotationPolicy
    ) -> Dict[str, Any]:
        """Rotate service token."""
        from src.core.vault_client import generate_api_key
        
        current_secret = self.vault_client.read_secret(secret_path)
        new_secret = current_secret.copy()
        new_secret['token'] = generate_api_key(48)
        new_secret['rotated_at'] = datetime.utcnow().isoformat()
        
        self.vault_client.write_secret(secret_path, new_secret)
        
        return new_secret
    
    async def _rotate_encryption_key(
        self,
        secret_path: str,
        state: RotationState,
        policy: RotationPolicy
    ) -> Dict[str, Any]:
        """Rotate encryption key."""
        from src.core.vault_client import generate_encryption_key
        
        current_secret = self.vault_client.read_secret(secret_path)
        new_secret = current_secret.copy()
        
        # Generate new key
        new_secret['key'] = generate_encryption_key()
        new_secret['key_id'] = f"key_{datetime.utcnow().timestamp()}"
        
        # Keep old keys for decryption
        old_keys = current_secret.get('old_keys', [])
        old_keys.append({
            'key': current_secret.get('key'),
            'key_id': current_secret.get('key_id'),
            'retired_at': datetime.utcnow().isoformat()
        })
        
        # Keep only max_versions
        new_secret['old_keys'] = old_keys[-(policy.max_versions - 1):]
        
        self.vault_client.write_secret(secret_path, new_secret)
        
        return new_secret
    
    async def _rotate_webhook_secret(
        self,
        secret_path: str,
        state: RotationState,
        policy: RotationPolicy
    ) -> Dict[str, Any]:
        """Rotate webhook secret."""
        from src.core.vault_client import generate_api_key
        
        current_secret = self.vault_client.read_secret(secret_path)
        new_secret = current_secret.copy()
        new_secret['secret'] = generate_api_key(32)
        new_secret['rotated_at'] = datetime.utcnow().isoformat()
        
        self.vault_client.write_secret(secret_path, new_secret)
        
        return new_secret
    
    async def _rotate_oauth_secret(
        self,
        secret_path: str,
        state: RotationState,
        policy: RotationPolicy
    ) -> Dict[str, Any]:
        """Rotate OAuth secret."""
        from src.core.vault_client import generate_api_key
        
        current_secret = self.vault_client.read_secret(secret_path)
        new_secret = current_secret.copy()
        new_secret['client_secret'] = generate_api_key(64)
        new_secret['rotated_at'] = datetime.utcnow().isoformat()
        
        # OAuth secrets often need provider-side update
        # This would integrate with OAuth provider API
        
        self.vault_client.write_secret(secret_path, new_secret)
        
        return new_secret
    
    async def _rotate_ssh_key(
        self,
        secret_path: str,
        state: RotationState,
        policy: RotationPolicy
    ) -> Dict[str, Any]:
        """Rotate SSH key."""
        import subprocess
        import tempfile
        
        current_secret = self.vault_client.read_secret(secret_path)
        new_secret = current_secret.copy()
        
        # Generate new SSH key pair
        with tempfile.TemporaryDirectory() as tmpdir:
            private_key_path = f"{tmpdir}/id_rsa"
            public_key_path = f"{tmpdir}/id_rsa.pub"
            
            # Generate key
            subprocess.run([
                "ssh-keygen", "-t", "rsa", "-b", "4096",
                "-f", private_key_path, "-N", "", "-C", f"rotated@{datetime.utcnow().isoformat()}"
            ], check=True)
            
            # Read keys
            with open(private_key_path, 'r') as f:
                new_secret['private_key'] = f.read()
            
            with open(public_key_path, 'r') as f:
                new_secret['public_key'] = f.read()
        
        new_secret['rotated_at'] = datetime.utcnow().isoformat()
        
        self.vault_client.write_secret(secret_path, new_secret)
        
        return new_secret
    
    async def _rotate_tls_cert(
        self,
        secret_path: str,
        state: RotationState,
        policy: RotationPolicy
    ) -> Dict[str, Any]:
        """Rotate TLS certificate."""
        # This would integrate with certificate authority
        # For now, just placeholder
        current_secret = self.vault_client.read_secret(secret_path)
        new_secret = current_secret.copy()
        new_secret['rotated_at'] = datetime.utcnow().isoformat()
        
        self.vault_client.write_secret(secret_path, new_secret)
        
        return new_secret
    
    async def _rotate_signing_key(
        self,
        secret_path: str,
        state: RotationState,
        policy: RotationPolicy
    ) -> Dict[str, Any]:
        """Rotate signing key."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        
        current_secret = self.vault_client.read_secret(secret_path)
        new_secret = current_secret.copy()
        
        # Generate new RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )
        
        # Serialize private key
        new_secret['private_key'] = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        # Serialize public key
        public_key = private_key.public_key()
        new_secret['public_key'] = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        new_secret['key_id'] = f"sign_{datetime.utcnow().timestamp()}"
        new_secret['rotated_at'] = datetime.utcnow().isoformat()
        
        self.vault_client.write_secret(secret_path, new_secret)
        
        return new_secret
    
    async def get_rotation_status(self) -> Dict[str, Any]:
        """Get current rotation status.
        
        Returns:
            Rotation status summary
        """
        with self._state_lock:
            total_secrets = len(self._rotation_states)
            overdue = sum(1 for s in self._rotation_states.values() if s.is_overdue)
            failed = sum(1 for s in self._rotation_states.values() if s.failure_count > 0)
            
            by_type = defaultdict(int)
            for state in self._rotation_states.values():
                by_type[state.secret_type.value] += 1
            
            pending_approvals = sum(
                1 for r in self._rotation_requests.values()
                if r.status == "pending"
            )
            
            return {
                "total_secrets": total_secrets,
                "overdue_rotations": overdue,
                "failed_rotations": failed,
                "pending_approvals": pending_approvals,
                "secrets_by_type": dict(by_type),
                "scheduler_running": self.scheduler.running
            }
    
    async def close(self):
        """Shutdown rotation manager."""
        self.scheduler.shutdown(wait=False)
        logger.info("Rotation manager closed")