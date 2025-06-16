"""
Specialized audit logging for secret access and management.

This module provides enhanced audit capabilities specifically for secret operations,
including detailed tracking, compliance reporting, and security analytics.
"""

import json
import hashlib
from typing import Dict, Any, List, Optional, Set
from datetime import datetime, timedelta
from collections import defaultdict
from dataclasses import dataclass, field
import asyncio
from enum import Enum

from src.auth.audit import AuditLogger, AuditEvent, AuditCategory
from src.core.logging_config import get_logger
from src.core.secrets_manager import SecretAccessLevel

__all__ = [
    "SecretAuditLogger",
    "SecretOperation",
    "SecretAuditReport",
    "ComplianceReport",
    "get_secret_audit_logger"
]

logger = get_logger(__name__)


class SecretOperation(Enum):
    """Types of secret operations for detailed tracking."""
    READ = "read"
    WRITE = "write"
    UPDATE = "update"
    DELETE = "delete"
    ROTATE = "rotate"
    LIST = "list"
    EXPORT = "export"
    IMPORT = "import"
    APPROVE = "approve"
    DENY = "deny"


@dataclass
class SecretAccessPattern:
    """Tracks access patterns for anomaly detection."""
    user_id: str
    secret_path: str
    access_times: List[datetime] = field(default_factory=list)
    operations: List[SecretOperation] = field(default_factory=list)
    ip_addresses: Set[str] = field(default_factory=set)
    user_agents: Set[str] = field(default_factory=set)
    
    def add_access(
        self,
        operation: SecretOperation,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> None:
        """Record a new access."""
        self.access_times.append(datetime.utcnow())
        self.operations.append(operation)
        if ip_address:
            self.ip_addresses.add(ip_address)
        if user_agent:
            self.user_agents.add(user_agent)


@dataclass
class SecretAuditReport:
    """Comprehensive audit report for secret access."""
    start_date: datetime
    end_date: datetime
    total_accesses: int = 0
    unique_users: int = 0
    unique_secrets: int = 0
    operations_breakdown: Dict[str, int] = field(default_factory=dict)
    access_by_level: Dict[str, int] = field(default_factory=dict)
    top_accessed_secrets: List[Dict[str, Any]] = field(default_factory=list)
    suspicious_activities: List[Dict[str, Any]] = field(default_factory=list)
    failed_attempts: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ComplianceReport:
    """Compliance-focused report for regulatory requirements."""
    report_date: datetime
    compliance_period: timedelta
    rotation_compliance: Dict[str, Any] = field(default_factory=dict)
    access_control_compliance: Dict[str, Any] = field(default_factory=dict)
    audit_trail_completeness: float = 0.0
    policy_violations: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class SecretAuditLogger:
    """Enhanced audit logger for secret operations."""
    
    def __init__(self, base_audit_logger: Optional[AuditLogger] = None):
        """Initialize secret audit logger.
        
        Args:
            base_audit_logger: Base audit logger instance
        """
        self.base_logger = base_audit_logger
        self._access_patterns: Dict[str, SecretAccessPattern] = {}
        self._failed_attempts: List[Dict[str, Any]] = []
        self._audit_cache: List[AuditEvent] = []
        self._cache_lock = asyncio.Lock()
        self._flush_interval = 60  # Flush cache every minute
        self._flush_task: Optional[asyncio.Task] = None
        
    async def initialize(self) -> None:
        """Initialize the audit logger and start background tasks."""
        if self.base_logger:
            await self.base_logger.initialize()
        
        # Start cache flush task
        self._flush_task = asyncio.create_task(self._flush_cache_periodically())
        
        logger.info("Secret audit logger initialized")
    
    async def log_secret_access(
        self,
        user_id: str,
        secret_path: str,
        operation: SecretOperation,
        access_level: SecretAccessLevel,
        success: bool = True,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> None:
        """Log a secret access event with enhanced tracking.
        
        Args:
            user_id: User performing the operation
            secret_path: Path to the secret
            operation: Type of operation
            access_level: Security level of the secret
            success: Whether operation succeeded
            details: Additional event details
            ip_address: Client IP address
            user_agent: Client user agent
        """
        # Create audit event
        event_details = {
            "operation": operation.value,
            "access_level": access_level.value,
            "success": success,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "secret_hash": self._hash_secret_path(secret_path)  # Hash for privacy
        }
        
        if details:
            event_details.update(details)
        
        event = AuditEvent(
            category=AuditCategory.SECRET_ACCESS,
            action=f"secret_{operation.value}",
            user_id=user_id,
            resource_type="secret",
            resource_id=secret_path,
            success=success,
            details=event_details
        )
        
        # Add to cache
        async with self._cache_lock:
            self._audit_cache.append(event)
        
        # Track access patterns
        if success:
            await self._track_access_pattern(
                user_id, secret_path, operation, ip_address, user_agent
            )
        else:
            await self._track_failed_attempt(
                user_id, secret_path, operation, ip_address, user_agent
            )
        
        # Check for anomalies
        await self._check_anomalies(user_id, secret_path, operation)
    
    async def log_rotation_event(
        self,
        secret_path: str,
        rotation_type: str,
        success: bool,
        old_version: Optional[int] = None,
        new_version: Optional[int] = None,
        error: Optional[str] = None
    ) -> None:
        """Log secret rotation event.
        
        Args:
            secret_path: Path to the rotated secret
            rotation_type: Type of rotation (auto/manual)
            success: Whether rotation succeeded
            old_version: Previous version number
            new_version: New version number
            error: Error message if failed
        """
        await self.log_secret_access(
            user_id="system",
            secret_path=secret_path,
            operation=SecretOperation.ROTATE,
            access_level=SecretAccessLevel.CRITICAL,
            success=success,
            details={
                "rotation_type": rotation_type,
                "old_version": old_version,
                "new_version": new_version,
                "error": error
            }
        )
    
    async def generate_audit_report(
        self,
        start_date: datetime,
        end_date: datetime,
        user_filter: Optional[str] = None,
        secret_filter: Optional[str] = None
    ) -> SecretAuditReport:
        """Generate comprehensive audit report.
        
        Args:
            start_date: Report start date
            end_date: Report end date
            user_filter: Filter by user ID
            secret_filter: Filter by secret path pattern
            
        Returns:
            Secret audit report
        """
        report = SecretAuditReport(start_date=start_date, end_date=end_date)
        
        # Ensure cache is flushed
        await self._flush_cache()
        
        if self.base_logger:
            # Query audit events from storage
            events = await self.base_logger.query_events(
                start_date=start_date,
                end_date=end_date,
                category=AuditCategory.SECRET_ACCESS,
                user_id=user_filter
            )
            
            # Process events
            unique_users = set()
            unique_secrets = set()
            operations_count = defaultdict(int)
            access_by_level = defaultdict(int)
            secret_access_count = defaultdict(int)
            
            for event in events:
                if secret_filter and secret_filter not in event.resource_id:
                    continue
                
                report.total_accesses += 1
                unique_users.add(event.user_id)
                unique_secrets.add(event.resource_id)
                
                details = event.details or {}
                operation = details.get("operation", "unknown")
                operations_count[operation] += 1
                
                access_level = details.get("access_level", "unknown")
                access_by_level[access_level] += 1
                
                if details.get("success", True):
                    secret_access_count[event.resource_id] += 1
            
            report.unique_users = len(unique_users)
            report.unique_secrets = len(unique_secrets)
            report.operations_breakdown = dict(operations_count)
            report.access_by_level = dict(access_by_level)
            
            # Top accessed secrets
            top_secrets = sorted(
                secret_access_count.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
            
            report.top_accessed_secrets = [
                {"secret_path": path, "access_count": count}
                for path, count in top_secrets
            ]
            
            # Add suspicious activities
            report.suspicious_activities = await self._identify_suspicious_activities(
                start_date, end_date
            )
            
            # Add failed attempts
            report.failed_attempts = [
                attempt for attempt in self._failed_attempts
                if start_date <= attempt["timestamp"] <= end_date
            ]
        
        return report
    
    async def generate_compliance_report(
        self,
        compliance_period: timedelta = timedelta(days=30)
    ) -> ComplianceReport:
        """Generate compliance-focused report.
        
        Args:
            compliance_period: Period to check compliance
            
        Returns:
            Compliance report
        """
        end_date = datetime.utcnow()
        start_date = end_date - compliance_period
        
        report = ComplianceReport(
            report_date=end_date,
            compliance_period=compliance_period
        )
        
        if self.base_logger:
            # Check rotation compliance
            rotation_events = await self.base_logger.query_events(
                start_date=start_date,
                end_date=end_date,
                action="secret_rotate"
            )
            
            total_secrets = len(set(e.resource_id for e in rotation_events))
            rotated_secrets = len([e for e in rotation_events if e.success])
            
            report.rotation_compliance = {
                "total_secrets": total_secrets,
                "rotated_secrets": rotated_secrets,
                "compliance_rate": rotated_secrets / total_secrets if total_secrets > 0 else 0,
                "overdue_rotations": await self._get_overdue_rotations()
            }
            
            # Check access control compliance
            access_events = await self.base_logger.query_events(
                start_date=start_date,
                end_date=end_date,
                category=AuditCategory.SECRET_ACCESS
            )
            
            unauthorized_accesses = [
                e for e in access_events
                if not e.success and e.details.get("reason") == "unauthorized"
            ]
            
            report.access_control_compliance = {
                "total_accesses": len(access_events),
                "unauthorized_attempts": len(unauthorized_accesses),
                "compliance_rate": 1 - (len(unauthorized_accesses) / len(access_events))
                if access_events else 1.0
            }
            
            # Calculate audit trail completeness
            expected_fields = ["user_id", "timestamp", "operation", "success", "ip_address"]
            complete_events = [
                e for e in access_events
                if all(e.details.get(field) for field in expected_fields)
            ]
            
            report.audit_trail_completeness = (
                len(complete_events) / len(access_events)
                if access_events else 0.0
            )
            
            # Identify policy violations
            report.policy_violations = await self._identify_policy_violations(
                access_events
            )
            
            # Generate recommendations
            report.recommendations = self._generate_recommendations(report)
        
        return report
    
    async def _track_access_pattern(
        self,
        user_id: str,
        secret_path: str,
        operation: SecretOperation,
        ip_address: Optional[str],
        user_agent: Optional[str]
    ) -> None:
        """Track access patterns for anomaly detection."""
        pattern_key = f"{user_id}:{secret_path}"
        
        if pattern_key not in self._access_patterns:
            self._access_patterns[pattern_key] = SecretAccessPattern(
                user_id=user_id,
                secret_path=secret_path
            )
        
        pattern = self._access_patterns[pattern_key]
        pattern.add_access(operation, ip_address, user_agent)
    
    async def _track_failed_attempt(
        self,
        user_id: str,
        secret_path: str,
        operation: SecretOperation,
        ip_address: Optional[str],
        user_agent: Optional[str]
    ) -> None:
        """Track failed access attempts."""
        self._failed_attempts.append({
            "timestamp": datetime.utcnow(),
            "user_id": user_id,
            "secret_path": secret_path,
            "operation": operation.value,
            "ip_address": ip_address,
            "user_agent": user_agent
        })
        
        # Keep only recent failed attempts (last 7 days)
        cutoff = datetime.utcnow() - timedelta(days=7)
        self._failed_attempts = [
            a for a in self._failed_attempts
            if a["timestamp"] > cutoff
        ]
    
    async def _check_anomalies(
        self,
        user_id: str,
        secret_path: str,
        operation: SecretOperation
    ) -> None:
        """Check for anomalous access patterns."""
        pattern_key = f"{user_id}:{secret_path}"
        pattern = self._access_patterns.get(pattern_key)
        
        if not pattern or len(pattern.access_times) < 5:
            return
        
        # Check for rapid access (more than 10 accesses in 1 minute)
        recent_accesses = [
            t for t in pattern.access_times
            if t > datetime.utcnow() - timedelta(minutes=1)
        ]
        
        if len(recent_accesses) > 10:
            logger.warning(
                f"Anomaly detected: Rapid access to {secret_path} by {user_id} "
                f"({len(recent_accesses)} accesses in 1 minute)"
            )
            
            # Log anomaly event
            await self.log_secret_access(
                user_id="system",
                secret_path=secret_path,
                operation=SecretOperation.READ,
                access_level=SecretAccessLevel.CRITICAL,
                success=True,
                details={
                    "anomaly_type": "rapid_access",
                    "access_count": len(recent_accesses),
                    "affected_user": user_id
                }
            )
        
        # Check for unusual access times (e.g., outside business hours)
        current_hour = datetime.utcnow().hour
        if current_hour < 6 or current_hour > 22:  # Outside 6 AM - 10 PM UTC
            if operation in [SecretOperation.WRITE, SecretOperation.DELETE, SecretOperation.ROTATE]:
                logger.warning(
                    f"Anomaly detected: Sensitive operation {operation.value} on {secret_path} "
                    f"by {user_id} outside business hours"
                )
        
        # Check for IP address changes
        if len(pattern.ip_addresses) > 5:
            logger.warning(
                f"Anomaly detected: User {user_id} accessing {secret_path} "
                f"from {len(pattern.ip_addresses)} different IP addresses"
            )
    
    async def _identify_suspicious_activities(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> List[Dict[str, Any]]:
        """Identify suspicious activities in the given period."""
        suspicious = []
        
        # Analyze access patterns
        for pattern_key, pattern in self._access_patterns.items():
            # Filter accesses in the period
            period_accesses = [
                t for t in pattern.access_times
                if start_date <= t <= end_date
            ]
            
            if not period_accesses:
                continue
            
            # Rapid access detection
            access_frequency = len(period_accesses) / max(
                (period_accesses[-1] - period_accesses[0]).total_seconds() / 3600,
                1
            )  # Accesses per hour
            
            if access_frequency > 100:  # More than 100 accesses per hour
                suspicious.append({
                    "type": "rapid_access",
                    "user_id": pattern.user_id,
                    "secret_path": pattern.secret_path,
                    "access_frequency": access_frequency,
                    "severity": "high"
                })
            
            # Multiple IP detection
            if len(pattern.ip_addresses) > 10:
                suspicious.append({
                    "type": "multiple_ips",
                    "user_id": pattern.user_id,
                    "secret_path": pattern.secret_path,
                    "ip_count": len(pattern.ip_addresses),
                    "severity": "medium"
                })
        
        return suspicious
    
    async def _get_overdue_rotations(self) -> List[Dict[str, Any]]:
        """Get list of overdue secret rotations."""
        # This would integrate with the secret manager to check rotation schedules
        # For now, return empty list
        return []
    
    async def _identify_policy_violations(
        self,
        events: List[AuditEvent]
    ) -> List[Dict[str, Any]]:
        """Identify policy violations from audit events."""
        violations = []
        
        for event in events:
            details = event.details or {}
            
            # Check for access to critical secrets without approval
            if (details.get("access_level") == "critical" and
                details.get("operation") in ["write", "delete", "rotate"] and
                not details.get("approval_id")):
                violations.append({
                    "type": "unapproved_critical_access",
                    "user_id": event.user_id,
                    "secret_path": event.resource_id,
                    "operation": details.get("operation"),
                    "timestamp": event.timestamp.isoformat(),
                    "severity": "high"
                })
            
            # Check for export operations on sensitive data
            if details.get("operation") == "export":
                violations.append({
                    "type": "secret_export",
                    "user_id": event.user_id,
                    "secret_path": event.resource_id,
                    "timestamp": event.timestamp.isoformat(),
                    "severity": "medium"
                })
        
        return violations
    
    def _generate_recommendations(self, report: ComplianceReport) -> List[str]:
        """Generate recommendations based on compliance report."""
        recommendations = []
        
        # Rotation compliance recommendations
        if report.rotation_compliance.get("compliance_rate", 0) < 0.9:
            recommendations.append(
                "Enable automatic secret rotation for improved compliance"
            )
        
        if report.rotation_compliance.get("overdue_rotations"):
            recommendations.append(
                f"Rotate {len(report.rotation_compliance['overdue_rotations'])} "
                f"overdue secrets immediately"
            )
        
        # Access control recommendations
        if report.access_control_compliance.get("unauthorized_attempts", 0) > 10:
            recommendations.append(
                "Review and strengthen access control policies"
            )
        
        # Audit trail recommendations
        if report.audit_trail_completeness < 0.95:
            recommendations.append(
                "Ensure all secret access events include complete audit information"
            )
        
        # Policy violation recommendations
        if report.policy_violations:
            recommendations.append(
                f"Address {len(report.policy_violations)} policy violations"
            )
            
            high_severity = [v for v in report.policy_violations if v.get("severity") == "high"]
            if high_severity:
                recommendations.append(
                    f"Immediate action required for {len(high_severity)} high-severity violations"
                )
        
        return recommendations
    
    def _hash_secret_path(self, path: str) -> str:
        """Hash secret path for privacy in logs."""
        return hashlib.sha256(path.encode()).hexdigest()[:16]
    
    async def _flush_cache(self) -> None:
        """Flush cached audit events to storage."""
        async with self._cache_lock:
            if not self._audit_cache or not self.base_logger:
                return
            
            # Batch log events
            for event in self._audit_cache:
                await self.base_logger.log_event(event)
            
            self._audit_cache.clear()
    
    async def _flush_cache_periodically(self) -> None:
        """Background task to flush cache periodically."""
        while True:
            try:
                await asyncio.sleep(self._flush_interval)
                await self._flush_cache()
            except Exception as e:
                logger.error(f"Error flushing audit cache: {e}")
    
    async def close(self) -> None:
        """Clean up resources."""
        # Cancel flush task
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        
        # Final flush
        await self._flush_cache()
        
        if self.base_logger:
            await self.base_logger.close()
        
        logger.info("Secret audit logger closed")


# Global instance
_secret_audit_logger: Optional[SecretAuditLogger] = None


def get_secret_audit_logger() -> SecretAuditLogger:
    """Get or create global secret audit logger instance."""
    global _secret_audit_logger
    if _secret_audit_logger is None:
        from src.auth.audit import get_audit_logger
        base_logger = get_audit_logger()
        _secret_audit_logger = SecretAuditLogger(base_logger)
    return _secret_audit_logger