"""Repository for audit log operations.

Provides specialized methods for audit log management including
search, filtering, and compliance-related queries.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta

from sqlalchemy import func, delete

from src.database.repositories.base import SQLAlchemyRepository, TortoiseRepository
from src.database.models import (
    SQLAlchemyAuditLog, TortoiseAuditLog, LogLevel
)

__all__ = [
    "AuditLogRepository",
    "TortoiseAuditLogRepository"
]
from src.core.logging_config import get_logger

logger = get_logger(__name__)


class AuditLogRepository(SQLAlchemyRepository[SQLAlchemyAuditLog]):
    """Repository for audit log operations using SQLAlchemy."""
    
    def __init__(self, session=None):
        super().__init__(SQLAlchemyAuditLog, session)
    
    async def log_action(
        self,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        user_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        success: bool = True,
        error_message: Optional[str] = None
    ) -> SQLAlchemyAuditLog:
        """Create a new audit log entry."""
        return await self.create(
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            user_id=user_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            error_message=error_message
        )
    
    async def get_user_actions(
        self,
        user_id: int,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100
    ) -> List[SQLAlchemyAuditLog]:
        """Get all actions performed by a specific user."""
        filters = {"user_id": user_id}
        
        # Add date filtering if provided
        query = self._session.query(SQLAlchemyAuditLog).filter_by(user_id=user_id)
        
        if start_date:
            query = query.filter(SQLAlchemyAuditLog.timestamp >= start_date)
        if end_date:
            query = query.filter(SQLAlchemyAuditLog.timestamp <= end_date)
        
        query = query.order_by(SQLAlchemyAuditLog.timestamp.desc()).limit(limit)
        
        result = await self._session.execute(query)
        return result.scalars().all()
    
    async def get_resource_history(
        self,
        resource_type: str,
        resource_id: str,
        limit: int = 50
    ) -> List[SQLAlchemyAuditLog]:
        """Get audit history for a specific resource."""
        return await self.get_many(
            filters={
                "resource_type": resource_type,
                "resource_id": resource_id
            },
            limit=limit,
            order_by="-timestamp"
        )
    
    async def get_failed_actions(
        self,
        start_date: Optional[datetime] = None,
        action_type: Optional[str] = None,
        limit: int = 100
    ) -> List[SQLAlchemyAuditLog]:
        """Get all failed actions for security monitoring."""
        filters = {"success": False}
        
        if action_type:
            filters["action"] = action_type
        
        query = self._session.query(SQLAlchemyAuditLog).filter_by(success=False)
        
        if start_date:
            query = query.filter(SQLAlchemyAuditLog.timestamp >= start_date)
        if action_type:
            query = query.filter(SQLAlchemyAuditLog.action == action_type)
        
        query = query.order_by(SQLAlchemyAuditLog.timestamp.desc()).limit(limit)
        
        result = await self._session.execute(query)
        return result.scalars().all()
    
    async def get_compliance_report(
        self,
        start_date: datetime,
        end_date: datetime,
        resource_types: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Generate compliance report for audit logs."""
        # Base query
        query = self._session.query(
            SQLAlchemyAuditLog.action,
            SQLAlchemyAuditLog.resource_type,
            SQLAlchemyAuditLog.success,
            func.count(SQLAlchemyAuditLog.id).label('count')
        ).filter(
            SQLAlchemyAuditLog.timestamp.between(start_date, end_date)
        )
        
        if resource_types:
            query = query.filter(SQLAlchemyAuditLog.resource_type.in_(resource_types))
        
        query = query.group_by(
            SQLAlchemyAuditLog.action,
            SQLAlchemyAuditLog.resource_type,
            SQLAlchemyAuditLog.success
        )
        
        result = await self._session.execute(query)
        data = result.all()
        
        # Process results into report format
        report = {
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "summary": {
                "total_actions": sum(row.count for row in data),
                "successful_actions": sum(row.count for row in data if row.success),
                "failed_actions": sum(row.count for row in data if not row.success),
            },
            "by_action": {},
            "by_resource_type": {}
        }
        
        for row in data:
            # By action
            if row.action not in report["by_action"]:
                report["by_action"][row.action] = {"success": 0, "failure": 0}
            report["by_action"][row.action]["success" if row.success else "failure"] += row.count
            
            # By resource type
            if row.resource_type not in report["by_resource_type"]:
                report["by_resource_type"][row.resource_type] = {"success": 0, "failure": 0}
            report["by_resource_type"][row.resource_type]["success" if row.success else "failure"] += row.count
        
        return report
    
    async def cleanup_old_logs(self, retention_days: int = 90) -> int:
        """Delete audit logs older than retention period."""
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        stmt = delete(SQLAlchemyAuditLog).where(
            SQLAlchemyAuditLog.timestamp < cutoff_date
        )
        
        result = await self._session.execute(stmt)
        await self._session.commit()
        
        deleted_count = result.rowcount
        logger.info(f"Deleted {deleted_count} audit logs older than {retention_days} days")
        
        return deleted_count


class TortoiseAuditLogRepository(TortoiseRepository[TortoiseAuditLog]):
    """Repository for audit log operations using Tortoise ORM."""
    
    def __init__(self):
        super().__init__(TortoiseAuditLog)
    
    async def log_action(
        self,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        user_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        success: bool = True,
        error_message: Optional[str] = None
    ) -> TortoiseAuditLog:
        """Create a new audit log entry."""
        return await self.create(
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            user_id=user_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            error_message=error_message
        )
    
    async def get_user_actions(
        self,
        user_id: int,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100
    ) -> List[TortoiseAuditLog]:
        """Get all actions performed by a specific user."""
        query = TortoiseAuditLog.filter(user_id=user_id)
        
        if start_date:
            query = query.filter(timestamp__gte=start_date)
        if end_date:
            query = query.filter(timestamp__lte=end_date)
        
        return await query.order_by("-timestamp").limit(limit)
    
    async def get_resource_history(
        self,
        resource_type: str,
        resource_id: str,
        limit: int = 50
    ) -> List[TortoiseAuditLog]:
        """Get audit history for a specific resource."""
        return await TortoiseAuditLog.filter(
            resource_type=resource_type,
            resource_id=resource_id
        ).order_by("-timestamp").limit(limit)
    
    async def cleanup_old_logs(self, retention_days: int = 90) -> int:
        """Delete audit logs older than retention period."""
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        deleted_count = await TortoiseAuditLog.filter(
            timestamp__lt=cutoff_date
        ).delete()
        
        logger.info(f"Deleted {deleted_count} audit logs older than {retention_days} days")
        return deleted_count