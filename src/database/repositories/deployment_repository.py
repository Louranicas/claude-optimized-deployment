"""Repository for deployment record operations.

Manages deployment history, rollback information, and deployment metrics.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta

from sqlalchemy import select, func, and_

from src.database.repositories.base import SQLAlchemyRepository, TortoiseRepository
from src.database.models import (
    SQLAlchemyDeploymentRecord, TortoiseDeploymentRecord, DeploymentStatus
)
from src.core.logging_config import get_logger

logger = get_logger(__name__)


class DeploymentRepository(SQLAlchemyRepository[SQLAlchemyDeploymentRecord]):
    """Repository for deployment operations using SQLAlchemy."""
    
    def __init__(self, session=None):
        super().__init__(SQLAlchemyDeploymentRecord, session)
    
    async def create_deployment(
        self,
        environment: str,
        service_name: str,
        version: str,
        deployment_type: str,
        user_id: Optional[int] = None,
        configuration: Optional[Dict[str, Any]] = None,
        manifest: Optional[str] = None
    ) -> SQLAlchemyDeploymentRecord:
        """Create a new deployment record."""
        return await self.create(
            environment=environment,
            service_name=service_name,
            version=version,
            deployment_type=deployment_type,
            user_id=user_id,
            configuration=configuration,
            manifest=manifest,
            status=DeploymentStatus.PENDING
        )
    
    async def start_deployment(self, deployment_id: str) -> Optional[SQLAlchemyDeploymentRecord]:
        """Mark deployment as in progress."""
        deployment = await self.get_by_deployment_id(deployment_id)
        if deployment:
            return await self.update(
                deployment.id,
                status=DeploymentStatus.IN_PROGRESS,
                start_time=datetime.utcnow()
            )
        return None
    
    async def complete_deployment(
        self,
        deployment_id: str,
        success: bool,
        error_logs: Optional[str] = None,
        metrics: Optional[Dict[str, Any]] = None
    ) -> Optional[SQLAlchemyDeploymentRecord]:
        """Mark deployment as completed or failed."""
        deployment = await self.get_by_deployment_id(deployment_id)
        if not deployment:
            return None
        
        end_time = datetime.utcnow()
        duration = None
        
        if deployment.start_time:
            duration = int((end_time - deployment.start_time).total_seconds())
        
        return await self.update(
            deployment.id,
            status=DeploymentStatus.COMPLETED if success else DeploymentStatus.FAILED,
            end_time=end_time,
            duration_seconds=duration,
            error_logs=error_logs,
            metrics=metrics
        )
    
    async def get_by_deployment_id(self, deployment_id: str) -> Optional[SQLAlchemyDeploymentRecord]:
        """Get deployment by unique deployment ID."""
        stmt = select(SQLAlchemyDeploymentRecord).where(
            SQLAlchemyDeploymentRecord.deployment_id == deployment_id
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def get_active_deployments(
        self,
        environment: Optional[str] = None
    ) -> List[SQLAlchemyDeploymentRecord]:
        """Get all currently active deployments."""
        query = select(SQLAlchemyDeploymentRecord).where(
            SQLAlchemyDeploymentRecord.status.in_([
                DeploymentStatus.PENDING,
                DeploymentStatus.IN_PROGRESS
            ])
        )
        
        if environment:
            query = query.where(SQLAlchemyDeploymentRecord.environment == environment)
        
        result = await self._session.execute(query)
        return result.scalars().all()
    
    async def get_latest_deployment(
        self,
        environment: str,
        service_name: str
    ) -> Optional[SQLAlchemyDeploymentRecord]:
        """Get the latest deployment for a service in an environment."""
        stmt = select(SQLAlchemyDeploymentRecord).where(
            and_(
                SQLAlchemyDeploymentRecord.environment == environment,
                SQLAlchemyDeploymentRecord.service_name == service_name
            )
        ).order_by(
            SQLAlchemyDeploymentRecord.timestamp.desc()
        ).limit(1)
        
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def get_deployment_history(
        self,
        environment: str,
        service_name: str,
        limit: int = 20
    ) -> List[SQLAlchemyDeploymentRecord]:
        """Get deployment history for a service."""
        return await self.get_many(
            filters={
                "environment": environment,
                "service_name": service_name
            },
            limit=limit,
            order_by="-timestamp"
        )
    
    async def get_rollback_candidates(
        self,
        environment: str,
        service_name: str,
        current_version: str
    ) -> List[SQLAlchemyDeploymentRecord]:
        """Get previous successful deployments that can be rolled back to."""
        stmt = select(SQLAlchemyDeploymentRecord).where(
            and_(
                SQLAlchemyDeploymentRecord.environment == environment,
                SQLAlchemyDeploymentRecord.service_name == service_name,
                SQLAlchemyDeploymentRecord.status == DeploymentStatus.COMPLETED,
                SQLAlchemyDeploymentRecord.version != current_version
            )
        ).order_by(
            SQLAlchemyDeploymentRecord.timestamp.desc()
        ).limit(10)
        
        result = await self._session.execute(stmt)
        return result.scalars().all()
    
    async def record_rollback(
        self,
        deployment_id: str,
        rollback_to_version: str
    ) -> Optional[SQLAlchemyDeploymentRecord]:
        """Record a rollback operation."""
        return await self.update(
            deployment_id,
            status=DeploymentStatus.ROLLED_BACK,
            rollback_version=rollback_to_version,
            end_time=datetime.utcnow()
        )
    
    async def get_deployment_metrics(
        self,
        start_date: datetime,
        end_date: datetime,
        environment: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get deployment metrics for a time period."""
        base_query = select(
            SQLAlchemyDeploymentRecord.status,
            func.count(SQLAlchemyDeploymentRecord.id).label('count'),
            func.avg(SQLAlchemyDeploymentRecord.duration_seconds).label('avg_duration')
        ).where(
            SQLAlchemyDeploymentRecord.timestamp.between(start_date, end_date)
        )
        
        if environment:
            base_query = base_query.where(
                SQLAlchemyDeploymentRecord.environment == environment
            )
        
        base_query = base_query.group_by(SQLAlchemyDeploymentRecord.status)
        
        result = await self._session.execute(base_query)
        status_data = result.all()
        
        # Get service deployment counts
        service_query = select(
            SQLAlchemyDeploymentRecord.service_name,
            func.count(SQLAlchemyDeploymentRecord.id).label('count')
        ).where(
            SQLAlchemyDeploymentRecord.timestamp.between(start_date, end_date)
        )
        
        if environment:
            service_query = service_query.where(
                SQLAlchemyDeploymentRecord.environment == environment
            )
        
        service_query = service_query.group_by(SQLAlchemyDeploymentRecord.service_name)
        
        service_result = await self._session.execute(service_query)
        service_data = service_result.all()
        
        # Compile metrics
        metrics = {
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "summary": {
                "total_deployments": sum(row.count for row in status_data),
                "successful_deployments": next((row.count for row in status_data if row.status == DeploymentStatus.COMPLETED), 0),
                "failed_deployments": next((row.count for row in status_data if row.status == DeploymentStatus.FAILED), 0),
                "rolled_back_deployments": next((row.count for row in status_data if row.status == DeploymentStatus.ROLLED_BACK), 0),
                "average_duration_seconds": next((float(row.avg_duration) for row in status_data if row.status == DeploymentStatus.COMPLETED and row.avg_duration), 0)
            },
            "by_service": {row.service_name: row.count for row in service_data}
        }
        
        # Calculate success rate
        if metrics["summary"]["total_deployments"] > 0:
            metrics["summary"]["success_rate"] = (
                metrics["summary"]["successful_deployments"] / 
                metrics["summary"]["total_deployments"] * 100
            )
        else:
            metrics["summary"]["success_rate"] = 0
        
        return metrics
    
    async def get_failed_deployments(
        self,
        since: Optional[datetime] = None,
        environment: Optional[str] = None
    ) -> List[SQLAlchemyDeploymentRecord]:
        """Get recent failed deployments for analysis."""
        query = select(SQLAlchemyDeploymentRecord).where(
            SQLAlchemyDeploymentRecord.status == DeploymentStatus.FAILED
        )
        
        if since:
            query = query.where(SQLAlchemyDeploymentRecord.timestamp >= since)
        
        if environment:
            query = query.where(SQLAlchemyDeploymentRecord.environment == environment)
        
        query = query.order_by(SQLAlchemyDeploymentRecord.timestamp.desc()).limit(50)
        
        result = await self._session.execute(query)
        return result.scalars().all()


class TortoiseDeploymentRepository(TortoiseRepository[TortoiseDeploymentRecord]):
    """Repository for deployment operations using Tortoise ORM."""
    
    def __init__(self):
        super().__init__(TortoiseDeploymentRecord)
    
    async def create_deployment(
        self,
        environment: str,
        service_name: str,
        version: str,
        deployment_type: str,
        user_id: Optional[int] = None,
        configuration: Optional[Dict[str, Any]] = None,
        manifest: Optional[str] = None
    ) -> TortoiseDeploymentRecord:
        """Create a new deployment record."""
        return await self.create(
            environment=environment,
            service_name=service_name,
            version=version,
            deployment_type=deployment_type,
            user_id=user_id,
            configuration=configuration,
            manifest=manifest,
            status=DeploymentStatus.PENDING
        )
    
    async def get_by_deployment_id(self, deployment_id: str) -> Optional[TortoiseDeploymentRecord]:
        """Get deployment by unique deployment ID."""
        return await TortoiseDeploymentRecord.get_or_none(deployment_id=deployment_id)
    
    async def get_active_deployments(
        self,
        environment: Optional[str] = None
    ) -> List[TortoiseDeploymentRecord]:
        """Get all currently active deployments."""
        query = TortoiseDeploymentRecord.filter(
            status__in=[DeploymentStatus.PENDING, DeploymentStatus.IN_PROGRESS]
        )
        
        if environment:
            query = query.filter(environment=environment)
        
        return await query.all()