"""Repository for time-series metrics data.

Handles storage and retrieval of Prometheus-compatible metrics data.
"""

from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timedelta

from sqlalchemy import select, func, and_, delete

from src.database.repositories.base import SQLAlchemyRepository, TortoiseRepository
from src.database.models import SQLAlchemyMetricData, TortoiseMetricData
from src.core.logging_config import get_logger

logger = get_logger(__name__)


class MetricsRepository(SQLAlchemyRepository[SQLAlchemyMetricData]):
    """Repository for metrics operations using SQLAlchemy."""
    
    def __init__(self, session=None):
        super().__init__(SQLAlchemyMetricData, session)
    
    async def record_metric(
        self,
        metric_name: str,
        value: float,
        timestamp: Optional[datetime] = None,
        labels: Optional[Dict[str, str]] = None
    ) -> SQLAlchemyMetricData:
        """Record a single metric data point."""
        return await self.create(
            metric_name=metric_name,
            value=value,
            timestamp=timestamp or datetime.utcnow(),
            labels=labels or {}
        )
    
    async def record_metrics_batch(
        self,
        metrics: List[Dict[str, Any]]
    ) -> List[SQLAlchemyMetricData]:
        """Record multiple metric data points efficiently."""
        instances = []
        for metric in metrics:
            instance = SQLAlchemyMetricData(
                metric_name=metric["metric_name"],
                value=metric["value"],
                timestamp=metric.get("timestamp", datetime.utcnow()),
                labels=metric.get("labels", {})
            )
            instances.append(instance)
        
        self._session.add_all(instances)
        await self._session.commit()
        
        return instances
    
    async def query_metrics(
        self,
        metric_name: str,
        start_time: datetime,
        end_time: datetime,
        labels: Optional[Dict[str, str]] = None,
        aggregation: Optional[str] = None,
        step_seconds: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Query metrics data with optional aggregation."""
        base_query = select(SQLAlchemyMetricData).where(
            and_(
                SQLAlchemyMetricData.metric_name == metric_name,
                SQLAlchemyMetricData.timestamp >= start_time,
                SQLAlchemyMetricData.timestamp <= end_time
            )
        )
        
        # Filter by labels if provided
        if labels:
            for key, value in labels.items():
                # This assumes PostgreSQL JSONB operators
                # For SQLite, this would need different handling
                base_query = base_query.where(
                    SQLAlchemyMetricData.labels[key].astext == value
                )
        
        if aggregation and step_seconds:
            # Perform time-based aggregation
            return await self._query_with_aggregation(
                metric_name, start_time, end_time, labels, aggregation, step_seconds
            )
        else:
            # Return raw data points
            base_query = base_query.order_by(SQLAlchemyMetricData.timestamp)
            result = await self._session.execute(base_query)
            data_points = result.scalars().all()
            
            return [
                {
                    "timestamp": dp.timestamp.isoformat(),
                    "value": dp.value,
                    "labels": dp.labels
                }
                for dp in data_points
            ]
    
    async def _query_with_aggregation(
        self,
        metric_name: str,
        start_time: datetime,
        end_time: datetime,
        labels: Optional[Dict[str, str]],
        aggregation: str,
        step_seconds: int
    ) -> List[Dict[str, Any]]:
        """Query metrics with time-based aggregation."""
        # This is a simplified version - in production, you'd use
        # database-specific time bucketing functions
        
        # Calculate time buckets
        current_time = start_time
        buckets = []
        
        while current_time < end_time:
            bucket_end = min(current_time + timedelta(seconds=step_seconds), end_time)
            
            # Query for this time bucket
            query = select(
                func.avg(SQLAlchemyMetricData.value).label('avg_value'),
                func.min(SQLAlchemyMetricData.value).label('min_value'),
                func.max(SQLAlchemyMetricData.value).label('max_value'),
                func.count(SQLAlchemyMetricData.id).label('count')
            ).where(
                and_(
                    SQLAlchemyMetricData.metric_name == metric_name,
                    SQLAlchemyMetricData.timestamp >= current_time,
                    SQLAlchemyMetricData.timestamp < bucket_end
                )
            )
            
            if labels:
                for key, value in labels.items():
                    query = query.where(
                        SQLAlchemyMetricData.labels[key].astext == value
                    )
            
            result = await self._session.execute(query)
            row = result.one()
            
            # Select appropriate aggregation
            if aggregation == "avg":
                value = float(row.avg_value) if row.avg_value else 0.0
            elif aggregation == "min":
                value = row.min_value or 0.0
            elif aggregation == "max":
                value = row.max_value or 0.0
            elif aggregation == "sum":
                value = (float(row.avg_value) if row.avg_value else 0.0) * row.count
            else:
                value = float(row.avg_value) if row.avg_value else 0.0
            
            buckets.append({
                "timestamp": current_time.isoformat(),
                "value": value,
                "count": row.count
            })
            
            current_time = bucket_end
        
        return buckets
    
    async def get_metric_names(
        self,
        prefix: Optional[str] = None
    ) -> List[str]:
        """Get all unique metric names."""
        query = select(
            func.distinct(SQLAlchemyMetricData.metric_name)
        )
        
        if prefix:
            query = query.where(
                SQLAlchemyMetricData.metric_name.like(f"{prefix}%")
            )
        
        result = await self._session.execute(query)
        return [row[0] for row in result.all()]
    
    async def get_metric_labels(
        self,
        metric_name: str
    ) -> List[Dict[str, str]]:
        """Get all unique label combinations for a metric."""
        # This is simplified - in production you'd want to aggregate
        # distinct label combinations more efficiently
        query = select(
            func.distinct(SQLAlchemyMetricData.labels)
        ).where(
            SQLAlchemyMetricData.metric_name == metric_name
        )
        
        result = await self._session.execute(query)
        return [row[0] for row in result.all() if row[0]]
    
    async def get_latest_value(
        self,
        metric_name: str,
        labels: Optional[Dict[str, str]] = None
    ) -> Optional[Dict[str, Any]]:
        """Get the latest value for a metric."""
        query = select(SQLAlchemyMetricData).where(
            SQLAlchemyMetricData.metric_name == metric_name
        )
        
        if labels:
            for key, value in labels.items():
                query = query.where(
                    SQLAlchemyMetricData.labels[key].astext == value
                )
        
        query = query.order_by(
            SQLAlchemyMetricData.timestamp.desc()
        ).limit(1)
        
        result = await self._session.execute(query)
        data_point = result.scalar_one_or_none()
        
        if data_point:
            return {
                "timestamp": data_point.timestamp.isoformat(),
                "value": data_point.value,
                "labels": data_point.labels
            }
        return None
    
    async def cleanup_old_metrics(
        self,
        retention_days: int = 30,
        metric_name: Optional[str] = None
    ) -> int:
        """Delete metrics older than retention period."""
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        stmt = delete(SQLAlchemyMetricData).where(
            SQLAlchemyMetricData.timestamp < cutoff_date
        )
        
        if metric_name:
            stmt = stmt.where(SQLAlchemyMetricData.metric_name == metric_name)
        
        result = await self._session.execute(stmt)
        await self._session.commit()
        
        deleted_count = result.rowcount
        logger.info(
            f"Deleted {deleted_count} metric data points older than {retention_days} days"
            + (f" for metric {metric_name}" if metric_name else "")
        )
        
        return deleted_count
    
    async def get_metrics_summary(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Get summary statistics for all metrics."""
        # Base query for counting
        count_query = select(
            SQLAlchemyMetricData.metric_name,
            func.count(SQLAlchemyMetricData.id).label('count'),
            func.min(SQLAlchemyMetricData.timestamp).label('oldest'),
            func.max(SQLAlchemyMetricData.timestamp).label('newest')
        )
        
        if start_time:
            count_query = count_query.where(
                SQLAlchemyMetricData.timestamp >= start_time
            )
        if end_time:
            count_query = count_query.where(
                SQLAlchemyMetricData.timestamp <= end_time
            )
        
        count_query = count_query.group_by(SQLAlchemyMetricData.metric_name)
        
        result = await self._session.execute(count_query)
        data = result.all()
        
        summary = {
            "total_metrics": len(data),
            "total_data_points": sum(row.count for row in data),
            "metrics": {}
        }
        
        for row in data:
            summary["metrics"][row.metric_name] = {
                "data_points": row.count,
                "oldest_timestamp": row.oldest.isoformat() if row.oldest else None,
                "newest_timestamp": row.newest.isoformat() if row.newest else None
            }
        
        return summary


class TortoiseMetricsRepository(TortoiseRepository[TortoiseMetricData]):
    """Repository for metrics operations using Tortoise ORM."""
    
    def __init__(self):
        super().__init__(TortoiseMetricData)
    
    async def record_metric(
        self,
        metric_name: str,
        value: float,
        timestamp: Optional[datetime] = None,
        labels: Optional[Dict[str, str]] = None
    ) -> TortoiseMetricData:
        """Record a single metric data point."""
        return await self.create(
            metric_name=metric_name,
            value=value,
            timestamp=timestamp or datetime.utcnow(),
            labels=labels or {}
        )
    
    async def query_metrics(
        self,
        metric_name: str,
        start_time: datetime,
        end_time: datetime,
        labels: Optional[Dict[str, str]] = None
    ) -> List[Dict[str, Any]]:
        """Query metrics data."""
        query = TortoiseMetricData.filter(
            metric_name=metric_name,
            timestamp__gte=start_time,
            timestamp__lte=end_time
        )
        
        # Note: Label filtering would require JSON field support in Tortoise
        # This is a simplified version
        
        data_points = await query.order_by("timestamp").all()
        
        return [
            {
                "timestamp": dp.timestamp.isoformat(),
                "value": dp.value,
                "labels": dp.labels
            }
            for dp in data_points
        ]