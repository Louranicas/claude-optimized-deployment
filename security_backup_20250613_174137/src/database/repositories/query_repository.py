"""Repository for Circle of Experts query history operations.

Manages storage and retrieval of AI consultation queries,
including performance metrics and cost tracking.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import func, select

from src.database.repositories.base import SQLAlchemyRepository, TortoiseRepository
from src.database.models import SQLAlchemyQueryHistory, TortoiseQueryHistory
from src.core.logging_config import get_logger

__all__ = [
    "QueryHistoryRepository",
    "TortoiseQueryHistoryRepository"
]


logger = get_logger(__name__)


class QueryHistoryRepository(SQLAlchemyRepository[SQLAlchemyQueryHistory]):
    """Repository for query history operations using SQLAlchemy."""
    
    def __init__(self, session=None):
        super().__init__(SQLAlchemyQueryHistory, session)
    
    async def record_query(
        self,
        query_text: str,
        query_type: str,
        experts_consulted: List[str],
        user_id: Optional[int] = None,
        response_summary: Optional[str] = None,
        response_data: Optional[Dict[str, Any]] = None,
        execution_time_ms: Optional[int] = None,
        tokens_used: Optional[int] = None,
        estimated_cost: Optional[float] = None,
        success: bool = True,
        error_message: Optional[str] = None
    ) -> SQLAlchemyQueryHistory:
        """Record a new Circle of Experts query."""
        return await self.create(
            query_text=query_text,
            query_type=query_type,
            experts_consulted=experts_consulted,
            user_id=user_id,
            response_summary=response_summary,
            response_data=response_data,
            execution_time_ms=execution_time_ms,
            tokens_used=tokens_used,
            estimated_cost=estimated_cost,
            success=success,
            error_message=error_message
        )
    
    async def get_by_query_id(self, query_id: str) -> Optional[SQLAlchemyQueryHistory]:
        """Get query by unique query ID."""
        stmt = select(SQLAlchemyQueryHistory).where(
            SQLAlchemyQueryHistory.query_id == query_id
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def get_user_queries(
        self,
        user_id: int,
        limit: int = 50,
        offset: int = 0,
        query_type: Optional[str] = None
    ) -> List[SQLAlchemyQueryHistory]:
        """Get queries for a specific user."""
        query = select(SQLAlchemyQueryHistory).where(
            SQLAlchemyQueryHistory.user_id == user_id
        )
        
        if query_type:
            query = query.where(SQLAlchemyQueryHistory.query_type == query_type)
        
        query = query.order_by(SQLAlchemyQueryHistory.timestamp.desc())
        query = query.limit(limit).offset(offset)
        
        result = await self._session.execute(query)
        return result.scalars().all()
    
    async def get_expert_usage_stats(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Dict[str, Any]]:
        """Get usage statistics for each expert."""
        # This would require a more complex query to unnest the experts_consulted JSON array
        # For now, we'll fetch all queries and process in Python
        query = select(SQLAlchemyQueryHistory)
        
        if start_date:
            query = query.where(SQLAlchemyQueryHistory.timestamp >= start_date)
        if end_date:
            query = query.where(SQLAlchemyQueryHistory.timestamp <= end_date)
        
        result = await self._session.execute(query)
        queries = result.scalars().all()
        
        # Process expert usage
        expert_stats = {}
        for q in queries:
            for expert in q.experts_consulted:
                if expert not in expert_stats:
                    expert_stats[expert] = {
                        "total_queries": 0,
                        "successful_queries": 0,
                        "failed_queries": 0,
                        "total_tokens": 0,
                        "total_cost": 0.0,
                        "avg_execution_time_ms": 0.0
                    }
                
                stats = expert_stats[expert]
                stats["total_queries"] += 1
                
                if q.success:
                    stats["successful_queries"] += 1
                else:
                    stats["failed_queries"] += 1
                
                if q.tokens_used:
                    stats["total_tokens"] += q.tokens_used
                
                if q.estimated_cost:
                    stats["total_cost"] += q.estimated_cost
                
                if q.execution_time_ms:
                    # Update running average
                    prev_avg = stats["avg_execution_time_ms"]
                    n = stats["total_queries"]
                    stats["avg_execution_time_ms"] = (prev_avg * (n - 1) + q.execution_time_ms) / n
        
        return expert_stats
    
    async def get_cost_summary(
        self,
        start_date: datetime,
        end_date: datetime,
        user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Get cost summary for queries in a date range."""
        query = select(
            func.sum(SQLAlchemyQueryHistory.estimated_cost).label('total_cost'),
            func.sum(SQLAlchemyQueryHistory.tokens_used).label('total_tokens'),
            func.count(SQLAlchemyQueryHistory.id).label('query_count'),
            func.avg(SQLAlchemyQueryHistory.estimated_cost).label('avg_cost')
        ).where(
            SQLAlchemyQueryHistory.timestamp.between(start_date, end_date)
        )
        
        if user_id:
            query = query.where(SQLAlchemyQueryHistory.user_id == user_id)
        
        result = await self._session.execute(query)
        row = result.one()
        
        return {
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "total_cost": float(row.total_cost or 0),
            "total_tokens": row.total_tokens or 0,
            "query_count": row.query_count or 0,
            "average_cost_per_query": float(row.avg_cost or 0)
        }
    
    async def get_performance_metrics(
        self,
        query_type: Optional[str] = None,
        limit: int = 100
    ) -> Dict[str, Any]:
        """Get performance metrics for queries."""
        query = select(
            SQLAlchemyQueryHistory.query_type,
            func.avg(SQLAlchemyQueryHistory.execution_time_ms).label('avg_time'),
            func.min(SQLAlchemyQueryHistory.execution_time_ms).label('min_time'),
            func.max(SQLAlchemyQueryHistory.execution_time_ms).label('max_time'),
            func.count(SQLAlchemyQueryHistory.id).label('count')
        ).where(
            SQLAlchemyQueryHistory.execution_time_ms.isnot(None)
        )
        
        if query_type:
            query = query.where(SQLAlchemyQueryHistory.query_type == query_type)
        
        query = query.group_by(SQLAlchemyQueryHistory.query_type)
        
        result = await self._session.execute(query)
        data = result.all()
        
        metrics = {}
        for row in data:
            metrics[row.query_type] = {
                "average_time_ms": float(row.avg_time),
                "min_time_ms": row.min_time,
                "max_time_ms": row.max_time,
                "query_count": row.count
            }
        
        return metrics
    
    async def search_queries(
        self,
        search_term: str,
        limit: int = 50
    ) -> List[SQLAlchemyQueryHistory]:
        """Search queries by text content."""
        # Use ILIKE for case-insensitive search (PostgreSQL)
        # For SQLite, this would need to be adjusted
        query = select(SQLAlchemyQueryHistory).where(
            SQLAlchemyQueryHistory.query_text.ilike(f"%{search_term}%")
        ).order_by(
            SQLAlchemyQueryHistory.timestamp.desc()
        ).limit(limit)
        
        result = await self._session.execute(query)
        return result.scalars().all()


class TortoiseQueryHistoryRepository(TortoiseRepository[TortoiseQueryHistory]):
    """Repository for query history operations using Tortoise ORM."""
    
    def __init__(self):
        super().__init__(TortoiseQueryHistory)
    
    async def record_query(
        self,
        query_text: str,
        query_type: str,
        experts_consulted: List[str],
        user_id: Optional[int] = None,
        response_summary: Optional[str] = None,
        response_data: Optional[Dict[str, Any]] = None,
        execution_time_ms: Optional[int] = None,
        tokens_used: Optional[int] = None,
        estimated_cost: Optional[float] = None,
        success: bool = True,
        error_message: Optional[str] = None
    ) -> TortoiseQueryHistory:
        """Record a new Circle of Experts query."""
        return await self.create(
            query_text=query_text,
            query_type=query_type,
            experts_consulted=experts_consulted,
            user_id=user_id,
            response_summary=response_summary,
            response_data=response_data,
            execution_time_ms=execution_time_ms,
            tokens_used=tokens_used,
            estimated_cost=estimated_cost,
            success=success,
            error_message=error_message
        )
    
    async def get_by_query_id(self, query_id: str) -> Optional[TortoiseQueryHistory]:
        """Get query by unique query ID."""
        return await TortoiseQueryHistory.get_or_none(query_id=query_id)
    
    async def get_user_queries(
        self,
        user_id: int,
        limit: int = 50,
        offset: int = 0,
        query_type: Optional[str] = None
    ) -> List[TortoiseQueryHistory]:
        """Get queries for a specific user."""
        query = TortoiseQueryHistory.filter(user_id=user_id)
        
        if query_type:
            query = query.filter(query_type=query_type)
        
        return await query.order_by("-timestamp").limit(limit).offset(offset)