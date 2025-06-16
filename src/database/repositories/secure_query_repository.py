"""
Secure repository for Circle of Experts query history operations.

Implements proper parameterized queries to prevent SQL injection.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import func, select, text, bindparam, and_
from sqlalchemy.sql import literal_column

from src.database.repositories.base import SQLAlchemyRepository, TortoiseRepository
from src.database.models import SQLAlchemyQueryHistory, TortoiseQueryHistory
from src.core.logging_config import get_logger
from src.core.security_validators import SecurityValidators, ValidationError

__all__ = [
    "SecureQueryHistoryRepository",
    "SecureTortoiseQueryHistoryRepository"
]

logger = get_logger(__name__)


class SecureQueryHistoryRepository(SQLAlchemyRepository[SQLAlchemyQueryHistory]):
    """Secure repository for query history operations with SQL injection prevention."""
    
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
        """Record a new Circle of Experts query with validation."""
        # Validate inputs
        if query_type and len(query_type) > 50:
            raise ValidationError("Query type too long (max 50 characters)")
        
        if experts_consulted and len(experts_consulted) > 20:
            raise ValidationError("Too many experts (max 20)")
        
        # Sanitize text fields to prevent XSS when displayed
        query_text = SecurityValidators.validate_xss(query_text, "query_text")
        if response_summary:
            response_summary = SecurityValidators.validate_xss(response_summary, "response_summary")
        if error_message:
            error_message = SecurityValidators.validate_xss(error_message, "error_message")
        
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
        """Get query by unique query ID with validation."""
        # Validate UUID format
        try:
            UUID(query_id)
        except ValueError:
            raise ValidationError("Invalid query ID format")
        
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
        """Get queries for a specific user with validation."""
        # Validate parameters
        if not isinstance(user_id, int) or user_id < 1:
            raise ValidationError("Invalid user ID")
        
        if limit < 1 or limit > 100:
            raise ValidationError("Limit must be between 1 and 100")
        
        if offset < 0:
            raise ValidationError("Offset must be non-negative")
        
        query = select(SQLAlchemyQueryHistory).where(
            SQLAlchemyQueryHistory.user_id == user_id
        )
        
        if query_type:
            # Validate query type
            if len(query_type) > 50:
                raise ValidationError("Query type too long")
            query = query.where(SQLAlchemyQueryHistory.query_type == query_type)
        
        query = query.order_by(SQLAlchemyQueryHistory.timestamp.desc())
        query = query.limit(limit).offset(offset)
        
        result = await self._session.execute(query)
        return result.scalars().all()
    
    async def search_queries(
        self,
        search_term: str,
        limit: int = 50
    ) -> List[SQLAlchemyQueryHistory]:
        """Search queries by text content with proper parameterization."""
        # Validate inputs
        if not search_term or len(search_term) < 3:
            raise ValidationError("Search term must be at least 3 characters")
        
        if len(search_term) > 100:
            raise ValidationError("Search term too long (max 100 characters)")
        
        if limit < 1 or limit > 100:
            raise ValidationError("Limit must be between 1 and 100")
        
        # Escape special SQL LIKE characters
        escaped_term = search_term.replace('\\', '\\\\')  # Escape backslash first
        escaped_term = escaped_term.replace('%', '\\%')   # Escape percent
        escaped_term = escaped_term.replace('_', '\\_')    # Escape underscore
        
        # Use parameterized query with explicit ESCAPE clause
        stmt = select(SQLAlchemyQueryHistory).where(
            SQLAlchemyQueryHistory.query_text.ilike(
                literal_column(':search_pattern'),
                escape='\\'
            )
        ).order_by(
            SQLAlchemyQueryHistory.timestamp.desc()
        ).limit(limit)
        
        # Execute with bound parameter
        result = await self._session.execute(
            stmt,
            {'search_pattern': f'%{escaped_term}%'}
        )
        
        return result.scalars().all()
    
    async def search_queries_advanced(
        self,
        search_criteria: Dict[str, Any],
        limit: int = 50
    ) -> List[SQLAlchemyQueryHistory]:
        """Advanced search with multiple criteria and proper validation."""
        # Build query dynamically but safely
        query = select(SQLAlchemyQueryHistory)
        conditions = []
        params = {}
        
        # Text search
        if 'text' in search_criteria:
            text_term = search_criteria['text']
            if not isinstance(text_term, str) or len(text_term) < 3:
                raise ValidationError("Text search term must be at least 3 characters")
            
            escaped_text = text_term.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
            conditions.append(
                SQLAlchemyQueryHistory.query_text.ilike(
                    bindparam('text_pattern'),
                    escape='\\'
                )
            )
            params['text_pattern'] = f'%{escaped_text}%'
        
        # User filter
        if 'user_id' in search_criteria:
            user_id = search_criteria['user_id']
            if not isinstance(user_id, int) or user_id < 1:
                raise ValidationError("Invalid user ID")
            conditions.append(SQLAlchemyQueryHistory.user_id == bindparam('user_id'))
            params['user_id'] = user_id
        
        # Date range filter
        if 'start_date' in search_criteria:
            start_date = search_criteria['start_date']
            if not isinstance(start_date, datetime):
                raise ValidationError("Start date must be datetime object")
            conditions.append(SQLAlchemyQueryHistory.timestamp >= bindparam('start_date'))
            params['start_date'] = start_date
        
        if 'end_date' in search_criteria:
            end_date = search_criteria['end_date']
            if not isinstance(end_date, datetime):
                raise ValidationError("End date must be datetime object")
            conditions.append(SQLAlchemyQueryHistory.timestamp <= bindparam('end_date'))
            params['end_date'] = end_date
        
        # Query type filter
        if 'query_type' in search_criteria:
            query_type = search_criteria['query_type']
            if not isinstance(query_type, str) or len(query_type) > 50:
                raise ValidationError("Invalid query type")
            conditions.append(SQLAlchemyQueryHistory.query_type == bindparam('query_type'))
            params['query_type'] = query_type
        
        # Success filter
        if 'success' in search_criteria:
            success = search_criteria['success']
            if not isinstance(success, bool):
                raise ValidationError("Success must be boolean")
            conditions.append(SQLAlchemyQueryHistory.success == bindparam('success'))
            params['success'] = success
        
        # Apply conditions
        if conditions:
            query = query.where(and_(*conditions))
        
        query = query.order_by(SQLAlchemyQueryHistory.timestamp.desc()).limit(limit)
        
        # Execute with parameters
        result = await self._session.execute(query, params)
        return result.scalars().all()
    
    async def get_cost_summary(
        self,
        start_date: datetime,
        end_date: datetime,
        user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Get cost summary with parameterized queries."""
        # Validate dates
        if start_date >= end_date:
            raise ValidationError("Start date must be before end date")
        
        if (end_date - start_date).days > 365:
            raise ValidationError("Date range cannot exceed 1 year")
        
        # Build parameterized query
        stmt = select(
            func.sum(SQLAlchemyQueryHistory.estimated_cost).label('total_cost'),
            func.sum(SQLAlchemyQueryHistory.tokens_used).label('total_tokens'),
            func.count(SQLAlchemyQueryHistory.id).label('query_count'),
            func.avg(SQLAlchemyQueryHistory.estimated_cost).label('avg_cost')
        ).where(
            and_(
                SQLAlchemyQueryHistory.timestamp >= bindparam('start_date'),
                SQLAlchemyQueryHistory.timestamp <= bindparam('end_date')
            )
        )
        
        params = {
            'start_date': start_date,
            'end_date': end_date
        }
        
        if user_id is not None:
            if not isinstance(user_id, int) or user_id < 1:
                raise ValidationError("Invalid user ID")
            stmt = stmt.where(SQLAlchemyQueryHistory.user_id == bindparam('user_id'))
            params['user_id'] = user_id
        
        result = await self._session.execute(stmt, params)
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
    
    async def execute_safe_raw_query(
        self,
        query_template: str,
        params: Dict[str, Any],
        fetch_one: bool = False
    ) -> Any:
        """Execute raw SQL safely with parameterized queries."""
        # Validate query template doesn't contain obvious injection attempts
        query_lower = query_template.lower()
        dangerous_keywords = ['drop', 'truncate', 'delete', 'insert', 'update', 'alter', 'create']
        
        for keyword in dangerous_keywords:
            if keyword in query_lower and 'select' not in query_lower[:10]:
                raise SecurityError(f"Dangerous SQL keyword '{keyword}' not allowed")
        
        # Validate all parameters
        for key, value in params.items():
            if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', key):
                raise ValidationError(f"Invalid parameter name: {key}")
            
            # Ensure value is a safe type
            if not isinstance(value, (str, int, float, bool, datetime, type(None))):
                raise ValidationError(f"Invalid parameter type for {key}: {type(value)}")
        
        # Execute with text() and bound parameters
        stmt = text(query_template)
        result = await self._session.execute(stmt, params)
        
        if fetch_one:
            return result.one_or_none()
        return result.all()


class SecureTortoiseQueryHistoryRepository(TortoiseRepository[TortoiseQueryHistory]):
    """Secure Tortoise ORM repository with injection prevention."""
    
    def __init__(self):
        super().__init__(TortoiseQueryHistory)
    
    async def search_queries(
        self,
        search_term: str,
        limit: int = 50
    ) -> List[TortoiseQueryHistory]:
        """Search queries with Tortoise ORM parameterization."""
        # Validate inputs
        if not search_term or len(search_term) < 3:
            raise ValidationError("Search term must be at least 3 characters")
        
        if len(search_term) > 100:
            raise ValidationError("Search term too long (max 100 characters)")
        
        # Escape special characters for LIKE
        escaped_term = search_term.replace('\\', '\\\\')
        escaped_term = escaped_term.replace('%', '\\%')
        escaped_term = escaped_term.replace('_', '\\_')
        
        # Use Tortoise ORM's query builder with proper parameterization
        # Tortoise ORM automatically parameterizes queries
        return await TortoiseQueryHistory.filter(
            query_text__icontains=escaped_term
        ).order_by("-timestamp").limit(limit)