"""Base repository classes for data access patterns.

Provides abstract base classes for repository pattern implementation
with support for both SQLAlchemy and Tortoise ORM.
"""

from abc import ABC, abstractmethod
from typing import TypeVar, Generic, Optional, List, Dict, Any, Type, Union, AsyncGenerator
from contextlib import asynccontextmanager
from datetime import datetime
import json
import asyncio
import time

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, and_, or_, func, text
from sqlalchemy.orm import selectinload
from sqlalchemy.exc import SQLAlchemyError, TimeoutError as SQLTimeoutError
from tortoise.models import Model
from tortoise.queryset import QuerySet
from tortoise.exceptions import DoesNotExist

from src.core.logging_config import get_logger
from src.core.exceptions import NotFoundError, DatabaseError
from src.database.pool_manager import get_pool_manager, DatabasePoolConfig

__all__ = [
    "AsyncRepository",
    "BaseRepository",
    "SQLAlchemyRepository",
    "TortoiseRepository"
]


logger = get_logger(__name__)

# Type variable for model classes
T = TypeVar('T')


class AsyncRepository(ABC, Generic[T]):
    """Abstract base repository for async database operations."""
    
    @abstractmethod
    async def create(self, **kwargs) -> T:
        """Create a new entity."""
        pass
    
    @abstractmethod
    async def get(self, id: Any) -> Optional[T]:
        """Get entity by ID."""
        pass
    
    @abstractmethod
    async def get_many(self, filters: Dict[str, Any], limit: int = 100, offset: int = 0) -> List[T]:
        """Get multiple entities with filters."""
        pass
    
    @abstractmethod
    async def update(self, id: Any, **kwargs) -> Optional[T]:
        """Update an entity."""
        pass
    
    @abstractmethod
    async def delete(self, id: Any) -> bool:
        """Delete an entity."""
        pass
    
    @abstractmethod
    async def count(self, filters: Dict[str, Any] = None) -> int:
        """Count entities with optional filters."""
        pass


class BaseRepository(AsyncRepository[T]):
    """Base repository implementation with common functionality."""
    
    def __init__(self, session: Union[AsyncSession, None] = None):
        """Initialize repository with optional session."""
        self._session = session
        self._model_class: Optional[Type[T]] = None
    
    async def set_session(self, session: AsyncSession) -> None:
        """Set the database session."""
        self._session = session
    
    def _serialize_json_fields(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Serialize JSON fields for storage."""
        result = data.copy()
        for key, value in result.items():
            if isinstance(value, (dict, list)) and not isinstance(value, str):
                result[key] = json.dumps(value)
        return result
    
    def _deserialize_json_fields(self, instance: T) -> T:
        """Deserialize JSON fields after retrieval."""
        # Implementation depends on specific ORM
        return instance


class SQLAlchemyRepository(BaseRepository[T]):
    """SQLAlchemy-specific repository implementation."""
    
    def __init__(self, model_class: Type[T], session: Optional[AsyncSession] = None):
        """Initialize with SQLAlchemy model class."""
        super().__init__(session)
        self._model_class = model_class
        self._query_timeout = 30  # Default 30 seconds
        self._lock_timeout = 5    # Default 5 seconds for row locks
    
    @asynccontextmanager
    async def _get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get a database session with proper cleanup."""
        if self._session:
            # Use provided session
            yield self._session
        else:
            # Get session from pool manager
            pool_manager = await get_pool_manager()
            async with pool_manager.get_session() as session:
                yield session
    
    async def _execute_with_timeout(self, query, timeout: Optional[int] = None):
        """Execute a query with timeout."""
        if timeout is None:
            timeout = self._query_timeout
        
        async with self._get_session() as session:
            # Set query timeout for PostgreSQL
            if session.bind.url.drivername == "postgresql+asyncpg":
                await session.execute(
                    text(f"SET LOCAL statement_timeout = {timeout * 1000}")
                )
            
            return await session.execute(query)
    
    async def create(self, **kwargs) -> T:
        """Create a new entity with proper connection management."""
        start_time = time.time()
        
        try:
            async with self._get_session() as session:
                instance = self._model_class(**kwargs)
                session.add(instance)
                
                # Commit with timeout
                await asyncio.wait_for(
                    session.commit(),
                    timeout=self._query_timeout
                )
                
                # Refresh to get generated fields
                await session.refresh(instance)
                
                logger.debug(
                    f"Created {self._model_class.__name__} in {time.time() - start_time:.3f}s"
                )
                return instance
                
        except asyncio.TimeoutError:
            logger.error(
                f"Timeout creating {self._model_class.__name__} after {self._query_timeout}s"
            )
            raise DatabaseError(f"Creation timeout after {self._query_timeout}s")
        except SQLAlchemyError as e:
            logger.error(f"Database error creating {self._model_class.__name__}: {e}")
            raise DatabaseError(f"Creation failed: {e}")
        except Exception as e:
            logger.error(f"Unexpected error creating {self._model_class.__name__}: {e}")
            raise DatabaseError(f"Creation failed: {e}")
    
    async def get(self, id: Any) -> Optional[T]:
        """Get entity by ID with timeout."""
        start_time = time.time()
        
        try:
            stmt = select(self._model_class).where(self._model_class.id == id)
            
            result = await self._execute_with_timeout(stmt)
            entity = result.scalar_one_or_none()
            
            logger.debug(
                f"Retrieved {self._model_class.__name__} {id} in {time.time() - start_time:.3f}s"
            )
            return entity
            
        except asyncio.TimeoutError:
            logger.error(
                f"Timeout getting {self._model_class.__name__} {id} after {self._query_timeout}s"
            )
            raise DatabaseError(f"Query timeout after {self._query_timeout}s")
        except SQLAlchemyError as e:
            logger.error(f"Database error getting {self._model_class.__name__} {id}: {e}")
            raise DatabaseError(f"Retrieval failed: {e}")
        except Exception as e:
            logger.error(f"Unexpected error getting {self._model_class.__name__} {id}: {e}")
            raise DatabaseError(f"Retrieval failed: {e}")
    
    async def get_many(
        self, 
        filters: Dict[str, Any] = None, 
        limit: int = 100, 
        offset: int = 0,
        order_by: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> List[T]:
        """Get multiple entities with filters and timeout."""
        start_time = time.time()
        
        # Validate limit to prevent excessive data retrieval
        if limit > 1000:
            logger.warning(f"Large limit {limit} requested, capping at 1000")
            limit = 1000
        
        try:
            stmt = select(self._model_class)
            
            # Apply filters
            if filters:
                conditions = []
                for key, value in filters.items():
                    if hasattr(self._model_class, key):
                        if isinstance(value, list):
                            conditions.append(getattr(self._model_class, key).in_(value))
                        else:
                            conditions.append(getattr(self._model_class, key) == value)
                if conditions:
                    stmt = stmt.where(and_(*conditions))
            
            # Apply ordering
            if order_by:
                if order_by.startswith('-'):
                    stmt = stmt.order_by(getattr(self._model_class, order_by[1:]).desc())
                else:
                    stmt = stmt.order_by(getattr(self._model_class, order_by))
            
            # Apply pagination
            stmt = stmt.limit(limit).offset(offset)
            
            result = await self._execute_with_timeout(stmt, timeout)
            entities = result.scalars().all()
            
            logger.debug(
                f"Retrieved {len(entities)} {self._model_class.__name__} entities "
                f"in {time.time() - start_time:.3f}s"
            )
            return entities
            
        except asyncio.TimeoutError:
            logger.error(
                f"Timeout getting {self._model_class.__name__} list after {timeout or self._query_timeout}s"
            )
            raise DatabaseError(f"Query timeout after {timeout or self._query_timeout}s")
        except SQLAlchemyError as e:
            logger.error(f"Database error getting {self._model_class.__name__} list: {e}")
            raise DatabaseError(f"Query failed: {e}")
        except Exception as e:
            logger.error(f"Unexpected error getting {self._model_class.__name__} list: {e}")
            raise DatabaseError(f"Query failed: {e}")
    
    async def update(self, id: Any, **kwargs) -> Optional[T]:
        """Update an entity with proper locking and timeout."""
        start_time = time.time()
        
        try:
            async with self._get_session() as session:
                # Use SELECT FOR UPDATE to prevent concurrent modifications
                select_stmt = (
                    select(self._model_class)
                    .where(self._model_class.id == id)
                    .with_for_update(nowait=False, skip_locked=False)
                )
                
                # Set lock timeout
                if session.bind.url.drivername == "postgresql+asyncpg":
                    await session.execute(
                        text(f"SET LOCAL lock_timeout = {self._lock_timeout * 1000}")
                    )
                
                # Get and lock the row
                result = await session.execute(select_stmt)
                entity = result.scalar_one_or_none()
                
                if not entity:
                    return None
                
                # Update the entity
                for key, value in kwargs.items():
                    if hasattr(entity, key):
                        setattr(entity, key, value)
                
                # Commit with timeout
                await asyncio.wait_for(
                    session.commit(),
                    timeout=self._query_timeout
                )
                
                # Refresh to get updated values
                await session.refresh(entity)
                
                logger.debug(
                    f"Updated {self._model_class.__name__} {id} in {time.time() - start_time:.3f}s"
                )
                return entity
                
        except asyncio.TimeoutError:
            logger.error(
                f"Timeout updating {self._model_class.__name__} {id} after {self._query_timeout}s"
            )
            raise DatabaseError(f"Update timeout after {self._query_timeout}s")
        except SQLAlchemyError as e:
            logger.error(f"Database error updating {self._model_class.__name__} {id}: {e}")
            raise DatabaseError(f"Update failed: {e}")
        except Exception as e:
            logger.error(f"Unexpected error updating {self._model_class.__name__} {id}: {e}")
            raise DatabaseError(f"Update failed: {e}")
    
    async def delete(self, id: Any) -> bool:
        """Delete an entity with proper locking."""
        start_time = time.time()
        
        try:
            async with self._get_session() as session:
                # First check if entity exists with lock
                select_stmt = (
                    select(self._model_class)
                    .where(self._model_class.id == id)
                    .with_for_update(nowait=False, skip_locked=False)
                )
                
                result = await session.execute(select_stmt)
                entity = result.scalar_one_or_none()
                
                if not entity:
                    return False
                
                # Delete the entity
                await session.delete(entity)
                
                # Commit with timeout
                await asyncio.wait_for(
                    session.commit(),
                    timeout=self._query_timeout
                )
                
                logger.debug(
                    f"Deleted {self._model_class.__name__} {id} in {time.time() - start_time:.3f}s"
                )
                return True
                
        except asyncio.TimeoutError:
            logger.error(
                f"Timeout deleting {self._model_class.__name__} {id} after {self._query_timeout}s"
            )
            raise DatabaseError(f"Delete timeout after {self._query_timeout}s")
        except SQLAlchemyError as e:
            logger.error(f"Database error deleting {self._model_class.__name__} {id}: {e}")
            raise DatabaseError(f"Deletion failed: {e}")
        except Exception as e:
            logger.error(f"Unexpected error deleting {self._model_class.__name__} {id}: {e}")
            raise DatabaseError(f"Deletion failed: {e}")
    
    async def count(self, filters: Dict[str, Any] = None, timeout: Optional[int] = None) -> int:
        """Count entities with optional filters and timeout."""
        start_time = time.time()
        
        try:
            stmt = select(func.count()).select_from(self._model_class)
            
            if filters:
                conditions = []
                for key, value in filters.items():
                    if hasattr(self._model_class, key):
                        conditions.append(getattr(self._model_class, key) == value)
                if conditions:
                    stmt = stmt.where(and_(*conditions))
            
            result = await self._execute_with_timeout(stmt, timeout)
            count = result.scalar() or 0
            
            logger.debug(
                f"Counted {count} {self._model_class.__name__} entities "
                f"in {time.time() - start_time:.3f}s"
            )
            return count
            
        except asyncio.TimeoutError:
            logger.error(
                f"Timeout counting {self._model_class.__name__} after {timeout or self._query_timeout}s"
            )
            raise DatabaseError(f"Count timeout after {timeout or self._query_timeout}s")
        except SQLAlchemyError as e:
            logger.error(f"Database error counting {self._model_class.__name__}: {e}")
            raise DatabaseError(f"Count failed: {e}")
        except Exception as e:
            logger.error(f"Unexpected error counting {self._model_class.__name__}: {e}")
            raise DatabaseError(f"Count failed: {e}")


class TortoiseRepository(BaseRepository[T]):
    """Tortoise ORM-specific repository implementation."""
    
    def __init__(self, model_class: Type[Model]):
        """Initialize with Tortoise model class."""
        super().__init__()
        self._model_class = model_class
    
    async def create(self, **kwargs) -> T:
        """Create a new entity."""
        try:
            instance = await self._model_class.create(**kwargs)
            return instance
        except Exception as e:
            logger.error(f"Failed to create {self._model_class.__name__}: {e}")
            raise DatabaseError(f"Creation failed: {e}")
    
    async def get(self, id: Any) -> Optional[T]:
        """Get entity by ID."""
        try:
            return await self._model_class.get_or_none(id=id)
        except Exception as e:
            logger.error(f"Failed to get {self._model_class.__name__} with id {id}: {e}")
            raise DatabaseError(f"Retrieval failed: {e}")
    
    async def get_many(
        self, 
        filters: Dict[str, Any] = None, 
        limit: int = 100, 
        offset: int = 0,
        order_by: Optional[str] = None
    ) -> List[T]:
        """Get multiple entities with filters."""
        try:
            query = self._model_class.all()
            
            # Apply filters
            if filters:
                query = query.filter(**filters)
            
            # Apply ordering
            if order_by:
                query = query.order_by(order_by)
            
            # Apply pagination
            query = query.limit(limit).offset(offset)
            
            return await query
        except Exception as e:
            logger.error(f"Failed to get many {self._model_class.__name__}: {e}")
            raise DatabaseError(f"Query failed: {e}")
    
    async def update(self, id: Any, **kwargs) -> Optional[T]:
        """Update an entity."""
        try:
            instance = await self._model_class.get_or_none(id=id)
            if instance:
                await instance.update_from_dict(kwargs)
                await instance.save()
            return instance
        except Exception as e:
            logger.error(f"Failed to update {self._model_class.__name__} with id {id}: {e}")
            raise DatabaseError(f"Update failed: {e}")
    
    async def delete(self, id: Any) -> bool:
        """Delete an entity."""
        try:
            instance = await self._model_class.get_or_none(id=id)
            if instance:
                await instance.delete()
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to delete {self._model_class.__name__} with id {id}: {e}")
            raise DatabaseError(f"Deletion failed: {e}")
    
    async def count(self, filters: Dict[str, Any] = None) -> int:
        """Count entities with optional filters."""
        try:
            query = self._model_class.all()
            if filters:
                query = query.filter(**filters)
            return await query.count()
        except Exception as e:
            logger.error(f"Failed to count {self._model_class.__name__}: {e}")
            raise DatabaseError(f"Count failed: {e}")