"""Base repository classes for data access patterns.

Provides abstract base classes for repository pattern implementation
with support for both SQLAlchemy and Tortoise ORM.
"""

from abc import ABC, abstractmethod
from typing import TypeVar, Generic, Optional, List, Dict, Any, Type, Union
from datetime import datetime
import json

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, and_, or_, func
from sqlalchemy.orm import selectinload
from tortoise.models import Model
from tortoise.queryset import QuerySet
from tortoise.exceptions import DoesNotExist

from src.core.logging_config import get_logger
from src.core.exceptions import NotFoundError, DatabaseError

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
    
    async def create(self, **kwargs) -> T:
        """Create a new entity."""
        try:
            instance = self._model_class(**kwargs)
            self._session.add(instance)
            await self._session.commit()
            await self._session.refresh(instance)
            return instance
        except Exception as e:
            await self._session.rollback()
            logger.error(f"Failed to create {self._model_class.__name__}: {e}")
            raise DatabaseError(f"Creation failed: {e}")
    
    async def get(self, id: Any) -> Optional[T]:
        """Get entity by ID."""
        try:
            stmt = select(self._model_class).where(self._model_class.id == id)
            result = await self._session.execute(stmt)
            return result.scalar_one_or_none()
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
            
            result = await self._session.execute(stmt)
            return result.scalars().all()
        except Exception as e:
            logger.error(f"Failed to get many {self._model_class.__name__}: {e}")
            raise DatabaseError(f"Query failed: {e}")
    
    async def update(self, id: Any, **kwargs) -> Optional[T]:
        """Update an entity."""
        try:
            stmt = (
                update(self._model_class)
                .where(self._model_class.id == id)
                .values(**kwargs)
                .returning(self._model_class)
            )
            result = await self._session.execute(stmt)
            await self._session.commit()
            return result.scalar_one_or_none()
        except Exception as e:
            await self._session.rollback()
            logger.error(f"Failed to update {self._model_class.__name__} with id {id}: {e}")
            raise DatabaseError(f"Update failed: {e}")
    
    async def delete(self, id: Any) -> bool:
        """Delete an entity."""
        try:
            stmt = delete(self._model_class).where(self._model_class.id == id)
            result = await self._session.execute(stmt)
            await self._session.commit()
            return result.rowcount > 0
        except Exception as e:
            await self._session.rollback()
            logger.error(f"Failed to delete {self._model_class.__name__} with id {id}: {e}")
            raise DatabaseError(f"Deletion failed: {e}")
    
    async def count(self, filters: Dict[str, Any] = None) -> int:
        """Count entities with optional filters."""
        try:
            stmt = select(func.count()).select_from(self._model_class)
            
            if filters:
                conditions = []
                for key, value in filters.items():
                    if hasattr(self._model_class, key):
                        conditions.append(getattr(self._model_class, key) == value)
                if conditions:
                    stmt = stmt.where(and_(*conditions))
            
            result = await self._session.execute(stmt)
            return result.scalar() or 0
        except Exception as e:
            logger.error(f"Failed to count {self._model_class.__name__}: {e}")
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