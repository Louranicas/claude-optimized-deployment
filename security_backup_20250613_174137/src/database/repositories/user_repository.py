"""Repository for user management operations.

Handles user CRUD operations, authentication, and role management.
"""

from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
import hashlib
import secrets
import asyncio
import time

from sqlalchemy import select, func, or_, delete, text
from sqlalchemy.exc import SQLAlchemyError

from src.database.repositories.base import SQLAlchemyRepository, TortoiseRepository
from src.database.models import SQLAlchemyUser, TortoiseUser, UserRole
from src.core.logging_config import get_logger
from src.core.exceptions import AuthenticationError, AuthorizationError, DatabaseError

__all__ = [
    "UserRepository",
    "TortoiseUserRepository"
]


logger = get_logger(__name__)


class UserRepository(SQLAlchemyRepository[SQLAlchemyUser]):
    """Repository for user operations using SQLAlchemy."""
    
    def __init__(self, session=None):
        super().__init__(SQLAlchemyUser, session)
    
    async def create_user(
        self,
        username: str,
        email: str,
        full_name: Optional[str] = None,
        role: UserRole = UserRole.VIEWER,
        preferences: Optional[Dict[str, Any]] = None
    ) -> SQLAlchemyUser:
        """Create a new user."""
        # Check for existing user
        existing = await self.get_by_username_or_email(username, email)
        if existing:
            raise ValueError(f"User with username '{username}' or email '{email}' already exists")
        
        return await self.create(
            username=username,
            email=email,
            full_name=full_name,
            role=role,
            preferences=preferences or {}
        )
    
    async def get_by_username(self, username: str) -> Optional[SQLAlchemyUser]:
        """Get user by username with timeout."""
        try:
            stmt = select(SQLAlchemyUser).where(
                SQLAlchemyUser.username == username
            )
            result = await self._execute_with_timeout(stmt, timeout=5)  # 5 second timeout for user lookups
            return result.scalar_one_or_none()
        except asyncio.TimeoutError:
            logger.error(f"Timeout getting user by username: {username}")
            raise DatabaseError("User lookup timeout")
        except SQLAlchemyError as e:
            logger.error(f"Database error getting user by username {username}: {e}")
            raise DatabaseError(f"User lookup failed: {e}")
    
    async def get_by_email(self, email: str) -> Optional[SQLAlchemyUser]:
        """Get user by email with timeout."""
        try:
            stmt = select(SQLAlchemyUser).where(
                SQLAlchemyUser.email == email
            )
            result = await self._execute_with_timeout(stmt, timeout=5)  # 5 second timeout for user lookups
            return result.scalar_one_or_none()
        except asyncio.TimeoutError:
            logger.error(f"Timeout getting user by email: {email}")
            raise DatabaseError("User lookup timeout")
        except SQLAlchemyError as e:
            logger.error(f"Database error getting user by email {email}: {e}")
            raise DatabaseError(f"User lookup failed: {e}")
    
    async def get_by_username_or_email(
        self,
        username: str,
        email: str
    ) -> Optional[SQLAlchemyUser]:
        """Get user by username or email."""
        stmt = select(SQLAlchemyUser).where(
            or_(
                SQLAlchemyUser.username == username,
                SQLAlchemyUser.email == email
            )
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def authenticate_by_api_key(self, api_key: str) -> Optional[SQLAlchemyUser]:
        """Authenticate user by API key with proper connection management."""
        start_time = time.time()
        
        try:
            # Hash the provided API key
            api_key_hash = self._hash_api_key(api_key)
            
            async with self._get_session() as session:
                stmt = select(SQLAlchemyUser).where(
                    SQLAlchemyUser.api_key_hash == api_key_hash,
                    SQLAlchemyUser.is_active == True
                )
                
                # Execute with short timeout for auth queries
                result = await asyncio.wait_for(
                    session.execute(stmt),
                    timeout=3.0  # 3 second timeout for auth
                )
                user = result.scalar_one_or_none()
                
                if user:
                    # Update last login in the same transaction
                    user.last_login = datetime.utcnow()
                    await session.commit()
                    
                    logger.debug(
                        f"API key authentication completed in {time.time() - start_time:.3f}s"
                    )
                
                return user
                
        except asyncio.TimeoutError:
            logger.error("Timeout during API key authentication")
            raise AuthenticationError("Authentication timeout")
        except SQLAlchemyError as e:
            logger.error(f"Database error during API key authentication: {e}")
            raise AuthenticationError("Authentication failed")
        except Exception as e:
            logger.error(f"Unexpected error during API key authentication: {e}")
            raise AuthenticationError("Authentication failed")
    
    async def generate_api_key(self, user_id: int) -> str:
        """Generate a new API key for a user."""
        # Generate a secure random API key
        api_key = secrets.token_urlsafe(32)
        api_key_hash = self._hash_api_key(api_key)
        
        # Update user with hashed API key
        await self.update(user_id, api_key_hash=api_key_hash)
        
        # Return the unhashed key (only shown once)
        return api_key
    
    async def revoke_api_key(self, user_id: int) -> bool:
        """Revoke a user's API key."""
        user = await self.get(user_id)
        if user:
            await self.update(user_id, api_key_hash=None)
            return True
        return False
    
    async def update_last_login(self, user_id: int) -> None:
        """Update user's last login timestamp."""
        await self.update(user_id, last_login=datetime.utcnow())
    
    async def update_user_role(
        self,
        user_id: int,
        new_role: UserRole,
        admin_user_id: int
    ) -> Optional[SQLAlchemyUser]:
        """Update a user's role (requires admin)."""
        # Check if admin user has permission
        admin = await self.get(admin_user_id)
        if not admin or admin.role != UserRole.ADMIN:
            raise AuthorizationError("Only admins can change user roles")
        
        return await self.update(user_id, role=new_role)
    
    async def deactivate_user(
        self,
        user_id: int,
        admin_user_id: int
    ) -> Optional[SQLAlchemyUser]:
        """Deactivate a user (requires admin)."""
        # Check if admin user has permission
        admin = await self.get(admin_user_id)
        if not admin or admin.role != UserRole.ADMIN:
            raise AuthorizationError("Only admins can deactivate users")
        
        return await self.update(user_id, is_active=False, api_key_hash=None)
    
    async def reactivate_user(
        self,
        user_id: int,
        admin_user_id: int
    ) -> Optional[SQLAlchemyUser]:
        """Reactivate a user (requires admin)."""
        # Check if admin user has permission
        admin = await self.get(admin_user_id)
        if not admin or admin.role != UserRole.ADMIN:
            raise AuthorizationError("Only admins can reactivate users")
        
        return await self.update(user_id, is_active=True)
    
    async def get_users_by_role(
        self,
        role: UserRole,
        include_inactive: bool = False
    ) -> List[SQLAlchemyUser]:
        """Get all users with a specific role with timeout."""
        try:
            stmt = select(SQLAlchemyUser).where(
                SQLAlchemyUser.role == role
            )
            
            if not include_inactive:
                stmt = stmt.where(SQLAlchemyUser.is_active == True)
            
            stmt = stmt.order_by(SQLAlchemyUser.username)
            
            # Use longer timeout for potentially large result sets
            result = await self._execute_with_timeout(stmt, timeout=15)
            return result.scalars().all()
            
        except asyncio.TimeoutError:
            logger.error(f"Timeout getting users by role: {role}")
            raise DatabaseError("Query timeout")
        except SQLAlchemyError as e:
            logger.error(f"Database error getting users by role {role}: {e}")
            raise DatabaseError(f"Query failed: {e}")
    
    async def search_users(
        self,
        search_term: str,
        limit: int = 50
    ) -> List[SQLAlchemyUser]:
        """Search users by username, email, or full name with timeout."""
        # Validate and sanitize search term
        if len(search_term) < 2:
            return []  # Don't search for very short terms
        
        # Limit search term length to prevent DOS
        search_term = search_term[:100]
        search_pattern = f"%{search_term}%"
        
        # Cap limit
        limit = min(limit, 100)
        
        try:
            stmt = select(SQLAlchemyUser).where(
                or_(
                    SQLAlchemyUser.username.ilike(search_pattern),
                    SQLAlchemyUser.email.ilike(search_pattern),
                    SQLAlchemyUser.full_name.ilike(search_pattern)
                )
            ).limit(limit)
            
            # Use shorter timeout for search queries
            result = await self._execute_with_timeout(stmt, timeout=10)
            return result.scalars().all()
            
        except asyncio.TimeoutError:
            logger.error(f"Timeout searching users with term: {search_term}")
            raise DatabaseError("Search timeout")
        except SQLAlchemyError as e:
            logger.error(f"Database error searching users: {e}")
            raise DatabaseError(f"Search failed: {e}")
    
    async def update_preferences(
        self,
        user_id: int,
        preferences: Dict[str, Any]
    ) -> Optional[SQLAlchemyUser]:
        """Update user preferences."""
        user = await self.get(user_id)
        if user:
            # Merge with existing preferences
            current_prefs = user.preferences or {}
            current_prefs.update(preferences)
            return await self.update(user_id, preferences=current_prefs)
        return None
    
    async def get_user_statistics(self) -> Dict[str, Any]:
        """Get user statistics with proper timeout handling."""
        start_time = time.time()
        stats = {
            "total_users": 0,
            "active_users": 0,
            "inactive_users": 0,
            "users_by_role": {},
            "recent_logins_30d": 0
        }
        
        try:
            async with self._get_session() as session:
                # Use a single query with subqueries for better performance
                # Set a longer timeout for statistics queries
                if session.bind.url.drivername == "postgresql+asyncpg":
                    await session.execute(
                        text(f"SET LOCAL statement_timeout = 30000")  # 30 seconds
                    )
                
                # Total and active users in one query
                user_counts_stmt = select(
                    func.count(SQLAlchemyUser.id).label('total'),
                    func.count(SQLAlchemyUser.id).filter(
                        SQLAlchemyUser.is_active == True
                    ).label('active')
                )
                
                result = await session.execute(user_counts_stmt)
                counts = result.first()
                
                if counts:
                    stats["total_users"] = counts.total or 0
                    stats["active_users"] = counts.active or 0
                    stats["inactive_users"] = stats["total_users"] - stats["active_users"]
                
                # Users by role
                role_stmt = select(
                    SQLAlchemyUser.role,
                    func.count(SQLAlchemyUser.id).label('count')
                ).group_by(SQLAlchemyUser.role)
                
                role_result = await session.execute(role_stmt)
                role_data = role_result.all()
                stats["users_by_role"] = {row.role: row.count for row in role_data}
                
                # Recent logins
                thirty_days_ago = datetime.utcnow() - timedelta(days=30)
                recent_stmt = select(func.count(SQLAlchemyUser.id)).where(
                    SQLAlchemyUser.last_login >= thirty_days_ago
                )
                recent_result = await session.execute(recent_stmt)
                stats["recent_logins_30d"] = recent_result.scalar() or 0
                
                logger.debug(
                    f"User statistics gathered in {time.time() - start_time:.3f}s"
                )
                
                return stats
                
        except asyncio.TimeoutError:
            logger.error("Timeout getting user statistics")
            # Return partial stats rather than failing completely
            return stats
        except SQLAlchemyError as e:
            logger.error(f"Database error getting user statistics: {e}")
            # Return partial stats rather than failing completely
            return stats
    
    def _hash_api_key(self, api_key: str) -> str:
        """Hash an API key for storage."""
        return hashlib.sha256(api_key.encode()).hexdigest()


class TortoiseUserRepository(TortoiseRepository[TortoiseUser]):
    """Repository for user operations using Tortoise ORM."""
    
    def __init__(self):
        super().__init__(TortoiseUser)
    
    async def create_user(
        self,
        username: str,
        email: str,
        full_name: Optional[str] = None,
        role: UserRole = UserRole.VIEWER,
        preferences: Optional[Dict[str, Any]] = None
    ) -> TortoiseUser:
        """Create a new user."""
        # Check for existing
        existing = await TortoiseUser.exists(
            username=username
        ) or await TortoiseUser.exists(email=email)
        
        if existing:
            raise ValueError(f"User with username '{username}' or email '{email}' already exists")
        
        return await self.create(
            username=username,
            email=email,
            full_name=full_name,
            role=role,
            preferences=preferences or {}
        )
    
    async def get_by_username(self, username: str) -> Optional[TortoiseUser]:
        """Get user by username."""
        return await TortoiseUser.get_or_none(username=username)
    
    async def get_by_email(self, email: str) -> Optional[TortoiseUser]:
        """Get user by email."""
        return await TortoiseUser.get_or_none(email=email)
    
    def _hash_api_key(self, api_key: str) -> str:
        """Hash an API key for storage."""
        return hashlib.sha256(api_key.encode()).hexdigest()