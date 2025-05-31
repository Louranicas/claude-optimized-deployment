"""Repository for user management operations.

Handles user CRUD operations, authentication, and role management.
"""

from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
import hashlib
import secrets

from sqlalchemy import select, func, or_, delete

from src.database.repositories.base import SQLAlchemyRepository, TortoiseRepository
from src.database.models import SQLAlchemyUser, TortoiseUser, UserRole
from src.core.logging_config import get_logger
from src.core.exceptions import AuthenticationError, AuthorizationError

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
        """Get user by username."""
        stmt = select(SQLAlchemyUser).where(
            SQLAlchemyUser.username == username
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def get_by_email(self, email: str) -> Optional[SQLAlchemyUser]:
        """Get user by email."""
        stmt = select(SQLAlchemyUser).where(
            SQLAlchemyUser.email == email
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()
    
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
        """Authenticate user by API key."""
        # Hash the provided API key
        api_key_hash = self._hash_api_key(api_key)
        
        stmt = select(SQLAlchemyUser).where(
            SQLAlchemyUser.api_key_hash == api_key_hash,
            SQLAlchemyUser.is_active == True
        )
        result = await self._session.execute(stmt)
        user = result.scalar_one_or_none()
        
        if user:
            # Update last login
            await self.update_last_login(user.id)
        
        return user
    
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
        """Get all users with a specific role."""
        query = select(SQLAlchemyUser).where(
            SQLAlchemyUser.role == role
        )
        
        if not include_inactive:
            query = query.where(SQLAlchemyUser.is_active == True)
        
        query = query.order_by(SQLAlchemyUser.username)
        
        result = await self._session.execute(query)
        return result.scalars().all()
    
    async def search_users(
        self,
        search_term: str,
        limit: int = 50
    ) -> List[SQLAlchemyUser]:
        """Search users by username, email, or full name."""
        search_pattern = f"%{search_term}%"
        
        stmt = select(SQLAlchemyUser).where(
            or_(
                SQLAlchemyUser.username.ilike(search_pattern),
                SQLAlchemyUser.email.ilike(search_pattern),
                SQLAlchemyUser.full_name.ilike(search_pattern)
            )
        ).limit(limit)
        
        result = await self._session.execute(stmt)
        return result.scalars().all()
    
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
        """Get user statistics."""
        # Total users
        total_stmt = select(func.count(SQLAlchemyUser.id))
        total_result = await self._session.execute(total_stmt)
        total_users = total_result.scalar() or 0
        
        # Active users
        active_stmt = select(func.count(SQLAlchemyUser.id)).where(
            SQLAlchemyUser.is_active == True
        )
        active_result = await self._session.execute(active_stmt)
        active_users = active_result.scalar() or 0
        
        # Users by role
        role_stmt = select(
            SQLAlchemyUser.role,
            func.count(SQLAlchemyUser.id).label('count')
        ).group_by(SQLAlchemyUser.role)
        
        role_result = await self._session.execute(role_stmt)
        role_data = role_result.all()
        
        users_by_role = {row.role: row.count for row in role_data}
        
        # Recent logins (last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_stmt = select(func.count(SQLAlchemyUser.id)).where(
            SQLAlchemyUser.last_login >= thirty_days_ago
        )
        recent_result = await self._session.execute(recent_stmt)
        recent_logins = recent_result.scalar() or 0
        
        return {
            "total_users": total_users,
            "active_users": active_users,
            "inactive_users": total_users - active_users,
            "users_by_role": users_by_role,
            "recent_logins_30d": recent_logins
        }
    
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