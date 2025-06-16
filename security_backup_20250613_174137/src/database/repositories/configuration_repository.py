"""Repository for configuration management.

Handles system configuration storage with versioning and audit trails.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
import json

from sqlalchemy import select, func

from src.database.repositories.base import SQLAlchemyRepository, TortoiseRepository
from src.database.models import SQLAlchemyConfiguration, TortoiseConfiguration
from src.core.logging_config import get_logger
from src.core.exceptions import ConfigurationError

__all__ = [
    "ConfigurationRepository",
    "TortoiseConfigurationRepository"
]


logger = get_logger(__name__)


class ConfigurationRepository(SQLAlchemyRepository[SQLAlchemyConfiguration]):
    """Repository for configuration operations using SQLAlchemy."""
    
    def __init__(self, session=None):
        super().__init__(SQLAlchemyConfiguration, session)
    
    async def set_config(
        self,
        key: str,
        value: Any,
        category: str,
        description: Optional[str] = None,
        is_sensitive: bool = False,
        user_id: Optional[int] = None
    ) -> SQLAlchemyConfiguration:
        """Set or update a configuration value."""
        # Check if config exists
        existing = await self.get_by_key(key)
        
        if existing:
            # Update existing config with version increment
            return await self.update(
                existing.id,
                value=value,
                description=description or existing.description,
                category=category,
                is_sensitive=is_sensitive,
                updated_by=user_id,
                version=existing.version + 1
            )
        else:
            # Create new config
            return await self.create(
                key=key,
                value=value,
                category=category,
                description=description,
                is_sensitive=is_sensitive,
                updated_by=user_id
            )
    
    async def get_config(self, key: str) -> Optional[Any]:
        """Get configuration value by key."""
        config = await self.get_by_key(key)
        return config.value if config else None
    
    async def get_by_key(self, key: str) -> Optional[SQLAlchemyConfiguration]:
        """Get configuration object by key."""
        stmt = select(SQLAlchemyConfiguration).where(
            SQLAlchemyConfiguration.key == key
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def get_category_configs(
        self,
        category: str,
        include_sensitive: bool = False
    ) -> Dict[str, Any]:
        """Get all configurations for a category."""
        query = select(SQLAlchemyConfiguration).where(
            SQLAlchemyConfiguration.category == category
        )
        
        if not include_sensitive:
            query = query.where(SQLAlchemyConfiguration.is_sensitive == False)
        
        result = await self._session.execute(query)
        configs = result.scalars().all()
        
        return {
            config.key: config.value for config in configs
        }
    
    async def get_all_configs(
        self,
        include_sensitive: bool = False
    ) -> Dict[str, Dict[str, Any]]:
        """Get all configurations grouped by category."""
        query = select(SQLAlchemyConfiguration)
        
        if not include_sensitive:
            query = query.where(SQLAlchemyConfiguration.is_sensitive == False)
        
        query = query.order_by(
            SQLAlchemyConfiguration.category,
            SQLAlchemyConfiguration.key
        )
        
        result = await self._session.execute(query)
        configs = result.scalars().all()
        
        # Group by category
        grouped = {}
        for config in configs:
            if config.category not in grouped:
                grouped[config.category] = {}
            grouped[config.category][config.key] = {
                "value": config.value,
                "description": config.description,
                "is_sensitive": config.is_sensitive,
                "version": config.version,
                "updated_at": config.updated_at.isoformat() if config.updated_at else None
            }
        
        return grouped
    
    async def delete_config(self, key: str) -> bool:
        """Delete a configuration by key."""
        config = await self.get_by_key(key)
        if config:
            return await self.delete(config.id)
        return False
    
    async def bulk_set_configs(
        self,
        configs: Dict[str, Dict[str, Any]],
        user_id: Optional[int] = None
    ) -> List[SQLAlchemyConfiguration]:
        """Set multiple configurations at once."""
        results = []
        
        for key, config_data in configs.items():
            result = await self.set_config(
                key=key,
                value=config_data.get("value"),
                category=config_data.get("category", "general"),
                description=config_data.get("description"),
                is_sensitive=config_data.get("is_sensitive", False),
                user_id=user_id
            )
            results.append(result)
        
        return results
    
    async def export_configs(
        self,
        category: Optional[str] = None,
        include_sensitive: bool = False
    ) -> Dict[str, Any]:
        """Export configurations for backup or migration."""
        if category:
            configs = await self.get_category_configs(category, include_sensitive)
            export_data = {
                "category": category,
                "configs": configs,
                "exported_at": datetime.utcnow().isoformat()
            }
        else:
            configs = await self.get_all_configs(include_sensitive)
            export_data = {
                "all_categories": True,
                "configs": configs,
                "exported_at": datetime.utcnow().isoformat()
            }
        
        return export_data
    
    async def import_configs(
        self,
        import_data: Dict[str, Any],
        user_id: Optional[int] = None,
        overwrite: bool = False
    ) -> Dict[str, Any]:
        """Import configurations from exported data."""
        imported = 0
        skipped = 0
        errors = []
        
        configs = import_data.get("configs", {})
        
        if import_data.get("all_categories"):
            # Handle multi-category import
            for category, category_configs in configs.items():
                for key, config_info in category_configs.items():
                    try:
                        existing = await self.get_by_key(key)
                        if existing and not overwrite:
                            skipped += 1
                            continue
                        
                        await self.set_config(
                            key=key,
                            value=config_info.get("value") if isinstance(config_info, dict) else config_info,
                            category=category,
                            description=config_info.get("description") if isinstance(config_info, dict) else None,
                            is_sensitive=config_info.get("is_sensitive", False) if isinstance(config_info, dict) else False,
                            user_id=user_id
                        )
                        imported += 1
                    except Exception as e:
                        errors.append(f"Failed to import {key}: {str(e)}")
        else:
            # Handle single category import
            category = import_data.get("category", "general")
            for key, value in configs.items():
                try:
                    existing = await self.get_by_key(key)
                    if existing and not overwrite:
                        skipped += 1
                        continue
                    
                    await self.set_config(
                        key=key,
                        value=value,
                        category=category,
                        user_id=user_id
                    )
                    imported += 1
                except Exception as e:
                    errors.append(f"Failed to import {key}: {str(e)}")
        
        return {
            "imported": imported,
            "skipped": skipped,
            "errors": errors
        }
    
    async def get_config_history(
        self,
        key: str,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Get configuration change history.
        
        Note: This would require a separate history table in a real implementation.
        For now, we can only show current version info.
        """
        config = await self.get_by_key(key)
        if not config:
            return []
        
        return [{
            "key": config.key,
            "value": config.value,
            "version": config.version,
            "updated_at": config.updated_at.isoformat() if config.updated_at else None,
            "updated_by": config.updated_by
        }]


class TortoiseConfigurationRepository(TortoiseRepository[TortoiseConfiguration]):
    """Repository for configuration operations using Tortoise ORM."""
    
    def __init__(self):
        super().__init__(TortoiseConfiguration)
    
    async def set_config(
        self,
        key: str,
        value: Any,
        category: str,
        description: Optional[str] = None,
        is_sensitive: bool = False,
        user_id: Optional[int] = None
    ) -> TortoiseConfiguration:
        """Set or update a configuration value."""
        existing = await self.get_by_key(key)
        
        if existing:
            # Update existing
            existing.value = value
            existing.category = category
            existing.description = description or existing.description
            existing.is_sensitive = is_sensitive
            existing.updated_by_id = user_id
            existing.version += 1
            await existing.save()
            return existing
        else:
            # Create new
            return await self.create(
                key=key,
                value=value,
                category=category,
                description=description,
                is_sensitive=is_sensitive,
                updated_by_id=user_id
            )
    
    async def get_config(self, key: str) -> Optional[Any]:
        """Get configuration value by key."""
        config = await self.get_by_key(key)
        return config.value if config else None
    
    async def get_by_key(self, key: str) -> Optional[TortoiseConfiguration]:
        """Get configuration object by key."""
        return await TortoiseConfiguration.get_or_none(key=key)