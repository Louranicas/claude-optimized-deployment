"""Repository pattern implementations for data access.

This module provides repository classes that abstract database operations
and provide a clean interface for the application layer.
"""

from src.database.repositories.base import BaseRepository, AsyncRepository, SQLAlchemyRepository, TortoiseRepository
from src.database.repositories.audit_repository import AuditLogRepository, TortoiseAuditLogRepository
from src.database.repositories.query_repository import QueryHistoryRepository, TortoiseQueryHistoryRepository
from src.database.repositories.deployment_repository import DeploymentRepository, TortoiseDeploymentRepository
from src.database.repositories.configuration_repository import ConfigurationRepository, TortoiseConfigurationRepository
from src.database.repositories.user_repository import UserRepository, TortoiseUserRepository
from src.database.repositories.metrics_repository import MetricsRepository, TortoiseMetricsRepository

__all__ = [
    # Base repositories
    "BaseRepository",
    "AsyncRepository",
    "SQLAlchemyRepository",
    "TortoiseRepository",
    
    # SQLAlchemy repositories
    "AuditLogRepository",
    "QueryHistoryRepository",
    "DeploymentRepository",
    "ConfigurationRepository",
    "UserRepository",
    "MetricsRepository",
    
    # Tortoise repositories
    "TortoiseAuditLogRepository",
    "TortoiseQueryHistoryRepository",
    "TortoiseDeploymentRepository",
    "TortoiseConfigurationRepository",
    "TortoiseUserRepository",
    "TortoiseMetricsRepository",
]