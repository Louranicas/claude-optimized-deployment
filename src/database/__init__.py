"""Database module for Claude Optimized Deployment Engine.

This module provides:
- Async ORM support with SQLAlchemy and Tortoise ORM
- Connection pooling and management
- Data models for audit logs, queries, deployments, etc.
- Repository pattern for data access
- Migration support with Alembic/Aerich
- Support for PostgreSQL (primary) and SQLite (development)
- Backup/restore utilities and database optimization
- Time-series metrics storage
"""

from src.database.connection import (
    DatabaseConnection,
    get_database_connection,
    init_database,
    close_database,
)
from src.database.models import (
    # SQLAlchemy models
    SQLAlchemyAuditLog,
    SQLAlchemyQueryHistory,
    SQLAlchemyDeploymentRecord,
    SQLAlchemyConfiguration,
    SQLAlchemyUser,
    SQLAlchemyMetricData,
    
    # Tortoise models
    TortoiseAuditLog,
    TortoiseQueryHistory,
    TortoiseDeploymentRecord,
    TortoiseConfiguration,
    TortoiseUser,
    TortoiseMetricData,
    
    # Enums
    DeploymentStatus,
    LogLevel,
    UserRole,
    
    # Aliases (default to SQLAlchemy)
    AuditLog,
    QueryHistory,
    DeploymentRecord,
    Configuration,
    User,
    MetricData,
    Base,
)

from src.database.repositories.audit_repository import AuditLogRepository
from src.database.repositories.query_repository import QueryHistoryRepository
from src.database.repositories.deployment_repository import DeploymentRepository
from src.database.repositories.configuration_repository import ConfigurationRepository
from src.database.repositories.user_repository import UserRepository
from src.database.repositories.metrics_repository import MetricsRepository
from src.database.repositories.base import BaseRepository, SQLAlchemyRepository, TortoiseRepository

from src.database.utils import (
    DatabaseBackup,
    DatabaseRestore,
    DatabaseOptimizer,
    DatabaseArchiver,
)

from src.database.init import DatabaseInitializer

__all__ = [
    # Connection management
    "DatabaseConnection",
    "get_database_connection",
    "init_database",
    "close_database",
    
    # SQLAlchemy models
    "SQLAlchemyAuditLog",
    "SQLAlchemyQueryHistory",
    "SQLAlchemyDeploymentRecord",
    "SQLAlchemyConfiguration",
    "SQLAlchemyUser",
    "SQLAlchemyMetricData",
    "Base",
    
    # Tortoise models
    "TortoiseAuditLog",
    "TortoiseQueryHistory",
    "TortoiseDeploymentRecord",
    "TortoiseConfiguration",
    "TortoiseUser",
    "TortoiseMetricData",
    
    # Enums
    "DeploymentStatus",
    "LogLevel",
    "UserRole",
    
    # Default aliases
    "AuditLog",
    "QueryHistory",
    "DeploymentRecord",
    "Configuration",
    "User",
    "MetricData",
    
    # Repositories
    "AuditLogRepository",
    "QueryHistoryRepository",
    "DeploymentRepository",
    "ConfigurationRepository",
    "UserRepository",
    "MetricsRepository",
    "BaseRepository",
    "SQLAlchemyRepository",
    "TortoiseRepository",
    
    # Utilities
    "DatabaseBackup",
    "DatabaseRestore",
    "DatabaseOptimizer",
    "DatabaseArchiver",
    "DatabaseInitializer",
]