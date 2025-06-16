from src.database.repositories.audit_repository import AuditLogRepository
from src.database.repositories.query_repository import QueryHistoryRepository
from src.database.repositories.deployment_repository import DeploymentRepository
from src.database.repositories.configuration_repository import ConfigurationRepository
from src.database.repositories.user_repository import UserRepository
from src.database.repositories.metrics_repository import MetricsRepository
from src.database.repositories.base import BaseRepository, SQLAlchemyRepository, TortoiseRepository
from src.database.init import DatabaseInitializer

try:
    from src.database.connection import (
        DatabaseConnection,
        get_database_connection,
        init_database,
        close_database,
    )
except ImportError:
    # Fallback definitions
    DatabaseConnection = None
    get_database_connection = None
    init_database = None
    close_database = None

try:
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
except ImportError:
    # Fallback definitions
    SQLAlchemyAuditLog = None
    SQLAlchemyQueryHistory = None
    SQLAlchemyDeploymentRecord = None
    SQLAlchemyConfiguration = None
    SQLAlchemyUser = None
    SQLAlchemyMetricData = None
    TortoiseAuditLog = None
    TortoiseQueryHistory = None
    TortoiseDeploymentRecord = None
    TortoiseConfiguration = None
    TortoiseUser = None
    TortoiseMetricData = None
    DeploymentStatus = None
    LogLevel = None
    UserRole = None
    AuditLog = None
    QueryHistory = None
    DeploymentRecord = None
    Configuration = None
    User = None
    MetricData = None
    Base = None

try:
    from src.database.utils import (
        DatabaseBackup,
        DatabaseRestore,
        DatabaseOptimizer,
        DatabaseArchiver,
    )
except ImportError:
    # Fallback definitions
    DatabaseBackup = None
    DatabaseRestore = None
    DatabaseOptimizer = None
    DatabaseArchiver = None

__version__ = "0.1.0"
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