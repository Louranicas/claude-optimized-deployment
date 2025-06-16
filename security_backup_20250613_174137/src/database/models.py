"""Database models for audit logs, query history, deployments, and more.

This module provides both SQLAlchemy and Tortoise ORM models for flexibility.
The models support async operations and include proper indexing for performance.
"""

from datetime import datetime
from typing import Optional, Dict, Any, List
from enum import Enum
import json
from uuid import uuid4

# SQLAlchemy imports
from sqlalchemy import (
    Column, String, Integer, DateTime, Text, JSON, Boolean, 
    ForeignKey, Index, Float, UniqueConstraint, BigInteger
)

__all__ = [
    "DeploymentStatus",
    "LogLevel",
    "UserRole",
    "SQLAlchemyAuditLog",
    "SQLAlchemyQueryHistory",
    "SQLAlchemyDeploymentRecord",
    "SQLAlchemyConfiguration",
    "SQLAlchemyUser",
    "SQLAlchemyMetricData",
    "TortoiseAuditLog",
    "TortoiseQueryHistory",
    "TortoiseDeploymentRecord",
    "TortoiseConfiguration",
    "TortoiseUser",
    "TortoiseMetricData"
]
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import UUID

# Tortoise ORM imports
from tortoise.models import Model
from tortoise import fields

# Create SQLAlchemy base
Base = declarative_base()


# Enums for common statuses
class DeploymentStatus(str, Enum):
    """Deployment status enumeration."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class LogLevel(str, Enum):
    """Log level enumeration."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class UserRole(str, Enum):
    """User role enumeration."""
    ADMIN = "admin"
    DEVELOPER = "developer"
    OPERATOR = "operator"
    VIEWER = "viewer"


# ===== SQLAlchemy Models =====

class SQLAlchemyAuditLog(Base):
    """Audit log for tracking all system actions (SQLAlchemy)."""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(50), nullable=False, index=True)
    resource_id = Column(String(255), nullable=True)
    details = Column(JSON, nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    success = Column(Boolean, default=True, nullable=False)
    error_message = Column(Text, nullable=True)
    
    # Relationships
    user = relationship("SQLAlchemyUser", back_populates="audit_logs")
    
    # Indexes for performance
    __table_args__ = (
        Index("idx_audit_timestamp_action", "timestamp", "action"),
        Index("idx_audit_user_timestamp", "user_id", "timestamp"),
        Index("idx_audit_resource", "resource_type", "resource_id"),
    )


class SQLAlchemyQueryHistory(Base):
    """History of Circle of Experts queries (SQLAlchemy)."""
    __tablename__ = "query_history"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    query_id = Column(String(36), default=lambda: str(uuid4()), unique=True, nullable=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    query_text = Column(Text, nullable=False)
    query_type = Column(String(50), nullable=False)
    experts_consulted = Column(JSON, nullable=False)  # List of expert names
    response_summary = Column(Text, nullable=True)
    response_data = Column(JSON, nullable=True)  # Full response data
    execution_time_ms = Column(Integer, nullable=True)
    tokens_used = Column(Integer, nullable=True)
    estimated_cost = Column(Float, nullable=True)
    success = Column(Boolean, default=True, nullable=False)
    error_message = Column(Text, nullable=True)
    
    # Relationships
    user = relationship("SQLAlchemyUser", back_populates="queries")
    
    # Indexes
    __table_args__ = (
        Index("idx_query_timestamp_user", "timestamp", "user_id"),
        Index("idx_query_type_success", "query_type", "success"),
    )


class SQLAlchemyDeploymentRecord(Base):
    """Deployment records for tracking infrastructure changes (SQLAlchemy)."""
    __tablename__ = "deployment_records"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    deployment_id = Column(String(36), default=lambda: str(uuid4()), unique=True, nullable=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    environment = Column(String(50), nullable=False, index=True)
    service_name = Column(String(100), nullable=False, index=True)
    version = Column(String(50), nullable=False)
    status = Column(String(20), default=DeploymentStatus.PENDING, nullable=False, index=True)
    deployment_type = Column(String(50), nullable=False)  # docker, kubernetes, terraform, etc.
    configuration = Column(JSON, nullable=True)
    manifest = Column(Text, nullable=True)
    start_time = Column(DateTime(timezone=True), nullable=True)
    end_time = Column(DateTime(timezone=True), nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    rollback_version = Column(String(50), nullable=True)
    error_logs = Column(Text, nullable=True)
    metrics = Column(JSON, nullable=True)  # Performance metrics, resource usage, etc.
    
    # Relationships
    user = relationship("SQLAlchemyUser", back_populates="deployments")
    
    # Indexes
    __table_args__ = (
        Index("idx_deployment_env_service", "environment", "service_name"),
        Index("idx_deployment_timestamp_status", "timestamp", "status"),
        UniqueConstraint("environment", "service_name", "version", name="uq_deployment_version"),
    )


class SQLAlchemyConfiguration(Base):
    """Configuration storage for system settings (SQLAlchemy)."""
    __tablename__ = "configurations"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(255), unique=True, nullable=False, index=True)
    value = Column(JSON, nullable=False)
    description = Column(Text, nullable=True)
    category = Column(String(50), nullable=False, index=True)
    is_sensitive = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    updated_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    version = Column(Integer, default=1, nullable=False)
    
    # Relationships
    user = relationship("SQLAlchemyUser", foreign_keys=[updated_by])
    
    # Indexes
    __table_args__ = (
        Index("idx_config_category_key", "category", "key"),
    )


class SQLAlchemyUser(Base):
    """User management for access control (SQLAlchemy)."""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(255), nullable=True)
    role = Column(String(20), default=UserRole.VIEWER, nullable=False, index=True)
    is_active = Column(Boolean, default=True, nullable=False)
    api_key_hash = Column(String(255), nullable=True)  # For API access
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_login = Column(DateTime(timezone=True), nullable=True)
    preferences = Column(JSON, nullable=True)
    
    # Relationships
    audit_logs = relationship("SQLAlchemyAuditLog", back_populates="user")
    queries = relationship("SQLAlchemyQueryHistory", back_populates="user")
    deployments = relationship("SQLAlchemyDeploymentRecord", back_populates="user")


# Time-series data model for Prometheus integration
class SQLAlchemyMetricData(Base):
    """Time-series metric data storage (SQLAlchemy)."""
    __tablename__ = "metric_data"
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    metric_name = Column(String(255), nullable=False, index=True)
    labels = Column(JSON, nullable=True)
    value = Column(Float, nullable=False)
    
    # Indexes for time-series queries
    __table_args__ = (
        Index("idx_metric_time_name", "timestamp", "metric_name"),
        Index("idx_metric_name_time", "metric_name", "timestamp"),
    )


# ===== Tortoise ORM Models =====

class TortoiseAuditLog(Model):
    """Audit log for tracking all system actions (Tortoise ORM)."""
    id = fields.IntField(pk=True)
    timestamp = fields.DatetimeField(auto_now_add=True, index=True)
    user = fields.ForeignKeyField("models.TortoiseUser", related_name="audit_logs", null=True)
    action = fields.CharField(max_length=100, index=True)
    resource_type = fields.CharField(max_length=50, index=True)
    resource_id = fields.CharField(max_length=255, null=True)
    details = fields.JSONField(null=True)
    ip_address = fields.CharField(max_length=45, null=True)
    user_agent = fields.TextField(null=True)
    success = fields.BooleanField(default=True)
    error_message = fields.TextField(null=True)
    
    class Meta:
        table = "tortoise_audit_logs"
        indexes = [
            ("timestamp", "action"),
            ("user_id", "timestamp"),
            ("resource_type", "resource_id"),
        ]


class TortoiseQueryHistory(Model):
    """History of Circle of Experts queries (Tortoise ORM)."""
    id = fields.IntField(pk=True)
    query_id = fields.UUIDField(unique=True, default=uuid4)
    timestamp = fields.DatetimeField(auto_now_add=True, index=True)
    user = fields.ForeignKeyField("models.TortoiseUser", related_name="queries", null=True)
    query_text = fields.TextField()
    query_type = fields.CharField(max_length=50)
    experts_consulted = fields.JSONField()
    response_summary = fields.TextField(null=True)
    response_data = fields.JSONField(null=True)
    execution_time_ms = fields.IntField(null=True)
    tokens_used = fields.IntField(null=True)
    estimated_cost = fields.FloatField(null=True)
    success = fields.BooleanField(default=True)
    error_message = fields.TextField(null=True)
    
    class Meta:
        table = "tortoise_query_history"
        indexes = [
            ("timestamp", "user_id"),
            ("query_type", "success"),
        ]


class TortoiseDeploymentRecord(Model):
    """Deployment records for tracking infrastructure changes (Tortoise ORM)."""
    id = fields.IntField(pk=True)
    deployment_id = fields.UUIDField(unique=True, default=uuid4)
    timestamp = fields.DatetimeField(auto_now_add=True, index=True)
    user = fields.ForeignKeyField("models.TortoiseUser", related_name="deployments", null=True)
    environment = fields.CharField(max_length=50, index=True)
    service_name = fields.CharField(max_length=100, index=True)
    version = fields.CharField(max_length=50)
    status = fields.CharEnumField(DeploymentStatus, default=DeploymentStatus.PENDING, index=True)
    deployment_type = fields.CharField(max_length=50)
    configuration = fields.JSONField(null=True)
    manifest = fields.TextField(null=True)
    start_time = fields.DatetimeField(null=True)
    end_time = fields.DatetimeField(null=True)
    duration_seconds = fields.IntField(null=True)
    rollback_version = fields.CharField(max_length=50, null=True)
    error_logs = fields.TextField(null=True)
    metrics = fields.JSONField(null=True)
    
    class Meta:
        table = "tortoise_deployment_records"
        indexes = [
            ("environment", "service_name"),
            ("timestamp", "status"),
        ]
        unique_together = [("environment", "service_name", "version")]


class TortoiseConfiguration(Model):
    """Configuration storage for system settings (Tortoise ORM)."""
    id = fields.IntField(pk=True)
    key = fields.CharField(max_length=255, unique=True, index=True)
    value = fields.JSONField()
    description = fields.TextField(null=True)
    category = fields.CharField(max_length=50, index=True)
    is_sensitive = fields.BooleanField(default=False)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)
    updated_by = fields.ForeignKeyField("models.TortoiseUser", null=True)
    version = fields.IntField(default=1)
    
    class Meta:
        table = "tortoise_configurations"
        indexes = [("category", "key")]


class TortoiseUser(Model):
    """User management for access control (Tortoise ORM)."""
    id = fields.IntField(pk=True)
    username = fields.CharField(max_length=50, unique=True, index=True)
    email = fields.CharField(max_length=255, unique=True, index=True)
    full_name = fields.CharField(max_length=255, null=True)
    role = fields.CharEnumField(UserRole, default=UserRole.VIEWER, index=True)
    is_active = fields.BooleanField(default=True)
    api_key_hash = fields.CharField(max_length=255, null=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    last_login = fields.DatetimeField(null=True)
    preferences = fields.JSONField(null=True)
    
    class Meta:
        table = "tortoise_users"


class TortoiseMetricData(Model):
    """Time-series metric data storage (Tortoise ORM)."""
    id = fields.BigIntField(pk=True)
    timestamp = fields.DatetimeField(index=True)
    metric_name = fields.CharField(max_length=255, index=True)
    labels = fields.JSONField(null=True)
    value = fields.FloatField()
    
    class Meta:
        table = "tortoise_metric_data"
        indexes = [
            ("timestamp", "metric_name"),
            ("metric_name", "timestamp"),
        ]


# Aliases for easier imports
AuditLog = SQLAlchemyAuditLog
QueryHistory = SQLAlchemyQueryHistory
DeploymentRecord = SQLAlchemyDeploymentRecord
Configuration = SQLAlchemyConfiguration
User = SQLAlchemyUser
MetricData = SQLAlchemyMetricData