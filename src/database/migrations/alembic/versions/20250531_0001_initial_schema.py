"""Initial schema creation for all database models

Revision ID: 0001
Revises: 
Create Date: 2025-05-31

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create all initial tables with proper indexes."""
    
    # Create users table
    op.create_table('users',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('username', sa.String(length=50), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('full_name', sa.String(length=255), nullable=True),
        sa.Column('role', sa.String(length=20), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('api_key_hash', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('last_login', sa.DateTime(timezone=True), nullable=True),
        sa.Column('preferences', sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=True)
    op.create_index(op.f('ix_users_role'), 'users', ['role'], unique=False)

    # Create audit_logs table
    op.create_table('audit_logs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('resource_type', sa.String(length=50), nullable=False),
        sa.Column('resource_id', sa.String(length=255), nullable=True),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('success', sa.Boolean(), nullable=False),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_audit_timestamp_action', 'audit_logs', ['timestamp', 'action'], unique=False)
    op.create_index('idx_audit_user_timestamp', 'audit_logs', ['user_id', 'timestamp'], unique=False)
    op.create_index('idx_audit_resource', 'audit_logs', ['resource_type', 'resource_id'], unique=False)
    op.create_index(op.f('ix_audit_logs_timestamp'), 'audit_logs', ['timestamp'], unique=False)
    op.create_index(op.f('ix_audit_logs_action'), 'audit_logs', ['action'], unique=False)
    op.create_index(op.f('ix_audit_logs_resource_type'), 'audit_logs', ['resource_type'], unique=False)

    # Create query_history table
    op.create_table('query_history',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('query_id', sa.String(length=36), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('query_text', sa.Text(), nullable=False),
        sa.Column('query_type', sa.String(length=50), nullable=False),
        sa.Column('experts_consulted', sa.JSON(), nullable=False),
        sa.Column('response_summary', sa.Text(), nullable=True),
        sa.Column('response_data', sa.JSON(), nullable=True),
        sa.Column('execution_time_ms', sa.Integer(), nullable=True),
        sa.Column('tokens_used', sa.Integer(), nullable=True),
        sa.Column('estimated_cost', sa.Float(), nullable=True),
        sa.Column('success', sa.Boolean(), nullable=False),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('query_id')
    )
    op.create_index('idx_query_timestamp_user', 'query_history', ['timestamp', 'user_id'], unique=False)
    op.create_index('idx_query_type_success', 'query_history', ['query_type', 'success'], unique=False)
    op.create_index(op.f('ix_query_history_timestamp'), 'query_history', ['timestamp'], unique=False)

    # Create deployment_records table
    op.create_table('deployment_records',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('deployment_id', sa.String(length=36), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('environment', sa.String(length=50), nullable=False),
        sa.Column('service_name', sa.String(length=100), nullable=False),
        sa.Column('version', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('deployment_type', sa.String(length=50), nullable=False),
        sa.Column('configuration', sa.JSON(), nullable=True),
        sa.Column('manifest', sa.Text(), nullable=True),
        sa.Column('start_time', sa.DateTime(timezone=True), nullable=True),
        sa.Column('end_time', sa.DateTime(timezone=True), nullable=True),
        sa.Column('duration_seconds', sa.Integer(), nullable=True),
        sa.Column('rollback_version', sa.String(length=50), nullable=True),
        sa.Column('error_logs', sa.Text(), nullable=True),
        sa.Column('metrics', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('deployment_id'),
        sa.UniqueConstraint('environment', 'service_name', 'version', name='uq_deployment_version')
    )
    op.create_index('idx_deployment_env_service', 'deployment_records', ['environment', 'service_name'], unique=False)
    op.create_index('idx_deployment_timestamp_status', 'deployment_records', ['timestamp', 'status'], unique=False)
    op.create_index(op.f('ix_deployment_records_environment'), 'deployment_records', ['environment'], unique=False)
    op.create_index(op.f('ix_deployment_records_service_name'), 'deployment_records', ['service_name'], unique=False)
    op.create_index(op.f('ix_deployment_records_status'), 'deployment_records', ['status'], unique=False)
    op.create_index(op.f('ix_deployment_records_timestamp'), 'deployment_records', ['timestamp'], unique=False)

    # Create configurations table
    op.create_table('configurations',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('key', sa.String(length=255), nullable=False),
        sa.Column('value', sa.JSON(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('category', sa.String(length=50), nullable=False),
        sa.Column('is_sensitive', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_by', sa.Integer(), nullable=True),
        sa.Column('version', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['updated_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('key')
    )
    op.create_index('idx_config_category_key', 'configurations', ['category', 'key'], unique=False)
    op.create_index(op.f('ix_configurations_category'), 'configurations', ['category'], unique=False)
    op.create_index(op.f('ix_configurations_key'), 'configurations', ['key'], unique=True)

    # Create metric_data table for time-series data
    op.create_table('metric_data',
        sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('metric_name', sa.String(length=255), nullable=False),
        sa.Column('labels', sa.JSON(), nullable=True),
        sa.Column('value', sa.Float(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_metric_time_name', 'metric_data', ['timestamp', 'metric_name'], unique=False)
    op.create_index('idx_metric_name_time', 'metric_data', ['metric_name', 'timestamp'], unique=False)
    op.create_index(op.f('ix_metric_data_timestamp'), 'metric_data', ['timestamp'], unique=False)
    op.create_index(op.f('ix_metric_data_metric_name'), 'metric_data', ['metric_name'], unique=False)


def downgrade() -> None:
    """Drop all tables."""
    op.drop_index(op.f('ix_metric_data_metric_name'), table_name='metric_data')
    op.drop_index(op.f('ix_metric_data_timestamp'), table_name='metric_data')
    op.drop_index('idx_metric_name_time', table_name='metric_data')
    op.drop_index('idx_metric_time_name', table_name='metric_data')
    op.drop_table('metric_data')
    
    op.drop_index(op.f('ix_configurations_key'), table_name='configurations')
    op.drop_index(op.f('ix_configurations_category'), table_name='configurations')
    op.drop_index('idx_config_category_key', table_name='configurations')
    op.drop_table('configurations')
    
    op.drop_index(op.f('ix_deployment_records_timestamp'), table_name='deployment_records')
    op.drop_index(op.f('ix_deployment_records_status'), table_name='deployment_records')
    op.drop_index(op.f('ix_deployment_records_service_name'), table_name='deployment_records')
    op.drop_index(op.f('ix_deployment_records_environment'), table_name='deployment_records')
    op.drop_index('idx_deployment_timestamp_status', table_name='deployment_records')
    op.drop_index('idx_deployment_env_service', table_name='deployment_records')
    op.drop_table('deployment_records')
    
    op.drop_index(op.f('ix_query_history_timestamp'), table_name='query_history')
    op.drop_index('idx_query_type_success', table_name='query_history')
    op.drop_index('idx_query_timestamp_user', table_name='query_history')
    op.drop_table('query_history')
    
    op.drop_index(op.f('ix_audit_logs_resource_type'), table_name='audit_logs')
    op.drop_index(op.f('ix_audit_logs_action'), table_name='audit_logs')
    op.drop_index(op.f('ix_audit_logs_timestamp'), table_name='audit_logs')
    op.drop_index('idx_audit_resource', table_name='audit_logs')
    op.drop_index('idx_audit_user_timestamp', table_name='audit_logs')
    op.drop_index('idx_audit_timestamp_action', table_name='audit_logs')
    op.drop_table('audit_logs')
    
    op.drop_index(op.f('ix_users_role'), table_name='users')
    op.drop_index(op.f('ix_users_username'), table_name='users')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_table('users')