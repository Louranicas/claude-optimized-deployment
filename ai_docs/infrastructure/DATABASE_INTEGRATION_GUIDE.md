# Database Integration Guide

## Overview

The Claude Optimized Deployment Engine features a comprehensive database integration layer with support for both SQLAlchemy and Tortoise ORM, providing:

- ✅ **Async ORM Support**: Full async/await database operations
- ✅ **Dual ORM Support**: SQLAlchemy (primary) + Tortoise ORM (optional)
- ✅ **Connection Pooling**: Optimized connection management
- ✅ **Repository Pattern**: Clean data access layer
- ✅ **Migrations**: Alembic integration for schema management
- ✅ **Backup/Restore**: Comprehensive data protection
- ✅ **Time-Series Support**: Built-in metrics storage
- ✅ **Performance Optimization**: Database tuning utilities

## Architecture

### Models

All database models support both SQLAlchemy and Tortoise ORM:

```python
from src.database import (
    User, AuditLog, QueryHistory, DeploymentRecord, 
    Configuration, MetricData, UserRole, DeploymentStatus
)
```

### Repository Pattern

Clean data access through repository classes:

```python
from src.database import (
    UserRepository, AuditLogRepository, DeploymentRepository,
    ConfigurationRepository, MetricsRepository
)

# Usage with async context
async with db_connection.get_session() as session:
    user_repo = UserRepository(session)
    user = await user_repo.create_user(
        username="developer",
        email="dev@company.com",
        role=UserRole.DEVELOPER
    )
```

## Quick Start

### 1. Installation

```bash
# Install database dependencies
pip install -r requirements.txt

# For PostgreSQL (recommended for production)
pip install asyncpg

# For SQLite (development)
pip install aiosqlite
```

### 2. Configuration

Copy the example configuration:

```bash
cp .env.database.example .env
```

Configure your database URL in `.env`:

```bash
# Development (SQLite)
DATABASE_URL=sqlite+aiosqlite:///./code_deployment.db

# Production (PostgreSQL)
DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/code_deployment
```

### 3. Initialize Database

```bash
# Using the CLI tool
python scripts/db_manager.py init

# Or using Python
python -c "
import asyncio
from src.database.init import DatabaseInitializer

async def setup():
    db_init = DatabaseInitializer()
    await db_init.initialize()
    await db_init.setup_database()

asyncio.run(setup())
"
```

### 4. Basic Usage

```python
import asyncio
from src.database import init_database, UserRepository, UserRole

async def example():
    # Initialize database connection
    db_connection = await init_database()
    
    # Use repository
    async with db_connection.get_session() as session:
        user_repo = UserRepository(session)
        
        # Create user
        user = await user_repo.create_user(
            username="admin",
            email="admin@example.com",
            role=UserRole.ADMIN
        )
        
        # Generate API key
        api_key = await user_repo.generate_api_key(user.id)
        print(f"API Key: {api_key}")

asyncio.run(example())
```

## Database Models

### Core Models

#### Users (`users` table)
- User management and authentication
- Role-based access control (Admin, Developer, Operator, Viewer)
- API key authentication
- Activity tracking

```python
user = await user_repo.create_user(
    username="developer",
    email="dev@company.com",
    full_name="Development User",
    role=UserRole.DEVELOPER
)
```

#### Audit Logs (`audit_logs` table)
- Complete audit trail of all system actions
- User activity tracking
- Resource change history
- Compliance reporting

```python
await audit_repo.log_action(
    action="CREATE_DEPLOYMENT",
    resource_type="DEPLOYMENT",
    resource_id=deployment.deployment_id,
    user_id=user.id,
    details={"environment": "production"},
    success=True
)
```

#### Query History (`query_history` table)
- Circle of Experts consultation history
- Performance metrics and cost tracking
- Expert usage analytics

```python
await query_repo.record_query(
    query_text="Deploy application to production",
    query_type="deployment",
    experts_consulted=["claude", "deepseek"],
    execution_time_ms=1250,
    tokens_used=1500,
    estimated_cost=0.025
)
```

#### Deployment Records (`deployment_records` table)
- Infrastructure deployment tracking
- Version management and rollback support
- Performance metrics collection

```python
deployment = await deploy_repo.create_deployment(
    environment="production",
    service_name="api-service",
    version="v1.2.3",
    deployment_type="kubernetes"
)

await deploy_repo.complete_deployment(
    deployment.deployment_id,
    success=True,
    metrics={"cpu_usage": 45.2, "memory_usage": 67.8}
)
```

#### Configurations (`configurations` table)
- System configuration management
- Environment-specific settings
- Version tracking and audit trail

```python
await config_repo.set_config(
    key="deployment.timeout",
    value=300,
    category="deployment",
    description="Default deployment timeout in seconds"
)
```

#### Metric Data (`metric_data` table)
- Time-series metrics storage
- Prometheus-compatible data model
- Performance monitoring data

```python
await metrics_repo.record_metric(
    metric_name="cpu_usage_percent",
    value=75.5,
    labels={"host": "prod-server-01", "service": "api"}
)
```

## Repository Operations

### User Management

```python
async with db_connection.get_session() as session:
    user_repo = UserRepository(session)
    
    # Create user
    user = await user_repo.create_user(
        username="newuser",
        email="user@company.com",
        role=UserRole.DEVELOPER
    )
    
    # Generate API key
    api_key = await user_repo.generate_api_key(user.id)
    
    # Authenticate by API key
    auth_user = await user_repo.authenticate_by_api_key(api_key)
    
    # Search users
    users = await user_repo.search_users("developer")
    
    # Get statistics
    stats = await user_repo.get_user_statistics()
```

### Audit Trail

```python
async with db_connection.get_session() as session:
    audit_repo = AuditLogRepository(session)
    
    # Log action
    await audit_repo.log_action(
        action="UPDATE_CONFIG",
        resource_type="CONFIGURATION",
        resource_id="app.timeout",
        user_id=user.id,
        details={"old_value": 30, "new_value": 60}
    )
    
    # Get user actions
    actions = await audit_repo.get_user_actions(user.id)
    
    # Get resource history
    history = await audit_repo.get_resource_history(
        "CONFIGURATION", "app.timeout"
    )
    
    # Generate compliance report
    report = await audit_repo.get_compliance_report(
        start_date=datetime.now() - timedelta(days=30),
        end_date=datetime.now()
    )
```

### Deployment Tracking

```python
async with db_connection.get_session() as session:
    deploy_repo = DeploymentRepository(session)
    
    # Create deployment
    deployment = await deploy_repo.create_deployment(
        environment="staging",
        service_name="api",
        version="1.0.0",
        deployment_type="docker"
    )
    
    # Start deployment
    await deploy_repo.start_deployment(deployment.deployment_id)
    
    # Complete deployment
    await deploy_repo.complete_deployment(
        deployment.deployment_id,
        success=True,
        metrics={"duration": 120, "cpu_peak": 80}
    )
    
    # Get deployment history
    history = await deploy_repo.get_deployment_history(
        "staging", "api"
    )
    
    # Get metrics
    metrics = await deploy_repo.get_deployment_metrics(
        start_date=datetime.now() - timedelta(days=7),
        end_date=datetime.now()
    )
```

### Metrics Collection

```python
async with db_connection.get_session() as session:
    metrics_repo = MetricsRepository(session)
    
    # Record single metric
    await metrics_repo.record_metric(
        metric_name="response_time_ms",
        value=45.2,
        labels={"endpoint": "/api/health", "method": "GET"}
    )
    
    # Batch recording
    metrics_batch = [
        {
            "metric_name": "cpu_usage",
            "value": 75.5,
            "labels": {"host": "server-01"}
        },
        {
            "metric_name": "memory_usage", 
            "value": 60.2,
            "labels": {"host": "server-01"}
        }
    ]
    await metrics_repo.record_metrics_batch(metrics_batch)
    
    # Query metrics
    data = await metrics_repo.query_metrics(
        metric_name="cpu_usage",
        start_time=datetime.now() - timedelta(hours=1),
        end_time=datetime.now(),
        aggregation="avg",
        step_seconds=300
    )
```

## Database Management

### CLI Tool

The `scripts/db_manager.py` provides comprehensive database management:

```bash
# Initialize database
python scripts/db_manager.py init

# Run migrations
python scripts/db_manager.py migrate

# Check health
python scripts/db_manager.py health --detailed

# Create backup
python scripts/db_manager.py backup --type json --output backup.json

# Show statistics
python scripts/db_manager.py stats

# Archive old data
python scripts/db_manager.py archive --days 90

# Clean up specific tables
python scripts/db_manager.py cleanup audit_logs --days 30
```

### Programmatic Management

```python
from src.database.init import DatabaseInitializer
from src.database.utils import DatabaseBackup, DatabaseOptimizer

# Initialize database
db_init = DatabaseInitializer()
await db_init.initialize()
await db_init.setup_database()

# Health check
health = await db_init.health_check()

# Create backup
backup_file = await db_init.backup_database("json")

# Optimize database
optimization = await db_init.optimize_database()

# Archive old data
archive_results = await db_init.archive_old_data(days_to_keep=90)
```

## Migrations

### Creating Migrations

```bash
# Generate migration from model changes
cd src/database
alembic revision --autogenerate -m "Add new feature table"

# Create empty migration
alembic revision -m "Custom migration"
```

### Running Migrations

```bash
# Using CLI tool
python scripts/db_manager.py migrate

# Using alembic directly
cd src/database
alembic upgrade head

# Programmatically
from src.database.init import DatabaseInitializer
db_init = DatabaseInitializer()
await db_init.run_migrations()
```

### Migration Structure

```python
"""Add new feature

Revision ID: 0002
Revises: 0001
Create Date: 2025-05-31
"""

def upgrade() -> None:
    """Upgrade database schema."""
    op.create_table('new_feature',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )

def downgrade() -> None:
    """Downgrade database schema."""
    op.drop_table('new_feature')
```

## Backup and Restore

### Backup Options

```python
from src.database.utils import DatabaseBackup

backup_manager = DatabaseBackup("./backups")

# JSON backup (cross-platform)
backup_file = await backup_manager.backup_to_json([
    "users", "audit_logs", "configurations"
])

# PostgreSQL dump
backup_file = await backup_manager.backup_postgresql(connection_string)

# SQLite backup
backup_file = await backup_manager.backup_sqlite(db_path)
```

### Restore Operations

```python
from src.database.utils import DatabaseRestore

restore_manager = DatabaseRestore()

# Restore from JSON
result = await restore_manager.restore_from_json("backup.json")

# Restore PostgreSQL
await restore_manager.restore_postgresql("backup.sql", connection_string)
```

## Performance Optimization

### Connection Pooling

Configure in `.env`:

```bash
# PostgreSQL connection pooling
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=10
DB_POOL_TIMEOUT=30
DB_POOL_RECYCLE=3600
```

### Database Optimization

```python
from src.database.utils import DatabaseOptimizer

optimizer = DatabaseOptimizer()

# Analyze performance
analysis = await optimizer.analyze_postgresql()

# Run maintenance
await optimizer.vacuum_analyze()

# Get index suggestions
suggestions = await optimizer.create_missing_indexes()
```

### Monitoring

```python
# Health monitoring
health = await db_connection.health_check()
print(f"Pool status: {health['pool_status']}")

# Performance metrics
from src.database.repositories.metrics_repository import MetricsRepository
metrics_repo = MetricsRepository(session)
summary = await metrics_repo.get_metrics_summary()
```

## Testing

### Integration Tests

Run comprehensive database tests:

```bash
python test_database_integration.py
```

### Unit Tests

```python
import pytest
from src.database import init_database, UserRepository

@pytest.mark.asyncio
async def test_user_creation():
    db_connection = await init_database("sqlite+aiosqlite:///:memory:")
    
    async with db_connection.get_session() as session:
        user_repo = UserRepository(session)
        user = await user_repo.create_user(
            username="testuser",
            email="test@example.com"
        )
        assert user.username == "testuser"
```

## Security Considerations

### Authentication

- API key hashing with SHA-256
- Secure random key generation
- Session management
- Role-based access control

### Data Protection

- Sensitive configuration encryption
- Audit trail integrity
- Connection encryption (SSL)
- Input validation and sanitization

### Access Control

```python
# Role-based permissions
@require_role(UserRole.ADMIN)
async def admin_operation():
    pass

# Audit logging
await audit_repo.log_action(
    action="SENSITIVE_OPERATION",
    resource_type="SYSTEM",
    user_id=current_user.id,
    success=True
)
```

## Production Deployment

### Database Setup

1. **PostgreSQL Configuration**:
   ```sql
   CREATE DATABASE code_deployment;
   CREATE USER code_user WITH PASSWORD 'secure_password';
   GRANT ALL PRIVILEGES ON DATABASE code_deployment TO code_user;
   ```

2. **SSL Configuration**:
   ```bash
   DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/db?sslmode=require
   ```

3. **Connection Pooling**:
   ```bash
   DB_POOL_SIZE=50
   DB_MAX_OVERFLOW=20
   DB_POOL_TIMEOUT=30
   ```

### Monitoring and Maintenance

```bash
# Daily health check
python scripts/db_manager.py health --detailed

# Weekly optimization
python scripts/db_manager.py optimize

# Monthly archival
python scripts/db_manager.py archive --days 90

# Quarterly backup
python scripts/db_manager.py backup --type postgresql --output monthly_backup.sql
```

## Troubleshooting

### Common Issues

1. **Connection Pool Exhaustion**:
   - Increase `DB_POOL_SIZE`
   - Check for connection leaks
   - Monitor pool status

2. **Slow Queries**:
   - Enable query logging (`DB_ECHO=true`)
   - Run database optimization
   - Check index usage

3. **Migration Failures**:
   - Check database permissions
   - Verify schema compatibility
   - Review migration logs

### Debug Mode

```bash
# Enable detailed logging
export DB_ECHO=true
export DB_ECHO_POOL=true
python scripts/db_manager.py health --detailed
```

### Performance Monitoring

```python
# Monitor connection pool
health = await db_connection.health_check()
pool_status = health.get('pool_status', {})

if pool_status.get('size', 0) > 0.8 * pool_status.get('total', 1):
    logger.warning("Connection pool utilization high")
```

## Best Practices

1. **Use Transactions**: Always use session context managers
2. **Index Optimization**: Regularly check and create indexes
3. **Data Archival**: Implement automated old data cleanup
4. **Backup Strategy**: Multiple backup types and locations
5. **Monitoring**: Track performance and health metrics
6. **Security**: Use SSL, rotate keys, audit access

## Integration Examples

### Circle of Experts Integration

```python
from src.circle_of_experts import CircleOfExperts
from src.database import QueryHistoryRepository

async def consult_experts_with_logging(query: str):
    # Consult experts
    experts = CircleOfExperts()
    result = await experts.process_query(query)
    
    # Log to database
    async with db_connection.get_session() as session:
        query_repo = QueryHistoryRepository(session)
        await query_repo.record_query(
            query_text=query,
            query_type="general",
            experts_consulted=result.experts_used,
            execution_time_ms=result.execution_time,
            tokens_used=result.total_tokens,
            estimated_cost=result.estimated_cost,
            success=result.success,
            response_summary=result.summary
        )
    
    return result
```

### MCP Server Integration

```python
from src.mcp import get_mcp_manager
from src.database import AuditLogRepository

async def execute_mcp_tool_with_audit(tool_name: str, params: dict, user_id: int):
    # Execute MCP tool
    manager = get_mcp_manager()
    result = await manager.call_tool(tool_name, params)
    
    # Log to audit trail
    async with db_connection.get_session() as session:
        audit_repo = AuditLogRepository(session)
        await audit_repo.log_action(
            action=f"MCP_TOOL_{tool_name.upper()}",
            resource_type="MCP_TOOL",
            resource_id=tool_name,
            user_id=user_id,
            details={"params": params, "result_summary": str(result)[:200]},
            success=result.get("success", True)
        )
    
    return result
```

---

## Support

For issues or questions:

1. Check the troubleshooting section
2. Review logs with `--verbose` flag
3. Run health checks
4. Consult the test suite for examples

The database integration layer provides a solid foundation for the Claude Optimized Deployment Engine with enterprise-grade features for data management, audit trails, and performance optimization.