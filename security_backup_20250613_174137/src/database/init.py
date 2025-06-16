"""Database initialization and management script.

Handles database setup, migrations, seeding, and maintenance operations.
"""

import asyncio
import os
import sys
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime

from alembic.config import Config
from alembic import command
from alembic.script import ScriptDirectory
from alembic.runtime.migration import MigrationContext

from src.database.connection import init_database, get_database_connection, close_database
from src.database.pool_manager import (
    DatabasePoolConfig,
    DatabasePoolManager,
    get_pool_manager,
    close_pool_manager
)
from src.database.models import Base, DeploymentStatus, UserRole, LogLevel
from src.database.repositories.user_repository import UserRepository
from src.database.repositories.configuration_repository import ConfigurationRepository
from src.database.utils import DatabaseBackup, DatabaseOptimizer, DatabaseArchiver
from src.core.logging_config import get_logger

__all__ = [
    "DatabaseInitializer"
]


logger = get_logger(__name__)


class DatabaseInitializer:
    """Manages database initialization and setup."""
    
    def __init__(self, connection_string: Optional[str] = None):
        """Initialize the database manager."""
        self.connection_string = connection_string
        self.db_connection = None
        
    async def initialize(self) -> None:
        """Initialize database connection."""
        self.db_connection = await init_database(self.connection_string)
        logger.info("Database connection initialized")
    
    async def setup_database(self, run_migrations: bool = True, seed_data: bool = True) -> Dict[str, Any]:
        """Complete database setup including migrations and seeding."""
        results = {
            "migrations_run": False,
            "tables_created": False,
            "data_seeded": False,
            "errors": []
        }
        
        try:
            if run_migrations:
                await self.run_migrations()
                results["migrations_run"] = True
            
            # Verify tables exist
            await self.verify_tables()
            results["tables_created"] = True
            
            if seed_data:
                await self.seed_initial_data()
                results["data_seeded"] = True
            
            logger.info("Database setup completed successfully")
            
        except Exception as e:
            logger.error(f"Database setup failed: {e}")
            results["errors"].append(str(e))
            raise
        
        return results
    
    async def run_migrations(self) -> None:
        """Run Alembic migrations."""
        try:
            # Get Alembic configuration
            alembic_cfg = self._get_alembic_config()
            
            # Check current revision
            async with self.db_connection._engine.connect() as conn:
                context = MigrationContext.configure(conn)
                current_rev = context.get_current_revision()
                
                # Get script directory
                script = ScriptDirectory.from_config(alembic_cfg)
                head_rev = script.get_current_head()
                
                if current_rev != head_rev:
                    logger.info(f"Running migrations from {current_rev} to {head_rev}")
                    
                    # Run migrations (this is sync, so we need to handle it properly)
                    await asyncio.get_event_loop().run_in_executor(
                        None, command.upgrade, alembic_cfg, "head"
                    )
                    logger.info("Migrations completed successfully")
                else:
                    logger.info("Database is already up to date")
                    
        except Exception as e:
            logger.error(f"Migration failed: {e}")
            raise
    
    def _get_alembic_config(self) -> Config:
        """Get Alembic configuration."""
        # Get path to alembic.ini
        db_dir = Path(__file__).parent
        ini_path = db_dir / "alembic.ini"
        
        alembic_cfg = Config(str(ini_path))
        
        # Set the database URL
        db_url = self.connection_string or os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./code_deployment.db")
        alembic_cfg.set_main_option("sqlalchemy.url", db_url)
        
        return alembic_cfg
    
    async def verify_tables(self) -> bool:
        """Verify that all required tables exist."""
        try:
            async with self.db_connection.get_session() as session:
                # Try to query each main table
                tables_to_check = [
                    "users", "audit_logs", "query_history", 
                    "deployment_records", "configurations", "metric_data"
                ]
                
                for table in tables_to_check:
                    result = await session.execute(f"SELECT 1 FROM {table} LIMIT 1")
                    logger.debug(f"Table {table} verified")
                
                logger.info("All required tables verified")
                return True
                
        except Exception as e:
            logger.error(f"Table verification failed: {e}")
            return False
    
    async def seed_initial_data(self) -> None:
        """Seed the database with initial required data."""
        try:
            async with self.db_connection.get_session() as session:
                user_repo = UserRepository(session)
                config_repo = ConfigurationRepository(session)
                
                # Create default admin user if not exists
                admin_user = await user_repo.get_by_username("admin")
                if not admin_user:
                    admin_user = await user_repo.create_user(
                        username="admin",
                        email="admin@localhost",
                        full_name="System Administrator",
                        role=UserRole.ADMIN
                    )
                    
                    # Generate API key for admin
                    api_key = await user_repo.generate_api_key(admin_user.id)
                    logger.info(f"Created admin user with API key: {api_key}")
                    logger.warning("Please save this API key - it won't be shown again!")
                
                # Seed default configurations
                default_configs = {
                    "system.version": {
                        "value": "1.0.0",
                        "category": "system",
                        "description": "System version"
                    },
                    "deployment.default_timeout": {
                        "value": 300,
                        "category": "deployment",
                        "description": "Default deployment timeout in seconds"
                    },
                    "audit.retention_days": {
                        "value": 90,
                        "category": "audit",
                        "description": "Audit log retention period in days"
                    },
                    "metrics.retention_days": {
                        "value": 30,
                        "category": "metrics",
                        "description": "Metrics data retention period in days"
                    },
                    "experts.default_timeout": {
                        "value": 30,
                        "category": "experts",
                        "description": "Default Circle of Experts timeout in seconds"
                    },
                    "mcp.max_connections": {
                        "value": 10,
                        "category": "mcp",
                        "description": "Maximum MCP server connections"
                    }
                }
                
                for key, config_data in default_configs.items():
                    existing = await config_repo.get_by_key(key)
                    if not existing:
                        await config_repo.set_config(
                            key=key,
                            value=config_data["value"],
                            category=config_data["category"],
                            description=config_data["description"],
                            user_id=admin_user.id if admin_user else None
                        )
                
                await session.commit()
                logger.info("Initial data seeded successfully")
                
        except Exception as e:
            logger.error(f"Data seeding failed: {e}")
            raise
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform comprehensive database health check."""
        if not self.db_connection:
            await self.initialize()
        
        health_status = await self.db_connection.health_check()
        
        # Add additional checks
        try:
            async with self.db_connection.get_session() as session:
                # Check table counts
                from sqlalchemy import text
                
                table_counts = {}
                tables = ["users", "audit_logs", "query_history", "deployment_records", "configurations", "metric_data"]
                
                for table in tables:
                    result = await session.execute(text(f"SELECT COUNT(*) FROM {table}"))
                    count = result.scalar()
                    table_counts[table] = count
                
                health_status["table_counts"] = table_counts
                health_status["overall_health"] = "healthy"
                
        except Exception as e:
            health_status["overall_health"] = "unhealthy"
            health_status["error"] = str(e)
        
        return health_status
    
    async def backup_database(self, backup_type: str = "json") -> str:
        """Create a database backup."""
        backup_manager = DatabaseBackup()
        
        if backup_type == "json":
            tables = ["users", "audit_logs", "query_history", "deployment_records", "configurations"]
            return await backup_manager.backup_to_json(tables)
        elif backup_type == "postgresql" and "postgresql" in (self.connection_string or ""):
            return await backup_manager.backup_postgresql(self.connection_string)
        elif backup_type == "sqlite" and "sqlite" in (self.connection_string or ""):
            db_path = self.connection_string.replace("sqlite+aiosqlite://", "").replace("sqlite://", "")
            return await backup_manager.backup_sqlite(db_path)
        else:
            raise ValueError(f"Unsupported backup type: {backup_type}")
    
    async def optimize_database(self) -> Dict[str, Any]:
        """Run database optimization operations."""
        optimizer = DatabaseOptimizer()
        
        # Run analysis
        analysis = await optimizer.analyze_postgresql()
        
        # Run VACUUM ANALYZE
        await optimizer.vacuum_analyze()
        
        # Get index suggestions
        index_suggestions = await optimizer.create_missing_indexes()
        
        return {
            "analysis": analysis,
            "index_suggestions": index_suggestions,
            "optimization_completed": True
        }
    
    async def archive_old_data(self, days_to_keep: int = 90) -> Dict[str, Any]:
        """Archive old data to maintain performance."""
        archiver = DatabaseArchiver()
        
        results = {}
        
        # Archive old audit logs
        results["audit_logs"] = await archiver.archive_old_data(
            "audit_logs", "timestamp", days_to_keep
        )
        
        # Archive old query history
        results["query_history"] = await archiver.archive_old_data(
            "query_history", "timestamp", days_to_keep
        )
        
        # Archive old metric data (shorter retention)
        results["metric_data"] = await archiver.archive_old_data(
            "metric_data", "timestamp", days_to_keep // 3
        )
        
        return results
    
    async def cleanup(self) -> None:
        """Clean up database connections."""
        if self.db_connection:
            await close_database()


async def main():
    """Main CLI interface for database management."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Database management CLI")
    parser.add_argument("--init", action="store_true", help="Initialize database")
    parser.add_argument("--migrate", action="store_true", help="Run migrations")
    parser.add_argument("--seed", action="store_true", help="Seed initial data")
    parser.add_argument("--health", action="store_true", help="Health check")
    parser.add_argument("--backup", choices=["json", "postgresql", "sqlite"], help="Create backup")
    parser.add_argument("--optimize", action="store_true", help="Optimize database")
    parser.add_argument("--archive", type=int, metavar="DAYS", help="Archive old data (days to keep)")
    parser.add_argument("--connection-string", help="Database connection string")
    
    args = parser.parse_args()
    
    if not any([args.init, args.migrate, args.seed, args.health, args.backup, args.optimize, args.archive]):
        parser.print_help()
        return
    
    # Initialize database manager
    db_init = DatabaseInitializer(args.connection_string)
    
    try:
        await db_init.initialize()
        
        if args.init:
            logger.info("Initializing database...")
            result = await db_init.setup_database()
            print(f"Database initialization result: {result}")
        
        if args.migrate:
            logger.info("Running migrations...")
            await db_init.run_migrations()
            print("Migrations completed")
        
        if args.seed:
            logger.info("Seeding initial data...")
            await db_init.seed_initial_data()
            print("Data seeding completed")
        
        if args.health:
            logger.info("Running health check...")
            health = await db_init.health_check()
            print(f"Database health: {health}")
        
        if args.backup:
            logger.info(f"Creating {args.backup} backup...")
            backup_file = await db_init.backup_database(args.backup)
            print(f"Backup created: {backup_file}")
        
        if args.optimize:
            logger.info("Optimizing database...")
            optimization_result = await db_init.optimize_database()
            print(f"Optimization completed: {optimization_result}")
        
        if args.archive:
            logger.info(f"Archiving data older than {args.archive} days...")
            archive_result = await db_init.archive_old_data(args.archive)
            print(f"Archiving completed: {archive_result}")
    
    except Exception as e:
        logger.error(f"Operation failed: {e}")
        sys.exit(1)
    
    finally:
        await db_init.cleanup()


if __name__ == "__main__":
    asyncio.run(main())