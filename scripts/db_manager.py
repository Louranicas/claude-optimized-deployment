#!/usr/bin/env python3
"""Database management CLI script.

Provides command-line interface for database operations including:
- Initialization and setup
- Migrations
- Backup and restore
- Optimization and maintenance
- Data archiving
"""

import asyncio
import sys
import os
import argparse
from pathlib import Path
from typing import Optional
import json

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.database.init import DatabaseInitializer
from src.database.utils import DatabaseBackup, DatabaseRestore, DatabaseOptimizer, DatabaseArchiver
from src.core.logging_config import get_logger

logger = get_logger(__name__)


class DatabaseCLI:
    """Command-line interface for database management."""
    
    def __init__(self, connection_string: Optional[str] = None):
        """Initialize database CLI."""
        self.connection_string = connection_string or os.getenv("DATABASE_URL")
        self.db_init = DatabaseInitializer(self.connection_string)
    
    async def init_command(self, migrate: bool = True, seed: bool = True) -> None:
        """Initialize database with optional migration and seeding."""
        logger.info("Initializing database...")
        
        await self.db_init.initialize()
        result = await self.db_init.setup_database(
            run_migrations=migrate,
            seed_data=seed
        )
        
        print("Database initialization completed:")
        print(f"  Migrations run: {result['migrations_run']}")
        print(f"  Tables created: {result['tables_created']}")
        print(f"  Data seeded: {result['data_seeded']}")
        
        if result['errors']:
            print("Errors encountered:")
            for error in result['errors']:
                print(f"  - {error}")
    
    async def migrate_command(self) -> None:
        """Run database migrations."""
        logger.info("Running migrations...")
        
        await self.db_init.initialize()
        await self.db_init.run_migrations()
        
        print("Migrations completed successfully")
    
    async def seed_command(self) -> None:
        """Seed database with initial data."""
        logger.info("Seeding database...")
        
        await self.db_init.initialize()
        await self.db_init.seed_initial_data()
        
        print("Database seeding completed")
    
    async def health_command(self, detailed: bool = False) -> None:
        """Check database health."""
        logger.info("Checking database health...")
        
        await self.db_init.initialize()
        health = await self.db_init.health_check()
        
        print("Database Health Status:")
        print(f"  Database Type: {health.get('database_type', 'Unknown')}")
        print(f"  SQLAlchemy Connected: {health.get('sqlalchemy_connected', False)}")
        print(f"  Tortoise Connected: {health.get('tortoise_connected', False)}")
        print(f"  Overall Health: {health.get('overall_health', 'Unknown')}")
        
        if detailed and 'table_counts' in health:
            print("\nTable Counts:")
            for table, count in health['table_counts'].items():
                print(f"  {table}: {count}")
        
        if 'pool_status' in health and health['pool_status']:
            print("\nConnection Pool Status:")
            pool = health['pool_status']
            print(f"  Size: {pool.get('size', 'N/A')}")
            print(f"  Checked In: {pool.get('checked_in', 'N/A')}")
            print(f"  Overflow: {pool.get('overflow', 'N/A')}")
            print(f"  Total: {pool.get('total', 'N/A')}")
    
    async def backup_command(
        self,
        backup_type: str = "json",
        output_path: Optional[str] = None
    ) -> None:
        """Create database backup."""
        logger.info(f"Creating {backup_type} backup...")
        
        await self.db_init.initialize()
        backup_file = await self.db_init.backup_database(backup_type)
        
        if output_path:
            import shutil
            shutil.move(backup_file, output_path)
            backup_file = output_path
        
        print(f"Backup created successfully: {backup_file}")
    
    async def restore_command(self, backup_file: str) -> None:
        """Restore database from backup."""
        logger.info(f"Restoring from backup: {backup_file}")
        
        if not os.path.exists(backup_file):
            print(f"Error: Backup file not found: {backup_file}")
            return
        
        restore_manager = DatabaseRestore()
        
        if backup_file.endswith('.json'):
            result = await restore_manager.restore_from_json(backup_file)
            print("Restore completed:")
            for table, count in result.items():
                print(f"  {table}: {count} records restored")
        else:
            print("Error: Only JSON restore is currently supported")
    
    async def optimize_command(self) -> None:
        """Optimize database performance."""
        logger.info("Optimizing database...")
        
        await self.db_init.initialize()
        result = await self.db_init.optimize_database()
        
        print("Database optimization completed")
        
        if 'index_suggestions' in result and result['index_suggestions']:
            print("\nIndex suggestions:")
            for suggestion in result['index_suggestions']:
                print(f"  {suggestion}")
    
    async def archive_command(self, days_to_keep: int = 90) -> None:
        """Archive old data."""
        logger.info(f"Archiving data older than {days_to_keep} days...")
        
        await self.db_init.initialize()
        result = await self.db_init.archive_old_data(days_to_keep)
        
        print("Data archiving completed:")
        for table, info in result.items():
            if isinstance(info, dict):
                archived = info.get('archived_count', 0)
                print(f"  {table}: {archived} records archived")
            else:
                print(f"  {table}: {info}")
    
    async def cleanup_command(self, table: str, days: int) -> None:
        """Clean up old data from specific table."""
        logger.info(f"Cleaning up {table} data older than {days} days...")
        
        await self.db_init.initialize()
        
        from src.database import get_database_connection
        from src.database.repositories.audit_repository import AuditLogRepository
        from src.database.repositories.metrics_repository import MetricsRepository
        
        conn = await get_database_connection()
        
        async with conn.get_session() as session:
            if table == "audit_logs":
                repo = AuditLogRepository(session)
                deleted = await repo.cleanup_old_logs(days)
                print(f"Deleted {deleted} audit log records")
            
            elif table == "metric_data":
                repo = MetricsRepository(session)
                deleted = await repo.cleanup_old_metrics(days)
                print(f"Deleted {deleted} metric data points")
            
            else:
                print(f"Error: Cleanup not supported for table: {table}")
    
    async def stats_command(self) -> None:
        """Show database statistics."""
        logger.info("Gathering database statistics...")
        
        await self.db_init.initialize()
        
        from src.database import get_database_connection
        from src.database.repositories.user_repository import UserRepository
        from src.database.repositories.metrics_repository import MetricsRepository
        
        conn = await get_database_connection()
        
        async with conn.get_session() as session:
            # User statistics
            user_repo = UserRepository(session)
            user_stats = await user_repo.get_user_statistics()
            
            print("User Statistics:")
            print(f"  Total Users: {user_stats.get('total_users', 0)}")
            print(f"  Active Users: {user_stats.get('active_users', 0)}")
            print(f"  Recent Logins (30d): {user_stats.get('recent_logins_30d', 0)}")
            
            print("\nUsers by Role:")
            for role, count in user_stats.get('users_by_role', {}).items():
                print(f"  {role}: {count}")
            
            # Metrics statistics
            metrics_repo = MetricsRepository(session)
            metrics_summary = await metrics_repo.get_metrics_summary()
            
            print(f"\nMetrics Statistics:")
            print(f"  Total Metrics: {metrics_summary.get('total_metrics', 0)}")
            print(f"  Total Data Points: {metrics_summary.get('total_data_points', 0)}")
    
    async def export_command(self, table: str, format: str = "json") -> None:
        """Export table data."""
        logger.info(f"Exporting {table} data in {format} format...")
        
        await self.db_init.initialize()
        
        if table == "configurations":
            from src.database import get_database_connection
            from src.database.repositories.configuration_repository import ConfigurationRepository
            
            conn = await get_database_connection()
            
            async with conn.get_session() as session:
                config_repo = ConfigurationRepository(session)
                export_data = await config_repo.export_configs()
                
                filename = f"config_export_{export_data['exported_at'][:10]}.json"
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2)
                
                print(f"Configuration data exported to: {filename}")
        else:
            print(f"Export not implemented for table: {table}")
    
    async def cleanup(self) -> None:
        """Clean up resources."""
        await self.db_init.cleanup()


async def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Database management CLI for Claude Optimized Deployment Engine"
    )
    parser.add_argument(
        "--connection-string",
        help="Database connection string (default: from DATABASE_URL env var)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Init command
    init_parser = subparsers.add_parser("init", help="Initialize database")
    init_parser.add_argument("--no-migrate", action="store_true", help="Skip migrations")
    init_parser.add_argument("--no-seed", action="store_true", help="Skip seeding")
    
    # Migrate command
    subparsers.add_parser("migrate", help="Run database migrations")
    
    # Seed command
    subparsers.add_parser("seed", help="Seed database with initial data")
    
    # Health command
    health_parser = subparsers.add_parser("health", help="Check database health")
    health_parser.add_argument("--detailed", action="store_true", help="Show detailed health info")
    
    # Backup command
    backup_parser = subparsers.add_parser("backup", help="Create database backup")
    backup_parser.add_argument("--type", choices=["json", "postgresql", "sqlite"], default="json")
    backup_parser.add_argument("--output", help="Output file path")
    
    # Restore command
    restore_parser = subparsers.add_parser("restore", help="Restore from backup")
    restore_parser.add_argument("backup_file", help="Path to backup file")
    
    # Optimize command
    subparsers.add_parser("optimize", help="Optimize database performance")
    
    # Archive command
    archive_parser = subparsers.add_parser("archive", help="Archive old data")
    archive_parser.add_argument("--days", type=int, default=90, help="Days to keep (default: 90)")
    
    # Cleanup command
    cleanup_parser = subparsers.add_parser("cleanup", help="Clean up old data")
    cleanup_parser.add_argument("table", choices=["audit_logs", "metric_data"])
    cleanup_parser.add_argument("--days", type=int, default=90, help="Days to keep")
    
    # Stats command
    subparsers.add_parser("stats", help="Show database statistics")
    
    # Export command
    export_parser = subparsers.add_parser("export", help="Export table data")
    export_parser.add_argument("table", choices=["configurations"])
    export_parser.add_argument("--format", choices=["json"], default="json")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Set up logging
    if args.verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize CLI
    cli = DatabaseCLI(args.connection_string)
    
    try:
        # Execute command
        if args.command == "init":
            await cli.init_command(
                migrate=not args.no_migrate,
                seed=not args.no_seed
            )
        elif args.command == "migrate":
            await cli.migrate_command()
        elif args.command == "seed":
            await cli.seed_command()
        elif args.command == "health":
            await cli.health_command(detailed=args.detailed)
        elif args.command == "backup":
            await cli.backup_command(args.type, args.output)
        elif args.command == "restore":
            await cli.restore_command(args.backup_file)
        elif args.command == "optimize":
            await cli.optimize_command()
        elif args.command == "archive":
            await cli.archive_command(args.days)
        elif args.command == "cleanup":
            await cli.cleanup_command(args.table, args.days)
        elif args.command == "stats":
            await cli.stats_command()
        elif args.command == "export":
            await cli.export_command(args.table, args.format)
        
        return 0
        
    except Exception as e:
        logger.error(f"Command failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    
    finally:
        await cli.cleanup()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))