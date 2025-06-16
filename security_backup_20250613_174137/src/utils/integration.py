"""
Integration module for unified utility management and script consolidation.

This module provides a unified interface for all utility modules and manages
the integration of standalone scripts into the modular codebase architecture.
"""

import asyncio
import sys
import logging
import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Type
from dataclasses import dataclass
from datetime import datetime
import argparse

from .imports import ImportManager
from .git import GitManager
from .security import SecurityValidator
from .monitoring import MemoryAnalyzer

# Import database with fallback
try:
    from .database import DatabaseManager, DatabaseConfig
    HAS_DATABASE = True
except ImportError:
    DatabaseManager = None
    DatabaseConfig = None
    HAS_DATABASE = False

logger = logging.getLogger(__name__)


@dataclass
class IntegrationResult:
    """Result from integrating a script or utility."""
    script_name: str
    integration_type: str  # 'module', 'cli', 'deprecated'
    success: bool
    new_location: Optional[str] = None
    backward_compatible: bool = True
    migration_notes: List[str] = None
    
    def __post_init__(self):
        if self.migration_notes is None:
            self.migration_notes = []


class UtilityManager:
    """
    Unified manager for all utility modules and script integrations.
    
    Provides centralized access to all utility functionality and manages
    the transition from standalone scripts to modular architecture.
    """
    
    def __init__(self, project_root: Optional[Path] = None):
        """
        Initialize UtilityManager.
        
        Args:
            project_root: Root directory of the project
        """
        self.project_root = Path(project_root) if project_root else Path.cwd()
        
        # Initialize utility modules
        self.import_manager = ImportManager(self.project_root)
        self.git_manager = GitManager(self.project_root)
        self.security_validator = SecurityValidator(self.project_root)
        self.memory_analyzer = MemoryAnalyzer()
        self.database_manager: Optional[DatabaseManager] = None
        
        # Track integration status
        self.integration_registry: Dict[str, IntegrationResult] = {}
        self.deprecated_scripts: Dict[str, str] = {}
        self.migration_history: List[Dict[str, Any]] = []
        
    async def initialize_database(self, database_url: str):
        """
        Initialize database manager with connection.
        
        Args:
            database_url: Database connection URL
        """
        if not HAS_DATABASE:
            logger.warning("Database functionality not available")
            return
            
        config = DatabaseConfig(url=database_url)
        self.database_manager = DatabaseManager(config)
        await self.database_manager.initialize()
        
    async def close_connections(self):
        """Close all active connections."""
        if self.database_manager:
            await self.database_manager.close()
            
    def register_script_migration(self, 
                                 script_name: str,
                                 integration_type: str,
                                 new_location: Optional[str] = None) -> IntegrationResult:
        """
        Register the migration of a script to modular architecture.
        
        Args:
            script_name: Name of the original script
            integration_type: Type of integration (module, cli, deprecated)
            new_location: New location/access method
            
        Returns:
            IntegrationResult with migration details
        """
        result = IntegrationResult(
            script_name=script_name,
            integration_type=integration_type,
            success=True,
            new_location=new_location,
            backward_compatible=True
        )
        
        # Add specific migration notes based on script type
        if script_name.startswith('fix_') and 'import' in script_name:
            result.migration_notes.extend([
                "Consolidated into ImportManager module",
                "Use: from src.utils import ImportManager",
                "CLI: python -m src.utils.imports analyze|fix"
            ])
            
        elif 'git' in script_name:
            result.migration_notes.extend([
                "Consolidated into GitManager module", 
                "Use: from src.utils import GitManager",
                "CLI: python -m src.utils.git status|push|setup"
            ])
            
        elif 'security' in script_name:
            result.migration_notes.extend([
                "Consolidated into SecurityValidator module",
                "Use: from src.utils import SecurityValidator", 
                "CLI: python -m src.utils.security audit|scan"
            ])
            
        elif 'memory' in script_name or 'analyze' in script_name:
            result.migration_notes.extend([
                "Consolidated into MemoryAnalyzer module",
                "Use: from src.utils import MemoryAnalyzer",
                "CLI: python -m src.utils.monitoring analyze|monitor"
            ])
            
        elif 'db' in script_name or 'database' in script_name:
            result.migration_notes.extend([
                "Consolidated into DatabaseManager module",
                "Use: from src.utils import DatabaseManager",
                "CLI: python -m src.utils.database stats|query|migrate"
            ])
            
        self.integration_registry[script_name] = result
        
        # Record migration in history
        self.migration_history.append({
            'timestamp': datetime.now().isoformat(),
            'script': script_name,
            'integration_type': integration_type,
            'new_location': new_location
        })
        
        return result
        
    def get_migration_guide(self) -> Dict[str, Any]:
        """
        Get comprehensive migration guide for all scripts.
        
        Returns:
            Dictionary with migration information
        """
        return {
            'total_scripts_migrated': len(self.integration_registry),
            'migration_types': {
                'module': len([r for r in self.integration_registry.values() 
                              if r.integration_type == 'module']),
                'cli': len([r for r in self.integration_registry.values() 
                           if r.integration_type == 'cli']),
                'deprecated': len([r for r in self.integration_registry.values() 
                                 if r.integration_type == 'deprecated'])
            },
            'backward_compatibility': all(r.backward_compatible 
                                        for r in self.integration_registry.values()),
            'migrations': self.integration_registry,
            'history': self.migration_history
        }
        
    async def run_comprehensive_analysis(self) -> Dict[str, Any]:
        """
        Run comprehensive analysis across all utility modules.
        
        Returns:
            Dictionary with analysis results from all modules
        """
        logger.info("Starting comprehensive analysis across all utilities...")
        
        analysis_results = {
            'timestamp': datetime.now().isoformat(),
            'project_root': str(self.project_root),
            'modules': {}
        }
        
        try:
            # Import analysis
            logger.info("Running import analysis...")
            import_result = self.import_manager.analyze_project()
            analysis_results['modules']['imports'] = {
                'total_files': import_result.total_files,
                'files_with_issues': import_result.files_with_issues,
                'total_issues': import_result.total_issues,
                'issues_by_type': import_result.issues_by_type,
                'issues_by_severity': import_result.issues_by_severity
            }
            
            # Git analysis
            logger.info("Running git analysis...")
            git_status = self.git_manager.get_status()
            analysis_results['modules']['git'] = {
                'branch': git_status.branch,
                'is_clean': git_status.is_clean,
                'uncommitted_changes': len(git_status.uncommitted_changes),
                'unpushed_commits': git_status.unpushed_commits,
                'remotes': len(git_status.remotes)
            }
            
            # Security analysis
            logger.info("Running security analysis...")
            security_results = self.security_validator.run_full_audit()
            analysis_results['modules']['security'] = {
                'total_vulnerabilities': security_results['summary']['total_vulnerabilities'],
                'critical': security_results['summary']['critical'],
                'high': security_results['summary']['high'],
                'medium': security_results['summary']['medium'],
                'low': security_results['summary']['low'],
                'compliance_scores': security_results['summary']['compliance_scores']
            }
            
            # Memory analysis
            logger.info("Running memory analysis...")
            memory_analysis = self.memory_analyzer.analyze_memory_usage()
            analysis_results['modules']['memory'] = {
                'process_memory_mb': memory_analysis['summary']['process_memory_mb'],
                'memory_percent': memory_analysis['summary']['memory_percent'],
                'growth_rate_mb_per_hour': memory_analysis['summary']['growth_rate_mb_per_hour'],
                'estimated_leak': memory_analysis['summary']['estimated_leak'],
                'gc_pressure': memory_analysis['summary']['gc_pressure']
            }
            
            # Database analysis (if configured)
            if self.database_manager:
                logger.info("Running database analysis...")
                db_stats = await self.database_manager.get_database_stats()
                analysis_results['modules']['database'] = {
                    'connection_count': db_stats.connection_count,
                    'active_connections': db_stats.active_connections,
                    'query_count': db_stats.query_count,
                    'average_query_time_ms': db_stats.average_query_time_ms,
                    'slow_query_count': db_stats.slow_query_count,
                    'error_count': db_stats.error_count,
                    'database_size_mb': db_stats.database_size_mb,
                    'table_count': db_stats.table_count
                }
                
        except Exception as e:
            logger.error(f"Error during comprehensive analysis: {e}")
            analysis_results['error'] = str(e)
            
        # Generate summary
        analysis_results['summary'] = self._generate_analysis_summary(analysis_results)
        
        return analysis_results
        
    def _generate_analysis_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of analysis results."""
        summary = {
            'overall_health': 'good',
            'critical_issues': 0,
            'recommendations': [],
            'modules_analyzed': len(results.get('modules', {}))
        }
        
        modules = results.get('modules', {})
        
        # Check for critical issues
        if 'security' in modules:
            critical_security = modules['security'].get('critical', 0)
            if critical_security > 0:
                summary['critical_issues'] += critical_security
                summary['overall_health'] = 'critical'
                summary['recommendations'].append(
                    f"URGENT: Fix {critical_security} critical security vulnerabilities"
                )
                
        if 'imports' in modules:
            import_issues = modules['imports'].get('total_issues', 0)
            if import_issues > 50:
                summary['recommendations'].append(
                    f"Address {import_issues} import issues for better code quality"
                )
                
        if 'memory' in modules:
            if modules['memory'].get('estimated_leak', False):
                summary['recommendations'].append(
                    "Investigate potential memory leaks"
                )
                if summary['overall_health'] == 'good':
                    summary['overall_health'] = 'warning'
                    
        if 'git' in modules:
            uncommitted = modules['git'].get('uncommitted_changes', 0)
            unpushed = modules['git'].get('unpushed_commits', 0)
            if uncommitted > 10 or unpushed > 5:
                summary['recommendations'].append(
                    "Commit and push pending changes"
                )
                
        if 'database' in modules:
            error_count = modules['database'].get('error_count', 0)
            slow_queries = modules['database'].get('slow_query_count', 0)
            if error_count > 0 or slow_queries > 10:
                summary['recommendations'].append(
                    "Review database performance and errors"
                )
                
        return summary
        
    def create_unified_cli(self) -> argparse.ArgumentParser:
        """
        Create unified CLI interface for all utility modules.
        
        Returns:
            Configured ArgumentParser
        """
        parser = argparse.ArgumentParser(
            description="Unified utility management for Claude Optimized Deployment Engine",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Run comprehensive analysis
  python -m src.utils analyze --all
  
  # Import management
  python -m src.utils imports fix --dry-run
  
  # Git operations  
  python -m src.utils git push --all --parallel
  
  # Security auditing
  python -m src.utils security audit --output security_report.md
  
  # Memory monitoring
  python -m src.utils memory monitor --duration 300
  
  # Database management
  python -m src.utils database stats --url postgresql://localhost/mydb
  
  # Migration guide
  python -m src.utils migration-guide
            """
        )
        
        subparsers = parser.add_subparsers(dest='module', help='Utility module to use')
        
        # Analysis command
        analyze_parser = subparsers.add_parser('analyze', help='Run comprehensive analysis')
        analyze_parser.add_argument('--all', action='store_true',
                                   help='Run analysis on all modules')
        analyze_parser.add_argument('--output', '-o', help='Output file for results')
        analyze_parser.add_argument('--format', choices=['json', 'yaml', 'text'],
                                   default='text', help='Output format')
        
        # Import management
        imports_parser = subparsers.add_parser('imports', help='Import management')
        imports_subparsers = imports_parser.add_subparsers(dest='imports_command')
        
        imports_analyze = imports_subparsers.add_parser('analyze', help='Analyze imports')
        imports_analyze.add_argument('path', nargs='?', default='.', help='Path to analyze')
        
        imports_fix = imports_subparsers.add_parser('fix', help='Fix import issues')
        imports_fix.add_argument('path', nargs='?', default='.', help='Path to fix')
        imports_fix.add_argument('--dry-run', action='store_true', help='Show changes without applying')
        
        # Git operations
        git_parser = subparsers.add_parser('git', help='Git operations')
        git_subparsers = git_parser.add_subparsers(dest='git_command')
        
        git_status = git_subparsers.add_parser('status', help='Show git status')
        
        git_push = git_subparsers.add_parser('push', help='Push to remotes')
        git_push.add_argument('--all', action='store_true', help='Push to all remotes')
        git_push.add_argument('--parallel', action='store_true', help='Push in parallel')
        
        git_setup = git_subparsers.add_parser('setup', help='Setup multi-remote')
        
        # Security
        security_parser = subparsers.add_parser('security', help='Security validation')
        security_subparsers = security_parser.add_subparsers(dest='security_command')
        
        security_audit = security_subparsers.add_parser('audit', help='Full security audit')
        security_audit.add_argument('--output', '-o', help='Output report file')
        
        security_scan = security_subparsers.add_parser('scan', help='Run specific scan')
        security_scan.add_argument('scan_type', 
                                  choices=['static', 'dependencies', 'secrets', 'containers'])
        
        # Memory monitoring
        memory_parser = subparsers.add_parser('memory', help='Memory analysis')
        memory_subparsers = memory_parser.add_subparsers(dest='memory_command')
        
        memory_analyze = memory_subparsers.add_parser('analyze', help='Analyze memory usage')
        memory_analyze.add_argument('--detailed', action='store_true', help='Detailed analysis')
        
        memory_monitor = memory_subparsers.add_parser('monitor', help='Monitor memory')
        memory_monitor.add_argument('--duration', type=int, default=60, help='Duration in seconds')
        
        # Database
        database_parser = subparsers.add_parser('database', help='Database management')
        database_subparsers = database_parser.add_subparsers(dest='database_command')
        
        database_stats = database_subparsers.add_parser('stats', help='Database statistics')
        database_stats.add_argument('--url', required=True, help='Database URL')
        
        database_query = database_subparsers.add_parser('query', help='Execute query')
        database_query.add_argument('--url', required=True, help='Database URL')
        database_query.add_argument('--sql', required=True, help='SQL query')
        
        # Migration guide
        migration_parser = subparsers.add_parser('migration-guide', 
                                               help='Show script migration guide')
        
        return parser
        
    async def handle_cli_command(self, args: argparse.Namespace) -> int:
        """
        Handle CLI command execution.
        
        Args:
            args: Parsed command line arguments
            
        Returns:
            Exit code (0 for success, 1 for error)
        """
        try:
            if args.module == 'analyze':
                return await self._handle_analyze_command(args)
            elif args.module == 'imports':
                return self._handle_imports_command(args)
            elif args.module == 'git':
                return self._handle_git_command(args)
            elif args.module == 'security':
                return self._handle_security_command(args)
            elif args.module == 'memory':
                return self._handle_memory_command(args)
            elif args.module == 'database':
                return await self._handle_database_command(args)
            elif args.module == 'migration-guide':
                return self._handle_migration_guide_command(args)
            else:
                print("No command specified. Use --help for usage information.")
                return 1
                
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            print(f"Error: {e}")
            return 1
            
    async def _handle_analyze_command(self, args: argparse.Namespace) -> int:
        """Handle comprehensive analysis command."""
        if args.all:
            print("🔍 Running comprehensive analysis across all modules...")
            results = await self.run_comprehensive_analysis()
            
            if args.format == 'json':
                output = json.dumps(results, indent=2)
            elif args.format == 'yaml':
                import yaml
                output = yaml.dump(results, default_flow_style=False)
            else:
                output = self._format_analysis_results(results)
                
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(output)
                print(f"✅ Analysis results saved to: {args.output}")
            else:
                print(output)
                
            return 0
        else:
            print("Use --all to run comprehensive analysis")
            return 1
            
    def _format_analysis_results(self, results: Dict[str, Any]) -> str:
        """Format analysis results for text output."""
        lines = [
            "# Comprehensive Analysis Results",
            f"\n**Generated**: {results['timestamp']}",
            f"**Project**: {results['project_root']}",
            "\n## Summary"
        ]
        
        summary = results.get('summary', {})
        lines.extend([
            f"- **Overall Health**: {summary.get('overall_health', 'unknown').upper()}",
            f"- **Modules Analyzed**: {summary.get('modules_analyzed', 0)}",
            f"- **Critical Issues**: {summary.get('critical_issues', 0)}",
        ])
        
        if summary.get('recommendations'):
            lines.append("\n### Recommendations")
            for rec in summary['recommendations']:
                lines.append(f"- {rec}")
                
        # Module results
        lines.append("\n## Module Results")
        
        modules = results.get('modules', {})
        for module_name, module_data in modules.items():
            lines.append(f"\n### {module_name.title()}")
            
            if module_name == 'imports':
                lines.extend([
                    f"- **Files Analyzed**: {module_data.get('total_files', 0)}",
                    f"- **Files with Issues**: {module_data.get('files_with_issues', 0)}",
                    f"- **Total Issues**: {module_data.get('total_issues', 0)}"
                ])
                
            elif module_name == 'security':
                lines.extend([
                    f"- **Total Vulnerabilities**: {module_data.get('total_vulnerabilities', 0)}",
                    f"- **Critical**: {module_data.get('critical', 0)}",
                    f"- **High**: {module_data.get('high', 0)}",
                    f"- **Medium**: {module_data.get('medium', 0)}",
                    f"- **Low**: {module_data.get('low', 0)}"
                ])
                
            elif module_name == 'memory':
                lines.extend([
                    f"- **Process Memory**: {module_data.get('process_memory_mb', 0):.2f} MB",
                    f"- **Memory Percent**: {module_data.get('memory_percent', 0):.1f}%",
                    f"- **Growth Rate**: {module_data.get('growth_rate_mb_per_hour', 0):.2f} MB/hr",
                    f"- **Potential Leak**: {'Yes' if module_data.get('estimated_leak') else 'No'}"
                ])
                
            elif module_name == 'git':
                lines.extend([
                    f"- **Branch**: {module_data.get('branch', 'unknown')}",
                    f"- **Clean**: {'Yes' if module_data.get('is_clean') else 'No'}",
                    f"- **Uncommitted Changes**: {module_data.get('uncommitted_changes', 0)}",
                    f"- **Unpushed Commits**: {module_data.get('unpushed_commits', 0)}",
                    f"- **Remotes**: {module_data.get('remotes', 0)}"
                ])
                
            elif module_name == 'database':
                lines.extend([
                    f"- **Active Connections**: {module_data.get('active_connections', 0)}",
                    f"- **Query Count**: {module_data.get('query_count', 0)}",
                    f"- **Average Query Time**: {module_data.get('average_query_time_ms', 0):.2f}ms",
                    f"- **Slow Queries**: {module_data.get('slow_query_count', 0)}",
                    f"- **Database Size**: {module_data.get('database_size_mb', 0):.2f}MB"
                ])
                
        return '\n'.join(lines)
        
    def _handle_imports_command(self, args: argparse.Namespace) -> int:
        """Handle import management commands."""
        if args.imports_command == 'analyze':
            result = self.import_manager.analyze_project()
            print(f"Import Analysis Results:")
            print(f"  Files analyzed: {result.total_files}")
            print(f"  Files with issues: {result.files_with_issues}")
            print(f"  Total issues: {result.total_issues}")
            
            if result.issues_by_type:
                print(f"  Issues by type:")
                for issue_type, count in result.issues_by_type.items():
                    print(f"    {issue_type}: {count}")
                    
        elif args.imports_command == 'fix':
            results = self.import_manager.fix_project(dry_run=args.dry_run)
            action = "Would fix" if args.dry_run else "Fixed"
            print(f"{action} {results['files_fixed']} files with {results['total_changes']} changes")
            
        return 0
        
    def _handle_git_command(self, args: argparse.Namespace) -> int:
        """Handle git operation commands."""
        if args.git_command == 'status':
            status = self.git_manager.get_status()
            print(f"Git Status:")
            print(f"  Branch: {status.branch}")
            print(f"  Clean: {'Yes' if status.is_clean else 'No'}")
            print(f"  Uncommitted changes: {len(status.uncommitted_changes)}")
            print(f"  Unpushed commits: {status.unpushed_commits}")
            print(f"  Remotes: {', '.join(r.name for r in status.remotes)}")
            
        elif args.git_command == 'push':
            if args.all:
                results = self.git_manager.push_to_all_remotes(parallel=args.parallel)
                for remote, result in results.items():
                    status = "✅" if result.success else "❌"
                    print(f"{status} {remote}: {result.message}")
            else:
                print("Use --all to push to all remotes")
                
        elif args.git_command == 'setup':
            results = self.git_manager.setup_multi_remote()
            for service, success in results.items():
                status = "✅" if success else "❌"
                print(f"{status} {service}")
                
        return 0
        
    def _handle_security_command(self, args: argparse.Namespace) -> int:
        """Handle security validation commands."""
        if args.security_command == 'audit':
            print("🔍 Running comprehensive security audit...")
            results = self.security_validator.run_full_audit()
            
            report = self.security_validator.generate_report(
                results, 
                Path(args.output) if args.output else None
            )
            
            if not args.output:
                print(report)
            else:
                print(f"✅ Security report saved to: {args.output}")
                
            # Return error code if critical issues found
            if results['summary']['critical'] > 0:
                return 1
                
        elif args.security_command == 'scan':
            if args.scan_type == 'static':
                result = self.security_validator.run_static_analysis()
            elif args.scan_type == 'dependencies':
                result = self.security_validator.scan_dependencies()
            elif args.scan_type == 'secrets':
                result = self.security_validator.scan_for_secrets()
            elif args.scan_type == 'containers':
                result = self.security_validator.scan_containers()
                
            print(f"Security Scan Results ({args.scan_type}):")
            print(f"  Total issues: {result.total_issues}")
            print(f"  Critical: {result.critical_count}")
            print(f"  High: {result.high_count}")
            print(f"  Medium: {result.medium_count}")
            print(f"  Low: {result.low_count}")
            
        return 0
        
    def _handle_memory_command(self, args: argparse.Namespace) -> int:
        """Handle memory analysis commands."""
        if args.memory_command == 'analyze':
            analysis = self.memory_analyzer.analyze_memory_usage(detailed=args.detailed)
            report = self.memory_analyzer.get_memory_report()
            print(report)
            
        elif args.memory_command == 'monitor':
            print(f"📊 Starting memory monitoring for {args.duration} seconds...")
            self.memory_analyzer.start_monitoring()
            
            import time
            try:
                time.sleep(args.duration)
            except KeyboardInterrupt:
                pass
            finally:
                self.memory_analyzer.stop_monitoring()
                
            report = self.memory_analyzer.get_memory_report()
            print(report)
            
        return 0
        
    async def _handle_database_command(self, args: argparse.Namespace) -> int:
        """Handle database management commands."""
        await self.initialize_database(args.url)
        
        try:
            if args.database_command == 'stats':
                stats = await self.database_manager.get_database_stats()
                print(f"Database Statistics:")
                print(f"  Connections: {stats.active_connections}/{stats.connection_count}")
                print(f"  Queries: {stats.query_count}")
                print(f"  Average query time: {stats.average_query_time_ms:.2f}ms")
                print(f"  Database size: {stats.database_size_mb:.2f}MB")
                print(f"  Tables: {stats.table_count}")
                
            elif args.database_command == 'query':
                result = await self.database_manager.execute_query(args.sql)
                if result.success:
                    print(f"Query executed in {result.execution_time_ms:.2f}ms")
                    print(f"Rows returned: {result.row_count}")
                else:
                    print(f"Query failed: {result.error}")
                    return 1
                    
        finally:
            await self.close_connections()
            
        return 0
        
    def _handle_migration_guide_command(self, args: argparse.Namespace) -> int:
        """Handle migration guide command."""
        # Register all known script migrations
        self._register_all_migrations()
        
        guide = self.get_migration_guide()
        
        print("# Script Migration Guide")
        print(f"\nTotal scripts migrated: {guide['total_scripts_migrated']}")
        print(f"Integration types: {guide['migration_types']}")
        print(f"Backward compatible: {'Yes' if guide['backward_compatibility'] else 'No'}")
        
        print("\n## Migration Details")
        for script_name, migration in guide['migrations'].items():
            print(f"\n### {script_name}")
            print(f"- **Type**: {migration.integration_type}")
            print(f"- **New Location**: {migration.new_location or 'N/A'}")
            print(f"- **Backward Compatible**: {'Yes' if migration.backward_compatible else 'No'}")
            
            if migration.migration_notes:
                print("- **Migration Notes**:")
                for note in migration.migration_notes:
                    print(f"  - {note}")
                    
        return 0
        
    def _register_all_migrations(self):
        """Register all known script migrations."""
        # Import scripts
        self.register_script_migration('fix_imports.py', 'module', 'src.utils.imports')
        self.register_script_migration('fix_all_imports.py', 'module', 'src.utils.imports') 
        self.register_script_migration('fix_remaining_imports.py', 'module', 'src.utils.imports')
        self.register_script_migration('fix_retry_imports.py', 'module', 'src.utils.imports')
        
        # Git scripts
        self.register_script_migration('setup_git_remotes.sh', 'module', 'src.utils.git')
        self.register_script_migration('push_to_all_services.sh', 'module', 'src.utils.git')
        self.register_script_migration('push_all_configured.sh', 'module', 'src.utils.git')
        self.register_script_migration('push_all_parallel.sh', 'module', 'src.utils.git')
        self.register_script_migration('configure_git_remotes.sh', 'module', 'src.utils.git')
        self.register_script_migration('add_git_services.sh', 'module', 'src.utils.git')
        
        # Security scripts
        self.register_script_migration('security_audit.py', 'module', 'src.utils.security')
        self.register_script_migration('security_audit_test.py', 'module', 'src.utils.security')
        self.register_script_migration('validate_security_updates.py', 'module', 'src.utils.security')
        
        # Memory/monitoring scripts
        self.register_script_migration('analyze_memory_usage.py', 'module', 'src.utils.monitoring')
        
        # Database scripts
        self.register_script_migration('db_manager.py', 'module', 'src.utils.database')


# Main CLI entry point
def main():
    """Main CLI entry point for unified utilities."""
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    manager = UtilityManager()
    parser = manager.create_unified_cli()
    args = parser.parse_args()
    
    if not args.module:
        parser.print_help()
        return 1
        
    # Run command
    exit_code = asyncio.run(manager.handle_cli_command(args))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())