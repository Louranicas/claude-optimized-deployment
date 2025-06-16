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
            f"\n**Generated**: {results['timestamp']}",\n            f"**Project**: {results['project_root']}",\n            "\n## Summary"\n        ]\n\n        summary = results.get('summary', {})\n        lines.extend([\n            f"- **Overall Health**: {summary.get('overall_health', 'unknown').upper()}",\n            f"- **Modules Analyzed**: {summary.get('modules_analyzed', 0)}",\n            f"- **Critical Issues**: {summary.get('critical_issues', 0)}",\n        ])\n\n        if summary.get('recommendations'):\n            lines.append("\n### Recommendations")\n            for rec in summary['recommendations']:\n                lines.append(f"- {rec}")\n\n        # Module results\n        lines.append("\n## Module Results")\n\n        modules = results.get('modules', {})\n        for module_name, module_data in modules.items():\n            lines.append(f"\n### {module_name.title()}")\n\n            if module_name == 'imports':\n                lines.extend([\n                    f"- **Files Analyzed**: {module_data.get('total_files', 0)}",\n                    f"- **Files with Issues**: {module_data.get('files_with_issues', 0)}",\n                    f"- **Total Issues**: {module_data.get('total_issues', 0)}"\n                ])\n\n            elif module_name == 'security':\n                lines.extend([\n                    f"- **Total Vulnerabilities**: {module_data.get('total_vulnerabilities', 0)}",\n                    f"- **Critical**: {module_data.get('critical', 0)}",\n                    f"- **High**: {module_data.get('high', 0)}",\n                    f"- **Medium**: {module_data.get('medium', 0)}",\n                    f"- **Low**: {module_data.get('low', 0)}"\n                ])\n\n            elif module_name == 'memory':\n                lines.extend([\n                    f"- **Process Memory**: {module_data.get('process_memory_mb', 0):.2f} MB",\n                    f"- **Memory Percent**: {module_data.get('memory_percent', 0):.1f}%",\n                    f"- **Growth Rate**: {module_data.get('growth_rate_mb_per_hour', 0):.2f} MB/hr",\n                    f"- **Potential Leak**: {'Yes' if module_data.get('estimated_leak') else 'No'}"\n                ])\n\n            elif module_name == 'git':\n                lines.extend([\n                    f"- **Branch**: {module_data.get('branch', 'unknown')}",\n                    f"- **Clean**: {'Yes' if module_data.get('is_clean') else 'No'}",\n                    f"- **Uncommitted Changes**: {module_data.get('uncommitted_changes', 0)}",\n                    f"- **Unpushed Commits**: {module_data.get('unpushed_commits', 0)}",\n                    f"- **Remotes**: {module_data.get('remotes', 0)}"\n                ])\n\n            elif module_name == 'database':\n                lines.extend([\n                    f"- **Active Connections**: {module_data.get('active_connections', 0)}",\n                    f"- **Query Count**: {module_data.get('query_count', 0)}",\n                    f"- **Average Query Time**: {module_data.get('average_query_time_ms', 0):.2f}ms",\n                    f"- **Slow Queries**: {module_data.get('slow_query_count', 0)}",\n                    f"- **Database Size**: {module_data.get('database_size_mb', 0):.2f}MB"\n                ])\n\n        return '\n'.join(lines)\n\n    def _handle_imports_command(self, args: argparse.Namespace) -> int:\n        """Handle import management commands."""\n        if args.imports_command == 'analyze':\n            result = self.import_manager.analyze_project()\n            print(f"Import Analysis Results:")\n            print(f"  Files analyzed: {result.total_files}")\n            print(f"  Files with issues: {result.files_with_issues}")\n            print(f"  Total issues: {result.total_issues}")\n\n            if result.issues_by_type:\n                print(f"  Issues by type:")\n                for issue_type, count in result.issues_by_type.items():\n                    print(f"    {issue_type}: {count}")\n\n        elif args.imports_command == 'fix':\n            results = self.import_manager.fix_project(dry_run=args.dry_run)\n            action = "Would fix" if args.dry_run else "Fixed"\n            print(f"{action} {results['files_fixed']} files with {results['total_changes']} changes")\n\n        return 0\n\n    def _handle_git_command(self, args: argparse.Namespace) -> int:\n        """Handle git operation commands."""\n        if args.git_command == 'status':\n            status = self.git_manager.get_status()\n            print(f"Git Status:")\n            print(f"  Branch: {status.branch}")\n            print(f"  Clean: {'Yes' if status.is_clean else 'No'}")\n            print(f"  Uncommitted changes: {len(status.uncommitted_changes)}")\n            print(f"  Unpushed commits: {status.unpushed_commits}")\n            print(f"  Remotes: {', '.join(r.name for r in status.remotes)}")\n\n        elif args.git_command == 'push':\n            if args.all:\n                results = self.git_manager.push_to_all_remotes(parallel=args.parallel)\n                for remote, result in results.items():\n                    status = "✅" if result.success else "❌"\n                    print(f"{status} {remote}: {result.message}")\n            else:\n                print("Use --all to push to all remotes")\n\n        elif args.git_command == 'setup':\n            results = self.git_manager.setup_multi_remote()\n            for service, success in results.items():\n                status = "✅" if success else "❌"\n                print(f"{status} {service}")\n\n        return 0\n\n    def _handle_security_command(self, args: argparse.Namespace) -> int:\n        """Handle security validation commands."""\n        if args.security_command == 'audit':\n            print("🔍 Running comprehensive security audit...")\n            results = self.security_validator.run_full_audit()\n\n            report = self.security_validator.generate_report(\n                results,\n                Path(args.output) if args.output else None\n            )\n\n            if not args.output:\n                print(report)\n            else:\n                print(f"✅ Security report saved to: {args.output}")\n\n            # Return error code if critical issues found\n            if results['summary']['critical'] > 0:\n                return 1\n\n        elif args.security_command == 'scan':\n            if args.scan_type == 'static':\n                result = self.security_validator.run_static_analysis()\n            elif args.scan_type == 'dependencies':\n                result = self.security_validator.scan_dependencies()\n            elif args.scan_type == 'secrets':\n                result = self.security_validator.scan_for_secrets()\n            elif args.scan_type == 'containers':\n                result = self.security_validator.scan_containers()\n\n            print(f"Security Scan Results ({args.scan_type}):")\n            print(f"  Total issues: {result.total_issues}")\n            print(f"  Critical: {result.critical_count}")\n            print(f"  High: {result.high_count}")\n            print(f"  Medium: {result.medium_count}")\n            print(f"  Low: {result.low_count}")\n\n        return 0\n\n    def _handle_memory_command(self, args: argparse.Namespace) -> int:\n        """Handle memory analysis commands."""\n        if args.memory_command == 'analyze':\n            analysis = self.memory_analyzer.analyze_memory_usage(detailed=args.detailed)\n            report = self.memory_analyzer.get_memory_report()\n            print(report)\n\n        elif args.memory_command == 'monitor':\n            print(f"📊 Starting memory monitoring for {args.duration} seconds...")\n            self.memory_analyzer.start_monitoring()\n\n            import time\n            try:\n                time.sleep(args.duration)\n            except KeyboardInterrupt:\n                pass\n            finally:\n                self.memory_analyzer.stop_monitoring()\n\n            report = self.memory_analyzer.get_memory_report()\n            print(report)\n\n        return 0\n\n    async def _handle_database_command(self, args: argparse.Namespace) -> int:\n        """Handle database management commands."""\n        await self.initialize_database(args.url)\n\n        try:\n            if args.database_command == 'stats':\n                stats = await self.database_manager.get_database_stats()\n                print(f"Database Statistics:")\n                print(f"  Connections: {stats.active_connections}/{stats.connection_count}")\n                print(f"  Queries: {stats.query_count}")\n                print(f"  Average query time: {stats.average_query_time_ms:.2f}ms")\n                print(f"  Database size: {stats.database_size_mb:.2f}MB")\n                print(f"  Tables: {stats.table_count}")\n\n            elif args.database_command == 'query':\n                result = await self.database_manager.execute_query(args.sql)\n                if result.success:\n                    print(f"Query executed in {result.execution_time_ms:.2f}ms")\n                    print(f"Rows returned: {result.row_count}")\n                else:\n                    print(f"Query failed: {result.error}")\n                    return 1\n\n        finally:\n            await self.close_connections()\n\n        return 0\n\n    def _handle_migration_guide_command(self, args: argparse.Namespace) -> int:\n        """Handle migration guide command."""\n        # Register all known script migrations\n        self._register_all_migrations()\n\n        guide = self.get_migration_guide()\n\n        print("# Script Migration Guide")\n        print(f"\nTotal scripts migrated: {guide['total_scripts_migrated']}")\n        print(f"Integration types: {guide['migration_types']}")\n        print(f"Backward compatible: {'Yes' if guide['backward_compatibility'] else 'No'}")\n\n        print("\n## Migration Details")\n        for script_name, migration in guide['migrations'].items():\n            print(f"\n### {script_name}")\n            print(f"- **Type**: {migration.integration_type}")\n            print(f"- **New Location**: {migration.new_location or 'N/A'}")\n            print(f"- **Backward Compatible**: {'Yes' if migration.backward_compatible else 'No'}")\n\n            if migration.migration_notes:\n                print("- **Migration Notes**:")\n                for note in migration.migration_notes:\n                    print(f"  - {note}")\n\n        return 0\n\n    def _register_all_migrations(self):\n        """Register all known script migrations."""\n        # Import scripts\n        self.register_script_migration('fix_imports.py', 'module', 'src.utils.imports')\n        self.register_script_migration('fix_all_imports.py', 'module', 'src.utils.imports')\n        self.register_script_migration('fix_remaining_imports.py', 'module', 'src.utils.imports')\n        self.register_script_migration('fix_retry_imports.py', 'module', 'src.utils.imports')\n\n        # Git scripts\n        self.register_script_migration('setup_git_remotes.sh', 'module', 'src.utils.git')\n        self.register_script_migration('push_to_all_services.sh', 'module', 'src.utils.git')\n        self.register_script_migration('push_all_configured.sh', 'module', 'src.utils.git')\n        self.register_script_migration('push_all_parallel.sh', 'module', 'src.utils.git')\n        self.register_script_migration('configure_git_remotes.sh', 'module', 'src.utils.git')\n        self.register_script_migration('add_git_services.sh', 'module', 'src.utils.git')\n\n        # Security scripts\n        self.register_script_migration('security_audit.py', 'module', 'src.utils.security')\n        self.register_script_migration('security_audit_test.py', 'module', 'src.utils.security')\n        self.register_script_migration('validate_security_updates.py', 'module', 'src.utils.security')\n\n        # Memory/monitoring scripts\n        self.register_script_migration('analyze_memory_usage.py', 'module', 'src.utils.monitoring')\n\n        # Database scripts\n        self.register_script_migration('db_manager.py', 'module', 'src.utils.database')\n\n\n# Main CLI entry point\ndef main():\n    """Main CLI entry point for unified utilities."""\n    # Configure logging\n    logging.basicConfig(\n        level=logging.INFO,\n        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'\n    )\n\n    manager = UtilityManager()\n    parser = manager.create_unified_cli()\n    args = parser.parse_args()\n\n    if not args.module:\n        parser.print_help()\n        return 1\n\n    # Run command\n    exit_code = asyncio.run(manager.handle_cli_command(args))\n    return exit_code\n\n\nif __name__ == "__main__":\n    sys.exit(main())