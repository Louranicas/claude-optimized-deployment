#!/usr/bin/env python3
"""
MCP Deployment CLI Tool

Command-line interface for MCP deployment orchestration with
comprehensive deployment management capabilities.
"""

import asyncio
import click
import json
import yaml
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional
from tabulate import tabulate
import time

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.mcp.deployment.orchestrator import (
    MCPDeploymentOrchestrator, 
    ServerDeploymentSpec, 
    DeploymentPhase,
    DeploymentStatus
)
from src.mcp.deployment.config_manager import DeploymentConfigManager
from src.mcp.deployment.health_validator import HealthValidator, HealthCheckConfig, HealthCheckType
from src.mcp.deployment.rollback_manager import RollbackManager, RollbackStrategy
from src.mcp.deployment.deployment_monitor import DeploymentMonitor
from src.core.logging_config import get_logger

logger = get_logger(__name__)


class DeploymentCLI:
    """CLI interface for MCP deployment operations."""
    
    def __init__(self):
        self.orchestrator = MCPDeploymentOrchestrator()
        self.config_manager = DeploymentConfigManager()
        self.health_validator = HealthValidator()
        self.rollback_manager = RollbackManager()
        self.monitor = DeploymentMonitor()
        
        # CLI state
        self.verbose = False
        self.config_file = None
    
    def set_verbose(self, verbose: bool):
        """Set verbose output mode."""
        self.verbose = verbose
    
    def load_config_file(self, config_file: str):
        """Load configuration from file."""
        self.config_file = Path(config_file)
        if self.config_file.exists():
            click.echo(f"Loaded configuration from {config_file}")
        else:
            click.echo(f"Warning: Configuration file not found: {config_file}", err=True)


# Create CLI instance
cli_instance = DeploymentCLI()


@click.group()
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--config', '-c', help='Configuration file path')
def cli(verbose, config):
    """MCP Deployment Orchestration CLI"""
    cli_instance.set_verbose(verbose)
    if config:
        cli_instance.load_config_file(config)


@cli.group()
def deploy():
    """Deployment operations"""
    pass


@cli.group()
def monitor():
    """Monitoring and status operations"""
    pass


@cli.group()
def rollback():
    """Rollback operations"""
    pass


@cli.group()
def config():
    """Configuration management"""
    pass


@cli.group() 
def health():
    """Health check operations"""
    pass


# Deployment commands
@deploy.command()
@click.argument('deployment_file')
@click.option('--environment', '-e', default='production', help='Target environment')
@click.option('--dry-run', is_flag=True, help='Show deployment plan without executing')
@click.option('--parallel', is_flag=True, default=True, help='Enable parallel deployment')
@click.option('--watch', '-w', is_flag=True, help='Watch deployment progress')
def start(deployment_file, environment, dry_run, parallel, watch):
    """Start a new deployment from configuration file."""
    asyncio.run(_start_deployment(deployment_file, environment, dry_run, parallel, watch))


async def _start_deployment(deployment_file: str, environment: str, dry_run: bool, parallel: bool, watch: bool):
    """Execute deployment start command."""
    try:
        # Load deployment specification
        deploy_path = Path(deployment_file)
        if not deploy_path.exists():
            click.echo(f"Error: Deployment file not found: {deployment_file}", err=True)
            return
        
        with open(deploy_path, 'r') as f:
            if deploy_path.suffix.lower() in ['.yaml', '.yml']:
                deploy_spec = yaml.safe_load(f)
            else:
                deploy_spec = json.load(f)
        
        # Parse server specifications
        servers = []
        for server_config in deploy_spec.get('servers', []):
            server = ServerDeploymentSpec(
                name=server_config['name'],
                server_type=server_config['server_type'],
                dependencies=server_config.get('dependencies', []),
                environment=environment,
                config=server_config.get('config', {}),
                health_checks=server_config.get('health_checks', []),
                timeout_seconds=server_config.get('timeout_seconds', 300),
                retry_attempts=server_config.get('retry_attempts', 3),
                priority=server_config.get('priority', 0),
                parallel_safe=server_config.get('parallel_safe', False)
            )
            servers.append(server)
        
        if not servers:
            click.echo("Error: No servers defined in deployment file", err=True)
            return
        
        click.echo(f"Creating deployment plan for {len(servers)} servers...")
        
        # Create deployment plan
        plan = await cli_instance.orchestrator.create_deployment_plan(
            servers=servers,
            environment=environment
        )
        
        # Display deployment plan
        click.echo(f"\nDeployment Plan: {plan.deployment_id}")\n        click.echo(f"Environment: {environment}")\n        click.echo(f"Total Servers: {len(servers)}")\n        click.echo(f"Parallel Groups: {len(plan.parallel_groups)}")\n\n        # Show parallel groups\n        for i, group in enumerate(plan.parallel_groups):\n            click.echo(f"  Group {i+1}: {', '.join(group)}")\n\n        if dry_run:\n            click.echo("\nDry run complete - no deployment executed")\n            return\n\n        # Start monitoring if watch mode\n        if watch:\n            await cli_instance.monitor.start_monitoring()\n            await cli_instance.monitor.start_deployment_monitoring(\n                plan.deployment_id,\n                len(servers),\n                [s.name for s in servers]\n            )\n\n        # Execute deployment\n        click.echo("\nStarting deployment...")\n\n        def progress_callback(deployment_id: str, phase: DeploymentPhase, progress: float):\n            click.echo(f"Phase: {phase.value} - Progress: {progress*100:.1f}%")\n\n        results = await cli_instance.orchestrator.execute_deployment(\n            plan,\n            progress_callback=progress_callback if cli_instance.verbose else None\n        )\n\n        # Display results\n        successful = len([r for r in results if r.status == DeploymentStatus.SUCCESS])\n        failed = len([r for r in results if r.status == DeploymentStatus.FAILED])\n\n        click.echo(f"\nDeployment completed:")\n        click.echo(f"  Successful: {successful}")\n        click.echo(f"  Failed: {failed}")\n\n        if watch:\n            await cli_instance.monitor.complete_deployment_monitoring(\n                plan.deployment_id,\n                failed == 0\n            )\n\n            if failed == 0:\n                click.echo("✅ Deployment successful!")\n            else:\n                click.echo("❌ Deployment failed!")\n\n    except Exception as e:\n        click.echo(f"Error: {e}", err=True)\n        if cli_instance.verbose:\n            import traceback\n            traceback.print_exc()\n\n\n@deploy.command()\n@click.option('--limit', '-l', default=10, help='Number of deployments to list')\ndef list(limit):\n    """List recent deployments."""\n    asyncio.run(_list_deployments(limit))\n\n\nasync def _list_deployments(limit: int):\n    """List recent deployments."""\n    # This would typically query a database or state store\n    click.echo("Recent deployments:")\n    click.echo("(This would show recent deployment history)")\n\n\n@deploy.command()\n@click.argument('deployment_id')\ndef status(deployment_id):\n    """Get status of a specific deployment."""\n    asyncio.run(_get_deployment_status(deployment_id))\n\n\nasync def _get_deployment_status(deployment_id: str):\n    """Get deployment status."""\n    status = cli_instance.orchestrator.get_deployment_status(deployment_id)\n\n    if 'error' in status:\n        click.echo(f"Error: {status['error']}", err=True)\n        return\n\n    click.echo(f"Deployment: {deployment_id}")\n    click.echo(f"Total Operations: {status['total_operations']}")\n    click.echo(f"Successful: {status['successful_operations']}")\n    click.echo(f"Failed: {status['failed_operations']}")\n    click.echo(f"Phases Completed: {status['phases_completed']}")\n\n    if status['results']:\n        click.echo("\nDetailed Results:")\n        table_data = []\n        for result in status['results']:\n            table_data.append([\n                result['server'],\n                result['phase'],\n                result['status'],\n                f"{result['duration']:.2f}s",\n                result['error'] or ''\n            ])\n\n        click.echo(tabulate(\n            table_data,\n            headers=['Server', 'Phase', 'Status', 'Duration', 'Error'],\n            tablefmt='grid'\n        ))\n\n\n# Monitoring commands\n@monitor.command()\n@click.option('--port', '-p', default=8765, help='WebSocket port for monitoring')\ndef start(port):\n    """Start the deployment monitor."""\n    asyncio.run(_start_monitor(port))\n\n\nasync def _start_monitor(port: int):\n    """Start deployment monitor."""\n    cli_instance.monitor.websocket_port = port\n\n    click.echo(f"Starting deployment monitor on port {port}...")\n    await cli_instance.monitor.start_monitoring()\n\n    click.echo("Monitor started. Press Ctrl+C to stop.")\n    try:\n        while True:\n            await asyncio.sleep(1)\n    except KeyboardInterrupt:\n        click.echo("\nStopping monitor...")\n        await cli_instance.monitor.stop_monitoring()\n\n\n@monitor.command()\n@click.argument('deployment_id', required=False)\n@click.option('--events', '-e', is_flag=True, help='Show recent events')\n@click.option('--metrics', '-m', is_flag=True, help='Show system metrics')\ndef show(deployment_id, events, metrics):\n    """Show monitoring information."""\n    asyncio.run(_show_monitoring_info(deployment_id, events, metrics))\n\n\nasync def _show_monitoring_info(deployment_id: Optional[str], show_events: bool, show_metrics: bool):\n    """Show monitoring information."""\n    if deployment_id:\n        status = cli_instance.monitor.get_deployment_status(deployment_id)\n        if status:\n            click.echo(f"Deployment: {deployment_id}")\n            click.echo(f"Status: {status['status']}")\n            click.echo(f"Progress: {status['progress_percentage']:.1f}%")\n\n            if status['duration_seconds']:\n                click.echo(f"Duration: {status['duration_seconds']:.1f}s")\n\n            # Show server details\n            if status['server_details']:\n                click.echo("\nServers:")\n                table_data = []\n                for server in status['server_details']:\n                    table_data.append([\n                        server['name'],\n                        server['status'],\n                        server['health_status'],\n                        server['alerts_count']\n                    ])\n\n                click.echo(tabulate(\n                    table_data,\n                    headers=['Name', 'Status', 'Health', 'Alerts'],\n                    tablefmt='grid'\n                ))\n        else:\n            click.echo(f"Deployment not found: {deployment_id}")\n\n    if show_events:\n        events = cli_instance.monitor.get_recent_events(deployment_id=deployment_id, limit=20)\n        if events:\n            click.echo("\nRecent Events:")\n            for event in events[-10:]:  # Show last 10\n                timestamp = time.strftime('%H:%M:%S', time.localtime(event['timestamp']))\n                click.echo(f"[{timestamp}] {event['event_type']} - {event['deployment_id']} - {event.get('server_name', 'system')}")\n\n    if show_metrics:\n        metrics = cli_instance.monitor.get_system_metrics()\n        if metrics:\n            click.echo("\nSystem Metrics:")\n            click.echo(f"CPU Usage: {metrics.get('cpu_usage', 0):.1f}%")\n            click.echo(f"Memory Usage: {metrics.get('memory_usage', 0):.1f}%")\n            click.echo(f"Disk Usage: {metrics.get('disk_usage', 0):.1f}%")\n\n\n# Rollback commands\n@rollback.command()\n@click.argument('deployment_id')\n@click.option('--strategy', default='graceful', type=click.Choice(['immediate', 'batch', 'manual', 'graceful', 'aggressive']))\n@click.option('--servers', help='Comma-separated list of servers to rollback')\n@click.option('--confirm', is_flag=True, help='Skip confirmation prompt')\ndef start(deployment_id, strategy, servers, confirm):\n    """Start rollback for a failed deployment."""\n    asyncio.run(_start_rollback(deployment_id, strategy, servers, confirm))\n\n\nasync def _start_rollback(deployment_id: str, strategy: str, servers: Optional[str], confirm: bool):\n    """Start rollback operation."""\n    try:\n        failed_servers = servers.split(',') if servers else []\n\n        if not failed_servers:\n            click.echo("Error: No servers specified for rollback", err=True)\n            return\n\n        rollback_strategy = RollbackStrategy(strategy)\n\n        if not confirm:\n            click.echo(f"Starting rollback for deployment: {deployment_id}")\n            click.echo(f"Strategy: {strategy}")\n            click.echo(f"Servers: {', '.join(failed_servers)}")\n\n            if not click.confirm("Continue with rollback?"):\n                click.echo("Rollback cancelled")\n                return\n\n        # Create rollback plan\n        plan = await cli_instance.rollback_manager.create_rollback_plan(\n            deployment_id=deployment_id,\n            failed_servers=failed_servers,\n            rollback_strategy=rollback_strategy\n        )\n\n        click.echo(f"Created rollback plan: {plan.plan_id}")\n        click.echo(f"Actions: {len(plan.actions)}")\n        click.echo(f"Estimated duration: {plan.estimated_duration_seconds:.1f}s")\n\n        # Execute rollback\n        click.echo("\nExecuting rollback...")\n\n        def progress_callback(plan_id: str, current: int, total: int):\n            click.echo(f"Progress: {current}/{total} actions completed")\n\n        results = await cli_instance.rollback_manager.execute_rollback_plan(\n            plan,\n            progress_callback=progress_callback if cli_instance.verbose else None\n        )\n\n        # Display results\n        successful = len([r for r in results if r.success])\n        failed = len([r for r in results if not r.success])\n\n        click.echo(f"\nRollback completed:")\n        click.echo(f"  Successful actions: {successful}")\n        click.echo(f"  Failed actions: {failed}")\n\n        if failed == 0:\n            click.echo("✅ Rollback successful!")\n        else:\n            click.echo("⚠️ Rollback completed with errors")\n\n    except Exception as e:\n        click.echo(f"Error: {e}", err=True)\n\n\n@rollback.command()\n@click.argument('plan_id')\ndef status(plan_id):\n    """Get rollback plan status."""\n    status = cli_instance.rollback_manager.get_rollback_status(plan_id)\n\n    if 'error' in status:\n        click.echo(f"Error: {status['error']}", err=True)\n        return\n\n    click.echo(f"Rollback Plan: {plan_id}")\n    click.echo(f"Status: {status['status']}")\n    click.echo(f"Total Actions: {status['total_actions']}")\n    click.echo(f"Completed: {status['completed_actions']}")\n    click.echo(f"Successful: {status['successful_actions']}")\n    click.echo(f"Failed: {status['failed_actions']}")\n\n\n@rollback.command()\ndef list():\n    """List available snapshots for rollback."""\n    snapshots = cli_instance.rollback_manager.list_snapshots()\n\n    if not snapshots:\n        click.echo("No snapshots available")\n        return\n\n    click.echo("Available snapshots:")\n    table_data = []\n    for snapshot in snapshots[:20]:  # Show last 20\n        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(snapshot['timestamp']))\n        table_data.append([\n            snapshot['snapshot_id'][:16],\n            snapshot['deployment_id'][:16],\n            snapshot['server_name'],\n            timestamp,\n            '✓' if snapshot['has_config_backup'] else '',\n            snapshot['file_backup_count']\n        ])\n\n    click.echo(tabulate(\n        table_data,\n        headers=['Snapshot ID', 'Deployment', 'Server', 'Created', 'Config', 'Files'],\n        tablefmt='grid'\n    ))\n\n\n# Configuration commands\n@config.command()\n@click.argument('server_name')\n@click.argument('environment')\n@click.option('--output', '-o', help='Output file path')\n@click.option('--format', default='yaml', type=click.Choice(['yaml', 'json']))\ndef show(server_name, environment, output, format):\n    """Show resolved configuration for a server."""\n    try:\n        config_data = cli_instance.config_manager.get_server_config(server_name, environment)\n\n        if format == 'json':\n            output_text = json.dumps(config_data, indent=2, default=str)\n        else:\n            output_text = yaml.dump(config_data, default_flow_style=False, sort_keys=False)\n\n        if output:\n            Path(output).write_text(output_text)\n            click.echo(f"Configuration saved to {output}")\n        else:\n            click.echo(output_text)\n\n    except Exception as e:\n        click.echo(f"Error: {e}", err=True)\n\n\n@config.command()\ndef validate():\n    """Validate all configurations."""\n    errors = cli_instance.config_manager.validate_all_configurations()\n\n    if not errors:\n        click.echo("✅ All configurations are valid")\n        return\n\n    click.echo("❌ Configuration validation errors:")\n    for key, error_list in errors.items():\n        click.echo(f"\n{key}:")\n        for error in error_list:\n            click.echo(f"  - {error}")\n\n\n@config.command()\ndef list():\n    """List available environments and servers."""\n    environments = cli_instance.config_manager.list_environments()\n    servers = cli_instance.config_manager.list_servers()\n\n    click.echo("Environments:")\n    for env in environments:\n        info = cli_instance.config_manager.get_environment_info(env)\n        click.echo(f"  {env} ({info['variables_count']} vars, {info['secrets_count']} secrets)")\n\n    click.echo("\nServers:")\n    for server in servers:\n        info = cli_instance.config_manager.get_server_info(server)\n        click.echo(f"  {server} ({info['server_type']}) - {len(info['environment_overrides'])} env overrides")\n\n\n# Health check commands\n@health.command()\n@click.argument('config_file')\ndef register(config_file):\n    """Register health checks from configuration file."""\n    asyncio.run(_register_health_checks(config_file))\n\n\nasync def _register_health_checks(config_file: str):\n    """Register health checks from file."""\n    try:\n        config_path = Path(config_file)\n        with open(config_path, 'r') as f:\n            if config_path.suffix.lower() in ['.yaml', '.yml']:\n                health_config = yaml.safe_load(f)\n            else:\n                health_config = json.load(f)\n\n        for check_config in health_config.get('health_checks', []):\n            config = HealthCheckConfig(\n                name=check_config['name'],\n                check_type=HealthCheckType(check_config['type']),\n                config=check_config.get('config', {}),\n                timeout_seconds=check_config.get('timeout_seconds', 30),\n                retry_attempts=check_config.get('retry_attempts', 3),\n                critical=check_config.get('critical', True),\n                tags=check_config.get('tags', [])\n            )\n\n            cli_instance.health_validator.register_health_check(config)\n            click.echo(f"Registered health check: {config.name}")\n\n    except Exception as e:\n        click.echo(f"Error: {e}", err=True)\n\n\n@health.command()\n@click.argument('check_name', required=False)\n@click.option('--all', is_flag=True, help='Run all registered health checks')\n@click.option('--tags', help='Comma-separated list of tags to filter checks')\ndef run(check_name, all, tags):\n    """Run health checks."""\n    asyncio.run(_run_health_checks(check_name, all, tags))\n\n\nasync def _run_health_checks(check_name: Optional[str], run_all: bool, tags: Optional[str]):\n    """Run health checks."""\n    try:\n        if check_name:\n            # Run single check\n            result = await cli_instance.health_validator.execute_health_check(check_name)\n\n            status_icon = "✅" if result.status.value == "healthy" else "❌"\n            click.echo(f"{status_icon} {result.check_name}: {result.status.value}")\n            click.echo(f"  Duration: {result.duration_ms:.1f}ms")\n            if result.message:\n                click.echo(f"  Message: {result.message}")\n            if result.error:\n                click.echo(f"  Error: {result.error}")\n\n        elif run_all or tags:\n            # Run multiple checks\n            tag_list = tags.split(',') if tags else None\n            results = await cli_instance.health_validator.execute_all_health_checks(\n                tags=tag_list,\n                parallel=True\n            )\n\n            # Generate report\n            report = cli_instance.health_validator.generate_health_report(results)\n\n            click.echo(f"Health Check Report")\n            click.echo(f"Overall Status: {report['overall_status']}")\n            click.echo(f"Success Rate: {report['summary']['success_rate']:.1f}%")\n            click.echo(f"Average Duration: {report['summary']['average_duration_ms']:.1f}ms")\n\n            # Show individual results\n            click.echo("\nIndividual Results:")\n            table_data = []\n            for detail in report['details']:\n                status_icon = "✅" if detail['status'] == "healthy" else "❌"\n                table_data.append([\n                    detail['name'],\n                    detail['type'],\n                    f"{status_icon} {detail['status']}",\n                    f"{detail['duration_ms']:.1f}ms",\n                    detail['error'] or detail['message'] or ''\n                ])\n\n            click.echo(tabulate(\n                table_data,\n                headers=['Name', 'Type', 'Status', 'Duration', 'Message'],\n                tablefmt='grid'\n            ))\n\n        else:\n            click.echo("Please specify a check name, use --all, or specify --tags")\n\n    except Exception as e:\n        click.echo(f"Error: {e}", err=True)\n\n\n@health.command()\ndef list():\n    """List registered health checks."""\n    checks = cli_instance.health_validator.list_health_checks()\n\n    if not checks:\n        click.echo("No health checks registered")\n        return\n\n    click.echo("Registered Health Checks:")\n    table_data = []\n    for check in checks:\n        table_data.append([\n            check['name'],\n            check['type'],\n            f"{check['timeout_seconds']}s",\n            check['retry_attempts'],\n            '✓' if check['critical'] else '',\n            ', '.join(check['tags'])\n        ])\n\n    click.echo(tabulate(\n        table_data,\n        headers=['Name', 'Type', 'Timeout', 'Retries', 'Critical', 'Tags'],\n        tablefmt='grid'\n    ))\n\n\nif __name__ == '__main__':\n    cli()