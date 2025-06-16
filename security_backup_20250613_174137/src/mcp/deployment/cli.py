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
        click.echo(f"\nDeployment Plan: {plan.deployment_id}")
        click.echo(f"Environment: {environment}")
        click.echo(f"Total Servers: {len(servers)}")
        click.echo(f"Parallel Groups: {len(plan.parallel_groups)}")
        
        # Show parallel groups
        for i, group in enumerate(plan.parallel_groups):
            click.echo(f"  Group {i+1}: {', '.join(group)}")
        
        if dry_run:
            click.echo("\nDry run complete - no deployment executed")
            return
        
        # Start monitoring if watch mode
        if watch:
            await cli_instance.monitor.start_monitoring()
            await cli_instance.monitor.start_deployment_monitoring(
                plan.deployment_id,
                len(servers),
                [s.name for s in servers]
            )
        
        # Execute deployment
        click.echo("\nStarting deployment...")
        
        def progress_callback(deployment_id: str, phase: DeploymentPhase, progress: float):
            click.echo(f"Phase: {phase.value} - Progress: {progress*100:.1f}%")
        
        results = await cli_instance.orchestrator.execute_deployment(
            plan,
            progress_callback=progress_callback if cli_instance.verbose else None
        )
        
        # Display results
        successful = len([r for r in results if r.status == DeploymentStatus.SUCCESS])
        failed = len([r for r in results if r.status == DeploymentStatus.FAILED])
        
        click.echo(f"\nDeployment completed:")
        click.echo(f"  Successful: {successful}")
        click.echo(f"  Failed: {failed}")
        
        if watch:
            await cli_instance.monitor.complete_deployment_monitoring(
                plan.deployment_id,
                failed == 0
            )
            
            if failed == 0:
                click.echo("✅ Deployment successful!")
            else:
                click.echo("❌ Deployment failed!")
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        if cli_instance.verbose:
            import traceback
            traceback.print_exc()


@deploy.command()
@click.option('--limit', '-l', default=10, help='Number of deployments to list')
def list(limit):
    """List recent deployments."""
    asyncio.run(_list_deployments(limit))


async def _list_deployments(limit: int):
    """List recent deployments."""
    # This would typically query a database or state store
    click.echo("Recent deployments:")
    click.echo("(This would show recent deployment history)")


@deploy.command()
@click.argument('deployment_id')
def status(deployment_id):
    """Get status of a specific deployment."""
    asyncio.run(_get_deployment_status(deployment_id))


async def _get_deployment_status(deployment_id: str):
    """Get deployment status."""
    status = cli_instance.orchestrator.get_deployment_status(deployment_id)
    
    if 'error' in status:
        click.echo(f"Error: {status['error']}", err=True)
        return
    
    click.echo(f"Deployment: {deployment_id}")
    click.echo(f"Total Operations: {status['total_operations']}")
    click.echo(f"Successful: {status['successful_operations']}")
    click.echo(f"Failed: {status['failed_operations']}")
    click.echo(f"Phases Completed: {status['phases_completed']}")
    
    if status['results']:
        click.echo("\nDetailed Results:")
        table_data = []
        for result in status['results']:
            table_data.append([
                result['server'],
                result['phase'],
                result['status'],
                f"{result['duration']:.2f}s",
                result['error'] or ''
            ])
        
        click.echo(tabulate(
            table_data,
            headers=['Server', 'Phase', 'Status', 'Duration', 'Error'],
            tablefmt='grid'
        ))


# Monitoring commands
@monitor.command()
@click.option('--port', '-p', default=8765, help='WebSocket port for monitoring')
def start(port):
    """Start the deployment monitor."""
    asyncio.run(_start_monitor(port))


async def _start_monitor(port: int):
    """Start deployment monitor."""
    cli_instance.monitor.websocket_port = port
    
    click.echo(f"Starting deployment monitor on port {port}...")
    await cli_instance.monitor.start_monitoring()
    
    click.echo("Monitor started. Press Ctrl+C to stop.")
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        click.echo("\nStopping monitor...")
        await cli_instance.monitor.stop_monitoring()


@monitor.command()
@click.argument('deployment_id', required=False)
@click.option('--events', '-e', is_flag=True, help='Show recent events')
@click.option('--metrics', '-m', is_flag=True, help='Show system metrics')
def show(deployment_id, events, metrics):
    """Show monitoring information."""
    asyncio.run(_show_monitoring_info(deployment_id, events, metrics))


async def _show_monitoring_info(deployment_id: Optional[str], show_events: bool, show_metrics: bool):
    """Show monitoring information."""
    if deployment_id:
        status = cli_instance.monitor.get_deployment_status(deployment_id)
        if status:
            click.echo(f"Deployment: {deployment_id}")
            click.echo(f"Status: {status['status']}")
            click.echo(f"Progress: {status['progress_percentage']:.1f}%")
            
            if status['duration_seconds']:
                click.echo(f"Duration: {status['duration_seconds']:.1f}s")
            
            # Show server details
            if status['server_details']:
                click.echo("\nServers:")
                table_data = []
                for server in status['server_details']:
                    table_data.append([
                        server['name'],
                        server['status'],
                        server['health_status'],
                        server['alerts_count']
                    ])
                
                click.echo(tabulate(
                    table_data,
                    headers=['Name', 'Status', 'Health', 'Alerts'],
                    tablefmt='grid'
                ))
        else:
            click.echo(f"Deployment not found: {deployment_id}")
    
    if show_events:
        events = cli_instance.monitor.get_recent_events(deployment_id=deployment_id, limit=20)
        if events:
            click.echo("\nRecent Events:")
            for event in events[-10:]:  # Show last 10
                timestamp = time.strftime('%H:%M:%S', time.localtime(event['timestamp']))
                click.echo(f"[{timestamp}] {event['event_type']} - {event['deployment_id']} - {event.get('server_name', 'system')}")
    
    if show_metrics:
        metrics = cli_instance.monitor.get_system_metrics()
        if metrics:
            click.echo("\nSystem Metrics:")
            click.echo(f"CPU Usage: {metrics.get('cpu_usage', 0):.1f}%")
            click.echo(f"Memory Usage: {metrics.get('memory_usage', 0):.1f}%")
            click.echo(f"Disk Usage: {metrics.get('disk_usage', 0):.1f}%")


# Rollback commands  
@rollback.command()
@click.argument('deployment_id')
@click.option('--strategy', default='graceful', type=click.Choice(['immediate', 'batch', 'manual', 'graceful', 'aggressive']))
@click.option('--servers', help='Comma-separated list of servers to rollback')
@click.option('--confirm', is_flag=True, help='Skip confirmation prompt')
def start(deployment_id, strategy, servers, confirm):
    """Start rollback for a failed deployment."""
    asyncio.run(_start_rollback(deployment_id, strategy, servers, confirm))


async def _start_rollback(deployment_id: str, strategy: str, servers: Optional[str], confirm: bool):
    """Start rollback operation."""
    try:
        failed_servers = servers.split(',') if servers else []
        
        if not failed_servers:
            click.echo("Error: No servers specified for rollback", err=True)
            return
        
        rollback_strategy = RollbackStrategy(strategy)
        
        if not confirm:
            click.echo(f"Starting rollback for deployment: {deployment_id}")
            click.echo(f"Strategy: {strategy}")
            click.echo(f"Servers: {', '.join(failed_servers)}")
            
            if not click.confirm("Continue with rollback?"):
                click.echo("Rollback cancelled")
                return
        
        # Create rollback plan
        plan = await cli_instance.rollback_manager.create_rollback_plan(
            deployment_id=deployment_id,
            failed_servers=failed_servers,
            rollback_strategy=rollback_strategy
        )
        
        click.echo(f"Created rollback plan: {plan.plan_id}")
        click.echo(f"Actions: {len(plan.actions)}")
        click.echo(f"Estimated duration: {plan.estimated_duration_seconds:.1f}s")
        
        # Execute rollback
        click.echo("\nExecuting rollback...")
        
        def progress_callback(plan_id: str, current: int, total: int):
            click.echo(f"Progress: {current}/{total} actions completed")
        
        results = await cli_instance.rollback_manager.execute_rollback_plan(
            plan,
            progress_callback=progress_callback if cli_instance.verbose else None
        )
        
        # Display results
        successful = len([r for r in results if r.success])
        failed = len([r for r in results if not r.success])
        
        click.echo(f"\nRollback completed:")
        click.echo(f"  Successful actions: {successful}")
        click.echo(f"  Failed actions: {failed}")
        
        if failed == 0:
            click.echo("✅ Rollback successful!")
        else:
            click.echo("⚠️ Rollback completed with errors")
    
    except Exception as e:
        click.echo(f"Error: {e}", err=True)


@rollback.command()
@click.argument('plan_id')
def status(plan_id):
    """Get rollback plan status."""
    status = cli_instance.rollback_manager.get_rollback_status(plan_id)
    
    if 'error' in status:
        click.echo(f"Error: {status['error']}", err=True)
        return
    
    click.echo(f"Rollback Plan: {plan_id}")
    click.echo(f"Status: {status['status']}")
    click.echo(f"Total Actions: {status['total_actions']}")
    click.echo(f"Completed: {status['completed_actions']}")
    click.echo(f"Successful: {status['successful_actions']}")
    click.echo(f"Failed: {status['failed_actions']}")


@rollback.command()
def list():
    """List available snapshots for rollback."""
    snapshots = cli_instance.rollback_manager.list_snapshots()
    
    if not snapshots:
        click.echo("No snapshots available")
        return
    
    click.echo("Available snapshots:")
    table_data = []
    for snapshot in snapshots[:20]:  # Show last 20
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(snapshot['timestamp']))
        table_data.append([
            snapshot['snapshot_id'][:16],
            snapshot['deployment_id'][:16],
            snapshot['server_name'],
            timestamp,
            '✓' if snapshot['has_config_backup'] else '',
            snapshot['file_backup_count']
        ])
    
    click.echo(tabulate(
        table_data,
        headers=['Snapshot ID', 'Deployment', 'Server', 'Created', 'Config', 'Files'],
        tablefmt='grid'
    ))


# Configuration commands
@config.command()
@click.argument('server_name')
@click.argument('environment')
@click.option('--output', '-o', help='Output file path')
@click.option('--format', default='yaml', type=click.Choice(['yaml', 'json']))
def show(server_name, environment, output, format):
    """Show resolved configuration for a server."""
    try:
        config_data = cli_instance.config_manager.get_server_config(server_name, environment)
        
        if format == 'json':
            output_text = json.dumps(config_data, indent=2, default=str)
        else:
            output_text = yaml.dump(config_data, default_flow_style=False, sort_keys=False)
        
        if output:
            Path(output).write_text(output_text)
            click.echo(f"Configuration saved to {output}")
        else:
            click.echo(output_text)
    
    except Exception as e:
        click.echo(f"Error: {e}", err=True)


@config.command()
def validate():
    """Validate all configurations."""
    errors = cli_instance.config_manager.validate_all_configurations()
    
    if not errors:
        click.echo("✅ All configurations are valid")
        return
    
    click.echo("❌ Configuration validation errors:")
    for key, error_list in errors.items():
        click.echo(f"\n{key}:")
        for error in error_list:
            click.echo(f"  - {error}")


@config.command()
def list():
    """List available environments and servers."""
    environments = cli_instance.config_manager.list_environments()
    servers = cli_instance.config_manager.list_servers()
    
    click.echo("Environments:")
    for env in environments:
        info = cli_instance.config_manager.get_environment_info(env)
        click.echo(f"  {env} ({info['variables_count']} vars, {info['secrets_count']} secrets)")
    
    click.echo("\nServers:")
    for server in servers:
        info = cli_instance.config_manager.get_server_info(server)
        click.echo(f"  {server} ({info['server_type']}) - {len(info['environment_overrides'])} env overrides")


# Health check commands
@health.command()
@click.argument('config_file')
def register(config_file):
    """Register health checks from configuration file."""
    asyncio.run(_register_health_checks(config_file))


async def _register_health_checks(config_file: str):
    """Register health checks from file."""
    try:
        config_path = Path(config_file)
        with open(config_path, 'r') as f:
            if config_path.suffix.lower() in ['.yaml', '.yml']:
                health_config = yaml.safe_load(f)
            else:
                health_config = json.load(f)
        
        for check_config in health_config.get('health_checks', []):
            config = HealthCheckConfig(
                name=check_config['name'],
                check_type=HealthCheckType(check_config['type']),
                config=check_config.get('config', {}),
                timeout_seconds=check_config.get('timeout_seconds', 30),
                retry_attempts=check_config.get('retry_attempts', 3),
                critical=check_config.get('critical', True),
                tags=check_config.get('tags', [])
            )
            
            cli_instance.health_validator.register_health_check(config)
            click.echo(f"Registered health check: {config.name}")
    
    except Exception as e:
        click.echo(f"Error: {e}", err=True)


@health.command()
@click.argument('check_name', required=False)
@click.option('--all', is_flag=True, help='Run all registered health checks')
@click.option('--tags', help='Comma-separated list of tags to filter checks')
def run(check_name, all, tags):
    """Run health checks."""
    asyncio.run(_run_health_checks(check_name, all, tags))


async def _run_health_checks(check_name: Optional[str], run_all: bool, tags: Optional[str]):
    """Run health checks."""
    try:
        if check_name:
            # Run single check
            result = await cli_instance.health_validator.execute_health_check(check_name)
            
            status_icon = "✅" if result.status.value == "healthy" else "❌"
            click.echo(f"{status_icon} {result.check_name}: {result.status.value}")
            click.echo(f"  Duration: {result.duration_ms:.1f}ms")
            if result.message:
                click.echo(f"  Message: {result.message}")
            if result.error:
                click.echo(f"  Error: {result.error}")
        
        elif run_all or tags:
            # Run multiple checks
            tag_list = tags.split(',') if tags else None
            results = await cli_instance.health_validator.execute_all_health_checks(
                tags=tag_list,
                parallel=True
            )
            
            # Generate report
            report = cli_instance.health_validator.generate_health_report(results)
            
            click.echo(f"Health Check Report")
            click.echo(f"Overall Status: {report['overall_status']}")
            click.echo(f"Success Rate: {report['summary']['success_rate']:.1f}%")
            click.echo(f"Average Duration: {report['summary']['average_duration_ms']:.1f}ms")
            
            # Show individual results
            click.echo("\nIndividual Results:")
            table_data = []
            for detail in report['details']:
                status_icon = "✅" if detail['status'] == "healthy" else "❌"
                table_data.append([
                    detail['name'],
                    detail['type'],
                    f"{status_icon} {detail['status']}",
                    f"{detail['duration_ms']:.1f}ms",
                    detail['error'] or detail['message'] or ''
                ])
            
            click.echo(tabulate(
                table_data,
                headers=['Name', 'Type', 'Status', 'Duration', 'Message'],
                tablefmt='grid'
            ))
        
        else:
            click.echo("Please specify a check name, use --all, or specify --tags")
    
    except Exception as e:
        click.echo(f"Error: {e}", err=True)


@health.command()
def list():
    """List registered health checks."""
    checks = cli_instance.health_validator.list_health_checks()
    
    if not checks:
        click.echo("No health checks registered")
        return
    
    click.echo("Registered Health Checks:")
    table_data = []
    for check in checks:
        table_data.append([
            check['name'],
            check['type'],
            f"{check['timeout_seconds']}s",
            check['retry_attempts'],
            '✓' if check['critical'] else '',
            ', '.join(check['tags'])
        ])
    
    click.echo(tabulate(
        table_data,
        headers=['Name', 'Type', 'Timeout', 'Retries', 'Critical', 'Tags'],
        tablefmt='grid'
    ))


if __name__ == '__main__':
    cli()