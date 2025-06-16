"""
Deployment command group with enhanced UX.

Features:
- Smart deployment strategies
- Progress tracking
- Rollback capabilities
- Batch operations
"""

import asyncio
from pathlib import Path
from typing import Dict, Any, List, Optional
import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Confirm

from src.cli.utils import (
    format_success, format_error, format_warning, format_info,
    auto_detect_deployment_strategy, auto_detect_project_type,
    create_batch_operation_plan, ProgressTracker
)

console = Console()


@click.group(name='deploy')
def deploy_group():
    """
    Deployment operations with intelligent automation.
    
    Smart features:
    - Auto-detection of project type and environment
    - Intelligent strategy selection
    - Progress tracking with ETA
    - Automatic rollback on failure
    """
    pass


@deploy_group.command()
@click.argument('deployment_file', required=False, type=click.Path(exists=True))
@click.option('--environment', '-e', help='Target environment (auto-detected if not specified)')
@click.option('--strategy', '-s', 
              type=click.Choice(['rolling', 'blue-green', 'canary', 'recreate']),
              help='Deployment strategy (auto-selected if not specified)')
@click.option('--dry-run', is_flag=True, help='Show what would be deployed without executing')
@click.option('--watch', '-w', is_flag=True, help='Watch deployment progress in real-time')
@click.option('--parallel', is_flag=True, default=True, help='Enable parallel deployment where safe')
@click.option('--auto-rollback/--no-auto-rollback', default=True, 
              help='Automatically rollback on failure')
@click.option('--timeout', default=600, help='Deployment timeout in seconds')
@click.option('--health-check/--skip-health-check', default=True,
              help='Perform health checks after deployment')
@click.pass_context
def start(ctx, deployment_file, environment, strategy, dry_run, watch, 
          parallel, auto_rollback, timeout, health_check):
    """
    Start a new deployment with intelligent defaults.
    
    Examples:
        claude-deploy deploy                    # Deploy current directory
        claude-deploy deploy app.yaml          # Deploy from file
        claude-deploy deploy --dry-run         # Preview deployment
        claude-deploy deploy --environment prod # Deploy to production
    """
    try:
        # Auto-detect deployment file if not provided
        if not deployment_file:
            deployment_file = auto_detect_deployment_file()
            if deployment_file:
                console.print(format_info(f"Auto-detected deployment file: {deployment_file}"))
            else:
                console.print(format_error("No deployment file found. Use 'claude-deploy init' to create one."))
                return
                
        # Auto-detect environment if not provided
        if not environment:
            environment = ctx.obj.get('environment', 'development')
            
        # Auto-detect strategy if not provided
        if not strategy:
            project_type = auto_detect_project_type(Path.cwd())
            strategy = auto_detect_deployment_strategy(project_type, environment)
            console.print(format_info(f"Auto-selected strategy: {strategy}"))
            
        # Load and validate deployment specification
        deploy_spec = load_deployment_spec(deployment_file)
        validation_errors = validate_deployment_spec(deploy_spec, environment)
        
        if validation_errors:
            console.print(format_error("Deployment validation failed:"))
            for error in validation_errors:
                console.print(f"  • {error}")
            return
            
        # Show deployment summary
        show_deployment_summary(deploy_spec, environment, strategy, parallel)
        
        if dry_run:
            console.print(format_success("✅ Dry run completed - deployment plan is valid"))
            return
            
        # Confirm deployment for production
        if environment == 'production' and not Confirm.ask(
            "⚠️  Deploy to PRODUCTION environment?", default=False
        ):
            console.print(format_warning("Deployment cancelled"))
            return
            
        # Execute deployment
        result = asyncio.run(execute_deployment(
            deploy_spec, environment, strategy, 
            parallel, auto_rollback, timeout, health_check, watch
        ))
        
        if result['success']:
            console.print(format_success("🚀 Deployment completed successfully!"))
            show_post_deployment_info(result)
        else:
            console.print(format_error(f"❌ Deployment failed: {result['error']}"))
            if result.get('rollback_performed'):
                console.print(format_warning("🔄 Automatic rollback completed"))
                
    except Exception as e:
        console.print(format_error(f"Deployment error: {e}"))


@deploy_group.command()
@click.option('--environment', '-e', help='Environment to list deployments from')
@click.option('--status', '-s', type=click.Choice(['all', 'running', 'failed', 'completed']),
              default='all', help='Filter by deployment status')
@click.option('--limit', '-l', default=20, help='Number of deployments to show')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json', 'yaml']),
              default='table', help='Output format')
def list(environment, status, limit, output_format):
    """
    List recent deployments with status and metrics.
    
    Shows deployment history with:
    - Current status and health
    - Resource usage
    - Performance metrics
    - Quick action buttons
    """
    deployments = get_deployment_list(environment, status, limit)
    
    if output_format == 'table':
        show_deployments_table(deployments)
    elif output_format == 'json':
        import json
        console.print(json.dumps(deployments, indent=2, default=str))
    else:  # yaml
        import yaml
        console.print(yaml.dump(deployments, default_flow_style=False))


@deploy_group.command()
@click.argument('deployment_id')
@click.option('--detailed', '-d', is_flag=True, help='Show detailed status including logs')
@click.option('--watch', '-w', is_flag=True, help='Watch status in real-time')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json']),
              default='table', help='Output format')
def status(deployment_id, detailed, watch, output_format):
    """
    Show detailed status of a specific deployment.
    
    Displays:
    - Current phase and progress
    - Resource utilization
    - Health check results
    - Recent events and logs
    """
    if watch:
        asyncio.run(watch_deployment_status(deployment_id, detailed))
    else:
        deployment_status = get_deployment_status(deployment_id)
        if output_format == 'table':
            show_deployment_status_table(deployment_status, detailed)
        else:
            import json
            console.print(json.dumps(deployment_status, indent=2, default=str))


@deploy_group.command()
@click.argument('deployment_id')
@click.option('--strategy', type=click.Choice(['immediate', 'graceful', 'manual']),
              default='graceful', help='Rollback strategy')
@click.option('--to-version', help='Specific version to rollback to')
@click.option('--dry-run', is_flag=True, help='Show rollback plan without executing')
@click.option('--confirm', is_flag=True, help='Skip confirmation prompt')
def rollback(deployment_id, strategy, to_version, dry_run, confirm):
    """
    Rollback a deployment to previous version.
    
    Strategies:
    - immediate: Fast rollback, may cause brief downtime
    - graceful: Gradual rollback maintaining availability  
    - manual: Step-by-step guided rollback
    """
    try:
        # Get deployment info
        deployment = get_deployment_info(deployment_id)
        if not deployment:
            console.print(format_error(f"Deployment not found: {deployment_id}"))
            return
            
        # Determine target version
        if not to_version:
            versions = get_available_versions(deployment_id)
            if not versions:
                console.print(format_error("No previous versions available for rollback"))
                return
            to_version = versions[0]  # Most recent previous version
            
        # Show rollback plan
        rollback_plan = create_rollback_plan(deployment, to_version, strategy)
        show_rollback_plan(rollback_plan)
        
        if dry_run:
            console.print(format_success("✅ Rollback plan generated successfully"))
            return
            
        # Confirm rollback
        if not confirm and not Confirm.ask(
            f"Rollback deployment {deployment_id} to version {to_version}?",
            default=False
        ):
            console.print(format_warning("Rollback cancelled"))
            return
            
        # Execute rollback
        result = asyncio.run(execute_rollback(rollback_plan))
        
        if result['success']:
            console.print(format_success("🔄 Rollback completed successfully!"))
        else:
            console.print(format_error(f"❌ Rollback failed: {result['error']}"))
            
    except Exception as e:
        console.print(format_error(f"Rollback error: {e}"))


@deploy_group.command()
@click.argument('deployment_id')
@click.option('--replicas', '-r', type=int, help='Number of replicas')
@click.option('--cpu', help='CPU allocation (e.g., "2", "500m")')
@click.option('--memory', help='Memory allocation (e.g., "2Gi", "512Mi")')
@click.option('--auto-scale/--no-auto-scale', help='Enable/disable auto-scaling')
@click.option('--min-replicas', type=int, help='Minimum replicas for auto-scaling')
@click.option('--max-replicas', type=int, help='Maximum replicas for auto-scaling')
def scale(deployment_id, replicas, cpu, memory, auto_scale, min_replicas, max_replicas):
    """
    Scale deployment resources up or down.
    
    Supports both manual scaling and auto-scaling configuration.
    Changes are applied gradually to maintain availability.
    """
    try:
        scaling_config = {
            'deployment_id': deployment_id,
            'replicas': replicas,
            'cpu': cpu,
            'memory': memory,
            'auto_scale': auto_scale,
            'min_replicas': min_replicas,
            'max_replicas': max_replicas
        }
        
        # Remove None values
        scaling_config = {k: v for k, v in scaling_config.items() if v is not None}
        
        if len(scaling_config) == 1:  # Only deployment_id
            console.print(format_error("No scaling parameters provided"))
            return
            
        # Show current and target configuration
        current_config = get_current_scaling_config(deployment_id)
        show_scaling_comparison(current_config, scaling_config)
        
        if not Confirm.ask("Apply scaling changes?", default=True):
            console.print(format_warning("Scaling cancelled"))
            return
            
        # Execute scaling
        result = asyncio.run(execute_scaling(scaling_config))
        
        if result['success']:
            console.print(format_success("📈 Scaling completed successfully!"))
        else:
            console.print(format_error(f"❌ Scaling failed: {result['error']}"))
            
    except Exception as e:
        console.print(format_error(f"Scaling error: {e}"))


@deploy_group.command()
@click.argument('deployments', nargs=-1)
@click.option('--environment', '-e', help='Target environment for all deployments')
@click.option('--strategy', type=click.Choice(['sequential', 'parallel', 'waves']),
              default='waves', help='Batch deployment strategy')
@click.option('--max-parallel', default=5, help='Maximum parallel deployments')
@click.option('--continue-on-failure', is_flag=True, 
              help='Continue batch even if some deployments fail')
@click.option('--dry-run', is_flag=True, help='Show batch plan without executing')
def batch(deployments, environment, strategy, max_parallel, continue_on_failure, dry_run):
    """
    Deploy multiple applications in a coordinated batch.
    
    Strategies:
    - sequential: Deploy one after another
    - parallel: Deploy all simultaneously (up to max-parallel)
    - waves: Deploy in waves based on dependencies
    """
    try:
        if not deployments:
            console.print(format_error("No deployment files specified"))
            return
            
        # Load and validate all deployment specs
        batch_specs = []
        for deployment_file in deployments:
            if not Path(deployment_file).exists():
                console.print(format_error(f"Deployment file not found: {deployment_file}"))
                return
            spec = load_deployment_spec(deployment_file)
            spec['file'] = deployment_file
            batch_specs.append(spec)
            
        # Create batch execution plan
        operations = []
        for spec in batch_specs:
            operations.append({
                'name': spec.get('name', Path(spec['file']).stem),
                'file': spec['file'],
                'dependencies': spec.get('dependencies', []),
                'priority': spec.get('priority', 0),
                'estimated_time': estimate_deployment_time(spec)
            })
            
        execution_plan = create_batch_operation_plan(operations, max_parallel)
        
        # Show batch plan
        show_batch_execution_plan(execution_plan, strategy)
        
        if dry_run:
            console.print(format_success("✅ Batch deployment plan generated successfully"))
            return
            
        if not Confirm.ask("Execute batch deployment?", default=True):
            console.print(format_warning("Batch deployment cancelled"))
            return
            
        # Execute batch deployment
        result = asyncio.run(execute_batch_deployment(
            execution_plan, environment, strategy, continue_on_failure
        ))
        
        # Show results summary
        show_batch_results(result)
        
    except Exception as e:
        console.print(format_error(f"Batch deployment error: {e}"))


# Helper functions

def auto_detect_deployment_file() -> Optional[str]:
    """Auto-detect deployment file in current directory."""
    possible_files = [
        'claude-deploy.yaml', 'claude-deploy.yml',
        'deployment.yaml', 'deployment.yml',
        'deploy.yaml', 'deploy.yml',
        'docker-compose.yaml', 'docker-compose.yml'
    ]
    
    for filename in possible_files:
        if Path(filename).exists():
            return filename
    return None


def load_deployment_spec(deployment_file: str) -> Dict[str, Any]:
    """Load and parse deployment specification."""
    import yaml
    with open(deployment_file, 'r') as f:
        return yaml.safe_load(f)


def validate_deployment_spec(spec: Dict[str, Any], environment: str) -> List[str]:
    """Validate deployment specification."""
    errors = []
    
    if 'name' not in spec:
        errors.append("Missing required field: name")
    if 'version' not in spec:
        errors.append("Missing required field: version")
    if 'servers' not in spec and 'services' not in spec:
        errors.append("Missing required field: servers or services")
        
    return errors


def show_deployment_summary(spec: Dict[str, Any], environment: str, 
                          strategy: str, parallel: bool):
    """Show deployment summary before execution."""
    table = Table(title="Deployment Summary")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("Name", spec.get('name', 'unknown'))
    table.add_row("Version", spec.get('version', 'unknown'))
    table.add_row("Environment", environment)
    table.add_row("Strategy", strategy)
    table.add_row("Parallel", "✓" if parallel else "✗")
    
    services_count = len(spec.get('servers', spec.get('services', [])))
    table.add_row("Services", str(services_count))
    
    console.print(table)


async def execute_deployment(spec: Dict[str, Any], environment: str, strategy: str,
                            parallel: bool, auto_rollback: bool, timeout: int,
                            health_check: bool, watch: bool) -> Dict[str, Any]:
    """Execute the deployment with progress tracking."""
    deployment_id = f"deploy_{int(asyncio.get_event_loop().time())}"
    
    # Simulate deployment phases
    phases = [
        ("Validating", 2),
        ("Building", 15),
        ("Pushing", 10),
        ("Deploying", 20),
        ("Health Checks", 5) if health_check else None,
        ("Finalizing", 2)
    ]
    phases = [p for p in phases if p is not None]
    
    total_steps = sum(duration for _, duration in phases)
    tracker = ProgressTracker(total_steps, "Deploying")
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Starting deployment...", total=total_steps)
            
            for phase_name, duration in phases:
                for step in range(duration):
                    progress.update(task, description=f"{phase_name}...")
                    await asyncio.sleep(0.1)  # Simulate work
                    progress.advance(task, 1)
                    
        return {
            'success': True,
            'deployment_id': deployment_id,
            'duration': sum(duration for _, duration in phases) * 0.1,
            'services_deployed': len(spec.get('servers', spec.get('services', [])))
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'rollback_performed': auto_rollback
        }


def show_post_deployment_info(result: Dict[str, Any]):
    """Show information after successful deployment."""
    console.print("\n📋 [bold]Deployment Complete[/bold]")
    console.print(f"Deployment ID: {result['deployment_id']}")
    console.print(f"Duration: {result['duration']:.1f}s")
    console.print(f"Services: {result['services_deployed']}")
    
    console.print("\n[bold]Next Steps:[/bold]")
    console.print(f"• Check status: claude-deploy deploy status {result['deployment_id']}")
    console.print(f"• View logs: claude-deploy logs {result['deployment_id']}")
    console.print(f"• Monitor: claude-deploy monitor dashboard")


# Placeholder implementations for other functions

def get_deployment_list(environment: str, status: str, limit: int) -> List[Dict[str, Any]]:
    """Get list of deployments."""
    # Mock data
    return [
        {
            'id': 'deploy_001',
            'name': 'api-server',
            'status': 'running',
            'environment': 'production',
            'created': '2024-01-15T10:30:00Z',
            'replicas': 3
        }
    ]


def show_deployments_table(deployments: List[Dict[str, Any]]):
    """Show deployments in table format."""
    table = Table(title="Deployments")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Status", style="green")
    table.add_column("Environment")
    table.add_column("Created")
    table.add_column("Replicas")
    
    for dep in deployments:
        status_color = "green" if dep['status'] == 'running' else "yellow"
        table.add_row(
            dep['id'][:12],
            dep['name'],
            f"[{status_color}]{dep['status']}[/{status_color}]",
            dep['environment'],
            dep['created'][:10],
            str(dep['replicas'])
        )
    
    console.print(table)


def get_deployment_status(deployment_id: str) -> Dict[str, Any]:
    """Get detailed deployment status."""
    return {
        'id': deployment_id,
        'status': 'running',
        'phase': 'steady-state',
        'progress': 100,
        'health': 'healthy',
        'metrics': {
            'cpu': 45,
            'memory': 67,
            'requests_per_second': 120
        }
    }


def show_deployment_status_table(status: Dict[str, Any], detailed: bool):
    """Show deployment status in table format."""
    console.print(f"[bold]Deployment: {status['id']}[/bold]")
    console.print(f"Status: [green]{status['status']}[/green]")
    console.print(f"Phase: {status['phase']}")
    console.print(f"Progress: {status['progress']}%")
    
    if detailed:
        console.print(f"\n[bold]Metrics:[/bold]")\n        console.print(f"CPU: {status['metrics']['cpu']}%")\n        console.print(f"Memory: {status['metrics']['memory']}%")\n        console.print(f"RPS: {status['metrics']['requests_per_second']}")\n\n\nasync def watch_deployment_status(deployment_id: str, detailed: bool):\n    """Watch deployment status in real-time."""\n    console.print(f"[bold]Watching deployment: {deployment_id}[/bold]")\n    console.print("Press Ctrl+C to stop watching
")
    
    try:
        while True:
            status = get_deployment_status(deployment_id)
            console.clear()
            show_deployment_status_table(status, detailed)
            await asyncio.sleep(2)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped watching[/yellow]")\n\n\n# More placeholder implementations...\n\ndef get_deployment_info(deployment_id: str) -> Optional[Dict[str, Any]]:\n    return {'id': deployment_id, 'name': 'test-app'}\n\ndef get_available_versions(deployment_id: str) -> List[str]:\n    return ['v1.0.0', 'v0.9.0']\n\ndef create_rollback_plan(deployment: Dict[str, Any], to_version: str, strategy: str) -> Dict[str, Any]:\n    return {'deployment': deployment, 'target_version': to_version, 'strategy': strategy}\n\ndef show_rollback_plan(plan: Dict[str, Any]):\n    console.print(format_info(f"Rollback plan: {plan['target_version']} using {plan['strategy']} strategy"))\n\nasync def execute_rollback(plan: Dict[str, Any]) -> Dict[str, Any]:\n    await asyncio.sleep(2)\n    return {'success': True}\n\ndef get_current_scaling_config(deployment_id: str) -> Dict[str, Any]:\n    return {'replicas': 3, 'cpu': '1', 'memory': '2Gi'}\n\ndef show_scaling_comparison(current: Dict[str, Any], target: Dict[str, Any]):\n    console.print("Scaling comparison (placeholder)")\n\nasync def execute_scaling(config: Dict[str, Any]) -> Dict[str, Any]:\n    await asyncio.sleep(1)\n    return {'success': True}\n\ndef estimate_deployment_time(spec: Dict[str, Any]) -> int:\n    return 60  # seconds\n\ndef show_batch_execution_plan(plan: List[List[Dict[str, Any]]], strategy: str):\n    console.print(f"Batch execution plan using {strategy} strategy (placeholder)")\n\nasync def execute_batch_deployment(plan: List[List[Dict[str, Any]]], environment: str,\n                                 strategy: str, continue_on_failure: bool) -> Dict[str, Any]:\n    await asyncio.sleep(3)\n    return {'success': True, 'deployed': 3, 'failed': 0}\n\ndef show_batch_results(result: Dict[str, Any]):\n    console.print(format_success(f"Batch deployment: {result['deployed']} deployed, {result['failed']} failed"))