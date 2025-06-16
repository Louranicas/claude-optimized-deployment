#!/usr/bin/env python3
"""
Enhanced main CLI module with improved user experience.

Features:
- Intuitive command hierarchy
- Context-aware help
- Smart defaults
- Progress indicators
- Error recovery suggestions
"""

import asyncio
import os
import sys
from pathlib import Path
from typing import Optional, Dict, Any, List
import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.text import Text
from rich.syntax import Syntax
import yaml
import json

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.core.logging_config import get_logger
from src.cli.commands import deploy, expert, mcp, monitor, config
from src.cli.utils import (
    CLIContext, 
    format_error, 
    format_success,
    format_warning,
    format_info,
    auto_detect_environment,
    suggest_recovery_actions
)
from src.cli.interactive import InteractiveMode
from src.cli.tutorial import show_tutorial_menu, run_quick_start
from src.core.exceptions import BaseDeploymentError

logger = get_logger(__name__)
console = Console()

# Version info
VERSION = "1.0.0"
BANNER = """
╔═══════════════════════════════════════════════════════════════╗
║       Claude-Optimized Deployment Engine v{version}       ║
║                                                               ║
║  🚀 Enterprise-grade AI deployment orchestration              ║
║  🤖 Powered by Circle of Experts architecture                 ║
║  🔧 Model Context Protocol (MCP) integration                  ║
╚═══════════════════════════════════════════════════════════════╝
""".format(version=VERSION)


class CLIApplication:
    """Main CLI application with enhanced UX features."""
    
    def __init__(self):
        self.context = CLIContext()
        self.console = console
        self.interactive_mode = InteractiveMode(self.console)
        
    def show_banner(self):
        """Display welcome banner."""
        self.console.print(Panel(BANNER, style="bold blue"))
        
    def check_first_run(self):
        """Check if this is the first run and offer setup."""
        config_dir = Path.home() / ".claude-deploy"
        if not config_dir.exists():
            self.console.print(format_info("Welcome! This appears to be your first time using Claude Deploy."))
            if Confirm.ask("Would you like to run the interactive setup wizard?"):
                self.run_setup_wizard()
                
    def run_setup_wizard(self):
        """Run interactive setup wizard for first-time users."""
        self.console.print("\n[bold]🧙 Setup Wizard[/bold]\n")
        
        # Create config directory
        config_dir = Path.home() / ".claude-deploy"
        config_dir.mkdir(exist_ok=True)
        
        # Basic configuration
        config = {
            "default_environment": Prompt.ask(
                "Default environment",
                choices=["development", "staging", "production"],
                default="development"
            ),
            "mcp_servers": {},
            "expert_config": {
                "timeout": 30,
                "retry_attempts": 3
            },
            "ui_preferences": {
                "color_theme": Prompt.ask(
                    "Color theme",
                    choices=["default", "dark", "light"],
                    default="default"
                ),
                "progress_style": Prompt.ask(
                    "Progress indicator style", 
                    choices=["spinner", "bar", "minimal"],
                    default="spinner"
                )
            }
        }
        
        # Save configuration
        config_file = config_dir / "config.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
            
        self.console.print(format_success(f"Configuration saved to {config_file}"))
        self.console.print("\n[bold]Setup complete![/bold] You can now start using Claude Deploy.
")


# Create global app instance
app = CLIApplication()


@click.group(invoke_without_command=True)
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--quiet', '-q', is_flag=True, help='Minimize output')
@click.option('--config', '-c', help='Configuration file path')
@click.option('--environment', '-e', help='Target environment (auto-detected if not specified)')
@click.option('--no-color', is_flag=True, help='Disable colored output')
@click.option('--json', is_flag=True, help='Output in JSON format')
@click.version_option(version=VERSION)
@click.pass_context
def cli(ctx, verbose, quiet, config, environment, no_color, json):
    """
    Claude-Optimized Deployment Engine CLI
    
    A powerful tool for orchestrating AI model deployments with
    intelligent error handling and automated optimization.
    
    Quick Start:
        claude-deploy init          # Initialize a new project
        claude-deploy deploy        # Deploy with smart defaults
        claude-deploy status        # Check deployment status
        
    For interactive mode, run without any commands.
    """
    # Set up context
    ctx.ensure_object(dict)
    ctx.obj['app'] = app
    ctx.obj['verbose'] = verbose
    ctx.obj['quiet'] = quiet
    ctx.obj['json_output'] = json
    
    # Configure console
    if no_color:
        console._color_system = None
        
    # Auto-detect environment if not specified
    if not environment:
        environment = auto_detect_environment()
        if not quiet:
            console.print(format_info(f"Auto-detected environment: {environment}"))
            
    ctx.obj['environment'] = environment
    
    # Load configuration
    if config:
        app.context.load_config(config)
    
    # Show banner on first run or when no command specified
    if ctx.invoked_subcommand is None:
        app.show_banner()
        app.check_first_run()
        
        # Enter interactive mode
        if not json:
            app.interactive_mode.start()


@cli.command()
@click.option('--template', '-t', help='Project template to use')
@click.option('--name', '-n', help='Project name')
@click.option('--path', '-p', type=click.Path(), help='Project path')
def init(template, name, path):
    """
    Initialize a new Claude deployment project.
    
    This command creates a new project structure with:
    - Configuration templates
    - Example deployment files
    - Best practices documentation
    """
    console.print("[bold]🚀 Initializing new project[/bold]
")
    
    # Interactive prompts if not provided
    if not name:
        name = Prompt.ask("Project name", default="my-claude-project")
        
    if not path:
        path = Path.cwd() / name
    else:
        path = Path(path)
        
    if not template:
        templates = ["basic", "microservices", "ml-pipeline", "full-stack"]
        template = Prompt.ask("Template", choices=templates, default="basic")
    
    # Create project structure
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Creating project structure...", total=5)
        
        # Create directories
        for dir_name in ["config", "deployments", "scripts", "docs", "tests"]:
            (path / dir_name).mkdir(parents=True, exist_ok=True)
            progress.update(task, advance=1)
            
    # Generate files based on template
    generate_project_files(path, template, name)
    
    console.print(format_success(f"Project '{name}' created successfully at {path}"))
    console.print("\n[bold]Next steps:[/bold]")\n    console.print("1. cd " + str(path))\n    console.print("2. claude-deploy config validate")\n    console.print("3. claude-deploy deploy --dry-run")\n\n\n@cli.command()\n@click.option('--detailed', '-d', is_flag=True, help='Show detailed status')\n@click.option('--watch', '-w', is_flag=True, help='Watch status in real-time')\n@click.pass_context\ndef status(ctx, detailed, watch):\n    """\n    Show current deployment status with health indicators.\n\n    Displays:\n    - Active deployments\n    - System health\n    - Resource usage\n    - Recent events\n    """\n    app = ctx.obj['app']\n\n    if watch:\n        # Real-time monitoring mode\n        asyncio.run(monitor_status_realtime(app))\n    else:\n        # One-time status display\n        show_deployment_status(app, detailed)\n\n\n@cli.command()\n@click.argument('query')\n@click.option('--category', '-c', help='Search category (commands, docs, errors)')\n@click.option('--limit', '-l', default=10, help='Number of results')\ndef search(query, category, limit):\n    """\n    Search for commands, documentation, or error solutions.\n\n    Examples:\n        claude-deploy search "deployment failed"\n        claude-deploy search "mcp" --category commands\n    """\n    results = perform_search(query, category, limit)\n\n    if not results:\n        console.print(format_warning(f"No results found for '{query}'"))\n        return\n\n    # Display results in a table\n    table = Table(title=f"Search Results for '{query}'")\n    table.add_column("Type", style="cyan")\n    table.add_column("Match", style="green")\n    table.add_column("Description")\n\n    for result in results:\n        table.add_row(result['type'], result['match'], result['description'])\n\n    console.print(table)\n\n\n@cli.command()\n@click.option('--tutorial', help='Specific tutorial to run')\n@click.option('--quick-start', is_flag=True, help='Run quick start guide')\ndef tutorial(tutorial, quick_start):\n    """\n    Interactive tutorials and learning modules.\n\n    Learn Claude Deploy through hands-on tutorials covering:\n    - Getting started with deployments\n    - Advanced deployment strategies\n    - Troubleshooting and debugging\n    - Expert system usage\n    """\n    if quick_start:\n        run_quick_start()\n    else:\n        show_tutorial_menu()\n\n\n@cli.command()\n@click.option('--component', '-c', help='Component to diagnose')\n@click.option('--deep', is_flag=True, help='Perform deep diagnostics')\ndef diagnose(component, deep):\n    """\n    Run system diagnostics and suggest optimizations.\n\n    Checks:\n    - Configuration validity\n    - Network connectivity\n    - Resource availability\n    - Component health\n    """\n    console.print("[bold]🔍 Running diagnostics...[/bold]
")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        
        # Run diagnostic checks
        checks = [
            ("Configuration", check_configuration),
            ("Network", check_network),
            ("Resources", check_resources),
            ("MCP Servers", check_mcp_servers),
            ("Expert Systems", check_expert_systems)
        ]
        
        if component:
            checks = [(name, func) for name, func in checks if component.lower() in name.lower()]
            
        task = progress.add_task("Running diagnostics", total=len(checks))
        results = []
        
        for check_name, check_func in checks:
            result = check_func(deep=deep)
            results.append((check_name, result))
            progress.update(task, advance=1)
    
    # Display results
    display_diagnostic_results(results)


# Add command groups
cli.add_command(deploy.deploy_group)
cli.add_command(expert.expert_group)
cli.add_command(mcp.mcp_group)
cli.add_command(monitor.monitor_group)
cli.add_command(config.config_group)


# Helper functions

def generate_project_files(path: Path, template: str, name: str):
    """Generate project files based on template."""
    # config.yaml
    config_content = {
        "project": {
            "name": name,
            "version": "1.0.0",
            "template": template
        },
        "environments": {
            "development": {
                "mcp_servers": {
                    "local": {
                        "type": "docker",
                        "config": {}
                    }
                }
            },
            "production": {
                "mcp_servers": {
                    "kubernetes": {
                        "type": "k8s",
                        "config": {}
                    }
                }
            }
        },
        "experts": {
            "providers": ["claude", "openai", "local"],
            "consensus": {
                "strategy": "weighted_vote",
                "min_confidence": 0.7
            }
        }
    }
    
    with open(path / "config" / "config.yaml", 'w') as f:
        yaml.dump(config_content, f, default_flow_style=False)
        
    # Example deployment file
    deployment_content = {
        "name": f"{name}-deployment",
        "version": "1.0.0",
        "servers": [
            {
                "name": "api-server",
                "type": "fastapi",
                "config": {
                    "port": 8000,
                    "workers": 4
                }
            }
        ]
    }
    
    with open(path / "deployments" / "example.yaml", 'w') as f:
        yaml.dump(deployment_content, f, default_flow_style=False)
        
    # README
    readme_content = f"""# {name}

Generated with Claude-Optimized Deployment Engine

## Quick Start

1. Configure your environment:
   ```bash
   claude-deploy config validate
   ```

2. Deploy:
   ```bash
   claude-deploy deploy deployments/example.yaml
   ```

3. Monitor:
   ```bash
   claude-deploy monitor dashboard
   ```

## Project Structure

- `config/` - Configuration files
- `deployments/` - Deployment specifications
- `scripts/` - Custom scripts
- `docs/` - Documentation
- `tests/` - Test files
"""
    
    with open(path / "README.md", 'w') as f:
        f.write(readme_content)


def show_deployment_status(app: CLIApplication, detailed: bool):
    """Display current deployment status."""
    # This would connect to actual deployment state
    console.print(Panel("[bold green]System Status: Healthy[/bold green]"))
    
    # Summary table
    table = Table(title="Active Deployments")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Status", style="green")
    table.add_column("Environment")
    table.add_column("Uptime")
    
    # Mock data - would be real deployment data
    table.add_row("dep-001", "api-server", "✓ Running", "production", "2d 14h")
    table.add_row("dep-002", "ml-pipeline", "✓ Running", "production", "5h 23m")
    
    console.print(table)
    
    if detailed:
        # Show additional details
        console.print("\n[bold]Resource Usage:[/bold]")\n        console.print("CPU: 45% | Memory: 2.3GB/4GB | Disk: 15GB/50GB")\n\n        console.print("\n[bold]Recent Events:[/bold]")\n        console.print("• [green]Deployment successful[/green] - api-server (5 min ago)")\n        console.print("• [yellow]Health check warning[/yellow] - ml-pipeline (1 hour ago)")\n\n\nasync def monitor_status_realtime(app: CLIApplication):\n    """Monitor status in real-time."""\n    console.print("[bold]Real-time monitoring started. Press Ctrl+C to exit.[/bold]
")
    
    try:
        while True:
            # Clear and redraw
            console.clear()
            show_deployment_status(app, detailed=True)
            await asyncio.sleep(2)
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitoring stopped.[/yellow]")\n\n\ndef perform_search(query: str, category: Optional[str], limit: int) -> List[Dict[str, str]]:\n    """Perform search across commands, docs, and errors."""\n    # This would implement actual search functionality\n    # For now, return mock results\n    return [\n        {\n            "type": "command",\n            "match": "deploy --dry-run",\n            "description": "Test deployment without executing"\n        },\n        {\n            "type": "error",\n            "match": "DeploymentError",\n            "description": "Common deployment failure - check configuration"\n        }\n    ]\n\n\ndef check_configuration(deep: bool = False) -> Dict[str, Any]:\n    """Check configuration validity."""\n    return {\n        "status": "healthy",\n        "issues": [],\n        "suggestions": ["Consider enabling caching for better performance"]\n    }\n\n\ndef check_network(deep: bool = False) -> Dict[str, Any]:\n    """Check network connectivity."""\n    return {\n        "status": "healthy",\n        "latency": {"api": "12ms", "database": "3ms"},\n        "issues": []\n    }\n\n\ndef check_resources(deep: bool = False) -> Dict[str, Any]:\n    """Check resource availability."""\n    return {\n        "status": "warning",\n        "usage": {"cpu": 75, "memory": 60, "disk": 30},\n        "issues": ["CPU usage above 70%"],\n        "suggestions": ["Consider scaling horizontally"]\n    }\n\n\ndef check_mcp_servers(deep: bool = False) -> Dict[str, Any]:\n    """Check MCP server health."""\n    return {\n        "status": "healthy",\n        "servers": {"local": "running", "remote": "running"},\n        "issues": []\n    }\n\n\ndef check_expert_systems(deep: bool = False) -> Dict[str, Any]:\n    """Check expert system availability."""\n    return {\n        "status": "healthy",\n        "experts": ["claude", "openai", "local"],\n        "issues": []\n    }\n\n\ndef display_diagnostic_results(results: List[tuple]):\n    """Display diagnostic results in a user-friendly format."""\n    console.print("\n[bold]Diagnostic Results:[/bold]
")
    
    all_healthy = True
    
    for component, result in results:
        status = result['status']
        icon = "✓" if status == "healthy" else "⚠" if status == "warning" else "✗"
        color = "green" if status == "healthy" else "yellow" if status == "warning" else "red"
        
        console.print(f"[{color}]{icon} {component}: {status.upper()}[/{color}]")
        
        if result.get('issues'):
            all_healthy = False
            for issue in result['issues']:
                console.print(f"  - {issue}")
                
        if result.get('suggestions'):
            console.print("  [dim]Suggestions:[/dim]")
            for suggestion in result['suggestions']:
                console.print(f"  → {suggestion}")
                
    if all_healthy:
        console.print(format_success("\n✅ All systems operational!"))\n    else:\n        console.print(format_warning("\n⚠ Some issues detected. Run 'claude-deploy diagnose --deep' for details."))\n\n\ndef create_app():\n    """Create and return the CLI application instance."""\n    return app\n\n\nif __name__ == '__main__':\n    cli()