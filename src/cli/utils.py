"""
CLI utilities for enhanced user experience.

Provides:
- Formatting helpers
- Auto-detection logic
- Error recovery suggestions
- Context management
"""

import os
import socket
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from datetime import datetime
import yaml
import json
from rich.text import Text
from rich.panel import Panel
from rich.table import Table
import psutil

from src.core.exceptions import (
    BaseDeploymentError,
    ErrorCode,
    AIError,
    MCPError,
    ValidationError,
    NetworkError,
    ConfigurationError
)


class CLIContext:
    """Manages CLI context and state."""
    
    def __init__(self):
        self.config = {}
        self.environment = None
        self.verbose = False
        self.json_output = False
        self.start_time = datetime.now()
        self.command_history = []
        
    def load_config(self, config_path: str):
        """Load configuration from file."""
        path = Path(config_path)
        if not path.exists():
            raise ConfigurationError(f"Configuration file not found: {config_path}")
            
        with open(path, 'r') as f:
            if path.suffix in ['.yaml', '.yml']:
                self.config = yaml.safe_load(f)
            else:
                self.config = json.load(f)
                
    def add_command(self, command: str):
        """Add command to history."""
        self.command_history.append({
            'command': command,
            'timestamp': datetime.now(),
            'environment': self.environment
        })
        
    def get_elapsed_time(self) -> str:
        """Get elapsed time since start."""
        delta = datetime.now() - self.start_time
        return f"{delta.total_seconds():.1f}s"


# Formatting helpers

def format_error(message: str, error: Optional[BaseDeploymentError] = None) -> Union[Text, Panel]:
    """Format error message with styling."""
    if error and isinstance(error, BaseDeploymentError):
        # Build detailed error panel
        content = Text()
        content.append(f"❌ {message}\n\n", style="bold red")
        
        # Add error details
        content.append(f"Error Code: ", style="dim")
        content.append(f"{error.error_code.value}\n", style="yellow")
        
        if error.context:
            content.append("\nContext:\n", style="dim")
            for key, value in error.context.items():
                content.append(f"  {key}: ", style="cyan")
                content.append(f"{value}\n")
                
        # Add recovery suggestions
        suggestions = suggest_recovery_actions(error)
        if suggestions:
            content.append("\n💡 Suggestions:\n", style="bold yellow")
            for suggestion in suggestions:
                content.append(f"  • {suggestion}\n", style="white")
                
        return Panel(content, title="Error Details", border_style="red")
    else:
        return Text(f"❌ {message}", style="bold red")


def format_success(message: str) -> Text:
    """Format success message with styling."""
    return Text(f"✅ {message}", style="bold green")


def format_warning(message: str) -> Text:
    """Format warning message with styling."""
    return Text(f"⚠️  {message}", style="bold yellow")


def format_info(message: str) -> Text:
    """Format info message with styling."""
    return Text(f"ℹ️  {message}", style="bold blue")


def format_progress(current: int, total: int, description: str = "") -> Text:
    """Format progress indicator."""
    percentage = (current / total) * 100 if total > 0 else 0
    bar_length = 20
    filled = int(bar_length * current / total) if total > 0 else 0
    bar = "█" * filled + "░" * (bar_length - filled)
    
    text = Text()
    text.append(f"[{bar}] ", style="cyan")
    text.append(f"{percentage:.0f}% ", style="bold")
    if description:
        text.append(f"- {description}", style="dim")
        
    return text


# Auto-detection functions

def auto_detect_environment() -> str:
    """Auto-detect the current environment."""
    # Check environment variables
    env_var = os.getenv('ENVIRONMENT', os.getenv('ENV', ''))
    if env_var:
        return env_var.lower()
        
    # Check hostname patterns
    hostname = socket.gethostname().lower()
    if 'prod' in hostname:
        return 'production'
    elif 'staging' in hostname or 'stage' in hostname:
        return 'staging'
    elif 'dev' in hostname or 'local' in hostname:
        return 'development'
        
    # Check for CI/CD environments
    if os.getenv('CI') or os.getenv('CONTINUOUS_INTEGRATION'):
        return 'ci'
        
    # Check for containerization
    if os.path.exists('/.dockerenv'):
        return 'docker'
        
    if os.getenv('KUBERNETES_SERVICE_HOST'):
        return 'kubernetes'
        
    # Default to development
    return 'development'


def auto_detect_project_type(path: Path) -> str:
    """Auto-detect project type based on files."""
    # Check for common project files
    if (path / 'package.json').exists():
        return 'nodejs'
    elif (path / 'requirements.txt').exists() or (path / 'pyproject.toml').exists():
        return 'python'
    elif (path / 'Cargo.toml').exists():
        return 'rust'
    elif (path / 'go.mod').exists():
        return 'golang'
    elif (path / 'pom.xml').exists():
        return 'java'
    elif (path / 'docker-compose.yml').exists() or (path / 'docker-compose.yaml').exists():
        return 'docker-compose'
    else:
        return 'generic'


def auto_detect_deployment_strategy(project_type: str, environment: str) -> str:
    """Auto-detect best deployment strategy."""
    strategies = {
        'nodejs': {
            'development': 'local',
            'staging': 'docker',
            'production': 'kubernetes'
        },
        'python': {
            'development': 'venv',
            'staging': 'docker',
            'production': 'kubernetes'
        },
        'docker-compose': {
            'development': 'docker-compose',
            'staging': 'docker-swarm',
            'production': 'kubernetes'
        }
    }
    
    return strategies.get(project_type, {}).get(environment, 'docker')


# Error recovery suggestions

def suggest_recovery_actions(error: BaseDeploymentError) -> List[str]:
    """Suggest recovery actions based on error type."""
    suggestions = []
    
    # Common suggestions based on error code
    error_suggestions = {
        ErrorCode.NETWORK_CONNECTION: [
            "Check network connectivity",
            "Verify firewall rules",
            "Try using a VPN if accessing remote resources",
            "Run 'claude-deploy diagnose --component network'"
        ],
        ErrorCode.AUTH_INVALID_CREDENTIALS: [
            "Verify your credentials are correct",
            "Check if your API keys are expired",
            "Run 'claude-deploy config auth' to update credentials",
            "Ensure environment variables are set correctly"
        ],
        ErrorCode.CONFIG_MISSING: [
            "Run 'claude-deploy init' to create a configuration",
            "Check if config file exists in expected location",
            "Use --config flag to specify config file path",
            "Set required environment variables"
        ],
        ErrorCode.INFRASTRUCTURE_DOCKER: [
            "Ensure Docker daemon is running",
            "Check Docker permissions (may need sudo)",
            "Verify Docker installation with 'docker version'",
            "Check available disk space"
        ],
        ErrorCode.AI_RATE_LIMIT: [
            "Wait before retrying (check retry-after header)",
            "Consider implementing request batching",
            "Upgrade your API plan for higher limits",
            "Use caching to reduce API calls"
        ],
        ErrorCode.MCP_SERVER_NOT_FOUND: [
            "List available servers with 'claude-deploy mcp list'",
            "Check server name spelling",
            "Ensure MCP server is running",
            "Run 'claude-deploy mcp install <server>'"
        ]
    }
    
    # Get suggestions for specific error code
    if error.error_code in error_suggestions:
        suggestions.extend(error_suggestions[error.error_code])
        
    # Add context-specific suggestions
    if isinstance(error, NetworkError) and error.context.get('url'):
        url = error.context['url']
        if 'localhost' in url or '127.0.0.1' in url:
            suggestions.append("Ensure local service is running")
            
    if isinstance(error, ValidationError):
        field = error.context.get('field')
        if field:
            suggestions.append(f"Check documentation for valid values for '{field}'")
            
    # Add general suggestions
    suggestions.extend([
        "Check logs with 'claude-deploy logs --tail 50'",
        "Run in verbose mode with -v flag for more details"
    ])
    
    return suggestions[:5]  # Limit to 5 most relevant suggestions


# Smart defaults

def get_smart_defaults(command: str, context: CLIContext) -> Dict[str, Any]:
    """Get smart default values based on command and context."""
    defaults = {
        'deploy': {
            'strategy': auto_detect_deployment_strategy(
                auto_detect_project_type(Path.cwd()),
                context.environment or auto_detect_environment()
            ),
            'parallel': True,
            'health_check': True,
            'rollback_on_failure': True
        },
        'expert': {
            'providers': ['claude', 'openai'] if context.environment == 'production' else ['claude'],
            'consensus_strategy': 'weighted_vote',
            'timeout': 30,
            'retry_attempts': 3
        },
        'mcp': {
            'startup_timeout': 60,
            'health_check_interval': 30,
            'max_connections': 10
        },
        'monitor': {
            'interval': 5,
            'metrics': ['cpu', 'memory', 'network'],
            'alert_thresholds': {
                'cpu': 80,
                'memory': 90,
                'disk': 85
            }
        }
    }
    
    return defaults.get(command, {})


# Progress tracking

class ProgressTracker:
    """Track and display progress for long-running operations."""
    
    def __init__(self, total_steps: int, description: str = "Processing"):
        self.total_steps = total_steps
        self.current_step = 0
        self.description = description
        self.start_time = datetime.now()
        self.step_times = []
        
    def update(self, step_description: str = ""):
        """Update progress."""
        self.current_step += 1
        self.step_times.append(datetime.now())
        
        # Calculate ETA
        if self.current_step > 1:
            avg_time = self._calculate_average_step_time()
            remaining_steps = self.total_steps - self.current_step
            eta_seconds = avg_time * remaining_steps
            eta_str = self._format_time(eta_seconds)
        else:
            eta_str = "calculating..."
            
        return {
            'current': self.current_step,
            'total': self.total_steps,
            'percentage': (self.current_step / self.total_steps) * 100,
            'description': step_description or self.description,
            'eta': eta_str
        }
        
    def _calculate_average_step_time(self) -> float:
        """Calculate average time per step."""
        if len(self.step_times) < 2:
            return 0
            
        total_time = (self.step_times[-1] - self.start_time).total_seconds()
        return total_time / self.current_step
        
    def _format_time(self, seconds: float) -> str:
        """Format time in human-readable format."""
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            return f"{seconds/60:.0f}m {seconds%60:.0f}s"
        else:
            return f"{seconds/3600:.0f}h {(seconds%3600)/60:.0f}m"


# System resource helpers

def check_system_resources() -> Dict[str, Any]:
    """Check available system resources."""
    return {
        'cpu': {
            'count': psutil.cpu_count(),
            'usage_percent': psutil.cpu_percent(interval=1),
            'load_average': os.getloadavg() if hasattr(os, 'getloadavg') else None
        },
        'memory': {
            'total': psutil.virtual_memory().total,
            'available': psutil.virtual_memory().available,
            'percent': psutil.virtual_memory().percent
        },
        'disk': {
            'total': psutil.disk_usage('/').total,
            'free': psutil.disk_usage('/').free,
            'percent': psutil.disk_usage('/').percent
        },
        'network': {
            'connections': len(psutil.net_connections()),
            'interfaces': list(psutil.net_if_addrs().keys())
        }
    }


def format_resource_usage(resources: Dict[str, Any]) -> Table:
    """Format resource usage as a table."""
    table = Table(title="System Resources")
    table.add_column("Resource", style="cyan")
    table.add_column("Usage", style="yellow")
    table.add_column("Status", style="green")
    
    # CPU
    cpu_usage = resources['cpu']['usage_percent']
    cpu_status = "✓" if cpu_usage < 80 else "⚠" if cpu_usage < 90 else "✗"
    table.add_row("CPU", f"{cpu_usage:.1f}%", cpu_status)
    
    # Memory
    mem_percent = resources['memory']['percent']
    mem_status = "✓" if mem_percent < 80 else "⚠" if mem_percent < 90 else "✗"
    table.add_row("Memory", f"{mem_percent:.1f}%", mem_status)
    
    # Disk
    disk_percent = resources['disk']['percent']
    disk_status = "✓" if disk_percent < 80 else "⚠" if disk_percent < 90 else "✗"
    table.add_row("Disk", f"{disk_percent:.1f}%", disk_status)
    
    return table


# Batch operation helpers

def create_batch_operation_plan(operations: List[Dict[str, Any]], 
                               max_parallel: int = 5) -> List[List[Dict[str, Any]]]:
    """Create execution plan for batch operations."""
    # Sort by priority and dependencies
    sorted_ops = sorted(operations, key=lambda x: (x.get('priority', 0), x.get('name', '')))
    
    # Group into batches considering dependencies
    batches = []
    current_batch = []
    
    for op in sorted_ops:
        if len(current_batch) < max_parallel:
            # Check dependencies
            deps_satisfied = all(
                any(completed.get('name') == dep for batch in batches for completed in batch)
                for dep in op.get('dependencies', [])
            )
            
            if deps_satisfied:
                current_batch.append(op)
            else:
                if current_batch:
                    batches.append(current_batch)
                    current_batch = [op]
        else:
            batches.append(current_batch)
            current_batch = [op]
            
    if current_batch:
        batches.append(current_batch)
        
    return batches


# Export helpers

def export_results(data: Dict[str, Any], format: str, output_path: Optional[str] = None) -> str:
    """Export results in various formats."""
    if format == 'json':
        content = json.dumps(data, indent=2, default=str)
    elif format == 'yaml':
        content = yaml.dump(data, default_flow_style=False, sort_keys=False)
    elif format == 'csv':
        # Simple CSV for tabular data
        import csv
        import io
        output = io.StringIO()
        if isinstance(data, list) and data and isinstance(data[0], dict):
            writer = csv.DictWriter(output, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
        content = output.getvalue()
    else:
        content = str(data)
        
    if output_path:
        Path(output_path).write_text(content)
        return f"Results exported to {output_path}"
    else:
        return content