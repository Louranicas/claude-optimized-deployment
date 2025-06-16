"""
Secure Command Execution Module for CODE Project.

Provides a centralized, secure interface for executing system commands with:
- Command whitelisting
- Input sanitization
- Injection pattern detection
- Resource limits
- Sandboxing capabilities
- Comprehensive logging and auditing
"""

import os
import asyncio
import subprocess
import shlex
import re
import resource
import tempfile
import json
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set, Union
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
import logging

from src.core.exceptions import (
    CommandExecutionError,
    ValidationError,
    SecurityError,
    TimeoutError as CommandTimeoutError
)

logger = logging.getLogger(__name__)


class CommandCategory(Enum):
    """Categories of allowed commands."""
    VERSION_CONTROL = "version_control"
    BUILD_TOOLS = "build_tools"
    CONTAINER_OPS = "container_ops"
    PYTHON_TOOLS = "python_tools"
    NODE_TOOLS = "node_tools"
    SYSTEM_INFO = "system_info"
    FILE_OPS = "file_ops"
    NETWORK_OPS = "network_ops"
    INFRASTRUCTURE = "infrastructure"


# Command whitelist with categories and allowed arguments
COMMAND_WHITELIST: Dict[str, Dict[str, Any]] = {
    # Version control
    "git": {
        "category": CommandCategory.VERSION_CONTROL,
        "allowed_args": ["status", "log", "diff", "branch", "checkout", "pull", "fetch", "remote", "show", "tag"],
        "dangerous_args": ["push", "reset", "rebase", "merge", "clean"],
        "max_args": 10
    },
    "gh": {
        "category": CommandCategory.VERSION_CONTROL,
        "allowed_args": ["pr", "issue", "repo", "auth", "api"],
        "dangerous_args": ["delete", "remove"],
        "max_args": 15
    },
    
    # Python tools
    "python": {
        "category": CommandCategory.PYTHON_TOOLS,
        "allowed_args": ["-m", "-c", "--version"],
        "dangerous_args": ["-e"],  # No eval execution
        "max_args": 20
    },
    "python3": {
        "category": CommandCategory.PYTHON_TOOLS,
        "allowed_args": ["-m", "-c", "--version"],
        "dangerous_args": ["-e"],
        "max_args": 20
    },
    "pip": {
        "category": CommandCategory.PYTHON_TOOLS,
        "allowed_args": ["install", "list", "show", "freeze", "check"],
        "dangerous_args": ["uninstall"],
        "max_args": 10
    },
    "pip3": {
        "category": CommandCategory.PYTHON_TOOLS,
        "allowed_args": ["install", "list", "show", "freeze", "check"],
        "dangerous_args": ["uninstall"],
        "max_args": 10
    },
    "pytest": {
        "category": CommandCategory.PYTHON_TOOLS,
        "allowed_args": ["-v", "-s", "-k", "--cov", "--tb", "-x"],
        "dangerous_args": [],
        "max_args": 20
    },
    
    # Build tools
    "make": {
        "category": CommandCategory.BUILD_TOOLS,
        "allowed_args": ["-j", "-f", "-C", "-n", "--dry-run"],
        "dangerous_args": [],
        "max_args": 10
    },
    "cargo": {
        "category": CommandCategory.BUILD_TOOLS,
        "allowed_args": ["build", "test", "check", "clippy", "fmt", "doc"],
        "dangerous_args": ["publish"],
        "max_args": 15
    },
    
    # Container tools
    "docker": {
        "category": CommandCategory.CONTAINER_OPS,
        "allowed_args": ["ps", "images", "logs", "build", "run", "exec", "stop", "start", "inspect"],
        "dangerous_args": ["rm", "rmi", "system prune"],
        "max_args": 20
    },
    "docker-compose": {
        "category": CommandCategory.CONTAINER_OPS,
        "allowed_args": ["up", "down", "ps", "logs", "build", "exec", "stop", "start"],
        "dangerous_args": ["rm"],
        "max_args": 15
    },
    "kubectl": {
        "category": CommandCategory.CONTAINER_OPS,
        "allowed_args": ["get", "describe", "logs", "apply", "create", "port-forward", "exec"],
        "dangerous_args": ["delete"],
        "max_args": 20
    },
    
    # System info (read-only)
    "ls": {
        "category": CommandCategory.SYSTEM_INFO,
        "allowed_args": ["-la", "-l", "-a", "-h", "--color"],
        "dangerous_args": [],
        "max_args": 5
    },
    "pwd": {
        "category": CommandCategory.SYSTEM_INFO,
        "allowed_args": [],
        "dangerous_args": [],
        "max_args": 0
    },
    "echo": {
        "category": CommandCategory.SYSTEM_INFO,
        "allowed_args": [],
        "dangerous_args": [],
        "max_args": 50  # Echo can have many args
    },
    "cat": {
        "category": CommandCategory.FILE_OPS,
        "allowed_args": ["-n"],
        "dangerous_args": [],
        "max_args": 2
    },
    "grep": {
        "category": CommandCategory.FILE_OPS,
        "allowed_args": ["-r", "-i", "-n", "-v", "-E", "-F"],
        "dangerous_args": [],
        "max_args": 10
    },
    
    # Infrastructure tools
    "terraform": {
        "category": CommandCategory.INFRASTRUCTURE,
        "allowed_args": ["init", "plan", "apply", "show", "validate", "fmt"],
        "dangerous_args": ["destroy"],
        "max_args": 15
    },
    "ansible": {
        "category": CommandCategory.INFRASTRUCTURE,
        "allowed_args": ["--version", "-i", "--check", "--diff"],
        "dangerous_args": [],
        "max_args": 20
    },
    "helm": {
        "category": CommandCategory.INFRASTRUCTURE,
        "allowed_args": ["list", "status", "get", "install", "upgrade", "rollback"],
        "dangerous_args": ["delete", "uninstall"],
        "max_args": 15
    }
}


# Dangerous command patterns to block
INJECTION_PATTERNS = [
    # Command chaining and substitution
    re.compile(r'[;&|]{2,}'),  # Multiple command separators
    re.compile(r'(?<!\\)[;&|](?!&)'),  # Unescaped command separators
    re.compile(r'\$\([^)]+\)'),  # Command substitution $()
    re.compile(r'`[^`]+`'),  # Backtick substitution
    re.compile(r'\$\{[^}]+\}'),  # Variable expansion
    
    # Redirection abuse
    re.compile(r'>\s*/dev/(tcp|udp)'),  # Network redirection
    re.compile(r'<\s*/dev/(tcp|udp)'),  # Network input
    re.compile(r'>\s*/proc/'),  # Proc filesystem writes
    re.compile(r'>\s*/sys/'),  # Sys filesystem writes
    
    # Path traversal
    re.compile(r'\.\.(/|\\){2,}'),  # Multiple parent directory references
    re.compile(r'/\.\.'),  # Hidden parent directory
    
    # Shell features
    re.compile(r'function\s+\w+'),  # Function definitions
    re.compile(r'\w+\s*\(\s*\)\s*\{'),  # Function syntax
    re.compile(r'(eval|exec)\s+'),  # Eval/exec commands
    
    # Dangerous operations
    re.compile(r'rm\s+(-rf?|-fr?)\s+/'),  # Recursive root deletion
    re.compile(r':(){ :|:& };:'),  # Fork bomb
    re.compile(r'>\s*/dev/null\s+2>&1'),  # Hiding errors (could be suspicious)
    
    # Script execution
    re.compile(r'(sh|bash|zsh|csh|ksh|fish)\s+-c'),  # Shell execution
    re.compile(r'(python|perl|ruby|php)\s+-e'),  # Script execution
    
    # System modification
    re.compile(r'chmod\s+(-R\s+)?777'),  # Dangerous permissions
    re.compile(r'/etc/(passwd|shadow|sudoers)'),  # System files
    
    # Environment manipulation
    re.compile(r'LD_PRELOAD='),
    re.compile(r'LD_LIBRARY_PATH='),
    re.compile(r'PATH='),
    
    # Network operations
    re.compile(r'nc\s+-l'),  # Netcat listener
    re.compile(r'curl.*\|.*sh'),  # Piping to shell
    re.compile(r'wget.*\|.*sh'),  # Piping to shell
]


# Resource limits for subprocess execution
RESOURCE_LIMITS = {
    resource.RLIMIT_CPU: (60, 120),  # CPU time in seconds
    resource.RLIMIT_AS: (1 * 1024**3, 2 * 1024**3),  # Virtual memory (1-2GB)
    resource.RLIMIT_NPROC: (50, 100),  # Number of processes
    resource.RLIMIT_NOFILE: (256, 512),  # Number of open files
    resource.RLIMIT_CORE: (0, 0),  # No core dumps
}


@dataclass
class CommandExecutionResult:
    """Result from command execution."""
    command: str
    exit_code: int
    stdout: str
    stderr: str
    execution_time: float
    success: bool
    truncated: bool = False
    working_directory: Optional[str] = None
    environment_vars: Dict[str, str] = field(default_factory=dict)
    resource_usage: Optional[Dict[str, Any]] = None


@dataclass
class CommandAuditEntry:
    """Audit log entry for command execution."""
    timestamp: datetime
    command: str
    user: Optional[str]
    success: bool
    exit_code: int
    execution_time: float
    error: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)
    command_hash: Optional[str] = None


class SecureCommandExecutor:
    """
    Secure command execution with comprehensive protection mechanisms.
    
    Features:
    - Command whitelisting with argument validation
    - Input sanitization and injection prevention
    - Resource limiting and sandboxing
    - Comprehensive audit logging
    - Async and sync execution support
    """
    
    def __init__(
        self,
        working_directory: Optional[Path] = None,
        max_output_size: int = 10 * 1024 * 1024,  # 10MB
        enable_sandbox: bool = True,
        audit_log_path: Optional[Path] = None
    ):
        """
        Initialize SecureCommandExecutor.
        
        Args:
            working_directory: Default working directory for commands
            max_output_size: Maximum allowed output size in bytes
            enable_sandbox: Enable sandboxing features
            audit_log_path: Path to audit log file
        """
        self.working_directory = working_directory or Path.cwd()
        self.max_output_size = max_output_size
        self.enable_sandbox = enable_sandbox
        self.audit_log_path = audit_log_path or Path("/var/log/secure_commands.log")
        self._audit_entries: List[CommandAuditEntry] = []
        
        # Ensure audit directory exists
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
    
    def validate_command(self, command: str) -> Tuple[bool, Optional[str], List[str]]:
        """
        Validate command for security issues.
        
        Args:
            command: Command string to validate
            
        Returns:
            Tuple of (is_valid, error_message, parsed_args)
        """
        # Check command length
        if len(command) > 4096:
            return False, "Command exceeds maximum length", []
        
        # Check for empty command
        if not command or not command.strip():
            return False, "Empty command", []
        
        # Check injection patterns
        for pattern in INJECTION_PATTERNS:
            if pattern.search(command):
                return False, f"Command contains dangerous pattern: {pattern.pattern}", []
        
        # Parse command safely
        try:
            parts = shlex.split(command)
        except ValueError as e:
            return False, f"Invalid command syntax: {str(e)}", []
        
        if not parts:
            return False, "No command specified", []
        
        base_command = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        
        # Extract base command name if it's a path
        base_name = os.path.basename(base_command)
        
        # Check whitelist
        if base_name not in COMMAND_WHITELIST and base_command not in COMMAND_WHITELIST:
            return False, f"Command '{base_command}' is not whitelisted", []
        
        # Get command config
        cmd_config = COMMAND_WHITELIST.get(base_name) or COMMAND_WHITELIST.get(base_command)
        
        # Check argument count
        if len(args) > cmd_config.get("max_args", 50):
            return False, f"Too many arguments ({len(args)} > {cmd_config['max_args']})", []
        
        # Check for dangerous arguments
        dangerous_args = cmd_config.get("dangerous_args", [])
        for arg in args:
            if any(dangerous in arg for dangerous in dangerous_args):
                return False, f"Dangerous argument detected: {arg}", []
        
        # Additional validation for specific commands
        if base_name in ["rm", "rmdir"]:
            # Never allow these even if someone adds them to whitelist
            return False, "Destructive commands are not allowed", []
        
        return True, None, parts
    
    def _apply_resource_limits(self):
        """Apply resource limits to subprocess."""
        if not self.enable_sandbox:
            return
        
        for resource_type, (soft, hard) in RESOURCE_LIMITS.items():
            try:
                resource.setrlimit(resource_type, (soft, hard))
            except Exception as e:
                logger.warning(f"Failed to set resource limit {resource_type}: {e}")
    
    def _create_sandbox_env(self, custom_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Create sandboxed environment variables."""
        # Start with minimal safe environment
        safe_env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LANG": "en_US.UTF-8",
            "LC_ALL": "en_US.UTF-8",
            "USER": os.environ.get("USER", "nobody"),
            "HOME": str(Path.home()),
            "TMPDIR": tempfile.gettempdir()
        }
        
        # Add specific allowed environment variables
        allowed_env_vars = {
            "PYTHONPATH", "VIRTUAL_ENV", "NODE_PATH", "CARGO_HOME",
            "DOCKER_HOST", "KUBERNETES_MASTER", "TERM", "COLUMNS", "LINES"
        }
        
        for var in allowed_env_vars:
            if var in os.environ:
                safe_env[var] = os.environ[var]
        
        # Add custom environment variables (after validation)
        if custom_env:
            for key, value in custom_env.items():
                # Validate environment variable names
                if re.match(r'^[A-Z_][A-Z0-9_]*$', key) and len(key) < 64:
                    safe_env[key] = str(value)[:1024]  # Limit value length
        
        return safe_env
    
    async def execute_async(
        self,
        command: str,
        working_directory: Optional[Union[str, Path]] = None,
        environment: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = 60.0,
        user: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> CommandExecutionResult:
        """
        Execute command asynchronously with security controls.
        
        Args:
            command: Command to execute
            working_directory: Working directory for execution
            environment: Additional environment variables
            timeout: Execution timeout in seconds
            user: Username for audit logging
            context: Additional context for audit logging
            
        Returns:
            CommandExecutionResult
        """
        start_time = datetime.utcnow()
        audit_entry = CommandAuditEntry(
            timestamp=start_time,
            command=command,
            user=user,
            success=False,
            exit_code=-1,
            execution_time=0.0,
            context=context or {},
            command_hash=hashlib.sha256(command.encode()).hexdigest()
        )
        
        try:
            # Validate command
            is_valid, error_msg, parts = self.validate_command(command)
            if not is_valid:
                audit_entry.error = error_msg
                raise ValidationError(error_msg, field="command", value=command)
            
            # Validate and resolve working directory
            work_dir = Path(working_directory) if working_directory else self.working_directory
            work_dir = work_dir.resolve()
            
            if not work_dir.exists():
                raise ValidationError(
                    f"Working directory does not exist: {work_dir}",
                    field="working_directory",
                    value=str(working_directory)
                )
            
            if not work_dir.is_dir():
                raise ValidationError(
                    f"Working directory is not a directory: {work_dir}",
                    field="working_directory",
                    value=str(working_directory)
                )
            
            # Create sandboxed environment
            env = self._create_sandbox_env(environment)
            
            # Log execution
            logger.info(f"Executing command: {parts[0]} (user: {user or 'unknown'})")
            
            # Create subprocess with security controls
            process = await asyncio.create_subprocess_exec(
                *parts,  # Unpack safely parsed command parts
                cwd=work_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                stdin=asyncio.subprocess.DEVNULL,  # No stdin access
                preexec_fn=self._apply_resource_limits if self.enable_sandbox else None
            )
            
            # Execute with timeout and output limits
            stdout_chunks = []
            stderr_chunks = []
            stdout_size = 0
            stderr_size = 0
            truncated = False
            
            async def read_stream_with_limit(stream, chunks, size_tracker, name):
                nonlocal truncated
                while True:
                    chunk = await stream.read(8192)
                    if not chunk:
                        break
                    
                    if size_tracker[0] + len(chunk) > self.max_output_size:
                        truncated = True
                        chunk = chunk[:self.max_output_size - size_tracker[0]]
                        chunks.append(chunk)
                        size_tracker[0] += len(chunk)
                        logger.warning(f"{name} output truncated at {self.max_output_size} bytes")
                        break
                    
                    chunks.append(chunk)
                    size_tracker[0] += len(chunk)
            
            # Read both streams concurrently
            stdout_size_tracker = [stdout_size]
            stderr_size_tracker = [stderr_size]
            
            try:
                await asyncio.wait_for(
                    asyncio.gather(
                        read_stream_with_limit(process.stdout, stdout_chunks, stdout_size_tracker, "stdout"),
                        read_stream_with_limit(process.stderr, stderr_chunks, stderr_size_tracker, "stderr"),
                        process.wait()
                    ),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                # Kill process on timeout
                try:
                    process.terminate()
                    await asyncio.sleep(0.5)
                    if process.returncode is None:
                        process.kill()
                    await process.wait()
                except:
                    pass
                
                raise CommandTimeoutError(
                    f"Command timed out after {timeout} seconds",
                    timeout_seconds=timeout,
                    operation="execute_command",
                    context={"command": command, "working_directory": str(work_dir)}
                )
            
            # Decode output
            stdout = b''.join(stdout_chunks).decode('utf-8', errors='replace')
            stderr = b''.join(stderr_chunks).decode('utf-8', errors='replace')
            
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            
            # Create result
            result = CommandExecutionResult(
                command=command,
                exit_code=process.returncode,
                stdout=stdout,
                stderr=stderr,
                execution_time=execution_time,
                success=process.returncode == 0,
                truncated=truncated,
                working_directory=str(work_dir),
                environment_vars=environment or {}
            )
            
            # Update audit entry
            audit_entry.success = result.success
            audit_entry.exit_code = result.exit_code
            audit_entry.execution_time = execution_time
            
            return result
            
        except Exception as e:
            audit_entry.error = str(e)
            audit_entry.execution_time = (datetime.utcnow() - start_time).total_seconds()
            raise
        finally:
            # Always log audit entry
            self._log_audit_entry(audit_entry)
    
    def execute_sync(
        self,
        command: str,
        working_directory: Optional[Union[str, Path]] = None,
        environment: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = 60.0,
        user: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> CommandExecutionResult:
        """
        Execute command synchronously with security controls.
        
        Args:
            command: Command to execute
            working_directory: Working directory for execution
            environment: Additional environment variables
            timeout: Execution timeout in seconds
            user: Username for audit logging
            context: Additional context for audit logging
            
        Returns:
            CommandExecutionResult
        """
        start_time = datetime.utcnow()
        audit_entry = CommandAuditEntry(
            timestamp=start_time,
            command=command,
            user=user,
            success=False,
            exit_code=-1,
            execution_time=0.0,
            context=context or {},
            command_hash=hashlib.sha256(command.encode()).hexdigest()
        )
        
        try:
            # Validate command
            is_valid, error_msg, parts = self.validate_command(command)
            if not is_valid:
                audit_entry.error = error_msg
                raise ValidationError(error_msg, field="command", value=command)
            
            # Validate and resolve working directory
            work_dir = Path(working_directory) if working_directory else self.working_directory
            work_dir = work_dir.resolve()
            
            if not work_dir.exists() or not work_dir.is_dir():
                raise ValidationError(
                    f"Invalid working directory: {work_dir}",
                    field="working_directory",
                    value=str(working_directory)
                )
            
            # Create sandboxed environment
            env = self._create_sandbox_env(environment)
            
            # Log execution
            logger.info(f"Executing command (sync): {parts[0]} (user: {user or 'unknown'})")
            
            # Execute with subprocess.run
            result = subprocess.run(
                parts,
                cwd=work_dir,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                preexec_fn=self._apply_resource_limits if self.enable_sandbox else None
            )
            
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            
            # Check output size and truncate if needed
            truncated = False
            stdout = result.stdout
            stderr = result.stderr
            
            if len(stdout.encode()) > self.max_output_size:
                stdout = stdout[:self.max_output_size]
                truncated = True
            
            if len(stderr.encode()) > self.max_output_size:
                stderr = stderr[:self.max_output_size]
                truncated = True
            
            # Create result
            cmd_result = CommandExecutionResult(
                command=command,
                exit_code=result.returncode,
                stdout=stdout,
                stderr=stderr,
                execution_time=execution_time,
                success=result.returncode == 0,
                truncated=truncated,
                working_directory=str(work_dir),
                environment_vars=environment or {}
            )
            
            # Update audit entry
            audit_entry.success = cmd_result.success
            audit_entry.exit_code = cmd_result.exit_code
            audit_entry.execution_time = execution_time
            
            return cmd_result
            
        except subprocess.TimeoutExpired:
            raise CommandTimeoutError(
                f"Command timed out after {timeout} seconds",
                timeout_seconds=timeout,
                operation="execute_command",
                context={"command": command, "working_directory": str(work_dir)}
            )
        except Exception as e:
            audit_entry.error = str(e)
            audit_entry.execution_time = (datetime.utcnow() - start_time).total_seconds()
            raise
        finally:
            # Always log audit entry
            self._log_audit_entry(audit_entry)
    
    def _log_audit_entry(self, entry: CommandAuditEntry):
        """Log audit entry to file and memory."""
        self._audit_entries.append(entry)
        
        # Keep only last 1000 entries in memory
        if len(self._audit_entries) > 1000:
            self._audit_entries = self._audit_entries[-1000:]
        
        # Write to audit log file
        try:
            with open(self.audit_log_path, 'a') as f:
                audit_dict = {
                    "timestamp": entry.timestamp.isoformat(),
                    "command": entry.command,
                    "command_hash": entry.command_hash,
                    "user": entry.user,
                    "success": entry.success,
                    "exit_code": entry.exit_code,
                    "execution_time": entry.execution_time,
                    "error": entry.error,
                    "context": entry.context
                }
                f.write(json.dumps(audit_dict) + '\n')
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")
    
    def get_audit_entries(
        self,
        user: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        success_only: bool = False
    ) -> List[CommandAuditEntry]:
        """
        Get audit entries based on filters.
        
        Args:
            user: Filter by user
            start_time: Filter by start time
            end_time: Filter by end time
            success_only: Only return successful executions
            
        Returns:
            List of matching audit entries
        """
        entries = self._audit_entries.copy()
        
        if user:
            entries = [e for e in entries if e.user == user]
        
        if start_time:
            entries = [e for e in entries if e.timestamp >= start_time]
        
        if end_time:
            entries = [e for e in entries if e.timestamp <= end_time]
        
        if success_only:
            entries = [e for e in entries if e.success]
        
        return entries
    
    def add_to_whitelist(
        self,
        command: str,
        category: CommandCategory,
        allowed_args: List[str] = None,
        dangerous_args: List[str] = None,
        max_args: int = 10
    ):
        """
        Add a command to the whitelist (use with caution).
        
        Args:
            command: Command name to add
            category: Command category
            allowed_args: List of allowed arguments
            dangerous_args: List of dangerous arguments to block
            max_args: Maximum number of arguments
        """
        if command in COMMAND_WHITELIST:
            logger.warning(f"Command {command} already in whitelist")
            return
        
        COMMAND_WHITELIST[command] = {
            "category": category,
            "allowed_args": allowed_args or [],
            "dangerous_args": dangerous_args or [],
            "max_args": max_args
        }
        
        logger.info(f"Added {command} to whitelist in category {category.value}")
    
    def remove_from_whitelist(self, command: str):
        """
        Remove a command from the whitelist.
        
        Args:
            command: Command name to remove
        """
        if command in COMMAND_WHITELIST:
            del COMMAND_WHITELIST[command]
            logger.info(f"Removed {command} from whitelist")
        else:
            logger.warning(f"Command {command} not in whitelist")


# Singleton instance for global usage
_executor_instance: Optional[SecureCommandExecutor] = None


def get_secure_executor() -> SecureCommandExecutor:
    """Get or create the global secure command executor instance."""
    global _executor_instance
    if _executor_instance is None:
        _executor_instance = SecureCommandExecutor()
    return _executor_instance


# Convenience functions
async def execute_command_async(
    command: str,
    working_directory: Optional[Union[str, Path]] = None,
    environment: Optional[Dict[str, str]] = None,
    timeout: Optional[float] = 60.0,
    user: Optional[str] = None
) -> CommandExecutionResult:
    """
    Execute a command asynchronously using the global secure executor.
    
    Args:
        command: Command to execute
        working_directory: Working directory for execution
        environment: Additional environment variables
        timeout: Execution timeout in seconds
        user: Username for audit logging
        
    Returns:
        CommandExecutionResult
    """
    executor = get_secure_executor()
    return await executor.execute_async(
        command=command,
        working_directory=working_directory,
        environment=environment,
        timeout=timeout,
        user=user
    )


def execute_command_sync(
    command: str,
    working_directory: Optional[Union[str, Path]] = None,
    environment: Optional[Dict[str, str]] = None,
    timeout: Optional[float] = 60.0,
    user: Optional[str] = None
) -> CommandExecutionResult:
    """
    Execute a command synchronously using the global secure executor.
    
    Args:
        command: Command to execute
        working_directory: Working directory for execution
        environment: Additional environment variables
        timeout: Execution timeout in seconds
        user: Username for audit logging
        
    Returns:
        CommandExecutionResult
    """
    executor = get_secure_executor()
    return executor.execute_sync(
        command=command,
        working_directory=working_directory,
        environment=environment,
        timeout=timeout,
        user=user
    )