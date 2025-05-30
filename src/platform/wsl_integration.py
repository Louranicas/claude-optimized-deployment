"""
WSL Integration Module for CODE
Handles Windows Subsystem for Linux detection and optimization
"""

import os
import platform
import subprocess
import json
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
import logging
from functools import lru_cache

# Configure logging for Claude context
logger = logging.getLogger(__name__)


class WSLEnvironment:
    """
    CLAUDE-CONTEXT: Manages WSL environment detection and configuration
    PURPOSE: Seamless integration between Windows and WSL for CODE
    FEATURES:
    - Automatic WSL detection
    - Path translation between Windows and WSL
    - Performance optimizations
    - Cross-platform command execution
    """
    
    def __init__(self):
        self._is_wsl = None
        self._wsl_version = None
        self._windows_home = None
        self._distro_name = None
        
    @property
    def is_wsl(self) -> bool:
        """Check if running inside WSL"""
        if self._is_wsl is None:
            self._is_wsl = self._detect_wsl()
        return self._is_wsl
    
    @property
    def wsl_version(self) -> Optional[str]:
        """Get WSL version (1 or 2)"""
        if self._wsl_version is None and self.is_wsl:
            self._wsl_version = self._detect_wsl_version()
        return self._wsl_version
    
    @property
    def windows_home(self) -> Optional[Path]:
        """Get Windows home directory path from WSL"""
        if self._windows_home is None and self.is_wsl:
            self._windows_home = self._find_windows_home()
        return self._windows_home
    
    @property
    def distro_name(self) -> Optional[str]:
        """Get WSL distribution name"""
        if self._distro_name is None and self.is_wsl:
            self._distro_name = self._get_distro_name()
        return self._distro_name
    
    def _detect_wsl(self) -> bool:
        """Detect if running in WSL environment"""
        # Check multiple indicators for WSL
        indicators = [
            # WSL1 and WSL2
            'microsoft' in platform.uname().release.lower(),
            'wsl' in platform.uname().release.lower(),
            # Check for WSL-specific files
            Path('/proc/sys/fs/binfmt_misc/WSLInterop').exists(),
            # Check environment variable
            os.environ.get('WSL_DISTRO_NAME') is not None,
        ]
        return any(indicators)
    
    def _detect_wsl_version(self) -> str:
        """Detect WSL version"""
        try:
            # WSL2 has different kernel version pattern
            kernel_version = platform.uname().release
            if 'microsoft-standard-WSL2' in kernel_version:
                return '2'
            elif 'Microsoft' in kernel_version or 'microsoft' in kernel_version:
                return '1'
            
            # Alternative: check for WSL2-specific features
            if Path('/sys/fs/cgroup/cgroup.controllers').exists():
                return '2'
            
            return '1'  # Default to WSL1 if uncertain
        except Exception as e:
            logger.warning(f"Failed to detect WSL version: {e}")
            return '1'
    
    def _find_windows_home(self) -> Optional[Path]:
        """Find Windows home directory from WSL"""
        try:
            # Method 1: Use wslpath if available
            result = subprocess.run(
                ['wslpath', '-u', '%USERPROFILE%'],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                return Path(result.stdout.strip())
            
            # Method 2: Parse from environment
            username = os.environ.get('USER', '')
            windows_home = Path(f'/mnt/c/Users/{username}')
            if windows_home.exists():
                return windows_home
            
            # Method 3: Use cmd.exe
            result = subprocess.run(
                ['cmd.exe', '/c', 'echo %USERPROFILE%'],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                windows_path = result.stdout.strip()
                return self.windows_to_wsl_path(windows_path)
                
        except Exception as e:
            logger.warning(f"Failed to find Windows home: {e}")
        
        return None
    
    def _get_distro_name(self) -> Optional[str]:
        """Get WSL distribution name"""
        # First try environment variable
        distro = os.environ.get('WSL_DISTRO_NAME')
        if distro:
            return distro
        
        # Try to parse from /etc/os-release
        try:
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if line.startswith('NAME='):
                        return line.split('=')[1].strip().strip('"')
        except Exception as e:
            logger.warning(f"Failed to get distro name: {e}")
        
        return None
    
    @staticmethod
    def windows_to_wsl_path(windows_path: str) -> Path:
        """
        Convert Windows path to WSL path
        Example: C:\\Users\\name\\project -> /mnt/c/Users/name/project
        """
        # Handle various Windows path formats
        path = windows_path.strip()
        
        # Replace backslashes with forward slashes
        path = path.replace('\\', '/')
        
        # Handle drive letters
        if len(path) >= 2 and path[1] == ':':
            drive_letter = path[0].lower()
            path = f'/mnt/{drive_letter}{path[2:]}'
        
        return Path(path)
    
    @staticmethod
    def wsl_to_windows_path(wsl_path: str) -> str:
        """
        Convert WSL path to Windows path
        Example: /mnt/c/Users/name/project -> C:\\Users\\name\\project
        """
        path = str(wsl_path)
        
        # Check if it's a /mnt/ path
        if path.startswith('/mnt/'):
            parts = path.split('/')
            if len(parts) > 2:
                drive_letter = parts[2].upper()
                remaining = '\\'.join(parts[3:])
                return f'{drive_letter}:\\{remaining}'
        
        # For non-/mnt paths, try using wslpath command
        try:
            result = subprocess.run(
                ['wslpath', '-w', path],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        
        # Return original if conversion fails
        return path
    
    def optimize_for_wsl(self) -> Dict[str, Any]:
        """
        Apply WSL-specific optimizations
        Returns dict of applied optimizations
        """
        optimizations = {}
        
        if not self.is_wsl:
            return optimizations
        
        # 1. File system optimizations
        if self.wsl_version == '2':
            # WSL2 specific optimizations
            optimizations['filesystem'] = {
                'recommendation': 'Use WSL2 native filesystem for better performance',
                'avoid': '/mnt/c paths for intensive I/O operations'
            }
        
        # 2. Memory optimizations
        wsl_config_path = self.windows_home / '.wslconfig' if self.windows_home else None
        if wsl_config_path and wsl_config_path.exists():
            optimizations['memory'] = 'WSL config found'
        else:
            optimizations['memory'] = {
                'recommendation': 'Create .wslconfig for memory limits',
                'suggested_config': {
                    'memory': '8GB',
                    'processors': 4,
                    'swap': '4GB'
                }
            }
        
        # 3. Network optimizations
        optimizations['network'] = {
            'localhost_forwarding': 'enabled' if self.wsl_version == '2' else 'native',
            'recommendation': 'Use localhost for service communication'
        }
        
        # 4. Docker optimizations
        docker_desktop = self._check_docker_desktop()
        optimizations['docker'] = {
            'docker_desktop': docker_desktop,
            'recommendation': 'Use Docker Desktop for WSL2' if docker_desktop else 'Consider Podman as alternative'
        }
        
        return optimizations
    
    def _check_docker_desktop(self) -> bool:
        """Check if Docker Desktop is available"""
        try:
            result = subprocess.run(
                ['docker', '--version'],
                capture_output=True,
                text=True
            )
            return result.returncode == 0 and 'Docker Desktop' in result.stdout
        except:
            return False
    
    def execute_in_windows(self, command: str) -> Tuple[int, str, str]:
        """
        Execute command in Windows from WSL
        Returns: (return_code, stdout, stderr)
        """
        if not self.is_wsl:
            raise EnvironmentError("Not running in WSL")
        
        try:
            # Use cmd.exe for Windows commands
            result = subprocess.run(
                ['cmd.exe', '/c', command],
                capture_output=True,
                text=True
            )
            return result.returncode, result.stdout, result.stderr
        except Exception as e:
            logger.error(f"Failed to execute Windows command: {e}")
            return 1, '', str(e)
    
    def execute_in_wsl(self, command: str, distro: Optional[str] = None) -> Tuple[int, str, str]:
        """
        Execute command in WSL from Windows
        Returns: (return_code, stdout, stderr)
        """
        if self.is_wsl:
            # Already in WSL, execute directly
            import shlex
            command_parts = shlex.split(command)
            result = subprocess.run(
                command_parts,
                capture_output=True,
                text=True
            )
            return result.returncode, result.stdout, result.stderr
        
        # Execute from Windows
        wsl_command = ['wsl']
        if distro:
            wsl_command.extend(['-d', distro])
        wsl_command.extend(['-e', 'bash', '-c', command])
        
        try:
            result = subprocess.run(
                wsl_command,
                capture_output=True,
                text=True
            )
            return result.returncode, result.stdout, result.stderr
        except Exception as e:
            logger.error(f"Failed to execute WSL command: {e}")
            return 1, '', str(e)
    
    def get_environment_info(self) -> Dict[str, Any]:
        """Get comprehensive environment information"""
        info = {
            'platform': platform.system(),
            'is_wsl': self.is_wsl,
            'wsl_version': self.wsl_version,
            'distro': self.distro_name,
            'python_version': platform.python_version(),
            'architecture': platform.machine(),
        }
        
        if self.is_wsl:
            info['windows_home'] = str(self.windows_home) if self.windows_home else None
            info['kernel'] = platform.release()
            
            # Get Windows version through interop
            returncode, stdout, _ = self.execute_in_windows('ver')
            if returncode == 0:
                info['windows_version'] = stdout.strip()
        
        return info
    
    def setup_development_environment(self) -> Dict[str, bool]:
        """
        Setup optimal development environment for CODE
        Returns dict of setup results
        """
        results = {}
        
        if not self.is_wsl:
            logger.info("Not in WSL, skipping WSL-specific setup")
            return results
        
        # 1. Check systemd support (WSL2)
        systemd_enabled = Path('/run/systemd/system').exists()
        results['systemd'] = systemd_enabled
        
        if not systemd_enabled and self.wsl_version == '2':
            logger.info("Consider enabling systemd in /etc/wsl.conf for better service management")
        
        # 2. Check development tools
        dev_tools = {
            'git': 'git --version',
            'python3': 'python3 --version',
            'docker': 'docker --version',
            'kubectl': 'kubectl version --client',
            'terraform': 'terraform --version',
            'ollama': 'ollama --version'
        }
        
        for tool, check_cmd in dev_tools.items():
            try:
                import shlex
                command_parts = shlex.split(check_cmd)
                result = subprocess.run(
                    command_parts,
                    capture_output=True,
                    text=True
                )
                results[f'tool_{tool}'] = result.returncode == 0
            except:
                results[f'tool_{tool}'] = False
        
        # 3. Check for CODE workspace
        workspace_path = Path.home() / 'code-workspace'
        results['workspace_exists'] = workspace_path.exists()
        
        if not workspace_path.exists():
            try:
                workspace_path.mkdir(parents=True, exist_ok=True)
                (workspace_path / 'projects').mkdir(exist_ok=True)
                (workspace_path / 'configs').mkdir(exist_ok=True)
                (workspace_path / 'scripts').mkdir(exist_ok=True)
                results['workspace_created'] = True
            except Exception as e:
                logger.error(f"Failed to create workspace: {e}")
                results['workspace_created'] = False
        
        return results


# Singleton instance for easy access
wsl_env = WSLEnvironment()


# Utility functions for Claude Code
def is_wsl() -> bool:
    """Quick check if running in WSL"""
    return wsl_env.is_wsl


def convert_path(path: str, to_windows: bool = False) -> str:
    """
    Convert path between Windows and WSL formats
    
    Args:
        path: Path to convert
        to_windows: If True, convert to Windows format; else to WSL format
    """
    if to_windows:
        return wsl_env.wsl_to_windows_path(path)
    else:
        return str(wsl_env.windows_to_wsl_path(path))


def run_cross_platform(command: str, in_windows: bool = False) -> Tuple[int, str, str]:
    """
    Run command in appropriate environment
    
    Args:
        command: Command to execute
        in_windows: If True and in WSL, run in Windows; if False and in Windows, run in WSL
    """
    if wsl_env.is_wsl and in_windows:
        return wsl_env.execute_in_windows(command)
    elif not wsl_env.is_wsl and not in_windows:
        return wsl_env.execute_in_wsl(command)
    else:
        # Run in current environment
        import shlex
        command_parts = shlex.split(command)
        result = subprocess.run(
            command_parts,
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr


# Example usage for Claude context
if __name__ == "__main__":
    """
    CLAUDE-CONTEXT: Example WSL integration usage
    Shows how to detect and work with WSL environment
    """
    
    env = WSLEnvironment()
    
    print(f"Running in WSL: {env.is_wsl}")
    if env.is_wsl:
        print(f"WSL Version: {env.wsl_version}")
        print(f"Distribution: {env.distro_name}")
        print(f"Windows Home: {env.windows_home}")
        
        # Path conversion examples
        wsl_path = "/mnt/c/Users/test/project"
        windows_path = env.wsl_to_windows_path(wsl_path)
        print(f"WSL Path: {wsl_path} -> Windows: {windows_path}")
        
        # Get optimizations
        optimizations = env.optimize_for_wsl()
        print(f"Optimizations: {json.dumps(optimizations, indent=2)}")
        
        # Setup development environment
        setup_results = env.setup_development_environment()
        print(f"Setup Results: {json.dumps(setup_results, indent=2)}")
