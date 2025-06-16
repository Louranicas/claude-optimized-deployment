"""
Git operations management module for standardized version control operations.

This module consolidates functionality from multiple git scripts:
- setup_git_remotes.sh
- push_to_all_services.sh
- push_all_configured.sh
- push_all_parallel.sh
- configure_git_remotes.sh
- setup_git_for_claude.sh
- add_git_services.sh

Provides a unified Python interface for git operations with enterprise standards.
"""

import asyncio
import subprocess
import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import re

logger = logging.getLogger(__name__)


@dataclass
class GitRemote:
    """Represents a git remote configuration."""
    name: str
    url: str
    push_url: Optional[str] = None
    fetch_url: Optional[str] = None
    
    
@dataclass
class GitStatus:
    """Represents the current git repository status."""
    branch: str
    is_clean: bool
    uncommitted_changes: List[str]
    unpushed_commits: int
    remotes: List[GitRemote]
    
    
@dataclass
class PushResult:
    """Result of a git push operation."""
    remote: str
    success: bool
    message: str
    duration: float
    timestamp: datetime


class GitManager:
    """
    Unified git operations manager for enterprise development.
    
    Consolidates git operations from multiple shell scripts into a
    single, well-tested, production-ready Python module.
    """
    
    # Supported git services and their URL patterns
    GIT_SERVICES = {
        'github': {
            'pattern': r'github\.com[:/](.+?)(?:\.git)?$',
            'ssh_format': 'git@github.com:{}.git',
            'https_format': 'https://github.com/{}.git'
        },
        'gitlab': {
            'pattern': r'gitlab\.com[:/](.+?)(?:\.git)?$',
            'ssh_format': 'git@gitlab.com:{}.git',
            'https_format': 'https://gitlab.com/{}.git'
        },
        'bitbucket': {
            'pattern': r'bitbucket\.org[:/](.+?)(?:\.git)?$',
            'ssh_format': 'git@bitbucket.org:{}.git',
            'https_format': 'https://bitbucket.org/{}.git'
        },
        'azure': {
            'pattern': r'dev\.azure\.com/(.+?)(?:\.git)?$',
            'ssh_format': 'git@ssh.dev.azure.com:v3/{}.git',
            'https_format': 'https://dev.azure.com/{}.git'
        }
    }
    
    def __init__(self, repo_path: Optional[Path] = None):
        """
        Initialize GitManager.
        
        Args:
            repo_path: Path to git repository. Defaults to current directory.
        """
        self.repo_path = Path(repo_path) if repo_path else Path.cwd()
        self._validate_git_repo()
        
    def _validate_git_repo(self):
        """Validate that we're in a git repository."""
        git_dir = self.repo_path / '.git'
        if not git_dir.exists():
            raise ValueError(f"{self.repo_path} is not a git repository")
            
    def _run_git_command(self, args: List[str], 
                        check: bool = True,
                        capture_output: bool = True) -> subprocess.CompletedProcess:
        """
        Run a git command and return the result.
        
        Args:
            args: Git command arguments
            check: Whether to raise on non-zero exit
            capture_output: Whether to capture stdout/stderr
            
        Returns:
            CompletedProcess instance
        """
        cmd = ['git'] + args
        logger.debug(f"Running command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                cwd=self.repo_path,
                check=check,
                capture_output=capture_output,
                text=True
            )
            return result
        except subprocess.CalledProcessError as e:
            logger.error(f"Git command failed: {e.cmd}")
            logger.error(f"Error output: {e.stderr}")
            raise
            
    async def _run_git_command_async(self, args: List[str]) -> Tuple[bool, str]:
        """
        Run a git command asynchronously.
        
        Args:
            args: Git command arguments
            
        Returns:
            Tuple of (success, output/error message)
        """
        cmd = ['git'] + args
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=self.repo_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await proc.communicate()
            
            if proc.returncode == 0:
                return True, stdout.decode().strip()
            else:
                return False, stderr.decode().strip()
                
        except Exception as e:
            return False, str(e)
            
    def get_status(self) -> GitStatus:
        """
        Get the current repository status.
        
        Returns:
            GitStatus object with current repository state
        """
        # Get current branch
        result = self._run_git_command(['rev-parse', '--abbrev-ref', 'HEAD'])
        branch = result.stdout.strip()
        
        # Check for uncommitted changes
        result = self._run_git_command(['status', '--porcelain'])
        uncommitted_changes = [line for line in result.stdout.strip().split('\n') if line]
        is_clean = len(uncommitted_changes) == 0
        
        # Count unpushed commits
        try:
            result = self._run_git_command(['rev-list', f'{branch}...origin/{branch}', '--count'])
            unpushed_commits = int(result.stdout.strip() or 0)
        except:
            unpushed_commits = 0
            
        # Get remotes
        remotes = self.list_remotes()
        
        return GitStatus(
            branch=branch,
            is_clean=is_clean,
            uncommitted_changes=uncommitted_changes,
            unpushed_commits=unpushed_commits,
            remotes=remotes
        )
        
    def list_remotes(self) -> List[GitRemote]:
        """
        List all configured git remotes.
        
        Returns:
            List of GitRemote objects
        """
        remotes = []
        
        # Get remote names
        result = self._run_git_command(['remote'])
        remote_names = result.stdout.strip().split('
') if result.stdout.strip() else []
        
        # Get details for each remote
        for name in remote_names:
            result = self._run_git_command(['remote', 'get-url', name])
            url = result.stdout.strip()
            
            # Try to get push URL (might be same as fetch URL)
            try:
                result = self._run_git_command(['remote', 'get-url', '--push', name])
                push_url = result.stdout.strip()
            except:
                push_url = url
                
            remotes.append(GitRemote(
                name=name,
                url=url,
                push_url=push_url,
                fetch_url=url
            ))
            
        return remotes
        
    def add_remote(self, name: str, url: str, push_only: bool = False) -> bool:
        """
        Add a new git remote.
        
        Args:
            name: Remote name
            url: Remote URL
            push_only: If True, set as push URL only
            
        Returns:
            True if successful
        """
        try:
            if push_only:
                # First check if remote exists
                remotes = [r.name for r in self.list_remotes()]
                if name not in remotes:
                    # Add remote with a dummy URL first
                    self._run_git_command(['remote', 'add', name, url])
                else:
                    # Set push URL for existing remote
                    self._run_git_command(['remote', 'set-url', '--push', name, url])
            else:
                self._run_git_command(['remote', 'add', name, url])
                
            logger.info(f"Added remote '{name}' with URL: {url}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to add remote '{name}': {e}")
            return False
            
    def remove_remote(self, name: str) -> bool:
        """
        Remove a git remote.
        
        Args:
            name: Remote name to remove
            
        Returns:
            True if successful
        """
        try:
            self._run_git_command(['remote', 'remove', name])
            logger.info(f"Removed remote '{name}'")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to remove remote '{name}': {e}")
            return False
            
    def setup_multi_remote(self, services: Optional[List[str]] = None) -> Dict[str, bool]:
        """
        Set up multiple git remotes for different services.
        
        This replicates the functionality of the setup_git_remotes.sh script.
        
        Args:
            services: List of services to set up. Defaults to all supported.
            
        Returns:
            Dictionary mapping service names to success status
        """
        if services is None:
            services = list(self.GIT_SERVICES.keys())
            
        # Get current origin URL to determine repo path
        remotes = self.list_remotes()
        origin_remote = next((r for r in remotes if r.name == 'origin'), None)
        
        if not origin_remote:
            logger.error("No origin remote found")
            return {service: False for service in services}
            
        # Extract repository path from origin URL
        repo_path = None
        for service_name, service_config in self.GIT_SERVICES.items():
            match = re.search(service_config['pattern'], origin_remote.url)
            if match:
                repo_path = match.group(1)
                break
                
        if not repo_path:
            logger.error("Could not extract repository path from origin URL")
            return {service: False for service in services}
            
        results = {}
        
        # Set up each service
        for service in services:
            if service not in self.GIT_SERVICES:
                logger.warning(f"Unknown service: {service}")
                results[service] = False
                continue
                
            service_config = self.GIT_SERVICES[service]
            
            # Use SSH format by default
            remote_url = service_config['ssh_format'].format(repo_path)
            
            # Add or update remote
            results[service] = self.add_remote(service, remote_url)
            
        return results
        
    def push_to_remote(self, remote: str, branch: Optional[str] = None,
                      force: bool = False, tags: bool = False) -> PushResult:
        """
        Push to a specific remote.
        
        Args:
            remote: Remote name to push to
            branch: Branch to push (defaults to current branch)
            force: Force push if True
            tags: Push tags if True
            
        Returns:
            PushResult object
        """
        if not branch:
            status = self.get_status()
            branch = status.branch
            
        args = ['push', remote, branch]
        if force:
            args.append('--force')
        if tags:
            args.append('--tags')
            
        start_time = datetime.now()
        
        try:
            result = self._run_git_command(args)
            duration = (datetime.now() - start_time).total_seconds()
            
            return PushResult(
                remote=remote,
                success=True,
                message=result.stdout or "Push successful",
                duration=duration,
                timestamp=datetime.now()
            )
            
        except subprocess.CalledProcessError as e:
            duration = (datetime.now() - start_time).total_seconds()
            
            return PushResult(
                remote=remote,
                success=False,
                message=e.stderr or str(e),
                duration=duration,
                timestamp=datetime.now()
            )
            
    def push_to_all_remotes(self, branch: Optional[str] = None,
                           parallel: bool = True,
                           exclude: Optional[List[str]] = None) -> Dict[str, PushResult]:
        """
        Push to all configured remotes.
        
        This replicates the functionality of push_to_all_services.sh and
        push_all_parallel.sh scripts.
        
        Args:
            branch: Branch to push (defaults to current branch)
            parallel: Push to remotes in parallel if True
            exclude: List of remote names to exclude
            
        Returns:
            Dictionary mapping remote names to PushResult objects
        """
        if exclude is None:
            exclude = []
            
        remotes = [r for r in self.list_remotes() if r.name not in exclude]
        results = {}
        
        if not remotes:
            logger.warning("No remotes configured")
            return results
            
        if parallel:
            # Push to all remotes in parallel
            with ThreadPoolExecutor(max_workers=len(remotes)) as executor:
                future_to_remote = {
                    executor.submit(self.push_to_remote, remote.name, branch): remote
                    for remote in remotes
                }
                
                for future in as_completed(future_to_remote):
                    remote = future_to_remote[future]
                    try:
                        result = future.result()
                        results[remote.name] = result
                    except Exception as e:
                        results[remote.name] = PushResult(
                            remote=remote.name,
                            success=False,
                            message=str(e),
                            duration=0,
                            timestamp=datetime.now()
                        )
        else:
            # Push to remotes sequentially
            for remote in remotes:
                results[remote.name] = self.push_to_remote(remote.name, branch)
                
        return results
        
    async def push_to_all_remotes_async(self, branch: Optional[str] = None,
                                       exclude: Optional[List[str]] = None) -> Dict[str, PushResult]:
        """
        Push to all remotes asynchronously.
        
        Args:
            branch: Branch to push (defaults to current branch)
            exclude: List of remote names to exclude
            
        Returns:
            Dictionary mapping remote names to PushResult objects
        """
        if exclude is None:
            exclude = []
            
        if not branch:
            status = self.get_status()
            branch = status.branch
            
        remotes = [r for r in self.list_remotes() if r.name not in exclude]
        
        tasks = []
        for remote in remotes:
            args = ['push', remote.name, branch]
            task = self._push_async(remote.name, args)
            tasks.append(task)
            
        results = await asyncio.gather(*tasks)
        
        return {r.remote: r for r in results}
        
    async def _push_async(self, remote_name: str, args: List[str]) -> PushResult:
        """Helper method for async push operations."""
        start_time = datetime.now()
        success, output = await self._run_git_command_async(args)
        duration = (datetime.now() - start_time).total_seconds()
        
        return PushResult(
            remote=remote_name,
            success=success,
            message=output,
            duration=duration,
            timestamp=datetime.now()
        )
        
    def fetch_all_remotes(self, prune: bool = True) -> Dict[str, bool]:
        """
        Fetch from all configured remotes.
        
        Args:
            prune: Prune deleted remote branches if True
            
        Returns:
            Dictionary mapping remote names to success status
        """
        remotes = self.list_remotes()
        results = {}
        
        for remote in remotes:
            args = ['fetch', remote.name]
            if prune:
                args.append('--prune')
                
            try:
                self._run_git_command(args)
                results[remote.name] = True
                logger.info(f"Fetched from remote '{remote.name}'")
            except subprocess.CalledProcessError as e:
                results[remote.name] = False
                logger.error(f"Failed to fetch from '{remote.name}': {e}")
                
        return results
        
    def create_mirror_remote(self, name: str, url: str) -> bool:
        """
        Create a mirror remote for backup purposes.
        
        Args:
            name: Remote name
            url: Remote URL
            
        Returns:
            True if successful
        """
        try:
            # Add remote
            self._run_git_command(['remote', 'add', '--mirror=push', name, url])
            logger.info(f"Created mirror remote '{name}'")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to create mirror remote: {e}")
            return False
            
    def sync_to_mirror(self, mirror_name: str) -> bool:
        """
        Sync repository to a mirror remote.
        
        Args:
            mirror_name: Name of the mirror remote
            
        Returns:
            True if successful
        """
        try:
            self._run_git_command(['push', '--mirror', mirror_name])
            logger.info(f"Synced to mirror '{mirror_name}'")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to sync to mirror: {e}")
            return False
            
    def setup_hooks(self, hooks_dir: Optional[Path] = None) -> bool:
        """
        Set up git hooks for the repository.
        
        Args:
            hooks_dir: Directory containing hook scripts
            
        Returns:
            True if successful
        """
        if hooks_dir is None:
            hooks_dir = self.repo_path / '.git' / 'hooks'
            
        # Common hooks to set up
        hooks = {
            'pre-commit': self._get_pre_commit_hook(),
            'pre-push': self._get_pre_push_hook(),
            'commit-msg': self._get_commit_msg_hook()
        }
        
        try:
            hooks_dir.mkdir(parents=True, exist_ok=True)
            
            for hook_name, hook_content in hooks.items():
                hook_path = hooks_dir / hook_name
                
                with open(hook_path, 'w') as f:
                    f.write(hook_content)
                    
                # Make executable
                os.chmod(hook_path, 0o755)
                
                logger.info(f"Set up git hook: {hook_name}")
                
            return True
            
        except Exception as e:
            logger.error(f"Failed to set up hooks: {e}")
            return False
            
    def _get_pre_commit_hook(self) -> str:
        """Get pre-commit hook content."""
        return """#!/bin/bash
# Pre-commit hook for code quality checks

# Run linting
make lint || exit 1

# Run type checking
make type-check || exit 1

# Run security checks
make security-check || exit 1

echo "✅ Pre-commit checks passed"
"""

    def _get_pre_push_hook(self) -> str:
        """Get pre-push hook content."""
        return """#!/bin/bash
# Pre-push hook for running tests

# Run tests
make test || exit 1

echo "✅ Pre-push checks passed"
"""

    def _get_commit_msg_hook(self) -> str:
        """Get commit-msg hook content."""
        return """#!/bin/bash
# Commit message validation hook

commit_regex='^(feat|fix|docs|style|refactor|test|chore)\\(.+\\)?: .{1,50}'

if ! grep -qE "$commit_regex" "$1"; then
    echo "❌ Invalid commit message format!"
    echo "Expected format: <type>(<scope>): <subject>"
    echo "Example: feat(api): add user authentication"
    exit 1
fi

echo "✅ Commit message format valid"
"""

    def get_config(self, key: str) -> Optional[str]:
        """
        Get a git config value.
        
        Args:
            key: Config key to get
            
        Returns:
            Config value or None if not set
        """
        try:
            result = self._run_git_command(['config', '--get', key])
            return result.stdout.strip()
        except:
            return None
            
    def set_config(self, key: str, value: str, global_config: bool = False) -> bool:
        """
        Set a git config value.
        
        Args:
            key: Config key to set
            value: Config value
            global_config: Set globally if True, locally if False
            
        Returns:
            True if successful
        """
        try:
            args = ['config']
            if global_config:
                args.append('--global')
            args.extend([key, value])
            
            self._run_git_command(args)
            logger.info(f"Set git config {key} = {value}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to set git config: {e}")
            return False


# CLI interface for backward compatibility
def main():
    """Command-line interface for git operations."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Git operations management tool")
    
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Show repository status')
    
    # Remotes command
    remotes_parser = subparsers.add_parser('remotes', help='List configured remotes')
    
    # Setup command
    setup_parser = subparsers.add_parser('setup', help='Set up multiple remotes')
    setup_parser.add_argument('--services', nargs='+', 
                            choices=['github', 'gitlab', 'bitbucket', 'azure'],
                            help='Services to set up')
    
    # Push command
    push_parser = subparsers.add_parser('push', help='Push to remotes')
    push_parser.add_argument('remote', nargs='?', default='all',
                           help='Remote to push to (or "all")')
    push_parser.add_argument('--branch', help='Branch to push')
    push_parser.add_argument('--parallel', action='store_true',
                           help='Push to all remotes in parallel')
    push_parser.add_argument('--exclude', nargs='+',
                           help='Remotes to exclude')
    
    # Fetch command
    fetch_parser = subparsers.add_parser('fetch', help='Fetch from all remotes')
    fetch_parser.add_argument('--no-prune', action='store_true',
                            help='Do not prune deleted branches')
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(level=logging.INFO,
                       format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    try:
        manager = GitManager()
    except ValueError as e:
        print(f"Error: {e}")
        return 1
        
    if args.command == 'status':
        status = manager.get_status()
        print(f"Branch: {status.branch}")
        print(f"Clean: {'Yes' if status.is_clean else 'No'}")
        if status.uncommitted_changes:
            print("Uncommitted changes:")
            for change in status.uncommitted_changes:
                print(f"  {change}")
        print(f"Unpushed commits: {status.unpushed_commits}")
        print(f"Remotes: {', '.join(r.name for r in status.remotes)}")
        
    elif args.command == 'remotes':
        remotes = manager.list_remotes()
        for remote in remotes:
            print(f"{remote.name}: {remote.url}")
            
    elif args.command == 'setup':
        results = manager.setup_multi_remote(args.services)
        for service, success in results.items():
            status = "✅" if success else "❌"
            print(f"{status} {service}")
            
    elif args.command == 'push':
        if args.remote == 'all':
            results = manager.push_to_all_remotes(
                branch=args.branch,
                parallel=args.parallel,
                exclude=args.exclude or []
            )
            for remote, result in results.items():
                status = "✅" if result.success else "❌"
                print(f"{status} {remote}: {result.message} ({result.duration:.2f}s)")
        else:
            result = manager.push_to_remote(args.remote, args.branch)
            status = "✅" if result.success else "❌"
            print(f"{status} {result.message}")
            
    elif args.command == 'fetch':
        results = manager.fetch_all_remotes(prune=not args.no_prune)
        for remote, success in results.items():
            status = "✅" if success else "❌"
            print(f"{status} {remote}")
            
    else:
        parser.print_help()
        

if __name__ == "__main__":
    main()