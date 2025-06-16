"""
Rollback Management System

Comprehensive error handling and rollback mechanisms for MCP deployments
with automated recovery, state management, and rollback strategies.
"""

from __future__ import annotations
import asyncio
import json
import time
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Union
from dataclasses import dataclass, field
from pathlib import Path
import shutil
import tempfile

from src.core.logging_config import get_logger
from src.core.exceptions import MCPError

logger = get_logger(__name__)


class RollbackStrategy(Enum):
    """Available rollback strategies"""
    IMMEDIATE = "immediate"  # Rollback immediately on failure
    BATCH = "batch"  # Rollback entire batch on failure
    MANUAL = "manual"  # Require manual approval for rollback
    GRACEFUL = "graceful"  # Attempt graceful rollback with cleanup
    AGGRESSIVE = "aggressive"  # Fast rollback without cleanup


class RollbackStatus(Enum):
    """Status of rollback operations"""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


class ErrorSeverity(Enum):
    """Severity levels for deployment errors"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DeploymentSnapshot:
    """Snapshot of deployment state for rollback purposes"""
    snapshot_id: str
    server_name: str
    timestamp: float
    state_data: Dict[str, Any]
    config_backup: Dict[str, Any]
    file_backups: Dict[str, str] = field(default_factory=dict)  # original_path -> backup_path
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RollbackAction:
    """Individual rollback action to be executed"""
    action_id: str
    action_type: str  # "stop_server", "restore_config", "restore_files", etc.
    server_name: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    rollback_order: int = 0  # Lower numbers execute first
    critical: bool = True  # Whether failure of this action should fail entire rollback


@dataclass
class RollbackPlan:
    """Complete rollback plan with all necessary actions"""
    plan_id: str
    deployment_id: str
    rollback_strategy: RollbackStrategy
    actions: List[RollbackAction] = field(default_factory=list)
    snapshots: List[DeploymentSnapshot] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    estimated_duration_seconds: float = 0


@dataclass
class RollbackResult:
    """Result of rollback execution"""
    action_id: str
    server_name: str
    success: bool
    duration_seconds: float
    error_message: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class RollbackManager:
    """
    Comprehensive rollback management system with automated
    recovery strategies and state management.
    """
    
    def __init__(self, backup_directory: Optional[Path] = None):
        """
        Initialize rollback manager.
        
        Args:
            backup_directory: Directory for storing backup files and snapshots
        """
        self.backup_directory = backup_directory or Path("deploy/backups")
        self.backup_directory.mkdir(parents=True, exist_ok=True)
        
        # State tracking
        self.deployment_snapshots: Dict[str, List[DeploymentSnapshot]] = {}
        self.rollback_plans: Dict[str, RollbackPlan] = {}
        self.rollback_results: Dict[str, List[RollbackResult]] = {}
        
        # Rollback action handlers
        self.action_handlers: Dict[str, Callable] = {
            "stop_server": self._stop_server_action,
            "restore_config": self._restore_config_action,
            "restore_files": self._restore_files_action,
            "restart_server": self._restart_server_action,
            "cleanup_resources": self._cleanup_resources_action,
            "revert_database": self._revert_database_action,
            "custom": self._custom_action
        }
        
        # Custom action handlers
        self.custom_handlers: Dict[str, Callable] = {}
    
    def register_custom_action_handler(self, action_type: str, handler: Callable):
        """Register a custom rollback action handler."""
        self.custom_handlers[action_type] = handler
        self.action_handlers[action_type] = handler
        logger.info(f"Registered custom rollback action handler: {action_type}")
    
    async def create_deployment_snapshot(
        self,
        deployment_id: str,
        server_name: str,
        state_data: Dict[str, Any],
        config_data: Dict[str, Any],
        files_to_backup: Optional[List[str]] = None
    ) -> DeploymentSnapshot:
        """
        Create a deployment snapshot for rollback purposes.
        
        Args:
            deployment_id: ID of the deployment
            server_name: Name of the server
            state_data: Current state data to preserve
            config_data: Current configuration to backup
            files_to_backup: Optional list of file paths to backup
            
        Returns:
            Created deployment snapshot
        """
        snapshot_id = f"snapshot_{deployment_id}_{server_name}_{int(time.time())}"
        
        # Create backup directory for this snapshot
        snapshot_dir = self.backup_directory / snapshot_id
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        
        # Backup files if specified
        file_backups = {}
        if files_to_backup:
            for file_path in files_to_backup:
                try:
                    source_path = Path(file_path)
                    if source_path.exists():
                        backup_path = snapshot_dir / source_path.name
                        if source_path.is_file():
                            shutil.copy2(source_path, backup_path)
                        else:
                            shutil.copytree(source_path, backup_path)
                        file_backups[str(source_path)] = str(backup_path)
                        logger.debug(f"Backed up {source_path} to {backup_path}")
                except Exception as e:
                    logger.warning(f"Failed to backup {file_path}: {e}")
        
        # Create snapshot
        snapshot = DeploymentSnapshot(
            snapshot_id=snapshot_id,
            server_name=server_name,
            timestamp=time.time(),
            state_data=state_data.copy(),
            config_backup=config_data.copy(),
            file_backups=file_backups,
            metadata={
                "deployment_id": deployment_id,
                "snapshot_directory": str(snapshot_dir)
            }
        )
        
        # Store snapshot
        if deployment_id not in self.deployment_snapshots:
            self.deployment_snapshots[deployment_id] = []
        self.deployment_snapshots[deployment_id].append(snapshot)
        
        # Save snapshot metadata to disk
        snapshot_file = snapshot_dir / "snapshot_metadata.json"
        with open(snapshot_file, 'w') as f:
            json.dump({
                "snapshot_id": snapshot.snapshot_id,
                "server_name": snapshot.server_name,
                "timestamp": snapshot.timestamp,
                "state_data": snapshot.state_data,
                "config_backup": snapshot.config_backup,
                "file_backups": snapshot.file_backups,
                "metadata": snapshot.metadata
            }, f, indent=2, default=str)
        
        logger.info(f"Created deployment snapshot: {snapshot_id}")
        return snapshot
    
    async def create_rollback_plan(
        self,
        deployment_id: str,
        failed_servers: List[str],
        rollback_strategy: RollbackStrategy = RollbackStrategy.GRACEFUL,
        custom_actions: Optional[List[RollbackAction]] = None
    ) -> RollbackPlan:
        """
        Create a comprehensive rollback plan.
        
        Args:
            deployment_id: ID of the failed deployment
            failed_servers: List of servers that need rollback
            rollback_strategy: Strategy for rollback execution
            custom_actions: Optional custom rollback actions
            
        Returns:
            Created rollback plan
        """
        plan_id = f"rollback_{deployment_id}_{int(time.time())}"
        
        # Get snapshots for this deployment
        snapshots = self.deployment_snapshots.get(deployment_id, [])
        
        # Filter snapshots for failed servers
        relevant_snapshots = [
            snapshot for snapshot in snapshots
            if snapshot.server_name in failed_servers
        ]
        
        # Generate rollback actions
        actions = []
        action_order = 0
        
        # Add custom actions first if provided
        if custom_actions:
            for action in custom_actions:
                action.rollback_order = action_order
                actions.append(action)
                action_order += 1
        
        # Generate standard rollback actions for each server
        for server_name in failed_servers:
            server_snapshots = [s for s in relevant_snapshots if s.server_name == server_name]
            
            if not server_snapshots:
                logger.warning(f"No snapshots found for server {server_name}, limited rollback options")
                continue
            
            # Use most recent snapshot
            latest_snapshot = max(server_snapshots, key=lambda s: s.timestamp)
            
            # Stop server action
            actions.append(RollbackAction(
                action_id=f"stop_{server_name}_{action_order}",
                action_type="stop_server",
                server_name=server_name,
                parameters={"graceful": rollback_strategy == RollbackStrategy.GRACEFUL},
                rollback_order=action_order,
                critical=True
            ))
            action_order += 1
            
            # Restore configuration action
            if latest_snapshot.config_backup:
                actions.append(RollbackAction(
                    action_id=f"restore_config_{server_name}_{action_order}",
                    action_type="restore_config",
                    server_name=server_name,
                    parameters={
                        "snapshot_id": latest_snapshot.snapshot_id,
                        "config_data": latest_snapshot.config_backup
                    },
                    rollback_order=action_order,
                    critical=True
                ))
                action_order += 1
            
            # Restore files action
            if latest_snapshot.file_backups:
                actions.append(RollbackAction(
                    action_id=f"restore_files_{server_name}_{action_order}",
                    action_type="restore_files",
                    server_name=server_name,
                    parameters={
                        "snapshot_id": latest_snapshot.snapshot_id,
                        "file_backups": latest_snapshot.file_backups
                    },
                    rollback_order=action_order,
                    critical=False  # File restoration is less critical
                ))
                action_order += 1
            
            # Restart server action (only for graceful rollback)
            if rollback_strategy == RollbackStrategy.GRACEFUL:
                actions.append(RollbackAction(
                    action_id=f"restart_{server_name}_{action_order}",
                    action_type="restart_server",
                    server_name=server_name,
                    parameters={"wait_for_health": True},
                    rollback_order=action_order,
                    critical=False
                ))
                action_order += 1
        
        # Sort actions by rollback order
        actions.sort(key=lambda a: a.rollback_order)
        
        # Estimate duration
        estimated_duration = len(actions) * 30  # 30 seconds per action estimate
        if rollback_strategy == RollbackStrategy.AGGRESSIVE:
            estimated_duration *= 0.5  # Faster execution
        elif rollback_strategy == RollbackStrategy.GRACEFUL:
            estimated_duration *= 1.5  # Slower, more careful execution
        
        # Create rollback plan
        plan = RollbackPlan(
            plan_id=plan_id,
            deployment_id=deployment_id,
            rollback_strategy=rollback_strategy,
            actions=actions,
            snapshots=relevant_snapshots,
            estimated_duration_seconds=estimated_duration
        )
        
        self.rollback_plans[plan_id] = plan
        logger.info(f"Created rollback plan {plan_id} with {len(actions)} actions")
        
        return plan
    
    async def execute_rollback_plan(
        self,
        plan: RollbackPlan,
        progress_callback: Optional[Callable[[str, int, int], None]] = None
    ) -> List[RollbackResult]:
        """
        Execute a rollback plan.
        
        Args:
            plan: Rollback plan to execute
            progress_callback: Optional callback for progress updates
            
        Returns:
            List of rollback results
        """
        plan_id = plan.plan_id
        logger.info(f"Executing rollback plan: {plan_id}")
        
        self.rollback_results[plan_id] = []
        results = []
        
        try:
            # Execute actions in order
            for i, action in enumerate(plan.actions):
                if progress_callback:
                    progress_callback(plan_id, i, len(plan.actions))
                
                logger.info(f"Executing rollback action: {action.action_id}")
                result = await self._execute_rollback_action(action)
                results.append(result)
                self.rollback_results[plan_id].append(result)
                
                # Handle action failure
                if not result.success:
                    logger.error(f"Rollback action failed: {action.action_id} - {result.error_message}")
                    
                    if action.critical:
                        if plan.rollback_strategy == RollbackStrategy.AGGRESSIVE:
                            # Continue despite failures
                            logger.warning("Continuing rollback despite critical action failure (aggressive mode)")
                        else:
                            # Stop rollback on critical failure
                            logger.error("Stopping rollback due to critical action failure")
                            break
                
                # Add delay between actions for graceful rollback
                if plan.rollback_strategy == RollbackStrategy.GRACEFUL and i < len(plan.actions) - 1:
                    await asyncio.sleep(2)
            
            if progress_callback:
                progress_callback(plan_id, len(plan.actions), len(plan.actions))
            
            logger.info(f"Rollback plan execution completed: {plan_id}")
            
        except Exception as e:
            logger.error(f"Rollback plan execution failed: {plan_id} - {e}")
            raise MCPError(f"Rollback execution failed: {e}")
        
        return results
    
    async def _execute_rollback_action(self, action: RollbackAction) -> RollbackResult:
        """Execute a single rollback action."""
        start_time = time.time()
        
        try:
            if action.action_type not in self.action_handlers:
                raise MCPError(f"No handler for rollback action type: {action.action_type}")
            
            handler = self.action_handlers[action.action_type]
            
            # Execute action handler
            if asyncio.iscoroutinefunction(handler):
                await handler(action)
            else:
                handler(action)
            
            duration = time.time() - start_time
            
            return RollbackResult(
                action_id=action.action_id,
                server_name=action.server_name,
                success=True,
                duration_seconds=duration,
                details={"action_type": action.action_type}
            )
            
        except Exception as e:
            duration = time.time() - start_time
            
            return RollbackResult(
                action_id=action.action_id,
                server_name=action.server_name,
                success=False,
                duration_seconds=duration,
                error_message=str(e),
                details={"action_type": action.action_type}
            )
    
    # Rollback action handlers
    async def _stop_server_action(self, action: RollbackAction):
        """Stop server rollback action."""
        server_name = action.server_name
        graceful = action.parameters.get("graceful", True)
        
        logger.info(f"Stopping server {server_name} ({'graceful' if graceful else 'force'})")
        
        # TODO: Implement actual server stopping logic
        # This would integrate with the MCP server management system
        if graceful:
            await asyncio.sleep(2)  # Simulate graceful stop
        else:
            await asyncio.sleep(0.5)  # Simulate force stop
        
        logger.info(f"Server {server_name} stopped")
    
    async def _restore_config_action(self, action: RollbackAction):
        """Restore configuration rollback action."""
        server_name = action.server_name
        config_data = action.parameters.get("config_data", {})
        
        logger.info(f"Restoring configuration for server {server_name}")
        
        # TODO: Implement actual configuration restoration
        # This would restore configuration files/settings
        await asyncio.sleep(1)  # Simulate config restoration
        
        logger.info(f"Configuration restored for server {server_name}")
    
    async def _restore_files_action(self, action: RollbackAction):
        """Restore files rollback action."""
        server_name = action.server_name
        file_backups = action.parameters.get("file_backups", {})
        
        logger.info(f"Restoring files for server {server_name}")
        
        for original_path, backup_path in file_backups.items():
            try:
                backup_file = Path(backup_path)
                original_file = Path(original_path)
                
                if backup_file.exists():
                    # Ensure parent directory exists
                    original_file.parent.mkdir(parents=True, exist_ok=True)
                    
                    if backup_file.is_file():
                        shutil.copy2(backup_file, original_file)
                    else:
                        if original_file.exists():
                            shutil.rmtree(original_file)
                        shutil.copytree(backup_file, original_file)
                    
                    logger.debug(f"Restored {original_path} from {backup_path}")
                else:
                    logger.warning(f"Backup file not found: {backup_path}")
            except Exception as e:
                logger.error(f"Failed to restore {original_path}: {e}")
                raise
        
        logger.info(f"Files restored for server {server_name}")
    
    async def _restart_server_action(self, action: RollbackAction):
        """Restart server rollback action."""
        server_name = action.server_name
        wait_for_health = action.parameters.get("wait_for_health", True)
        
        logger.info(f"Restarting server {server_name}")
        
        # TODO: Implement actual server restart logic
        await asyncio.sleep(3)  # Simulate server restart
        
        if wait_for_health:
            # TODO: Implement health check waiting
            await asyncio.sleep(2)  # Simulate health check wait
        
        logger.info(f"Server {server_name} restarted")
    
    async def _cleanup_resources_action(self, action: RollbackAction):
        """Cleanup resources rollback action."""
        server_name = action.server_name
        
        logger.info(f"Cleaning up resources for server {server_name}")
        
        # TODO: Implement resource cleanup (temp files, connections, etc.)
        await asyncio.sleep(1)  # Simulate cleanup
        
        logger.info(f"Resources cleaned up for server {server_name}")
    
    async def _revert_database_action(self, action: RollbackAction):
        """Revert database rollback action."""
        server_name = action.server_name
        
        logger.info(f"Reverting database changes for server {server_name}")
        
        # TODO: Implement database rollback logic
        await asyncio.sleep(2)  # Simulate database revert
        
        logger.info(f"Database changes reverted for server {server_name}")
    
    async def _custom_action(self, action: RollbackAction):
        """Execute custom rollback action."""
        custom_type = action.parameters.get("custom_type", "")
        
        if custom_type in self.custom_handlers:
            handler = self.custom_handlers[custom_type]
            if asyncio.iscoroutinefunction(handler):
                await handler(action)
            else:
                handler(action)
        else:
            raise MCPError(f"Custom action handler not found: {custom_type}")
    
    def get_rollback_status(self, plan_id: str) -> Dict[str, Any]:
        """Get status of a rollback plan execution."""
        if plan_id not in self.rollback_results:
            return {"error": "Rollback plan not found"}
        
        results = self.rollback_results[plan_id]
        plan = self.rollback_plans.get(plan_id)
        
        successful_actions = len([r for r in results if r.success])
        failed_actions = len([r for r in results if not r.success])
        
        # Determine overall status
        if not results:
            status = RollbackStatus.NOT_STARTED
        elif len(results) < len(plan.actions) if plan else 0:
            status = RollbackStatus.IN_PROGRESS
        elif failed_actions == 0:
            status = RollbackStatus.COMPLETED
        elif successful_actions == 0:
            status = RollbackStatus.FAILED
        else:
            status = RollbackStatus.PARTIAL
        
        return {
            "plan_id": plan_id,
            "status": status.value,
            "total_actions": len(plan.actions) if plan else 0,
            "completed_actions": len(results),
            "successful_actions": successful_actions,
            "failed_actions": failed_actions,
            "results": [
                {
                    "action_id": r.action_id,
                    "server_name": r.server_name,
                    "success": r.success,
                    "duration_seconds": r.duration_seconds,
                    "error_message": r.error_message
                }
                for r in results
            ]
        }
    
    def cleanup_old_snapshots(self, max_age_days: int = 30) -> int:
        """Clean up old deployment snapshots."""
        cutoff_time = time.time() - (max_age_days * 24 * 3600)
        cleaned_count = 0
        
        for deployment_id, snapshots in list(self.deployment_snapshots.items()):
            old_snapshots = [s for s in snapshots if s.timestamp < cutoff_time]
            
            for snapshot in old_snapshots:
                try:
                    # Remove snapshot directory
                    snapshot_dir = Path(snapshot.metadata.get("snapshot_directory", ""))
                    if snapshot_dir.exists():
                        shutil.rmtree(snapshot_dir)
                    
                    # Remove from memory
                    snapshots.remove(snapshot)
                    cleaned_count += 1
                    
                    logger.debug(f"Cleaned up old snapshot: {snapshot.snapshot_id}")
                except Exception as e:
                    logger.warning(f"Failed to cleanup snapshot {snapshot.snapshot_id}: {e}")
        
        logger.info(f"Cleaned up {cleaned_count} old snapshots")
        return cleaned_count
    
    def list_snapshots(self, deployment_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List available deployment snapshots."""
        snapshots = []
        
        deployments_to_check = [deployment_id] if deployment_id else self.deployment_snapshots.keys()
        
        for dep_id in deployments_to_check:
            for snapshot in self.deployment_snapshots.get(dep_id, []):
                snapshots.append({
                    "snapshot_id": snapshot.snapshot_id,
                    "deployment_id": dep_id,
                    "server_name": snapshot.server_name,
                    "timestamp": snapshot.timestamp,
                    "has_config_backup": bool(snapshot.config_backup),
                    "has_file_backups": bool(snapshot.file_backups),
                    "file_backup_count": len(snapshot.file_backups)
                })
        
        return sorted(snapshots, key=lambda s: s["timestamp"], reverse=True)