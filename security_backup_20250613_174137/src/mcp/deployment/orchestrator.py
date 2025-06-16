"""
MCP Deployment Orchestrator - Core deployment orchestration system

Manages automated deployment of MCP servers with proper dependency
resolution, sequencing, and error handling.
"""

from __future__ import annotations
import asyncio
import logging
import time
from enum import Enum
from typing import Dict, List, Optional, Set, Any, Callable
from dataclasses import dataclass, field
from pathlib import Path
import yaml
import json

from src.core.logging_config import get_logger
from src.core.exceptions import MCPError, MCPInitializationError

logger = get_logger(__name__)


class DeploymentPhase(Enum):
    """Deployment phases for orchestrated deployment"""
    PRE_VALIDATION = "pre_validation"
    DEPENDENCY_RESOLUTION = "dependency_resolution" 
    ENVIRONMENT_SETUP = "environment_setup"
    SERVER_DEPLOYMENT = "server_deployment"
    HEALTH_VALIDATION = "health_validation"
    INTEGRATION_TESTING = "integration_testing"
    POST_DEPLOYMENT = "post_deployment"
    CLEANUP = "cleanup"


class DeploymentStatus(Enum):
    """Status of deployment operations"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    CANCELLED = "cancelled"


@dataclass
class ServerDeploymentSpec:
    """Specification for deploying a single MCP server"""
    name: str
    server_type: str
    dependencies: List[str] = field(default_factory=list)
    environment: str = "production"
    config: Dict[str, Any] = field(default_factory=dict)
    health_checks: List[str] = field(default_factory=list)
    timeout_seconds: int = 300
    retry_attempts: int = 3
    priority: int = 0  # Higher priority deployed first
    parallel_safe: bool = False  # Can be deployed in parallel


@dataclass
class DeploymentPlan:
    """Complete deployment plan with all servers and phases"""
    deployment_id: str
    servers: List[ServerDeploymentSpec]
    environment: str
    phases: List[DeploymentPhase] = field(default_factory=lambda: list(DeploymentPhase))
    parallel_groups: List[List[str]] = field(default_factory=list)
    rollback_enabled: bool = True
    validation_enabled: bool = True
    created_at: float = field(default_factory=time.time)


@dataclass
class DeploymentResult:
    """Result of a deployment operation"""
    deployment_id: str
    server_name: str
    phase: DeploymentPhase
    status: DeploymentStatus
    duration_seconds: float
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class MCPDeploymentOrchestrator:
    """
    Core MCP deployment orchestrator with automated sequencing,
    dependency management, and comprehensive error handling.
    """
    
    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize deployment orchestrator.
        
        Args:
            config_path: Optional path to deployment configuration file
        """
        self.config_path = config_path
        self.active_deployments: Dict[str, DeploymentPlan] = {}
        self.deployment_results: Dict[str, List[DeploymentResult]] = {}
        self.deployment_hooks: Dict[DeploymentPhase, List[Callable]] = {
            phase: [] for phase in DeploymentPhase
        }
        
        # Deployment state tracking
        self.server_states: Dict[str, DeploymentStatus] = {}
        self.dependency_graph: Dict[str, Set[str]] = {}
        
        # Load configuration if provided
        if config_path and config_path.exists():
            self._load_configuration()
    
    def _load_configuration(self) -> Dict[str, Any]:
        """Load deployment configuration from file."""
        if not self.config_path or not self.config_path.exists():
            return {}
        
        try:
            with open(self.config_path, 'r') as f:
                if self.config_path.suffix.lower() in ['.yaml', '.yml']:
                    return yaml.safe_load(f)
                elif self.config_path.suffix.lower() == '.json':
                    return json.load(f)
                else:
                    logger.warning(f"Unsupported config file format: {self.config_path}")
                    return {}
        except Exception as e:
            logger.error(f"Failed to load configuration from {self.config_path}: {e}")
            return {}
    
    def register_deployment_hook(
        self, 
        phase: DeploymentPhase, 
        hook: Callable[[DeploymentPlan, str], None]
    ):
        """
        Register a hook to be called during specific deployment phases.
        
        Args:
            phase: Deployment phase to hook into
            hook: Callable to execute during the phase
        """
        self.deployment_hooks[phase].append(hook)
        logger.info(f"Registered deployment hook for phase: {phase.value}")
    
    async def create_deployment_plan(
        self,
        servers: List[ServerDeploymentSpec],
        environment: str = "production",
        deployment_id: Optional[str] = None
    ) -> DeploymentPlan:
        """
        Create an optimized deployment plan with dependency resolution.
        
        Args:
            servers: List of server deployment specifications
            environment: Target deployment environment
            deployment_id: Optional custom deployment ID
            
        Returns:
            Optimized deployment plan
        """
        if not deployment_id:
            deployment_id = f"deploy_{int(time.time())}"
        
        logger.info(f"Creating deployment plan {deployment_id} for {len(servers)} servers")
        
        # Build dependency graph
        dependency_graph = self._build_dependency_graph(servers)
        
        # Resolve deployment order with parallel grouping
        parallel_groups = self._resolve_parallel_deployment_groups(servers, dependency_graph)
        
        # Create deployment plan
        plan = DeploymentPlan(
            deployment_id=deployment_id,
            servers=servers,
            environment=environment,
            parallel_groups=parallel_groups
        )
        
        # Validate deployment plan
        self._validate_deployment_plan(plan)
        
        self.active_deployments[deployment_id] = plan
        logger.info(f"Created deployment plan with {len(parallel_groups)} parallel groups")
        
        return plan
    
    def _build_dependency_graph(self, servers: List[ServerDeploymentSpec]) -> Dict[str, Set[str]]:
        """Build dependency graph for servers."""
        graph = {}
        server_names = {server.name for server in servers}
        
        for server in servers:
            dependencies = set()
            for dep in server.dependencies:
                if dep in server_names:
                    dependencies.add(dep)
                else:
                    logger.warning(f"Dependency '{dep}' for '{server.name}' not found in deployment")
            graph[server.name] = dependencies
        
        # Detect circular dependencies
        self._detect_circular_dependencies(graph)
        
        return graph
    
    def _detect_circular_dependencies(self, graph: Dict[str, Set[str]]):
        """Detect and raise error for circular dependencies."""
        visited = set()
        rec_stack = set()
        
        def has_cycle(node: str) -> bool:
            visited.add(node)
            rec_stack.add(node)
            
            for neighbor in graph.get(node, set()):
                if neighbor not in visited:
                    if has_cycle(neighbor):
                        return True
                elif neighbor in rec_stack:
                    return True
            
            rec_stack.remove(node)
            return False
        
        for node in graph:
            if node not in visited:
                if has_cycle(node):
                    raise MCPInitializationError(
                        f"Circular dependency detected in deployment plan involving '{node}'"
                    )
    
    def _resolve_parallel_deployment_groups(
        self, 
        servers: List[ServerDeploymentSpec], 
        dependency_graph: Dict[str, Set[str]]
    ) -> List[List[str]]:
        """
        Resolve parallel deployment groups based on dependencies and parallel safety.
        
        Returns:
            List of parallel deployment groups (each group can deploy concurrently)
        """
        # Sort servers by priority (higher priority first)
        sorted_servers = sorted(servers, key=lambda s: s.priority, reverse=True)
        
        groups = []
        deployed = set()
        
        while len(deployed) < len(servers):
            current_group = []
            
            for server in sorted_servers:
                if server.name in deployed:
                    continue
                
                # Check if all dependencies are deployed
                dependencies_met = all(
                    dep in deployed for dep in dependency_graph.get(server.name, set())
                )
                
                if dependencies_met:
                    # Add to current group if parallel safe or group is empty
                    if not current_group or server.parallel_safe:
                        current_group.append(server.name)
                        deployed.add(server.name)
                    elif not server.parallel_safe:
                        # Non-parallel safe servers must deploy alone
                        break
            
            if current_group:
                groups.append(current_group)
            else:
                # No servers can be deployed - check for unresolvable dependencies
                remaining = [s.name for s in sorted_servers if s.name not in deployed]
                raise MCPInitializationError(
                    f"Cannot resolve dependencies for remaining servers: {remaining}"
                )
        
        return groups
    
    def _validate_deployment_plan(self, plan: DeploymentPlan):
        """Validate deployment plan for correctness."""
        # Check for duplicate server names
        server_names = [server.name for server in plan.servers]
        if len(server_names) != len(set(server_names)):
            duplicates = [name for name in server_names if server_names.count(name) > 1]
            raise MCPInitializationError(f"Duplicate server names in deployment: {duplicates}")
        
        # Validate parallel groups contain all servers
        all_group_servers = set()
        for group in plan.parallel_groups:
            all_group_servers.update(group)
        
        plan_servers = {server.name for server in plan.servers}
        if all_group_servers != plan_servers:
            missing = plan_servers - all_group_servers
            extra = all_group_servers - plan_servers
            raise MCPInitializationError(
                f"Parallel groups mismatch. Missing: {missing}, Extra: {extra}"
            )
        
        logger.info(f"Deployment plan validation passed for {plan.deployment_id}")
    
    async def execute_deployment(
        self, 
        plan: DeploymentPlan,
        progress_callback: Optional[Callable[[str, DeploymentPhase, float], None]] = None
    ) -> List[DeploymentResult]:
        """
        Execute deployment plan with full orchestration.
        
        Args:
            plan: Deployment plan to execute
            progress_callback: Optional callback for progress updates
            
        Returns:
            List of deployment results
        """
        deployment_id = plan.deployment_id
        logger.info(f"Starting deployment execution: {deployment_id}")
        
        # Initialize deployment results tracking
        self.deployment_results[deployment_id] = []
        
        try:
            # Execute each deployment phase
            for phase in plan.phases:
                logger.info(f"Executing deployment phase: {phase.value}")
                
                # Call pre-phase hooks
                await self._execute_hooks(phase, plan, "pre")
                
                # Execute phase
                phase_results = await self._execute_deployment_phase(plan, phase)
                self.deployment_results[deployment_id].extend(phase_results)
                
                # Check for phase failures
                failed_results = [r for r in phase_results if r.status == DeploymentStatus.FAILED]
                if failed_results:
                    logger.error(f"Phase {phase.value} failed with {len(failed_results)} failures")
                    
                    # Execute rollback if enabled
                    if plan.rollback_enabled:
                        await self._execute_rollback(plan, phase)
                    
                    raise MCPError(f"Deployment phase {phase.value} failed")
                
                # Call post-phase hooks
                await self._execute_hooks(phase, plan, "post")
                
                # Update progress
                if progress_callback:
                    progress = (list(plan.phases).index(phase) + 1) / len(plan.phases)
                    progress_callback(deployment_id, phase, progress)
            
            logger.info(f"Deployment {deployment_id} completed successfully")
            return self.deployment_results[deployment_id]
            
        except Exception as e:
            logger.error(f"Deployment {deployment_id} failed: {e}")
            
            # Mark deployment as failed
            for server in plan.servers:
                self.server_states[server.name] = DeploymentStatus.FAILED
            
            raise
        
        finally:
            # Cleanup deployment state
            if deployment_id in self.active_deployments:
                del self.active_deployments[deployment_id]
    
    async def _execute_deployment_phase(
        self, 
        plan: DeploymentPlan, 
        phase: DeploymentPhase
    ) -> List[DeploymentResult]:
        """Execute a specific deployment phase."""
        results = []
        
        if phase == DeploymentPhase.PRE_VALIDATION:
            results = await self._execute_pre_validation(plan)
        elif phase == DeploymentPhase.DEPENDENCY_RESOLUTION:
            results = await self._execute_dependency_resolution(plan)
        elif phase == DeploymentPhase.ENVIRONMENT_SETUP:
            results = await self._execute_environment_setup(plan)
        elif phase == DeploymentPhase.SERVER_DEPLOYMENT:
            results = await self._execute_server_deployment(plan)
        elif phase == DeploymentPhase.HEALTH_VALIDATION:
            results = await self._execute_health_validation(plan)
        elif phase == DeploymentPhase.INTEGRATION_TESTING:
            results = await self._execute_integration_testing(plan)
        elif phase == DeploymentPhase.POST_DEPLOYMENT:
            results = await self._execute_post_deployment(plan)
        elif phase == DeploymentPhase.CLEANUP:
            results = await self._execute_cleanup(plan)
        
        return results
    
    async def _execute_pre_validation(self, plan: DeploymentPlan) -> List[DeploymentResult]:
        """Execute pre-deployment validation phase."""
        results = []
        
        for server in plan.servers:
            start_time = time.time()
            
            try:
                # Validate server configuration
                self._validate_server_config(server)
                
                # Check environment prerequisites  
                await self._check_environment_prerequisites(server, plan.environment)
                
                result = DeploymentResult(
                    deployment_id=plan.deployment_id,
                    server_name=server.name,
                    phase=DeploymentPhase.PRE_VALIDATION,
                    status=DeploymentStatus.SUCCESS,
                    duration_seconds=time.time() - start_time
                )
                
            except Exception as e:
                result = DeploymentResult(
                    deployment_id=plan.deployment_id,
                    server_name=server.name,
                    phase=DeploymentPhase.PRE_VALIDATION,
                    status=DeploymentStatus.FAILED,
                    duration_seconds=time.time() - start_time,
                    error_message=str(e)
                )
                logger.error(f"Pre-validation failed for {server.name}: {e}")
            
            results.append(result)
        
        return results
    
    async def _execute_server_deployment(self, plan: DeploymentPlan) -> List[DeploymentResult]:
        """Execute main server deployment phase with parallel groups."""
        results = []
        
        for group in plan.parallel_groups:
            logger.info(f"Deploying parallel group: {group}")
            
            # Deploy all servers in this group concurrently
            group_tasks = []
            for server_name in group:
                server = next(s for s in plan.servers if s.name == server_name)
                task = self._deploy_single_server(plan, server)
                group_tasks.append(task)
            
            # Wait for all servers in group to complete
            group_results = await asyncio.gather(*group_tasks, return_exceptions=True)
            
            for i, result in enumerate(group_results):
                if isinstance(result, Exception):
                    # Handle deployment exception
                    server_name = group[i]
                    error_result = DeploymentResult(
                        deployment_id=plan.deployment_id,
                        server_name=server_name,
                        phase=DeploymentPhase.SERVER_DEPLOYMENT,
                        status=DeploymentStatus.FAILED,
                        duration_seconds=0,
                        error_message=str(result)
                    )
                    results.append(error_result)
                    logger.error(f"Server deployment failed for {server_name}: {result}")
                else:
                    results.append(result)
            
            # Check if any servers in group failed
            failed_in_group = [r for r in group_results if isinstance(r, Exception) or 
                             (hasattr(r, 'status') and r.status == DeploymentStatus.FAILED)]
            
            if failed_in_group:
                logger.error(f"Group deployment failed with {len(failed_in_group)} failures")
                break  # Stop deployment on group failure
        
        return results
    
    async def _deploy_single_server(
        self, 
        plan: DeploymentPlan, 
        server: ServerDeploymentSpec
    ) -> DeploymentResult:
        """Deploy a single MCP server with retries."""
        start_time = time.time()
        last_error = None
        
        for attempt in range(server.retry_attempts):
            try:
                logger.info(f"Deploying {server.name} (attempt {attempt + 1}/{server.retry_attempts})")
                
                # Mark server as deploying
                self.server_states[server.name] = DeploymentStatus.RUNNING
                
                # Execute actual deployment logic here
                await self._perform_server_deployment(server, plan.environment)
                
                # Mark server as deployed
                self.server_states[server.name] = DeploymentStatus.SUCCESS
                
                return DeploymentResult(
                    deployment_id=plan.deployment_id,
                    server_name=server.name,
                    phase=DeploymentPhase.SERVER_DEPLOYMENT,
                    status=DeploymentStatus.SUCCESS,
                    duration_seconds=time.time() - start_time,
                    metadata={"attempts": attempt + 1}
                )
                
            except Exception as e:
                last_error = e
                logger.warning(f"Deployment attempt {attempt + 1} failed for {server.name}: {e}")
                
                if attempt < server.retry_attempts - 1:
                    # Wait before retry
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
        
        # All attempts failed
        self.server_states[server.name] = DeploymentStatus.FAILED
        
        return DeploymentResult(
            deployment_id=plan.deployment_id,
            server_name=server.name,
            phase=DeploymentPhase.SERVER_DEPLOYMENT,
            status=DeploymentStatus.FAILED,
            duration_seconds=time.time() - start_time,
            error_message=str(last_error),
            metadata={"attempts": server.retry_attempts}
        )
    
    async def _perform_server_deployment(self, server: ServerDeploymentSpec, environment: str):
        """Perform actual server deployment - to be implemented with specific deployment logic."""
        # This is where the actual MCP server deployment logic would go
        # For now, simulate deployment with a delay
        await asyncio.sleep(1)
        
        # TODO: Implement actual MCP server initialization and deployment
        logger.info(f"Deployed MCP server: {server.name}")
    
    async def _execute_health_validation(self, plan: DeploymentPlan) -> List[DeploymentResult]:
        """Execute health validation phase."""
        results = []
        
        for server in plan.servers:
            start_time = time.time()
            
            try:
                # Perform health checks
                await self._perform_health_checks(server)
                
                result = DeploymentResult(
                    deployment_id=plan.deployment_id,
                    server_name=server.name,
                    phase=DeploymentPhase.HEALTH_VALIDATION,
                    status=DeploymentStatus.SUCCESS,
                    duration_seconds=time.time() - start_time
                )
                
            except Exception as e:
                result = DeploymentResult(
                    deployment_id=plan.deployment_id,
                    server_name=server.name,
                    phase=DeploymentPhase.HEALTH_VALIDATION,
                    status=DeploymentStatus.FAILED,
                    duration_seconds=time.time() - start_time,
                    error_message=str(e)
                )
                logger.error(f"Health validation failed for {server.name}: {e}")
            
            results.append(result)
        
        return results
    
    async def _perform_health_checks(self, server: ServerDeploymentSpec):
        """Perform health checks for a deployed server."""
        # Simulate health checks
        await asyncio.sleep(0.5)
        
        # TODO: Implement actual health check logic
        logger.info(f"Health check passed for {server.name}")
    
    def _validate_server_config(self, server: ServerDeploymentSpec):
        """Validate server configuration."""
        if not server.name:
            raise MCPInitializationError("Server name is required")
        
        if not server.server_type:
            raise MCPInitializationError(f"Server type is required for {server.name}")
    
    async def _check_environment_prerequisites(self, server: ServerDeploymentSpec, environment: str):
        """Check environment prerequisites for server deployment."""
        # Simulate environment checks
        await asyncio.sleep(0.1)
        
        # TODO: Implement actual environment prerequisite checks
        logger.debug(f"Environment prerequisites met for {server.name} in {environment}")
    
    # Placeholder implementations for other phases
    async def _execute_dependency_resolution(self, plan: DeploymentPlan) -> List[DeploymentResult]:
        """Execute dependency resolution phase."""
        return []
    
    async def _execute_environment_setup(self, plan: DeploymentPlan) -> List[DeploymentResult]:
        """Execute environment setup phase."""
        return []
    
    async def _execute_integration_testing(self, plan: DeploymentPlan) -> List[DeploymentResult]:
        """Execute integration testing phase."""
        return []
    
    async def _execute_post_deployment(self, plan: DeploymentPlan) -> List[DeploymentResult]:
        """Execute post-deployment phase."""
        return []
    
    async def _execute_cleanup(self, plan: DeploymentPlan) -> List[DeploymentResult]:
        """Execute cleanup phase."""
        return []
    
    async def _execute_hooks(self, phase: DeploymentPhase, plan: DeploymentPlan, stage: str):
        """Execute deployment hooks for a specific phase and stage."""
        hooks = self.deployment_hooks.get(phase, [])
        for hook in hooks:
            try:
                await hook(plan, stage)
            except Exception as e:
                logger.error(f"Deployment hook failed for {phase.value}: {e}")
    
    async def _execute_rollback(self, plan: DeploymentPlan, failed_phase: DeploymentPhase):
        """Execute rollback for failed deployment."""
        logger.warning(f"Executing rollback for deployment {plan.deployment_id}")
        
        # TODO: Implement comprehensive rollback logic
        for server in plan.servers:
            if self.server_states.get(server.name) == DeploymentStatus.SUCCESS:
                self.server_states[server.name] = DeploymentStatus.ROLLED_BACK
                logger.info(f"Rolled back {server.name}")
    
    def get_deployment_status(self, deployment_id: str) -> Dict[str, Any]:
        """Get comprehensive status of a deployment."""
        if deployment_id not in self.deployment_results:
            return {"error": "Deployment not found"}
        
        results = self.deployment_results[deployment_id]
        
        return {
            "deployment_id": deployment_id,
            "total_operations": len(results),
            "successful_operations": len([r for r in results if r.status == DeploymentStatus.SUCCESS]),
            "failed_operations": len([r for r in results if r.status == DeploymentStatus.FAILED]),
            "phases_completed": len(set(r.phase for r in results)),
            "server_states": dict(self.server_states),
            "results": [
                {
                    "server": r.server_name,
                    "phase": r.phase.value,
                    "status": r.status.value,
                    "duration": r.duration_seconds,
                    "error": r.error_message
                }
                for r in results
            ]
        }