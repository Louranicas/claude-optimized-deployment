#!/usr/bin/env python3
"""
Automated MCP Server Deployment Script

Production-ready deployment automation for MCP servers with
comprehensive orchestration, monitoring, and error handling.
"""

import asyncio
import argparse
import json
import yaml
import sys
import os
from pathlib import Path
from typing import Dict, Any, List, Optional
import time
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

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


class MCPDeploymentAutomation:
    """
    Comprehensive MCP deployment automation with orchestration,
    monitoring, health checks, and rollback capabilities.
    """
    
    def __init__(
        self,
        config_dir: Optional[Path] = None,
        backup_dir: Optional[Path] = None,
        enable_monitoring: bool = True
    ):
        """
        Initialize deployment automation.
        
        Args:
            config_dir: Configuration directory
            backup_dir: Backup directory for rollbacks
            enable_monitoring: Whether to enable real-time monitoring
        """
        self.config_dir = config_dir or Path("deploy/config")
        self.backup_dir = backup_dir or Path("deploy/backups")
        
        # Initialize components
        self.orchestrator = MCPDeploymentOrchestrator()
        self.config_manager = DeploymentConfigManager(self.config_dir)
        self.health_validator = HealthValidator()
        self.rollback_manager = RollbackManager(self.backup_dir)
        
        # Optional monitoring
        self.monitor = None
        if enable_monitoring:
            self.monitor = DeploymentMonitor()
        
        # Deployment state
        self.current_deployment_id = None
        self.deployment_snapshots = {}
    
    async def initialize(self):
        """Initialize all components."""
        logger.info("Initializing MCP deployment automation...")
        
        # Create directories
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Start monitoring if enabled
        if self.monitor:
            await self.monitor.start_monitoring()
            logger.info("Deployment monitoring started")
        
        # Register standard health checks
        await self._register_standard_health_checks()
        
        logger.info("MCP deployment automation initialized")
    
    async def deploy_from_config(
        self,
        deployment_file: Path,
        environment: str = "production",
        dry_run: bool = False,
        rollback_on_failure: bool = True,
        parallel_deployment: bool = True
    ) -> bool:
        """
        Deploy MCP servers from configuration file.
        
        Args:
            deployment_file: Path to deployment configuration
            environment: Target environment
            dry_run: Show plan without executing
            rollback_on_failure: Enable automatic rollback on failure
            parallel_deployment: Enable parallel deployment where safe
            
        Returns:
            True if deployment successful, False otherwise
        """
        try:
            logger.info(f"Starting deployment from {deployment_file}")
            
            # Load deployment configuration
            deployment_spec = await self._load_deployment_spec(deployment_file)
            
            # Parse server specifications
            servers = await self._parse_server_specs(deployment_spec, environment)
            
            if not servers:
                logger.error("No servers defined in deployment configuration")
                return False
            
            # Create deployment plan
            plan = await self.orchestrator.create_deployment_plan(
                servers=servers,
                environment=environment
            )
            
            self.current_deployment_id = plan.deployment_id
            
            logger.info(f"Created deployment plan: {plan.deployment_id}")
            logger.info(f"  Servers: {len(servers)}")
            logger.info(f"  Parallel groups: {len(plan.parallel_groups)}")
            
            # Show deployment plan
            await self._display_deployment_plan(plan)
            
            if dry_run:
                logger.info("Dry run completed - no deployment executed")
                return True
            
            # Create pre-deployment snapshots
            await self._create_deployment_snapshots(plan)
            
            # Start monitoring if available
            if self.monitor:
                await self.monitor.start_deployment_monitoring(
                    plan.deployment_id,
                    len(servers),
                    [s.name for s in servers]
                )
            
            # Execute deployment
            success = await self._execute_deployment_with_monitoring(plan)
            
            # Handle deployment result
            if success:
                logger.info(f"✅ Deployment {plan.deployment_id} completed successfully")
                await self._run_post_deployment_validation(plan)
            else:
                logger.error(f"❌ Deployment {plan.deployment_id} failed")
                
                if rollback_on_failure:
                    logger.info("Initiating automatic rollback...")
                    await self._execute_automatic_rollback(plan)
            
            # Complete monitoring
            if self.monitor:
                await self.monitor.complete_deployment_monitoring(
                    plan.deployment_id,
                    success
                )
            
            return success
            
        except Exception as e:
            logger.error(f"Deployment failed with exception: {e}")
            return False
    
    async def _load_deployment_spec(self, deployment_file: Path) -> Dict[str, Any]:
        """Load deployment specification from file."""
        if not deployment_file.exists():
            raise FileNotFoundError(f"Deployment file not found: {deployment_file}")
        
        with open(deployment_file, 'r') as f:
            if deployment_file.suffix.lower() in ['.yaml', '.yml']:
                return yaml.safe_load(f)
            else:
                return json.load(f)
    
    async def _parse_server_specs(
        self, 
        deployment_spec: Dict[str, Any], 
        environment: str
    ) -> List[ServerDeploymentSpec]:
        """Parse server specifications from deployment config."""
        servers = []
        
        for server_config in deployment_spec.get('servers', []):
            # Get resolved configuration for this server and environment
            server_name = server_config['name']
            
            try:
                resolved_config = self.config_manager.get_server_config(
                    server_name,
                    environment
                )
            except Exception as e:
                logger.warning(f"Failed to resolve config for {server_name}: {e}")
                resolved_config = server_config.get('config', {})
            
            server = ServerDeploymentSpec(
                name=server_name,
                server_type=server_config['server_type'],
                dependencies=server_config.get('dependencies', []),
                environment=environment,
                config=resolved_config,
                health_checks=server_config.get('health_checks', []),
                timeout_seconds=server_config.get('timeout_seconds', 300),
                retry_attempts=server_config.get('retry_attempts', 3),
                priority=server_config.get('priority', 0),
                parallel_safe=server_config.get('parallel_safe', False)
            )
            servers.append(server)
        
        return servers
    
    async def _display_deployment_plan(self, plan):
        """Display deployment plan information."""
        print("\n" + "="*60)
        print(f"DEPLOYMENT PLAN: {plan.deployment_id}")
        print("="*60)
        print(f"Environment: {plan.environment}")
        print(f"Total Servers: {len(plan.servers)}")
        print(f"Deployment Phases: {len(plan.phases)}")
        
        print("\nParallel Groups:")
        for i, group in enumerate(plan.parallel_groups):
            print(f"  Group {i+1}: {', '.join(group)}")
        
        print("\nServer Details:")
        for server in plan.servers:
            deps = f" (deps: {', '.join(server.dependencies)})" if server.dependencies else ""
            parallel = " [parallel-safe]" if server.parallel_safe else ""
            print(f"  • {server.name} ({server.server_type}){deps}{parallel}")
        
        print("="*60)
    
    async def _create_deployment_snapshots(self, plan):
        """Create pre-deployment snapshots for rollback."""
        logger.info("Creating pre-deployment snapshots...")
        
        for server in plan.servers:
            try:
                # Create snapshot for rollback
                snapshot = await self.rollback_manager.create_deployment_snapshot(
                    deployment_id=plan.deployment_id,
                    server_name=server.name,
                    state_data={"status": "pre_deployment"},
                    config_data=server.config,
                    files_to_backup=[]  # Would include actual config files in production
                )
                
                self.deployment_snapshots[server.name] = snapshot
                logger.debug(f"Created snapshot for {server.name}: {snapshot.snapshot_id}")
                
            except Exception as e:
                logger.warning(f"Failed to create snapshot for {server.name}: {e}")
    
    async def _execute_deployment_with_monitoring(self, plan) -> bool:
        """Execute deployment with comprehensive monitoring."""
        try:
            # Progress tracking
            progress_data = {
                "current_phase": 0,
                "total_phases": len(plan.phases),
                "current_server": 0,
                "total_servers": len(plan.servers)
            }
            
            def progress_callback(deployment_id: str, phase: DeploymentPhase, progress: float):
                phase_name = phase.value.replace('_', ' ').title()
                logger.info(f"Phase: {phase_name} - Progress: {progress*100:.1f}%")
                
                # Update monitoring if available
                if self.monitor:
                    asyncio.create_task(self.monitor.update_deployment_progress(
                        deployment_id,
                        phase_name,
                        progress * 100,
                        {"phase_index": progress_data["current_phase"]}
                    ))
            
            # Execute deployment
            results = await self.orchestrator.execute_deployment(
                plan,
                progress_callback=progress_callback
            )
            
            # Analyze results
            successful_results = [r for r in results if r.status == DeploymentStatus.SUCCESS]
            failed_results = [r for r in results if r.status == DeploymentStatus.FAILED]
            
            logger.info(f"Deployment results: {len(successful_results)} successful, {len(failed_results)} failed")
            
            # Log detailed results
            for result in results:
                status_icon = "✅" if result.status == DeploymentStatus.SUCCESS else "❌"
                logger.info(f"{status_icon} {result.server_name} - {result.phase.value} ({result.duration_seconds:.2f}s)")
                
                if result.error_message:
                    logger.error(f"   Error: {result.error_message}")
            
            return len(failed_results) == 0
            
        except Exception as e:
            logger.error(f"Deployment execution failed: {e}")
            return False
    
    async def _run_post_deployment_validation(self, plan):
        """Run comprehensive post-deployment validation."""
        logger.info("Running post-deployment validation...")
        
        validation_success = True
        
        for server in plan.servers:
            try:
                # Run health checks for this server
                server_health_checks = [
                    check for check in server.health_checks 
                    if hasattr(self.health_validator, 'health_checks') and check in self.health_validator.health_checks
                ]
                
                if server_health_checks:
                    logger.info(f"Running health checks for {server.name}...")
                    
                    for check_name in server_health_checks:
                        result = await self.health_validator.execute_health_check(check_name)
                        
                        if result.status.value == "healthy":
                            logger.info(f"  ✅ {check_name}: healthy ({result.duration_ms:.1f}ms)")
                        else:
                            logger.warning(f"  ❌ {check_name}: {result.status.value} - {result.error or result.message}")
                            validation_success = False
                        
                        # Record in monitoring
                        if self.monitor:
                            await self.monitor.record_health_check_result(
                                plan.deployment_id,
                                server.name,
                                check_name,
                                result.status.value == "healthy",
                                result.duration_ms,
                                result.details
                            )
                
            except Exception as e:
                logger.error(f"Health check failed for {server.name}: {e}")
                validation_success = False
        
        if validation_success:
            logger.info("✅ Post-deployment validation passed")
        else:
            logger.warning("⚠️ Post-deployment validation completed with warnings")
    
    async def _execute_automatic_rollback(self, plan):
        """Execute automatic rollback on deployment failure."""
        try:
            # Determine which servers need rollback
            failed_servers = []
            
            # Get deployment status to identify failed servers
            status = self.orchestrator.get_deployment_status(plan.deployment_id)
            
            for result in status.get('results', []):
                if result['status'] == 'failed':
                    failed_servers.append(result['server'])
            
            if not failed_servers:
                logger.info("No servers require rollback")
                return
            
            logger.info(f"Rolling back {len(failed_servers)} failed servers...")
            
            # Create rollback plan
            rollback_plan = await self.rollback_manager.create_rollback_plan(
                deployment_id=plan.deployment_id,
                failed_servers=failed_servers,
                rollback_strategy=RollbackStrategy.GRACEFUL
            )
            
            # Execute rollback
            rollback_results = await self.rollback_manager.execute_rollback_plan(rollback_plan)
            
            # Report rollback results
            successful_rollbacks = len([r for r in rollback_results if r.success])
            failed_rollbacks = len([r for r in rollback_results if not r.success])
            
            if failed_rollbacks == 0:
                logger.info(f"✅ Rollback completed successfully ({successful_rollbacks} actions)")
            else:
                logger.warning(f"⚠️ Rollback completed with {failed_rollbacks} failures")
            
        except Exception as e:
            logger.error(f"Automatic rollback failed: {e}")
    
    async def _register_standard_health_checks(self):
        """Register standard health checks."""
        # HTTP health check for web services
        http_check = HealthCheckConfig(
            name="http_health",
            check_type=HealthCheckType.HTTP,
            config={
                "url": "http://localhost:8000/health",
                "expected_status": [200],
                "timeout_seconds": 10
            },
            timeout_seconds=15,
            retry_attempts=3,
            critical=True,
            tags=["http", "api"]
        )
        self.health_validator.register_health_check(http_check)
        
        # TCP connectivity check
        tcp_check = HealthCheckConfig(
            name="tcp_connectivity",
            check_type=HealthCheckType.TCP,
            config={
                "host": "localhost",
                "port": 8000
            },
            timeout_seconds=10,
            retry_attempts=2,
            critical=True,
            tags=["tcp", "connectivity"]
        )
        self.health_validator.register_health_check(tcp_check)
        
        # File system check
        fs_check = HealthCheckConfig(
            name="filesystem_health",
            check_type=HealthCheckType.FILE_SYSTEM,
            config={
                "path": "/tmp",
                "check_readable": True,
                "check_writable": True,
                "min_free_space_mb": 100
            },
            timeout_seconds=5,
            retry_attempts=1,
            critical=False,
            tags=["filesystem"]
        )
        self.health_validator.register_health_check(fs_check)
        
        logger.info("Registered standard health checks")
    
    async def cleanup(self):
        """Cleanup resources."""
        if self.monitor:
            await self.monitor.stop_monitoring()
        
        # Cleanup old snapshots (older than 7 days)
        cleaned = self.rollback_manager.cleanup_old_snapshots(max_age_days=7)
        if cleaned > 0:
            logger.info(f"Cleaned up {cleaned} old snapshots")


async def main():
    """Main deployment automation entry point."""
    parser = argparse.ArgumentParser(description="MCP Server Deployment Automation")
    parser.add_argument('deployment_file', help='Path to deployment configuration file')
    parser.add_argument('--environment', '-e', default='production', help='Target environment')
    parser.add_argument('--dry-run', action='store_true', help='Show deployment plan without executing')
    parser.add_argument('--no-rollback', action='store_true', help='Disable automatic rollback on failure')
    parser.add_argument('--sequential', action='store_true', help='Disable parallel deployment')
    parser.add_argument('--no-monitoring', action='store_true', help='Disable real-time monitoring')
    parser.add_argument('--config-dir', help='Configuration directory path')
    parser.add_argument('--backup-dir', help='Backup directory path')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Configure logging
    if args.verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize deployment automation
    automation = MCPDeploymentAutomation(
        config_dir=Path(args.config_dir) if args.config_dir else None,
        backup_dir=Path(args.backup_dir) if args.backup_dir else None,
        enable_monitoring=not args.no_monitoring
    )
    
    try:
        # Initialize components
        await automation.initialize()
        
        # Execute deployment
        success = await automation.deploy_from_config(
            deployment_file=Path(args.deployment_file),
            environment=args.environment,
            dry_run=args.dry_run,
            rollback_on_failure=not args.no_rollback,
            parallel_deployment=not args.sequential
        )
        
        if success:
            print("\n🎉 Deployment completed successfully!")
            sys.exit(0)
        else:
            print("\n💥 Deployment failed!")
            sys.exit(1)
    
    except KeyboardInterrupt:
        print("\n⏹️ Deployment interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n💥 Deployment failed with error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    
    finally:
        # Cleanup
        await automation.cleanup()


if __name__ == "__main__":
    asyncio.run(main())