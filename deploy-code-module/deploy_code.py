#!/usr/bin/env python3
"""
Deploy CODE Module - Python Integration Layer
Provides a Python API for the Rust deployment orchestrator
"""

import asyncio
import json
import logging
import os
import subprocess
import sys
import time
import yaml
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import aiohttp
import psutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('deploy-code')


class DeploymentStatus(Enum):
    """Deployment status enumeration"""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class ServiceStatus(Enum):
    """Service status enumeration"""
    NOT_STARTED = "not_started"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"
    UNKNOWN = "unknown"


@dataclass
class ServiceInfo:
    """Service information dataclass"""
    name: str
    status: ServiceStatus
    health: str
    pid: Optional[int] = None
    port: Optional[int] = None
    cpu_usage: Optional[float] = None
    memory_usage: Optional[float] = None
    uptime: Optional[float] = None
    message: Optional[str] = None


@dataclass
class DeploymentReport:
    """Deployment report dataclass"""
    success: bool
    total_services: int
    deployed_services: int
    failed_services: int
    warnings: int
    duration: float
    phases_completed: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


class DeployCodeError(Exception):
    """Custom exception for deployment errors"""
    pass


class DeployCode:
    """Main deployment orchestrator class"""
    
    def __init__(self, config_path: str = "deploy-code.yaml", dry_run: bool = False, force: bool = False):
        self.config_path = Path(config_path)
        self.dry_run = dry_run
        self.force = force
        self.binary_path = self._find_binary()
        self.config = self._load_config()
        self.process = None
        self._api_session = None
        
    def _find_binary(self) -> Path:
        """Find the deploy-code binary"""
        # Check common locations
        locations = [
            Path(__file__).parent / "target/release/deploy-code",
            Path(__file__).parent / "target/debug/deploy-code",
            Path("/usr/local/bin/deploy-code"),
            Path("/usr/bin/deploy-code"),
        ]
        
        # Check PATH
        try:
            result = subprocess.run(["which", "deploy-code"], capture_output=True, text=True)
            if result.returncode == 0:
                locations.insert(0, Path(result.stdout.strip()))
        except:
            pass
        
        for path in locations:
            if path.exists() and path.is_file():
                return path
        
        raise DeployCodeError("deploy-code binary not found. Please build it first.")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load deployment configuration"""
        if not self.config_path.exists():
            raise DeployCodeError(f"Configuration file not found: {self.config_path}")
        
        with open(self.config_path, 'r') as f:
            if self.config_path.suffix in ['.yaml', '.yml']:
                return yaml.safe_load(f)
            elif self.config_path.suffix == '.json':
                return json.load(f)
            else:
                raise DeployCodeError(f"Unsupported config format: {self.config_path.suffix}")
    
    async def deploy(self, services: Optional[List[str]] = None, skip_phases: Optional[List[str]] = None) -> DeploymentReport:
        """Deploy CODE services"""
        logger.info("Starting CODE deployment...")
        
        cmd = [str(self.binary_path), "deploy"]
        
        if self.dry_run:
            cmd.append("--dry-run")
        
        if self.force:
            cmd.append("--force")
        
        if services:
            cmd.extend(["--services", ",".join(services)])
        
        if skip_phases:
            cmd.extend(["--skip-phases", ",".join(skip_phases)])
        
        cmd.extend(["--config", str(self.config_path)])
        
        # Execute deployment
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else stdout.decode()
                raise DeployCodeError(f"Deployment failed: {error_msg}")
            
            # Parse output to create report
            output = stdout.decode()
            return self._parse_deployment_output(output)
            
        except Exception as e:
            logger.error(f"Deployment error: {e}")
            raise
    
    async def stop(self, timeout: int = 30) -> None:
        """Stop all CODE services"""
        logger.info("Stopping all CODE services...")
        
        cmd = [str(self.binary_path), "stop", "--timeout", str(timeout)]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            error_msg = stderr.decode() if stderr else stdout.decode()
            raise DeployCodeError(f"Stop failed: {error_msg}")
        
        logger.info("All services stopped successfully")
    
    async def status(self, detailed: bool = False) -> Dict[str, Any]:
        """Get status of all services"""
        cmd = [str(self.binary_path), "status"]
        
        if detailed:
            cmd.append("--detailed")
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            error_msg = stderr.decode() if stderr else stdout.decode()
            raise DeployCodeError(f"Status check failed: {error_msg}")
        
        return self._parse_status_output(stdout.decode())
    
    async def restart(self, services: Optional[List[str]] = None) -> None:
        """Restart services"""
        logger.info(f"Restarting services: {services or 'all'}")
        
        cmd = [str(self.binary_path), "restart"]
        
        if services:
            cmd.extend(["--services", ",".join(services)])
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            error_msg = stderr.decode() if stderr else stdout.decode()
            raise DeployCodeError(f"Restart failed: {error_msg}")
        
        logger.info("Services restarted successfully")
    
    async def validate(self) -> Dict[str, Any]:
        """Validate deployment configuration"""
        cmd = [str(self.binary_path), "validate", "--config", str(self.config_path)]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            output = stderr.decode() if stderr else stdout.decode()
            return {
                "is_valid": False,
                "errors": [output],
                "warnings": []
            }
        
        return {
            "is_valid": True,
            "errors": [],
            "warnings": []
        }
    
    async def health(self, format: str = "json") -> Dict[str, Any]:
        """Get health status"""
        cmd = [str(self.binary_path), "health", "--format", format]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            error_msg = stderr.decode() if stderr else stdout.decode()
            raise DeployCodeError(f"Health check failed: {error_msg}")
        
        if format == "json":
            return json.loads(stdout.decode())
        else:
            return {"output": stdout.decode()}
    
    def _parse_deployment_output(self, output: str) -> DeploymentReport:
        """Parse deployment command output"""
        # Simple parsing - in production, this would parse structured output
        lines = output.strip().split('\n')
        
        report = DeploymentReport(
            success=True,
            total_services=0,
            deployed_services=0,
            failed_services=0,
            warnings=0,
            duration=0.0
        )
        
        for line in lines:
            if "Total services deployed:" in line:
                report.total_services = int(line.split(':')[1].strip())
            elif "Deployment time:" in line:
                report.duration = float(line.split(':')[1].strip().rstrip('s'))
            elif "warnings" in line.lower():
                report.warnings = int(line.split()[0])
            elif "failed" in line.lower():
                report.success = False
        
        return report
    
    def _parse_status_output(self, output: str) -> Dict[str, Any]:
        """Parse status command output"""
        # Simple parsing - in production, this would parse structured output
        lines = output.strip().split('\n')
        
        status = {
            "overall_health": "unknown",
            "total_services": 0,
            "running_services": 0,
            "failed_services": 0,
            "services": {}
        }
        
        for line in lines:
            if "Overall Health:" in line:
                status["overall_health"] = line.split(':')[1].strip()
            elif "Total Services:" in line:
                status["total_services"] = int(line.split(':')[1].strip())
            elif "Running Services:" in line:
                status["running_services"] = int(line.split(':')[1].strip())
            elif "Failed Services:" in line:
                status["failed_services"] = int(line.split(':')[1].strip())
        
        return status
    
    async def wait_for_healthy(self, timeout: int = 300, check_interval: int = 5) -> bool:
        """Wait for all services to become healthy"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                health = await self.health()
                if health.get("status") == "healthy":
                    logger.info("All services are healthy!")
                    return True
            except Exception as e:
                logger.warning(f"Health check error: {e}")
            
            await asyncio.sleep(check_interval)
        
        logger.error(f"Services did not become healthy within {timeout} seconds")
        return False
    
    async def monitor_deployment(self, callback=None):
        """Monitor deployment progress with optional callback"""
        while True:
            try:
                status = await self.status(detailed=True)
                
                if callback:
                    callback(status)
                
                # Check if deployment is complete
                if status.get("deployment_complete", False):
                    break
                
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
            
            await asyncio.sleep(2)
    
    def get_service_logs(self, service: str, lines: int = 100) -> List[str]:
        """Get logs for a specific service"""
        log_dir = self.config.get("infrastructure", {}).get("storage", {}).get("log_dir", "/var/log/deploy-code")
        log_file = Path(log_dir) / f"{service}.log"
        
        if not log_file.exists():
            return []
        
        with open(log_file, 'r') as f:
            return f.readlines()[-lines:]
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get system metrics"""
        return {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory": psutil.virtual_memory()._asdict(),
            "disk": psutil.disk_usage('/')._asdict(),
            "network": psutil.net_io_counters()._asdict() if psutil.net_io_counters() else {},
            "timestamp": time.time()
        }


async def main():
    """Main entry point for CLI usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Deploy CODE - Python CLI")
    parser.add_argument("--config", default="deploy-code.yaml", help="Configuration file path")
    parser.add_argument("--dry-run", action="store_true", help="Dry run mode")
    parser.add_argument("--force", action="store_true", help="Force deployment")
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Deploy command
    deploy_parser = subparsers.add_parser("deploy", help="Deploy services")
    deploy_parser.add_argument("--services", help="Services to deploy (comma-separated)")
    deploy_parser.add_argument("--skip-phases", help="Phases to skip (comma-separated)")
    
    # Stop command
    stop_parser = subparsers.add_parser("stop", help="Stop services")
    stop_parser.add_argument("--timeout", type=int, default=30, help="Timeout in seconds")
    
    # Status command
    status_parser = subparsers.add_parser("status", help="Get status")
    status_parser.add_argument("--detailed", action="store_true", help="Show detailed status")
    
    # Other commands
    subparsers.add_parser("validate", help="Validate configuration")
    subparsers.add_parser("health", help="Get health status")
    
    restart_parser = subparsers.add_parser("restart", help="Restart services")
    restart_parser.add_argument("--services", help="Services to restart (comma-separated)")
    
    args = parser.parse_args()
    
    # Initialize deployer
    deployer = DeployCode(
        config_path=args.config,
        dry_run=args.dry_run,
        force=args.force
    )
    
    try:
        if args.command == "deploy":
            services = args.services.split(",") if args.services else None
            skip_phases = args.skip_phases.split(",") if args.skip_phases else None
            report = await deployer.deploy(services, skip_phases)
            print(f"Deployment {'succeeded' if report.success else 'failed'}")
            print(f"Total services: {report.total_services}")
            print(f"Deployed: {report.deployed_services}")
            print(f"Failed: {report.failed_services}")
            
        elif args.command == "stop":
            await deployer.stop(args.timeout)
            
        elif args.command == "status":
            status = await deployer.status(args.detailed)
            print(json.dumps(status, indent=2))
            
        elif args.command == "validate":
            result = await deployer.validate()
            if result["is_valid"]:
                print("Configuration is valid")
            else:
                print("Configuration is invalid:")
                for error in result["errors"]:
                    print(f"  - {error}")
                    
        elif args.command == "health":
            health = await deployer.health()
            print(json.dumps(health, indent=2))
            
        elif args.command == "restart":
            services = args.services.split(",") if args.services else None
            await deployer.restart(services)
            
        else:
            # Default: deploy all
            report = await deployer.deploy()
            if report.success:
                print("CODE platform deployed successfully!")
                await deployer.wait_for_healthy()
            else:
                print("Deployment failed!")
                sys.exit(1)
                
    except DeployCodeError as e:
        logger.error(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())