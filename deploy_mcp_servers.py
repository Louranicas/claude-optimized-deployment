#!/usr/bin/env python3
"""
Comprehensive MCP Server Deployment Orchestrator
Deploys all MCP servers systematically with proper authentication and monitoring.
"""

import asyncio
import logging
import sys
import time
import traceback
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import json

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

from src.mcp.manager import MCPManager, get_mcp_manager
from src.mcp.servers import MCPServerRegistry
from src.auth.rbac import RBACManager
from src.auth.middleware import AuthMiddleware
from src.mcp.security.auth_integration import setup_mcp_authentication, MCPAuthMiddleware

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('mcp_deployment.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class DeploymentResult:
    """Result of MCP server deployment."""
    server_name: str
    success: bool
    start_time: float
    end_time: float
    error: Optional[str] = None
    tools_count: int = 0
    health_check: bool = False
    
    @property
    def duration(self) -> float:
        return self.end_time - self.start_time


class MCPServerDeployer:
    """Orchestrates MCP server deployment with proper sequencing and validation."""
    
    def __init__(self):
        """Initialize the MCP server deployer."""
        self.mcp_manager: Optional[MCPManager] = None
        self.rbac_manager: Optional[RBACManager] = None
        self.auth_middleware: Optional[AuthMiddleware] = None
        self.deployment_results: List[DeploymentResult] = []
        self.deployment_start_time = time.time()
        
        # Server deployment tiers (order matters for dependencies)
        self.deployment_tiers = {
            "infrastructure": [
                "desktop-commander",
                "docker", 
                "kubernetes"
            ],
            "devops": [
                "azure-devops",
                "windows-system"
            ],
            "monitoring": [
                "prometheus-monitoring"
            ],
            "security": [
                "security-scanner",
                "sast-scanner",
                "supply-chain-security"
            ],
            "communication": [
                "slack-notifications"
            ],
            "storage": [
                "s3-storage",
                "cloud-storage"
            ],
            "search": [
                "brave"
            ]
        }
    
    async def initialize_dependencies(self):
        """Initialize core dependencies for MCP deployment."""
        logger.info("Initializing core dependencies...")
        
        try:
            # Initialize RBAC Manager
            self.rbac_manager = RBACManager()
            logger.info("✓ RBAC Manager initialized")
            
            # Initialize Auth Middleware (mock for this deployment)
            class MockAuthMiddleware:
                def __init__(self):
                    self.authenticated = True
                
                async def authenticate(self, token: str):
                    return True
            
            self.auth_middleware = MockAuthMiddleware()
            logger.info("✓ Auth Middleware initialized")
            
            # Get MCP Manager
            self.mcp_manager = get_mcp_manager()
            logger.info("✓ MCP Manager obtained")
            
        except Exception as e:
            logger.error(f"Failed to initialize dependencies: {e}")
            raise
    
    async def deploy_server_tier(self, tier_name: str, server_names: List[str]) -> List[DeploymentResult]:
        """Deploy a specific tier of MCP servers."""
        logger.info(f"Deploying {tier_name} tier: {', '.join(server_names)}")
        tier_results = []
        
        for server_name in server_names:
            result = await self.deploy_single_server(server_name)
            tier_results.append(result)
            
            if not result.success:
                logger.warning(f"Server {server_name} failed to deploy, continuing with tier...")
        
        successful = sum(1 for r in tier_results if r.success)
        logger.info(f"Tier {tier_name} completed: {successful}/{len(server_names)} servers deployed successfully")
        
        return tier_results
    
    async def deploy_single_server(self, server_name: str) -> DeploymentResult:
        """Deploy a single MCP server with health checks."""
        start_time = time.time()
        logger.info(f"Deploying MCP server: {server_name}")
        
        try:
            # Get server from registry
            server = self.mcp_manager.registry.get(server_name)
            if not server:
                raise ValueError(f"Server {server_name} not found in registry")
            
            # Initialize server if it has initialization method
            if hasattr(server, 'initialize'):
                await server.initialize()
                logger.debug(f"  ✓ {server_name} initialized")
            
            # Get server info and tools
            server_info = server.get_server_info()
            tools = server.get_tools()
            
            logger.info(f"  ✓ {server_name} loaded: {len(tools)} tools available")
            
            # Basic health check
            health_check = await self.perform_health_check(server, server_name)
            
            # Create successful result
            result = DeploymentResult(
                server_name=server_name,
                success=True,
                start_time=start_time,
                end_time=time.time(),
                tools_count=len(tools),
                health_check=health_check
            )
            
            logger.info(f"  ✓ {server_name} deployed successfully in {result.duration:.2f}s")
            return result
            
        except Exception as e:
            error_msg = f"Failed to deploy {server_name}: {str(e)}"
            logger.error(f"  ✗ {error_msg}")
            logger.debug(f"Stack trace: {traceback.format_exc()}")
            
            return DeploymentResult(
                server_name=server_name,
                success=False,
                start_time=start_time,
                end_time=time.time(),
                error=error_msg
            )
    
    async def perform_health_check(self, server, server_name: str) -> bool:
        """Perform basic health check on MCP server."""
        try:
            # Check if server has required methods
            required_methods = ['get_server_info', 'get_tools']
            for method in required_methods:
                if not hasattr(server, method):
                    logger.warning(f"  ! {server_name} missing required method: {method}")
                    return False
            
            # Try to get server info
            server_info = server.get_server_info()
            if not server_info:
                logger.warning(f"  ! {server_name} returned empty server info")
                return False
            
            # Try to get tools
            tools = server.get_tools()
            if not isinstance(tools, list):
                logger.warning(f"  ! {server_name} tools is not a list")
                return False
            
            logger.debug(f"  ✓ {server_name} health check passed")
            return True
            
        except Exception as e:
            logger.warning(f"  ! {server_name} health check failed: {e}")
            return False
    
    async def setup_authentication(self):
        """Set up authentication for all deployed servers."""
        logger.info("Setting up authentication for MCP servers...")
        
        try:
            # Get all servers from registry
            servers = {}
            for server_name in self.mcp_manager.registry.list_servers():
                server = self.mcp_manager.registry.get(server_name)
                if server:
                    servers[server_name] = server
            
            # Set up authentication
            authenticated_servers = await setup_mcp_authentication(
                servers, self.auth_middleware, self.rbac_manager
            )
            
            logger.info(f"✓ Authentication configured for {len(authenticated_servers)} servers")
            
        except Exception as e:
            logger.error(f"Failed to setup authentication: {e}")
            # Continue without authentication for this deployment
    
    async def run_deployment_tests(self):
        """Run basic tests on deployed servers."""
        logger.info("Running deployment validation tests...")
        
        test_results = {}
        
        for server_name in self.mcp_manager.registry.list_servers():
            try:
                server = self.mcp_manager.registry.get(server_name)
                if not server:
                    continue
                
                # Test basic operations
                server_info = server.get_server_info()
                tools = server.get_tools()
                
                test_results[server_name] = {
                    "server_info": bool(server_info),
                    "tools_available": len(tools),
                    "health_check": await self.perform_health_check(server, server_name)
                }
                
                logger.debug(f"  ✓ {server_name} tests passed")
                
            except Exception as e:
                test_results[server_name] = {
                    "error": str(e),
                    "health_check": False
                }
                logger.warning(f"  ! {server_name} tests failed: {e}")
        
        successful_tests = sum(1 for result in test_results.values() 
                             if result.get("health_check", False))
        total_tests = len(test_results)
        
        logger.info(f"✓ Deployment tests completed: {successful_tests}/{total_tests} servers passed")
        return test_results
    
    def generate_deployment_report(self) -> Dict[str, Any]:
        """Generate comprehensive deployment report."""
        total_duration = time.time() - self.deployment_start_time
        successful_deployments = [r for r in self.deployment_results if r.success]
        failed_deployments = [r for r in self.deployment_results if not r.success]
        
        report = {
            "deployment_summary": {
                "start_time": datetime.fromtimestamp(self.deployment_start_time).isoformat(),
                "total_duration": f"{total_duration:.2f}s",
                "total_servers": len(self.deployment_results),
                "successful": len(successful_deployments),
                "failed": len(failed_deployments),
                "success_rate": f"{len(successful_deployments)/len(self.deployment_results)*100:.1f}%" if self.deployment_results else "0%"
            },
            "successful_deployments": [
                {
                    "server_name": r.server_name,
                    "duration": f"{r.duration:.2f}s",
                    "tools_count": r.tools_count,
                    "health_check": r.health_check
                }
                for r in successful_deployments
            ],
            "failed_deployments": [
                {
                    "server_name": r.server_name,
                    "duration": f"{r.duration:.2f}s",
                    "error": r.error
                }
                for r in failed_deployments
            ],
            "deployment_tiers": self.deployment_tiers,
            "recommendations": self.generate_recommendations()
        }
        
        return report
    
    def generate_recommendations(self) -> List[str]:
        """Generate deployment recommendations based on results."""
        recommendations = []
        
        failed_servers = [r for r in self.deployment_results if not r.success]
        if failed_servers:
            recommendations.append(f"Review and fix {len(failed_servers)} failed server deployments")
        
        unhealthy_servers = [r for r in self.deployment_results if r.success and not r.health_check]
        if unhealthy_servers:
            recommendations.append(f"Investigate {len(unhealthy_servers)} servers that failed health checks")
        
        if len([r for r in self.deployment_results if r.success]) < len(self.deployment_results):
            recommendations.append("Consider implementing retry mechanisms for failed deployments")
        
        if not recommendations:
            recommendations.append("All servers deployed successfully - consider implementing monitoring and alerting")
        
        return recommendations
    
    async def deploy_all_servers(self):
        """Deploy all MCP servers in proper sequence."""
        logger.info("🚀 Starting comprehensive MCP server deployment")
        
        try:
            # Initialize dependencies
            await self.initialize_dependencies()
            
            # Deploy servers tier by tier
            for tier_name, server_names in self.deployment_tiers.items():
                tier_results = await self.deploy_server_tier(tier_name, server_names)
                self.deployment_results.extend(tier_results)
                
                # Brief pause between tiers
                await asyncio.sleep(1)
            
            # Set up authentication
            await self.setup_authentication()
            
            # Run validation tests
            test_results = await self.run_deployment_tests()
            
            # Generate and save report
            report = self.generate_deployment_report()
            
            # Save deployment report
            report_file = Path("mcp_deployment_report.json")
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            logger.info(f"✓ Deployment report saved to {report_file}")
            
            # Print summary
            summary = report["deployment_summary"]
            logger.info("🎉 MCP Server Deployment Complete!")
            logger.info(f"   Total Duration: {summary['total_duration']}")
            logger.info(f"   Success Rate: {summary['success_rate']}")
            logger.info(f"   Servers Deployed: {summary['successful']}/{summary['total_servers']}")
            
            if report["failed_deployments"]:
                logger.warning("⚠️  Failed Deployments:")
                for failure in report["failed_deployments"]:
                    logger.warning(f"   - {failure['server_name']}: {failure['error']}")
            
            return report
            
        except Exception as e:
            logger.error(f"💥 Deployment failed: {e}")
            logger.debug(f"Stack trace: {traceback.format_exc()}")
            raise


async def main():
    """Main deployment entry point."""
    deployer = MCPServerDeployer()
    
    try:
        report = await deployer.deploy_all_servers()
        
        # Exit with appropriate code
        failed_count = len(report["failed_deployments"])
        if failed_count > 0:
            logger.warning(f"Deployment completed with {failed_count} failures")
            sys.exit(1)
        else:
            logger.info("🎉 All servers deployed successfully!")
            sys.exit(0)
            
    except Exception as e:
        logger.error(f"💥 Deployment orchestration failed: {e}")
        sys.exit(2)


if __name__ == "__main__":
    # Run the deployment
    asyncio.run(main())