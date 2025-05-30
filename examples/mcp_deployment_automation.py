#!/usr/bin/env python3
"""
MCP Deployment Automation Example for CODE Project

Demonstrates AI-powered infrastructure deployment using integrated MCP servers.
This example shows how the Circle of Experts can now execute deployment
recommendations automatically through MCP server integrations.
"""

import asyncio
import sys
import os
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from mcp.manager import get_mcp_manager


class MCPDeploymentAutomation:
    """
    Automated deployment orchestrator using MCP servers.
    
    Demonstrates the enhanced CODE project capabilities where AI recommendations
    are automatically executed through infrastructure automation.
    """
    
    def __init__(self):
        self.mcp_manager = None
        self.context_id = f"deployment_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.deployment_log: List[Dict[str, Any]] = []
    
    async def initialize(self):
        """Initialize MCP manager and enable required servers."""
        print("🚀 Initializing MCP Deployment Automation")
        print("=" * 50)
        
        self.mcp_manager = get_mcp_manager()
        await self.mcp_manager.initialize()
        
        # Create deployment context
        context = self.mcp_manager.create_context(self.context_id)
        
        # Enable core deployment servers
        deployment_servers = [
            "desktop-commander",
            "docker",
            "kubernetes", 
            "security-scanner",
            "slack-notifications",
            "s3-storage",
            "prometheus-monitoring"
        ]
        
        for server in deployment_servers:
            self.mcp_manager.enable_server(self.context_id, server)
            print(f"  ✅ Enabled {server}")
        
        print(f"\n📋 Deployment context: {self.context_id}")
        return True
    
    async def run_security_assessment(self) -> Dict[str, Any]:
        """Run comprehensive security assessment before deployment."""
        print("\n🔒 Running Pre-Deployment Security Assessment...")
        
        security_results = {}
        
        try:
            # Scan current directory for security issues
            file_scan = await self.mcp_manager.call_tool(
                "security-scanner.file_security_scan",
                {"file_path": ".", "scan_type": "all"},
                self.context_id
            )
            
            security_results["file_scan"] = {
                "findings": len(file_scan.get("findings", [])),
                "status": "clean" if len(file_scan.get("findings", [])) == 0 else "issues_found"
            }
            print(f"  📁 File scan: {security_results['file_scan']['findings']} findings")
            
            # Check npm dependencies if package.json exists
            if Path("package.json").exists():
                npm_audit = await self.mcp_manager.call_tool(
                    "security-scanner.npm_audit",
                    {"package_json_path": "package.json", "audit_level": "moderate"},
                    self.context_id
                )
                
                vulnerabilities = npm_audit.get("vulnerabilities", {})
                security_results["npm_audit"] = {
                    "vulnerabilities": len(vulnerabilities),
                    "status": "clean" if len(vulnerabilities) == 0 else "vulnerabilities_found"
                }
                print(f"  📦 NPM audit: {security_results['npm_audit']['vulnerabilities']} vulnerabilities")
            
            # Check Python dependencies if requirements.txt exists
            if Path("requirements.txt").exists():
                try:
                    python_safety = await self.mcp_manager.call_tool(
                        "security-scanner.python_safety_check",
                        {"requirements_path": "requirements.txt"},
                        self.context_id
                    )
                    
                    vulns = python_safety.get("vulnerabilities", [])
                    security_results["python_safety"] = {
                        "vulnerabilities": len(vulns) if isinstance(vulns, list) else 0,
                        "status": "clean" if len(vulns) == 0 else "vulnerabilities_found"
                    }
                    print(f"  🐍 Python safety: {security_results['python_safety']['vulnerabilities']} vulnerabilities")
                except Exception as e:
                    print(f"  ⚠️  Python safety check: {str(e)[:50]}...")
            
        except Exception as e:
            print(f"  ❌ Security assessment error: {e}")
            security_results["error"] = str(e)
        
        self.deployment_log.append({
            "step": "security_assessment",
            "timestamp": datetime.now().isoformat(),
            "results": security_results
        })
        
        return security_results
    
    async def prepare_deployment_environment(self) -> Dict[str, Any]:
        """Prepare deployment environment using MCP servers."""
        print("\n🏗️  Preparing Deployment Environment...")
        
        preparation_results = {}
        
        try:
            # Create deployment directory structure
            directories_result = await self.mcp_manager.call_tool(
                "desktop-commander.execute_command",
                {"command": "mkdir -p deploy/{config,logs,backup}"},
                self.context_id
            )
            
            preparation_results["directories"] = {
                "success": directories_result.get("success", False),
                "command": directories_result.get("command", "")
            }
            print(f"  📁 Directory structure: {'✅' if preparation_results['directories']['success'] else '❌'}")
            
            # Check Docker availability
            docker_check = await self.mcp_manager.call_tool(
                "docker.docker_ps",
                {"all": False},
                self.context_id
            )
            
            preparation_results["docker"] = {
                "available": docker_check.get("success", False),
                "containers": len(docker_check.get("containers", []))
            }
            print(f"  🐳 Docker: {'✅ Available' if preparation_results['docker']['available'] else '❌ Not available'}")
            
            # Check Kubernetes connectivity
            try:
                k8s_check = await self.mcp_manager.call_tool(
                    "kubernetes.kubectl_get",
                    {"resource_type": "nodes"},
                    self.context_id
                )
                
                preparation_results["kubernetes"] = {
                    "available": k8s_check.get("success", False),
                    "cluster": "connected" if k8s_check.get("success", False) else "not_connected"
                }
                print(f"  ☸️  Kubernetes: {'✅ Connected' if preparation_results['kubernetes']['available'] else '❌ Not connected'}")
            except Exception:
                preparation_results["kubernetes"] = {"available": False, "cluster": "not_configured"}
                print("  ☸️  Kubernetes: ❌ Not configured")
            
            # Test cloud storage connectivity
            try:
                s3_check = await self.mcp_manager.call_tool(
                    "s3-storage.s3_list_buckets",
                    {},
                    self.context_id
                )
                
                preparation_results["s3"] = {
                    "available": s3_check.get("success", False),
                    "buckets": len(s3_check.get("buckets", []))
                }
                print(f"  ☁️  S3 Storage: {'✅ Connected' if preparation_results['s3']['available'] else '❌ Not configured'}")
            except Exception:
                preparation_results["s3"] = {"available": False, "buckets": 0}
                print("  ☁️  S3 Storage: ❌ Not configured")
            
        except Exception as e:
            print(f"  ❌ Environment preparation error: {e}")
            preparation_results["error"] = str(e)
        
        self.deployment_log.append({
            "step": "environment_preparation",
            "timestamp": datetime.now().isoformat(),
            "results": preparation_results
        })
        
        return preparation_results
    
    async def execute_deployment_workflow(self) -> Dict[str, Any]:
        """Execute automated deployment workflow."""
        print("\n🚀 Executing Deployment Workflow...")
        
        deployment_results = {}
        
        try:
            # Step 1: Build application (if Dockerfile exists)
            if Path("Dockerfile").exists():
                print("  🔨 Building Docker image...")
                build_result = await self.mcp_manager.call_tool(
                    "docker.docker_build",
                    {
                        "dockerfile_path": "Dockerfile",
                        "image_tag": "code-project:latest",
                        "build_context": "."
                    },
                    self.context_id
                )
                
                deployment_results["docker_build"] = {
                    "success": build_result.get("success", False),
                    "image_tag": build_result.get("image_tag", "")
                }
                print(f"    {'✅' if deployment_results['docker_build']['success'] else '❌'} Docker build")
            
            # Step 2: Run deployment commands using make
            make_targets = ["quality", "test", "docker-build"]
            deployment_results["make_commands"] = {}
            
            for target in make_targets:
                try:
                    make_result = await self.mcp_manager.call_tool(
                        "desktop-commander.make_command",
                        {"target": target},
                        self.context_id
                    )
                    
                    deployment_results["make_commands"][target] = {
                        "success": make_result.get("success", False),
                        "exit_code": make_result.get("exit_code", -1)
                    }
                    print(f"    {'✅' if deployment_results['make_commands'][target]['success'] else '❌'} make {target}")
                    
                except Exception as e:
                    print(f"    ⚠️  make {target}: {str(e)[:50]}...")
                    deployment_results["make_commands"][target] = {"success": False, "error": str(e)}
            
            # Step 3: Deploy to Kubernetes (if configured)
            try:
                if Path("k8s").exists():
                    k8s_deploy = await self.mcp_manager.call_tool(
                        "kubernetes.kubectl_apply",
                        {"manifest_path": "k8s/", "namespace": "default"},
                        self.context_id
                    )
                    
                    deployment_results["kubernetes_deploy"] = {
                        "success": k8s_deploy.get("success", False),
                        "namespace": k8s_deploy.get("namespace", "default")
                    }
                    print(f"    {'✅' if deployment_results['kubernetes_deploy']['success'] else '❌'} Kubernetes deployment")
            except Exception as e:
                print(f"    ⚠️  Kubernetes deployment: {str(e)[:50]}...")
        
        except Exception as e:
            print(f"  ❌ Deployment workflow error: {e}")
            deployment_results["error"] = str(e)
        
        self.deployment_log.append({
            "step": "deployment_execution",
            "timestamp": datetime.now().isoformat(),
            "results": deployment_results
        })
        
        return deployment_results
    
    async def send_deployment_notification(self, deployment_summary: Dict[str, Any]):
        """Send deployment notification via Slack."""
        print("\n📢 Sending Deployment Notification...")
        
        try:
            # Determine overall deployment status
            overall_success = all(
                step.get("results", {}).get("success", False) 
                for step in self.deployment_log 
                if "success" in step.get("results", {})
            )
            
            status = "success" if overall_success else "warning"
            
            # Send Slack notification
            notification_result = await self.mcp_manager.call_tool(
                "slack-notifications.send_notification",
                {
                    "channel": "#deployments",
                    "event_type": "deployment",
                    "status": status,
                    "details": {
                        "project": "CODE",
                        "timestamp": datetime.now().isoformat(),
                        "deployment_id": self.context_id,
                        "steps_completed": len(self.deployment_log),
                        "overall_status": status,
                        "summary": f"Deployment {'completed successfully' if overall_success else 'completed with warnings'}"
                    }
                },
                self.context_id
            )
            
            print(f"  {'✅' if notification_result.get('success', False) else '⚠️'} Slack notification sent")
            
        except Exception as e:
            print(f"  ⚠️  Notification (expected without Slack config): {str(e)[:50]}...")
    
    async def generate_deployment_report(self) -> Dict[str, Any]:
        """Generate comprehensive deployment report."""
        print("\n📊 Generating Deployment Report...")
        
        report = {
            "deployment_id": self.context_id,
            "timestamp": datetime.now().isoformat(),
            "steps": self.deployment_log,
            "summary": {
                "total_steps": len(self.deployment_log),
                "successful_steps": len([
                    step for step in self.deployment_log 
                    if not step.get("results", {}).get("error")
                ]),
                "duration_minutes": len(self.deployment_log) * 2,  # Estimated
                "status": "completed"
            }
        }
        
        # Save report to file
        report_path = Path("deploy/logs") / f"deployment_report_{self.context_id}.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            await self.mcp_manager.call_tool(
                "desktop-commander.write_file",
                {
                    "file_path": str(report_path),
                    "content": json.dumps(report, indent=2)
                },
                self.context_id
            )
            print(f"  📄 Report saved: {report_path}")
        except Exception as e:
            print(f"  ⚠️  Report save error: {e}")
        
        # Display summary
        print(f"\n📈 Deployment Summary:")
        print(f"  • Deployment ID: {report['deployment_id']}")
        print(f"  • Total Steps: {report['summary']['total_steps']}")
        print(f"  • Successful Steps: {report['summary']['successful_steps']}")
        print(f"  • Status: {report['summary']['status'].title()}")
        
        return report
    
    async def cleanup(self):
        """Cleanup MCP resources."""
        if self.mcp_manager:
            await self.mcp_manager.cleanup()


async def demonstrate_mcp_deployment():
    """Demonstrate comprehensive MCP-powered deployment automation."""
    print("🎪 CODE Project: MCP-Powered Deployment Automation Demo")
    print("=" * 60)
    print("This demonstrates how the Circle of Experts can now execute")
    print("deployment recommendations automatically through MCP servers.")
    print()
    
    automation = MCPDeploymentAutomation()
    
    try:
        # Initialize automation system
        await automation.initialize()
        
        # Run deployment workflow
        security_results = await automation.run_security_assessment()
        environment_results = await automation.prepare_deployment_environment()
        deployment_results = await automation.execute_deployment_workflow()
        
        # Generate comprehensive summary
        deployment_summary = {
            "security": security_results,
            "environment": environment_results,
            "deployment": deployment_results
        }
        
        # Send notifications and generate report
        await automation.send_deployment_notification(deployment_summary)
        report = await automation.generate_deployment_report()
        
        print("\n🎯 MCP Integration Benefits Demonstrated:")
        print("  ✅ Automated security scanning")
        print("  ✅ Infrastructure environment preparation")
        print("  ✅ Multi-platform deployment orchestration")
        print("  ✅ Real-time notification system")
        print("  ✅ Comprehensive reporting and audit trails")
        print("  ✅ Cross-tool integration and automation")
        
        print("\n💡 Circle of Experts Enhancement:")
        print("  • AI recommendations → Automated execution")
        print("  • Multi-AI consensus → Infrastructure actions")
        print("  • Expert validation → Real-time deployment")
        print("  • Performance analysis → Optimization actions")
        
        return report
        
    except Exception as e:
        print(f"\n💥 Deployment automation error: {e}")
        import traceback
        traceback.print_exc()
        
    finally:
        await automation.cleanup()


if __name__ == "__main__":
    print("🚀 Starting MCP Deployment Automation Demonstration...")
    print()
    
    try:
        result = asyncio.run(demonstrate_mcp_deployment())
        print("\n🎉 MCP Deployment Automation Demo Complete!")
        
    except KeyboardInterrupt:
        print("\n⏹️  Demo interrupted by user")
    except Exception as e:
        print(f"\n💥 Demo failed: {e}")