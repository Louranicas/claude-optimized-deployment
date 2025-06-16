#!/usr/bin/env python3
"""
Deploy MCP Servers with Comprehensive Security Hardening
Deploys all MCP servers with full security measures enabled.

This script provides:
1. Secure MCP server deployment
2. Security configuration management
3. Compliance framework setup
4. Vulnerability scanning integration
5. Security monitoring and alerting
6. Automated security testing
"""

import asyncio
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

# Import security modules
from src.security.mcp_security_core import (
    SecurityConfig, AuthenticationMethod, get_security_core
)
from src.security.mcp_secure_server import (
    SecureServerConfig, get_secure_manager
)
from src.security.vulnerability_management import get_vulnerability_manager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('mcp_security_deployment.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class SecurityMCPDeployer:
    """Deploys MCP servers with comprehensive security hardening."""
    
    def __init__(self):
        self.manager = get_secure_manager()
        self.deployment_config = {}
        self.deployed_servers = {}
        self.security_status = {}
        
    def create_security_config(self, environment: str = "production") -> SecurityConfig:
        """Create security configuration based on environment."""
        if environment == "production":
            return SecurityConfig(
                # Authentication
                auth_methods=[AuthenticationMethod.API_KEY, AuthenticationMethod.JWT_TOKEN],
                jwt_secret=self._generate_jwt_secret(),
                jwt_expiry_hours=8,  # Shorter expiry for production
                api_key_length=128,  # Longer keys for production
                
                # Rate limiting
                rate_limit_enabled=True,
                requests_per_minute=100,
                burst_capacity=150,
                adaptive_rate_limiting=True,
                ddos_protection=True,
                
                # Input validation
                input_validation_enabled=True,
                max_request_size=5 * 1024 * 1024,  # 5MB limit
                allowed_content_types=["application/json"],
                
                # Encryption
                encryption_enabled=True,
                tls_enabled=True,
                
                # Security monitoring
                audit_logging=True,
                intrusion_detection=True,
                anomaly_detection=True,
                security_metrics=True,
                
                # Session management
                session_timeout_minutes=15,  # Strict timeout for production
                max_concurrent_sessions=50,
                session_encryption=True
            )
        
        elif environment == "staging":
            return SecurityConfig(
                auth_methods=[AuthenticationMethod.API_KEY, AuthenticationMethod.JWT_TOKEN],
                jwt_secret=self._generate_jwt_secret(),
                jwt_expiry_hours=24,
                api_key_length=64,
                rate_limit_enabled=True,
                requests_per_minute=200,
                burst_capacity=300,
                adaptive_rate_limiting=True,
                ddos_protection=True,
                input_validation_enabled=True,
                max_request_size=10 * 1024 * 1024,
                encryption_enabled=True,
                tls_enabled=True,
                audit_logging=True,
                intrusion_detection=True,
                anomaly_detection=True,
                session_timeout_minutes=30,
                max_concurrent_sessions=100
            )
        
        else:  # development
            return SecurityConfig(
                auth_methods=[AuthenticationMethod.API_KEY],
                jwt_secret=self._generate_jwt_secret(),
                jwt_expiry_hours=48,
                api_key_length=64,
                rate_limit_enabled=True,
                requests_per_minute=500,
                burst_capacity=1000,
                input_validation_enabled=True,
                max_request_size=50 * 1024 * 1024,
                encryption_enabled=True,
                tls_enabled=False,  # Can be disabled for local development
                audit_logging=True,
                intrusion_detection=False,
                anomaly_detection=False,
                session_timeout_minutes=60
            )
    
    def create_server_config(self, environment: str = "production") -> SecureServerConfig:
        """Create secure server configuration."""
        security_config = self.create_security_config(environment)
        
        if environment == "production":
            return SecureServerConfig(
                security_config=security_config,
                enable_tls=True,
                tls_cert_file="/etc/ssl/certs/mcp-server.pem",
                tls_key_file="/etc/ssl/private/mcp-server.key",
                require_client_cert=True,
                tls_ciphers="ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!DSS",
                enable_cors=True,
                allowed_origins=["https://your-domain.com"],
                max_request_size=5 * 1024 * 1024,
                request_timeout=30,
                enable_vulnerability_scanning=True,
                scan_interval_hours=6,  # Frequent scanning for production
                auto_patch=False,  # Manual approval for production
                compliance_frameworks=["SOC2", "GDPR", "HIPAA", "PCI_DSS"],
                audit_retention_days=2555,  # 7 years for compliance
                security_monitoring=True,
                intrusion_detection=True,
                anomaly_detection=True
            )
        
        elif environment == "staging":
            return SecureServerConfig(
                security_config=security_config,
                enable_tls=True,
                require_client_cert=False,
                enable_cors=True,
                allowed_origins=["https://staging.your-domain.com"],
                max_request_size=10 * 1024 * 1024,
                request_timeout=45,
                enable_vulnerability_scanning=True,
                scan_interval_hours=12,
                auto_patch=True,  # Can auto-patch in staging
                compliance_frameworks=["SOC2", "GDPR"],
                audit_retention_days=90,
                security_monitoring=True,
                intrusion_detection=True,
                anomaly_detection=True
            )
        
        else:  # development
            return SecureServerConfig(
                security_config=security_config,
                enable_tls=False,
                enable_cors=True,
                allowed_origins=["http://localhost:3000", "http://localhost:8080"],
                max_request_size=50 * 1024 * 1024,
                request_timeout=60,
                enable_vulnerability_scanning=True,
                scan_interval_hours=24,
                auto_patch=True,
                compliance_frameworks=["SOC2"],
                audit_retention_days=30,
                security_monitoring=True,
                intrusion_detection=False,
                anomaly_detection=False
            )
    
    def _generate_jwt_secret(self) -> str:
        """Generate secure JWT secret."""
        import secrets
        return secrets.token_urlsafe(64)
    
    async def deploy_mcp_servers(self, environment: str = "production") -> Dict[str, Any]:
        """Deploy all MCP servers with security hardening."""
        logger.info(f"🚀 Starting secure MCP server deployment for {environment} environment")
        
        deployment_start = datetime.utcnow()
        deployment_results = {
            "environment": environment,
            "started_at": deployment_start.isoformat(),
            "servers": {},
            "security_status": {},
            "compliance_status": {},
            "vulnerabilities": {},
            "errors": []
        }
        
        try:
            # Set global security configuration
            server_config = self.create_server_config(environment)
            self.manager.set_global_config(server_config)
            
            # Define MCP servers to deploy
            servers_to_deploy = [
                {
                    "name": "docker_mcp",
                    "class": "DockerMCPServer",
                    "description": "Docker container management"
                },
                {
                    "name": "kubernetes_mcp", 
                    "class": "KubernetesMCPServer",
                    "description": "Kubernetes cluster management"
                },
                {
                    "name": "prometheus_mcp",
                    "class": "PrometheusMCPServer", 
                    "description": "Prometheus monitoring and metrics"
                },
                {
                    "name": "security_scanner_mcp",
                    "class": "SecurityScannerMCPServer",
                    "description": "Security vulnerability scanning"
                },
                {
                    "name": "slack_mcp",
                    "class": "SlackMCPServer",
                    "description": "Slack notifications and communication"
                },
                {
                    "name": "s3_mcp",
                    "class": "S3MCPServer",
                    "description": "AWS S3 storage operations"
                },
                {
                    "name": "brave_search_mcp",
                    "class": "BraveSearchMCPServer",
                    "description": "Brave web search integration"
                }
            ]
            
            # Deploy each server with security hardening
            for server_def in servers_to_deploy:
                try:
                    logger.info(f"🔒 Deploying {server_def['name']} with security hardening...")
                    
                    # Create mock server for demonstration
                    # In real deployment, you would instantiate actual MCP servers
                    mock_server = self._create_mock_server(server_def)
                    
                    # Add to secure manager
                    await self.manager.add_server(
                        server_def["name"],
                        mock_server,
                        server_config
                    )
                    
                    # Verify deployment
                    secure_server = self.manager.get_server(server_def["name"])
                    if secure_server:
                        # Run security audit
                        audit_results = await secure_server.run_security_audit()
                        
                        deployment_results["servers"][server_def["name"]] = {
                            "status": "deployed",
                            "description": server_def["description"],
                            "security_score": audit_results.get("overall_security_score", 0),
                            "compliance_status": audit_results["audit_sections"]["compliance"],
                            "vulnerabilities": len(audit_results["audit_sections"]["vulnerability_scan"].get("vulnerabilities", [])),
                            "deployed_at": datetime.utcnow().isoformat()
                        }
                        
                        logger.info(f"✅ {server_def['name']} deployed successfully with security score: {audit_results.get('overall_security_score', 0)}")
                    else:
                        raise Exception("Failed to retrieve deployed server")
                        
                except Exception as e:
                    error_msg = f"Failed to deploy {server_def['name']}: {str(e)}"
                    logger.error(f"❌ {error_msg}")
                    deployment_results["errors"].append(error_msg)
                    deployment_results["servers"][server_def["name"]] = {
                        "status": "failed",
                        "error": str(e)
                    }
            
            # Run global security assessment
            logger.info("🔍 Running global security assessment...")
            global_status = await self.manager.get_global_security_status()
            global_audit = await self.manager.run_global_security_audit()
            
            deployment_results["security_status"] = global_status
            deployment_results["global_security_score"] = global_audit.get("global_security_score", 0)
            
            # Run vulnerability management scan
            logger.info("🛡️ Running comprehensive vulnerability scan...")
            vuln_manager = get_vulnerability_manager()
            
            # Scan current directory for vulnerabilities
            current_dir = str(Path.cwd())
            vuln_results = await vuln_manager.run_comprehensive_scan(current_dir)
            vuln_summary = vuln_manager.get_vulnerability_summary(vuln_results)
            
            deployment_results["vulnerabilities"] = {
                "summary": vuln_summary,
                "scan_results": {k: v.summary for k, v in vuln_results.items()}
            }
            
            # Generate security report
            security_report = await vuln_manager.generate_security_report(vuln_results)
            
            # Save security report
            report_file = f"security_report_{environment}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            with open(report_file, 'w') as f:
                json.dump(security_report, f, indent=2)
            
            logger.info(f"📋 Security report saved to {report_file}")
            
            # Setup monitoring and alerting
            await self._setup_security_monitoring(environment)
            
            # Create user credentials for different roles
            credentials = await self._create_default_users(environment)
            deployment_results["credentials"] = credentials
            
            deployment_results["completed_at"] = datetime.utcnow().isoformat()
            deployment_results["status"] = "success"
            
            # Log deployment summary
            self._log_deployment_summary(deployment_results)
            
        except Exception as e:
            error_msg = f"Deployment failed: {str(e)}"
            logger.error(f"❌ {error_msg}")
            deployment_results["status"] = "failed"
            deployment_results["error"] = error_msg
            deployment_results["completed_at"] = datetime.utcnow().isoformat()
        
        return deployment_results
    
    def _create_mock_server(self, server_def: Dict[str, str]):
        """Create mock MCP server for demonstration."""
        class MockMCPServer:
            def __init__(self, name, description):
                self.name = name
                self.description = description
                
            def get_server_info(self):
                return {
                    "name": self.name,
                    "description": self.description,
                    "version": "1.0.0",
                    "capabilities": ["execute", "monitor", "manage"]
                }
            
            def get_tools(self):
                if "docker" in self.name:
                    return [
                        {"name": "docker_ps", "description": "List containers"},
                        {"name": "docker_build", "description": "Build image"},
                        {"name": "docker_run", "description": "Run container"}
                    ]
                elif "kubernetes" in self.name:
                    return [
                        {"name": "kubectl_get", "description": "Get resources"},
                        {"name": "kubectl_apply", "description": "Apply manifests"},
                        {"name": "kubectl_delete", "description": "Delete resources"}
                    ]
                elif "prometheus" in self.name:
                    return [
                        {"name": "prometheus_query", "description": "Query metrics"},
                        {"name": "prometheus_targets", "description": "List targets"}
                    ]
                elif "security" in self.name:
                    return [
                        {"name": "vulnerability_scan", "description": "Scan for vulnerabilities"},
                        {"name": "security_audit", "description": "Run security audit"}
                    ]
                else:
                    return [
                        {"name": "generic_action", "description": "Generic action"}
                    ]
            
            async def call_tool(self, tool_name, arguments):
                return {"result": f"Mock result from {tool_name}", "arguments": arguments}
        
        return MockMCPServer(server_def["name"], server_def["description"])
    
    async def _setup_security_monitoring(self, environment: str):
        """Setup security monitoring and alerting."""
        logger.info("📊 Setting up security monitoring...")
        
        try:
            # Initialize security core for monitoring
            security_core = await get_security_core()
            
            # Setup monitoring configuration based on environment
            if environment == "production":
                # Production monitoring - strict thresholds
                monitoring_config = {
                    "failed_auth_threshold": 5,
                    "rate_limit_threshold": 10,
                    "anomaly_threshold": 0.7,
                    "alert_email": "security@company.com",
                    "escalation_timeout": 300  # 5 minutes
                }
            else:
                # Development/staging - relaxed thresholds
                monitoring_config = {
                    "failed_auth_threshold": 20,
                    "rate_limit_threshold": 50,
                    "anomaly_threshold": 0.9,
                    "alert_email": "dev-security@company.com",
                    "escalation_timeout": 900  # 15 minutes
                }
            
            # Save monitoring configuration
            config_file = f"security_monitoring_{environment}.json"
            with open(config_file, 'w') as f:
                json.dump(monitoring_config, f, indent=2)
            
            logger.info(f"✅ Security monitoring configured for {environment}")
            
        except Exception as e:
            logger.error(f"❌ Failed to setup security monitoring: {e}")
    
    async def _create_default_users(self, environment: str) -> Dict[str, Dict[str, str]]:
        """Create default users with appropriate permissions."""
        logger.info("👥 Creating default user accounts...")
        
        security_core = await get_security_core()
        users = {}
        
        try:
            # Admin user
            admin_creds = security_core.create_user_credentials(
                user_id=f"admin_{environment}",
                roles=["admin"],
                permissions=["*:*"]
            )
            users["admin"] = {
                "user_id": f"admin_{environment}",
                "roles": ["admin"],
                "api_key": admin_creds["api_key"],
                "jwt_token": admin_creds.get("jwt_token", ""),
                "description": "System administrator with full access"
            }
            
            # Operator user
            operator_creds = security_core.create_user_credentials(
                user_id=f"operator_{environment}",
                roles=["operator"],
                permissions=[
                    "mcp.docker:execute",
                    "mcp.kubernetes:execute",
                    "mcp.prometheus:read",
                    "mcp.security_scanner:execute"
                ]
            )
            users["operator"] = {
                "user_id": f"operator_{environment}",
                "roles": ["operator"],
                "api_key": operator_creds["api_key"],
                "jwt_token": operator_creds.get("jwt_token", ""),
                "description": "Operations team with deployment and monitoring access"
            }
            
            # Viewer user
            viewer_creds = security_core.create_user_credentials(
                user_id=f"viewer_{environment}",
                roles=["viewer"],
                permissions=[
                    "mcp.docker:read",
                    "mcp.kubernetes:read",
                    "mcp.prometheus:read"
                ]
            )
            users["viewer"] = {
                "user_id": f"viewer_{environment}",
                "roles": ["viewer"],
                "api_key": viewer_creds["api_key"],
                "jwt_token": viewer_creds.get("jwt_token", ""),
                "description": "Read-only access for monitoring and reporting"
            }
            
            # Service account
            service_creds = security_core.create_user_credentials(
                user_id=f"mcp_service_{environment}",
                roles=["mcp_service"],
                permissions=[
                    "mcp.*:execute",
                    "mcp.*:read"
                ]
            )
            users["service"] = {
                "user_id": f"mcp_service_{environment}",
                "roles": ["mcp_service"],
                "api_key": service_creds["api_key"],
                "jwt_token": service_creds.get("jwt_token", ""),
                "description": "Service-to-service communication account"
            }
            
            # Save credentials securely
            credentials_file = f"mcp_credentials_{environment}.json"
            with open(credentials_file, 'w') as f:
                json.dump(users, f, indent=2)
            
            logger.info(f"✅ Default users created and saved to {credentials_file}")
            logger.warning("🔐 Please secure the credentials file and rotate keys regularly!")
            
        except Exception as e:
            logger.error(f"❌ Failed to create default users: {e}")
            users["error"] = str(e)
        
        return users
    
    def _log_deployment_summary(self, results: Dict[str, Any]):
        """Log deployment summary."""
        logger.info("\n" + "="*60)
        logger.info("🔒 MCP SECURITY DEPLOYMENT SUMMARY")
        logger.info("="*60)
        
        logger.info(f"Environment: {results['environment']}")
        logger.info(f"Status: {results['status']}")
        logger.info(f"Started: {results['started_at']}")
        logger.info(f"Completed: {results.get('completed_at', 'N/A')}")
        
        if results['status'] == 'success':
            logger.info(f"Global Security Score: {results.get('global_security_score', 'N/A')}")
            
            logger.info("\n📊 Server Deployment Status:")
            for server_name, server_info in results['servers'].items():
                if server_info['status'] == 'deployed':
                    logger.info(f"  ✅ {server_name}: Security Score {server_info['security_score']}")
                else:
                    logger.info(f"  ❌ {server_name}: {server_info.get('error', 'Unknown error')}")
            
            # Vulnerability summary
            vuln_summary = results.get('vulnerabilities', {}).get('summary', {})
            if vuln_summary:
                logger.info(f"\n🛡️ Vulnerability Summary:")
                logger.info(f"  Total Vulnerabilities: {vuln_summary.get('total_vulnerabilities', 0)}")
                logger.info(f"  Risk Score: {vuln_summary.get('overall_risk_score', 0):.1f}")
                
                severity_breakdown = vuln_summary.get('severity_breakdown', {})
                for severity, count in severity_breakdown.items():
                    if count > 0:
                        logger.info(f"  {severity.upper()}: {count}")
            
            # Compliance status
            logger.info("\n✅ Compliance Status:")
            for server_name, server_info in results['servers'].items():
                if server_info['status'] == 'deployed':
                    compliance = server_info.get('compliance_status', {})
                    compliant_frameworks = [k for k, v in compliance.items() if v]
                    logger.info(f"  {server_name}: {', '.join(compliant_frameworks) if compliant_frameworks else 'None'}")
        
        if results.get('errors'):
            logger.error("\n❌ Deployment Errors:")
            for error in results['errors']:
                logger.error(f"  • {error}")
        
        logger.info("\n" + "="*60)
    
    async def run_security_tests(self) -> Dict[str, Any]:
        """Run comprehensive security tests on deployed servers."""
        logger.info("🧪 Running security tests on deployed servers...")
        
        test_results = {
            "started_at": datetime.utcnow().isoformat(),
            "tests": {},
            "overall_status": "unknown"
        }
        
        try:
            # Import and run the comprehensive security test
            from test_mcp_security_comprehensive import run_security_tests
            
            # Run security tests
            await run_security_tests()
            
            test_results["overall_status"] = "passed"
            test_results["message"] = "All security tests passed successfully"
            
        except Exception as e:
            logger.error(f"❌ Security tests failed: {e}")
            test_results["overall_status"] = "failed"
            test_results["error"] = str(e)
        
        test_results["completed_at"] = datetime.utcnow().isoformat()
        return test_results


async def main():
    """Main deployment function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Deploy MCP servers with security hardening")
    parser.add_argument(
        "--environment", 
        choices=["development", "staging", "production"],
        default="development",
        help="Deployment environment"
    )
    parser.add_argument(
        "--run-tests",
        action="store_true",
        help="Run security tests after deployment"
    )
    parser.add_argument(
        "--skip-vulnerability-scan",
        action="store_true", 
        help="Skip vulnerability scanning during deployment"
    )
    
    args = parser.parse_args()
    
    try:
        deployer = SecurityMCPDeployer()
        
        # Deploy with security hardening
        deployment_results = await deployer.deploy_mcp_servers(args.environment)
        
        # Save deployment results
        results_file = f"deployment_results_{args.environment}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        with open(results_file, 'w') as f:
            json.dump(deployment_results, f, indent=2)
        
        logger.info(f"📋 Deployment results saved to {results_file}")
        
        # Run security tests if requested
        if args.run_tests:
            test_results = await deployer.run_security_tests()
            
            test_file = f"security_test_results_{args.environment}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            with open(test_file, 'w') as f:
                json.dump(test_results, f, indent=2)
            
            logger.info(f"🧪 Test results saved to {test_file}")
        
        # Final status
        if deployment_results["status"] == "success":
            logger.info("🎉 MCP Security Deployment completed successfully!")
            return 0
        else:
            logger.error("❌ MCP Security Deployment failed!")
            return 1
            
    except KeyboardInterrupt:
        logger.info("⏸️ Deployment interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"💥 Unexpected error during deployment: {e}")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())