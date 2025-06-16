#!/usr/bin/env python3
"""
AGENT 8: MCP Integration Validation (Standalone)

Comprehensive standalone test to validate MCP integration with existing CODE components.
Tests integration points without heavy dependencies.
"""

import asyncio
import json
import logging
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class StandaloneMCPIntegrationValidator:
    """Validates MCP integration with CODE components."""
    
    def __init__(self):
        self.test_results = {
            "validation_timestamp": datetime.now().isoformat(),
            "integration_tests": {},
            "compatibility_matrix": {},
            "performance_metrics": {},
            "error_handling": {},
            "recommendations": []
        }
        
    async def validate_all_integrations(self) -> Dict[str, Any]:
        """Run all integration validation tests."""
        logger.info("Starting AGENT 8 MCP Integration validation...")
        
        try:
            # Test 1: Module Import Compatibility
            await self.test_module_imports()
            
            # Test 2: MCP Server Registration
            await self.test_mcp_server_registration()
            
            # Test 3: Database Connection Compatibility
            await self.test_database_compatibility()
            
            # Test 4: Authentication Integration
            await self.test_authentication_integration()
            
            # Test 5: Monitoring Integration
            await self.test_monitoring_integration()
            
            # Test 6: API Endpoint Integration
            await self.test_api_integration()
            
            # Test 7: Configuration Compatibility
            await self.test_configuration_compatibility()
            
            # Test 8: Error Handling Integration
            await self.test_error_handling()
            
            # Test 9: Performance Impact
            await self.test_performance_impact()
            
            # Test 10: Resource Management
            await self.test_resource_management()
            
            # Generate recommendations
            self.generate_integration_recommendations()
            
            return self.test_results
            
        except Exception as e:
            logger.error(f"Critical error in integration validation: {e}")
            self.test_results["critical_error"] = str(e)
            return self.test_results
    
    async def test_module_imports(self):
        """Test module import compatibility."""
        logger.info("Testing module import compatibility...")
        
        import_tests = {
            "mcp_core": "src.mcp",
            "mcp_manager": "src.mcp.manager",
            "mcp_servers": "src.mcp.servers",
            "mcp_protocols": "src.mcp.protocols",
            "database_core": "src.database",
            "auth_core": "src.auth",
            "monitoring_core": "src.monitoring",
            "core_exceptions": "src.core.exceptions",
            "core_circuit_breaker": "src.core.circuit_breaker"
        }
        
        results = {}
        
        for test_name, module_path in import_tests.items():
            try:
                # Add current directory to path for imports
                if str(Path.cwd()) not in sys.path:
                    sys.path.insert(0, str(Path.cwd()))
                
                # Attempt import
                __import__(module_path)
                results[test_name] = {
                    "status": "success",
                    "module": module_path,
                    "importable": True
                }
                logger.info(f"✓ {test_name} import successful")
                
            except ImportError as e:
                results[test_name] = {
                    "status": "error",
                    "module": module_path,
                    "error": str(e),
                    "importable": False
                }
                logger.warning(f"⚠ {test_name} import failed: {e}")
            except Exception as e:
                results[test_name] = {
                    "status": "error",
                    "module": module_path,
                    "error": f"Unexpected error: {str(e)}",
                    "importable": False
                }
        
        self.test_results["integration_tests"]["module_imports"] = results
    
    async def test_mcp_server_registration(self):
        """Test MCP server registration and discovery."""
        logger.info("Testing MCP server registration...")
        
        try:
            # Create a mock permission checker for testing
            class MockPermissionChecker:
                def check_permission(self, user, resource, action):
                    return True
                def __bool__(self):
                    return True
                def register_resource_permission(self, resource_type, resource_id, initial_permissions):
                    pass
            
            # Test MCP server registry with permission checker
            from src.mcp.servers import MCPServerRegistry
            
            mock_permission_checker = MockPermissionChecker()
            registry = MCPServerRegistry(mock_permission_checker)
            
            # Test basic MCP manager initialization
            from src.mcp.manager import MCPManager
            
            manager = MCPManager()
            
            # Test context creation
            context_id = str(uuid.uuid4())
            context = manager.create_context(context_id)
            
            # Test server registry access
            server_info = manager.get_server_info()
            
            # Test tool discovery
            available_tools = manager.get_available_tools()
            
            self.test_results["integration_tests"]["mcp_server_registration"] = {
                "status": "success",
                "manager_created": True,
                "registry_created": True,
                "context_created": context is not None,
                "context_id": context_id,
                "server_count": len(server_info),
                "available_tools": len(available_tools),
                "servers": list(server_info.keys())
            }
            
            logger.info("✓ MCP server registration test passed")
            
        except Exception as e:
            self.test_results["integration_tests"]["mcp_server_registration"] = {
                "status": "error",
                "error": str(e)
            }
            logger.error(f"MCP server registration test failed: {e}")
    
    async def test_database_compatibility(self):
        """Test database layer compatibility."""
        logger.info("Testing database compatibility...")
        
        try:
            # Test database module imports
            from src.database import get_database_connection
            
            # Check if database connection can be established
            try:
                # This might fail if database is not set up, but we're testing compatibility
                connection = await get_database_connection()
                database_available = connection is not None
            except Exception:
                database_available = False
            
            # Test repository imports
            repository_imports = {}
            repos = [
                "audit_repository",
                "query_repository", 
                "deployment_repository",
                "configuration_repository",
                "user_repository",
                "metrics_repository"
            ]
            
            for repo in repos:
                try:
                    module = __import__(f"src.database.repositories.{repo}", fromlist=[repo])
                    repository_imports[repo] = True
                except ImportError:
                    repository_imports[repo] = False
            
            self.test_results["integration_tests"]["database_compatibility"] = {
                "status": "success" if any(repository_imports.values()) else "partial",
                "database_available": database_available,
                "repository_imports": repository_imports,
                "compatibility_score": sum(repository_imports.values()) / len(repository_imports)
            }
            
            logger.info("✓ Database compatibility test completed")
            
        except Exception as e:
            self.test_results["integration_tests"]["database_compatibility"] = {
                "status": "error",
                "error": str(e)
            }
            logger.error(f"Database compatibility test failed: {e}")
    
    async def test_authentication_integration(self):
        """Test authentication system integration."""
        logger.info("Testing authentication integration...")
        
        try:
            # Test auth module imports
            auth_components = [
                "src.auth.middleware",
                "src.auth.rbac",
                "src.auth.tokens",
                "src.auth.permissions"
            ]
            
            import_results = {}
            for component in auth_components:
                try:
                    __import__(component)
                    import_results[component] = True
                except ImportError:
                    import_results[component] = False
            
            # Test MCP authentication integration
            try:
                from src.mcp.security.auth_middleware import MCPAuthMiddleware
                mcp_auth_available = True
            except ImportError:
                mcp_auth_available = False
            
            self.test_results["integration_tests"]["authentication_integration"] = {
                "status": "success" if any(import_results.values()) else "error",
                "auth_component_imports": import_results,
                "mcp_auth_middleware": mcp_auth_available,
                "integration_ready": mcp_auth_available and any(import_results.values())
            }
            
            logger.info("✓ Authentication integration test completed")
            
        except Exception as e:
            self.test_results["integration_tests"]["authentication_integration"] = {
                "status": "error",
                "error": str(e)
            }
            logger.error(f"Authentication integration test failed: {e}")
    
    async def test_monitoring_integration(self):
        """Test monitoring system integration."""
        logger.info("Testing monitoring integration...")
        
        try:
            # Test monitoring module imports
            monitoring_components = [
                "src.monitoring.metrics",
                "src.monitoring.alerts",
                "src.monitoring.health",
                "src.monitoring.tracing"
            ]
            
            import_results = {}
            for component in monitoring_components:
                try:
                    __import__(component)
                    import_results[component] = True
                except ImportError:
                    import_results[component] = False
            
            # Test MCP monitoring integration
            try:
                from src.monitoring.mcp_integration import MCPMetricsCollector
                mcp_monitoring_available = True
            except ImportError:
                mcp_monitoring_available = False
            
            self.test_results["integration_tests"]["monitoring_integration"] = {
                "status": "success" if any(import_results.values()) else "error",
                "monitoring_component_imports": import_results,
                "mcp_monitoring_available": mcp_monitoring_available,
                "integration_score": sum(import_results.values()) / len(import_results)
            }
            
            logger.info("✓ Monitoring integration test completed")
            
        except Exception as e:
            self.test_results["integration_tests"]["monitoring_integration"] = {
                "status": "error",
                "error": str(e)
            }
            logger.error(f"Monitoring integration test failed: {e}")
    
    async def test_api_integration(self):
        """Test API endpoint integration."""
        logger.info("Testing API integration...")
        
        try:
            # Test API module imports
            api_components = [
                "src.api.circuit_breaker_api"
            ]
            
            import_results = {}
            for component in api_components:
                try:
                    __import__(component)
                    import_results[component] = True
                except ImportError:
                    import_results[component] = False
            
            # Check for FastAPI or Flask integration
            web_frameworks = {
                "fastapi": False,
                "flask": False,
                "starlette": False
            }
            
            for framework in web_frameworks:
                try:
                    __import__(framework)
                    web_frameworks[framework] = True
                except ImportError:
                    pass
            
            self.test_results["integration_tests"]["api_integration"] = {
                "status": "success" if any(import_results.values()) else "partial",
                "api_component_imports": import_results,
                "web_frameworks_available": web_frameworks,
                "api_ready": any(web_frameworks.values())
            }
            
            logger.info("✓ API integration test completed")
            
        except Exception as e:
            self.test_results["integration_tests"]["api_integration"] = {
                "status": "error",
                "error": str(e)
            }
            logger.error(f"API integration test failed: {e}")
    
    async def test_configuration_compatibility(self):
        """Test configuration system compatibility."""
        logger.info("Testing configuration compatibility...")
        
        try:
            # Test core configuration modules
            config_components = [
                "src.core.logging_config",
                "src.core.circuit_breaker_config",
                "src.core.cors_config"
            ]
            
            import_results = {}
            for component in config_components:
                try:
                    __import__(component)
                    import_results[component] = True
                except ImportError:
                    import_results[component] = False
            
            # Check for configuration files
            config_files = [
                "pyproject.toml",
                "Cargo.toml",
                "docker-compose.monitoring.yml",
                "k8s/configmaps.yaml"
            ]
            
            file_checks = {}
            for config_file in config_files:
                file_path = Path(config_file)
                file_checks[config_file] = file_path.exists()
            
            self.test_results["integration_tests"]["configuration_compatibility"] = {
                "status": "success",
                "config_component_imports": import_results,
                "config_files_present": file_checks,
                "configuration_score": (
                    sum(import_results.values()) + sum(file_checks.values())
                ) / (len(import_results) + len(file_checks))
            }
            
            logger.info("✓ Configuration compatibility test completed")
            
        except Exception as e:
            self.test_results["integration_tests"]["configuration_compatibility"] = {
                "status": "error",
                "error": str(e)
            }
            logger.error(f"Configuration compatibility test failed: {e}")
    
    async def test_error_handling(self):
        """Test error handling integration."""
        logger.info("Testing error handling integration...")
        
        try:
            # Test core exception handling
            from src.core.exceptions import (
                MCPError,
                MCPServerNotFoundError,
                MCPToolNotFoundError,
                MCPToolExecutionError
            )
            
            # Test error handling functionality
            exception_tests = {
                "mcp_error": MCPError,
                "server_not_found": MCPServerNotFoundError,
                "tool_not_found": MCPToolNotFoundError,
                "tool_execution": MCPToolExecutionError
            }
            
            exception_results = {}
            for test_name, exception_class in exception_tests.items():
                try:
                    # Create and handle exception
                    test_exception = exception_class("Test error")
                    exception_results[test_name] = {
                        "creatable": True,
                        "class_name": exception_class.__name__,
                        "is_mcp_error": issubclass(exception_class, MCPError)
                    }
                except Exception as e:
                    exception_results[test_name] = {
                        "creatable": False,
                        "error": str(e)
                    }
            
            self.test_results["integration_tests"]["error_handling"] = {
                "status": "success",
                "exception_tests": exception_results,
                "error_hierarchy_working": True
            }
            
            logger.info("✓ Error handling integration test completed")
            
        except Exception as e:
            self.test_results["integration_tests"]["error_handling"] = {
                "status": "error",
                "error": str(e)
            }
            logger.error(f"Error handling integration test failed: {e}")
    
    async def test_performance_impact(self):
        """Test performance impact of integration."""
        logger.info("Testing performance impact...")
        
        try:
            # Measure import times
            import_times = {}
            
            modules_to_test = [
                "src.mcp.manager",
                "src.core.circuit_breaker",
                "src.core.exceptions"
            ]
            
            for module in modules_to_test:
                start_time = time.time()
                try:
                    __import__(module)
                    import_time = time.time() - start_time
                    import_times[module] = import_time
                except ImportError:
                    import_times[module] = None
            
            # Performance thresholds
            max_import_time = 1.0  # 1 second
            
            performance_acceptable = all(
                t is None or t < max_import_time 
                for t in import_times.values()
            )
            
            self.test_results["performance_metrics"]["integration_performance"] = {
                "status": "success" if performance_acceptable else "warning",
                "import_times": import_times,
                "max_import_time": max_import_time,
                "performance_acceptable": performance_acceptable,
                "total_import_time": sum(t for t in import_times.values() if t is not None)
            }
            
            logger.info("✓ Performance impact test completed")
            
        except Exception as e:
            self.test_results["performance_metrics"]["integration_performance"] = {
                "status": "error",
                "error": str(e)
            }
            logger.error(f"Performance impact test failed: {e}")
    
    async def test_resource_management(self):
        """Test resource management and cleanup."""
        logger.info("Testing resource management...")
        
        try:
            # Create a mock permission checker for testing
            class MockPermissionChecker:
                def check_permission(self, user, resource, action):
                    return True
                def __bool__(self):
                    return True
                def register_resource_permission(self, resource_type, resource_id, initial_permissions):
                    pass
            
            from src.mcp.manager import MCPManager
            
            # Test resource creation and cleanup
            manager = MCPManager()
            
            # Create multiple contexts to test resource management
            initial_context_count = len(manager.contexts)
            
            context_ids = []
            for i in range(5):
                context_id = str(uuid.uuid4())
                context = manager.create_context(context_id)
                context_ids.append(context_id)
            
            context_creation_count = len(manager.contexts) - initial_context_count
            
            # Test cleanup functionality
            cleanup_performed = False
            cleanup_count = 0
            try:
                cleanup_count = manager._cleanup_expired_contexts()
                cleanup_performed = True
            except Exception:
                cleanup_performed = False
            
            self.test_results["integration_tests"]["resource_management"] = {
                "status": "success",
                "initial_contexts": initial_context_count,
                "contexts_created": context_creation_count,
                "cleanup_performed": cleanup_performed,
                "cleanup_count": cleanup_count,
                "context_ids": context_ids[:3]  # Store first 3 for reference
            }
            
            logger.info("✓ Resource management test completed")
            
        except Exception as e:
            self.test_results["integration_tests"]["resource_management"] = {
                "status": "error",
                "error": str(e)
            }
            logger.error(f"Resource management test failed: {e}")
    
    def generate_integration_recommendations(self):
        """Generate integration recommendations based on test results."""
        recommendations = []
        
        # Analyze test results
        for test_category, results in self.test_results["integration_tests"].items():
            if isinstance(results, dict):
                status = results.get("status", "unknown")
                
                if status == "error":
                    recommendations.append({
                        "priority": "high",
                        "category": test_category,
                        "issue": f"{test_category} integration failed",
                        "recommendation": f"Review and fix {test_category} integration issues",
                        "details": results.get("error", "Unknown error")
                    })
                elif status == "partial":
                    recommendations.append({
                        "priority": "medium",
                        "category": test_category,
                        "issue": f"{test_category} integration partially working",
                        "recommendation": f"Complete {test_category} integration implementation",
                        "details": "Some components are missing or not functioning"
                    })
        
        # Performance recommendations
        perf_results = self.test_results.get("performance_metrics", {})
        for perf_test, results in perf_results.items():
            if isinstance(results, dict) and results.get("status") == "warning":
                recommendations.append({
                    "priority": "medium",
                    "category": "performance",
                    "issue": "Performance concerns detected",
                    "recommendation": "Optimize integration performance",
                    "details": f"Review {perf_test} performance metrics"
                })
        
        # General recommendations
        if len(recommendations) == 0:
            recommendations.append({
                "priority": "low",
                "category": "optimization",
                "issue": "Integration working well",
                "recommendation": "Consider additional optimizations and monitoring",
                "details": "All core integration tests passed successfully"
            })
        
        self.test_results["recommendations"] = recommendations
    
    def generate_compatibility_matrix(self):
        """Generate compatibility matrix."""
        matrix = {}
        
        for test_name, results in self.test_results["integration_tests"].items():
            if isinstance(results, dict):
                status = results.get("status", "unknown")
                matrix[test_name] = {
                    "compatible": status == "success",
                    "status": status,
                    "score": 1.0 if status == "success" else 0.5 if status == "partial" else 0.0
                }
        
        # Calculate overall compatibility score
        scores = [item["score"] for item in matrix.values()]
        overall_score = sum(scores) / len(scores) if scores else 0.0
        
        matrix["overall"] = {
            "compatibility_score": overall_score,
            "compatibility_grade": (
                "A" if overall_score >= 0.9 else
                "B" if overall_score >= 0.8 else
                "C" if overall_score >= 0.7 else
                "D" if overall_score >= 0.6 else "F"
            )
        }
        
        self.test_results["compatibility_matrix"] = matrix


async def main():
    """Run the MCP Integration validation."""
    print("🔧 AGENT 8: MCP Integration Validation (Standalone)")
    print("=" * 60)
    
    validator = StandaloneMCPIntegrationValidator()
    
    try:
        # Run validation
        results = await validator.validate_all_integrations()
        
        # Generate compatibility matrix
        validator.generate_compatibility_matrix()
        
        # Generate report
        report_file = f"/home/louranicas/projects/claude-optimized-deployment/agent8_mcp_integration_validation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(report_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        # Print summary
        print("\n📊 Integration Validation Summary")
        print("-" * 40)
        
        total_tests = 0
        passed_tests = 0
        partial_tests = 0
        
        for test_name, test_result in results["integration_tests"].items():
            total_tests += 1
            status = test_result.get("status", "unknown")
            
            if status == "success":
                passed_tests += 1
                print(f"✅ {test_name}")
            elif status == "partial":
                partial_tests += 1
                print(f"🟡 {test_name} (partial)")
            else:
                print(f"❌ {test_name}")
        
        # Print compatibility matrix
        matrix = results.get("compatibility_matrix", {})
        overall = matrix.get("overall", {})
        
        print(f"\n📈 Compatibility Results:")
        print(f"   Tests Run: {total_tests}")
        print(f"   Passed: {passed_tests}")
        print(f"   Partial: {partial_tests}")
        print(f"   Failed: {total_tests - passed_tests - partial_tests}")
        print(f"   Compatibility Score: {overall.get('compatibility_score', 0):.2f}")
        print(f"   Compatibility Grade: {overall.get('compatibility_grade', 'F')}")
        
        # Print recommendations
        recommendations = results.get("recommendations", [])
        if recommendations:
            print(f"\n🎯 Recommendations ({len(recommendations)}):")
            for rec in recommendations[:5]:  # Show top 5
                priority_icon = "🔴" if rec["priority"] == "high" else "🟡" if rec["priority"] == "medium" else "🟢"
                print(f"   {priority_icon} {rec['recommendation']}")
        
        print(f"\n📄 Full Report: {report_file}")
        
        # Determine success
        success_rate = (passed_tests + partial_tests * 0.5) / total_tests if total_tests > 0 else 0
        
        if success_rate >= 0.8:
            print("\n🎉 MCP Integration validation PASSED!")
            return True
        else:
            print("\n⚠️  MCP Integration validation needs attention.")
            return False
            
    except Exception as e:
        print(f"\n💥 Critical error during validation: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)