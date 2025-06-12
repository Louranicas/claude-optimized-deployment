#!/usr/bin/env python3
"""
Comprehensive Module Test Suite for Claude-Optimized Deployment Engine
This suite performs deep testing of all modules with actual execution
"""

import os
import sys
import json
import asyncio
import traceback
import subprocess
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional
from pathlib import Path
import importlib
import inspect
import tempfile
import shutil

class ComprehensiveModuleTestSuite:
    def __init__(self):
        self.test_results = {
            "timestamp": datetime.now().isoformat(),
            "modules": {},
            "errors": [],
            "security_issues": [],
            "performance_issues": [],
            "total_tests": 0,
            "passed_tests": 0,
            "failed_tests": 0
        }
        
    async def test_module_imports_deep(self, module_path: str) -> Dict[str, Any]:
        """Deep test of module imports including all submodules"""
        result = {
            "module": module_path,
            "import_test": "not_started",
            "submodules": {},
            "classes_found": [],
            "functions_found": [],
            "errors": []
        }
        
        try:
            # Import the module
            module = importlib.import_module(module_path)
            result["import_test"] = "success"
            
            # Get all attributes
            for name in dir(module):
                if not name.startswith('_'):
                    attr = getattr(module, name)
                    if inspect.isclass(attr):
                        result["classes_found"].append(name)
                    elif inspect.isfunction(attr):
                        result["functions_found"].append(name)
            
            # Try to import all submodules
            if hasattr(module, '__path__'):
                module_dir = Path(module.__path__[0])
                for item in module_dir.iterdir():
                    if item.is_file() and item.suffix == '.py' and item.stem != '__init__':
                        submodule_path = f"{module_path}.{item.stem}"
                        try:
                            importlib.import_module(submodule_path)
                            result["submodules"][submodule_path] = "success"
                        except Exception as e:
                            result["submodules"][submodule_path] = f"failed: {str(e)}"
                            result["errors"].append(f"Submodule {submodule_path}: {str(e)}")
                    elif item.is_dir() and not item.name.startswith('_'):
                        submodule_path = f"{module_path}.{item.name}"
                        try:
                            importlib.import_module(submodule_path)
                            result["submodules"][submodule_path] = "success"
                        except Exception as e:
                            result["submodules"][submodule_path] = f"failed: {str(e)}"
                            result["errors"].append(f"Submodule {submodule_path}: {str(e)}")
            
        except Exception as e:
            result["import_test"] = f"failed: {str(e)}"
            result["errors"].append(str(e))
            result["traceback"] = traceback.format_exc()
        
        return result

    async def test_circle_of_experts(self) -> Dict[str, Any]:
        """Test Circle of Experts functionality"""
        print("\n🤖 Testing Circle of Experts...")
        result = {
            "module": "circle_of_experts",
            "tests": {}
        }
        
        # Test 1: Import test
        try:
            from src.circle_of_experts import EnhancedExpertManager, ExpertManager
            from src.circle_of_experts.models.query import ExpertQuery, QueryType
            result["tests"]["import"] = "pass"
        except Exception as e:
            result["tests"]["import"] = f"fail: {str(e)}"
            return result
        
        # Test 2: Manager creation
        try:
            manager = EnhancedExpertManager()
            result["tests"]["manager_creation"] = "pass"
        except Exception as e:
            result["tests"]["manager_creation"] = f"fail: {str(e)}"
            return result
        
        # Test 3: Expert availability
        try:
            available_experts = []
            # Check which API keys are available
            if os.getenv("ANTHROPIC_API_KEY"):
                available_experts.append("Claude")
            if os.getenv("OPENAI_API_KEY"):
                available_experts.append("GPT-4")
            if os.getenv("GOOGLE_GEMINI_API_KEY"):
                available_experts.append("Gemini")
            
            result["tests"]["available_experts"] = available_experts if available_experts else "No API keys configured"
        except Exception as e:
            result["tests"]["available_experts"] = f"fail: {str(e)}"
        
        # Test 4: Query creation
        try:
            query = ExpertQuery(
                content="Test query",
                query_type=QueryType.TECHNICAL,
                metadata={"test": True}
            )
            result["tests"]["query_creation"] = "pass"
        except Exception as e:
            result["tests"]["query_creation"] = f"fail: {str(e)}"
        
        # Test 5: Rust acceleration check
        try:
            from src.circle_of_experts.rust_integration import is_rust_available, get_rust_stats
            rust_available = is_rust_available()
            rust_stats = get_rust_stats() if rust_available else None
            result["tests"]["rust_acceleration"] = {
                "available": rust_available,
                "stats": rust_stats
            }
        except Exception as e:
            result["tests"]["rust_acceleration"] = f"fail: {str(e)}"
        
        return result

    async def test_mcp_servers(self) -> Dict[str, Any]:
        """Test MCP server implementations"""
        print("\n🔧 Testing MCP Servers...")
        result = {
            "module": "mcp_servers",
            "tests": {},
            "servers": {}
        }
        
        # Test 1: Import MCP manager
        try:
            from src.mcp.manager import get_mcp_manager
            from src.mcp.servers import MCPServerRegistry
            result["tests"]["import"] = "pass"
        except Exception as e:
            result["tests"]["import"] = f"fail: {str(e)}"
            return result
        
        # Test 2: Initialize manager
        try:
            manager = get_mcp_manager()
            await manager.initialize()
            result["tests"]["manager_init"] = "pass"
        except Exception as e:
            result["tests"]["manager_init"] = f"fail: {str(e)}"
            return result
        
        # Test 3: Get available servers
        try:
            servers = manager.registry.get_all_servers()
            result["tests"]["server_count"] = len(servers)
            
            # Test each server
            for server_name, server in servers.items():
                server_result = {
                    "name": server_name,
                    "info": None,
                    "tools": [],
                    "errors": []
                }
                
                try:
                    # Get server info
                    info = server.get_server_info()
                    server_result["info"] = {
                        "name": info.name,
                        "version": info.version
                    }
                    
                    # Get tools
                    tools = server.get_tools()
                    server_result["tools"] = [tool.name for tool in tools]
                    
                except Exception as e:
                    server_result["errors"].append(str(e))
                
                result["servers"][server_name] = server_result
                
        except Exception as e:
            result["tests"]["server_enumeration"] = f"fail: {str(e)}"
        
        # Test 4: Get available tools
        try:
            tools = manager.get_available_tools()
            result["tests"]["total_tools"] = len(tools)
        except Exception as e:
            result["tests"]["total_tools"] = f"fail: {str(e)}"
        
        return result

    async def test_database_layer(self) -> Dict[str, Any]:
        """Test database functionality"""
        print("\n💾 Testing Database Layer...")
        result = {
            "module": "database",
            "tests": {}
        }
        
        # Test 1: Import test
        try:
            from src.database import models
            from src.database.connection import DatabaseConnection
            from src.database.repositories.base import BaseRepository
            result["tests"]["import"] = "pass"
        except Exception as e:
            result["tests"]["import"] = f"fail: {str(e)}"
            return result
        
        # Test 2: Database URL configuration
        db_url = os.getenv("DATABASE_URL", "sqlite:///./test_db.sqlite")
        result["tests"]["database_url"] = "configured" if db_url else "missing"
        
        # Test 3: Model definitions
        try:
            from src.database.models import User, Query, Expert, Deployment
            models_found = []
            for model_name in ["User", "Query", "Expert", "Deployment"]:
                if hasattr(models, model_name):
                    models_found.append(model_name)
            result["tests"]["models_found"] = models_found
        except Exception as e:
            result["tests"]["models"] = f"fail: {str(e)}"
        
        # Test 4: Repository pattern
        try:
            from src.database.repositories.user_repository import UserRepository
            from src.database.repositories.query_repository import QueryRepository
            result["tests"]["repositories"] = "pass"
        except Exception as e:
            result["tests"]["repositories"] = f"fail: {str(e)}"
        
        # Test 5: Tortoise ORM configuration
        try:
            from src.database.tortoise_config import TORTOISE_CONFIG
            result["tests"]["orm_config"] = "configured" if TORTOISE_CONFIG else "missing"
        except Exception as e:
            result["tests"]["orm_config"] = f"fail: {str(e)}"
        
        return result

    async def test_authentication_system(self) -> Dict[str, Any]:
        """Test authentication and RBAC"""
        print("\n🔐 Testing Authentication System...")
        result = {
            "module": "authentication",
            "tests": {}
        }
        
        # Test 1: Import test
        try:
            from src.auth.rbac import RBACManager, Permission
            from src.auth.tokens import TokenManager
            from src.auth.models import User, UserRole
            result["tests"]["import"] = "pass"
        except Exception as e:
            result["tests"]["import"] = f"fail: {str(e)}"
            return result
        
        # Test 2: JWT configuration
        jwt_secret = os.getenv("JWT_SECRET_KEY")
        result["tests"]["jwt_configured"] = "yes" if jwt_secret else "no"
        
        # Test 3: RBAC manager creation
        try:
            # Create event loop context for async initialization
            rbac = RBACManager()
            result["tests"]["rbac_creation"] = "pass"
        except Exception as e:
            result["tests"]["rbac_creation"] = f"fail: {str(e)}"
        
        # Test 4: Token manager
        try:
            if jwt_secret:
                token_manager = TokenManager(secret_key=jwt_secret)
                result["tests"]["token_manager"] = "pass"
            else:
                result["tests"]["token_manager"] = "skipped: no JWT secret"
        except Exception as e:
            result["tests"]["token_manager"] = f"fail: {str(e)}"
        
        # Test 5: Permission system
        try:
            from src.auth.permissions import PermissionChecker
            pm = PermissionChecker()
            result["tests"]["permission_checker"] = "pass"
        except Exception as e:
            result["tests"]["permission_checker"] = f"fail: {str(e)}"
        
        return result

    async def test_monitoring_system(self) -> Dict[str, Any]:
        """Test monitoring and observability"""
        print("\n📊 Testing Monitoring System...")
        result = {
            "module": "monitoring",
            "tests": {}
        }
        
        # Test 1: Import test
        try:
            from src.monitoring.metrics import MetricsCollector
            from src.monitoring.health import HealthCheck
            from src.monitoring.tracing import TracingManager
            from src.monitoring.alerts import AlertManager
            result["tests"]["import"] = "pass"
        except Exception as e:
            result["tests"]["import"] = f"fail: {str(e)}"
            return result
        
        # Test 2: Metrics collector
        try:
            metrics = MetricsCollector()
            # Test basic metric operations
            metrics.record_request("test_endpoint", "GET", 200, 0.1)
            result["tests"]["metrics_collector"] = "pass"
        except Exception as e:
            result["tests"]["metrics_collector"] = f"fail: {str(e)}"
        
        # Test 3: Health checks
        try:
            health = HealthCheck()
            # Add a test check
            health.add_check("test", lambda: {"status": "healthy"})
            status = await health.run_checks()
            result["tests"]["health_checks"] = "pass"
        except Exception as e:
            result["tests"]["health_checks"] = f"fail: {str(e)}"
        
        # Test 4: Tracing
        try:
            tracing = TracingManager()
            result["tests"]["tracing"] = "pass"
        except Exception as e:
            result["tests"]["tracing"] = f"fail: {str(e)}"
        
        # Test 5: Prometheus integration
        try:
            from prometheus_client import REGISTRY
            collectors = list(REGISTRY._collector_to_names.keys())
            result["tests"]["prometheus_collectors"] = len(collectors)
        except Exception as e:
            result["tests"]["prometheus_collectors"] = f"fail: {str(e)}"
        
        return result

    async def test_core_utilities(self) -> Dict[str, Any]:
        """Test core utility modules"""
        print("\n⚙️ Testing Core Utilities...")
        result = {
            "module": "core_utilities",
            "tests": {}
        }
        
        # Test 1: Circuit breaker
        try:
            from src.core.circuit_breaker import CircuitBreaker, CircuitBreakerConfig
            config = CircuitBreakerConfig(name="test", failure_threshold=5)
            cb = CircuitBreaker(config)
            result["tests"]["circuit_breaker"] = "pass"
        except Exception as e:
            result["tests"]["circuit_breaker"] = f"fail: {str(e)}"
        
        # Test 2: Retry logic
        try:
            from src.core.retry import retry_async, retry_network, RetryConfig
            result["tests"]["retry_logic"] = "pass"
        except Exception as e:
            result["tests"]["retry_logic"] = f"fail: {str(e)}"
        
        # Test 3: Exceptions
        try:
            from src.core.exceptions import (
                BaseDeploymentError, DatabaseError, 
                AuthorizationError, NotFoundError,
                ConflictError, NetworkError
            )
            result["tests"]["exceptions"] = "pass"
        except Exception as e:
            result["tests"]["exceptions"] = f"fail: {str(e)}"
        
        # Test 4: Connection pooling
        try:
            from src.core.connections import ConnectionPoolManager
            pool_manager = ConnectionPoolManager()
            result["tests"]["connection_pooling"] = "pass"
        except Exception as e:
            result["tests"]["connection_pooling"] = f"fail: {str(e)}"
        
        # Test 5: Logging
        try:
            from src.core.logging_config import setup_logging, get_logger
            logger = get_logger("test")
            result["tests"]["logging"] = "pass"
        except Exception as e:
            result["tests"]["logging"] = f"fail: {str(e)}"
        
        return result

    async def test_api_layer(self) -> Dict[str, Any]:
        """Test API endpoints and routing"""
        print("\n🌐 Testing API Layer...")
        result = {
            "module": "api",
            "tests": {}
        }
        
        # Test 1: Import test
        try:
            from src.api.circuit_breaker_api import router, CircuitBreakerAPI
            result["tests"]["import"] = "pass"
        except Exception as e:
            result["tests"]["import"] = f"fail: {str(e)}"
            return result
        
        # Test 2: FastAPI app creation
        try:
            from fastapi import FastAPI
            app = FastAPI()
            result["tests"]["fastapi_app"] = "pass"
        except Exception as e:
            result["tests"]["fastapi_app"] = f"fail: {str(e)}"
        
        # Test 3: Router inclusion
        try:
            app.include_router(router)
            result["tests"]["router_inclusion"] = "pass"
        except Exception as e:
            result["tests"]["router_inclusion"] = f"fail: {str(e)}"
        
        # Test 4: API instance
        try:
            api = CircuitBreakerAPI()
            result["tests"]["api_instance"] = "pass"
        except Exception as e:
            result["tests"]["api_instance"] = f"fail: {str(e)}"
        
        return result

    async def run_all_tests(self) -> Dict[str, Any]:
        """Run all module tests"""
        print("🚀 Starting Comprehensive Module Testing")
        print("=" * 60)
        
        # Define all modules to test
        modules_to_test = [
            ("Circle of Experts", self.test_circle_of_experts),
            ("MCP Servers", self.test_mcp_servers),
            ("Database Layer", self.test_database_layer),
            ("Authentication System", self.test_authentication_system),
            ("Monitoring System", self.test_monitoring_system),
            ("Core Utilities", self.test_core_utilities),
            ("API Layer", self.test_api_layer)
        ]
        
        # Run each test
        for module_name, test_func in modules_to_test:
            try:
                result = await test_func()
                self.test_results["modules"][module_name] = result
                
                # Count passed/failed tests
                if "tests" in result:
                    for test_name, test_result in result["tests"].items():
                        self.test_results["total_tests"] += 1
                        if isinstance(test_result, str) and ("pass" in test_result or test_result == "configured"):
                            self.test_results["passed_tests"] += 1
                        else:
                            self.test_results["failed_tests"] += 1
                            if isinstance(test_result, str) and "fail:" in test_result:
                                self.test_results["errors"].append({
                                    "module": module_name,
                                    "test": test_name,
                                    "error": test_result
                                })
                
            except Exception as e:
                self.test_results["modules"][module_name] = {
                    "error": str(e),
                    "traceback": traceback.format_exc()
                }
                self.test_results["errors"].append({
                    "module": module_name,
                    "error": str(e)
                })
        
        # Calculate success rate
        if self.test_results["total_tests"] > 0:
            self.test_results["success_rate"] = (
                self.test_results["passed_tests"] / self.test_results["total_tests"]
            ) * 100
        else:
            self.test_results["success_rate"] = 0
        
        return self.test_results

    def generate_report(self) -> str:
        """Generate detailed test report"""
        report = []
        report.append("=" * 80)
        report.append("COMPREHENSIVE MODULE TEST REPORT")
        report.append("=" * 80)
        report.append(f"Timestamp: {self.test_results['timestamp']}")
        report.append(f"Total Tests: {self.test_results['total_tests']}")
        report.append(f"Passed: {self.test_results['passed_tests']}")
        report.append(f"Failed: {self.test_results['failed_tests']}")
        report.append(f"Success Rate: {self.test_results['success_rate']:.1f}%")
        report.append("")
        
        # Module results
        report.append("MODULE TEST RESULTS:")
        report.append("-" * 40)
        for module_name, module_result in self.test_results["modules"].items():
            report.append(f"\n{module_name}:")
            if "error" in module_result:
                report.append(f"  ❌ Module Error: {module_result['error']}")
            elif "tests" in module_result:
                for test_name, test_result in module_result["tests"].items():
                    if isinstance(test_result, str):
                        if "pass" in test_result or test_result == "configured":
                            report.append(f"  ✅ {test_name}: {test_result}")
                        else:
                            report.append(f"  ❌ {test_name}: {test_result}")
                    else:
                        report.append(f"  ℹ️ {test_name}: {json.dumps(test_result, indent=4)}")
        
        # Errors summary
        if self.test_results["errors"]:
            report.append("\nERRORS FOUND:")
            report.append("-" * 40)
            for error in self.test_results["errors"]:
                report.append(f"  - {error['module']}/{error.get('test', 'N/A')}: {error['error']}")
        
        return "\n".join(report)

async def main():
    """Main test execution"""
    tester = ComprehensiveModuleTestSuite()
    
    # Run all tests
    results = await tester.run_all_tests()
    
    # Generate report
    report = tester.generate_report()
    print("\n" + report)
    
    # Save results
    with open('module_test_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n📄 Detailed results saved to: module_test_results.json")
    
    # Return exit code based on results
    if results["failed_tests"] > 0:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    asyncio.run(main())