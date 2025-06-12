#!/usr/bin/env python3
"""
Comprehensive Test Suite for Claude-Optimized Deployment Engine
This suite tests all modules systematically with parallel execution support
"""

import sys
import os
import json
import subprocess
import asyncio
import traceback
from datetime import datetime
from typing import Dict, List, Tuple, Any
from pathlib import Path
import importlib.util
import concurrent.futures
import time

class ComprehensiveTestSuite:
    def __init__(self):
        self.test_results = {
            "timestamp": datetime.now().isoformat(),
            "environment": {
                "python_version": sys.version,
                "platform": sys.platform,
                "working_dir": os.getcwd()
            },
            "modules": {},
            "summary": {
                "total_modules": 0,
                "passed": 0,
                "failed": 0,
                "errors": []
            }
        }
        
        # Define all modules to test
        self.modules_to_test = [
            # Core modules
            ("Circle of Experts", "src.circle_of_experts", [
                "src.circle_of_experts.core.expert_manager",
                "src.circle_of_experts.core.query_handler",
                "src.circle_of_experts.core.response_collector",
                "src.circle_of_experts.experts.expert_factory"
            ]),
            ("MCP Servers", "src.mcp", [
                "src.mcp.manager",
                "src.mcp.servers",
                "src.mcp.infrastructure_servers",
                "src.mcp.devops_servers",
                "src.mcp.protocols"
            ]),
            ("Authentication/RBAC", "src.auth", [
                "src.auth.rbac",
                "src.auth.tokens",
                "src.auth.permissions",
                "src.auth.user_manager",
                "src.auth.middleware"
            ]),
            ("Database", "src.database", [
                "src.database.connection",
                "src.database.models",
                "src.database.repositories.base",
                "src.database.init"
            ]),
            ("Core Utilities", "src.core", [
                "src.core.exceptions",
                "src.core.retry",
                "src.core.circuit_breaker",
                "src.core.logging_config",
                "src.core.connections"
            ]),
            ("Monitoring", "src.monitoring", [
                "src.monitoring.metrics",
                "src.monitoring.health",
                "src.monitoring.alerts",
                "src.monitoring.tracing"
            ]),
            ("API", "src.api", [
                "src.api.circuit_breaker_api"
            ])
        ]

    def check_dependencies(self) -> Dict[str, bool]:
        """Check if required dependencies are installed"""
        dependencies = {
            "pydantic": False,
            "aiohttp": False,
            "bcrypt": False,
            "sqlalchemy": False,
            "fastapi": False,
            "prometheus_client": False,
            "opentelemetry": False,
            "jwt": False,  # PyJWT imports as jwt
            "cryptography": False,
            "yaml": False  # PyYAML imports as yaml
        }
        
        for dep in dependencies:
            try:
                __import__(dep)
                dependencies[dep] = True
            except ImportError:
                dependencies[dep] = False
                
        return dependencies

    def test_module_import(self, module_name: str) -> Tuple[bool, str]:
        """Test if a module can be imported"""
        try:
            spec = importlib.util.find_spec(module_name)
            if spec is None:
                return False, f"Module {module_name} not found"
            
            module = importlib.import_module(module_name)
            return True, f"Successfully imported {module_name}"
        except Exception as e:
            return False, f"Failed to import {module_name}: {str(e)}"

    def test_module_functionality(self, module_category: str, base_module: str, submodules: List[str]) -> Dict[str, Any]:
        """Test a module category with all its submodules"""
        result = {
            "category": module_category,
            "base_module": base_module,
            "status": "untested",
            "submodules": {},
            "errors": [],
            "warnings": []
        }
        
        # Test base module import
        base_success, base_msg = self.test_module_import(base_module)
        result["base_import"] = {"success": base_success, "message": base_msg}
        
        if not base_success:
            result["status"] = "failed"
            result["errors"].append(base_msg)
            return result
        
        # Test submodules
        submodule_results = {}
        for submodule in submodules:
            success, msg = self.test_module_import(submodule)
            submodule_results[submodule] = {
                "success": success,
                "message": msg
            }
            if not success:
                result["errors"].append(msg)
        
        result["submodules"] = submodule_results
        
        # Determine overall status
        total_submodules = len(submodules)
        successful_submodules = sum(1 for r in submodule_results.values() if r["success"])
        
        if successful_submodules == total_submodules:
            result["status"] = "passed"
        elif successful_submodules > 0:
            result["status"] = "partial"
        else:
            result["status"] = "failed"
            
        result["success_rate"] = f"{successful_submodules}/{total_submodules}"
        
        return result

    def run_parallel_tests(self) -> None:
        """Run tests in parallel using ThreadPoolExecutor"""
        print("🚀 Starting Comprehensive Module Testing")
        print("=" * 60)
        
        # Check dependencies first
        print("\n📦 Checking Dependencies...")
        deps = self.check_dependencies()
        self.test_results["dependencies"] = deps
        
        missing_deps = [d for d, installed in deps.items() if not installed]
        if missing_deps:
            print(f"⚠️  Missing dependencies: {', '.join(missing_deps)}")
        else:
            print("✅ All dependencies installed")
        
        # Run module tests in parallel
        print("\n🧪 Testing Modules in Parallel...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_module = {
                executor.submit(self.test_module_functionality, name, base, subs): name
                for name, base, subs in self.modules_to_test
            }
            
            for future in concurrent.futures.as_completed(future_to_module):
                module_name = future_to_module[future]
                try:
                    result = future.result()
                    self.test_results["modules"][module_name] = result
                    
                    # Print result
                    status_icon = "✅" if result["status"] == "passed" else "⚠️" if result["status"] == "partial" else "❌"
                    print(f"{status_icon} {module_name}: {result['status']} ({result.get('success_rate', 'N/A')})")
                    
                except Exception as e:
                    print(f"❌ {module_name}: Exception - {str(e)}")
                    self.test_results["modules"][module_name] = {
                        "status": "error",
                        "error": str(e),
                        "traceback": traceback.format_exc()
                    }
        
        # Calculate summary
        self.calculate_summary()
        
    def calculate_summary(self):
        """Calculate test summary statistics"""
        total = len(self.modules_to_test)
        passed = sum(1 for m in self.test_results["modules"].values() if m.get("status") == "passed")
        failed = sum(1 for m in self.test_results["modules"].values() if m.get("status") in ["failed", "error"])
        partial = sum(1 for m in self.test_results["modules"].values() if m.get("status") == "partial")
        
        self.test_results["summary"] = {
            "total_modules": total,
            "passed": passed,
            "failed": failed,
            "partial": partial,
            "success_rate": f"{(passed/total)*100:.1f}%" if total > 0 else "0%"
        }

    def generate_report(self) -> str:
        """Generate a detailed test report"""
        report = []
        report.append("=" * 80)
        report.append("COMPREHENSIVE MODULE TEST REPORT")
        report.append("=" * 80)
        report.append(f"Timestamp: {self.test_results['timestamp']}")
        report.append(f"Python Version: {sys.version.split()[0]}")
        report.append("")
        
        # Dependencies
        report.append("DEPENDENCIES STATUS:")
        report.append("-" * 40)
        for dep, installed in self.test_results.get("dependencies", {}).items():
            status = "✅ Installed" if installed else "❌ Missing"
            report.append(f"  {dep}: {status}")
        
        # Module Results
        report.append("\nMODULE TEST RESULTS:")
        report.append("-" * 40)
        for module_name, result in self.test_results.get("modules", {}).items():
            status = result.get("status", "unknown")
            success_rate = result.get("success_rate", "N/A")
            status_icon = "✅" if status == "passed" else "⚠️" if status == "partial" else "❌"
            report.append(f"\n{status_icon} {module_name}")
            report.append(f"   Status: {status} ({success_rate})")
            
            if result.get("errors"):
                report.append("   Errors:")
                for error in result["errors"][:3]:  # Show first 3 errors
                    report.append(f"     - {error}")
        
        # Summary
        summary = self.test_results.get("summary", {})
        report.append("\nSUMMARY:")
        report.append("-" * 40)
        report.append(f"Total Modules: {summary.get('total_modules', 0)}")
        report.append(f"Passed: {summary.get('passed', 0)}")
        report.append(f"Failed: {summary.get('failed', 0)}")
        report.append(f"Partial: {summary.get('partial', 0)}")
        report.append(f"Success Rate: {summary.get('success_rate', '0%')}")
        
        return "\n".join(report)

    def save_results(self):
        """Save test results to JSON file"""
        filename = f"test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(self.test_results, f, indent=2)
        print(f"\n📄 Detailed results saved to: {filename}")

def main():
    """Main test execution"""
    tester = ComprehensiveTestSuite()
    
    # Run tests
    tester.run_parallel_tests()
    
    # Generate and print report
    report = tester.generate_report()
    print("\n" + report)
    
    # Save results
    tester.save_results()
    
    # Return exit code based on results
    summary = tester.test_results.get("summary", {})
    if summary.get("failed", 0) > 0:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()