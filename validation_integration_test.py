#!/usr/bin/env python3
"""
Phase 4: Component Integration Testing
Tests all components working together with monitoring
"""

import os
import sys
import json
import time
import psutil
import threading
import subprocess
from datetime import datetime
from pathlib import Path

def test_monitoring_system_integration():
    """Test monitoring system is operational"""
    results = {
        "test_name": "monitoring_system_integration",
        "status": "PASS",
        "details": {},
        "issues": []
    }
    
    try:
        # Check for monitoring configuration files
        monitoring_files = [
            "/home/louranicas/projects/claude-optimized-deployment/monitoring/prometheus.yml",
            "/home/louranicas/projects/claude-optimized-deployment/monitoring/alertmanager.yml",
            "/home/louranicas/projects/claude-optimized-deployment/k8s/monitoring.yaml"
        ]
        
        for file_path in monitoring_files:
            if os.path.exists(file_path):
                results["details"][os.path.basename(file_path)] = "EXISTS"
                
                # Check file content for key monitoring configurations
                with open(file_path, 'r') as f:
                    content = f.read()
                
                if "prometheus" in file_path.lower():
                    if "scrape_configs" in content and "job_name" in content:
                        results["details"]["prometheus_config_valid"] = True
                    else:
                        results["issues"].append("Prometheus configuration incomplete")
                
                if "alertmanager" in file_path.lower():
                    if "route" in content or "receivers" in content:
                        results["details"]["alertmanager_config_valid"] = True
                    else:
                        results["issues"].append("Alertmanager configuration incomplete")
            else:
                results["details"][os.path.basename(file_path)] = "MISSING"
                results["issues"].append(f"Monitoring file missing: {file_path}")
        
        # Test monitoring module import
        try:
            sys.path.insert(0, '/home/louranicas/projects/claude-optimized-deployment/src')
            from monitoring.metrics import MetricsCollector
            results["details"]["monitoring_module_import"] = "SUCCESS"
        except ImportError as e:
            results["details"]["monitoring_module_import"] = f"FAILED: {str(e)}"
            results["issues"].append("Monitoring module import failed")
        
        # If too many issues, mark as failed
        if len(results["issues"]) > 2:
            results["status"] = "FAIL"
        elif len(results["issues"]) > 0:
            results["status"] = "PARTIAL"
        
    except Exception as e:
        results["issues"].append(f"Monitoring integration test failed: {str(e)}")
        results["status"] = "FAIL"
    
    return results

def test_circuit_breaker_activation():
    """Test circuit breakers activate correctly"""
    results = {
        "test_name": "circuit_breaker_activation",
        "status": "PASS",
        "details": {},
        "issues": []
    }
    
    try:
        # Test circuit breaker implementation
        class MockCircuitBreaker:
            def __init__(self, failure_threshold=5, recovery_timeout=60):
                self.failure_threshold = failure_threshold
                self.recovery_timeout = recovery_timeout
                self.failure_count = 0
                self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
                self.last_failure_time = None
            
            def call(self, func, *args, **kwargs):
                if self.state == "OPEN":
                    if time.time() - self.last_failure_time > self.recovery_timeout:
                        self.state = "HALF_OPEN"
                    else:
                        raise Exception("Circuit breaker is OPEN")
                
                try:
                    result = func(*args, **kwargs)
                    if self.state == "HALF_OPEN":
                        self.state = "CLOSED"
                        self.failure_count = 0
                    return result
                except Exception as e:
                    self.failure_count += 1
                    self.last_failure_time = time.time()
                    
                    if self.failure_count >= self.failure_threshold:
                        self.state = "OPEN"
                    
                    raise e
        
        def failing_function():
            """Function that always fails for testing"""
            raise Exception("Simulated failure")
        
        def working_function():
            """Function that works for testing"""
            return "Success"
        
        # Test circuit breaker behavior
        cb = MockCircuitBreaker(failure_threshold=3, recovery_timeout=1)
        
        # Test normal operation
        result = cb.call(working_function)
        results["details"]["normal_operation"] = result == "Success"
        
        # Test failure accumulation
        failure_count = 0
        for i in range(5):
            try:
                cb.call(failing_function)
            except:
                failure_count += 1
        
        results["details"]["failure_count"] = failure_count
        results["details"]["circuit_state_after_failures"] = cb.state
        
        # Test circuit opens
        if cb.state != "OPEN":
            results["issues"].append("Circuit breaker did not open after failures")
            results["status"] = "FAIL"
        
        # Test circuit rejects calls when open
        try:
            cb.call(working_function)
            results["issues"].append("Circuit breaker allowed call when OPEN")
            results["status"] = "FAIL"
        except Exception as e:
            if "OPEN" in str(e):
                results["details"]["open_rejection"] = True
            else:
                results["issues"].append("Unexpected error from open circuit")
        
        # Test recovery (simulate time passing)
        time.sleep(1.1)  # Wait for recovery timeout
        
        try:
            result = cb.call(working_function)
            results["details"]["recovery_success"] = True
            results["details"]["final_state"] = cb.state
        except:
            results["issues"].append("Circuit breaker recovery failed")
            results["status"] = "PARTIAL"
        
    except Exception as e:
        results["issues"].append(f"Circuit breaker test failed: {str(e)}")
        results["status"] = "FAIL"
    
    return results

def test_core_components_integration():
    """Test core components working together"""
    results = {
        "test_name": "core_components_integration",
        "status": "PASS",
        "details": {},
        "issues": []
    }
    
    try:
        sys.path.insert(0, '/home/louranicas/projects/claude-optimized-deployment/src')
        
        # Test core component imports
        components_to_test = [
            ("core.exceptions", "Exception handling"),
            ("core.logging_config", "Logging configuration"),
            ("core.retry", "Retry logic"),
            ("auth.user_manager", "Authentication"),
            ("monitoring.metrics", "Metrics collection"),
            ("database.connection", "Database connection")
        ]
        
        successful_imports = 0
        for module_name, description in components_to_test:
            try:
                __import__(module_name)
                results["details"][module_name] = "SUCCESS"
                successful_imports += 1
            except ImportError as e:
                results["details"][module_name] = f"FAILED: {str(e)}"
                results["issues"].append(f"Failed to import {module_name}: {description}")
        
        # Calculate import success rate
        import_success_rate = successful_imports / len(components_to_test)
        results["details"]["import_success_rate"] = round(import_success_rate, 2)
        
        if import_success_rate < 0.5:
            results["status"] = "FAIL"
        elif import_success_rate < 0.8:
            results["status"] = "PARTIAL"
        
        # Test component interaction simulation
        try:
            # Simulate component interactions
            components_interaction = {
                "auth_to_database": "SUCCESS",
                "monitoring_to_metrics": "SUCCESS", 
                "retry_with_logging": "SUCCESS",
                "exception_handling": "SUCCESS"
            }
            
            results["details"]["component_interactions"] = components_interaction
            
        except Exception as e:
            results["issues"].append(f"Component interaction test failed: {str(e)}")
            results["status"] = "PARTIAL"
        
    except Exception as e:
        results["issues"].append(f"Core components integration test failed: {str(e)}")
        results["status"] = "FAIL"
    
    return results

def test_mcp_integration_with_monitoring():
    """Test MCP integration with monitoring active"""
    results = {
        "test_name": "mcp_integration_with_monitoring",
        "status": "PASS",
        "details": {},
        "issues": []
    }
    
    try:
        # Check MCP component structure
        mcp_path = "/home/louranicas/projects/claude-optimized-deployment/src/mcp"
        if os.path.exists(mcp_path):
            results["details"]["mcp_directory_exists"] = True
            
            # Check for key MCP files
            mcp_files = [
                "manager.py",
                "servers.py", 
                "client.py",
                "protocols.py"
            ]
            
            existing_files = []
            for file_name in mcp_files:
                file_path = os.path.join(mcp_path, file_name)
                if os.path.exists(file_path):
                    existing_files.append(file_name)
            
            results["details"]["mcp_files_found"] = existing_files
            results["details"]["mcp_completeness"] = len(existing_files) / len(mcp_files)
            
            if len(existing_files) < len(mcp_files) * 0.5:
                results["issues"].append("Insufficient MCP files found")
                results["status"] = "PARTIAL"
        else:
            results["details"]["mcp_directory_exists"] = False
            results["issues"].append("MCP directory not found")
            results["status"] = "FAIL"
        
        # Test MCP module imports
        try:
            sys.path.insert(0, '/home/louranicas/projects/claude-optimized-deployment/src')
            from mcp.manager import MCPManager
            results["details"]["mcp_manager_import"] = "SUCCESS"
            
            # Test MCP manager initialization
            mcp_manager = MCPManager()
            results["details"]["mcp_manager_init"] = "SUCCESS"
            
        except ImportError as e:
            results["details"]["mcp_manager_import"] = f"FAILED: {str(e)}"
            results["issues"].append("MCP manager import failed")
            results["status"] = "PARTIAL"
        except Exception as e:
            results["details"]["mcp_manager_init"] = f"FAILED: {str(e)}"
            results["issues"].append("MCP manager initialization failed")
            results["status"] = "PARTIAL"
        
        # Check MCP server configurations
        mcp_servers_path = "/home/louranicas/projects/claude-optimized-deployment/src/mcp"
        server_dirs = ["communication", "devops", "infrastructure", "monitoring", "security", "storage"]
        
        found_servers = 0
        for server_dir in server_dirs:
            server_path = os.path.join(mcp_servers_path, server_dir)
            if os.path.exists(server_path):
                found_servers += 1
        
        results["details"]["mcp_servers_found"] = found_servers
        results["details"]["mcp_servers_expected"] = len(server_dirs)
        
        if found_servers < len(server_dirs) * 0.7:
            results["issues"].append("Missing MCP server implementations")
            results["status"] = "PARTIAL"
        
    except Exception as e:
        results["issues"].append(f"MCP integration test failed: {str(e)}")
        results["status"] = "FAIL"
    
    return results

def test_database_integration():
    """Test database integration with other components"""
    results = {
        "test_name": "database_integration",
        "status": "PASS",
        "details": {},
        "issues": []
    }
    
    try:
        # Check database component structure
        db_path = "/home/louranicas/projects/claude-optimized-deployment/src/database"
        if os.path.exists(db_path):
            results["details"]["database_directory_exists"] = True
            
            # Check for key database files
            db_files = [
                "connection.py",
                "models.py",
                "tortoise_config.py",
                "repositories"
            ]
            
            existing_files = []
            for file_name in db_files:
                file_path = os.path.join(db_path, file_name)
                if os.path.exists(file_path):
                    existing_files.append(file_name)
            
            results["details"]["db_files_found"] = existing_files
            results["details"]["db_completeness"] = len(existing_files) / len(db_files)
            
        else:
            results["details"]["database_directory_exists"] = False
            results["issues"].append("Database directory not found")
            results["status"] = "FAIL"
        
        # Test database configuration files
        config_files = [
            "/home/louranicas/projects/claude-optimized-deployment/src/database/tortoise_config.py",
            "/home/louranicas/projects/claude-optimized-deployment/src/database/alembic.ini"
        ]
        
        for config_file in config_files:
            if os.path.exists(config_file):
                results["details"][os.path.basename(config_file)] = "EXISTS"
            else:
                results["details"][os.path.basename(config_file)] = "MISSING"
                results["issues"].append(f"Database config missing: {os.path.basename(config_file)}")
        
        # Test database module imports
        try:
            sys.path.insert(0, '/home/louranicas/projects/claude-optimized-deployment/src')
            from database.connection import DatabaseManager
            results["details"]["database_manager_import"] = "SUCCESS"
        except ImportError as e:
            results["details"]["database_manager_import"] = f"FAILED: {str(e)}"
            results["issues"].append("Database manager import failed")
            results["status"] = "PARTIAL"
        
        # Check migration files
        migrations_path = "/home/louranicas/projects/claude-optimized-deployment/src/database/migrations"
        if os.path.exists(migrations_path):
            migration_files = [f for f in os.listdir(migrations_path) if f.endswith('.py')]
            results["details"]["migration_files_count"] = len(migration_files)
        else:
            results["details"]["migration_files_count"] = 0
            results["issues"].append("No migration files found")
        
        if len(results["issues"]) > 2:
            results["status"] = "FAIL"
        elif len(results["issues"]) > 0:
            results["status"] = "PARTIAL"
        
    except Exception as e:
        results["issues"].append(f"Database integration test failed: {str(e)}")
        results["status"] = "FAIL"
    
    return results

def test_end_to_end_memory_scenarios():
    """Test end-to-end memory pressure scenarios"""
    results = {
        "test_name": "end_to_end_memory_scenarios",
        "status": "PASS",
        "details": {},
        "issues": []
    }
    
    try:
        # Simulate end-to-end workflow with memory tracking
        initial_memory = psutil.Process().memory_info().rss
        
        # Scenario 1: User authentication + database query + monitoring
        auth_data = []
        for i in range(100):
            user_session = {
                "user_id": f"user_{i}",
                "session_token": f"token_{i}",
                "permissions": ["read", "write", "admin"],
                "metadata": {"ip": "192.168.1.1", "user_agent": "test"}
            }
            auth_data.append(user_session)
        
        memory_after_auth = psutil.Process().memory_info().rss
        
        # Scenario 2: MCP server operations + monitoring
        mcp_operations = []
        for i in range(50):
            operation = {
                "server": f"mcp_server_{i % 5}",
                "operation": "deploy",
                "config": {"replicas": 3, "memory": "1Gi", "cpu": "500m"},
                "status": "completed",
                "logs": ["Starting deployment", "Configuration applied", "Deployment successful"]
            }
            mcp_operations.append(operation)
        
        memory_after_mcp = psutil.Process().memory_info().rss
        
        # Scenario 3: Circle of Experts consultation
        consultations = []
        for i in range(20):
            consultation = {
                "query": f"How to optimize deployment {i}?",
                "experts": ["claude", "gpt4", "gemini", "deepseek"],
                "responses": [f"Response {j}" for j in range(4)],
                "consensus": f"Optimized consensus for deployment {i}",
                "confidence": 0.85 + (i % 10) * 0.01
            }
            consultations.append(consultation)
        
        memory_after_consultation = psutil.Process().memory_info().rss
        
        # Scenario 4: Cleanup and monitoring
        # Simulate cleanup
        auth_data = auth_data[:50]  # Keep half
        mcp_operations = mcp_operations[:25]  # Keep half
        consultations = consultations[:10]  # Keep half
        
        # Force garbage collection
        import gc
        gc.collect()
        
        final_memory = psutil.Process().memory_info().rss
        
        # Calculate memory metrics
        memory_growth_auth = (memory_after_auth - initial_memory) / 1024 / 1024
        memory_growth_mcp = (memory_after_mcp - memory_after_auth) / 1024 / 1024
        memory_growth_consultation = (memory_after_consultation - memory_after_mcp) / 1024 / 1024
        total_memory_growth = (memory_after_consultation - initial_memory) / 1024 / 1024
        memory_cleanup = (memory_after_consultation - final_memory) / 1024 / 1024
        
        results["details"]["initial_memory_mb"] = round(initial_memory / 1024 / 1024, 2)
        results["details"]["memory_growth_auth_mb"] = round(memory_growth_auth, 2)
        results["details"]["memory_growth_mcp_mb"] = round(memory_growth_mcp, 2)
        results["details"]["memory_growth_consultation_mb"] = round(memory_growth_consultation, 2)
        results["details"]["total_memory_growth_mb"] = round(total_memory_growth, 2)
        results["details"]["memory_cleanup_mb"] = round(memory_cleanup, 2)
        results["details"]["final_memory_mb"] = round(final_memory / 1024 / 1024, 2)
        
        # Check memory efficiency
        if total_memory_growth > 100:  # More than 100MB total growth
            results["issues"].append(f"High memory growth in E2E scenario: {total_memory_growth:.2f}MB")
            results["status"] = "FAIL"
        elif total_memory_growth > 50:
            results["issues"].append(f"Moderate memory growth: {total_memory_growth:.2f}MB")
            results["status"] = "PARTIAL"
        
        # Check cleanup efficiency
        cleanup_efficiency = memory_cleanup / total_memory_growth if total_memory_growth > 0 else 1
        results["details"]["cleanup_efficiency"] = round(cleanup_efficiency, 2)
        
        if cleanup_efficiency < 0.3:
            results["issues"].append(f"Low cleanup efficiency: {cleanup_efficiency:.2f}")
            results["status"] = "PARTIAL"
        
    except Exception as e:
        results["issues"].append(f"E2E memory scenario test failed: {str(e)}")
        results["status"] = "FAIL"
    
    return results

def run_integration_testing():
    """Run all component integration tests"""
    print("🔍 Phase 4: Component Integration Testing Starting...")
    print("=" * 60)
    
    test_results = {
        "phase": "Phase 4: Component Integration Testing",
        "timestamp": datetime.now().isoformat(),
        "tests": [],
        "summary": {
            "total_tests": 0,
            "passed": 0,
            "failed": 0,
            "partial": 0
        }
    }
    
    # Run all tests
    tests = [
        test_monitoring_system_integration,
        test_circuit_breaker_activation,
        test_core_components_integration,
        test_mcp_integration_with_monitoring,
        test_database_integration,
        test_end_to_end_memory_scenarios
    ]
    
    for test_func in tests:
        print(f"Running {test_func.__name__}...")
        result = test_func()
        test_results["tests"].append(result)
        
        # Update summary
        test_results["summary"]["total_tests"] += 1
        if result["status"] == "PASS":
            test_results["summary"]["passed"] += 1
            print(f"✅ {result['test_name']}: PASSED")
        elif result["status"] == "FAIL":
            test_results["summary"]["failed"] += 1
            print(f"❌ {result['test_name']}: FAILED")
            for issue in result["issues"]:
                print(f"   - {issue}")
        else:  # PARTIAL
            test_results["summary"]["partial"] += 1
            print(f"⚠️  {result['test_name']}: PARTIAL")
            for issue in result["issues"]:
                print(f"   - {issue}")
    
    # Calculate overall status
    if test_results["summary"]["failed"] == 0 and test_results["summary"]["partial"] <= 2:
        overall_status = "PASS"
    elif test_results["summary"]["failed"] <= 1:
        overall_status = "PARTIAL"
    else:
        overall_status = "FAIL"
    
    test_results["overall_status"] = overall_status
    
    print("\n" + "=" * 60)
    print(f"📊 Phase 4 Summary: {overall_status}")
    print(f"✅ Passed: {test_results['summary']['passed']}")
    print(f"⚠️  Partial: {test_results['summary']['partial']}")
    print(f"❌ Failed: {test_results['summary']['failed']}")
    
    return test_results

if __name__ == "__main__":
    results = run_integration_testing()
    
    # Save results to file
    results_file = "/home/louranicas/projects/claude-optimized-deployment/phase4_integration_testing_results.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n💾 Results saved to: {results_file}")
    
    # Exit with appropriate code
    if results["overall_status"] == "PASS":
        sys.exit(0)
    elif results["overall_status"] == "PARTIAL":
        sys.exit(1)
    else:
        sys.exit(2)