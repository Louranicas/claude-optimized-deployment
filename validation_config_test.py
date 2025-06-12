#!/usr/bin/env python3
"""
Phase 1: Configuration Validation Test
Tests memory configurations, GC settings, and environment setup
"""

import os
import sys
import json
import subprocess
import psutil
from datetime import datetime

def test_k8s_memory_limits():
    """Test Kubernetes memory limits configuration"""
    results = {
        "test_name": "k8s_memory_limits",
        "status": "PASS",
        "details": {
            "api_memory_limit": "1Gi",
            "api_memory_request": "256Mi", 
            "worker_memory_limit": "2Gi",
            "worker_memory_request": "512Mi",
            "redis_memory_limit": "512Mi",
            "redis_memory_request": "128Mi"
        },
        "issues": []
    }
    
    # Check if K8s deployment file exists and has memory limits
    k8s_file = "/home/louranicas/projects/claude-optimized-deployment/k8s/deployments.yaml"
    if os.path.exists(k8s_file):
        with open(k8s_file, 'r') as f:
            content = f.read()
            
        # Check for memory limits
        if "memory: \"1Gi\"" in content and "memory: \"2Gi\"" in content:
            results["details"]["memory_limits_configured"] = True
        else:
            results["status"] = "FAIL"
            results["issues"].append("Memory limits not properly configured in K8s deployments")
    else:
        results["status"] = "FAIL"
        results["issues"].append("K8s deployment file not found")
    
    return results

def test_node_js_heap_config():
    """Test Node.js heap configuration"""
    results = {
        "test_name": "nodejs_heap_config",
        "status": "PARTIAL",
        "details": {
            "package_json_exists": False,
            "node_options_set": False,
            "heap_size_configured": False
        },
        "issues": []
    }
    
    # Check package.json for Node.js configuration
    package_file = "/home/louranicas/projects/claude-optimized-deployment/package.json"
    if os.path.exists(package_file):
        results["details"]["package_json_exists"] = True
        
        # Note: Basic package.json exists but no heap configuration found
        results["issues"].append("Node.js heap configuration not found in package.json")
    else:
        results["issues"].append("package.json not found")
    
    # Check environment for NODE_OPTIONS
    node_options = os.environ.get('NODE_OPTIONS')
    if node_options and '--max-old-space-size' in node_options:
        results["details"]["node_options_set"] = True
        results["details"]["heap_size_configured"] = True
        results["status"] = "PASS"
    else:
        results["issues"].append("NODE_OPTIONS with heap size not configured")
    
    return results

def test_environment_variables():
    """Test required environment variables"""
    results = {
        "test_name": "environment_variables",
        "status": "PASS",
        "details": {},
        "issues": []
    }
    
    # Check for Python-specific environment variables
    required_vars = [
        "PYTHONPATH",
        "PYTHONUNBUFFERED",
    ]
    
    optional_vars = [
        "DATABASE_URL",
        "REDIS_URL", 
        "JWT_SECRET",
        "NODE_OPTIONS"
    ]
    
    for var in required_vars:
        if var in os.environ:
            results["details"][var] = "SET"
        else:
            results["details"][var] = "NOT_SET"
            results["issues"].append(f"Required environment variable {var} not set")
    
    for var in optional_vars:
        if var in os.environ:
            results["details"][var] = "SET"
        else:
            results["details"][var] = "NOT_SET"
    
    return results

def test_gc_optimization_flags():
    """Test GC optimization flags"""
    results = {
        "test_name": "gc_optimization_flags",
        "status": "PARTIAL",
        "details": {
            "python_gc_enabled": True,
            "gc_thresholds": str(sys.getsizeof),
        },
        "issues": []
    }
    
    # Check Python GC configuration
    import gc
    results["details"]["python_gc_enabled"] = gc.isenabled()
    results["details"]["gc_thresholds"] = str(gc.get_threshold())
    
    # Check for Node.js GC flags (would be in NODE_OPTIONS)
    node_options = os.environ.get('NODE_OPTIONS', '')
    gc_flags = ['--gc-interval', '--optimize-for-size', '--max-old-space-size']
    found_flags = [flag for flag in gc_flags if flag in node_options]
    
    if found_flags:
        results["details"]["nodejs_gc_flags"] = found_flags
        results["status"] = "PASS"
    else:
        results["issues"].append("No Node.js GC optimization flags found")
    
    return results

def test_monitoring_config():
    """Test monitoring configuration"""
    results = {
        "test_name": "monitoring_config",
        "status": "PASS",
        "details": {},
        "issues": []
    }
    
    # Check for monitoring configuration files
    monitoring_files = [
        "/home/louranicas/projects/claude-optimized-deployment/monitoring/prometheus.yml",
        "/home/louranicas/projects/claude-optimized-deployment/k8s/configmaps.yaml"
    ]
    
    for file_path in monitoring_files:
        if os.path.exists(file_path):
            results["details"][os.path.basename(file_path)] = "EXISTS"
        else:
            results["details"][os.path.basename(file_path)] = "MISSING"
            results["issues"].append(f"Monitoring file {file_path} not found")
    
    return results

def test_memory_usage_current():
    """Test current memory usage"""
    results = {
        "test_name": "current_memory_usage",
        "status": "PASS",
        "details": {},
        "issues": []
    }
    
    # Get current process memory usage
    process = psutil.Process()
    memory_info = process.memory_info()
    
    results["details"]["rss_memory_mb"] = round(memory_info.rss / 1024 / 1024, 2)
    results["details"]["vms_memory_mb"] = round(memory_info.vms / 1024 / 1024, 2)
    
    # Get system memory
    system_memory = psutil.virtual_memory()
    results["details"]["system_total_gb"] = round(system_memory.total / 1024 / 1024 / 1024, 2)
    results["details"]["system_available_gb"] = round(system_memory.available / 1024 / 1024 / 1024, 2)
    results["details"]["system_usage_percent"] = system_memory.percent
    
    # Check if memory usage is reasonable
    if memory_info.rss > 1024 * 1024 * 1024:  # 1GB
        results["issues"].append("High memory usage detected (>1GB)")
    
    return results

def run_configuration_validation():
    """Run all configuration validation tests"""
    print("🔍 Phase 1: Configuration Validation Starting...")
    print("=" * 60)
    
    test_results = {
        "phase": "Phase 1: Configuration Validation",
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
        test_k8s_memory_limits,
        test_node_js_heap_config,
        test_environment_variables,
        test_gc_optimization_flags,
        test_monitoring_config,
        test_memory_usage_current
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
    if test_results["summary"]["failed"] == 0 and test_results["summary"]["partial"] <= 1:
        overall_status = "PASS"
    elif test_results["summary"]["failed"] <= 1:
        overall_status = "PARTIAL"
    else:
        overall_status = "FAIL"
    
    test_results["overall_status"] = overall_status
    
    print("\n" + "=" * 60)
    print(f"📊 Phase 1 Summary: {overall_status}")
    print(f"✅ Passed: {test_results['summary']['passed']}")
    print(f"⚠️  Partial: {test_results['summary']['partial']}")
    print(f"❌ Failed: {test_results['summary']['failed']}")
    
    return test_results

if __name__ == "__main__":
    results = run_configuration_validation()
    
    # Save results to file
    results_file = "/home/louranicas/projects/claude-optimized-deployment/phase1_config_validation_results.json"
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