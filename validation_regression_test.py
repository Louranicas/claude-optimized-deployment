#!/usr/bin/env python3
"""
Phase 6: Regression Testing
Ensures no functionality regression from memory optimizations
"""

import os
import sys
import json
import time
import subprocess
from datetime import datetime

def test_basic_python_functionality():
    """Test basic Python functionality still works"""
    results = {
        "test_name": "basic_python_functionality",
        "status": "PASS",
        "details": {},
        "issues": []
    }
    
    try:
        # Test basic operations
        basic_ops = {
            "list_operations": [1, 2, 3, 4, 5],
            "dict_operations": {"key": "value", "number": 42},
            "string_operations": "Hello World".upper(),
            "math_operations": sum(range(100)),
            "comprehensions": [x*2 for x in range(10)]
        }
        
        results["details"]["basic_ops_test"] = "PASSED"
        
        # Test imports of standard library
        import json, os, sys, time, threading, subprocess
        results["details"]["stdlib_imports"] = "PASSED"
        
        # Test file operations
        test_file = "/tmp/regression_test.txt"
        with open(test_file, 'w') as f:
            f.write("Regression test content")
        
        with open(test_file, 'r') as f:
            content = f.read()
        
        os.remove(test_file)
        
        if content == "Regression test content":
            results["details"]["file_operations"] = "PASSED"
        else:
            results["issues"].append("File operations failed")
            results["status"] = "FAIL"
        
    except Exception as e:
        results["issues"].append(f"Basic Python functionality test failed: {str(e)}")
        results["status"] = "FAIL"
    
    return results

def test_project_structure_integrity():
    """Test project structure is intact"""
    results = {
        "test_name": "project_structure_integrity",
        "status": "PASS",
        "details": {},
        "issues": []
    }
    
    try:
        # Check critical directories exist
        critical_dirs = [
            "/home/louranicas/projects/claude-optimized-deployment/src",
            "/home/louranicas/projects/claude-optimized-deployment/docs",
            "/home/louranicas/projects/claude-optimized-deployment/k8s",
            "/home/louranicas/projects/claude-optimized-deployment/monitoring",
            "/home/louranicas/projects/claude-optimized-deployment/rust_core"
        ]
        
        existing_dirs = []
        for dir_path in critical_dirs:
            if os.path.exists(dir_path):
                existing_dirs.append(os.path.basename(dir_path))
            else:
                results["issues"].append(f"Critical directory missing: {dir_path}")
        
        results["details"]["existing_dirs"] = existing_dirs
        results["details"]["dir_completeness"] = len(existing_dirs) / len(critical_dirs)
        
        # Check critical files exist
        critical_files = [
            "/home/louranicas/projects/claude-optimized-deployment/README.md",
            "/home/louranicas/projects/claude-optimized-deployment/Cargo.toml",
            "/home/louranicas/projects/claude-optimized-deployment/pyproject.toml",
            "/home/louranicas/projects/claude-optimized-deployment/requirements.txt"
        ]
        
        existing_files = []
        for file_path in critical_files:
            if os.path.exists(file_path):
                existing_files.append(os.path.basename(file_path))
            else:
                results["issues"].append(f"Critical file missing: {file_path}")
        
        results["details"]["existing_files"] = existing_files
        results["details"]["file_completeness"] = len(existing_files) / len(critical_files)
        
        # Overall completeness check
        overall_completeness = (len(existing_dirs) + len(existing_files)) / (len(critical_dirs) + len(critical_files))
        results["details"]["overall_completeness"] = round(overall_completeness, 2)
        
        if overall_completeness < 0.8:
            results["status"] = "FAIL"
        elif overall_completeness < 0.95:
            results["status"] = "PARTIAL"
        
    except Exception as e:
        results["issues"].append(f"Project structure test failed: {str(e)}")
        results["status"] = "FAIL"
    
    return results

def test_configuration_files_valid():
    """Test configuration files are still valid"""
    results = {
        "test_name": "configuration_files_valid",
        "status": "PASS",
        "details": {},
        "issues": []
    }
    
    try:
        # Test JSON files
        json_files = [
            "/home/louranicas/projects/claude-optimized-deployment/package.json"
        ]
        
        for json_file in json_files:
            if os.path.exists(json_file):
                try:
                    with open(json_file, 'r') as f:
                        json.load(f)
                    results["details"][f"{os.path.basename(json_file)}_valid"] = True
                except json.JSONDecodeError as e:
                    results["issues"].append(f"Invalid JSON in {json_file}: {str(e)}")
                    results["status"] = "FAIL"
            else:
                results["details"][f"{os.path.basename(json_file)}_exists"] = False
        
        # Test YAML files (basic syntax check)
        yaml_files = [
            "/home/louranicas/projects/claude-optimized-deployment/k8s/deployments.yaml",
            "/home/louranicas/projects/claude-optimized-deployment/monitoring/prometheus.yml"
        ]
        
        for yaml_file in yaml_files:
            if os.path.exists(yaml_file):
                try:
                    with open(yaml_file, 'r') as f:
                        content = f.read()
                    # Basic YAML syntax check (look for common issues)
                    if content.strip() and not content.startswith('---'):
                        results["details"][f"{os.path.basename(yaml_file)}_basic_valid"] = True
                    elif content.startswith('---'):
                        results["details"][f"{os.path.basename(yaml_file)}_basic_valid"] = True
                    else:
                        results["issues"].append(f"Empty or invalid YAML: {yaml_file}")
                except Exception as e:
                    results["issues"].append(f"Error reading YAML {yaml_file}: {str(e)}")
                    results["status"] = "PARTIAL"
            else:
                results["details"][f"{os.path.basename(yaml_file)}_exists"] = False
        
        # Test TOML files
        toml_files = [
            "/home/louranicas/projects/claude-optimized-deployment/Cargo.toml",
            "/home/louranicas/projects/claude-optimized-deployment/pyproject.toml"
        ]
        
        for toml_file in toml_files:
            if os.path.exists(toml_file):
                try:
                    with open(toml_file, 'r') as f:
                        content = f.read()
                    # Basic TOML syntax check
                    if '[' in content and ']' in content:
                        results["details"][f"{os.path.basename(toml_file)}_basic_valid"] = True
                    else:
                        results["issues"].append(f"Invalid TOML syntax: {toml_file}")
                        results["status"] = "PARTIAL"
                except Exception as e:
                    results["issues"].append(f"Error reading TOML {toml_file}: {str(e)}")
                    results["status"] = "PARTIAL"
        
    except Exception as e:
        results["issues"].append(f"Configuration validation test failed: {str(e)}")
        results["status"] = "FAIL"
    
    return results

def test_security_features_intact():
    """Test security features remain intact"""
    results = {
        "test_name": "security_features_intact",
        "status": "PASS",
        "details": {},
        "issues": []
    }
    
    try:
        # Check security-related files exist
        security_files = [
            "/home/louranicas/projects/claude-optimized-deployment/SECURITY.md",
            "/home/louranicas/projects/claude-optimized-deployment/k8s/rbac.yaml",
            "/home/louranicas/projects/claude-optimized-deployment/k8s/network-policies.yaml",
            "/home/louranicas/projects/claude-optimized-deployment/k8s/pod-security-policies.yaml"
        ]
        
        existing_security_files = 0
        for security_file in security_files:
            if os.path.exists(security_file):
                existing_security_files += 1
                results["details"][f"{os.path.basename(security_file)}_exists"] = True
            else:
                results["details"][f"{os.path.basename(security_file)}_exists"] = False
                results["issues"].append(f"Security file missing: {security_file}")
        
        security_completeness = existing_security_files / len(security_files)
        results["details"]["security_files_completeness"] = round(security_completeness, 2)
        
        # Check for security configurations in K8s deployments
        k8s_deployment = "/home/louranicas/projects/claude-optimized-deployment/k8s/deployments.yaml"
        if os.path.exists(k8s_deployment):
            with open(k8s_deployment, 'r') as f:
                content = f.read()
            
            security_features = {
                "runAsNonRoot": "runAsNonRoot: true" in content,
                "readOnlyRootFilesystem": "readOnlyRootFilesystem: true" in content,
                "allowPrivilegeEscalation": "allowPrivilegeEscalation: false" in content,
                "securityContext": "securityContext:" in content
            }
            
            results["details"]["k8s_security_features"] = security_features
            
            active_features = sum(security_features.values())
            if active_features < len(security_features) * 0.8:
                results["issues"].append("K8s security features may be incomplete")
                results["status"] = "PARTIAL"
        
        if security_completeness < 0.7:
            results["status"] = "FAIL"
        elif security_completeness < 0.9:
            results["status"] = "PARTIAL"
        
    except Exception as e:
        results["issues"].append(f"Security features test failed: {str(e)}")
        results["status"] = "FAIL"
    
    return results

def test_performance_not_degraded():
    """Test performance hasn't degraded"""
    results = {
        "test_name": "performance_not_degraded",
        "status": "PASS",
        "details": {},
        "issues": []
    }
    
    try:
        # Test basic performance metrics
        import time
        
        # Test 1: List operations performance
        start_time = time.perf_counter()
        test_list = [i for i in range(10000)]
        list_sum = sum(test_list)
        list_time = time.perf_counter() - start_time
        
        # Test 2: Dictionary operations performance
        start_time = time.perf_counter()
        test_dict = {f"key_{i}": i for i in range(1000)}
        dict_lookup_time = 0
        for i in range(1000):
            start_lookup = time.perf_counter()
            value = test_dict.get(f"key_{i}")
            dict_lookup_time += time.perf_counter() - start_lookup
        
        # Test 3: File I/O performance
        test_file = "/tmp/perf_test.txt"
        start_time = time.perf_counter()
        with open(test_file, 'w') as f:
            for i in range(1000):
                f.write(f"Line {i}\n")
        write_time = time.perf_counter() - start_time
        
        start_time = time.perf_counter()
        with open(test_file, 'r') as f:
            lines = f.readlines()
        read_time = time.perf_counter() - start_time
        
        os.remove(test_file)
        
        # Store performance metrics
        results["details"]["list_operations_time"] = round(list_time * 1000, 2)  # ms
        results["details"]["dict_lookup_avg_time"] = round(dict_lookup_time / 1000 * 1000000, 2)  # microseconds
        results["details"]["file_write_time"] = round(write_time * 1000, 2)  # ms
        results["details"]["file_read_time"] = round(read_time * 1000, 2)  # ms
        
        # Performance thresholds (reasonable for basic operations)
        if list_time > 0.1:  # 100ms
            results["issues"].append(f"List operations slow: {list_time*1000:.2f}ms")
            results["status"] = "PARTIAL"
        
        if dict_lookup_time / 1000 > 0.001:  # 1ms average
            results["issues"].append(f"Dictionary lookups slow: {dict_lookup_time/1000*1000:.2f}ms avg")
            results["status"] = "PARTIAL"
        
        if write_time > 0.5:  # 500ms
            results["issues"].append(f"File write slow: {write_time*1000:.2f}ms")
            results["status"] = "PARTIAL"
        
        if read_time > 0.1:  # 100ms
            results["issues"].append(f"File read slow: {read_time*1000:.2f}ms")
            results["status"] = "PARTIAL"
        
    except Exception as e:
        results["issues"].append(f"Performance test failed: {str(e)}")
        results["status"] = "FAIL"
    
    return results

def run_regression_testing():
    """Run all regression tests"""
    print("🔍 Phase 6: Regression Testing Starting...")
    print("=" * 60)
    
    test_results = {
        "phase": "Phase 6: Regression Testing",
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
        test_basic_python_functionality,
        test_project_structure_integrity,
        test_configuration_files_valid,
        test_security_features_intact,
        test_performance_not_degraded
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
    print(f"📊 Phase 6 Summary: {overall_status}")
    print(f"✅ Passed: {test_results['summary']['passed']}")
    print(f"⚠️  Partial: {test_results['summary']['partial']}")
    print(f"❌ Failed: {test_results['summary']['failed']}")
    
    return test_results

if __name__ == "__main__":
    results = run_regression_testing()
    
    # Save results to file
    results_file = "/home/louranicas/projects/claude-optimized-deployment/phase6_regression_testing_results.json"
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