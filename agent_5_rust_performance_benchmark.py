#!/usr/bin/env python3
"""
AGENT 5 - Rust Integration and Compilation Performance Benchmark
Tests Rust optimization and build performance for AMD systems
"""

import subprocess
import time
import json
import os
from datetime import datetime
from pathlib import Path

def run_rust_build_benchmark():
    """Benchmark Rust compilation and optimization performance"""
    results = {
        "timestamp": datetime.now().isoformat(),
        "rust_build_performance": {},
        "optimization_validation": {},
        "system_detection": {}
    }
    
    # Check if Rust is available
    try:
        rust_version = subprocess.run(['rustc', '--version'], capture_output=True, text=True, timeout=10)
        results["system_detection"]["rust_available"] = True
        results["system_detection"]["rust_version"] = rust_version.stdout.strip()
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        results["system_detection"]["rust_available"] = False
        return results
    
    # Check Cargo.toml configuration
    cargo_toml_path = "/home/louranicas/projects/claude-optimized-deployment/Cargo.toml"
    if os.path.exists(cargo_toml_path):
        results["system_detection"]["cargo_config_exists"] = True
        
        # Test build performance
        build_start = time.perf_counter()
        try:
            build_result = subprocess.run(
                ['cargo', 'check', '--release'],
                cwd="/home/louranicas/projects/claude-optimized-deployment",
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            build_duration = time.perf_counter() - build_start
            
            results["rust_build_performance"]["build_success"] = build_result.returncode == 0
            results["rust_build_performance"]["build_duration"] = build_duration
            results["rust_build_performance"]["build_output"] = build_result.stdout
            if build_result.stderr:
                results["rust_build_performance"]["build_errors"] = build_result.stderr
                
        except subprocess.TimeoutExpired:
            results["rust_build_performance"]["build_success"] = False
            results["rust_build_performance"]["build_timeout"] = True
            
        # Check optimization flags
        try:
            with open(cargo_toml_path, 'r') as f:
                cargo_content = f.read()
                results["optimization_validation"]["has_release_profile"] = "[profile.release]" in cargo_content
                results["optimization_validation"]["has_bench_profile"] = "[profile.bench]" in cargo_content
                results["optimization_validation"]["lto_enabled"] = "lto = " in cargo_content
                results["optimization_validation"]["opt_level_3"] = "opt-level = 3" in cargo_content
        except Exception as e:
            results["optimization_validation"]["config_read_error"] = str(e)
    
    return results

def benchmark_cpu_features():
    """Benchmark CPU-specific features and optimizations"""
    results = {
        "cpu_features": {},
        "performance_tests": {}
    }
    
    # Check CPU features
    try:
        cpuinfo = subprocess.run(['cat', '/proc/cpuinfo'], capture_output=True, text=True)
        cpu_info = cpuinfo.stdout
        
        results["cpu_features"]["avx2_support"] = "avx2" in cpu_info.lower()
        results["cpu_features"]["fma_support"] = "fma" in cpu_info.lower()
        results["cpu_features"]["amd_cpu"] = "amd" in cpu_info.lower()
        results["cpu_features"]["ryzen_cpu"] = "ryzen" in cpu_info.lower()
        
        # Extract CPU model
        for line in cpu_info.split('\n'):
            if 'model name' in line and ':' in line:
                results["cpu_features"]["cpu_model"] = line.split(':', 1)[1].strip()
                break
                
    except Exception as e:
        results["cpu_features"]["detection_error"] = str(e)
    
    # Simple CPU benchmark
    start_time = time.perf_counter()
    
    # CPU-intensive operation
    total = 0
    for i in range(10_000_000):
        total += i * i + i ** 0.5
    
    cpu_duration = time.perf_counter() - start_time
    results["performance_tests"]["cpu_intensive_duration"] = cpu_duration
    results["performance_tests"]["cpu_operations_per_second"] = 10_000_000 / cpu_duration
    
    return results

def main():
    """Main benchmark execution"""
    print("🎯 AGENT 5 - Rust Performance and AMD Optimization Benchmark")
    print("=" * 70)
    
    # Run Rust build benchmark
    print("🦀 Testing Rust build performance...")
    rust_results = run_rust_build_benchmark()
    
    # Run CPU feature benchmark
    print("🖥️  Testing CPU features and performance...")
    cpu_results = benchmark_cpu_features()
    
    # Combine results
    final_results = {
        "agent_id": "AGENT_5",
        "test_type": "RUST_AMD_OPTIMIZATION_BENCHMARK",
        "timestamp": datetime.now().isoformat(),
        "rust_benchmark": rust_results,
        "cpu_benchmark": cpu_results
    }
    
    # Save results
    output_file = f"/home/louranicas/projects/claude-optimized-deployment/AGENT_5_RUST_AMD_BENCHMARK_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(final_results, f, indent=2)
    
    print(f"📊 Benchmark complete! Results saved to: {output_file}")
    
    # Print summary
    print("\n🎯 RUST BUILD SUMMARY:")
    print("=" * 40)
    if rust_results.get("system_detection", {}).get("rust_available"):
        print(f"✅ Rust Version: {rust_results['system_detection'].get('rust_version', 'Unknown')}")
        
        if rust_results.get("rust_build_performance", {}).get("build_success"):
            build_time = rust_results["rust_build_performance"]["build_duration"]
            print(f"✅ Build Success: {build_time:.2f}s")
        else:
            print("❌ Build Failed or Timed Out")
            
        # Optimization flags
        opt_validation = rust_results.get("optimization_validation", {})
        print(f"🔧 Release Profile: {'✅' if opt_validation.get('has_release_profile') else '❌'}")
        print(f"🔧 Optimization Level 3: {'✅' if opt_validation.get('opt_level_3') else '❌'}")
        print(f"🔧 LTO Enabled: {'✅' if opt_validation.get('lto_enabled') else '❌'}")
    else:
        print("❌ Rust not available")
    
    print("\n🖥️  CPU PERFORMANCE SUMMARY:")
    print("=" * 40)
    cpu_features = cpu_results.get("cpu_features", {})
    print(f"🖥️  CPU Model: {cpu_features.get('cpu_model', 'Unknown')}")
    print(f"🚀 AMD CPU: {'✅' if cpu_features.get('amd_cpu') else '❌'}")
    print(f"🚀 Ryzen CPU: {'✅' if cpu_features.get('ryzen_cpu') else '❌'}")
    print(f"🔧 AVX2 Support: {'✅' if cpu_features.get('avx2_support') else '❌'}")
    print(f"🔧 FMA Support: {'✅' if cpu_features.get('fma_support') else '❌'}")
    
    perf_tests = cpu_results.get("performance_tests", {})
    if "cpu_operations_per_second" in perf_tests:
        ops_per_sec = perf_tests["cpu_operations_per_second"]
        print(f"⚡ CPU Performance: {ops_per_sec:,.0f} ops/sec")
    
    return final_results

if __name__ == "__main__":
    main()