#!/usr/bin/env python3
"""
Hardware-Optimized Test Orchestrator
Leverages 16-thread CPU, 32GB RAM, and NVMe SSD for maximum test throughput
"""

import asyncio
import multiprocessing
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import psutil
import json
import subprocess
from datetime import datetime
import tempfile
import shutil

# Performance monitoring
try:
    import pynvml
    NVIDIA_AVAILABLE = True
    pynvml.nvmlInit()
except:
    NVIDIA_AVAILABLE = False


@dataclass
class TestConfiguration:
    """Hardware-optimized test configuration"""
    # CPU settings
    parallel_processes: int = 12  # Leave 4 threads for system
    thread_pool_size: int = 16
    
    # Memory settings
    max_memory_per_process: int = 1024 * 1024 * 1024  # 1GB per process
    total_memory_limit: int = 16 * 1024 * 1024 * 1024  # 16GB for testing
    
    # Storage settings
    test_data_path: Path = Path("/tmp/test_data")  # Use fast NVMe storage
    cache_path: Path = Path("/tmp/test_cache")
    results_path: Path = Path("./test_results")
    
    # Test categories
    test_categories: List[str] = field(default_factory=lambda: [
        "unit", "integration", "ffi", "performance", "security",
        "mcp", "rust", "memory", "stress", "e2e"
    ])
    
    # GPU settings
    use_gpu: bool = True
    gpu_tests_markers: List[str] = field(default_factory=lambda: ["gpu", "ml", "ai"])


class HardwareMonitor:
    """Monitor system resources during test execution"""
    
    def __init__(self):
        self.cpu_percent_history = []
        self.memory_usage_history = []
        self.disk_io_history = []
        self.gpu_usage_history = []
        
    def capture_metrics(self) -> Dict:
        """Capture current system metrics"""
        metrics = {
            "timestamp": datetime.now().isoformat(),
            "cpu_percent": psutil.cpu_percent(interval=0.1, percpu=True),
            "cpu_freq": psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None,
            "memory": psutil.virtual_memory()._asdict(),
            "disk_io": psutil.disk_io_counters()._asdict() if psutil.disk_io_counters() else None,
            "network_io": psutil.net_io_counters()._asdict() if psutil.net_io_counters() else None,
        }
        
        # GPU metrics if available
        if NVIDIA_AVAILABLE:
            try:
                handle = pynvml.nvmlDeviceGetHandleByIndex(0)
                metrics["gpu"] = {
                    "utilization": pynvml.nvmlDeviceGetUtilizationRates(handle).gpu,
                    "memory_used": pynvml.nvmlDeviceGetMemoryInfo(handle).used,
                    "memory_total": pynvml.nvmlDeviceGetMemoryInfo(handle).total,
                    "temperature": pynvml.nvmlDeviceGetTemperature(handle, pynvml.NVML_TEMPERATURE_GPU)
                }
            except:
                pass
                
        return metrics


class TestOrchestrator:
    """Main test orchestration system"""
    
    def __init__(self, config: TestConfiguration):
        self.config = config
        self.monitor = HardwareMonitor()
        self.test_results = {}
        self.performance_baselines = {}
        
        # Initialize directories
        self._setup_directories()
        
        # Load performance baselines if they exist
        self._load_performance_baselines()
        
    def _setup_directories(self):
        """Setup test directories on fast storage"""
        for path in [self.config.test_data_path, self.config.cache_path, self.config.results_path]:
            path.mkdir(parents=True, exist_ok=True)
            
    def _load_performance_baselines(self):
        """Load existing performance baselines"""
        baseline_file = self.config.results_path / "performance_baselines.json"
        if baseline_file.exists():
            with open(baseline_file, 'r') as f:
                self.performance_baselines = json.load(f)
    
    async def run_test_suite(self, test_category: str) -> Dict:
        """Run a specific test category with hardware optimization"""
        start_time = time.time()
        
        # Prepare test command
        pytest_args = [
            "pytest",
            f"-m", test_category,
            f"-n", str(self.config.parallel_processes),
            "--dist", "loadscope",
            "--benchmark-only" if test_category == "performance" else "",
            f"--basetemp={self.config.test_data_path / test_category}",
            "--tb=short",
            "-v",
            f"--junitxml={self.config.results_path / f'{test_category}_results.xml'}",
            f"--html={self.config.results_path / f'{test_category}_report.html'}",
            "--self-contained-html",
        ]
        
        # Remove empty strings
        pytest_args = [arg for arg in pytest_args if arg]
        
        # GPU-specific settings
        if test_category in self.config.gpu_tests_markers and self.config.use_gpu:
            env = os.environ.copy()
            env["CUDA_VISIBLE_DEVICES"] = "0"
        else:
            env = os.environ.copy()
            
        # Run tests with resource monitoring
        metrics_log = []
        process = await asyncio.create_subprocess_exec(
            *pytest_args,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Monitor resources during test execution
        monitor_task = asyncio.create_task(self._monitor_resources(metrics_log))
        
        stdout, stderr = await process.communicate()
        monitor_task.cancel()
        
        # Collect results
        end_time = time.time()
        duration = end_time - start_time
        
        result = {
            "category": test_category,
            "duration": duration,
            "exit_code": process.returncode,
            "stdout": stdout.decode() if stdout else "",
            "stderr": stderr.decode() if stderr else "",
            "metrics": metrics_log,
            "timestamp": datetime.now().isoformat()
        }
        
        # Save results
        self._save_test_results(test_category, result)
        
        return result
    
    async def _monitor_resources(self, metrics_log: List[Dict]):
        """Monitor system resources during test execution"""
        while True:
            try:
                metrics = self.monitor.capture_metrics()
                metrics_log.append(metrics)
                await asyncio.sleep(1)
            except asyncio.CancelledError:
                break
                
    def _save_test_results(self, category: str, result: Dict):
        """Save test results to disk"""
        result_file = self.config.results_path / f"{category}_detailed_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(result_file, 'w') as f:
            json.dump(result, f, indent=2)
            
    async def run_parallel_test_suites(self, categories: Optional[List[str]] = None) -> Dict:
        """Run multiple test categories in parallel"""
        if categories is None:
            categories = self.config.test_categories
            
        # Group tests by resource requirements
        cpu_intensive = ["performance", "stress", "rust", "ffi"]
        memory_intensive = ["memory", "integration", "e2e"]
        io_intensive = ["mcp", "security"]
        light_tests = ["unit"]
        
        # Schedule tests to balance resource usage
        scheduled_groups = [
            light_tests,  # Run lightweight tests first
            [c for c in categories if c in cpu_intensive],
            [c for c in categories if c in memory_intensive],
            [c for c in categories if c in io_intensive],
        ]
        
        all_results = {}
        
        for group in scheduled_groups:
            if not group:
                continue
                
            # Run tests in group concurrently
            tasks = [self.run_test_suite(category) for category in group if category in categories]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for category, result in zip(group, results):
                if isinstance(result, Exception):
                    all_results[category] = {"error": str(result)}
                else:
                    all_results[category] = result
                    
        return all_results
    
    def generate_performance_report(self, results: Dict) -> Dict:
        """Generate performance comparison report"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "summary": {},
            "regressions": [],
            "improvements": [],
            "resource_usage": {}
        }
        
        for category, result in results.items():
            if "error" in result:
                continue
                
            # Compare with baselines
            if category in self.performance_baselines:
                baseline = self.performance_baselines[category]
                current_duration = result["duration"]
                baseline_duration = baseline.get("duration", current_duration)
                
                diff_percent = ((current_duration - baseline_duration) / baseline_duration) * 100
                
                if diff_percent > 10:
                    report["regressions"].append({
                        "category": category,
                        "baseline": baseline_duration,
                        "current": current_duration,
                        "regression": f"{diff_percent:.1f}%"
                    })
                elif diff_percent < -10:
                    report["improvements"].append({
                        "category": category,
                        "baseline": baseline_duration,
                        "current": current_duration,
                        "improvement": f"{abs(diff_percent):.1f}%"
                    })
                    
            # Analyze resource usage
            if "metrics" in result and result["metrics"]:
                avg_cpu = sum(
                    sum(m["cpu_percent"]) / len(m["cpu_percent"]) 
                    for m in result["metrics"]
                ) / len(result["metrics"])
                
                max_memory = max(m["memory"]["percent"] for m in result["metrics"])
                
                report["resource_usage"][category] = {
                    "avg_cpu_percent": avg_cpu,
                    "max_memory_percent": max_memory
                }
                
        return report


class ContinuousTestRunner:
    """Continuous testing with file watching"""
    
    def __init__(self, orchestrator: TestOrchestrator):
        self.orchestrator = orchestrator
        self.watch_paths = [
            Path("src"),
            Path("tests"),
            Path("rust_core/src") if Path("rust_core/src").exists() else None
        ]
        self.watch_paths = [p for p in self.watch_paths if p]
        
    async def start_watching(self):
        """Start watching for file changes"""
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler
        except ImportError:
            print("watchdog not installed. Install with: pip install watchdog")
            return
            
        class TestHandler(FileSystemEventHandler):
            def __init__(self, runner):
                self.runner = runner
                self.last_run = 0
                self.debounce_seconds = 2
                
            def on_modified(self, event):
                if event.is_directory:
                    return
                    
                current_time = time.time()
                if current_time - self.last_run < self.debounce_seconds:
                    return
                    
                if event.src_path.endswith(('.py', '.rs')):
                    self.last_run = current_time
                    print(f"\nFile changed: {event.src_path}")
                    
                    # Determine which tests to run
                    if 'test_' in event.src_path:
                        category = "unit"
                    elif '.rs' in event.src_path:
                        category = "rust"
                    else:
                        category = "unit"
                        
                    # Run tests asynchronously
                    asyncio.create_task(self.runner.orchestrator.run_test_suite(category))
        
        handler = TestHandler(self)
        observer = Observer()
        
        for path in self.watch_paths:
            observer.schedule(handler, str(path), recursive=True)
            
        observer.start()
        print(f"Watching for changes in: {', '.join(str(p) for p in self.watch_paths)}")
        
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()


async def main():
    """Main entry point for test orchestration"""
    # Initialize configuration
    config = TestConfiguration()
    
    # Create orchestrator
    orchestrator = TestOrchestrator(config)
    
    # Run all test suites
    print("Starting comprehensive test suite execution...")
    print(f"CPU Threads: {config.parallel_processes}")
    print(f"Memory Limit: {config.total_memory_limit / (1024**3):.1f} GB")
    print(f"Test Data Path: {config.test_data_path}")
    print(f"GPU Available: {NVIDIA_AVAILABLE}")
    print("-" * 80)
    
    # Run tests
    results = await orchestrator.run_parallel_test_suites()
    
    # Generate report
    report = orchestrator.generate_performance_report(results)
    
    # Save report
    report_file = config.results_path / f"test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
        
    # Print summary
    print("\n" + "=" * 80)
    print("TEST EXECUTION SUMMARY")
    print("=" * 80)
    
    total_tests = len(results)
    passed_tests = sum(1 for r in results.values() if "error" not in r and r.get("exit_code") == 0)
    failed_tests = total_tests - passed_tests
    
    print(f"Total Test Suites: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {failed_tests}")
    
    if report["regressions"]:
        print(f"\nPerformance Regressions: {len(report['regressions'])}")
        for reg in report["regressions"]:
            print(f"  - {reg['category']}: {reg['regression']} slower")
            
    if report["improvements"]:
        print(f"\nPerformance Improvements: {len(report['improvements'])}")
        for imp in report["improvements"]:
            print(f"  - {imp['category']}: {imp['improvement']} faster")
            
    print(f"\nDetailed report saved to: {report_file}")
    
    # Start continuous testing if requested
    if "--watch" in sys.argv:
        print("\nStarting continuous test runner...")
        runner = ContinuousTestRunner(orchestrator)
        await runner.start_watching()


if __name__ == "__main__":
    asyncio.run(main())