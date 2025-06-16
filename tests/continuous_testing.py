#!/usr/bin/env python3
"""
Continuous Testing Framework
Automatically runs tests on file changes with intelligent test selection
"""

import asyncio
import os
import sys
import time
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from datetime import datetime
from collections import defaultdict
import hashlib
import pickle

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileModifiedEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    print("Warning: watchdog not installed. Install with: pip install watchdog")


class TestDependencyMapper:
    """Maps source files to relevant tests"""
    
    def __init__(self, cache_path: Path = Path(".test_dependency_cache")):
        self.cache_path = cache_path
        self.dependency_map = self._load_cache()
        self.import_graph = {}
        self._build_import_graph()
        
    def _load_cache(self) -> Dict:
        """Load dependency cache"""
        if self.cache_path.exists():
            try:
                with open(self.cache_path, "rb") as f:
                    return pickle.load(f)
            except:
                pass
        return {}
        
    def _save_cache(self):
        """Save dependency cache"""
        with open(self.cache_path, "wb") as f:
            pickle.dump(self.dependency_map, f)
            
    def _build_import_graph(self):
        """Build import dependency graph"""
        import ast
        
        for py_file in Path("src").rglob("*.py"):
            try:
                with open(py_file, "r") as f:
                    tree = ast.parse(f.read())
                    
                imports = []
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            imports.append(alias.name)
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            imports.append(node.module)
                            
                self.import_graph[str(py_file)] = imports
            except:
                pass
                
    def get_affected_tests(self, changed_file: Path) -> Set[str]:
        """Get tests affected by a file change"""
        affected = set()
        
        # Direct test file
        if "test_" in changed_file.name or changed_file.name.endswith("_test.py"):
            affected.add(str(changed_file))
            return affected
            
        # Map source file to tests
        if changed_file.suffix == ".py":
            # Find tests that import this module
            module_path = str(changed_file).replace("/", ".").replace(".py", "")
            
            for test_file in Path("tests").rglob("test_*.py"):
                try:
                    with open(test_file, "r") as f:
                        content = f.read()
                        if module_path in content or changed_file.stem in content:
                            affected.add(str(test_file))
                except:
                    pass
                    
        # Check dependency map
        file_key = str(changed_file)
        if file_key in self.dependency_map:
            affected.update(self.dependency_map[file_key])
            
        # If no specific tests found, run category tests
        if not affected:
            if "mcp" in str(changed_file):
                affected.add("tests/integration/test_mcp_*.py")
            elif "rust" in str(changed_file) or changed_file.suffix == ".rs":
                affected.add("tests/ffi/")
                affected.add("tests/performance/test_rust_*.py")
            elif "security" in str(changed_file):
                affected.add("tests/security/")
                
        return affected


class TestResultsTracker:
    """Track test results and provide insights"""
    
    def __init__(self, results_dir: Path = Path("test_results")):
        self.results_dir = results_dir
        self.results_dir.mkdir(exist_ok=True)
        self.history = defaultdict(list)
        self._load_history()
        
    def _load_history(self):
        """Load test history"""
        history_file = self.results_dir / "test_history.json"
        if history_file.exists():
            with open(history_file, "r") as f:
                self.history = defaultdict(list, json.load(f))
                
    def _save_history(self):
        """Save test history"""
        history_file = self.results_dir / "test_history.json"
        with open(history_file, "w") as f:
            json.dump(dict(self.history), f, indent=2)
            
    def record_result(self, test_name: str, passed: bool, duration: float, 
                     coverage: Optional[float] = None):
        """Record a test result"""
        result = {
            "timestamp": datetime.now().isoformat(),
            "passed": passed,
            "duration": duration,
            "coverage": coverage
        }
        
        self.history[test_name].append(result)
        
        # Keep only last 100 results per test
        if len(self.history[test_name]) > 100:
            self.history[test_name] = self.history[test_name][-100:]
            
        self._save_history()
        
    def get_flaky_tests(self, threshold: float = 0.1) -> List[str]:
        """Identify flaky tests"""
        flaky = []
        
        for test_name, results in self.history.items():
            if len(results) < 10:
                continue
                
            recent_results = results[-20:]
            failures = sum(1 for r in recent_results if not r["passed"])
            failure_rate = failures / len(recent_results)
            
            if 0 < failure_rate < 1 and failure_rate > threshold:
                flaky.append((test_name, failure_rate))
                
        return sorted(flaky, key=lambda x: x[1], reverse=True)
        
    def get_slow_tests(self, percentile: float = 0.95) -> List[Tuple[str, float]]:
        """Identify slow tests"""
        all_durations = []
        test_durations = {}
        
        for test_name, results in self.history.items():
            if results:
                avg_duration = sum(r["duration"] for r in results[-10:]) / len(results[-10:])
                test_durations[test_name] = avg_duration
                all_durations.append(avg_duration)
                
        if not all_durations:
            return []
            
        threshold = sorted(all_durations)[int(len(all_durations) * percentile)]
        
        slow_tests = [
            (name, duration) 
            for name, duration in test_durations.items() 
            if duration > threshold
        ]
        
        return sorted(slow_tests, key=lambda x: x[1], reverse=True)


class ContinuousTestRunner:
    """Main continuous test runner"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or self._default_config()
        self.dependency_mapper = TestDependencyMapper()
        self.results_tracker = TestResultsTracker()
        self.test_queue = asyncio.Queue()
        self.running = False
        
    def _default_config(self) -> Dict:
        """Default configuration"""
        return {
            "watch_paths": ["src", "tests"],
            "ignore_patterns": ["*.pyc", "__pycache__", ".git", ".pytest_cache"],
            "parallel_workers": 12,
            "debounce_seconds": 2,
            "test_timeout": 300,
            "coverage_threshold": 80,
            "auto_fix": True,
            "notify": True
        }
        
    async def start(self):
        """Start continuous testing"""
        self.running = True
        
        # Start test worker
        worker_task = asyncio.create_task(self._test_worker())
        
        # Start file watcher
        if WATCHDOG_AVAILABLE:
            watcher_task = asyncio.create_task(self._start_file_watcher())
        else:
            print("File watching not available. Running in manual mode.")
            watcher_task = None
            
        # Start dashboard
        dashboard_task = asyncio.create_task(self._run_dashboard())
        
        try:
            tasks = [worker_task, dashboard_task]
            if watcher_task:
                tasks.append(watcher_task)
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            self.running = False
            print("\nShutting down continuous testing...")
            
    async def _test_worker(self):
        """Worker that processes test queue"""
        while self.running:
            try:
                # Get test batch from queue
                test_batch = await asyncio.wait_for(
                    self.test_queue.get(), 
                    timeout=1.0
                )
                
                if test_batch:
                    await self._run_tests(test_batch)
                    
            except asyncio.TimeoutError:
                continue
                
    async def _run_tests(self, test_files: Set[str]):
        """Run a batch of tests"""
        print(f"\n{'='*80}")
        print(f"Running {len(test_files)} test files...")
        print(f"Time: {datetime.now().strftime('%H:%M:%S')}")
        print(f"{'='*80}")
        
        # Build pytest command
        cmd = [
            "pytest",
            "-n", str(self.config["parallel_workers"]),
            "--tb=short",
            "-v",
            "--cov=src",
            "--cov-report=term-missing",
            "--cov-report=html",
            "--cov-report=json",
        ]
        
        # Add test files
        for test_file in test_files:
            if "*" in test_file:
                # Pattern - use -k
                cmd.extend(["-k", test_file.replace("*", "")])
            else:
                cmd.append(test_file)
                
        # Run tests
        start_time = time.time()
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        duration = time.time() - start_time
        
        # Parse results
        passed = process.returncode == 0
        
        # Extract coverage if available
        coverage = None
        try:
            with open("coverage.json", "r") as f:
                cov_data = json.load(f)
                coverage = cov_data.get("totals", {}).get("percent_covered", 0)
        except:
            pass
            
        # Record results
        for test_file in test_files:
            self.results_tracker.record_result(
                test_file, passed, duration, coverage
            )
            
        # Display results
        self._display_results(passed, duration, coverage, stdout.decode())
        
        # Auto-fix if enabled and tests failed
        if not passed and self.config["auto_fix"]:
            await self._attempt_auto_fix(stderr.decode())
            
    def _display_results(self, passed: bool, duration: float, 
                        coverage: Optional[float], output: str):
        """Display test results"""
        status = "✅ PASSED" if passed else "❌ FAILED"
        
        print(f"\n{status}")
        print(f"Duration: {duration:.2f}s")
        
        if coverage:
            cov_status = "✅" if coverage >= self.config["coverage_threshold"] else "⚠️"
            print(f"Coverage: {cov_status} {coverage:.1f}%")
            
        # Show flaky tests
        flaky = self.results_tracker.get_flaky_tests()
        if flaky:
            print(f"\n⚠️  Flaky tests detected:")
            for test, rate in flaky[:5]:
                print(f"  - {test}: {rate*100:.1f}% failure rate")
                
        # Show slow tests
        slow = self.results_tracker.get_slow_tests()
        if slow:
            print(f"\n🐌 Slowest tests:")
            for test, duration in slow[:5]:
                print(f"  - {test}: {duration:.2f}s")
                
    async def _attempt_auto_fix(self, error_output: str):
        """Attempt to auto-fix common issues"""
        print("\n🔧 Attempting auto-fix...")
        
        fixes_applied = []
        
        # Fix missing imports
        if "ImportError" in error_output or "ModuleNotFoundError" in error_output:
            print("  - Fixing imports...")
            subprocess.run(["python", "scripts/fix_imports.py"])
            fixes_applied.append("imports")
            
        # Fix formatting
        if "formatting" in error_output.lower():
            print("  - Fixing formatting...")
            subprocess.run(["black", "src", "tests"])
            subprocess.run(["ruff", "--fix", "src", "tests"])
            fixes_applied.append("formatting")
            
        if fixes_applied:
            print(f"  - Applied fixes: {', '.join(fixes_applied)}")
            print("  - Re-running tests...")
            
            # Re-queue the tests
            await self.test_queue.put({"retry": True})
            
    async def _start_file_watcher(self):
        """Start watching for file changes"""
        class TestHandler(FileSystemEventHandler):
            def __init__(self, runner):
                self.runner = runner
                self.last_change = {}
                
            def on_modified(self, event):
                if event.is_directory:
                    return
                    
                path = Path(event.src_path)
                
                # Check ignore patterns
                for pattern in self.runner.config["ignore_patterns"]:
                    if pattern in str(path):
                        return
                        
                # Debounce
                now = time.time()
                if str(path) in self.last_change:
                    if now - self.last_change[str(path)] < self.runner.config["debounce_seconds"]:
                        return
                        
                self.last_change[str(path)] = now
                
                # Get affected tests
                affected_tests = self.runner.dependency_mapper.get_affected_tests(path)
                
                if affected_tests:
                    print(f"\n📝 File changed: {path}")
                    print(f"   Affected tests: {len(affected_tests)}")
                    
                    # Queue tests
                    asyncio.create_task(
                        self.runner.test_queue.put(affected_tests)
                    )
                    
        handler = TestHandler(self)
        observer = Observer()
        
        for watch_path in self.config["watch_paths"]:
            if Path(watch_path).exists():
                observer.schedule(handler, watch_path, recursive=True)
                print(f"👀 Watching: {watch_path}")
                
        observer.start()
        
        try:
            while self.running:
                await asyncio.sleep(1)
        finally:
            observer.stop()
            observer.join()
            
    async def _run_dashboard(self):
        """Run test dashboard"""
        while self.running:
            # Update dashboard every 60 seconds
            await asyncio.sleep(60)
            
            # Generate dashboard
            dashboard = {
                "timestamp": datetime.now().isoformat(),
                "summary": {
                    "total_tests": len(self.results_tracker.history),
                    "flaky_tests": len(self.results_tracker.get_flaky_tests()),
                    "slow_tests": len(self.results_tracker.get_slow_tests()),
                },
                "recent_runs": []
            }
            
            # Save dashboard
            dashboard_file = self.results_tracker.results_dir / "dashboard.json"
            with open(dashboard_file, "w") as f:
                json.dump(dashboard, f, indent=2)


async def main():
    """Main entry point"""
    print("🚀 Starting Continuous Testing Framework")
    print(f"CPU Cores: {os.cpu_count()}")
    print(f"Parallel Workers: 12")
    print("-" * 80)
    
    # Custom configuration
    config = {
        "watch_paths": ["src", "tests", "examples"],
        "parallel_workers": 12,
        "coverage_threshold": 80,
        "auto_fix": True,
    }
    
    runner = ContinuousTestRunner(config)
    
    # Run initial full test suite
    print("Running initial test suite...")
    await runner.test_queue.put({
        "tests/unit/",
        "tests/integration/",
        "tests/performance/",
    })
    
    # Start continuous testing
    await runner.start()


if __name__ == "__main__":
    asyncio.run(main())