"""
Test Automation Strategies and Frameworks
SYNTHEX Agent 8 - Testing Specialist

This module provides comprehensive test automation strategies including:
- Continuous testing pipeline
- Automated test data generation
- Dynamic test selection
- Performance regression detection
- Security vulnerability scanning
- Load testing orchestration
"""

import asyncio
import json
import time
import logging
from typing import Dict, List, Any, Optional, Callable, Union
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import subprocess
import tempfile
import shutil
from datetime import datetime, timedelta
import yaml
import aiofiles
import pytest
from pytest_benchmark import BenchmarkFixture
import hypothesis
from hypothesis import strategies as st
import locust
from locust import HttpUser, task, between


class TestEnvironment(Enum):
    """Test environment types."""
    UNIT = "unit"
    INTEGRATION = "integration"
    STAGING = "staging"
    PRODUCTION = "production"
    PERFORMANCE = "performance"
    SECURITY = "security"


class TestResult(Enum):
    """Test execution results."""
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"
    TIMEOUT = "timeout"


@dataclass
class TestExecution:
    """Test execution metadata."""
    test_id: str
    environment: TestEnvironment
    start_time: datetime
    end_time: Optional[datetime] = None
    result: Optional[TestResult] = None
    duration_seconds: float = 0.0
    error_message: Optional[str] = None
    metrics: Dict[str, Any] = None
    artifacts: List[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)


class TestAutomationOrchestrator:
    """Main orchestrator for test automation."""
    
    def __init__(self, config_path: Optional[Path] = None):
        self.config = self._load_config(config_path)
        self.execution_history: List[TestExecution] = []
        self.test_generators = {}
        self.performance_baselines = {}
        self.security_scanners = {}
        self.load_generators = {}
        
        self._setup_logging()
        self._initialize_components()
    
    def _load_config(self, config_path: Optional[Path]) -> Dict[str, Any]:
        """Load automation configuration."""
        default_config = {
            "environments": {
                "unit": {"timeout": 300, "parallel": True, "workers": 4},
                "integration": {"timeout": 600, "parallel": True, "workers": 2},
                "e2e": {"timeout": 1800, "parallel": False, "workers": 1},
                "performance": {"timeout": 3600, "baseline_tolerance": 0.1},
                "security": {"timeout": 7200, "vulnerability_threshold": 0},
                "load": {"timeout": 3600, "max_users": 1000, "ramp_time": 300}
            },
            "data_generation": {
                "enabled": True,
                "strategies": ["random", "edge_cases", "property_based"],
                "cache_enabled": True,
                "max_cache_size_mb": 1000
            },
            "reporting": {
                "formats": ["json", "html", "junit"],
                "include_artifacts": True,
                "retention_days": 30
            },
            "notifications": {
                "enabled": True,
                "channels": ["slack", "email"],
                "on_failure": True,
                "on_regression": True
            }
        }
        
        if config_path and config_path.exists():
            with open(config_path) as f:
                user_config = yaml.safe_load(f)
                default_config.update(user_config)
        
        return default_config
    
    def _setup_logging(self):
        """Setup logging for test automation."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('test_automation.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def _initialize_components(self):
        """Initialize automation components."""
        self.test_generators = {
            "document": DocumentTestGenerator(),
            "api": APITestGenerator(),
            "load": LoadTestGenerator(),
            "security": SecurityTestGenerator()
        }
        
        self.performance_monitor = PerformanceMonitor()
        self.security_scanner = SecurityScanner()
        self.load_orchestrator = LoadTestOrchestrator()
        self.regression_detector = RegressionDetector()
    
    async def run_test_suite(self, 
                           suite_name: str,
                           environment: TestEnvironment,
                           filters: Optional[Dict[str, Any]] = None) -> List[TestExecution]:
        """Run a complete test suite."""
        self.logger.info(f"Starting test suite: {suite_name} in {environment.value}")
        
        # Generate test cases if needed
        if self.config["data_generation"]["enabled"]:
            await self._generate_test_data(suite_name, environment)
        
        # Select and execute tests
        test_cases = await self._select_tests(suite_name, environment, filters)
        executions = await self._execute_tests(test_cases, environment)
        
        # Analyze results
        await self._analyze_results(executions, environment)
        
        # Generate reports
        await self._generate_reports(executions, suite_name, environment)
        
        # Send notifications if needed
        await self._send_notifications(executions)
        
        return executions
    
    async def _generate_test_data(self, suite_name: str, environment: TestEnvironment):
        """Generate test data for the suite."""
        generator = self.test_generators.get(suite_name)
        if not generator:
            return
        
        self.logger.info(f"Generating test data for {suite_name}")
        
        await generator.generate_data(
            environment=environment,
            strategies=self.config["data_generation"]["strategies"]
        )
    
    async def _select_tests(self, 
                          suite_name: str,
                          environment: TestEnvironment,
                          filters: Optional[Dict[str, Any]]) -> List[str]:
        """Intelligently select tests to run."""
        # Use pytest collection to discover tests
        cmd = [
            "python", "-m", "pytest",
            "--collect-only",
            "--quiet",
            f"-m {environment.value}",
            "--json-report", "--json-report-file=test_collection.json"
        ]
        
        if filters:
            for key, value in filters.items():
                cmd.extend([f"--{key}", str(value)])
        
        await asyncio.create_subprocess_exec(*cmd)
        
        # Parse collection results
        with open("test_collection.json") as f:
            collection = json.load(f)
        
        return [test["nodeid"] for test in collection.get("tests", [])]
    
    async def _execute_tests(self, 
                           test_cases: List[str],
                           environment: TestEnvironment) -> List[TestExecution]:
        """Execute test cases with proper orchestration."""
        env_config = self.config["environments"][environment.value]
        executions = []
        
        if env_config.get("parallel", False):
            executions = await self._execute_parallel(test_cases, env_config)
        else:
            executions = await self._execute_sequential(test_cases, env_config)
        
        return executions
    
    async def _execute_parallel(self, 
                              test_cases: List[str],
                              env_config: Dict[str, Any]) -> List[TestExecution]:
        """Execute tests in parallel."""
        semaphore = asyncio.Semaphore(env_config.get("workers", 4))
        
        async def run_single_test(test_case: str) -> TestExecution:
            async with semaphore:
                return await self._run_single_test(test_case, env_config)
        
        tasks = [run_single_test(test) for test in test_cases]
        return await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _execute_sequential(self, 
                                test_cases: List[str],
                                env_config: Dict[str, Any]) -> List[TestExecution]:
        """Execute tests sequentially."""
        executions = []
        for test_case in test_cases:
            execution = await self._run_single_test(test_case, env_config)
            executions.append(execution)
        return executions
    
    async def _run_single_test(self, 
                             test_case: str,
                             env_config: Dict[str, Any]) -> TestExecution:
        """Run a single test case."""
        execution = TestExecution(
            test_id=test_case,
            environment=TestEnvironment.UNIT,  # Will be set by caller
            start_time=datetime.now(),
            artifacts=[]
        )
        
        try:
            # Prepare test environment
            test_dir = tempfile.mkdtemp(prefix="test_")
            
            # Run pytest for single test
            cmd = [
                "python", "-m", "pytest",
                test_case,
                "--json-report",
                f"--json-report-file={test_dir}/result.json",
                "--tb=short",
                f"--timeout={env_config.get('timeout', 300)}"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=test_dir
            )
            
            stdout, stderr = await process.communicate()
            
            # Parse results
            result_file = Path(test_dir) / "result.json"
            if result_file.exists():
                with open(result_file) as f:
                    result_data = json.load(f)
                
                test_result = result_data.get("tests", [{}])[0]
                execution.result = TestResult(test_result.get("outcome", "error"))
                execution.duration_seconds = test_result.get("duration", 0)
                
                if execution.result == TestResult.FAILED:
                    execution.error_message = test_result.get("call", {}).get("longrepr", "")
            
            # Collect artifacts
            execution.artifacts = self._collect_artifacts(test_dir)
            
        except Exception as e:
            execution.result = TestResult.ERROR
            execution.error_message = str(e)
        finally:
            execution.end_time = datetime.now()
            if execution.end_time and execution.start_time:
                execution.duration_seconds = (
                    execution.end_time - execution.start_time
                ).total_seconds()
        
        return execution
    
    def _collect_artifacts(self, test_dir: str) -> List[str]:
        """Collect test artifacts."""
        artifacts = []
        test_path = Path(test_dir)
        
        # Collect logs, screenshots, dumps, etc.
        artifact_patterns = ["*.log", "*.png", "*.json", "*.xml", "*.html"]
        
        for pattern in artifact_patterns:
            for file_path in test_path.glob(pattern):
                artifacts.append(str(file_path))
        
        return artifacts
    
    async def _analyze_results(self, 
                             executions: List[TestExecution],
                             environment: TestEnvironment):
        """Analyze test results for patterns and regressions."""
        # Performance regression analysis
        if environment == TestEnvironment.PERFORMANCE:
            await self.regression_detector.analyze_performance(executions)
        
        # Security vulnerability analysis
        if environment == TestEnvironment.SECURITY:
            await self.security_scanner.analyze_results(executions)
        
        # General pattern analysis
        await self._analyze_failure_patterns(executions)
    
    async def _analyze_failure_patterns(self, executions: List[TestExecution]):
        """Analyze failure patterns to identify systemic issues."""
        failures = [e for e in executions if e.result == TestResult.FAILED]
        
        if not failures:
            return
        
        # Group failures by error patterns
        error_patterns = {}
        for failure in failures:
            if failure.error_message:
                # Simple pattern matching - could be more sophisticated
                key_words = failure.error_message.split()[:5]
                pattern = " ".join(key_words)
                
                if pattern not in error_patterns:
                    error_patterns[pattern] = []
                error_patterns[pattern].append(failure)
        
        # Log patterns with multiple occurrences
        for pattern, pattern_failures in error_patterns.items():
            if len(pattern_failures) > 1:
                self.logger.warning(
                    f"Pattern detected: {len(pattern_failures)} tests failed with pattern: {pattern}"
                )


class DocumentTestGenerator:
    """Generates test documents for various scenarios."""
    
    async def generate_data(self, 
                          environment: TestEnvironment,
                          strategies: List[str]):
        """Generate document test data."""
        generators = {
            "random": self._generate_random_documents,
            "edge_cases": self._generate_edge_case_documents,
            "property_based": self._generate_property_based_documents
        }
        
        for strategy in strategies:
            if strategy in generators:
                await generators[strategy](environment)
    
    async def _generate_random_documents(self, environment: TestEnvironment):
        """Generate random documents for testing."""
        formats = ["markdown", "latex", "html", "docx", "pdf"]
        sizes = [1, 10, 100, 1000]  # KB
        
        for fmt in formats:
            for size in sizes:
                await self._create_test_document(fmt, size, "random")
    
    async def _generate_edge_case_documents(self, environment: TestEnvironment):
        """Generate edge case documents."""
        edge_cases = [
            ("empty", 0),
            ("huge", 100000),  # 100MB
            ("unicode", 10),
            ("malformed", 5),
            ("deeply_nested", 50)
        ]
        
        for case_type, size in edge_cases:
            await self._create_test_document("markdown", size, case_type)
    
    async def _generate_property_based_documents(self, environment: TestEnvironment):
        """Generate documents using property-based testing."""
        # Use hypothesis to generate structured documents
        @hypothesis.given(
            chapters=st.lists(
                st.text(min_size=10, max_size=1000),
                min_size=1,
                max_size=20
            ),
            depth=st.integers(min_value=1, max_value=6)
        )
        def generate_structured_document(chapters, depth):
            content = []
            for i, chapter in enumerate(chapters):
                level = min(depth, (i % depth) + 1)
                header = "#" * level
                content.append(f"{header} Chapter {i+1}\n\n{chapter}\n\n")
            
            return "".join(content)
        
        # Generate several examples
        for _ in range(100):
            doc = generate_structured_document()
            await self._save_test_document(doc, "property_based")
    
    async def _create_test_document(self, fmt: str, size_kb: int, doc_type: str):
        """Create a test document of specified format and size."""
        # Implementation would create documents based on parameters
        pass
    
    async def _save_test_document(self, content: str, doc_type: str):
        """Save generated test document."""
        # Implementation would save to test data directory
        pass


class LoadTestOrchestrator:
    """Orchestrates load testing scenarios."""
    
    def __init__(self):
        self.scenarios = {}
        self.results = []
    
    def add_scenario(self, name: str, scenario_class: type):
        """Add a load test scenario."""
        self.scenarios[name] = scenario_class
    
    async def run_load_test(self, 
                          scenario_name: str,
                          users: int,
                          duration: int,
                          ramp_time: int = 60) -> Dict[str, Any]:
        """Run a load test scenario."""
        if scenario_name not in self.scenarios:
            raise ValueError(f"Unknown scenario: {scenario_name}")
        
        # Create Locust environment
        from locust.env import Environment
        from locust.stats import stats_printer
        from locust.log import setup_logging
        
        setup_logging("INFO", None)
        
        env = Environment(user_classes=[self.scenarios[scenario_name]])
        env.create_local_runner()
        
        # Start load test
        env.runner.start(user_count=users, spawn_rate=users/ramp_time)
        
        # Run for specified duration
        await asyncio.sleep(duration)
        
        # Stop test
        env.runner.quit()
        
        # Collect results
        stats = env.runner.stats
        results = {
            "total_requests": stats.total.num_requests,
            "total_failures": stats.total.num_failures,
            "average_response_time": stats.total.avg_response_time,
            "median_response_time": stats.total.median_response_time,
            "p90_response_time": stats.total.get_response_time_percentile(0.9),
            "p95_response_time": stats.total.get_response_time_percentile(0.95),
            "p99_response_time": stats.total.get_response_time_percentile(0.99),
            "requests_per_second": stats.total.total_rps,
            "failure_rate": stats.total.fail_ratio
        }
        
        return results


class DocumentProcessingUser(HttpUser):
    """Locust user class for document processing load tests."""
    
    wait_time = between(1, 3)
    
    def on_start(self):
        """Called when user starts."""
        self.auth_token = self._get_auth_token()
    
    @task(3)
    def upload_document(self):
        """Upload and process a document."""
        with open("test_data/sample_document.pdf", "rb") as f:
            response = self.client.post(
                "/api/documents/upload",
                files={"file": f},
                headers={"Authorization": f"Bearer {self.auth_token}"}
            )
        
        if response.status_code == 200:
            document_id = response.json()["document_id"]
            self._process_document(document_id)
    
    @task(2)
    def detect_chapters(self):
        """Detect chapters in an existing document."""
        # Get random document ID
        response = self.client.get(
            "/api/documents/random",
            headers={"Authorization": f"Bearer {self.auth_token}"}
        )
        
        if response.status_code == 200:
            document_id = response.json()["document_id"]
            self.client.post(
                f"/api/documents/{document_id}/detect-chapters",
                headers={"Authorization": f"Bearer {self.auth_token}"}
            )
    
    @task(1)
    def analyze_with_experts(self):
        """Analyze document with expert system."""
        response = self.client.get(
            "/api/documents/random",
            headers={"Authorization": f"Bearer {self.auth_token}"}
        )
        
        if response.status_code == 200:
            document_id = response.json()["document_id"]
            self.client.post(
                f"/api/documents/{document_id}/analyze",
                json={
                    "experts": ["claude-3.5", "gpt-4"],
                    "analysis_type": "comprehensive"
                },
                headers={"Authorization": f"Bearer {self.auth_token}"}
            )
    
    def _get_auth_token(self) -> str:
        """Get authentication token."""
        response = self.client.post("/api/auth/login", json={
            "username": "test_user",
            "password": "test_password"
        })
        
        if response.status_code == 200:
            return response.json()["access_token"]
        return "invalid_token"
    
    def _process_document(self, document_id: str):
        """Process document through complete pipeline."""
        self.client.post(
            f"/api/documents/{document_id}/process",
            json={"include_chapters": True, "include_analysis": True},
            headers={"Authorization": f"Bearer {self.auth_token}"}
        )


class SecurityScanner:
    """Automated security vulnerability scanner."""
    
    def __init__(self):
        self.scanners = {
            "static": self._run_static_analysis,
            "dynamic": self._run_dynamic_analysis,
            "dependency": self._run_dependency_scan,
            "secrets": self._run_secrets_scan
        }
    
    async def scan(self, scan_types: List[str] = None) -> Dict[str, Any]:
        """Run security scans."""
        if scan_types is None:
            scan_types = list(self.scanners.keys())
        
        results = {}
        for scan_type in scan_types:
            if scan_type in self.scanners:
                results[scan_type] = await self.scanners[scan_type]()
        
        return results
    
    async def _run_static_analysis(self) -> Dict[str, Any]:
        """Run static code analysis."""
        # Run bandit for Python security issues
        cmd = ["bandit", "-r", "src/", "-f", "json", "-o", "bandit_results.json"]
        process = await asyncio.create_subprocess_exec(*cmd)
        await process.communicate()
        
        # Parse results
        try:
            with open("bandit_results.json") as f:
                bandit_results = json.load(f)
            
            return {
                "tool": "bandit",
                "issues_found": len(bandit_results.get("results", [])),
                "high_severity": len([
                    r for r in bandit_results.get("results", [])
                    if r.get("issue_severity") == "HIGH"
                ]),
                "medium_severity": len([
                    r for r in bandit_results.get("results", [])
                    if r.get("issue_severity") == "MEDIUM"
                ]),
                "details": bandit_results
            }
        except FileNotFoundError:
            return {"error": "Bandit scan failed"}
    
    async def _run_dynamic_analysis(self) -> Dict[str, Any]:
        """Run dynamic security analysis."""
        # This would integrate with tools like OWASP ZAP
        return {"status": "not_implemented"}
    
    async def _run_dependency_scan(self) -> Dict[str, Any]:
        """Scan dependencies for vulnerabilities."""
        # Run safety check
        cmd = ["safety", "check", "--json"]
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        try:
            results = json.loads(stdout.decode())
            return {
                "tool": "safety",
                "vulnerabilities_found": len(results),
                "details": results
            }
        except json.JSONDecodeError:
            return {"error": "Safety scan failed"}
    
    async def _run_secrets_scan(self) -> Dict[str, Any]:
        """Scan for exposed secrets."""
        # This would integrate with tools like truffleHog or detect-secrets
        return {"status": "not_implemented"}


class PerformanceMonitor:
    """Monitors and analyzes performance metrics."""
    
    def __init__(self):
        self.baselines = {}
        self.thresholds = {}
    
    def set_baseline(self, metric_name: str, value: float):
        """Set performance baseline."""
        self.baselines[metric_name] = value
    
    def set_threshold(self, metric_name: str, max_degradation: float):
        """Set regression threshold."""
        self.thresholds[metric_name] = max_degradation
    
    def check_regression(self, metric_name: str, current_value: float) -> bool:
        """Check if current value represents a regression."""
        if metric_name not in self.baselines:
            return False
        
        baseline = self.baselines[metric_name]
        threshold = self.thresholds.get(metric_name, 0.1)  # 10% default
        
        degradation = (current_value - baseline) / baseline
        return degradation > threshold


class RegressionDetector:
    """Detects various types of regressions."""
    
    async def analyze_performance(self, executions: List[TestExecution]):
        """Analyze performance regressions."""
        performance_tests = [
            e for e in executions 
            if e.metrics and "performance" in e.metrics
        ]
        
        for execution in performance_tests:
            metrics = execution.metrics.get("performance", {})
            for metric_name, value in metrics.items():
                if self._is_regression(metric_name, value):
                    logging.warning(
                        f"Performance regression detected in {execution.test_id}: "
                        f"{metric_name} = {value}"
                    )
    
    def _is_regression(self, metric_name: str, value: float) -> bool:
        """Check if metric value represents a regression."""
        # Implementation would compare with historical baselines
        return False


# ============================================================================
# Continuous Integration Integration
# ============================================================================

class CIIntegration:
    """Integration with CI/CD systems."""
    
    def generate_github_actions_workflow(self) -> str:
        """Generate GitHub Actions workflow for testing."""
        workflow = """
name: Comprehensive Testing Suite

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.10, 3.11, 3.12]
    
    steps:
    - uses: actions/checkout@v3
    - name: Set up Python
      uses: actions/setup-python@v3
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -e .[mcp_testing]
    
    - name: Run unit tests
      run: |
        pytest tests/ -m unit --cov=src --cov-report=xml
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3

  integration-tests:
    runs-on: ubuntu-latest
    needs: unit-tests
    
    services:
      postgres:
        image: postgres:13
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    
    steps:
    - uses: actions/checkout@v3
    - name: Set up Python
      uses: actions/setup-python@v3
      with:
        python-version: 3.11
    
    - name: Install dependencies
      run: |
        pip install -e .[mcp_testing,database]
    
    - name: Run integration tests
      run: |
        pytest tests/ -m integration

  performance-tests:
    runs-on: ubuntu-latest
    needs: integration-tests
    
    steps:
    - uses: actions/checkout@v3
    - name: Set up Python
      uses: actions/setup-python@v3
      with:
        python-version: 3.11
    
    - name: Install dependencies
      run: |
        pip install -e .[mcp_testing]
    
    - name: Run performance tests
      run: |
        pytest tests/ -m performance --benchmark-json=benchmark.json
    
    - name: Store benchmark results
      uses: benchmark-action/github-action-benchmark@v1
      with:
        tool: 'pytest'
        output-file-path: benchmark.json

  security-tests:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    - name: Set up Python
      uses: actions/setup-python@v3
      with:
        python-version: 3.11
    
    - name: Install security tools
      run: |
        pip install bandit safety
    
    - name: Run security scan
      run: |
        bandit -r src/
        safety check
    
    - name: Run security tests
      run: |
        pytest tests/ -m security
"""
        return workflow.strip()
    
    def generate_gitlab_ci_config(self) -> str:
        """Generate GitLab CI configuration."""
        config = """
stages:
  - test
  - security
  - performance
  - deploy

variables:
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.cache/pip"

cache:
  paths:
    - .cache/pip/
    - venv/

unit_tests:
  stage: test
  image: python:3.11
  script:
    - python -m venv venv
    - source venv/bin/activate
    - pip install -e .[mcp_testing]
    - pytest tests/ -m unit --junitxml=report.xml --cov=src --cov-report=xml
  artifacts:
    when: always
    reports:
      junit: report.xml
      coverage_report:
        coverage_format: cobertura
        path: coverage.xml

integration_tests:
  stage: test
  image: python:3.11
  services:
    - postgres:13
  variables:
    POSTGRES_DB: test_db
    POSTGRES_USER: test_user
    POSTGRES_PASSWORD: test_pass
  script:
    - python -m venv venv
    - source venv/bin/activate
    - pip install -e .[mcp_testing,database]
    - pytest tests/ -m integration

security_scan:
  stage: security
  image: python:3.11
  script:
    - pip install bandit safety
    - bandit -r src/ -f json -o bandit-report.json
    - safety check --json > safety-report.json
    - pytest tests/ -m security
  artifacts:
    reports:
      sast: bandit-report.json
    paths:
      - safety-report.json

performance_tests:
  stage: performance
  image: python:3.11
  script:
    - python -m venv venv
    - source venv/bin/activate
    - pip install -e .[mcp_testing]
    - pytest tests/ -m performance --benchmark-json=benchmark.json
  artifacts:
    paths:
      - benchmark.json
"""
        return config.strip()


# ============================================================================
# Test Execution Entry Point
# ============================================================================

async def main():
    """Main entry point for test automation."""
    orchestrator = TestAutomationOrchestrator()
    
    # Example: Run comprehensive test suite
    results = await orchestrator.run_test_suite(
        suite_name="comprehensive",
        environment=TestEnvironment.INTEGRATION,
        filters={"maxfail": 5, "timeout": 300}
    )
    
    # Print summary
    total_tests = len(results)
    passed = len([r for r in results if r.result == TestResult.PASSED])
    failed = len([r for r in results if r.result == TestResult.FAILED])
    
    print(f"Test Summary: {passed}/{total_tests} passed, {failed} failed")


if __name__ == "__main__":
    asyncio.run(main())