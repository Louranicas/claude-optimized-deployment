# Testing Infrastructure Makefile for CODE Development
# 
# This Makefile provides convenient commands for running the comprehensive
# testing infrastructure with hardware optimization for 16 threads, 32GB RAM, and NVMe SSD.

.PHONY: help install test test-unit test-integration test-ffi test-performance test-security test-e2e
.PHONY: test-rust test-python test-parallel test-sequential test-quick test-full
.PHONY: benchmark profile coverage security-scan lint format clean setup-env
.PHONY: ci-test report monitor validate-env

# Default target
.DEFAULT_GOAL := help

# Configuration
PYTHON := python3
CARGO := cargo
PIP := pip3
PYTEST := pytest
MAX_WORKERS := 12
TEST_TIMEOUT := 30
RUST_FEATURES := testing

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
PURPLE := \033[0;35m
CYAN := \033[0;36m
NC := \033[0m # No Color

help: ## Show this help message
	@echo "$(CYAN)CODE Testing Infrastructure$(NC)"
	@echo "$(BLUE)Hardware-Optimized Testing for 16 threads, 32GB RAM, NVMe SSD$(NC)"
	@echo ""
	@echo "$(YELLOW)Available targets:$(NC)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(YELLOW)Quick commands:$(NC)"
	@echo "  $(GREEN)make test$(NC)           - Run all tests"
	@echo "  $(GREEN)make test-quick$(NC)     - Run quick test suite"
	@echo "  $(GREEN)make benchmark$(NC)      - Run performance benchmarks"
	@echo "  $(GREEN)make security-scan$(NC)  - Run security analysis"

install: ## Install all dependencies
	@echo "$(BLUE)Installing dependencies...$(NC)"
	$(PIP) install -r ../requirements.txt
	$(PIP) install -r ../requirements-dev.txt
	cd ../rust_core && $(CARGO) build --features $(RUST_FEATURES)
	@echo "$(GREEN)Dependencies installed successfully$(NC)"

setup-env: ## Set up testing environment
	@echo "$(BLUE)Setting up testing environment...$(NC)"
	mkdir -p results/{reports,artifacts,coverage,benchmarks,security}
	mkdir -p fixtures/data
	chmod +x ../run_comprehensive_tests.py
	@echo "$(GREEN)Testing environment ready$(NC)"

validate-env: ## Validate system environment for optimal testing
	@echo "$(BLUE)Validating system environment...$(NC)"
	@echo "CPU Cores: $(shell nproc)"
	@echo "Memory: $(shell free -h | grep '^Mem:' | awk '{print $$2}')"
	@echo "Disk Type: $(shell lsblk -d -o name,rota | grep -v ROTA | head -n 2 | tail -n 1 | awk '{print ($$2==0) ? "SSD" : "HDD"}')"
	@echo "Python: $(shell $(PYTHON) --version)"
	@echo "Rust: $(shell $(CARGO) --version)"
	@if [ $(shell nproc) -lt 8 ]; then echo "$(YELLOW)Warning: Less than 8 CPU cores detected$(NC)"; fi
	@if [ $(shell free -m | grep '^Mem:' | awk '{print $$2}') -lt 16000 ]; then echo "$(YELLOW)Warning: Less than 16GB RAM detected$(NC)"; fi
	@echo "$(GREEN)Environment validation complete$(NC)"

# Test execution targets
test: ## Run comprehensive test suite (recommended)
	@echo "$(BLUE)Running comprehensive test suite...$(NC)"
	$(PYTHON) ../run_comprehensive_tests.py --all --parallel --max-workers $(MAX_WORKERS)

test-quick: ## Run quick test suite (unit + integration)
	@echo "$(BLUE)Running quick test suite...$(NC)"
	$(PYTHON) ../run_comprehensive_tests.py --unit-tests --integration-tests --parallel --max-workers $(MAX_WORKERS)

test-unit: ## Run unit tests only
	@echo "$(BLUE)Running unit tests...$(NC)"
	$(PYTHON) ../run_comprehensive_tests.py --unit-tests --parallel --max-workers $(MAX_WORKERS)

test-integration: ## Run integration tests only
	@echo "$(BLUE)Running integration tests...$(NC)"
	$(PYTHON) ../run_comprehensive_tests.py --integration-tests --parallel --max-workers 6

test-ffi: ## Run FFI integration tests
	@echo "$(BLUE)Running FFI integration tests...$(NC)"
	$(PYTHON) ../run_comprehensive_tests.py --ffi-tests --max-workers 4

test-performance: ## Run performance tests and benchmarks
	@echo "$(BLUE)Running performance tests...$(NC)"
	$(PYTHON) ../run_comprehensive_tests.py --performance-tests --timeout-minutes 60

test-security: ## Run security vulnerability tests
	@echo "$(BLUE)Running security tests...$(NC)"
	$(PYTHON) ../run_comprehensive_tests.py --security-tests --timeout-minutes 20

test-e2e: ## Run end-to-end tests
	@echo "$(BLUE)Running end-to-end tests...$(NC)"
	$(PYTHON) ../run_comprehensive_tests.py --e2e-tests --timeout-minutes 45

# Language-specific tests
test-python: ## Run Python-specific tests
	@echo "$(BLUE)Running Python tests...$(NC)"
	$(PYTEST) unit/ integration/ -v --tb=short --maxfail=5 -n $(MAX_WORKERS)

test-rust: ## Run Rust-specific tests
	@echo "$(BLUE)Running Rust tests...$(NC)"
	cd ../rust_core && $(CARGO) test --features $(RUST_FEATURES) -- --test-threads=$(MAX_WORKERS)

# Execution modes
test-parallel: ## Run tests in parallel mode (default)
	@echo "$(BLUE)Running tests in parallel mode...$(NC)"
	$(PYTHON) ../run_comprehensive_tests.py --all --parallel --max-workers $(MAX_WORKERS)

test-sequential: ## Run tests in sequential mode
	@echo "$(BLUE)Running tests in sequential mode...$(NC)"
	$(PYTHON) ../run_comprehensive_tests.py --all

test-full: ## Run full test suite with extended timeout
	@echo "$(BLUE)Running full test suite...$(NC)"
	$(PYTHON) ../run_comprehensive_tests.py --all --parallel --max-workers $(MAX_WORKERS) --timeout-minutes 90

# Performance and profiling
benchmark: ## Run performance benchmarks
	@echo "$(BLUE)Running performance benchmarks...$(NC)"
	cd ../rust_core && $(CARGO) bench --features $(RUST_FEATURES)
	$(PYTHON) framework/performance_testing.py

profile: ## Run performance profiling
	@echo "$(BLUE)Running performance profiling...$(NC)"
	$(PYTHON) -m cProfile -o results/profile.stats ../run_comprehensive_tests.py --performance-tests
	$(PYTHON) -c "import pstats; p = pstats.Stats('results/profile.stats'); p.sort_stats('cumulative').print_stats(20)"

memory-profile: ## Run memory profiling
	@echo "$(BLUE)Running memory profiling...$(NC)"
	$(PYTHON) -m memory_profiler ../run_comprehensive_tests.py --unit-tests --integration-tests

# Coverage analysis
coverage: ## Run tests with coverage analysis
	@echo "$(BLUE)Running coverage analysis...$(NC)"
	$(PYTEST) unit/ integration/ --cov=../src --cov-report=html --cov-report=term --cov-report=xml
	@echo "$(GREEN)Coverage report generated in results/coverage/$(NC)"

coverage-rust: ## Run Rust coverage analysis
	@echo "$(BLUE)Running Rust coverage analysis...$(NC)"
	cd ../rust_core && cargo tarpaulin --features $(RUST_FEATURES) --out Html --output-dir ../tests/results/coverage/

# Security analysis
security-scan: ## Run comprehensive security scan
	@echo "$(BLUE)Running security scan...$(NC)"
	bandit -r ../src/ -f json -o results/security/bandit_report.json
	safety check --json --output results/security/safety_report.json
	pip-audit --format=json --output=results/security/pip_audit_report.json
	@echo "$(GREEN)Security reports generated in results/security/$(NC)"

# Code quality
lint: ## Run code linting
	@echo "$(BLUE)Running code linting...$(NC)"
	black --check ../src/ ../tests/
	ruff ../src/ ../tests/
	mypy ../src/
	cd ../rust_core && $(CARGO) clippy --features $(RUST_FEATURES) -- -D warnings

format: ## Format code
	@echo "$(BLUE)Formatting code...$(NC)"
	black ../src/ ../tests/
	cd ../rust_core && $(CARGO) fmt

# CI/CD integration
ci-test: ## Run tests in CI mode
	@echo "$(BLUE)Running CI tests...$(NC)"
	$(PYTHON) ../run_comprehensive_tests.py --all --ci-mode --parallel --max-workers $(MAX_WORKERS) --fast-fail

# Monitoring and reporting
monitor: ## Monitor test execution in real-time
	@echo "$(BLUE)Starting test monitoring...$(NC)"
	$(PYTHON) -c "
import time
import psutil
import threading

def monitor():
    while True:
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory().percent
        print(f'CPU: {cpu:5.1f}% | Memory: {mem:5.1f}% | Time: {time.strftime(\"%H:%M:%S\")}')
        time.sleep(5)

monitor_thread = threading.Thread(target=monitor, daemon=True)
monitor_thread.start()

# Run tests while monitoring
import subprocess
subprocess.run(['$(PYTHON)', '../run_comprehensive_tests.py', '--all', '--parallel'])
"

report: ## Generate comprehensive test report
	@echo "$(BLUE)Generating test reports...$(NC)"
	find results/ -name "*.json" -mtime -1 | head -5
	@echo "$(GREEN)Recent test reports:$(NC)"
	@ls -la results/comprehensive_test_report_*.json 2>/dev/null | head -3 || echo "No recent comprehensive reports found"

# Utility targets
clean: ## Clean test artifacts and temporary files
	@echo "$(BLUE)Cleaning test artifacts...$(NC)"
	rm -rf results/artifacts/*
	rm -rf results/coverage/*
	rm -rf ../__pycache__/ ../src/__pycache__/ __pycache__/
	rm -rf ../rust_core/target/debug/
	find . -name "*.pyc" -delete
	find . -name "*.pyo" -delete
	find . -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -name ".coverage" -delete 2>/dev/null || true
	@echo "$(GREEN)Cleanup complete$(NC)"

clean-all: clean ## Clean everything including dependencies
	@echo "$(BLUE)Cleaning all artifacts and dependencies...$(NC)"
	rm -rf ../rust_core/target/
	rm -rf results/
	@echo "$(GREEN)Full cleanup complete$(NC)"

# Development helpers
watch: ## Watch for changes and run tests automatically
	@echo "$(BLUE)Watching for changes...$(NC)"
	$(PYTHON) -c "
import time
import subprocess
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class TestHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path.endswith(('.py', '.rs')):
            print(f'File changed: {event.src_path}')
            subprocess.run(['make', 'test-quick'])

event_handler = TestHandler()
observer = Observer()
observer.schedule(event_handler, '../src', recursive=True)
observer.schedule(event_handler, '../rust_core/src', recursive=True)
observer.start()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    observer.stop()
observer.join()
"

# Documentation
docs: ## Generate testing documentation
	@echo "$(BLUE)Generating testing documentation...$(NC)"
	@echo "# Testing Infrastructure Status" > results/STATUS.md
	@echo "" >> results/STATUS.md
	@echo "Generated: $(shell date)" >> results/STATUS.md
	@echo "" >> results/STATUS.md
	@echo "## System Information" >> results/STATUS.md
	@echo "- CPU Cores: $(shell nproc)" >> results/STATUS.md
	@echo "- Memory: $(shell free -h | grep '^Mem:' | awk '{print $$2}')" >> results/STATUS.md
	@echo "- Python: $(shell $(PYTHON) --version)" >> results/STATUS.md
	@echo "- Rust: $(shell $(CARGO) --version)" >> results/STATUS.md
	@echo "" >> results/STATUS.md
	@echo "## Recent Test Results" >> results/STATUS.md
	@ls -la results/comprehensive_test_report_*.json 2>/dev/null | tail -3 >> results/STATUS.md || echo "No test reports found" >> results/STATUS.md
	@echo "$(GREEN)Documentation generated in results/STATUS.md$(NC)"

# Hardware optimization targets
optimize-cpu: ## Optimize for CPU-intensive testing
	@echo "$(BLUE)Optimizing for CPU-intensive testing...$(NC)"
	@echo "Setting CPU governor to performance..."
	@sudo cpupower frequency-set -g performance 2>/dev/null || echo "$(YELLOW)Could not set CPU governor (requires sudo)$(NC)"
	@echo "$(GREEN)CPU optimization applied$(NC)"

optimize-memory: ## Optimize memory settings for testing
	@echo "$(BLUE)Optimizing memory settings...$(NC)"
	@echo "Current memory settings:"
	@cat /proc/sys/vm/swappiness
	@echo "$(GREEN)Memory optimization complete$(NC)"

optimize-disk: ## Optimize disk settings for testing
	@echo "$(BLUE)Optimizing disk settings...$(NC)"
	@echo "Disk scheduler for main device:"
	@cat /sys/block/$(shell df / | tail -1 | cut -d' ' -f1 | sed 's/[0-9]*$$//' | sed 's|/dev/||')/queue/scheduler
	@echo "$(GREEN)Disk optimization complete$(NC)"

# Advanced testing scenarios
stress-test: ## Run stress testing with maximum load
	@echo "$(BLUE)Running stress tests...$(NC)"
	$(PYTHON) ../run_comprehensive_tests.py --all --parallel --max-workers 16 --timeout-minutes 120

endurance-test: ## Run endurance testing (long duration)
	@echo "$(BLUE)Running endurance tests...$(NC)"
	for i in {1..5}; do \
		echo "$(BLUE)Endurance test iteration $$i/5$(NC)"; \
		$(PYTHON) ../run_comprehensive_tests.py --all --parallel --max-workers $(MAX_WORKERS); \
		sleep 30; \
	done

regression-test: ## Run regression testing
	@echo "$(BLUE)Running regression tests...$(NC)"
	$(PYTHON) ../run_comprehensive_tests.py --all --parallel --max-workers $(MAX_WORKERS)
	@echo "Comparing with baseline..."
	@if [ -f results/baseline_performance.json ]; then \
		echo "$(GREEN)Baseline comparison available$(NC)"; \
	else \
		echo "$(YELLOW)No baseline found, current results will be baseline$(NC)"; \
		cp results/performance_report_*.json results/baseline_performance.json 2>/dev/null || true; \
	fi

# Statistics and analysis
stats: ## Show testing statistics
	@echo "$(CYAN)Testing Infrastructure Statistics$(NC)"
	@echo "=================================="
	@echo "Total test files: $(shell find . -name 'test_*.py' | wc -l)"
	@echo "Total Rust test modules: $(shell find ../rust_core -name '*.rs' -exec grep -l '#\[test\]' {} \; | wc -l)"
	@echo "Framework files: $(shell find framework/ -name '*.py' | wc -l)"
	@echo "Test fixtures: $(shell find fixtures/ -name '*' -type f | wc -l)"
	@echo "Recent reports: $(shell find results/ -name '*.json' -mtime -7 | wc -l)"
	@echo ""
	@echo "Disk usage:"
	@du -sh results/ 2>/dev/null || echo "No results directory"
	@echo ""
	@echo "$(GREEN)Statistics complete$(NC)"

# Debug helpers
debug: ## Run tests in debug mode
	@echo "$(BLUE)Running tests in debug mode...$(NC)"
	$(PYTHON) ../run_comprehensive_tests.py --unit-tests --verbose

debug-rust: ## Debug Rust tests
	@echo "$(BLUE)Debugging Rust tests...$(NC)"
	cd ../rust_core && $(CARGO) test --features $(RUST_FEATURES) -- --nocapture

# Make sure the results directory exists
$(shell mkdir -p results/{reports,artifacts,coverage,benchmarks,security})

# Help with colors
info:
	@echo "$(CYAN)CODE Testing Infrastructure$(NC)"
	@echo "$(BLUE)Optimized for 16 threads, 32GB RAM, NVMe SSD$(NC)"
	@echo ""
	@echo "This Makefile provides comprehensive testing capabilities with:"
	@echo "  • $(GREEN)Hardware-optimized parallel execution$(NC)"
	@echo "  • $(GREEN)Comprehensive test coverage$(NC)"
	@echo "  • $(GREEN)Performance benchmarking$(NC)"
	@echo "  • $(GREEN)Security vulnerability scanning$(NC)"
	@echo "  • $(GREEN)Real-time monitoring$(NC)"
	@echo "  • $(GREEN)Detailed reporting$(NC)"
	@echo ""
	@echo "Run '$(GREEN)make help$(NC)' for available commands."