.PHONY: help install dev test lint format clean build docs

# Default target
help:
	@echo "MCP Learning System - Python Package"
	@echo ""
	@echo "Available targets:"
	@echo "  install    Install package in production mode"
	@echo "  dev        Install package in development mode with all extras"
	@echo "  test       Run test suite"
	@echo "  lint       Run linting checks"
	@echo "  format     Format code with black and isort"
	@echo "  clean      Clean build artifacts"
	@echo "  build      Build package with Rust extensions"
	@echo "  docs       Generate documentation"

# Install production dependencies
install:
	pip install -e .

# Install development dependencies
dev:
	pip install -e ".[dev,ml]"
	pre-commit install

# Run tests
test:
	pytest tests/ -v --cov=mcp_learning --cov-report=html --cov-report=term

# Run specific test file
test-file:
	pytest $(FILE) -v -s

# Lint code
lint:
	flake8 mcp_learning/ tests/
	mypy mcp_learning/ --ignore-missing-imports
	black --check mcp_learning/ tests/
	isort --check-only mcp_learning/ tests/

# Format code
format:
	black mcp_learning/ tests/ examples/
	isort mcp_learning/ tests/ examples/

# Clean build artifacts
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete

# Build package with Rust extensions
build: clean
	python setup.py build_ext --inplace
	python -m build

# Build Rust extension only
rust:
	cd ../../rust_core && cargo build --release --features python-bindings
	cp ../../rust_core/target/release/libmcp_rust_core.so mcp_learning/rust_core.so

# Generate documentation
docs:
	sphinx-build -b html docs/ docs/_build/

# Run the demo
demo:
	python examples/learning_demo.py

# Performance benchmarks
benchmark:
	python -m pytest tests/performance/ -v --benchmark-only

# Start development server
server:
	uvicorn mcp_learning.api:app --reload --host 0.0.0.0 --port 8000

# Docker build
docker:
	docker build -t mcp-learning:latest .

# Install pre-commit hooks
pre-commit:
	pre-commit install
	pre-commit run --all-files

# Update dependencies
update-deps:
	pip-compile requirements.in -o requirements.txt --upgrade
	pip-compile requirements-dev.in -o requirements-dev.txt --upgrade

# Security scan
security:
	safety check
	bandit -r mcp_learning/

# Type checking
typecheck:
	mypy mcp_learning/ --strict --ignore-missing-imports

# Coverage report
coverage:
	pytest --cov=mcp_learning --cov-report=html
	open htmlcov/index.html

# Profile code
profile:
	python -m cProfile -o profile.stats examples/learning_demo.py
	python -m pstats profile.stats

# Memory profiling
memprofile:
	mprof run examples/learning_demo.py
	mprof plot