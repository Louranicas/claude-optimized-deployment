# MCP Learning System Makefile

.PHONY: help build test clean deploy benchmark docs lint

# Default target
help:
	@echo "MCP Learning System Build Commands"
	@echo "=================================="
	@echo ""
	@echo "Build commands:"
	@echo "  build           Build all components"
	@echo "  build-rust      Build Rust core"
	@echo "  build-python    Build Python learning layer"
	@echo "  build-docker    Build Docker images"
	@echo ""
	@echo "Test commands:"
	@echo "  test            Run all tests"
	@echo "  test-rust       Run Rust tests"
	@echo "  test-python     Run Python tests"
	@echo "  test-integration Run integration tests"
	@echo "  benchmark       Run performance benchmarks"
	@echo ""
	@echo "Development commands:"
	@echo "  dev             Start development environment"
	@echo "  lint            Run linters on all code"
	@echo "  format          Format all code"
	@echo "  clean           Clean build artifacts"
	@echo ""
	@echo "Deployment commands:"
	@echo "  deploy          Deploy to production"
	@echo "  deploy-dev      Deploy to development"
	@echo "  health-check    Check system health"
	@echo ""
	@echo "Documentation:"
	@echo "  docs            Generate documentation"
	@echo "  docs-serve      Serve documentation locally"

# Variables
RUST_DIR := rust_core
PYTHON_DIR := python_learning
DOCKER_COMPOSE := docker-compose
DOCKER_COMPOSE_DEV := docker-compose -f docker-compose.dev.yml
DOCKER_COMPOSE_PROD := docker-compose -f docker-compose.prod.yml

# Build targets
build: build-rust build-python
	@echo "✅ All components built successfully"

build-rust:
	@echo "🦀 Building Rust core..."
	cd $(RUST_DIR) && cargo build --release
	@echo "✅ Rust core built"

build-python:
	@echo "🐍 Building Python learning layer..."
	cd $(PYTHON_DIR) && poetry build
	@echo "✅ Python learning layer built"

build-docker:
	@echo "🐳 Building Docker images..."
	$(DOCKER_COMPOSE) build
	@echo "✅ Docker images built"

# Test targets
test: test-rust test-python test-integration
	@echo "✅ All tests passed"

test-rust:
	@echo "🦀 Running Rust tests..."
	cd $(RUST_DIR) && cargo test --release
	@echo "✅ Rust tests passed"

test-python:
	@echo "🐍 Running Python tests..."
	cd $(PYTHON_DIR) && poetry run pytest --cov=mcp_learning tests/
	@echo "✅ Python tests passed"

test-integration:
	@echo "🔗 Running integration tests..."
	$(DOCKER_COMPOSE) -f docker-compose.test.yml up --build --abort-on-container-exit
	$(DOCKER_COMPOSE) -f docker-compose.test.yml down
	@echo "✅ Integration tests passed"

benchmark:
	@echo "⚡ Running performance benchmarks..."
	cd $(RUST_DIR) && cargo bench
	cd $(PYTHON_DIR) && poetry run pytest --benchmark-only tests/
	@echo "✅ Benchmarks completed"

# Development targets
dev:
	@echo "🚀 Starting development environment..."
	$(DOCKER_COMPOSE_DEV) up --build

dev-down:
	@echo "🛑 Stopping development environment..."
	$(DOCKER_COMPOSE_DEV) down

# Code quality targets
lint: lint-rust lint-python
	@echo "✅ All linting passed"

lint-rust:
	@echo "🦀 Linting Rust code..."
	cd $(RUST_DIR) && cargo clippy -- -D warnings
	@echo "✅ Rust linting passed"

lint-python:
	@echo "🐍 Linting Python code..."
	cd $(PYTHON_DIR) && poetry run ruff check .
	cd $(PYTHON_DIR) && poetry run mypy mcp_learning/
	@echo "✅ Python linting passed"

format: format-rust format-python
	@echo "✅ All code formatted"

format-rust:
	@echo "🦀 Formatting Rust code..."
	cd $(RUST_DIR) && cargo fmt
	@echo "✅ Rust code formatted"

format-python:
	@echo "🐍 Formatting Python code..."
	cd $(PYTHON_DIR) && poetry run black .
	@echo "✅ Python code formatted"

# Deployment targets
deploy: build-docker
	@echo "🚀 Deploying to production..."
	$(DOCKER_COMPOSE_PROD) up -d
	@echo "✅ Production deployment complete"

deploy-dev: build-docker
	@echo "🚀 Deploying to development..."
	$(DOCKER_COMPOSE_DEV) up -d
	@echo "✅ Development deployment complete"

health-check:
	@echo "🏥 Checking system health..."
	@curl -f http://localhost:8080/health || (echo "❌ Rust core health check failed" && exit 1)
	@curl -f http://localhost:8000/health || (echo "❌ Python learning health check failed" && exit 1)
	@curl -f http://localhost:9090/-/healthy || (echo "❌ Prometheus health check failed" && exit 1)
	@echo "✅ All health checks passed"

# Documentation targets
docs:
	@echo "📚 Generating documentation..."
	cd $(RUST_DIR) && cargo doc --no-deps
	cd $(PYTHON_DIR) && poetry run sphinx-build -b html docs/ docs/_build/
	@echo "✅ Documentation generated"

docs-serve:
	@echo "📚 Serving documentation..."
	cd $(PYTHON_DIR)/docs/_build && python -m http.server 8080

# Utility targets
clean:
	@echo "🧹 Cleaning build artifacts..."
	cd $(RUST_DIR) && cargo clean
	cd $(PYTHON_DIR) && rm -rf dist/ .pytest_cache/ .coverage
	$(DOCKER_COMPOSE) down --rmi local --volumes
	@echo "✅ Cleanup complete"

install-deps:
	@echo "📦 Installing dependencies..."
	cd $(RUST_DIR) && cargo fetch
	cd $(PYTHON_DIR) && poetry install
	@echo "✅ Dependencies installed"

setup-dev:
	@echo "🛠️ Setting up development environment..."
	./scripts/install-git-hooks.sh
	./scripts/setup-dev-env.sh
	@echo "✅ Development environment setup complete"

# Security targets
security-scan:
	@echo "🔒 Running security scans..."
	cd $(RUST_DIR) && cargo audit
	cd $(PYTHON_DIR) && poetry run safety check
	cd $(PYTHON_DIR) && poetry run bandit -r mcp_learning/
	@echo "✅ Security scans complete"

# Performance targets
profile-rust:
	@echo "⚡ Profiling Rust performance..."
	cd $(RUST_DIR) && cargo build --release
	cd $(RUST_DIR) && perf record --call-graph=dwarf target/release/mcp-learning-core
	cd $(RUST_DIR) && perf report
	@echo "✅ Rust profiling complete"

profile-python:
	@echo "⚡ Profiling Python performance..."
	cd $(PYTHON_DIR) && poetry run python -m cProfile -o profile.stats scripts/benchmark.py
	cd $(PYTHON_DIR) && poetry run python -c "import pstats; pstats.Stats('profile.stats').sort_stats('tottime').print_stats(20)"
	@echo "✅ Python profiling complete"

# Database targets
db-migrate:
	@echo "💾 Running database migrations..."
	$(DOCKER_COMPOSE) exec python-learning poetry run alembic upgrade head
	@echo "✅ Database migrations complete"

db-reset:
	@echo "💾 Resetting database..."
	$(DOCKER_COMPOSE) exec python-learning poetry run alembic downgrade base
	$(DOCKER_COMPOSE) exec python-learning poetry run alembic upgrade head
	@echo "✅ Database reset complete"

# Monitoring targets
logs:
	@echo "📋 Showing logs..."
	$(DOCKER_COMPOSE) logs -f --tail=100

logs-rust:
	@echo "📋 Showing Rust core logs..."
	$(DOCKER_COMPOSE) logs -f rust-core

logs-python:
	@echo "📋 Showing Python learning logs..."
	$(DOCKER_COMPOSE) logs -f python-learning

metrics:
	@echo "📊 Showing metrics..."
	@curl -s http://localhost:9090/api/v1/query?query=up | jq '.'

# Release targets
release-patch:
	@echo "🏷️ Creating patch release..."
	./scripts/release.sh patch

release-minor:
	@echo "🏷️ Creating minor release..."
	./scripts/release.sh minor

release-major:
	@echo "🏷️ Creating major release..."
	./scripts/release.sh major

# Backup targets
backup:
	@echo "💾 Creating backup..."
	./scripts/backup.sh

restore:
	@echo "💾 Restoring from backup..."
	./scripts/restore.sh $(BACKUP_FILE)

# Load testing
load-test:
	@echo "⚡ Running load tests..."
	./scripts/load-test.sh

stress-test:
	@echo "💥 Running stress tests..."
	./scripts/stress-test.sh