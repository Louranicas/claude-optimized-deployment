# CODE Project Makefile
# Comprehensive automation for development, testing, and deployment

.PHONY: help
help: ## Show this help message
	@echo 'Claude-Optimized Deployment Engine (CODE) - Makefile'
	@echo ''
	@echo 'Usage:'
	@echo '  make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Variables
PYTHON := python3
PIP := $(PYTHON) -m pip
DOCKER := docker
DOCKER_COMPOSE := docker-compose
KUBECTL := kubectl
TERRAFORM := terraform
PYTEST := pytest
BLACK := black
RUFF := ruff
MYPY := mypy

# Project paths
SRC_DIR := src
TEST_DIR := tests
RUST_DIR := rust_core
DOCS_DIR := docs
K8S_DIR := k8s

# Docker settings
DOCKER_REGISTRY := ghcr.io
DOCKER_ORG := yourusername
DOCKER_IMAGE := $(DOCKER_REGISTRY)/$(DOCKER_ORG)/code
DOCKER_TAG := $(shell git rev-parse --short HEAD)

# Environment
ENV ?= dev
NAMESPACE := code-$(ENV)

#########################
# Development Targets
#########################

.PHONY: dev-setup
dev-setup: ## Set up development environment
	@echo "🚀 Setting up development environment..."
	$(PYTHON) -m venv venv
	. venv/bin/activate && $(PIP) install --upgrade pip
	. venv/bin/activate && $(PIP) install -r requirements.txt
	. venv/bin/activate && $(PIP) install -r requirements-dev.txt
	@echo "Installing pre-commit hooks..."
	. venv/bin/activate && pre-commit install
	@echo "Setting up git hooks..."
	cp scripts/hooks/* .git/hooks/
	chmod +x .git/hooks/*
	@echo "✅ Development environment ready!"

.PHONY: dev-clean
dev-clean: ## Clean development environment
	@echo "🧹 Cleaning development environment..."
	rm -rf venv/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	@echo "✅ Clean complete!"

.PHONY: dev-run
dev-run: ## Run development environment with Docker Compose
	@echo "🏃 Starting development environment..."
	$(DOCKER_COMPOSE) -f docker-compose.dev.yml up -d
	@echo "Waiting for services to start..."
	@sleep 10
	@echo "✅ Development environment running!"
	@echo "API: http://localhost:8000"
	@echo "Docs: http://localhost:8000/docs"

.PHONY: dev-stop
dev-stop: ## Stop development environment
	@echo "🛑 Stopping development environment..."
	$(DOCKER_COMPOSE) -f docker-compose.dev.yml down
	@echo "✅ Development environment stopped!"

.PHONY: dev-logs
dev-logs: ## Show development logs
	$(DOCKER_COMPOSE) -f docker-compose.dev.yml logs -f

#########################
# Circle of Experts
#########################

.PHONY: experts-setup
experts-setup: ## Set up Circle of Experts
	@echo "🤖 Setting up Circle of Experts..."
	$(PYTHON) scripts/setup_circle_of_experts.py
	@echo "✅ Circle of Experts ready!"

.PHONY: experts-health
experts-health: ## Check expert availability
	@echo "🏥 Checking expert health..."
	$(PYTHON) -c "import asyncio; from src.circle_of_experts.experts import ExpertHealthCheck; \
		hc = ExpertHealthCheck(); \
		asyncio.run(hc.get_summary())"

.PHONY: experts-demo
experts-demo: ## Run Circle of Experts demo
	@echo "🎭 Running Circle of Experts demo..."
	$(PYTHON) examples/circle_of_experts_usage.py

.PHONY: ollama-setup
ollama-setup: ## Set up Ollama for local AI
	@echo "🦙 Setting up Ollama..."
	curl -fsSL https://ollama.ai/install.sh | sh
	ollama pull mixtral
	ollama pull codellama
	ollama pull mistral
	@echo "✅ Ollama ready with models!"

#########################
# Code Quality
#########################

.PHONY: format
format: ## Format code with black and isort
	@echo "🎨 Formatting code..."
	$(BLACK) $(SRC_DIR) $(TEST_DIR)
	isort $(SRC_DIR) $(TEST_DIR)
	@echo "✅ Code formatted!"

.PHONY: lint
lint: ## Run linting with ruff
	@echo "🔍 Linting code..."
	$(RUFF) check $(SRC_DIR) $(TEST_DIR)
	@echo "✅ Linting passed!"

.PHONY: type-check
type-check: ## Run type checking with mypy
	@echo "🔍 Type checking..."
	$(MYPY) $(SRC_DIR)
	@echo "✅ Type checking passed!"

.PHONY: security-check
security-check: ## Run security checks
	@echo "🔒 Running security checks..."
	bandit -r $(SRC_DIR)
	safety check
	@echo "✅ Security checks passed!"

.PHONY: quality
quality: format lint type-check security-check ## Run all code quality checks

#########################
# Testing
#########################

.PHONY: test
test: ## Run unit tests
	@echo "🧪 Running unit tests..."
	$(PYTEST) $(TEST_DIR)/unit -v

.PHONY: test-integration
test-integration: ## Run integration tests
	@echo "🧪 Running integration tests..."
	$(PYTEST) $(TEST_DIR)/integration -v

.PHONY: test-e2e
test-e2e: ## Run end-to-end tests
	@echo "🧪 Running end-to-end tests..."
	$(PYTEST) $(TEST_DIR)/e2e -v

.PHONY: test-all
test-all: ## Run all tests with coverage
	@echo "🧪 Running all tests..."
	$(PYTEST) $(TEST_DIR) -v --cov=$(SRC_DIR) --cov-report=html --cov-report=term

.PHONY: test-watch
test-watch: ## Run tests in watch mode
	@echo "👀 Running tests in watch mode..."
	$(PYTEST) $(TEST_DIR) -v --watch

.PHONY: coverage
coverage: test-all ## Generate coverage report
	@echo "📊 Opening coverage report..."
	open htmlcov/index.html

#########################
# Rust Build
#########################

.PHONY: rust-build
rust-build: ## Build Rust extensions
	@echo "🦀 Building Rust extensions..."
	cd $(RUST_DIR) && maturin develop --release
	@echo "✅ Rust build complete!"

.PHONY: rust-test
rust-test: ## Test Rust code
	@echo "🦀 Testing Rust code..."
	cd $(RUST_DIR) && cargo test
	@echo "✅ Rust tests passed!"

.PHONY: rust-bench
rust-bench: ## Run Rust benchmarks
	@echo "🦀 Running Rust benchmarks..."
	cd $(RUST_DIR) && cargo bench
	@echo "✅ Benchmarks complete!"

#########################
# Docker
#########################

.PHONY: docker-build
docker-build: ## Build Docker image
	@echo "🐳 Building Docker image..."
	$(DOCKER) build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	$(DOCKER) tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_IMAGE):latest
	@echo "✅ Docker build complete!"

.PHONY: docker-push
docker-push: docker-build ## Push Docker image
	@echo "🐳 Pushing Docker image..."
	$(DOCKER) push $(DOCKER_IMAGE):$(DOCKER_TAG)
	$(DOCKER) push $(DOCKER_IMAGE):latest
	@echo "✅ Docker push complete!"

.PHONY: docker-run
docker-run: ## Run Docker container locally
	@echo "🐳 Running Docker container..."
	$(DOCKER) run -it --rm \
		-p 8000:8000 \
		-e ENVIRONMENT=local \
		$(DOCKER_IMAGE):latest

.PHONY: docker-scan
docker-scan: ## Scan Docker image for vulnerabilities
	@echo "🔍 Scanning Docker image..."
	trivy image $(DOCKER_IMAGE):$(DOCKER_TAG)
	@echo "✅ Docker scan complete!"

#########################
# Kubernetes
#########################

.PHONY: k8s-create-namespace
k8s-create-namespace: ## Create Kubernetes namespace
	@echo "☸️  Creating namespace $(NAMESPACE)..."
	$(KUBECTL) create namespace $(NAMESPACE) --dry-run=client -o yaml | $(KUBECTL) apply -f -

.PHONY: k8s-deploy
k8s-deploy: k8s-create-namespace ## Deploy to Kubernetes
	@echo "☸️  Deploying to $(NAMESPACE)..."
	$(KUBECTL) apply -f $(K8S_DIR)/$(ENV)/ -n $(NAMESPACE)
	@echo "✅ Deployment complete!"

.PHONY: k8s-status
k8s-status: ## Check Kubernetes deployment status
	@echo "☸️  Checking deployment status..."
	$(KUBECTL) get all -n $(NAMESPACE)

.PHONY: k8s-logs
k8s-logs: ## Show Kubernetes logs
	@echo "☸️  Showing logs from $(NAMESPACE)..."
	$(KUBECTL) logs -f -n $(NAMESPACE) -l app=code

.PHONY: k8s-rollback
k8s-rollback: ## Rollback Kubernetes deployment
	@echo "☸️  Rolling back deployment..."
	$(KUBECTL) rollout undo deployment/code-api -n $(NAMESPACE)
	@echo "✅ Rollback complete!"

.PHONY: k8s-delete
k8s-delete: ## Delete Kubernetes deployment
	@echo "☸️  Deleting deployment from $(NAMESPACE)..."
	$(KUBECTL) delete -f $(K8S_DIR)/$(ENV)/ -n $(NAMESPACE)
	@echo "✅ Deletion complete!"

#########################
# Infrastructure
#########################

.PHONY: infra-init
infra-init: ## Initialize Terraform
	@echo "🏗️  Initializing Terraform..."
	cd terraform/$(ENV) && $(TERRAFORM) init
	@echo "✅ Terraform initialized!"

.PHONY: infra-plan
infra-plan: ## Plan infrastructure changes
	@echo "🏗️  Planning infrastructure changes..."
	cd terraform/$(ENV) && $(TERRAFORM) plan -out=tfplan
	@echo "✅ Plan complete!"

.PHONY: infra-apply
infra-apply: ## Apply infrastructure changes
	@echo "🏗️  Applying infrastructure changes..."
	cd terraform/$(ENV) && $(TERRAFORM) apply tfplan
	@echo "✅ Infrastructure updated!"

.PHONY: infra-destroy
infra-destroy: ## Destroy infrastructure
	@echo "🏗️  Destroying infrastructure..."
	@echo "⚠️  This will destroy all resources in $(ENV)!"
	@read -p "Are you sure? (yes/no): " confirm && \
	if [ "$$confirm" = "yes" ]; then \
		cd terraform/$(ENV) && $(TERRAFORM) destroy -auto-approve; \
	fi

#########################
# Monitoring
#########################

.PHONY: monitoring-setup
monitoring-setup: ## Set up monitoring stack
	@echo "📊 Setting up monitoring..."
	helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
	helm repo add grafana https://grafana.github.io/helm-charts
	helm repo update
	helm install prometheus prometheus-community/kube-prometheus-stack \
		-n monitoring --create-namespace \
		-f helm/monitoring/prometheus-values.yaml
	@echo "✅ Monitoring stack deployed!"

.PHONY: monitoring-forward
monitoring-forward: ## Forward monitoring ports
	@echo "📊 Forwarding monitoring ports..."
	@echo "Grafana: http://localhost:3000 (admin/admin)"
	@echo "Prometheus: http://localhost:9090"
	$(KUBECTL) port-forward -n monitoring svc/prometheus-grafana 3000:80 &
	$(KUBECTL) port-forward -n monitoring svc/prometheus-kube-prometheus-prometheus 9090:9090 &

#########################
# Database
#########################

.PHONY: db-migrate
db-migrate: ## Run database migrations
	@echo "🗄️  Running database migrations..."
	alembic upgrade head
	@echo "✅ Migrations complete!"

.PHONY: db-rollback
db-rollback: ## Rollback database migration
	@echo "🗄️  Rolling back database migration..."
	alembic downgrade -1
	@echo "✅ Rollback complete!"

.PHONY: db-seed
db-seed: ## Seed database with test data
	@echo "🗄️  Seeding database..."
	$(PYTHON) scripts/seed_database.py
	@echo "✅ Database seeded!"

.PHONY: db-backup
db-backup: ## Backup database
	@echo "🗄️  Backing up database..."
	@mkdir -p backups
	@TIMESTAMP=$$(date +%Y%m%d_%H%M%S); \
	pg_dump -h localhost -U code -d code_$(ENV) | gzip > backups/backup_$$TIMESTAMP.sql.gz
	@echo "✅ Backup complete!"

#########################
# Documentation
#########################

.PHONY: docs-build
docs-build: ## Build documentation
	@echo "📚 Building documentation..."
	mkdocs build
	@echo "✅ Documentation built!"

.PHONY: docs-serve
docs-serve: ## Serve documentation locally
	@echo "📚 Serving documentation..."
	mkdocs serve

.PHONY: docs-deploy
docs-deploy: ## Deploy documentation to GitHub Pages
	@echo "📚 Deploying documentation..."
	mkdocs gh-deploy
	@echo "✅ Documentation deployed!"

#########################
# Release
#########################

.PHONY: release-patch
release-patch: ## Create patch release
	@echo "🚀 Creating patch release..."
	bump2version patch
	git push && git push --tags
	@echo "✅ Patch release created!"

.PHONY: release-minor
release-minor: ## Create minor release
	@echo "🚀 Creating minor release..."
	bump2version minor
	git push && git push --tags
	@echo "✅ Minor release created!"

.PHONY: release-major
release-major: ## Create major release
	@echo "🚀 Creating major release..."
	bump2version major
	git push && git push --tags
	@echo "✅ Major release created!"

#########################
# Utilities
#########################

.PHONY: clean
clean: dev-clean ## Clean all generated files
	@echo "🧹 Cleaning all generated files..."
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf terraform/*/.terraform
	rm -rf terraform/*/tfplan
	@echo "✅ Clean complete!"

.PHONY: install-tools
install-tools: ## Install required tools
	@echo "🔧 Installing required tools..."
	@which docker >/dev/null || echo "Please install Docker"
	@which kubectl >/dev/null || echo "Please install kubectl"
	@which terraform >/dev/null || echo "Please install Terraform"
	@which helm >/dev/null || echo "Please install Helm"
	@which trivy >/dev/null || brew install aquasecurity/trivy/trivy
	@which pre-commit >/dev/null || pip install pre-commit
	@echo "✅ Tools check complete!"

.PHONY: check-env
check-env: ## Check environment variables
	@echo "🔍 Checking environment variables..."
	@echo "GOOGLE_CREDENTIALS_PATH: $${GOOGLE_CREDENTIALS_PATH:-NOT SET}"
	@echo "ANTHROPIC_API_KEY: $${ANTHROPIC_API_KEY:+SET}"
	@echo "OPENAI_API_KEY: $${OPENAI_API_KEY:+SET}"
	@echo "AWS_PROFILE: $${AWS_PROFILE:-default}"
	@echo "ENVIRONMENT: $${ENV:-dev}"

.PHONY: cost-estimate
cost-estimate: ## Estimate monthly costs
	@echo "💰 Estimating monthly costs..."
	$(PYTHON) scripts/estimate_costs.py

.PHONY: performance-test
performance-test: ## Run performance tests
	@echo "⚡ Running performance tests..."
	locust -f tests/performance/locustfile.py --headless -u 100 -r 10 -t 60s

#########################
# Quick Commands
#########################

.PHONY: up
up: dev-run ## Quick start development

.PHONY: down
down: dev-stop ## Quick stop development

.PHONY: test
test: test-all ## Quick test

.PHONY: deploy
deploy: docker-build docker-push k8s-deploy ## Quick deploy

.PHONY: status
status: k8s-status ## Quick status check

# Default target
.DEFAULT_GOAL := help
#########################
# Git & GitHub Commands
#########################

.PHONY: git-setup
git-setup: ## Complete Git & GitHub setup for Claude Code
	@echo "🔧 Setting up Git & GitHub for Claude Code..."
	chmod +x scripts/setup_git_for_claude.sh
	./scripts/setup_git_for_claude.sh
	@echo "✅ Git setup complete!"

.PHONY: git-commit
git-commit: ## Create AI-powered commit
	@echo "🤖 Creating AI-powered commit..."
	git add -A
	git commit -m "$$(python scripts/generate_commit_message.py)"

.PHONY: git-pr
git-pr: ## Create PR with Claude Code template
	@echo "🔄 Creating pull request..."
	./scripts/git/create-pr.sh

.PHONY: git-sync
git-sync: ## Sync with upstream
	@echo "🔄 Syncing with upstream..."
	git fetch origin
	git rebase origin/main

.PHONY: git-release-patch
git-release-patch: ## Create patch release (x.x.X)
	@echo "🚀 Creating patch release..."
	./scripts/git/create-release.sh patch

.PHONY: git-release-minor
git-release-minor: ## Create minor release (x.X.0)
	@echo "🚀 Creating minor release..."
	./scripts/git/create-release.sh minor

.PHONY: git-release-major
git-release-major: ## Create major release (X.0.0)
	@echo "🚀 Creating major release..."
	./scripts/git/create-release.sh major

.PHONY: git-labels
git-labels: ## Create GitHub labels
	@echo "🏷️  Creating GitHub labels..."
	gh label create "claude-reviewed" --color "7057ff" --description "Reviewed by Claude Code" || true
	gh label create "circle-of-experts" --color "0075ca" --description "Circle of Experts feature" || true
	gh label create "needs-deployment-engine" --color "d73a4a" --description "Blocked by missing deployment" || true
	gh label create "P0-critical" --color "d73a4a" --description "Critical priority" || true
	gh label create "P1-high" --color "ff9800" --description "High priority" || true
	gh label create "P2-medium" --color "4caf50" --description "Medium priority" || true
	gh label create "P3-low" --color "2196f3" --description "Low priority" || true
	@echo "✅ Labels created!"

.PHONY: git-stats
git-stats: ## Show Git statistics
	@echo "📊 Git Statistics"
	@echo "================="
	@echo "Contributors:"
	@git shortlog -sn --all
	@echo ""
	@echo "Recent commits:"
	@git log --oneline -10
	@echo ""
	@echo "File changes:"
	@git diff --stat HEAD~10..HEAD

.PHONY: git-cleanup
git-cleanup: ## Clean up merged branches
	@echo "🧹 Cleaning up merged branches..."
	git branch --merged | grep -v "\*\|main\|develop" | xargs -n 1 git branch -d || true
	@echo "✅ Cleanup complete!"

.PHONY: pre-commit-run
pre-commit-run: ## Run pre-commit hooks manually
	@echo "🪝 Running pre-commit hooks..."
	pre-commit run --all-files

.PHONY: pre-commit-update
pre-commit-update: ## Update pre-commit hooks
	@echo "🔄 Updating pre-commit hooks..."
	pre-commit autoupdate

#########################
# Quick Commands
#########################

.PHONY: up
up: dev-run ## Quick start development

.PHONY: down
down: dev-stop ## Quick stop development

.PHONY: test
test: test-all ## Quick test

.PHONY: deploy
deploy: docker-build docker-push k8s-deploy ## Quick deploy

.PHONY: status
status: k8s-status ## Quick status check

.PHONY: commit
commit: git-commit ## Quick commit with AI

.PHONY: pr
pr: git-pr ## Quick PR creation

# Default target
.DEFAULT_GOAL := help
