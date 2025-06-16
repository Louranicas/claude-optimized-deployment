.PHONY: all build release test clean install deploy run help

# Variables
BINARY_NAME = deploy-code
RUST_TARGET = target/release/$(BINARY_NAME)
PYTHON_MODULE = deploy_code.py
INSTALL_PATH = /usr/local/bin
CONFIG_PATH = /etc/deploy-code

# Default target
all: build

help:
	@echo "Deploy CODE Module - Build and Deployment Commands"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build       - Build debug version"
	@echo "  release     - Build optimized release version"
	@echo "  test        - Run all tests"
	@echo "  install     - Install binary and configuration"
	@echo "  deploy      - Deploy CODE platform"
	@echo "  clean       - Remove build artifacts"
	@echo "  help        - Show this help message"

# Build debug version
build:
	@echo "Building deploy-code module (debug)..."
	cargo build
	@echo "Debug build complete: target/debug/$(BINARY_NAME)"

# Build release version
release:
	@echo "Building deploy-code module (release)..."
	cargo build --release
	@echo "Release build complete: $(RUST_TARGET)"

# Run tests
test: build
	@echo "Running Rust tests..."
	cargo test
	@echo "Running Python tests..."
	python -m pytest tests/ -v
	@echo "All tests passed!"

# Install binary and configuration
install: release
	@echo "Installing deploy-code..."
	@sudo mkdir -p $(CONFIG_PATH)
	@sudo mkdir -p $(CONFIG_PATH)/configs
	@sudo cp $(RUST_TARGET) $(INSTALL_PATH)/
	@sudo chmod +x $(INSTALL_PATH)/$(BINARY_NAME)
	@sudo cp deploy-code.yaml $(CONFIG_PATH)/
	@sudo cp $(PYTHON_MODULE) $(INSTALL_PATH)/
	@sudo chmod +x $(INSTALL_PATH)/$(PYTHON_MODULE)
	@echo "Installation complete!"
	@echo "Binary installed to: $(INSTALL_PATH)/$(BINARY_NAME)"
	@echo "Config installed to: $(CONFIG_PATH)/deploy-code.yaml"

# Deploy CODE platform
deploy: release
	@echo "Deploying CODE platform..."
	./$(RUST_TARGET) deploy --config deploy-code.yaml

# Run with Python wrapper
run:
	@echo "Running deploy-code with Python wrapper..."
	python $(PYTHON_MODULE) deploy

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -rf __pycache__
	rm -rf .pytest_cache
	rm -rf *.egg-info
	@echo "Clean complete!"

# Development shortcuts
dev-build:
	cargo build
	@echo "Dev build ready. Run with: ./target/debug/$(BINARY_NAME)"

dev-run: dev-build
	./target/debug/$(BINARY_NAME) --dry-run

# Docker-related targets
docker-build:
	@echo "Building Docker image for deploy-code..."
	docker build -t deploy-code:latest .

docker-run:
	@echo "Running deploy-code in Docker..."
	docker run -it --rm \
		-v $(PWD)/deploy-code.yaml:/etc/deploy-code/deploy-code.yaml \
		-v /var/run/docker.sock:/var/run/docker.sock \
		deploy-code:latest

# Validation and checks
validate:
	@echo "Validating configuration..."
	cargo run -- validate --config deploy-code.yaml

fmt:
	@echo "Formatting Rust code..."
	cargo fmt
	@echo "Formatting Python code..."
	black $(PYTHON_MODULE) tests/

lint:
	@echo "Linting Rust code..."
	cargo clippy -- -D warnings
	@echo "Linting Python code..."
	pylint $(PYTHON_MODULE)
	mypy $(PYTHON_MODULE)

# Security scan
security:
	@echo "Running security scan..."
	cargo audit
	bandit -r $(PYTHON_MODULE)

# Documentation
docs:
	@echo "Generating documentation..."
	cargo doc --no-deps --open

# Benchmarks
bench:
	@echo "Running benchmarks..."
	cargo bench

# Complete CI/CD pipeline
ci: fmt lint test security
	@echo "CI pipeline complete!"

# Production deployment
production: release test
	@echo "Preparing production deployment..."
	@echo "Running final validation..."
	./$(RUST_TARGET) validate --config deploy-code.yaml
	@echo "Production build ready!"

.DEFAULT_GOAL := help