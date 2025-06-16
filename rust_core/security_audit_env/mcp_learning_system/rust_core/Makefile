.PHONY: all build test bench clean install develop docs

# Default target
all: build test

# Build the Rust library
build:
	@echo "Building Rust library..."
	cargo build --release

# Build Python bindings
python: build
	@echo "Building Python bindings..."
	maturin build --release

# Install for development
develop:
	@echo "Installing for development..."
	maturin develop --release

# Run tests
test:
	@echo "Running Rust tests..."
	cargo test --release
	@echo "\nRunning Python tests..."
	cd .. && python test_rust_core.py || true

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	cargo bench

# Generate documentation
docs:
	@echo "Generating documentation..."
	cargo doc --no-deps --open

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -rf target/
	rm -f *.so *.pyd

# Install dependencies
install-deps:
	@echo "Installing dependencies..."
	pip install maturin
	rustup component add rustfmt clippy

# Format code
fmt:
	@echo "Formatting code..."
	cargo fmt

# Run clippy
clippy:
	@echo "Running clippy..."
	cargo clippy -- -D warnings

# Full CI pipeline
ci: fmt clippy build test bench

# Performance report
perf-report: bench
	@echo "\nGenerating performance report..."
	@echo "See target/criterion/report/index.html for detailed results"