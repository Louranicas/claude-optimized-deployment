# MCP Launcher Makefile

.PHONY: build run status stop clean install dev test release

# Build the launcher
build:
	cargo build --bin mcp_launcher

# Build release version
release:
	cargo build --release --bin mcp_launcher

# Run the launcher (launch all servers)
run:
	cargo run --bin mcp_launcher

# Check server status
status:
	cargo run --bin mcp_launcher status

# Stop all servers
stop:
	cargo run --bin mcp_launcher stop

# Development mode with logging
dev:
	RUST_LOG=mcp_launcher=debug cargo run --bin mcp_launcher

# Run tests
test:
	cargo test

# Install NPM dependencies for MCP servers
install:
	@echo "Installing MCP server dependencies..."
	npm install -g @modelcontextprotocol/server-filesystem
	npm install -g @modelcontextprotocol/server-github
	npm install -g @modelcontextprotocol/server-memory
	npm install -g @modelcontextprotocol/server-puppeteer
	npm install -g @modelcontextprotocol/server-brave-search
	npm install -g @modelcontextprotocol/server-google-maps
	npm install -g @modelcontextprotocol/server-sqlite

# Clean build artifacts
clean:
	cargo clean
	rm -rf data/*.db logs/*

# Setup environment
setup:
	@echo "Setting up MCP launcher environment..."
	@mkdir -p data logs
	@if [ ! -f .env.mcp ]; then \
		cp .env.mcp.example .env.mcp; \
		echo "Created .env.mcp - please add your API keys"; \
	fi

# Full setup and run
all: setup build install run

# Help
help:
	@echo "MCP Launcher Commands:"
	@echo "  make build    - Build the launcher"
	@echo "  make run      - Launch all MCP servers"
	@echo "  make status   - Check server status"
	@echo "  make stop     - Stop all servers"
	@echo "  make dev      - Run with debug logging"
	@echo "  make install  - Install MCP server dependencies"
	@echo "  make setup    - Setup environment files"
	@echo "  make all      - Full setup and run"