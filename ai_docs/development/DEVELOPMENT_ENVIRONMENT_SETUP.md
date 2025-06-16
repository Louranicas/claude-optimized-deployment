# Development Environment Setup Guide

**Version**: 2.0.0  
**Date**: December 08, 2025  
**For**: CODE Project Development Team

## Overview

This guide provides comprehensive instructions for setting up a complete development environment for the Claude-Optimized Deployment Engine (CODE) project. It covers everything from basic setup to advanced development configurations.

## Quick Setup (5 Minutes)

### Prerequisites Check
```bash
# Verify required tools
python3 --version  # Should be 3.10+
docker --version   # Should be 20.0+
git --version      # Should be 2.0+
node --version     # Should be 16.0+ (for MCP servers)
```

### Automated Setup
```bash
# Clone and setup everything
git clone https://github.com/louranicas/claude-optimized-deployment.git
cd claude-optimized-deployment

# One-command setup (recommended)
make dev-setup

# Verify installation
make check-env
make experts-health
```

## Manual Setup (Detailed)

### 1. System Dependencies

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install -y python3.11 python3.11-venv python3-pip
sudo apt install -y docker.io docker-compose
sudo apt install -y git git-lfs
sudo apt install -y nodejs npm
sudo apt install -y curl wget

# Enable Docker for current user
sudo usermod -aG docker $USER
newgrp docker
```

#### macOS
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python@3.11
brew install docker docker-compose
brew install git git-lfs
brew install node npm
```

#### Windows (WSL2 recommended)
```powershell
# Enable WSL2
wsl --install -d Ubuntu-22.04

# Then follow Ubuntu instructions inside WSL2
```

### 2. Python Environment Setup

#### Core Environment
```bash
# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Upgrade pip and tools
pip install --upgrade pip setuptools wheel

# Install development dependencies
pip install -e ".[dev]"

# OR install specific feature sets
pip install -e .                    # Core only (minimal)
pip install -e ".[ai]"              # AI/ML features (heavy)
pip install -e ".[cloud]"           # Cloud provider SDKs
pip install -e ".[monitoring]"      # Observability stack
pip install -e ".[database]"        # Database drivers
```

#### Dependency Optimization
```bash
# Check memory usage of different installations
make deps-analyze

# Install only what you need for development
pip install -e ".[dev]"            # Development tools only
pip install -e ".[ai,database]"    # AI + database features

# Avoid heavy installations in development
# Don't install: .[all] - 500MB+ of dependencies
```

### 3. AI Models and Providers

#### Local AI Setup (Recommended for Development)
```bash
# Install Ollama (free, local, private)
make ollama-setup

# OR manual installation
curl -fsSL https://ollama.ai/install.sh | sh

# Pull essential models
ollama pull mixtral          # Best general purpose (4.1GB)
ollama pull codellama        # Code-specific tasks (3.8GB)
ollama pull mistral          # Lightweight option (4.1GB)

# Verify Ollama is working
ollama list
curl http://localhost:11434/api/tags
```

#### Cloud AI Providers (Optional)
```bash
# Set up API keys in .env file
cat > .env << EOF
# Local AI (always available)
OLLAMA_ENABLED=true

# Cloud AI providers (optional, set at least one)
ANTHROPIC_API_KEY=your-anthropic-key
OPENAI_API_KEY=your-openai-key
GOOGLE_API_KEY=your-google-key
DEEPSEEK_API_KEY=your-deepseek-key

# Development settings
ENVIRONMENT=development
LOG_LEVEL=DEBUG
ENABLE_EXPERT_RECOMMENDATIONS=true
EOF
```

### 4. MCP Server Setup

#### Essential MCP Servers
```bash
# Core infrastructure servers
npm install -g @modelcontextprotocol/server-filesystem
npm install -g @modelcontextprotocol/server-git
npm install -g @modelcontextprotocol/server-postgres
npm install -g @modelcontextprotocol/server-redis

# Development tools
npm install -g @wonderwhy-er/desktop-commander
npm install -g @modelcontextprotocol/server-sequential-thinking

# Security and monitoring
npm install -g @modelcontextprotocol/server-prometheus

# Verify MCP servers
make experts-health
```

#### MCP Configuration
```bash
# Our MCP servers are pre-configured in mcp_configs/
ls mcp_configs/

# Test MCP integration
python -c "
import asyncio
from src.mcp.client import MCPClient

async def test():
    client = MCPClient()
    servers = await client.list_servers()
    print(f'Available servers: {len(servers)}')

asyncio.run(test())
"
```

### 5. Database Setup

#### Development Database (SQLite - Default)
```bash
# SQLite is used by default for development
# No additional setup required

# Run migrations
alembic upgrade head

# Verify database
python -c "
from src.database.connection import get_database_url
print(f'Database URL: {get_database_url()}')
"
```

#### PostgreSQL (Optional for Production-like Development)
```bash
# Start PostgreSQL with Docker
docker run -d --name code-postgres \
  -e POSTGRES_DB=code_dev \
  -e POSTGRES_USER=code \
  -e POSTGRES_PASSWORD=dev_password \
  -p 5432:5432 \
  postgres:15

# Update .env for PostgreSQL
echo "DATABASE_URL=postgresql://code:dev_password@localhost:5432/code_dev" >> .env

# Run migrations
alembic upgrade head
```

### 6. Monitoring and Observability

#### Development Monitoring Stack
```bash
# Start monitoring services
docker-compose -f docker-compose.monitoring.yml up -d

# Access dashboards
# Prometheus: http://localhost:9090
# Grafana: http://localhost:3000 (admin/admin)

# Import our pre-built dashboards
ls monitoring/dashboards/
```

#### Log Configuration
```bash
# Configure structured logging
export LOG_LEVEL=DEBUG
export STRUCTURED_LOGGING=true
export LOG_FORMAT=json

# View logs
make dev-logs
```

### 7. Security Configuration

#### Development Security Setup
```bash
# Generate development keys
python scripts/setup_audit_key.py

# Configure security scanning
pip install bandit safety pip-audit

# Run security checks
make security-check

# Configure pre-commit hooks
pre-commit install
```

#### Security Testing
```bash
# Run comprehensive security tests
make test-security

# Check for vulnerabilities
make deps-audit
```

## IDE and Tool Configuration

### VS Code Setup
```bash
# Install VS Code extensions (automated)
make setup-vscode

# OR manual installation of recommended extensions:
# - Python
# - Pylance  
# - Docker
# - GitLens
# - Rust-analyzer (if using Rust features)
```

### Git Configuration
```bash
# Set up Git for the project
make git-setup

# Configure Claude Code integration
git config --local user.name "Your Name"
git config --local user.email "your.email@example.com"

# Install git hooks
make pre-commit-install
```

### Pre-commit Hooks
```bash
# Our pre-commit configuration includes:
# - Black (code formatting)
# - isort (import sorting) 
# - Ruff (linting)
# - bandit (security)
# - mypy (type checking)

# Run hooks manually
make pre-commit-run

# Update hooks
make pre-commit-update
```

## Testing Setup

### Test Environment
```bash
# Run all tests
make test

# Run specific test categories
make test-unit          # Unit tests
make test-integration   # Integration tests  
make test-security      # Security tests
make test-performance   # Performance tests

# Run tests with coverage
make test-all

# Watch mode for development
make test-watch
```

### Test Database
```bash
# Tests use isolated test database
# Configuration in tests/conftest.py

# Reset test database
python -m pytest --reset-db

# Run tests with fresh database
python -m pytest --create-db
```

## Performance Optimization

### Memory Optimization
```bash
# Monitor memory usage during development
make deps-analyze

# Check for memory leaks
python scripts/analyze_memory_usage.py --profile-development

# Optimize import patterns
python scripts/analyze_memory_usage.py --analyze-imports
```

### Rust Extensions (Optional)
```bash
# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Build Rust extensions
make rust-build

# Run Rust tests
make rust-test

# Benchmark Rust code
make rust-bench
```

## Development Workflow

### Daily Development
```bash
# 1. Start development environment
make up

# 2. Run tests before coding
make test

# 3. Start coding with hot reload
make dev-run

# 4. Run quality checks
make quality

# 5. Commit changes
make commit  # Uses AI-powered commit messages

# 6. Stop environment
make down
```

### Feature Development
```bash
# 1. Create feature branch
git checkout -b feature/your-feature-name

# 2. Implement feature with TDD
make test-watch  # Keep running while coding

# 3. Add comprehensive tests
pytest tests/test_your_feature.py -v

# 4. Run full test suite
make test-all

# 5. Security and quality checks
make security-check
make quality

# 6. Create pull request
make pr
```

## Troubleshooting

### Common Issues

#### 1. Docker Permission Denied
```bash
# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Restart Docker service
sudo systemctl restart docker
```

#### 2. Python Version Issues
```bash
# Use pyenv for multiple Python versions
curl https://pyenv.run | bash
pyenv install 3.11.6
pyenv local 3.11.6
```

#### 3. MCP Server Not Found
```bash
# Reinstall MCP servers
npm install -g @modelcontextprotocol/server-filesystem

# Check Node.js path
which node
echo $NODE_PATH
```

#### 4. Database Connection Issues
```bash
# Reset database
rm -f code.db
alembic upgrade head

# Check database configuration
python -c "from src.database.connection import get_engine; print(get_engine())"
```

#### 5. Memory Issues
```bash
# Check memory usage
python scripts/analyze_memory_usage.py --check-development

# Use minimal installation
pip uninstall -y transformers torch tensorflow
pip install -e .  # Core only
```

### Debug Mode
```bash
# Enable comprehensive debugging
export DEBUG=true
export LOG_LEVEL=DEBUG
export PYTHONPATH=$PWD/src

# Run with debugger
python -m pdb src/__main__.py
```

### Performance Profiling
```bash
# Profile application startup
python -m cProfile -o profile.out src/__main__.py

# Analyze profile
python -c "
import pstats
p = pstats.Stats('profile.out')
p.sort_stats('cumulative').print_stats(20)
"
```

## Advanced Configuration

### Environment Variables
```bash
# Complete .env example for development
cat > .env << 'EOF'
# Environment
ENVIRONMENT=development
DEBUG=true
LOG_LEVEL=DEBUG

# AI Providers
ANTHROPIC_API_KEY=your-key
OPENAI_API_KEY=your-key
OLLAMA_ENABLED=true

# Database
DATABASE_URL=sqlite:///code_dev.db

# Security
JWT_SECRET_KEY=dev-secret-key
AUDIT_LOGGING_ENABLED=true

# Performance
MEMORY_OPTIMIZATION_ENABLED=true
CIRCUIT_BREAKER_ENABLED=true

# Monitoring
PROMETHEUS_URL=http://localhost:9090
METRICS_ENABLED=true

# MCP Configuration
MCP_TIMEOUT=30
MCP_RETRY_ATTEMPTS=3
EOF
```

### Custom Configuration
```bash
# Override default settings
cp config/development.yaml.example config/development.yaml
# Edit config/development.yaml for your needs
```

## Validation

### Environment Validation
```bash
# Comprehensive environment check
make check-env

# Validate all systems
python scripts/validate_development_environment.py

# Health check
make experts-health
```

### Success Criteria
- [ ] Python 3.11+ installed and working
- [ ] Virtual environment activated
- [ ] All dependencies installed successfully
- [ ] Docker containers running
- [ ] MCP servers responding
- [ ] Database connected and migrated
- [ ] Tests passing
- [ ] Circle of Experts responding
- [ ] Security checks passing
- [ ] Performance metrics collecting

## Next Steps

1. **Read the Contributing Guide**: [CONTRIBUTING.md](CONTRIBUTING.md)
2. **Explore the Codebase**: Start with `src/circle_of_experts/`
3. **Run Your First Test**: `make test-integration`
4. **Try Expert Consultation**: Use examples in `examples/`
5. **Check Security Setup**: `make security-check`
6. **Join Development**: Pick an issue from our roadmap

## Support

- **Documentation**: See `ai_docs/` directory
- **Examples**: Check `examples/` directory  
- **Tests**: Look at `tests/` for patterns
- **Issues**: GitHub Issues for bugs and features
- **Performance**: Use `make deps-analyze` for optimization

---

*Happy coding! The development environment is designed to be powerful yet efficient. Focus on what works today while building toward the full deployment engine vision.*