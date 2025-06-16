# MCP Development Environment Setup Guide

## Overview

This guide provides comprehensive instructions for setting up a development environment optimized for MCP (Model Context Protocol) server development in the Claude Optimized Deployment Engine (CODE) project. It includes tooling, dependencies, configuration, and best practices for efficient MCP development.

## 1. Prerequisites and System Requirements

### 1.1 Hardware Requirements

#### Minimum Requirements:
- **CPU**: 4 cores (Intel i5 or AMD Ryzen 5 equivalent)
- **Memory**: 16GB RAM
- **Storage**: 100GB available SSD space
- **Network**: Stable broadband connection

#### Recommended Requirements:
- **CPU**: 8+ cores (Intel i7/i9 or AMD Ryzen 7/9)
- **Memory**: 32GB+ RAM
- **Storage**: 500GB+ NVMe SSD
- **Network**: High-speed fiber connection

### 1.2 Operating System Support

#### Primary Support:
- **Linux**: Ubuntu 22.04 LTS, Ubuntu 24.04 LTS, Debian 12+
- **macOS**: macOS 12+ (Monterey and later)
- **Windows**: Windows 11 with WSL2

#### Container Support:
- Docker Desktop 4.20+
- Podman 4.0+ (Linux alternative)

### 1.3 Core Software Requirements

```bash
# Essential tools with minimum versions
Python 3.10+           # Primary development language
Node.js 18.0+          # MCP SDK and tooling
Rust 1.70+             # Performance-critical components
Git 2.40+              # Version control
Docker 24.0+           # Containerization
kubectl 1.27+          # Kubernetes CLI
```

## 2. Development Environment Setup

### 2.1 Automated Setup Script

Create and run the comprehensive setup script:

```bash
#!/bin/bash
# setup_mcp_development_environment.sh

set -e  # Exit on any error

echo "🚀 Setting up MCP Development Environment for CODE"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running on supported OS
check_os() {
    print_status "Checking operating system..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        print_success "Linux detected"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        print_success "macOS detected"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        OS="windows"
        print_warning "Windows detected - ensure WSL2 is installed"
    else
        print_error "Unsupported operating system: $OSTYPE"
        exit 1
    fi
}

# Install system dependencies
install_system_dependencies() {
    print_status "Installing system dependencies..."
    
    if [[ "$OS" == "linux" ]]; then
        # Update package list
        sudo apt-get update
        
        # Essential build tools
        sudo apt-get install -y \
            build-essential \
            curl \
            wget \
            git \
            unzip \
            software-properties-common \
            apt-transport-https \
            ca-certificates \
            gnupg \
            lsb-release \
            jq \
            htop \
            vim \
            tmux
            
    elif [[ "$OS" == "macos" ]]; then
        # Check if Homebrew is installed
        if ! command -v brew &> /dev/null; then
            print_status "Installing Homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
        
        # Install essential tools
        brew install \
            curl \
            wget \
            git \
            jq \
            htop \
            vim \
            tmux
    fi
    
    print_success "System dependencies installed"
}

# Install Python and setup virtual environment
setup_python() {
    print_status "Setting up Python environment..."
    
    # Check Python version
    if ! command -v python3 &> /dev/null || [[ $(python3 -c 'import sys; print(sys.version_info[:2] >= (3, 10))') != "True" ]]; then
        print_status "Installing Python 3.11..."
        
        if [[ "$OS" == "linux" ]]; then
            sudo add-apt-repository ppa:deadsnakes/ppa -y
            sudo apt-get update
            sudo apt-get install -y python3.11 python3.11-venv python3.11-dev python3-pip
            
            # Set Python 3.11 as default python3
            sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1
            
        elif [[ "$OS" == "macos" ]]; then
            brew install python@3.11
        fi
    fi
    
    # Install pipx for global Python tools
    python3 -m pip install --user pipx
    python3 -m pipx ensurepath
    
    # Install poetry for dependency management
    if ! command -v poetry &> /dev/null; then
        print_status "Installing Poetry..."
        curl -sSL https://install.python-poetry.org | python3 -
        export PATH="$HOME/.local/bin:$PATH"
    fi
    
    print_success "Python environment configured"
}

# Install Node.js and npm
setup_nodejs() {
    print_status "Setting up Node.js environment..."
    
    # Install nvm (Node Version Manager)
    if ! command -v nvm &> /dev/null; then
        print_status "Installing nvm..."
        curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
        export NVM_DIR="$HOME/.nvm"
        [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
    fi
    
    # Install and use Node.js LTS
    nvm install --lts
    nvm use --lts
    nvm alias default node
    
    # Install global packages
    npm install -g \
        @modelcontextprotocol/cli \
        @modelcontextprotocol/sdk \
        typescript \
        ts-node \
        nodemon \
        pm2
    
    print_success "Node.js environment configured"
}

# Install Rust toolchain
setup_rust() {
    print_status "Setting up Rust environment..."
    
    if ! command -v rustc &> /dev/null; then
        print_status "Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source $HOME/.cargo/env
    fi
    
    # Update to latest stable
    rustup update stable
    rustup default stable
    
    # Install useful Rust tools
    cargo install \
        maturin \
        cargo-watch \
        cargo-edit \
        cargo-audit \
        cargo-outdated
    
    print_success "Rust environment configured"
}

# Install Docker
setup_docker() {
    print_status "Setting up Docker..."
    
    if ! command -v docker &> /dev/null; then
        if [[ "$OS" == "linux" ]]; then
            # Add Docker's official GPG key
            curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
            
            # Add Docker repository
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
            
            # Install Docker
            sudo apt-get update
            sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
            
            # Add user to docker group
            sudo usermod -aG docker $USER
            
        elif [[ "$OS" == "macos" ]]; then
            print_warning "Please install Docker Desktop for Mac from https://www.docker.com/products/docker-desktop"
            print_warning "This script will continue, but Docker Desktop must be installed manually"
        fi
    fi
    
    # Install docker-compose if not present
    if ! command -v docker-compose &> /dev/null; then
        pip3 install docker-compose
    fi
    
    print_success "Docker setup completed"
}

# Install Kubernetes tools
setup_kubernetes() {
    print_status "Setting up Kubernetes tools..."
    
    # Install kubectl
    if ! command -v kubectl &> /dev/null; then
        if [[ "$OS" == "linux" ]]; then
            curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
            sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
            rm kubectl
        elif [[ "$OS" == "macos" ]]; then
            brew install kubectl
        fi
    fi
    
    # Install helm
    if ! command -v helm &> /dev/null; then
        curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
    fi
    
    # Install kind for local Kubernetes
    if ! command -v kind &> /dev/null; then
        if [[ "$OS" == "linux" ]]; then
            curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
            chmod +x ./kind
            sudo mv ./kind /usr/local/bin/kind
        elif [[ "$OS" == "macos" ]]; then
            brew install kind
        fi
    fi
    
    print_success "Kubernetes tools installed"
}

# Clone and setup the project
setup_project() {
    print_status "Setting up CODE project..."
    
    # Create development directory
    mkdir -p ~/development
    cd ~/development
    
    # Clone repository if not exists
    if [ ! -d "claude-optimized-deployment" ]; then
        print_status "Cloning repository..."
        git clone https://github.com/louranicas/claude-optimized-deployment.git
    fi
    
    cd claude-optimized-deployment
    
    # Create Python virtual environment
    print_status "Creating Python virtual environment..."
    python3 -m venv venv_mcp_dev
    source venv_mcp_dev/bin/activate
    
    # Upgrade pip and install build tools
    pip install --upgrade pip setuptools wheel
    
    # Install project dependencies
    print_status "Installing project dependencies..."
    pip install -e ".[dev,ai,monitoring,infrastructure]"
    
    # Setup pre-commit hooks
    print_status "Setting up pre-commit hooks..."
    pre-commit install
    
    # Install MCP inspector for debugging
    pip install mcp-inspector
    
    print_success "Project setup completed"
}

# Setup development tools
setup_development_tools() {
    print_status "Setting up development tools..."
    
    # Install VS Code extensions (if VS Code is available)
    if command -v code &> /dev/null; then
        print_status "Installing VS Code extensions..."
        code --install-extension ms-python.python
        code --install-extension ms-python.black-formatter
        code --install-extension ms-python.isort
        code --install-extension ms-python.pylint
        code --install-extension rust-lang.rust-analyzer
        code --install-extension bradlc.vscode-tailwindcss
        code --install-extension ms-vscode.vscode-typescript-next
        code --install-extension redhat.vscode-yaml
        code --install-extension ms-kubernetes-tools.vscode-kubernetes-tools
        code --install-extension ms-vscode.docker
    fi
    
    # Setup git configuration
    print_status "Configuring git..."
    git config --global init.defaultBranch main
    git config --global pull.rebase false
    
    # Setup shell aliases
    print_status "Setting up shell aliases..."
    cat >> ~/.bashrc << 'EOF'

# MCP Development Aliases
alias mcp-dev='cd ~/development/claude-optimized-deployment && source venv_mcp_dev/bin/activate'
alias mcp-test='pytest tests/mcp_servers/ -v'
alias mcp-lint='black src/ tests/ && ruff check src/ tests/'
alias mcp-run='python -m src.mcp_servers'
alias mcp-docker='docker-compose -f docker-compose.dev.yml'
alias mcp-k8s='kubectl config use-context kind-mcp-dev'

# Kubernetes shortcuts
alias k='kubectl'
alias kgp='kubectl get pods'
alias kgs='kubectl get services'
alias kgn='kubectl get nodes'

# Docker shortcuts
alias dps='docker ps'
alias dimg='docker images'
alias drun='docker run --rm -it'
alias dexec='docker exec -it'
EOF
    
    print_success "Development tools configured"
}

# Setup local infrastructure
setup_local_infrastructure() {
    print_status "Setting up local development infrastructure..."
    
    cd ~/development/claude-optimized-deployment
    
    # Create development docker-compose file
    cat > docker-compose.dev.yml << 'EOF'
version: '3.8'

services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: mcp_dev
      POSTGRES_USER: mcp_user
      POSTGRES_PASSWORD: mcp_pass
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U mcp_user -d mcp_dev"]
      interval: 30s
      timeout: 10s
      retries: 3

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana_data:/var/lib/grafana
      - ./monitoring/grafana-datasources.yml:/etc/grafana/provisioning/datasources/datasources.yml
    depends_on:
      - prometheus

  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686"
      - "14268:14268"
      - "6831:6831/udp"
    environment:
      - COLLECTOR_OTLP_ENABLED=true

volumes:
  postgres_data:
  redis_data:
  prometheus_data:
  grafana_data:
EOF

    # Start local infrastructure
    print_status "Starting local infrastructure..."
    docker-compose -f docker-compose.dev.yml up -d
    
    # Wait for services to be ready
    print_status "Waiting for services to be ready..."
    sleep 30
    
    # Create local Kubernetes cluster
    print_status "Creating local Kubernetes cluster..."
    cat > kind-config.yaml << 'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: mcp-dev
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: InitConfiguration
    nodeRegistration:
      kubeletExtraArgs:
        node-labels: "ingress-ready=true"
  extraPortMappings:
  - containerPort: 80
    hostPort: 80
    protocol: TCP
  - containerPort: 443
    hostPort: 443
    protocol: TCP
- role: worker
- role: worker
EOF
    
    kind create cluster --config kind-config.yaml
    
    print_success "Local infrastructure ready"
}

# Run tests to verify setup
verify_setup() {
    print_status "Verifying setup..."
    
    cd ~/development/claude-optimized-deployment
    source venv_mcp_dev/bin/activate
    
    # Run basic tests
    print_status "Running basic tests..."
    python -c "import sys; print(f'Python version: {sys.version}')"
    python -c "import fastapi; print(f'FastAPI version: {fastapi.__version__}')"
    python -c "import pydantic; print(f'Pydantic version: {pydantic.__version__}')"
    
    # Test Node.js
    node --version
    npm --version
    
    # Test Rust
    rustc --version
    cargo --version
    
    # Test Docker
    docker --version
    docker-compose --version
    
    # Test Kubernetes
    kubectl version --client
    kind --version
    
    # Test project imports
    python -c "from src.mcp_servers import __version__; print(f'MCP Servers version: {__version__}')" || print_warning "MCP servers not yet implemented"
    
    # Run quick test suite
    pytest tests/ -v --tb=short -x || print_warning "Some tests failed - this is normal for initial setup"
    
    print_success "Setup verification completed"
}

# Display final instructions
show_final_instructions() {
    print_success "🎉 MCP Development Environment Setup Complete!"
    
    echo ""
    echo "📋 Next Steps:"
    echo "1. Activate the Python environment: source ~/development/claude-optimized-deployment/venv_mcp_dev/bin/activate"
    echo "2. Navigate to project: cd ~/development/claude-optimized-deployment"
    echo "3. Start development: code . (if using VS Code)"
    echo "4. Run tests: pytest tests/mcp_servers/ -v"
    echo "5. Start local infrastructure: docker-compose -f docker-compose.dev.yml up -d"
    echo ""
    echo "🔗 Useful URLs:"
    echo "- Grafana Dashboard: http://localhost:3000 (admin/admin)"
    echo "- Prometheus: http://localhost:9090"
    echo "- Jaeger Tracing: http://localhost:16686"
    echo "- PostgreSQL: localhost:5432 (mcp_user/mcp_pass/mcp_dev)"
    echo "- Redis: localhost:6379"
    echo ""
    echo "📚 Development Commands:"
    echo "- mcp-dev: Navigate to project and activate environment"
    echo "- mcp-test: Run MCP server tests"
    echo "- mcp-lint: Run code formatting and linting"
    echo "- mcp-docker: Manage local infrastructure"
    echo "- k: kubectl shortcut"
    echo ""
    echo "⚠️  Important Notes:"
    echo "- Restart your shell or run 'source ~/.bashrc' to use aliases"
    echo "- On Linux, log out and back in for Docker group membership"
    echo "- Ensure Docker Desktop is running on macOS/Windows"
    echo ""
}

# Main execution
main() {
    print_status "Starting MCP Development Environment Setup..."
    
    check_os
    install_system_dependencies
    setup_python
    setup_nodejs
    setup_rust
    setup_docker
    setup_kubernetes
    setup_project
    setup_development_tools
    setup_local_infrastructure
    verify_setup
    show_final_instructions
    
    print_success "Setup completed successfully!"
}

# Run main function
main "$@"
```

### 2.2 Manual Setup Steps

If you prefer manual setup or need to troubleshoot the automated script:

#### Step 1: Python Environment
```bash
# Install Python 3.11
sudo apt-get install python3.11 python3.11-venv python3.11-dev

# Create virtual environment
python3.11 -m venv venv_mcp_dev
source venv_mcp_dev/bin/activate

# Install poetry
curl -sSL https://install.python-poetry.org | python3 -
```

#### Step 2: Project Dependencies
```bash
# Clone project
git clone https://github.com/louranicas/claude-optimized-deployment.git
cd claude-optimized-deployment

# Install dependencies
pip install -e ".[dev,ai,monitoring,infrastructure]"

# Setup pre-commit
pre-commit install
```

#### Step 3: MCP Tools
```bash
# Install MCP CLI and SDK
npm install -g @modelcontextprotocol/cli @modelcontextprotocol/sdk

# Install MCP Inspector
pip install mcp-inspector
```

### 2.3 Environment Configuration

#### Environment Variables
Create `.env.development` file:

```bash
# .env.development
# Database Configuration
DATABASE_URL=postgresql://mcp_user:mcp_pass@localhost:5432/mcp_dev
REDIS_URL=redis://localhost:6379/0

# Authentication
JWT_SECRET=your-development-jwt-secret-key
OAUTH_GITHUB_CLIENT_ID=your-github-client-id
OAUTH_GITHUB_CLIENT_SECRET=your-github-client-secret

# External Services
GITHUB_TOKEN=your-github-token
OPENAI_API_KEY=your-openai-api-key

# Monitoring
PROMETHEUS_URL=http://localhost:9090
GRAFANA_URL=http://localhost:3000
JAEGER_ENDPOINT=http://localhost:14268/api/traces

# Development Settings
DEBUG=true
LOG_LEVEL=DEBUG
TESTING=true
CORS_ORIGINS=["http://localhost:3000", "http://localhost:8080"]

# MCP Server Configuration
MCP_SERVER_HOST=localhost
MCP_SERVER_PORT_RANGE_START=8001
MCP_MAX_SERVERS=10
MCP_ENABLE_AUTO_RELOAD=true

# Resource Limits
MAX_MEMORY_MB=1024
MAX_CPU_CORES=4
REQUEST_TIMEOUT_SECONDS=30
```

#### VS Code Configuration
Create `.vscode/settings.json`:

```json
{
  "python.defaultInterpreterPath": "./venv_mcp_dev/bin/python",
  "python.formatting.provider": "black",
  "python.linting.enabled": true,
  "python.linting.pylintEnabled": true,
  "python.linting.mypyEnabled": true,
  "python.testing.pytestEnabled": true,
  "python.testing.pytestArgs": ["tests/"],
  "files.exclude": {
    "**/__pycache__": true,
    "**/*.pyc": true,
    "**/node_modules": true,
    "**/target": true,
    "**/.pytest_cache": true
  },
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.organizeImports": true
  },
  "rust-analyzer.cargo.features": "all",
  "docker.enableDockerComposeLanguageService": true,
  "kubernetes.vs-kubernetes.config-file": "${HOME}/.kube/config"
}
```

#### Launch Configuration
Create `.vscode/launch.json`:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Debug MCP Server",
      "type": "python",
      "request": "launch",
      "program": "${workspaceFolder}/src/mcp_servers/__main__.py",
      "args": ["--server", "development_workflow", "--debug"],
      "console": "integratedTerminal",
      "env": {
        "PYTHONPATH": "${workspaceFolder}",
        "ENV": "development"
      }
    },
    {
      "name": "Run Tests",
      "type": "python",
      "request": "launch",
      "module": "pytest",
      "args": ["tests/mcp_servers/", "-v", "--tb=short"],
      "console": "integratedTerminal"
    },
    {
      "name": "MCP Inspector",
      "type": "python",
      "request": "launch",
      "module": "mcp_inspector",
      "args": ["--server", "http://localhost:8001"],
      "console": "integratedTerminal"
    }
  ]
}
```

## 3. Open Source Tools and Libraries

### 3.1 MCP Development Tools

#### Official MCP Tools
```bash
# MCP CLI - Command line interface for MCP
npm install -g @modelcontextprotocol/cli

# MCP SDK - TypeScript/JavaScript SDK
npm install @modelcontextprotocol/sdk

# MCP Inspector - Debugging and testing tool
pip install mcp-inspector

# Alternative: Install from source
git clone https://github.com/modelcontextprotocol/inspector.git
cd inspector && npm install && npm run build
```

#### Python MCP Libraries
```bash
# Official Python MCP library
pip install mcp

# Additional useful libraries
pip install mcp-testing  # Testing utilities
pip install mcp-tools    # Additional tools
```

### 3.2 Development and Testing Tools

#### Code Quality Tools
```bash
# Python formatting and linting
pip install black isort ruff mypy pylint bandit safety

# Pre-commit hooks
pip install pre-commit

# Testing framework
pip install pytest pytest-asyncio pytest-cov pytest-mock pytest-xdist

# API testing
pip install httpx fastapi-testclient

# Load testing
pip install locust
```

#### Rust Development Tools
```bash
# Essential Rust tools
cargo install maturin cargo-watch cargo-edit cargo-audit cargo-outdated

# Code formatting and linting
rustup component add rustfmt clippy

# Testing tools
cargo install cargo-nextest cargo-tarpaulin
```

### 3.3 Infrastructure and Monitoring

#### Container and Orchestration
```bash
# Docker and Docker Compose (via package manager)
# Kubernetes tools
curl -LO https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl
chmod +x kubectl && sudo mv kubectl /usr/local/bin/

# Helm package manager
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Local Kubernetes
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
chmod +x ./kind && sudo mv ./kind /usr/local/bin/
```

#### Monitoring Stack
```yaml
# monitoring/docker-compose.monitoring.yml
version: '3.8'
services:
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.enable-lifecycle'

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/:/etc/grafana/provisioning/

  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686"
      - "14268:14268"
    environment:
      - COLLECTOR_OTLP_ENABLED=true

  alertmanager:
    image: prom/alertmanager:latest
    ports:
      - "9093:9093"
    volumes:
      - ./alertmanager.yml:/etc/alertmanager/alertmanager.yml

volumes:
  prometheus_data:
  grafana_data:
```

### 3.4 Database and Caching

#### Database Setup
```bash
# PostgreSQL with development data
docker run --name mcp-postgres \
  -e POSTGRES_DB=mcp_dev \
  -e POSTGRES_USER=mcp_user \
  -e POSTGRES_PASSWORD=mcp_pass \
  -p 5432:5432 \
  -d postgres:15

# Redis for caching
docker run --name mcp-redis \
  -p 6379:6379 \
  -d redis:7-alpine
```

#### Database Tools
```bash
# Database migration and ORM
pip install alembic sqlalchemy[asyncio] asyncpg

# Database CLI tools
pip install pgcli redis-cli

# Database testing
pip install pytest-postgresql pytest-redis
```

## 4. Development Workflow and Best Practices

### 4.1 Git Workflow

#### Branch Strategy
```bash
# Feature development
git checkout -b feature/mcp-development-workflow
git checkout -b feature/mcp-code-analysis  
git checkout -b bugfix/authentication-issue

# Release branches
git checkout -b release/v1.1.0

# Hotfix branches
git checkout -b hotfix/security-patch
```

#### Commit Message Convention
```bash
# Format: type(scope): description
git commit -m "feat(mcp): add development workflow server"
git commit -m "fix(auth): resolve JWT token validation"
git commit -m "docs(mcp): update setup guide"
git commit -m "test(mcp): add integration tests"
git commit -m "chore(deps): update dependencies"
```

### 4.2 Testing Strategy

#### Test Structure
```
tests/
├── unit/                   # Unit tests
│   ├── mcp_servers/
│   ├── auth/
│   └── utils/
├── integration/            # Integration tests
│   ├── test_mcp_workflows.py
│   └── test_server_communication.py
├── e2e/                   # End-to-end tests
│   └── test_complete_workflows.py
├── performance/           # Performance tests
│   └── test_load_handling.py
├── security/             # Security tests
│   └── test_auth_security.py
└── fixtures/             # Test data and fixtures
    ├── mcp_responses.json
    └── test_configs.yml
```

#### Test Commands
```bash
# Run all tests
pytest

# Run specific test categories
pytest tests/unit/ -v
pytest tests/integration/ -v
pytest tests/e2e/ -v

# Run with coverage
pytest --cov=src --cov-report=html

# Run performance tests
pytest tests/performance/ --benchmark-only

# Run security tests
pytest tests/security/ -v

# Run tests in parallel
pytest -n auto

# Run specific MCP server tests
pytest tests/unit/mcp_servers/test_development_workflow.py -v
```

### 4.3 Code Quality Standards

#### Python Code Standards
```python
# Example of well-structured MCP server
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from abc import ABC, abstractmethod
import asyncio
import logging

@dataclass
class ToolConfig:
    """Configuration for MCP tool"""
    name: str
    description: str
    parameters: Dict[str, Any]
    timeout: int = 30
    retries: int = 3

class MCPServer(ABC):
    """Abstract base class for MCP servers"""
    
    def __init__(self, name: str, version: str):
        self.name = name
        self.version = version
        self.logger = logging.getLogger(f"mcp.{name}")
        self.tools: Dict[str, ToolConfig] = {}
    
    @abstractmethod
    async def initialize(self) -> None:
        """Initialize server resources"""
        pass
    
    @abstractmethod
    async def cleanup(self) -> None:
        """Cleanup server resources"""
        pass
    
    def register_tool(self, config: ToolConfig):
        """Register a tool with the server"""
        self.tools[config.name] = config
        self.logger.info(f"Registered tool: {config.name}")
    
    async def execute_tool(self, tool_name: str, 
                          parameters: Dict[str, Any],
                          context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a registered tool"""
        if tool_name not in self.tools:
            raise ValueError(f"Tool not found: {tool_name}")
        
        tool_config = self.tools[tool_name]
        
        # Validate parameters
        self._validate_parameters(parameters, tool_config.parameters)
        
        # Execute with timeout and retries
        for attempt in range(tool_config.retries):
            try:
                result = await asyncio.wait_for(
                    self._execute_tool_impl(tool_name, parameters, context),
                    timeout=tool_config.timeout
                )
                return {
                    "success": True,
                    "data": result,
                    "tool": tool_name,
                    "attempt": attempt + 1
                }
            except asyncio.TimeoutError:
                if attempt == tool_config.retries - 1:
                    raise
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
            except Exception as e:
                self.logger.error(f"Tool execution failed: {e}")
                if attempt == tool_config.retries - 1:
                    raise
    
    @abstractmethod
    async def _execute_tool_impl(self, tool_name: str,
                                parameters: Dict[str, Any],
                                context: Dict[str, Any]) -> Any:
        """Implement tool execution logic"""
        pass
    
    def _validate_parameters(self, parameters: Dict[str, Any],
                           expected: Dict[str, Any]) -> None:
        """Validate tool parameters"""
        for param_name, param_config in expected.items():
            if param_config.get("required", False) and param_name not in parameters:
                raise ValueError(f"Required parameter missing: {param_name}")
            
            if param_name in parameters:
                param_value = parameters[param_name]
                param_type = param_config.get("type")
                if param_type and not isinstance(param_value, param_type):
                    raise TypeError(f"Parameter {param_name} must be {param_type}")
```

#### Configuration Management
```python
# config/settings.py
from pydantic import BaseSettings, Field
from typing import List, Optional
import os

class MCPSettings(BaseSettings):
    """MCP server configuration settings"""
    
    # Server settings
    server_host: str = Field(default="localhost", env="MCP_SERVER_HOST")
    server_port_start: int = Field(default=8001, env="MCP_SERVER_PORT_START")
    max_servers: int = Field(default=10, env="MCP_MAX_SERVERS")
    
    # Database settings
    database_url: str = Field(..., env="DATABASE_URL")
    redis_url: str = Field(default="redis://localhost:6379", env="REDIS_URL")
    
    # Authentication
    jwt_secret: str = Field(..., env="JWT_SECRET")
    jwt_algorithm: str = Field(default="HS256", env="JWT_ALGORITHM")
    token_expire_minutes: int = Field(default=30, env="TOKEN_EXPIRE_MINUTES")
    
    # External services
    github_token: Optional[str] = Field(None, env="GITHUB_TOKEN")
    openai_api_key: Optional[str] = Field(None, env="OPENAI_API_KEY")
    
    # Development settings
    debug: bool = Field(default=False, env="DEBUG")
    testing: bool = Field(default=False, env="TESTING")
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    
    # CORS settings
    cors_origins: List[str] = Field(
        default=["http://localhost:3000"],
        env="CORS_ORIGINS"
    )
    
    # Resource limits
    max_memory_mb: int = Field(default=1024, env="MAX_MEMORY_MB")
    max_cpu_cores: int = Field(default=4, env="MAX_CPU_CORES")
    request_timeout: int = Field(default=30, env="REQUEST_TIMEOUT_SECONDS")
    
    class Config:
        env_file = ".env"
        case_sensitive = False

# Usage
settings = MCPSettings()
```

### 4.4 Documentation Standards

#### Code Documentation
```python
def create_project_structure(
    project_name: str,
    template: str = "fastapi",
    features: List[str] = None,
    output_dir: str = "."
) -> Dict[str, Any]:
    """
    Create a new project structure based on template.
    
    Args:
        project_name: Name of the project to create
        template: Project template to use (fastapi, django, flask)
        features: List of features to include (auth, database, tests)
        output_dir: Directory where project should be created
        
    Returns:
        Dict containing:
            - project_path: Path to created project
            - files_created: List of files that were created
            - next_steps: List of recommended next steps
            
    Raises:
        ValueError: If template is not supported
        FileExistsError: If project directory already exists
        PermissionError: If insufficient permissions to create files
        
    Example:
        >>> result = create_project_structure(
        ...     project_name="my-api",
        ...     template="fastapi",
        ...     features=["auth", "database"]
        ... )
        >>> print(result["project_path"])
        /current/dir/my-api
    """
    if features is None:
        features = []
    
    # Implementation here...
```

#### API Documentation
Use FastAPI's automatic OpenAPI generation:

```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI(
    title="MCP Server API",
    description="Model Context Protocol Server API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

class ToolRequest(BaseModel):
    """Request model for tool execution"""
    tool_name: str = Field(..., description="Name of the tool to execute")
    parameters: Dict[str, Any] = Field(..., description="Tool parameters")
    context: Optional[Dict[str, Any]] = Field(None, description="Execution context")

class ToolResponse(BaseModel):
    """Response model for tool execution"""
    success: bool = Field(..., description="Whether execution was successful")
    data: Optional[Any] = Field(None, description="Tool execution result")
    error: Optional[str] = Field(None, description="Error message if failed")
    metadata: Dict[str, Any] = Field(..., description="Execution metadata")

@app.post(
    "/mcp/{server_name}/tools/{tool_name}",
    response_model=ToolResponse,
    summary="Execute MCP tool",
    description="Execute a tool on the specified MCP server",
    responses={
        200: {"description": "Tool executed successfully"},
        400: {"description": "Invalid parameters"},
        401: {"description": "Authentication required"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Tool or server not found"},
        429: {"description": "Rate limit exceeded"},
        500: {"description": "Internal server error"}
    }
)
async def execute_tool(
    server_name: str,
    tool_name: str,
    request: ToolRequest
) -> ToolResponse:
    """Execute a tool on an MCP server"""
    # Implementation here...
```

## 5. Performance Optimization

### 5.1 Python Performance

#### Async/Await Best Practices
```python
import asyncio
from typing import List, Any
import aiohttp
import aiofiles

class PerformantMCPServer:
    def __init__(self):
        self.session: aiohttp.ClientSession = None
        self.semaphore = asyncio.Semaphore(10)  # Limit concurrent operations
    
    async def initialize(self):
        """Initialize with connection pooling"""
        connector = aiohttp.TCPConnector(
            limit=100,  # Total connection pool size
            limit_per_host=30,  # Per host limit
            ttl_dns_cache=300,  # DNS cache TTL
            use_dns_cache=True,
        )
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=30)
        )
    
    async def batch_process(self, items: List[Any]) -> List[Any]:
        """Process items in parallel with rate limiting"""
        async def process_item(item):
            async with self.semaphore:
                return await self._process_single_item(item)
        
        # Process in batches to avoid overwhelming resources
        batch_size = 50
        results = []
        
        for i in range(0, len(items), batch_size):
            batch = items[i:i + batch_size]
            batch_results = await asyncio.gather(
                *[process_item(item) for item in batch],
                return_exceptions=True
            )
            results.extend(batch_results)
        
        return results
    
    async def _process_single_item(self, item: Any) -> Any:
        """Process individual item efficiently"""
        # Use async file I/O
        async with aiofiles.open(f"output_{item.id}.txt", "w") as f:
            await f.write(str(item))
        
        # Use connection pooling for HTTP requests
        async with self.session.get(f"https://api.example.com/item/{item.id}") as response:
            return await response.json()
```

#### Memory Optimization
```python
import gc
from functools import lru_cache
from typing import Generator
import weakref

class MemoryOptimizedMCPServer:
    def __init__(self):
        self.cache = weakref.WeakValueDictionary()
        self._processing_stats = {}
    
    @lru_cache(maxsize=1000)
    def get_cached_config(self, config_key: str) -> Dict[str, Any]:
        """Cache frequently accessed configuration"""
        # Expensive configuration loading
        return self._load_config(config_key)
    
    def process_large_dataset(self, file_path: str) -> Generator[Dict[str, Any], None, None]:
        """Process large files using generators to save memory"""
        with open(file_path, 'r') as f:
            for line_num, line in enumerate(f):
                # Process line and yield result
                result = self._process_line(line)
                yield {"line": line_num, "result": result}
                
                # Periodic garbage collection for large datasets
                if line_num % 10000 == 0:
                    gc.collect()
    
    def cleanup_resources(self):
        """Clean up resources to prevent memory leaks"""
        self.get_cached_config.cache_clear()
        self.cache.clear()
        gc.collect()
```

### 5.2 Rust Integration

#### PyO3 Bindings for Performance-Critical Code
```rust
// src/rust_acceleration/lib.rs
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::HashMap;
use rayon::prelude::*;

#[pyfunction]
fn analyze_code_performance(code: &str, patterns: Vec<String>) -> PyResult<PyObject> {
    // CPU-intensive code analysis in Rust
    let results: HashMap<String, usize> = patterns
        .par_iter()
        .map(|pattern| {
            let count = code.matches(pattern).count();
            (pattern.clone(), count)
        })
        .collect();
    
    Python::with_gil(|py| {
        let dict = PyDict::new(py);
        for (pattern, count) in results {
            dict.set_item(pattern, count)?;
        }
        Ok(dict.into())
    })
}

#[pyfunction]
fn process_large_files(file_paths: Vec<String>) -> PyResult<Vec<String>> {
    // Parallel file processing
    let results: Vec<String> = file_paths
        .par_iter()
        .map(|path| {
            // Process file in parallel
            std::fs::read_to_string(path)
                .map(|content| format!("Processed: {} chars", content.len()))
                .unwrap_or_else(|_| "Error reading file".to_string())
        })
        .collect();
    
    Ok(results)
}

#[pymodule]
fn mcp_rust_acceleration(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(analyze_code_performance, m)?)?;
    m.add_function(wrap_pyfunction!(process_large_files, m)?)?;
    Ok(())
}
```

#### Python Integration
```python
# Use Rust acceleration when available
try:
    from mcp_rust_acceleration import analyze_code_performance, process_large_files
    RUST_AVAILABLE = True
except ImportError:
    RUST_AVAILABLE = False

class CodeAnalysisServer(MCPServer):
    async def analyze_code_patterns(self, code: str, patterns: List[str]) -> Dict[str, Any]:
        """Analyze code patterns with optional Rust acceleration"""
        if RUST_AVAILABLE and len(code) > 10000:  # Use Rust for large files
            try:
                results = analyze_code_performance(code, patterns)
                return {"results": results, "accelerated": True}
            except Exception as e:
                # Fallback to Python implementation
                pass
        
        # Python fallback
        results = {}
        for pattern in patterns:
            results[pattern] = code.count(pattern)
        
        return {"results": results, "accelerated": False}
```

## 6. Troubleshooting Guide

### 6.1 Common Issues and Solutions

#### Python Environment Issues
```bash
# Issue: ImportError or module not found
# Solution: Verify virtual environment and dependencies
source venv_mcp_dev/bin/activate
pip list | grep mcp
pip install -e ".[dev]" --force-reinstall

# Issue: Poetry installation problems
# Solution: Clear poetry cache and reinstall
poetry cache clear . --all
poetry install --no-cache

# Issue: Permission denied errors
# Solution: Fix file permissions
chmod +x scripts/*.sh
sudo chown -R $USER:$USER ~/development/claude-optimized-deployment
```

#### Docker Issues
```bash
# Issue: Docker daemon not running
# Solution: Start Docker service
sudo systemctl start docker
sudo systemctl enable docker

# Issue: Permission denied for Docker
# Solution: Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Issue: Port already in use
# Solution: Find and stop conflicting services
sudo lsof -i :5432  # Check PostgreSQL port
docker-compose down  # Stop containers
```

#### Kubernetes Issues
```bash
# Issue: kubectl not found or misconfigured
# Solution: Reinstall and configure kubectl
curl -LO https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl
chmod +x kubectl && sudo mv kubectl /usr/local/bin/

# Issue: Kind cluster not starting
# Solution: Clean up and recreate
kind delete cluster --name mcp-dev
kind create cluster --config kind-config.yaml

# Issue: Insufficient resources
# Solution: Increase Docker resources
# Docker Desktop -> Settings -> Resources -> Advanced
# Increase Memory to 8GB+, CPU to 4+ cores
```

### 6.2 Performance Troubleshooting

#### Memory Issues
```bash
# Monitor memory usage
htop
ps aux --sort=-%mem | head -20

# Python memory profiling
pip install memory-profiler
python -m memory_profiler script.py

# Check for memory leaks
python -m tracemalloc script.py
```

#### Database Performance
```bash
# PostgreSQL performance monitoring
psql -U mcp_user -d mcp_dev -c "SELECT * FROM pg_stat_activity;"
psql -U mcp_user -d mcp_dev -c "SELECT * FROM pg_stat_user_tables;"

# Redis monitoring
redis-cli info memory
redis-cli monitor
```

### 6.3 Debugging Tools

#### Python Debugging
```python
# Built-in debugger
import pdb; pdb.set_trace()

# Rich debugging with ipdb
import ipdb; ipdb.set_trace()

# Async debugging
import aiotools; await aiotools.DebugSession().start()

# Logging configuration for debugging
import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
```

#### MCP-Specific Debugging
```bash
# Use MCP Inspector for server debugging
mcp-inspector --server http://localhost:8001 --debug

# Test individual tools
curl -X POST http://localhost:8001/mcp/development_workflow/create_project \
  -H "Content-Type: application/json" \
  -d '{"project_name": "test", "template": "fastapi"}'

# Monitor server health
curl http://localhost:8001/health
```

## 7. Next Steps and Advanced Configuration

### 7.1 Production Deployment Preparation

#### Security Hardening
```bash
# Setup SSL certificates
sudo apt-get install certbot
sudo certbot certonly --standalone -d api.your-domain.com

# Configure firewall
sudo ufw enable
sudo ufw allow 22
sudo ufw allow 80
sudo ufw allow 443
```

#### Environment-Specific Configuration
```bash
# Production environment file
cp .env.development .env.production

# Update production settings
sed -i 's/DEBUG=true/DEBUG=false/' .env.production
sed -i 's/localhost/your-production-domain.com/' .env.production
```

### 7.2 Monitoring and Alerting Setup

#### Prometheus Configuration
```yaml
# monitoring/prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'mcp-servers'
    static_configs:
      - targets: ['localhost:8001', 'localhost:8002', 'localhost:8003']
    metrics_path: /metrics
    scrape_interval: 10s
```

#### Grafana Dashboard Import
```bash
# Import pre-built dashboards
curl -X POST \
  http://admin:admin@localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @monitoring/dashboards/mcp-overview.json
```

### 7.3 CI/CD Integration

#### GitHub Actions Workflow
```yaml
# .github/workflows/mcp-development.yml
name: MCP Development Workflow

on:
  push:
    branches: [main, develop]
    paths: ['src/mcp_servers/**', 'tests/**']
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -e ".[dev,testing]"
    
    - name: Run tests
      run: |
        pytest tests/ -v --cov=src --cov-report=xml
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml
```

This comprehensive development environment setup guide provides everything needed to start developing MCP servers for the CODE project. The automated setup script handles most of the configuration, while the manual steps and troubleshooting guide ensure developers can resolve any issues that arise.

---

**Document Version**: 1.0  
**Last Updated**: January 8, 2025  
**Related Documents**: MCP_SERVER_DEVELOPMENT_STRATEGY.md, MCP_INFRASTRUCTURE_PLAN.md