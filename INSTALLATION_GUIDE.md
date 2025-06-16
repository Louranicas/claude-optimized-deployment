# CODE Development Environment Installation Guide

Complete installation guide for setting up the Claude Optimized Deployment Environment on Linux Mint 22.1 with AMD Ryzen 7 7800X3D and AMD RX 7900 XT.

## Quick Start

```bash
# Clone repository (if not already done)
cd /home/louranicas/projects/claude-optimized-deployment

# Run primary installation
./scripts/install-linux-mint.sh

# Install GPU support for AI/ML
./scripts/install-gpu-support.sh

# Install MCP development environment
./scripts/install-mcp-development.sh

# Build and install deploy-code module
cd deploy-code-module
make install
cd ..

# Reboot system for all drivers to load
sudo reboot
```

## Pre-Installation Checklist

- [ ] Linux Mint 22.1 installed and updated
- [ ] User has sudo privileges
- [ ] Internet connection available
- [ ] At least 20GB free disk space
- [ ] AMD RX 7900 XT properly seated and powered

## Installation Scripts Overview

### 1. Primary Installation (`install-linux-mint.sh`)

**What it installs:**
- ✅ System packages and build tools
- ✅ Rust 1.87.0 with performance optimizations
- ✅ Node.js 22.x via NVM
- ✅ PostgreSQL 16 with development database
- ✅ Redis 7.x server
- ✅ Docker with user permissions
- ✅ Python virtual environments (core, AI, MCP)
- ✅ Security and monitoring tools
- ✅ System optimizations for development

**Estimated time:** 15-30 minutes

```bash
./scripts/install-linux-mint.sh
```

### 2. GPU Support (`install-gpu-support.sh`)

**What it installs:**
- ✅ Mesa OpenCL and Vulkan drivers
- ✅ ROCm 6.0 for AI/ML acceleration
- ✅ PyTorch with ROCm support
- ✅ GPU-accelerated Python packages
- ✅ Benchmark and testing tools

**Estimated time:** 10-20 minutes

```bash
./scripts/install-gpu-support.sh
```

### 3. MCP Development (`install-mcp-development.sh`)

**What it installs:**
- ✅ MCP CLI and development tools
- ✅ TypeScript and Node.js MCP servers
- ✅ Python MCP libraries
- ✅ Example server implementations
- ✅ Testing and debugging tools
- ✅ Development workspace setup

**Estimated time:** 5-10 minutes

```bash
./scripts/install-mcp-development.sh
```

### 4. Maintenance Tools (`dependency-maintenance.sh`)

**What it provides:**
- ✅ Security vulnerability scanning
- ✅ Dependency updates with safety checks
- ✅ License compliance monitoring
- ✅ Automated reporting

```bash
# Run security scans
./scripts/dependency-maintenance.sh scan

# Apply security updates
./scripts/dependency-maintenance.sh update

# Full maintenance cycle
./scripts/dependency-maintenance.sh full
```

## Manual Installation Steps

If you prefer manual installation or need to troubleshoot:

### 1. System Dependencies

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install build essentials
sudo apt install -y build-essential cmake pkg-config
sudo apt install -y libssl-dev libffi-dev libpq-dev
sudo apt install -y python3-pip python3-venv python3-dev
sudo apt install -y curl wget git git-lfs

# Install databases
sudo apt install -y postgresql-16 postgresql-client-16
sudo apt install -y redis-server redis-tools
```

### 2. Programming Languages

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install Node.js
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
source ~/.bashrc
nvm install 22 && nvm use 22
```

### 3. GPU Support (AMD RX 7900 XT)

```bash
# Install Mesa OpenCL
sudo apt install -y mesa-opencl-icd clinfo vulkan-tools

# Add ROCm repository
wget -qO - https://repo.radeon.com/rocm/rocm.gpg.key | sudo apt-key add -
echo 'deb [arch=amd64] https://repo.radeon.com/rocm/apt/6.0/ ubuntu main' | sudo tee /etc/apt/sources.list.d/rocm.list
sudo apt update

# Install ROCm
sudo apt install -y rocm-dev rocm-libs hip-dev
sudo usermod -a -G video,render $USER
```

### 4. Python Environments

```bash
# Core environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
deactivate

# AI/ML environment with GPU support
python3 -m venv venv_ai
source venv_ai/bin/activate
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/rocm6.0
pip install transformers accelerate datasets
deactivate

# MCP development environment
python3 -m venv venv_mcp
source venv_mcp/bin/activate
pip install mcp mcp-server-git mcp-server-filesystem
deactivate
```

## Post-Installation Verification

### 1. Basic System Check

```bash
# Check installed versions
python3 --version     # Should be 3.12.3
cargo --version       # Should be 1.87.0
node --version        # Should be v22.16.0
docker --version      # Should be 27.5.1+
psql --version        # Should be PostgreSQL 16.x
redis-cli --version   # Should be redis-cli 7.x
```

### 2. GPU Verification

```bash
# Check GPU detection
lspci | grep AMD
clinfo | grep "Device Name"
vulkaninfo --summary | grep AMD

# Test ROCm
rocm-smi --showproductname

# Test PyTorch GPU support
source venv_ai/bin/activate
python -c "import torch; print(f'CUDA available: {torch.cuda.is_available()}')"
deactivate
```

### 3. MCP Development Check

```bash
# Test MCP CLI
mcp --help

# Test example servers
cd mcp_development
npx tsx src/servers/example/index.ts &
sleep 2
echo '{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}' | npx tsx src/servers/example/index.ts
killall node
```

### 4. Run Test Suite

```bash
# Activate core environment
source venv/bin/activate

# Run basic tests
python -c "import fastapi, sqlalchemy, pydantic; print('✅ Core packages working')"

# Test Rust integration
if [ -f "rust_core/Cargo.toml" ]; then
    cd rust_core && maturin develop --release && cd ..
fi

# Test deploy-code module
cd deploy-code-module
python -m pytest tests/ || echo "Deploy-code tests not yet available"
python deploy_code.py --test || echo "Deploy-code basic test"
cd ..

# Run project tests (if available)
pytest tests/ || echo "Test suite not yet available"

deactivate
```

## Development Workflow

### 1. Daily Setup

```bash
cd /home/louranicas/projects/claude-optimized-deployment

# For core development
source venv/bin/activate

# For AI/ML development
source venv_ai/bin/activate

# For MCP development
source venv_mcp/bin/activate
```

### 2. Running Services

```bash
# Start PostgreSQL
sudo systemctl start postgresql

# Start Redis
sudo systemctl start redis-server

# Start Docker (if needed)
sudo systemctl start docker

# Run MCP servers
cd mcp_development
npm run dev
```

### 3. Weekly Maintenance

```bash
# Security scan
./scripts/dependency-maintenance.sh scan

# Update dependencies
./scripts/dependency-maintenance.sh update

# Full maintenance (monthly)
./scripts/dependency-maintenance.sh full
```

## Hardware Optimization

### 1. CPU Optimization (Ryzen 7 7800X3D)

```bash
# Set performance governor
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Configure environment
export OMP_NUM_THREADS=16
export MALLOC_ARENA_MAX=2
```

### 2. GPU Optimization (RX 7900 XT)

```bash
# Set GPU environment variables
export HSA_OVERRIDE_GFX_VERSION=11.0.0
export GPU_MAX_HEAP_SIZE=100
export GPU_MAX_ALLOC_PERCENT=100

# Test GPU performance
source venv_ai/bin/activate
python scripts/gpu-benchmark.py
deactivate
```

### 3. Memory Optimization

```bash
# Increase file watchers for development
echo 'fs.inotify.max_user_watches=524288' | sudo tee -a /etc/sysctl.conf

# Configure swap usage
echo 'vm.swappiness=10' | sudo tee -a /etc/sysctl.conf

# Apply changes
sudo sysctl -p
```

## Troubleshooting

### Common Issues

1. **GPU not detected by ROCm**
   ```bash
   # Check GPU compatibility
   lspci | grep AMD
   
   # Verify user groups
   groups | grep -E "(video|render)"
   
   # Reboot if recently added to groups
   sudo reboot
   ```

2. **Python package conflicts**
   ```bash
   # Reset environment
   rm -rf venv
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **MCP servers not responding**
   ```bash
   # Check Node.js installation
   node --version
   npm --version
   
   # Reinstall MCP packages
   npm install -g @modelcontextprotocol/cli
   ```

4. **Docker permission issues**
   ```bash
   # Add user to docker group
   sudo usermod -aG docker $USER
   
   # Log out and back in, or:
   newgrp docker
   ```

### Log Files

- Installation logs: `~/installation-logs/`
- Application logs: `logs/`
- System logs: `/var/log/`
- Docker logs: `docker logs <container_name>`

## Security Considerations

1. **Firewall Configuration**
   ```bash
   sudo ufw enable
   sudo ufw default deny incoming
   sudo ufw allow ssh
   sudo ufw allow 8000  # FastAPI development
   ```

2. **Regular Security Updates**
   ```bash
   # Weekly security scan
   ./scripts/dependency-maintenance.sh scan
   
   # Apply security patches
   ./scripts/dependency-maintenance.sh update
   ```

3. **Database Security**
   ```bash
   # PostgreSQL security
   sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'secure_password';"
   
   # Redis security (if needed)
   redis-cli CONFIG SET requirepass "secure_password"
   ```

## Environment Variables

Create `~/.env` file:

```bash
# Database
DATABASE_URL=postgresql://postgres:password@localhost:5432/claude_development
REDIS_URL=redis://localhost:6379

# GPU
HSA_OVERRIDE_GFX_VERSION=11.0.0
GPU_MAX_HEAP_SIZE=100

# Development
DEBUG=true
LOG_LEVEL=info
MCP_LOG_LEVEL=debug
```

## Next Steps

1. **Development Setup Complete**: Start developing with the installed environment
2. **Performance Testing**: Run benchmarks to validate GPU acceleration
3. **MCP Development**: Create custom MCP servers for your use case
4. **Security Hardening**: Implement additional security measures for production
5. **Monitoring Setup**: Configure comprehensive monitoring and alerting

## Support

- **Documentation**: `/home/louranicas/projects/claude-optimized-deployment/ai_docs/`
- **Issue Tracking**: Check existing issues in the project
- **Community**: AMD GPU development communities for ROCm support
- **Updates**: Run `./scripts/dependency-maintenance.sh scan` weekly

---

Installation complete! Your CODE development environment is ready for high-performance AI/ML development with full MCP support.