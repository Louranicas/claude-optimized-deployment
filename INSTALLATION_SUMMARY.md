# Development Environment Installation Summary

**Date:** June 8, 2025
**System:** Linux Mint 22.1
**Hardware:** AMD Ryzen 7 7800X3D + AMD RX 7900 XT

## Installed Components

### Core Development Tools
- **Python:** 3.12.3
- **Node.js:** v22.16.0 (via NVM)
- **npm:** 10.9.2
- **Rust/Cargo:** 1.87.0
- **Docker:** 27.5.1
- **Git:** (pre-installed)

### Databases
- **PostgreSQL:** Not installed (requires sudo access)
- **Redis:** Not installed (requires sudo access)
- **MinIO:** RELEASE.2025-05-24T17-08-30Z (installed in ~/bin)

### Python Virtual Environments

#### 1. Core Environment (`venv`)
- **Path:** `/home/louranicas/projects/claude-optimized-deployment/venv`
- **Key Packages:**
  - pydantic 2.9.2
  - fastapi 0.115.12
  - uvicorn 0.34.3
  - sqlalchemy 2.0.41
  - pytest 8.4.0
  - black 25.1.0
  - mypy 1.16.0
  - ruff 0.11.13

#### 2. AI/ML Environment (`venv_ai`)
- **Path:** `/home/louranicas/projects/claude-optimized-deployment/venv_ai`
- **Key Packages:**
  - torch 2.7.1 (CUDA/CPU version - ROCm version download was interrupted)
  - transformers 4.52.4
  - accelerate 1.7.0
  - datasets 3.6.0
  - numpy 2.3.0
  - scipy 1.15.3
  - pandas 2.3.0
  - matplotlib 3.10.3
  - jupyterlab 4.4.3
  - notebook 7.4.3

#### 3. MCP Development Environment (`venv_mcp`)
- **Path:** `/home/louranicas/projects/claude-optimized-deployment/venv_mcp`
- **Key Packages:**
  - mcp 1.9.3
  - pydantic 2.11.5
  - websockets 15.0.1
  - asyncio-mqtt 0.16.2
  - pytest-asyncio 1.0.0

### Node.js/TypeScript Development
- **MCP SDK:** @modelcontextprotocol/sdk 1.12.1
- **MCP Servers:**
  - @modelcontextprotocol/server-filesystem 2025.3.28
  - @modelcontextprotocol/server-memory 2025.4.25
  - @modelcontextprotocol/server-postgres 0.6.2
- **Development Tools:**
  - typescript 5.8.3
  - tsx 4.19.4
  - jest 29.7.0
  - nodemon 3.1.10
  - concurrently 9.1.2

## Next Steps

### 1. Install Missing Components (Requires sudo)
```bash
# PostgreSQL 15
sudo apt install -y postgresql-16 postgresql-client-16 postgresql-contrib-16
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Redis 7
sudo apt install -y redis-server redis-tools
sudo systemctl start redis-server
sudo systemctl enable redis-server

# AMD GPU Support (OpenCL/ROCm)
sudo apt install -y mesa-opencl-icd clinfo vulkan-tools
```

### 2. Start MinIO
```bash
# Option 1: As a systemd user service
systemctl --user enable minio
systemctl --user start minio

# Option 2: Run directly
~/bin/minio server ~/minio-data --console-address :9001
```

### 3. Configure Databases
```bash
# PostgreSQL - Create development database
sudo -u postgres createuser --superuser $USER
sudo -u postgres createdb claude_development

# Test connections
psql -d claude_development -c "SELECT version();"
redis-cli ping
```

### 4. Install PyTorch with ROCm Support (for AMD GPU)
```bash
source venv_ai/bin/activate
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/rocm6.0
```

### 5. Test GPU Support
```bash
# Check OpenCL
clinfo | grep "Device Name"

# Test PyTorch GPU
source venv_ai/bin/activate
python -c "import torch; print(f'CUDA available: {torch.cuda.is_available()}')"
```

## Usage

### Activating Environments
```bash
# Core development
source venv/bin/activate

# AI/ML development
source venv_ai/bin/activate

# MCP development
source venv_mcp/bin/activate

# Start Jupyter Lab
source venv_ai/bin/activate
jupyter lab
```

### Running Services
```bash
# MinIO Object Storage
~/bin/minio server ~/minio-data --console-address :9001

# Access URLs
# MinIO API: http://localhost:9000
# MinIO Console: http://localhost:9001
# Default credentials: minioadmin/minioadmin
```

## Environment Variables
Add to `~/.bashrc`:
```bash
export PATH="$HOME/bin:$PATH"
```

## Notes
- PostgreSQL and Redis require sudo access for installation
- ROCm installation for AMD GPU requires system restart
- MinIO is installed in user space and doesn't require sudo
- All Python environments are isolated and can be used independently