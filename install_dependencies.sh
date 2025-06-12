#!/bin/bash
# Comprehensive dependency installation script for Linux Mint

echo "======================================"
echo "CODE Project Dependency Installation"
echo "======================================"

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install system dependencies
echo -e "\n📦 Installing system dependencies..."
echo "This requires sudo access. Please enter your password when prompted."

# Core Python packages
sudo apt update
sudo apt install -y \
    python3-pip \
    python3-venv \
    python3-dev \
    python3-setuptools \
    python3-wheel \
    build-essential \
    libffi-dev \
    libssl-dev \
    libpq-dev \
    git \
    curl \
    wget

# Install Rust (required for performance modules)
if ! command_exists rustc; then
    echo -e "\n🦀 Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo "✅ Rust already installed"
fi

# Create virtual environment
echo -e "\n🐍 Setting up Python virtual environment..."
cd /home/louranicas/projects/claude-optimized-deployment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
echo -e "\n📦 Upgrading pip..."
python -m pip install --upgrade pip setuptools wheel

# Install Python dependencies
echo -e "\n📦 Installing Python dependencies from requirements.txt..."
pip install -r requirements.txt

echo -e "\n📦 Installing development dependencies..."
pip install -r requirements-dev.txt

# Build Rust modules
if [ -f "rust_core/Cargo.toml" ]; then
    echo -e "\n🦀 Building Rust performance modules..."
    pip install maturin
    cd rust_core
    maturin develop --release
    cd ..
fi

# Verify installation
echo -e "\n✅ Verifying installation..."
python -c "
import sys
print(f'Python: {sys.version}')
try:
    import pydantic
    print('✅ pydantic installed')
except: print('❌ pydantic missing')
try:
    import aiohttp
    print('✅ aiohttp installed')
except: print('❌ aiohttp missing')
try:
    import sqlalchemy
    print('✅ sqlalchemy installed')
except: print('❌ sqlalchemy missing')
try:
    import fastapi
    print('✅ fastapi installed')
except: print('❌ fastapi missing')
"

echo -e "\n✅ Dependency installation complete!"
echo "To activate the virtual environment in future sessions, run:"
echo "source venv/bin/activate"