#!/bin/bash
# Comprehensive CODE Development Environment Installation for Linux Mint 22.1
# Optimized for AMD Ryzen 7 7800X3D + AMD RX 7900 XT

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

# Check if running on Linux Mint
check_system() {
    if ! grep -q "Linux Mint" /etc/os-release 2>/dev/null; then
        error "This script is designed for Linux Mint. Current system: $(lsb_release -d | cut -f2)"
    fi
    
    if [[ $EUID -eq 0 ]]; then
        error "Do not run this script as root. It will prompt for sudo when needed."
    fi
    
    log "✅ System check passed: $(lsb_release -d | cut -f2)"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Update system packages
update_system() {
    log "🔄 Updating system packages..."
    sudo apt update
    sudo apt upgrade -y
    
    # Install essential build tools
    sudo apt install -y \
        curl wget git git-lfs \
        build-essential cmake pkg-config \
        libssl-dev libffi-dev libpq-dev \
        python3-pip python3-venv python3-dev python3-setuptools python3-wheel \
        apt-transport-https ca-certificates gnupg lsb-release \
        htop btop iotop nethogs \
        clinfo mesa-utils \
        unzip zip tree \
        software-properties-common
        
    log "✅ System packages updated"
}

# Install Rust with performance optimizations
install_rust() {
    if command_exists rustc; then
        log "✅ Rust already installed: $(rustc --version)"
        return
    fi
    
    log "🦀 Installing Rust with performance optimizations..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    
    # Install additional Rust tools
    cargo install maturin cargo-audit cargo-deny cargo-watch
    
    # Configure Rust for performance
    mkdir -p ~/.cargo
    cat > ~/.cargo/config.toml << 'EOF'
[target.x86_64-unknown-linux-gnu]
rustflags = ["-C", "target-cpu=native"]

[build]
jobs = 16  # Match CPU thread count

[registries.crates-io]
protocol = "sparse"
EOF
    
    log "✅ Rust installed with performance optimizations"
}

# Install Node.js via Node Version Manager
install_nodejs() {
    if command_exists node; then
        log "✅ Node.js already installed: $(node --version)"
        return
    fi
    
    log "📦 Installing Node.js..."
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
    export NVM_DIR="$HOME/.nvm"
    [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
    
    nvm install 22
    nvm use 22
    nvm alias default 22
    
    # Install global packages for MCP development
    npm install -g @modelcontextprotocol/cli typescript tsx
    
    log "✅ Node.js installed with MCP development tools"
}

# Install PostgreSQL
install_postgresql() {
    if command_exists psql; then
        log "✅ PostgreSQL already installed"
        return
    fi
    
    log "🐘 Installing PostgreSQL..."
    sudo apt install -y postgresql-16 postgresql-client-16 postgresql-contrib-16
    
    # Start and enable PostgreSQL
    sudo systemctl start postgresql
    sudo systemctl enable postgresql
    
    # Create development database
    sudo -u postgres createuser --superuser $USER 2>/dev/null || true
    sudo -u postgres createdb claude_development 2>/dev/null || true
    
    log "✅ PostgreSQL installed and configured"
}

# Install Redis
install_redis() {
    if command_exists redis-cli; then
        log "✅ Redis already installed"
        return
    fi
    
    log "📡 Installing Redis..."
    sudo apt install -y redis-server redis-tools
    
    # Configure Redis for development
    sudo systemctl start redis-server
    sudo systemctl enable redis-server
    
    # Test Redis connection
    if redis-cli ping > /dev/null 2>&1; then
        log "✅ Redis installed and running"
    else
        warn "Redis installed but not responding to ping"
    fi
}

# Install AMD GPU drivers and ROCm for AI/ML
install_amd_gpu_support() {
    log "🎮 Installing AMD GPU support for RX 7900 XT..."
    
    # Check if GPU is detected
    if ! lspci | grep -qi "AMD.*Navi 31"; then
        warn "AMD RX 7900 XT not detected. Skipping GPU-specific installation."
        return
    fi
    
    # Install Mesa OpenCL
    sudo apt install -y mesa-opencl-icd clinfo vulkan-tools
    
    # Add ROCm repository
    wget -qO - https://repo.radeon.com/rocm/rocm.gpg.key | sudo apt-key add -
    echo 'deb [arch=amd64] https://repo.radeon.com/rocm/apt/6.0/ ubuntu main' | sudo tee /etc/apt/sources.list.d/rocm.list
    sudo apt update
    
    # Install ROCm for AI/ML (selective installation to avoid conflicts)
    sudo apt install -y rocm-dev rocm-libs hip-dev
    
    # Add user to video group for GPU access
    sudo usermod -a -G video,render $USER
    
    log "✅ AMD GPU support installed. Please reboot for full GPU access."
}

# Install Docker with proper configuration
install_docker() {
    if command_exists docker; then
        log "✅ Docker already installed: $(docker --version)"
        return
    fi
    
    log "🐳 Installing Docker..."
    
    # Add Docker repository
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu noble stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    sudo apt update
    sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    
    # Add user to docker group
    sudo usermod -aG docker $USER
    
    # Start and enable Docker
    sudo systemctl start docker
    sudo systemctl enable docker
    
    log "✅ Docker installed. Please log out and back in for group membership to take effect."
}

# Set up Python development environment
setup_python_environment() {
    log "🐍 Setting up Python development environment..."
    
    cd /home/louranicas/projects/claude-optimized-deployment
    
    # Create core virtual environment
    if [[ ! -d "venv" ]]; then
        python3 -m venv venv
        log "Created core Python virtual environment"
    fi
    
    # Activate and upgrade pip
    source venv/bin/activate
    pip install --upgrade pip setuptools wheel
    
    # Install core dependencies
    if [[ -f "requirements.txt" ]]; then
        pip install -r requirements.txt
        log "Installed core Python dependencies"
    fi
    
    # Install development dependencies
    if [[ -f "requirements-dev.txt" ]]; then
        pip install -r requirements-dev.txt
        log "Installed development dependencies"
    fi
    
    # Install package in development mode
    if [[ -f "pyproject.toml" ]]; then
        pip install -e .[dev]
        log "Installed package in development mode"
    fi
    
    # Create AI/ML environment with GPU support
    if [[ ! -d "venv_ai" ]]; then
        python3 -m venv venv_ai
        source venv_ai/bin/activate
        pip install --upgrade pip setuptools wheel
        
        # Install PyTorch with ROCm support
        pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/rocm6.0
        pip install transformers accelerate datasets
        
        log "Created AI/ML virtual environment with GPU support"
    fi
    
    deactivate 2>/dev/null || true
    log "✅ Python environments configured"
}

# Build Rust components
build_rust_components() {
    log "🦀 Building Rust performance components..."
    
    cd /home/louranicas/projects/claude-optimized-deployment
    
    if [[ -f "rust_core/Cargo.toml" ]]; then
        source venv/bin/activate
        pip install maturin
        
        cd rust_core
        maturin develop --release
        cd ..
        
        deactivate 2>/dev/null || true
        log "✅ Rust components built and integrated"
    else
        warn "rust_core/Cargo.toml not found. Skipping Rust build."
    fi
}

# Install security and monitoring tools
install_security_tools() {
    log "🔒 Installing security and monitoring tools..."
    
    # Python security tools
    source venv/bin/activate
    pip install bandit safety pip-audit semgrep
    deactivate 2>/dev/null || true
    
    # System monitoring tools
    sudo apt install -y \
        lynis \
        chkrootkit \
        rkhunter \
        fail2ban \
        ufw
        
    # Configure firewall
    sudo ufw --force reset
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw allow ssh
    sudo ufw --force enable
    
    log "✅ Security and monitoring tools installed"
}

# Configure system optimizations for development
configure_system_optimizations() {
    log "⚡ Configuring system optimizations..."
    
    # Configure CPU governor for performance
    echo 'GOVERNOR="performance"' | sudo tee /etc/default/cpufrequtils
    
    # Increase file watch limits for development
    echo 'fs.inotify.max_user_watches=524288' | sudo tee -a /etc/sysctl.conf
    
    # Configure memory management for large builds
    echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
    
    # Apply sysctl changes
    sudo sysctl -p
    
    # Configure Git for development
    git config --global init.defaultBranch main
    git config --global pull.rebase false
    git config --global core.autocrlf input
    
    log "✅ System optimizations configured"
}

# Verify installation
verify_installation() {
    log "🔍 Verifying installation..."
    
    # Check core tools
    local failures=0
    
    if ! command_exists python3; then echo "❌ Python3 not found"; ((failures++)); else echo "✅ Python3: $(python3 --version)"; fi
    if ! command_exists cargo; then echo "❌ Rust not found"; ((failures++)); else echo "✅ Rust: $(cargo --version)"; fi
    if ! command_exists node; then echo "❌ Node.js not found"; ((failures++)); else echo "✅ Node.js: $(node --version)"; fi
    if ! command_exists docker; then echo "❌ Docker not found"; ((failures++)); else echo "✅ Docker: $(docker --version)"; fi
    if ! command_exists psql; then echo "❌ PostgreSQL not found"; ((failures++)); else echo "✅ PostgreSQL: $(psql --version)"; fi
    if ! command_exists redis-cli; then echo "❌ Redis not found"; ((failures++)); else echo "✅ Redis: $(redis-cli --version)"; fi
    
    # Test GPU support
    if command_exists clinfo; then
        if clinfo | grep -q "AMD"; then
            echo "✅ AMD GPU OpenCL support detected"
        else
            echo "⚠️  AMD GPU OpenCL support not detected"
        fi
    fi
    
    # Test Python environment
    if [[ -d "/home/louranicas/projects/claude-optimized-deployment/venv" ]]; then
        echo "✅ Python virtual environment created"
    else
        echo "❌ Python virtual environment missing"
        ((failures++))
    fi
    
    if [[ $failures -eq 0 ]]; then
        log "🎉 Installation verification successful!"
        echo ""
        echo "Next steps:"
        echo "1. Reboot your system to ensure all drivers are loaded"
        echo "2. Log out and back in for group memberships to take effect"
        echo "3. Run 'source venv/bin/activate' in the project directory"
        echo "4. Test GPU acceleration with 'clinfo' and 'rocm-smi'"
        echo "5. Run the test suite to verify functionality"
    else
        error "Installation verification failed with $failures errors"
    fi
}

# Main installation flow
main() {
    log "🚀 Starting CODE Development Environment Installation"
    log "Target: Linux Mint 22.1 with AMD Ryzen 7 7800X3D + AMD RX 7900 XT"
    
    check_system
    update_system
    install_rust
    install_nodejs
    install_postgresql
    install_redis
    install_amd_gpu_support
    install_docker
    setup_python_environment
    build_rust_components
    install_security_tools
    configure_system_optimizations
    verify_installation
    
    log "✅ Installation complete!"
}

# Handle interrupts gracefully
trap 'error "Installation interrupted"' INT TERM

# Run main installation
main "$@"