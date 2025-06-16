#!/bin/bash
# AMD Ryzen 7 7800X3D + RX 7900 XT Development Environment Setup
# Optimized for Linux Mint with 32GB DDR5 RAM

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[*]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root!"
   exit 1
fi

print_status "Starting AMD Development Environment Setup..."

# Update system
print_status "Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install essential development tools
print_status "Installing essential development tools..."
sudo apt install -y \
    build-essential \
    cmake \
    git \
    curl \
    wget \
    vim \
    neovim \
    htop \
    btop \
    iotop \
    dstat \
    sysstat \
    lm-sensors \
    cpufrequtils \
    linux-tools-common \
    linux-tools-generic \
    linux-tools-$(uname -r) \
    clang \
    llvm \
    lld \
    ninja-build \
    ccache \
    mold \
    pkg-config \
    libssl-dev \
    libclang-dev \
    python3-pip \
    python3-venv \
    nodejs \
    npm \
    ripgrep \
    fd-find \
    bat \
    exa \
    zsh \
    tmux \
    jq \
    ncdu \
    iftop \
    nethogs

# Install AMD GPU drivers and ROCm
print_status "Setting up AMD GPU drivers and ROCm..."

# Add AMD ROCm repository
wget -q -O - https://repo.radeon.com/rocm/rocm.gpg.key | sudo apt-key add -
echo 'deb [arch=amd64] https://repo.radeon.com/rocm/apt/debian/ ubuntu main' | sudo tee /etc/apt/sources.list.d/rocm.list
sudo apt update

# Install ROCm packages
sudo apt install -y \
    rocm-dev \
    rocm-libs \
    rocm-opencl \
    rocm-opencl-dev \
    rocm-clang-ocl \
    rocm-cmake \
    rocm-device-libs \
    rocm-smi-lib \
    rocm-utils \
    rocminfo \
    rocm-bandwidth-test

# Add user to render and video groups for GPU access
sudo usermod -a -G render,video $USER

# Install Rust with optimizations
print_status "Installing Rust with optimizations..."
if ! command -v rustc &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# Install Rust tools
rustup default stable
rustup component add rust-src rust-analyzer clippy rustfmt
cargo install cargo-watch cargo-edit cargo-audit cargo-outdated sccache

# Configure Rust for maximum performance
print_status "Configuring Rust build optimizations..."
mkdir -p ~/.cargo

cat > ~/.cargo/config.toml << 'EOF'
[build]
# Use all available cores for parallel compilation
jobs = 16
# Use mold linker for faster linking
rustflags = ["-C", "link-arg=-fuse-ld=mold"]

[target.x86_64-unknown-linux-gnu]
# Enable CPU-specific optimizations for Zen 4
rustflags = [
    "-C", "target-cpu=znver4",
    "-C", "link-arg=-fuse-ld=mold",
    "-C", "opt-level=3",
    "-C", "lto=thin",
    "-C", "codegen-units=1"
]

[profile.dev]
# Faster debug builds
opt-level = 1
debug = 1
incremental = true

[profile.release]
# Maximum performance for release builds
opt-level = 3
lto = "fat"
codegen-units = 1
panic = "abort"
strip = true

[profile.bench]
# Optimized for benchmarking
opt-level = 3
lto = "fat"
codegen-units = 1

[net]
# Use faster downloads
git-fetch-with-cli = true

[env]
# Use sccache for caching compilation
RUSTC_WRAPPER = "sccache"
EOF

# Set up environment variables
print_status "Setting up environment variables..."
cat >> ~/.bashrc << 'EOF'

# AMD Development Environment Variables
export ROCM_PATH=/opt/rocm
export PATH=$ROCM_PATH/bin:$ROCM_PATH/llvm/bin:$PATH
export LD_LIBRARY_PATH=$ROCM_PATH/lib:$LD_LIBRARY_PATH
export HSA_ENABLE_SDMA=0

# Rust optimizations
export RUSTFLAGS="-C target-cpu=znver4 -C link-arg=-fuse-ld=mold"
export CARGO_BUILD_JOBS=16
export CARGO_INCREMENTAL=1
export RUST_BACKTRACE=1
export RUSTC_WRAPPER=sccache

# Compilation optimizations
export CC=clang
export CXX=clang++
export MAKEFLAGS="-j16"
export CMAKE_BUILD_PARALLEL_LEVEL=16
export NINJA_STATUS="[%f/%t %p :: %e] "

# Memory optimizations
export MALLOC_ARENA_MAX=4
export MALLOC_MMAP_THRESHOLD_=131072
export MALLOC_TRIM_THRESHOLD_=131072
export MALLOC_TOP_PAD_=131072
export MALLOC_MMAP_MAX_=65536

# Node.js memory optimization
export NODE_OPTIONS="--max-old-space-size=16384"

# ccache configuration
export CCACHE_DIR="$HOME/.ccache"
export CCACHE_MAXSIZE="50G"
export CCACHE_SLOPPINESS="file_macro,locale,time_macros"
export CCACHE_COMPRESS=true
export CCACHE_COMPRESSLEVEL=6

# Development paths
export DEVELOPMENT_ROOT="$HOME/projects"
export CUDA_VISIBLE_DEVICES=""  # Disable CUDA, we're using ROCm

# Enable color output
export CLICOLOR=1
export LS_COLORS="di=1;34:ln=1;36:so=1;35:pi=1;33:ex=1;32:bd=1;34;46:cd=1;34;43"

# Pager settings
export PAGER="less -R"
export LESS="-R"

# Editor
export EDITOR=nvim
export VISUAL=nvim

# Python optimizations
export PYTHONUNBUFFERED=1
export PYTHON_CONFIGURE_OPTS="--enable-optimizations --with-lto"

# Aliases for productivity
alias ll='exa -la --git --icons'
alias ls='exa --icons'
alias tree='exa --tree --icons'
alias cat='bat'
alias find='fd'
alias grep='rg'
alias top='btop'
alias vim='nvim'
alias gc='git commit'
alias gp='git push'
alias gs='git status'
alias gd='git diff'
alias gl='git log --oneline --graph --decorate'

# Function to monitor system resources
sysmon() {
    tmux new-session -d -s sysmon
    tmux split-window -h -t sysmon
    tmux split-window -v -t sysmon:0.0
    tmux split-window -v -t sysmon:0.1
    tmux send-keys -t sysmon:0.0 'btop' C-m
    tmux send-keys -t sysmon:0.1 'watch -n 1 rocm-smi' C-m
    tmux send-keys -t sysmon:0.2 'dstat -cdnpmgs' C-m
    tmux send-keys -t sysmon:0.3 'iotop' C-m
    tmux attach-session -t sysmon
}

# Function to show hardware info
hwinfo() {
    echo "=== CPU Information ==="
    lscpu | grep -E "Model name|Socket|Core|Thread|CPU MHz|L3 cache"
    echo -e "\n=== Memory Information ==="
    free -h
    echo -e "\n=== GPU Information ==="
    rocm-smi --showtemp --showpower --showmeminfo vram
    echo -e "\n=== Storage Information ==="
    df -h | grep -E "^/dev|Filesystem"
}

# Development directory shortcut
dev() {
    cd "$DEVELOPMENT_ROOT/${1:-}"
}

# Quick project setup
newproject() {
    if [ -z "$1" ]; then
        echo "Usage: newproject <project-name>"
        return 1
    fi
    mkdir -p "$DEVELOPMENT_ROOT/$1"
    cd "$DEVELOPMENT_ROOT/$1"
    git init
    echo "# $1" > README.md
    echo "Project $1 initialized at $(pwd)"
}
EOF

# Configure ccache
print_status "Configuring ccache..."
ccache --max-size=50G
ccache --set-config=compression=true
ccache --set-config=compression_level=6

# Set up tmpfs for build acceleration
print_status "Setting up tmpfs for build acceleration..."
echo "tmpfs /tmp/build tmpfs defaults,size=16G,mode=1777 0 0" | sudo tee -a /etc/fstab
sudo mkdir -p /tmp/build
sudo mount /tmp/build

# Configure system for performance
print_status "Optimizing system settings..."

# CPU governor
echo "performance" | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Disable CPU mitigations for development (improves performance)
print_warning "Disabling CPU mitigations for better performance (development only)..."
sudo grubby --update-kernel=ALL --args="mitigations=off"

# Increase file watchers for development
echo "fs.inotify.max_user_watches=524288" | sudo tee -a /etc/sysctl.conf
echo "fs.inotify.max_user_instances=512" | sudo tee -a /etc/sysctl.conf

# Memory optimizations
echo "vm.swappiness=10" | sudo tee -a /etc/sysctl.conf
echo "vm.vfs_cache_pressure=50" | sudo tee -a /etc/sysctl.conf
echo "vm.dirty_background_ratio=1" | sudo tee -a /etc/sysctl.conf
echo "vm.dirty_ratio=50" | sudo tee -a /etc/sysctl.conf

# Network optimizations
echo "net.core.rmem_max=134217728" | sudo tee -a /etc/sysctl.conf
echo "net.core.wmem_max=134217728" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_rmem=4096 87380 134217728" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_wmem=4096 65536 134217728" | sudo tee -a /etc/sysctl.conf

sudo sysctl -p

# Set up monitoring services
print_status "Setting up monitoring services..."

# Create monitoring script
cat > ~/bin/hardware-monitor << 'EOF'
#!/bin/bash
# Hardware monitoring dashboard

while true; do
    clear
    echo "=== AMD System Monitor - $(date) ==="
    echo
    echo "--- CPU (Ryzen 7 7800X3D) ---"
    echo "Frequency: $(cat /proc/cpuinfo | grep "cpu MHz" | head -1 | awk '{print $4}') MHz"
    echo "Temperature: $(sensors | grep -E "Tctl|Tdie" | awk '{print $2}')"
    echo "Load: $(uptime | awk -F'load average:' '{print $2}')"
    echo
    echo "--- Memory (32GB DDR5) ---"
    free -h | grep -E "Mem|Swap"
    echo
    echo "--- GPU (RX 7900 XT) ---"
    rocm-smi --showtemp --showpower --showmeminfo vram | grep -E "GPU|Temperature|Power|Memory"
    echo
    echo "--- Storage ---"
    df -h | grep -E "nvme|sda|Filesystem" | awk '{printf "%-20s %5s %5s %5s %4s %s\n", $1, $2, $3, $4, $5, $6}'
    echo
    echo "--- Top Processes ---"
    ps aux --sort=-%cpu | head -6 | awk '{printf "%-10s %5s %5s %s\n", $1, $2, $3, $11}'
    
    sleep 2
done
EOF

chmod +x ~/bin/hardware-monitor

# Install development-specific tools
print_status "Installing additional development tools..."

# Docker
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo usermod -aG docker $USER

# VS Code
wget -q https://packages.microsoft.com/keys/microsoft.asc -O- | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://packages.microsoft.com/repos/vscode stable main"
sudo apt update
sudo apt install -y code

# Install VS Code extensions for development
code --install-extension rust-lang.rust-analyzer
code --install-extension vadimcn.vscode-lldb
code --install-extension serayuzgur.crates
code --install-extension tamasfe.even-better-toml
code --install-extension ms-python.python
code --install-extension ms-vscode.cpptools
code --install-extension ms-azuretools.vscode-docker

print_status "Setup complete!"
print_warning "Please log out and log back in for all changes to take effect."
print_warning "Run 'hwinfo' to see your hardware information."
print_warning "Run 'sysmon' to start the system monitoring dashboard."
print_warning "Run 'hardware-monitor' for a simple hardware monitoring view."

echo
echo "Optimizations applied:"
echo "- ROCm installed for GPU compute"
echo "- Rust configured with 16-thread parallel builds"
echo "- CPU governor set to performance mode"
echo "- Memory and storage optimizations enabled"
echo "- Development tools installed and configured"
echo "- Monitoring tools ready to use"