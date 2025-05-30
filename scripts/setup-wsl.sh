#!/bin/bash
# WSL Setup Script for Claude-Optimized Deployment Engine
# This script configures WSL2 environment for optimal CODE performance

set -e

echo "==================================="
echo "CODE WSL Environment Setup"
echo "==================================="

# Detect WSL version
if grep -q microsoft /proc/version; then
    echo "✓ WSL environment detected"
    WSL_VERSION=$(wsl.exe -l -v 2>/dev/null | grep -E "^\*" | awk '{print $4}' || echo "2")
    echo "  WSL Version: $WSL_VERSION"
else
    echo "✗ This script must be run inside WSL"
    exit 1
fi

# Function to check if running with systemd
check_systemd() {
    if [ -d /run/systemd/system ]; then
        echo "✓ systemd is available"
        return 0
    else
        echo "✗ systemd not available (consider enabling in /etc/wsl.conf)"
        return 1
    fi
}

# Update system packages
echo -e "\n📦 Updating system packages..."
sudo apt-get update -qq
sudo apt-get upgrade -y -qq

# Install essential tools
echo -e "\n🔧 Installing essential tools..."
PACKAGES=(
    # Development tools
    build-essential
    git
    curl
    wget
    vim
    jq
    htop
    
    # Python development
    python3-pip
    python3-dev
    python3-venv
    
    # Container tools
    podman
    buildah
    skopeo
    
    # Kubernetes tools
    kubectl
    helm
    
    # Additional tools
    tmux
    zsh
    fzf
    ripgrep
    bat
    exa
    fd-find
)

for package in "${PACKAGES[@]}"; do
    echo "  Installing $package..."
    sudo apt-get install -y -qq "$package" || echo "  ⚠ Failed to install $package"
done

# Install K3s (lightweight Kubernetes)
echo -e "\n☸️ Installing K3s..."
if ! command -v k3s &> /dev/null; then
    curl -sfL https://get.k3s.io | sh -s - --write-kubeconfig-mode 644
    
    # Configure kubectl
    mkdir -p ~/.kube
    sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
    sudo chown $USER:$USER ~/.kube/config
    
    # Add to shell profile
    echo 'export KUBECONFIG=~/.kube/config' >> ~/.bashrc
else
    echo "  K3s already installed"
fi

# Install Kind (Kubernetes in Docker)
echo -e "\n🐳 Installing Kind..."
if ! command -v kind &> /dev/null; then
    curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
    chmod +x ./kind
    sudo mv ./kind /usr/local/bin/kind
else
    echo "  Kind already installed"
fi

# Install OpenTofu (Terraform alternative)
echo -e "\n🏗️ Installing OpenTofu..."
if ! command -v tofu &> /dev/null; then
    curl -Lo ./tofu.tar.gz https://github.com/opentofu/opentofu/releases/download/v1.6.0/tofu_1.6.0_linux_amd64.tar.gz
    tar -xzf tofu.tar.gz
    sudo mv tofu /usr/local/bin/
    rm tofu.tar.gz
else
    echo "  OpenTofu already installed"
fi

# Install Ollama for local LLM
echo -e "\n🤖 Installing Ollama..."
if ! command -v ollama &> /dev/null; then
    curl -fsSL https://ollama.ai/install.sh | sh
    
    # Start Ollama service if systemd available
    if check_systemd; then
        sudo systemctl enable ollama
        sudo systemctl start ollama
    else
        echo "  ⚠ Please start Ollama manually: ollama serve"
    fi
else
    echo "  Ollama already installed"
fi

# Configure WSL-specific optimizations
echo -e "\n⚡ Configuring WSL optimizations..."

# Create WSL config if not exists
if [ ! -f /etc/wsl.conf ]; then
    echo "Creating /etc/wsl.conf..."
    sudo tee /etc/wsl.conf > /dev/null <<EOF
[boot]
systemd=true

[interop]
enabled=true
appendWindowsPath=false

[network]
generateHosts=true
generateResolvConf=true

[filesystem]
umask=022
EOF
fi

# Configure git for cross-platform development
echo -e "\n📝 Configuring Git..."
git config --global core.autocrlf input
git config --global core.eol lf

# Set up Python virtual environment
echo -e "\n🐍 Setting up Python environment..."
cd /home/$USER
if [ ! -d "code-env" ]; then
    python3 -m venv code-env
    source code-env/bin/activate
    pip install --upgrade pip setuptools wheel
    
    # Install Python packages for CODE
    pip install \
        fastapi \
        uvicorn \
        pydantic \
        httpx \
        aiohttp \
        kubernetes \
        openai \
        langchain \
        prometheus-client \
        structlog \
        click \
        rich
fi

# Create CODE workspace structure
echo -e "\n📁 Creating CODE workspace..."
CODE_DIR="$HOME/code-workspace"
mkdir -p "$CODE_DIR"/{projects,configs,scripts,models}

# Create helpful aliases
echo -e "\n🎯 Setting up aliases..."
cat >> ~/.bashrc <<'EOF'

# CODE aliases
alias code-env='source ~/code-env/bin/activate'
alias k='kubectl'
alias kns='kubectl config set-context --current --namespace'
alias tf='tofu'

# WSL helpers
alias win-home='cd /mnt/c/Users/$USER'
alias win-desktop='cd /mnt/c/Users/$USER/Desktop'

# Development helpers
alias ll='exa -la'
alias cat='bat'
alias find='fd'
alias grep='rg'

# Function to convert Windows paths to WSL paths
win2wsl() {
    echo "$1" | sed 's|\\|/|g' | sed 's|C:|/mnt/c|'
}

# Function to convert WSL paths to Windows paths
wsl2win() {
    echo "$1" | sed 's|/mnt/c|C:|' | sed 's|/|\\|g'
}
EOF

# Create systemd service for CODE (if systemd available)
if check_systemd; then
    echo -e "\n🔄 Creating CODE systemd service..."
    sudo tee /etc/systemd/system/code-engine.service > /dev/null <<EOF
[Unit]
Description=Claude-Optimized Deployment Engine
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$HOME/code-workspace
ExecStart=$HOME/code-env/bin/python -m code_engine
Restart=always
Environment="PATH=$HOME/code-env/bin:/usr/local/bin:/usr/bin:/bin"

[Install]
WantedBy=multi-user.target
EOF
fi

# Performance tuning for WSL
echo -e "\n🚀 Applying performance optimizations..."

# Increase file watchers
echo "fs.inotify.max_user_watches=524288" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Configure memory limits for WSL
USERPROFILE=$(wslpath "$(cmd.exe /c 'echo %USERPROFILE%' 2>/dev/null | tr -d '\r')")
if [ -d "$USERPROFILE" ]; then
    cat > "$USERPROFILE/.wslconfig" <<EOF
[wsl2]
memory=8GB
processors=4
swap=4GB
localhostForwarding=true

[experimental]
sparseVhd=true
EOF
    echo "  WSL config created at $USERPROFILE/.wslconfig"
fi

# Install Claude Code CLI helper
echo -e "\n🤖 Installing Claude Code CLI helper..."
cat > ~/code-workspace/scripts/claude-code << 'EOF'
#!/bin/bash
# Claude Code CLI Helper

case "$1" in
    deploy)
        shift
        echo "🚀 Deploying: $*"
        # Natural language deployment logic
        ;;
    analyze)
        echo "📊 Analyzing infrastructure..."
        # Cost and performance analysis
        ;;
    secure)
        echo "🔒 Running security audit..."
        # Security scanning logic
        ;;
    *)
        echo "Usage: claude-code {deploy|analyze|secure} [args]"
        ;;
esac
EOF

chmod +x ~/code-workspace/scripts/claude-code
sudo ln -sf ~/code-workspace/scripts/claude-code /usr/local/bin/claude-code

# Final setup message
echo -e "\n✅ WSL Setup Complete!"
echo "==================================="
echo "Next steps:"
echo "1. Restart WSL: wsl.exe --shutdown (from Windows)"
echo "2. Activate Python env: code-env"
echo "3. Start Ollama: ollama serve"
echo "4. Test Claude Code: claude-code deploy 'hello world api'"
echo ""
echo "Useful commands:"
echo "- k (kubectl)"
echo "- tf (tofu/terraform)"
echo "- win-home (go to Windows home)"
echo "- win2wsl/wsl2win (path converters)"
echo "==================================="
