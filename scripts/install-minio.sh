#!/bin/bash
# MinIO installation script for Linux Mint

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +'%H:%M:%S')] $1${NC}"; }
warn() { echo -e "${YELLOW}[WARNING] $1${NC}"; }

install_minio() {
    log "📦 Installing MinIO object storage..."
    
    # Create installation directory
    mkdir -p ~/bin
    cd ~/bin
    
    # Download MinIO server
    log "Downloading MinIO server..."
    wget -q https://dl.min.io/server/minio/release/linux-amd64/minio
    chmod +x minio
    
    # Download MinIO client
    log "Downloading MinIO client (mc)..."
    wget -q https://dl.min.io/client/mc/release/linux-amd64/mc
    chmod +x mc
    
    # Create MinIO data directory
    mkdir -p ~/minio-data
    
    # Create MinIO configuration
    mkdir -p ~/.minio
    
    # Create systemd service file (user service)
    mkdir -p ~/.config/systemd/user
    cat > ~/.config/systemd/user/minio.service << 'EOF'
[Unit]
Description=MinIO Object Storage Server
Documentation=https://min.io
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
Environment="MINIO_ROOT_USER=minioadmin"
Environment="MINIO_ROOT_PASSWORD=minioadmin"
Environment="MINIO_VOLUMES=/home/%u/minio-data"
Environment="MINIO_OPTS=--console-address :9001"
ExecStart=/home/%u/bin/minio server $MINIO_OPTS $MINIO_VOLUMES
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
EOF
    
    # Add MinIO to PATH
    if ! grep -q "~/bin" ~/.bashrc; then
        echo 'export PATH="$HOME/bin:$PATH"' >> ~/.bashrc
        log "Added ~/bin to PATH in ~/.bashrc"
    fi
    
    # Configure MinIO client
    export PATH="$HOME/bin:$PATH"
    ./mc alias set local http://localhost:9000 minioadmin minioadmin
    
    log "✅ MinIO installed successfully"
    echo ""
    echo "MinIO Installation Complete!"
    echo "============================"
    echo ""
    echo "To start MinIO:"
    echo "  systemctl --user enable minio"
    echo "  systemctl --user start minio"
    echo ""
    echo "Or run directly:"
    echo "  ~/bin/minio server ~/minio-data --console-address :9001"
    echo ""
    echo "Access:"
    echo "  MinIO API: http://localhost:9000"
    echo "  MinIO Console: http://localhost:9001"
    echo "  Default credentials: minioadmin/minioadmin"
    echo ""
    echo "MinIO client usage:"
    echo "  mc ls local/"
    echo "  mc mb local/mybucket"
}

# Check if already installed
if [[ -f ~/bin/minio ]] && [[ -f ~/bin/mc ]]; then
    log "✅ MinIO already installed"
    ~/bin/minio --version
    ~/bin/mc --version
else
    install_minio
fi