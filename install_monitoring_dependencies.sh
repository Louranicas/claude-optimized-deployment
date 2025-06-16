#!/bin/bash
# Install dependencies for the hardware monitoring dashboard

set -euo pipefail

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[*]${NC} $1"
}

print_status "Installing Python dependencies for monitoring dashboard..."

# Install system dependencies
sudo apt update
sudo apt install -y python3-pip python3-venv python3-dev

# Create virtual environment for monitoring
python3 -m venv ~/.config/hardware_monitor_env
source ~/.config/hardware_monitor_env/bin/activate

# Install Python packages
pip install --upgrade pip
pip install asyncio aiohttp aiofiles websockets psutil sqlite3

# Install additional system monitoring tools
sudo apt install -y smartmontools lm-sensors

# Configure sensors
sudo sensors-detect --auto

print_status "Dependencies installed successfully!"
print_warning "To run the monitoring dashboard:"
echo "source ~/.config/hardware_monitor_env/bin/activate"
echo "python3 configs/monitoring-dashboard.py"
echo
print_warning "Then open http://localhost:8080 in your browser"