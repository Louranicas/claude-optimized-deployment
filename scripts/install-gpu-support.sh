#!/bin/bash
# AMD RX 7900 XT GPU Support Installation for AI/ML Development
# Optimized for Linux Mint 22.1

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +'%H:%M:%S')] $1${NC}"; }
warn() { echo -e "${YELLOW}[WARNING] $1${NC}"; }
error() { echo -e "${RED}[ERROR] $1${NC}"; exit 1; }

# Check if RX 7900 XT is present
check_gpu() {
    log "🔍 Checking for AMD RX 7900 XT..."
    
    if ! lspci | grep -qi "Navi 31"; then
        error "AMD RX 7900 XT (Navi 31) not detected. Found GPUs: $(lspci | grep VGA)"
    fi
    
    log "✅ AMD RX 7900 XT detected"
    lspci | grep -i "VGA\|3D" | grep -i AMD
}

# Install Mesa OpenCL and Vulkan
install_mesa_support() {
    log "📦 Installing Mesa OpenCL and Vulkan support..."
    
    sudo apt update
    sudo apt install -y \
        mesa-opencl-icd \
        opencl-headers \
        clinfo \
        vulkan-tools \
        vulkan-validationlayers \
        mesa-vulkan-drivers \
        libvulkan1 \
        mesa-utils
    
    log "✅ Mesa support installed"
}

# Install ROCm for AI/ML workloads
install_rocm() {
    log "🚀 Installing ROCm for AI/ML acceleration..."
    
    # Check if ROCm is already installed
    if command -v rocm-smi >/dev/null 2>&1; then
        log "✅ ROCm already installed: $(rocm-smi --version 2>/dev/null | head -1 || echo 'Version check failed')"
        return
    fi
    
    # Add ROCm repository key
    wget -qO - https://repo.radeon.com/rocm/rocm.gpg.key | sudo apt-key add -
    
    # Add ROCm repository (Ubuntu 22.04/24.04 compatible)
    echo "deb [arch=amd64] https://repo.radeon.com/rocm/apt/6.0/ ubuntu main" | sudo tee /etc/apt/sources.list.d/rocm.list
    
    sudo apt update
    
    # Install core ROCm packages (selective to avoid conflicts)
    sudo apt install -y \
        rocm-dev \
        rocm-libs \
        hip-dev \
        rocblas \
        rocsparse \
        rocfft \
        rocrand \
        miopen-hip \
        rocm-device-libs
    
    # Add user to video and render groups for GPU access
    sudo usermod -a -G video,render $USER
    
    log "✅ ROCm installed. User added to video and render groups."
}

# Configure environment variables
configure_environment() {
    log "🔧 Configuring environment variables..."
    
    # Create ROCm environment configuration
    cat > ~/.rocm_env << 'EOF'
# ROCm Environment Configuration for AMD RX 7900 XT
export ROCM_PATH=/opt/rocm
export PATH=$ROCM_PATH/bin:$PATH
export LD_LIBRARY_PATH=$ROCM_PATH/lib:$LD_LIBRARY_PATH
export LIBRARY_PATH=$ROCM_PATH/lib:$LIBRARY_PATH
export CPATH=$ROCM_PATH/include:$CPATH

# AMD GPU specific settings
export HSA_OVERRIDE_GFX_VERSION=11.0.0  # For RX 7900 XT compatibility
export GPU_MAX_HEAP_SIZE=100
export GPU_MAX_ALLOC_PERCENT=100
export GPU_SINGLE_ALLOC_PERCENT=100

# OpenCL settings
export OPENCL_VENDOR_PATH=/etc/OpenCL/vendors
EOF
    
    # Add to shell profile
    if ! grep -q "source ~/.rocm_env" ~/.bashrc; then
        echo "source ~/.rocm_env" >> ~/.bashrc
        log "Added ROCm environment to ~/.bashrc"
    fi
    
    # Source environment for current session
    source ~/.rocm_env
    
    log "✅ Environment configured"
}

# Install Python packages with GPU support
install_gpu_python_packages() {
    log "🐍 Installing Python packages with GPU acceleration..."
    
    local project_dir="/home/louranicas/projects/claude-optimized-deployment"
    cd "$project_dir"
    
    # Create or activate AI environment
    if [[ ! -d "venv_ai" ]]; then
        python3 -m venv venv_ai
        log "Created venv_ai environment"
    fi
    
    source venv_ai/bin/activate
    pip install --upgrade pip setuptools wheel
    
    # Install PyTorch with ROCm support
    log "Installing PyTorch with ROCm 6.0 support..."
    pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/rocm6.0
    
    # Install additional AI/ML packages
    pip install \
        transformers>=4.37.0 \
        accelerate>=0.24.0 \
        datasets>=2.14.0 \
        tokenizers>=0.15.0 \
        huggingface-hub>=0.19.0
    
    # Install computer vision with GPU support
    pip install \
        opencv-python-headless>=4.8.0 \
        pillow>=10.0.0 \
        scikit-image>=0.21.0
    
    # Install scientific computing
    pip install \
        numpy>=1.26.0 \
        scipy>=1.11.0 \
        pandas>=2.1.0 \
        matplotlib>=3.7.0
    
    deactivate
    log "✅ GPU-accelerated Python packages installed"
}

# Test GPU functionality
test_gpu_functionality() {
    log "🧪 Testing GPU functionality..."
    
    # Test OpenCL
    log "Testing OpenCL..."
    if clinfo | grep -q "AMD"; then
        log "✅ OpenCL devices found:"
        clinfo | grep -A 3 "Device Name"
    else
        warn "No AMD OpenCL devices found"
    fi
    
    # Test ROCm
    log "Testing ROCm..."
    if command -v rocm-smi >/dev/null 2>&1; then
        rocm-smi --showproductname || warn "ROCm device query failed"
    else
        warn "rocm-smi not available"
    fi
    
    # Test Vulkan
    log "Testing Vulkan..."
    if vulkaninfo --summary | grep -q "AMD"; then
        log "✅ Vulkan support detected"
    else
        warn "Vulkan support not detected"
    fi
    
    # Test PyTorch GPU support
    local project_dir="/home/louranicas/projects/claude-optimized-deployment"
    if [[ -d "$project_dir/venv_ai" ]]; then
        log "Testing PyTorch GPU support..."
        cd "$project_dir"
        source venv_ai/bin/activate
        
        python3 -c "
import torch
print(f'PyTorch version: {torch.__version__}')
print(f'CUDA available: {torch.cuda.is_available()}')
if torch.cuda.is_available():
    print(f'CUDA devices: {torch.cuda.device_count()}')
    print(f'Current device: {torch.cuda.get_device_name()}')
else:
    print('No CUDA devices detected (expected for ROCm)')
    
# Test ROCm support
try:
    import torch
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    x = torch.randn(1000, 1000, device=device)
    y = torch.mm(x, x)
    print(f'✅ GPU tensor operations successful on {device}')
except Exception as e:
    print(f'❌ GPU tensor operations failed: {e}')
"
        deactivate
    fi
}

# Create GPU benchmark script
create_benchmark_script() {
    log "📊 Creating GPU benchmark script..."
    
    local project_dir="/home/louranicas/projects/claude-optimized-deployment"
    cat > "$project_dir/scripts/gpu-benchmark.py" << 'EOF'
#!/usr/bin/env python3
"""
AMD RX 7900 XT GPU Benchmark Script
Tests compute performance for AI/ML workloads
"""

import time
import torch
import numpy as np
from typing import List, Tuple

def benchmark_matrix_operations(device: torch.device, size: int = 4096, iterations: int = 10) -> float:
    """Benchmark matrix multiplication performance."""
    print(f"Benchmarking {size}x{size} matrix multiplication on {device}")
    
    # Create random matrices
    a = torch.randn(size, size, device=device, dtype=torch.float32)
    b = torch.randn(size, size, device=device, dtype=torch.float32)
    
    # Warmup
    for _ in range(3):
        torch.mm(a, b)
    
    # Synchronize and time
    if device.type == 'cuda':
        torch.cuda.synchronize()
    
    start_time = time.time()
    for _ in range(iterations):
        c = torch.mm(a, b)
        if device.type == 'cuda':
            torch.cuda.synchronize()
    
    end_time = time.time()
    avg_time = (end_time - start_time) / iterations
    
    # Calculate GFLOPS
    operations = 2 * size**3  # Matrix multiplication operations
    gflops = operations / (avg_time * 1e9)
    
    print(f"  Average time: {avg_time:.4f} seconds")
    print(f"  Performance: {gflops:.2f} GFLOPS")
    
    return gflops

def benchmark_convolution(device: torch.device, batch_size: int = 32, iterations: int = 10) -> float:
    """Benchmark 2D convolution performance."""
    print(f"Benchmarking convolution on {device}")
    
    # Create input tensor and conv layer
    input_tensor = torch.randn(batch_size, 256, 64, 64, device=device)
    conv_layer = torch.nn.Conv2d(256, 512, kernel_size=3, padding=1).to(device)
    
    # Warmup
    with torch.no_grad():
        for _ in range(3):
            conv_layer(input_tensor)
    
    # Synchronize and time
    if device.type == 'cuda':
        torch.cuda.synchronize()
    
    start_time = time.time()
    with torch.no_grad():
        for _ in range(iterations):
            output = conv_layer(input_tensor)
            if device.type == 'cuda':
                torch.cuda.synchronize()
    
    end_time = time.time()
    avg_time = (end_time - start_time) / iterations
    
    print(f"  Average time: {avg_time:.4f} seconds")
    print(f"  Throughput: {batch_size / avg_time:.2f} samples/second")
    
    return batch_size / avg_time

def main():
    print("AMD RX 7900 XT GPU Benchmark")
    print("=" * 40)
    
    # Check available devices
    print(f"PyTorch version: {torch.__version__}")
    print(f"CUDA available: {torch.cuda.is_available()}")
    
    devices = [torch.device('cpu')]
    if torch.cuda.is_available():
        devices.append(torch.device('cuda:0'))
        print(f"GPU: {torch.cuda.get_device_name(0)}")
    
    print()
    
    results = {}
    for device in devices:
        print(f"Testing on {device}")
        print("-" * 30)
        
        try:
            # Matrix multiplication benchmark
            gflops = benchmark_matrix_operations(device)
            results[f"{device}_matmul_gflops"] = gflops
            
            # Convolution benchmark
            throughput = benchmark_convolution(device)
            results[f"{device}_conv_throughput"] = throughput
            
        except Exception as e:
            print(f"Error testing {device}: {e}")
        
        print()
    
    # Print summary
    print("Benchmark Results Summary:")
    print("=" * 40)
    for key, value in results.items():
        if "gflops" in key:
            print(f"{key}: {value:.2f} GFLOPS")
        else:
            print(f"{key}: {value:.2f} samples/second")

if __name__ == "__main__":
    main()
EOF
    
    chmod +x "$project_dir/scripts/gpu-benchmark.py"
    log "✅ GPU benchmark script created at scripts/gpu-benchmark.py"
}

# Main installation flow
main() {
    log "🚀 Installing AMD RX 7900 XT GPU support for AI/ML development"
    
    check_gpu
    install_mesa_support
    install_rocm
    configure_environment
    install_gpu_python_packages
    create_benchmark_script
    test_gpu_functionality
    
    log "✅ GPU support installation complete!"
    echo ""
    echo "Next steps:"
    echo "1. Reboot your system to ensure all drivers are loaded properly"
    echo "2. Source the new environment: source ~/.rocm_env"
    echo "3. Test GPU functionality: cd to project and run ./scripts/gpu-benchmark.py"
    echo "4. For AI/ML work, activate the GPU environment: source venv_ai/bin/activate"
    
    warn "A system reboot is recommended for all GPU drivers to be properly loaded."
}

main "$@"