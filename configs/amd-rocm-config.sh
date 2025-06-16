#!/bin/bash
# ROCm and GPU Acceleration Configuration for RX 7900 XT
# Advanced GPU compute setup for development workloads

# ROCm environment configuration
export ROCM_PATH=/opt/rocm
export HIP_PATH=$ROCM_PATH
export ROCM_VERSION=$(cat $ROCM_PATH/.info/version)

# GPU device configuration
export HIP_VISIBLE_DEVICES=0
export HSA_ENABLE_SDMA=0
export HSA_FORCE_FINE_GRAIN_PCIE=1
export HSA_ENABLE_INTERRUPT=0

# Memory and performance optimizations
export HIP_COHERENT_HOST_ALLOC=1
export HIP_HOST_COHERENT=1
export HSA_XNACK=0
export GPU_MAX_HEAP_SIZE="90%"
export GPU_MAX_ALLOC_PERCENT=90

# OpenCL configuration
export OPENCL_VENDOR_PATH=/opt/rocm/opencl/vendors

# Compiler flags for GPU-accelerated applications
export HIP_CLANG_PATH=$ROCM_PATH/llvm/bin
export HIP_COMPILER=clang
export HIP_RUNTIME=rocclr
export HIP_PLATFORM=amd

# Development-specific optimizations
export ROCBLAS_LAYER=1
export MIOPEN_LOG_LEVEL=3
export ROCFFT_LOG_TRACE_PATH=/tmp/rocfft-trace.txt

# Function to verify ROCm installation
verify_rocm() {
    echo "=== ROCm Installation Verification ==="
    echo "ROCm version: $(cat $ROCM_PATH/.info/version 2>/dev/null || echo 'Not found')"
    echo
    echo "Available GPUs:"
    rocminfo | grep -A 5 "Agent.*GPU" || echo "No GPUs detected"
    echo
    echo "ROCm SMI status:"
    rocm-smi --showid --showtemp --showpower || echo "rocm-smi not available"
    echo
    echo "HIP devices:"
    $ROCM_PATH/bin/hipconfig --full || echo "HIP not configured"
}

# Function to run GPU compute tests
test_gpu_compute() {
    echo "=== GPU Compute Test ==="
    
    # Test ROCm bandwidth
    if command -v rocm-bandwidth-test &> /dev/null; then
        echo "Running memory bandwidth test..."
        rocm-bandwidth-test | tail -10
    fi
    
    # Test OpenCL
    if command -v clinfo &> /dev/null; then
        echo "OpenCL platforms:"
        clinfo --list
    fi
    
    # Test HIP compilation
    echo "Testing HIP compilation..."
    cat > /tmp/hip_test.cpp << 'EOF'
#include <hip/hip_runtime.h>
#include <iostream>

__global__ void vectorAdd(float* a, float* b, float* c, int n) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < n) {
        c[idx] = a[idx] + b[idx];
    }
}

int main() {
    const int n = 1000000;
    const size_t size = n * sizeof(float);
    
    float *h_a, *h_b, *h_c;
    float *d_a, *d_b, *d_c;
    
    // Allocate host memory
    h_a = (float*)malloc(size);
    h_b = (float*)malloc(size);
    h_c = (float*)malloc(size);
    
    // Initialize host arrays
    for(int i = 0; i < n; i++) {
        h_a[i] = float(i);
        h_b[i] = float(i * 2);
    }
    
    // Allocate device memory
    hipMalloc((void**)&d_a, size);
    hipMalloc((void**)&d_b, size);
    hipMalloc((void**)&d_c, size);
    
    // Copy host memory to device
    hipMemcpy(d_a, h_a, size, hipMemcpyHostToDevice);
    hipMemcpy(d_b, h_b, size, hipMemcpyHostToDevice);
    
    // Launch kernel
    int threadsPerBlock = 256;
    int blocksPerGrid = (n + threadsPerBlock - 1) / threadsPerBlock;
    hipLaunchKernelGGL(vectorAdd, dim3(blocksPerGrid), dim3(threadsPerBlock), 0, 0, d_a, d_b, d_c, n);
    
    // Copy result back to host
    hipMemcpy(h_c, d_c, size, hipMemcpyDeviceToHost);
    
    // Verify result
    bool success = true;
    for(int i = 0; i < 10; i++) {
        if(abs(h_c[i] - (h_a[i] + h_b[i])) > 1e-5) {
            success = false;
            break;
        }
    }
    
    std::cout << "HIP test " << (success ? "PASSED" : "FAILED") << std::endl;
    
    // Cleanup
    free(h_a); free(h_b); free(h_c);
    hipFree(d_a); hipFree(d_b); hipFree(d_c);
    
    return success ? 0 : 1;
}
EOF

    if command -v hipcc &> /dev/null; then
        cd /tmp
        hipcc -o hip_test hip_test.cpp
        ./hip_test
        rm -f hip_test hip_test.cpp
    else
        echo "HIP compiler not available"
    fi
}

# Function to optimize GPU for development workloads
optimize_gpu_development() {
    echo "=== Optimizing GPU for Development ==="
    
    # Set GPU power profile to high performance
    sudo sh -c 'echo high > /sys/class/drm/card0/device/power_dpm_force_performance_level'
    
    # Increase GPU memory clock
    sudo sh -c 'echo 1 > /sys/class/drm/card0/device/pp_mclk_od'
    
    # Set maximum fan speed for sustained workloads
    sudo sh -c 'echo 1 > /sys/class/drm/card0/device/hwmon/hwmon*/pwm1_enable'
    sudo sh -c 'echo 200 > /sys/class/drm/card0/device/hwmon/hwmon*/pwm1'
    
    echo "GPU optimized for development workloads"
}

# Function to monitor GPU utilization
monitor_gpu() {
    echo "=== GPU Monitoring Dashboard ==="
    watch -n 1 'rocm-smi --showid --showtemp --showpower --showmeminfo vram --showuse'
}

# Function to reset GPU to default settings
reset_gpu() {
    echo "=== Resetting GPU to Default Settings ==="
    sudo sh -c 'echo auto > /sys/class/drm/card0/device/power_dpm_force_performance_level'
    sudo sh -c 'echo 2 > /sys/class/drm/card0/device/hwmon/hwmon*/pwm1_enable'
    echo "GPU reset to default settings"
}

# Function to setup development workspaces with GPU acceleration
setup_gpu_workspace() {
    workspace_name=${1:-"gpu-dev"}
    workspace_dir="$HOME/gpu-workspaces/$workspace_name"
    
    echo "Creating GPU development workspace: $workspace_name"
    mkdir -p "$workspace_dir"
    cd "$workspace_dir"
    
    # Create example Rust project with GPU acceleration
    if command -v cargo &> /dev/null; then
        echo "Setting up Rust GPU project..."
        cargo init --name gpu-rust-example
        cd gpu-rust-example
        
        # Add GPU dependencies to Cargo.toml
        cat >> Cargo.toml << 'EOF'

[dependencies]
ocl = "0.19"
candle-core = { version = "0.3", features = ["cuda"] }
tch = { version = "0.8", features = ["download-libtorch"] }
EOF
        
        # Create example GPU-accelerated code
        cat > src/main.rs << 'EOF'
use ocl::{Platform, Device, Context, Queue, Buffer, Kernel, Program};

fn main() -> ocl::Result<()> {
    // List available OpenCL platforms and devices
    println!("Available OpenCL platforms:");
    for platform in Platform::list() {
        println!("  Platform: {}", platform.name()?);
        for device in Device::list_all(&platform)? {
            println!("    Device: {}", device.name()?);
            println!("      Type: {:?}", device.device_type()?);
            println!("      Memory: {} MB", device.mem_size()? / (1024 * 1024));
        }
    }
    
    // Simple vector addition example
    let platform = Platform::default();
    let device = Device::first(platform)?;
    let context = Context::builder().platform(platform).devices(device).build()?;
    let queue = Queue::new(&context, device, None)?;
    
    let dims = 100_000;
    let src = r#"
        __kernel void add(__global float* a, __global float* b, __global float* c) {
            int gid = get_global_id(0);
            c[gid] = a[gid] + b[gid];
        }
    "#;
    
    let program = Program::builder()
        .devices(device)
        .src(src)
        .build(&context)?;
    
    let kernel = Kernel::builder()
        .program(&program)
        .name("add")
        .global_work_size(dims)
        .build()?;
    
    let a = vec![1.0f32; dims];
    let b = vec![2.0f32; dims];
    let mut c = vec![0.0f32; dims];
    
    let a_buffer = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_READ_ONLY)
        .len(dims)
        .copy_host_slice(&a)
        .build()?;
    
    let b_buffer = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_READ_ONLY)
        .len(dims)
        .copy_host_slice(&b)
        .build()?;
    
    let c_buffer = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_WRITE_ONLY)
        .len(dims)
        .build()?;
    
    unsafe {
        kernel.set_arg("a", &a_buffer)?;
        kernel.set_arg("b", &b_buffer)?;
        kernel.set_arg("c", &c_buffer)?;
        kernel.enq()?;
    }
    
    c_buffer.read(&mut c).enq()?;
    
    println!("GPU computation completed successfully!");
    println!("First 10 results: {:?}", &c[0..10]);
    
    Ok(())
}
EOF
        
        echo "GPU Rust example created at $workspace_dir/gpu-rust-example"
        cd ..
    fi
    
    echo "GPU workspace setup complete at: $workspace_dir"
}

# Export functions for use in other scripts
export -f verify_rocm
export -f test_gpu_compute
export -f optimize_gpu_development
export -f monitor_gpu
export -f reset_gpu
export -f setup_gpu_workspace

echo "ROCm configuration loaded. Available functions:"
echo "  verify_rocm          - Verify ROCm installation"
echo "  test_gpu_compute     - Run GPU compute tests"
echo "  optimize_gpu_development - Optimize GPU for development"
echo "  monitor_gpu          - Start GPU monitoring"
echo "  reset_gpu           - Reset GPU to defaults"
echo "  setup_gpu_workspace  - Create GPU development workspace"