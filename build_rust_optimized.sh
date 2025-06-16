#!/bin/bash

set -euo pipefail

# Rust Build Optimization Script for Ryzen 7 7800X3D
# Builds all MCP Rust servers with maximum optimization

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

PROJECT_ROOT="/home/louranicas/projects/claude-optimized-deployment"
BUILD_LOG="$PROJECT_ROOT/rust_build_optimized.log"

# Initialize build log
echo "Rust Build Optimization Log - $(date)" > "$BUILD_LOG"
echo "===============================================" >> "$BUILD_LOG"

log_info "Starting optimized Rust build for MCP servers..."
log_info "Build log: $BUILD_LOG"

# Check system configuration
log_info "Checking system configuration..."
echo "System Information:" >> "$BUILD_LOG"
echo "CPU: $(lscpu | grep 'Model name' | cut -d ':' -f2 | xargs)" >> "$BUILD_LOG"
echo "Cores: $(nproc)" >> "$BUILD_LOG"
echo "Memory: $(free -h | awk '/^Mem:/ {print $2}')" >> "$BUILD_LOG"
echo "Rust version: $(rustc --version)" >> "$BUILD_LOG"
echo "Cargo version: $(cargo --version)" >> "$BUILD_LOG"
echo "" >> "$BUILD_LOG"

# Check for required tools
log_info "Checking build tools..."
if ! command -v clang &> /dev/null; then
    log_warning "clang not found, using gcc as fallback linker"
fi

if ! command -v lld &> /dev/null; then
    log_warning "lld not found, using default linker"
fi

# Set environment variables for optimal builds
export RUSTFLAGS="-C target-cpu=znver4 -C target-feature=+avx2,+fma,+bmi2,+lzcnt,+popcnt"
export CARGO_BUILD_JOBS=16
export CARGO_PROFILE_RELEASE_LTO=fat
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1

log_info "Environment variables set for Ryzen 7 7800X3D optimization"
echo "Build Environment:" >> "$BUILD_LOG"
echo "RUSTFLAGS: $RUSTFLAGS" >> "$BUILD_LOG"
echo "CARGO_BUILD_JOBS: $CARGO_BUILD_JOBS" >> "$BUILD_LOG"
echo "" >> "$BUILD_LOG"

# Function to build a Rust project
build_rust_project() {
    local project_path="$1"
    local project_name="$2"
    
    log_info "Building $project_name..."
    echo "Building $project_name at $(date)" >> "$BUILD_LOG"
    
    if [ ! -f "$project_path/Cargo.toml" ]; then
        log_error "Cargo.toml not found in $project_path"
        echo "ERROR: Cargo.toml not found in $project_path" >> "$BUILD_LOG"
        return 1
    fi
    
    cd "$project_path"
    
    # Clean previous builds
    log_info "Cleaning previous builds for $project_name..."
    cargo clean >> "$BUILD_LOG" 2>&1
    
    # Update dependencies
    log_info "Updating dependencies for $project_name..."
    cargo update >> "$BUILD_LOG" 2>&1
    
    # Check for security vulnerabilities
    if command -v cargo-audit &> /dev/null; then
        log_info "Running security audit for $project_name..."
        cargo audit >> "$BUILD_LOG" 2>&1 || log_warning "Security audit found issues for $project_name"
    fi
    
    # Build with release profile
    log_info "Building release version of $project_name..."
    if cargo build --release --verbose >> "$BUILD_LOG" 2>&1; then
        log_success "Successfully built $project_name"
        
        # Check binary size and features
        if [ -d "target/release" ]; then
            log_info "Build artifacts for $project_name:"
            ls -la target/release/*.so 2>/dev/null || true
            ls -la target/release/*.rlib 2>/dev/null || true
            ls -la target/release/deps/ 2>/dev/null | head -5 || true
        fi
        
        return 0
    else
        log_error "Failed to build $project_name"
        echo "ERROR: Build failed for $project_name" >> "$BUILD_LOG"
        return 1
    fi
}

# Build order - dependencies first
declare -A RUST_PROJECTS=(
    ["$PROJECT_ROOT/mcp_learning_system/rust_core"]="MCP Rust Core"
    ["$PROJECT_ROOT/mcp_learning_system/servers/bash_god/rust_src"]="Bash God MCP Server"
    ["$PROJECT_ROOT/mcp_learning_system/servers/development/rust_src"]="Development MCP Server"
    ["$PROJECT_ROOT/mcp_learning_system/servers/devops/rust_src"]="DevOps MCP Server"
    ["$PROJECT_ROOT/mcp_learning_system/servers/quality/rust_src"]="Quality MCP Server"
)

BUILD_SUCCESS=0
BUILD_TOTAL=0

log_info "Starting build process for ${#RUST_PROJECTS[@]} Rust projects..."

for project_path in "${!RUST_PROJECTS[@]}"; do
    project_name="${RUST_PROJECTS[$project_path]}"
    BUILD_TOTAL=$((BUILD_TOTAL + 1))
    
    if build_rust_project "$project_path" "$project_name"; then
        BUILD_SUCCESS=$((BUILD_SUCCESS + 1))
    fi
    
    echo "" >> "$BUILD_LOG"
done

# Build summary
echo "Build Summary:" >> "$BUILD_LOG"
echo "Successful builds: $BUILD_SUCCESS/$BUILD_TOTAL" >> "$BUILD_LOG"
echo "Build completed at: $(date)" >> "$BUILD_LOG"

log_info "Build Summary:"
log_info "Successful builds: $BUILD_SUCCESS/$BUILD_TOTAL"

if [ $BUILD_SUCCESS -eq $BUILD_TOTAL ]; then
    log_success "All Rust projects built successfully!"
    
    # Verify FFI bindings
    log_info "Verifying FFI bindings and shared libraries..."
    echo "FFI Verification:" >> "$BUILD_LOG"
    
    for project_path in "${!RUST_PROJECTS[@]}"; do
        if [ -d "$project_path/target/release" ]; then
            so_files=$(find "$project_path/target/release" -name "*.so" 2>/dev/null || true)
            if [ -n "$so_files" ]; then
                echo "Found shared libraries in $project_path:" >> "$BUILD_LOG"
                echo "$so_files" >> "$BUILD_LOG"
                
                # Check symbols in shared libraries
                for so_file in $so_files; do
                    if command -v nm &> /dev/null; then
                        log_info "Checking symbols in $(basename $so_file)..."
                        nm -D "$so_file" 2>/dev/null | grep -E "(PyInit_|_Py)" | head -5 >> "$BUILD_LOG" || true
                    fi
                done
            fi
        fi
    done
    
    exit 0
else
    log_error "Some builds failed. Check $BUILD_LOG for details."
    exit 1
fi