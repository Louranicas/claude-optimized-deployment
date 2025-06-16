#!/bin/bash

set -euo pipefail

# Rust Workspace Build Script for Ryzen 7 7800X3D
# Builds all MCP Rust servers from workspace root

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
BUILD_LOG="$PROJECT_ROOT/rust_workspace_build.log"

# Change to project root
cd "$PROJECT_ROOT"

# Initialize build log
echo "Rust Workspace Build Log - $(date)" > "$BUILD_LOG"
echo "===============================================" >> "$BUILD_LOG"

log_info "Starting Rust workspace build..."
log_info "Build log: $BUILD_LOG"

# System info
log_info "System Information:"
echo "CPU: $(lscpu | grep 'Model name' | cut -d ':' -f2 | xargs)" | tee -a "$BUILD_LOG"
echo "Cores: $(nproc)" | tee -a "$BUILD_LOG"
echo "Memory: $(free -h | awk '/^Mem:/ {print $2}')" | tee -a "$BUILD_LOG"
echo "Rust version: $(rustc --version)" | tee -a "$BUILD_LOG"
echo "Cargo version: $(cargo --version)" | tee -a "$BUILD_LOG"
echo "" >> "$BUILD_LOG"

# Set environment variables for optimal builds
export RUSTFLAGS="-C target-cpu=znver4 -C target-feature=+avx2,+fma,+bmi2,+lzcnt,+popcnt"
export CARGO_BUILD_JOBS=16

log_info "Environment variables set for Ryzen 7 7800X3D optimization"
echo "RUSTFLAGS: $RUSTFLAGS" | tee -a "$BUILD_LOG"
echo "CARGO_BUILD_JOBS: $CARGO_BUILD_JOBS" | tee -a "$BUILD_LOG"
echo "" >> "$BUILD_LOG"

# Clean previous builds
log_info "Cleaning previous builds..."
cargo clean >> "$BUILD_LOG" 2>&1

# Update dependencies  
log_info "Updating dependencies..."
if cargo update >> "$BUILD_LOG" 2>&1; then
    log_success "Dependencies updated successfully"
else
    log_warning "Some dependency updates failed, continuing..."
fi

# Check workspace structure
log_info "Checking workspace structure..."
cargo metadata --format-version 1 | jq '.workspace_members' >> "$BUILD_LOG" 2>&1 || echo "jq not available" >> "$BUILD_LOG"

# Build all workspace members
log_info "Building all workspace members in release mode..."
echo "Starting workspace build at $(date)" >> "$BUILD_LOG"

if cargo build --release --workspace >> "$BUILD_LOG" 2>&1; then
    log_success "Workspace build completed successfully!"
    
    # List build artifacts
    log_info "Build artifacts created:"
    echo "Build artifacts:" >> "$BUILD_LOG"
    find target/release -name "*.so" -o -name "*.rlib" -o -name "*.a" 2>/dev/null | while read -r file; do
        size=$(du -h "$file" | cut -f1)
        echo "  $file ($size)" | tee -a "$BUILD_LOG"
    done
    
    # Verify FFI bindings
    log_info "Verifying FFI bindings..."
    echo "FFI bindings verification:" >> "$BUILD_LOG"
    for so_file in $(find target/release -name "*.so" 2>/dev/null); do
        if command -v nm &> /dev/null; then
            log_info "Checking symbols in $(basename "$so_file")..."
            echo "Symbols in $so_file:" >> "$BUILD_LOG"
            nm -D "$so_file" 2>/dev/null | grep -E "(PyInit_|_Py)" | head -10 >> "$BUILD_LOG" || echo "No Python symbols found" >> "$BUILD_LOG"
        fi
    done
    
    # Test that libraries can be loaded
    log_info "Testing library loading..."
    echo "Library loading test:" >> "$BUILD_LOG"
    for so_file in $(find target/release -name "*.so" 2>/dev/null); do
        if ldd "$so_file" &>/dev/null; then
            echo "✓ $so_file - OK" | tee -a "$BUILD_LOG"
        else
            echo "✗ $so_file - FAILED" | tee -a "$BUILD_LOG"
        fi
    done
    
    echo "Build completed successfully at $(date)" >> "$BUILD_LOG"
    exit 0
else
    log_error "Workspace build failed!"
    echo "Build failed at $(date)" >> "$BUILD_LOG"
    
    # Show last 50 lines of errors
    log_error "Last 50 lines of build output:"
    tail -50 "$BUILD_LOG" | grep -E "(error|ERROR)" || echo "No specific errors found in tail"
    
    exit 1
fi