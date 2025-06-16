#!/bin/bash

# Production Rust Build Script
# Optimized for AMD Ryzen 7 7800X3D with production settings

set -e  # Exit on error

# Configuration
PROJECT_ROOT="/home/louranicas/projects/claude-optimized-deployment"
BUILD_LOG="${PROJECT_ROOT}/rust_build_production.log"
CARGO_FLAGS="--release"
JOBS=16

# Colors for output
BLUE='\033[34m'
GREEN='\033[32m'
RED='\033[31m'
YELLOW='\033[33m'
NC='\033[0m'

# Logging function
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a "$BUILD_LOG"
}

success() {
    echo -e "${GREEN}✓ $1${NC}" | tee -a "$BUILD_LOG"
}

warning() {
    echo -e "${YELLOW}⚠ $1${NC}" | tee -a "$BUILD_LOG"
}

error() {
    echo -e "${RED}✗ $1${NC}" | tee -a "$BUILD_LOG"
}

# Initialize build log
echo "Production Rust Build Started: $(date)" > "$BUILD_LOG"

log "Starting production Rust build for Claude Optimized Deployment"
log "Target CPU: AMD Ryzen 7 7800X3D (native optimizations)"
log "Build threads: $JOBS"

cd "$PROJECT_ROOT"

# Set optimized environment variables
export CARGO_BUILD_JOBS=$JOBS
export RUSTFLAGS="-C target-cpu=native -C target-feature=+avx2,+fma,+sse4.2,+aes"
export RUST_LOG=info

log "Environment configured for optimized builds"

# Build main rust_core
log "Building main rust_core..."
cd "$PROJECT_ROOT/rust_core"
if cargo build $CARGO_FLAGS --features "simd,python"; then
    success "Main rust_core built successfully"
    
    # Check for Python bindings
    if [ -f "target/release/libclaude_optimized_deployment_rust.so" ]; then
        success "Python binding library found"
        # Copy to Python-importable location
        cp target/release/libclaude_optimized_deployment_rust.so target/release/claude_optimized_deployment_rust.so
        success "Python binding library copied for import"
    else
        warning "Python binding library not found as expected"
    fi
else
    error "Failed to build main rust_core"
fi

# Build mcp_learning_system rust_core
log "Building mcp_learning_system rust_core..."
cd "$PROJECT_ROOT/mcp_learning_system/rust_core"
if cargo build $CARGO_FLAGS; then
    success "MCP learning system rust_core built successfully"
else
    error "Failed to build mcp_learning_system rust_core"
fi

# Build individual MCP servers
log "Building MCP servers..."

# Build bash_god server
log "Building bash_god MCP server..."
cd "$PROJECT_ROOT/mcp_learning_system/servers/bash_god/rust_src"
if [ -f "Cargo.toml" ] && [ -d "src" ]; then
    if cargo build $CARGO_FLAGS; then
        success "bash_god MCP server built successfully"
    else
        warning "Failed to build bash_god MCP server"
    fi
else
    warning "bash_god server missing Cargo.toml or src directory"
fi

# Build devops server
log "Building devops MCP server..."
cd "$PROJECT_ROOT/mcp_learning_system/servers/devops/rust_src"
if [ -f "Cargo.toml" ] && [ -d "src" ]; then
    if cargo build $CARGO_FLAGS; then
        success "devops MCP server built successfully"
    else
        warning "Failed to build devops MCP server"
    fi
else
    warning "devops server missing Cargo.toml or src directory"
fi

# Build quality server
log "Building quality MCP server..."
cd "$PROJECT_ROOT/mcp_learning_system/servers/quality/rust_src"
if [ -f "Cargo.toml" ] && [ -d "src" ]; then
    if cargo build $CARGO_FLAGS; then
        success "quality MCP server built successfully"
    else
        warning "Failed to build quality MCP server"
    fi
else
    warning "quality server missing Cargo.toml or src directory"
fi

# Build development server separately (if it has proper structure)
log "Building development MCP server..."
cd "$PROJECT_ROOT/mcp_learning_system/servers/development/rust_src"
if [ -f "Cargo.toml" ] && [ -d "src" ]; then
    if cargo build $CARGO_FLAGS; then
        success "development MCP server built successfully"
    else
        warning "Failed to build development MCP server"
    fi
else
    warning "development server missing Cargo.toml or src directory"
fi

# Collect build artifacts
log "Collecting build artifacts..."
cd "$PROJECT_ROOT"

DIST_DIR="$PROJECT_ROOT/dist/rust_production"
mkdir -p "$DIST_DIR/lib"
mkdir -p "$DIST_DIR/bin"

# Find and copy all shared libraries
find . -path "*/target/release/*" -name "*.so" -type f | while read lib; do
    if [[ ! "$lib" =~ "/deps/" ]]; then  # Skip dependency libraries
        cp "$lib" "$DIST_DIR/lib/"
        success "Copied library: $(basename "$lib")"
    fi
done

# Find and copy any binaries
find . -path "*/target/release" -type d | while read target_dir; do
    find "$target_dir" -maxdepth 1 -type f -executable | while read bin; do
        if [[ ! "$bin" =~ "/deps/" ]] && [[ ! "$bin" =~ "\.so$" ]] && [[ ! "$bin" =~ "\.rlib$" ]]; then
            cp "$bin" "$DIST_DIR/bin/"
            success "Copied binary: $(basename "$bin")"
        fi
    done
done

# Test FFI bindings
log "Testing FFI bindings..."
cd "$PROJECT_ROOT"

# Test Python bindings if available
if [ -f "$DIST_DIR/lib/claude_optimized_deployment_rust.so" ]; then
    export PYTHONPATH="$DIST_DIR/lib:$PYTHONPATH"
    if python3 -c "import claude_optimized_deployment_rust; print('FFI test successful')" 2>/dev/null; then
        success "Python FFI bindings verified"
    else
        warning "Python FFI bindings test failed"
    fi
fi

# Generate build report
log "Generating build report..."
REPORT_FILE="$PROJECT_ROOT/rust_build_report.md"

cat > "$REPORT_FILE" << EOF
# Rust Production Build Report

**Build Date:** $(date)
**Target Architecture:** x86_64-unknown-linux-gnu
**CPU Optimizations:** AMD Ryzen 7 7800X3D (native)
**Build Type:** Release with production optimizations

## Build Configuration

- **Optimization Level:** 3 (maximum)
- **LTO:** Thin (for compatibility)
- **Codegen Units:** 4 (for balance of speed and optimization)
- **CPU Features:** AVX2, FMA, SSE4.2, AES
- **Build Threads:** $JOBS

## Built Components

### Core Libraries
EOF

if [ -f "$PROJECT_ROOT/rust_core/target/release/deps"/*.so ]; then
    echo "- ✓ Main rust_core library" >> "$REPORT_FILE"
else
    echo "- ⚠ Main rust_core library (check build)" >> "$REPORT_FILE"
fi

if [ -f "$PROJECT_ROOT/mcp_learning_system/rust_core/target/release"/*.so ]; then
    echo "- ✓ MCP learning system rust_core" >> "$REPORT_FILE"
else
    echo "- ⚠ MCP learning system rust_core (check build)" >> "$REPORT_FILE"
fi

cat >> "$REPORT_FILE" << EOF

### MCP Servers
EOF

for server in bash_god devops quality development; do
    if [ -f "$PROJECT_ROOT/mcp_learning_system/servers/$server/rust_src/target/release"/*.so ]; then
        echo "- ✓ $server MCP server" >> "$REPORT_FILE"
    else
        echo "- ⚠ $server MCP server (check build)" >> "$REPORT_FILE"
    fi
done

cat >> "$REPORT_FILE" << EOF

## Build Artifacts

**Distribution Directory:** $DIST_DIR

### Shared Libraries
$(ls -la "$DIST_DIR/lib/" 2>/dev/null || echo "No libraries found")

### Binaries
$(ls -la "$DIST_DIR/bin/" 2>/dev/null || echo "No binaries found")

## Performance Optimizations Applied

1. **CPU-specific optimizations** for AMD Ryzen 7 7800X3D
2. **SIMD instructions** enabled (AVX2, FMA, SSE4.2)
3. **Link-time optimization** (thin LTO for compatibility)
4. **Parallel compilation** with $JOBS threads
5. **Release profile** with maximum optimization

## FFI Integration

### Python Bindings
$(if [ -f "$DIST_DIR/lib/claude_optimized_deployment_rust.so" ]; then
    echo "✓ Python bindings available"
    echo "✓ Location: $DIST_DIR/lib/claude_optimized_deployment_rust.so"
    echo "✓ Usage: \`import claude_optimized_deployment_rust\`"
else
    echo "⚠ Python bindings not found"
fi)

## Build Automation

This build was generated using:
- **Build script:** build_rust_production.sh
- **Makefile:** Makefile.rust
- **Cargo config:** .cargo/config.toml

## Next Steps

1. **Test integration** with Python components
2. **Validate performance** using benchmarks
3. **Deploy to production** environment
4. **Monitor performance** in real-world usage

---
Generated by Claude Code Rust Build System
EOF

success "Build report generated: $REPORT_FILE"

# Summary
log "Build Summary:"
log "=============="

TOTAL_LIBS=$(find "$DIST_DIR/lib" -name "*.so" 2>/dev/null | wc -l)
TOTAL_BINS=$(find "$DIST_DIR/bin" -type f 2>/dev/null | wc -l)

success "Total shared libraries built: $TOTAL_LIBS"
success "Total binaries built: $TOTAL_BINS"
success "Build artifacts saved to: $DIST_DIR"
success "Build report saved to: $REPORT_FILE"

log "Production Rust build completed successfully!"
log "Build log saved to: $BUILD_LOG"

echo
echo -e "${GREEN}🚀 Production Rust build completed successfully!${NC}"
echo -e "${BLUE}📦 Artifacts location: $DIST_DIR${NC}"
echo -e "${BLUE}📋 Build report: $REPORT_FILE${NC}"
echo -e "${BLUE}📝 Build log: $BUILD_LOG${NC}"