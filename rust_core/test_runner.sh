#!/bin/bash
# Comprehensive test runner for MCP Manager
# Follows patterns from "Zero to Production in Rust"

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test categories
TEST_UNIT=false
TEST_INTEGRATION=false
TEST_PROPERTY=false
TEST_BENCH=false
TEST_COVERAGE=false
TEST_ALL=false
QUICK_MODE=false
RELEASE_MODE=false

# Default values
THREADS=4
PROPTEST_CASES=256
TIMEOUT=300

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --unit)
            TEST_UNIT=true
            shift
            ;;
        --integration)
            TEST_INTEGRATION=true
            shift
            ;;
        --property)
            TEST_PROPERTY=true
            shift
            ;;
        --bench)
            TEST_BENCH=true
            shift
            ;;
        --coverage)
            TEST_COVERAGE=true
            shift
            ;;
        --all)
            TEST_ALL=true
            shift
            ;;
        --quick)
            QUICK_MODE=true
            PROPTEST_CASES=32
            TIMEOUT=60
            shift
            ;;
        --release)
            RELEASE_MODE=true
            shift
            ;;
        --threads)
            THREADS="$2"
            shift 2
            ;;
        --proptest-cases)
            PROPTEST_CASES="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--unit] [--integration] [--property] [--bench] [--coverage] [--all] [--quick] [--release] [--threads N] [--proptest-cases N]"
            exit 1
            ;;
    esac
done

# If no specific test selected, run all
if [[ "$TEST_UNIT" == false && "$TEST_INTEGRATION" == false && "$TEST_PROPERTY" == false && "$TEST_BENCH" == false && "$TEST_COVERAGE" == false ]]; then
    TEST_ALL=true
fi

# Build flags
BUILD_FLAGS=""
if [[ "$RELEASE_MODE" == true ]]; then
    BUILD_FLAGS="--release"
fi

echo -e "${BLUE}MCP Manager Test Runner${NC}"
echo -e "${BLUE}========================${NC}"
echo "Configuration:"
echo "  Threads: $THREADS"
echo "  Proptest cases: $PROPTEST_CASES"
echo "  Timeout: ${TIMEOUT}s"
echo "  Mode: $([ "$RELEASE_MODE" == true ] && echo "Release" || echo "Debug")"
echo ""

# Function to run a test category
run_test_category() {
    local category=$1
    local command=$2
    local start_time=$(date +%s)
    
    echo -e "${YELLOW}Running $category tests...${NC}"
    
    if eval "$command"; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        echo -e "${GREEN}✓ $category tests passed (${duration}s)${NC}"
        return 0
    else
        echo -e "${RED}✗ $category tests failed${NC}"
        return 1
    fi
}

# Track overall success
OVERALL_SUCCESS=true

# Unit tests
if [[ "$TEST_ALL" == true || "$TEST_UNIT" == true ]]; then
    if ! run_test_category "Unit" "cargo test --lib $BUILD_FLAGS -- --test-threads=$THREADS"; then
        OVERALL_SUCCESS=false
    fi
fi

# Integration tests
if [[ "$TEST_ALL" == true || "$TEST_INTEGRATION" == true ]]; then
    if ! run_test_category "Integration" "cargo test --test '*' $BUILD_FLAGS -- --test-threads=$THREADS"; then
        OVERALL_SUCCESS=false
    fi
fi

# Property tests
if [[ "$TEST_ALL" == true || "$TEST_PROPERTY" == true ]]; then
    export PROPTEST_CASES=$PROPTEST_CASES
    if ! run_test_category "Property" "cargo test property $BUILD_FLAGS -- --test-threads=1"; then
        OVERALL_SUCCESS=false
    fi
fi

# Thread safety tests (always run single-threaded)
if [[ "$TEST_ALL" == true ]]; then
    if ! run_test_category "Thread Safety" "cargo test thread_safety $BUILD_FLAGS -- --test-threads=1"; then
        OVERALL_SUCCESS=false
    fi
fi

# Error handling tests
if [[ "$TEST_ALL" == true ]]; then
    if ! run_test_category "Error Handling" "cargo test error_handling $BUILD_FLAGS -- --test-threads=$THREADS"; then
        OVERALL_SUCCESS=false
    fi
fi

# PyO3 binding tests
if [[ "$TEST_ALL" == true ]]; then
    if ! run_test_category "PyO3 Bindings" "cargo test pyo3 $BUILD_FLAGS -- --test-threads=$THREADS"; then
        OVERALL_SUCCESS=false
    fi
fi

# Benchmarks
if [[ "$TEST_BENCH" == true ]]; then
    echo -e "${YELLOW}Running benchmarks...${NC}"
    
    if [[ "$QUICK_MODE" == true ]]; then
        # Quick benchmark run
        cargo bench --no-run
        echo -e "${GREEN}✓ Benchmarks compiled successfully${NC}"
    else
        # Full benchmark run
        if cargo bench; then
            echo -e "${GREEN}✓ Benchmarks completed${NC}"
            
            # Generate comparison if baseline exists
            if [[ -d "target/criterion" ]]; then
                echo -e "${BLUE}Benchmark results saved to target/criterion/${NC}"
            fi
        else
            echo -e "${RED}✗ Benchmarks failed${NC}"
            OVERALL_SUCCESS=false
        fi
    fi
fi

# Coverage
if [[ "$TEST_COVERAGE" == true ]]; then
    echo -e "${YELLOW}Generating coverage report...${NC}"
    
    # Check if tarpaulin is installed
    if ! command -v cargo-tarpaulin &> /dev/null; then
        echo "Installing cargo-tarpaulin..."
        cargo install cargo-tarpaulin
    fi
    
    # Run coverage
    if cargo tarpaulin --all-features --timeout $TIMEOUT --out Html --output-dir target/coverage; then
        echo -e "${GREEN}✓ Coverage report generated${NC}"
        echo -e "${BLUE}Report available at: target/coverage/tarpaulin-report.html${NC}"
        
        # Display coverage summary
        cargo tarpaulin --all-features --timeout $TIMEOUT --print-summary
    else
        echo -e "${RED}✗ Coverage generation failed${NC}"
        OVERALL_SUCCESS=false
    fi
fi

# Lint checks (always run in non-quick mode)
if [[ "$QUICK_MODE" == false && "$TEST_ALL" == true ]]; then
    echo -e "${YELLOW}Running lint checks...${NC}"
    
    if cargo clippy --all-features -- -D warnings; then
        echo -e "${GREEN}✓ Lint checks passed${NC}"
    else
        echo -e "${RED}✗ Lint checks failed${NC}"
        OVERALL_SUCCESS=false
    fi
fi

# Format check (always run in non-quick mode)
if [[ "$QUICK_MODE" == false && "$TEST_ALL" == true ]]; then
    echo -e "${YELLOW}Checking code formatting...${NC}"
    
    if cargo fmt -- --check; then
        echo -e "${GREEN}✓ Code formatting correct${NC}"
    else
        echo -e "${RED}✗ Code formatting issues found${NC}"
        echo "Run 'cargo fmt' to fix formatting"
        OVERALL_SUCCESS=false
    fi
fi

# Security audit (always run in non-quick mode)
if [[ "$QUICK_MODE" == false && "$TEST_ALL" == true ]]; then
    echo -e "${YELLOW}Running security audit...${NC}"
    
    # Check if cargo-audit is installed
    if command -v cargo-audit &> /dev/null; then
        if cargo audit; then
            echo -e "${GREEN}✓ Security audit passed${NC}"
        else
            echo -e "${RED}✗ Security vulnerabilities found${NC}"
            OVERALL_SUCCESS=false
        fi
    else
        echo -e "${YELLOW}Skipping security audit (cargo-audit not installed)${NC}"
    fi
fi

# Summary
echo ""
echo -e "${BLUE}Test Summary${NC}"
echo -e "${BLUE}============${NC}"

if [[ "$OVERALL_SUCCESS" == true ]]; then
    echo -e "${GREEN}All tests passed! 🎉${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Please check the output above.${NC}"
    exit 1
fi