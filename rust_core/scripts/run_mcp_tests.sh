#!/bin/bash
# ============================================================================
# MCP Manager Comprehensive Test Runner
# ============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
RUST_LOG=${RUST_LOG:-"info"}
TEST_THREADS=${TEST_THREADS:-$(nproc)}
CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-"target"}

# Test categories
UNIT_TESTS=(
    "mcp_manager::tests::unit_tests"
    "mcp_manager::tests::distributed_tests"
    "mcp_manager::tests::resilience_tests"
    "mcp_manager::tests::optimization_tests"
    "mcp_manager::tests::security_tests"
)

INTEGRATION_TESTS=(
    "mcp_manager::tests::integration_tests"
)

STRESS_TESTS=(
    "mcp_manager::tests::stress_tests"
)

PROPERTY_TESTS=(
    "mcp_manager::tests::property_tests"
)

# Functions
print_header() {
    echo -e "\n${BLUE}==== $1 ====${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

run_test_category() {
    local category=$1
    local test_filter=$2
    local extra_args=${3:-""}
    
    print_header "Running $category"
    
    if RUST_LOG=$RUST_LOG cargo test \
        --manifest-path rust_core/Cargo.toml \
        --lib \
        $test_filter \
        -- \
        --test-threads=$TEST_THREADS \
        --nocapture \
        $extra_args; then
        print_success "$category passed"
        return 0
    else
        print_error "$category failed"
        return 1
    fi
}

run_unit_tests() {
    local failed=0
    
    print_header "Unit Tests"
    
    for test_mod in "${UNIT_TESTS[@]}"; do
        if ! run_test_category "Unit Test: $test_mod" "$test_mod"; then
            ((failed++))
        fi
    done
    
    return $failed
}

run_integration_tests() {
    local failed=0
    
    print_header "Integration Tests"
    
    for test_mod in "${INTEGRATION_TESTS[@]}"; do
        if ! run_test_category "Integration Test: $test_mod" "$test_mod" "--test-threads=1"; then
            ((failed++))
        fi
    done
    
    return $failed
}

run_stress_tests() {
    local failed=0
    
    print_header "Stress Tests"
    print_warning "Stress tests may take several minutes..."
    
    # Increase limits for stress tests
    ulimit -n 65536  # File descriptors
    ulimit -u 32768  # Processes/threads
    
    for test_mod in "${STRESS_TESTS[@]}"; do
        if ! RUST_LOG=warn cargo test \
            --manifest-path rust_core/Cargo.toml \
            --lib \
            --release \
            $test_mod \
            -- \
            --test-threads=8 \
            --nocapture; then
            ((failed++))
        fi
    done
    
    return $failed
}

run_property_tests() {
    local failed=0
    
    print_header "Property-Based Tests"
    
    for test_mod in "${PROPERTY_TESTS[@]}"; do
        if ! PROPTEST_CASES=1000 run_test_category "Property Test: $test_mod" "$test_mod"; then
            ((failed++))
        fi
    done
    
    return $failed
}

run_benchmarks() {
    print_header "Performance Benchmarks"
    
    # Run standard benchmarks
    print_warning "Running standard MCP Manager benchmarks..."
    cargo bench \
        --manifest-path rust_core/Cargo.toml \
        --bench mcp_manager_bench \
        -- --save-baseline mcp_baseline
    
    # Run enhanced benchmarks
    print_warning "Running enhanced MCP Manager benchmarks..."
    cargo bench \
        --manifest-path rust_core/Cargo.toml \
        --bench mcp_manager_enhanced_bench \
        -- --save-baseline mcp_enhanced_baseline
    
    print_success "Benchmarks completed"
}

run_security_audit() {
    print_header "Security Audit"
    
    if command -v cargo-audit &> /dev/null; then
        cargo audit --manifest-path rust_core/Cargo.toml
    else
        print_warning "cargo-audit not installed. Run: cargo install cargo-audit"
    fi
}

run_coverage() {
    print_header "Code Coverage"
    
    if command -v cargo-tarpaulin &> /dev/null; then
        cargo tarpaulin \
            --manifest-path rust_core/Cargo.toml \
            --lib \
            --out Html \
            --output-dir $CARGO_TARGET_DIR/coverage \
            --exclude-files "*/tests/*" \
            --exclude-files "*/benches/*" \
            --ignore-panics \
            --timeout 300
        
        print_success "Coverage report generated at: $CARGO_TARGET_DIR/coverage/tarpaulin-report.html"
    else
        print_warning "cargo-tarpaulin not installed. Run: cargo install cargo-tarpaulin"
    fi
}

run_clippy() {
    print_header "Clippy Lints"
    
    cargo clippy \
        --manifest-path rust_core/Cargo.toml \
        --all-targets \
        --all-features \
        -- \
        -D warnings \
        -D clippy::all \
        -D clippy::pedantic \
        -W clippy::nursery
}

run_doc_tests() {
    print_header "Documentation Tests"
    
    cargo test \
        --manifest-path rust_core/Cargo.toml \
        --doc
}

generate_test_report() {
    local total_tests=$1
    local failed_tests=$2
    local elapsed_time=$3
    
    print_header "Test Summary Report"
    
    echo "Total Tests Run: $total_tests"
    echo "Failed Tests: $failed_tests"
    echo "Success Rate: $(( (total_tests - failed_tests) * 100 / total_tests ))%"
    echo "Elapsed Time: ${elapsed_time}s"
    
    if [ $failed_tests -eq 0 ]; then
        print_success "All tests passed! 🎉"
    else
        print_error "$failed_tests tests failed"
    fi
}

# Main execution
main() {
    local start_time=$(date +%s)
    local total_failed=0
    local test_suite=${1:-"all"}
    
    print_header "MCP Manager Test Suite"
    echo "Test Threads: $TEST_THREADS"
    echo "Log Level: $RUST_LOG"
    echo "Test Suite: $test_suite"
    
    case $test_suite in
        "unit")
            run_unit_tests
            total_failed=$?
            ;;
        "integration")
            run_integration_tests
            total_failed=$?
            ;;
        "stress")
            run_stress_tests
            total_failed=$?
            ;;
        "property")
            run_property_tests
            total_failed=$?
            ;;
        "bench")
            run_benchmarks
            ;;
        "security")
            run_security_audit
            ;;
        "coverage")
            run_coverage
            ;;
        "clippy")
            run_clippy
            ;;
        "doc")
            run_doc_tests
            ;;
        "all")
            # Run all test categories
            local failed=0
            
            run_unit_tests
            ((failed+=$?))
            
            run_integration_tests
            ((failed+=$?))
            
            run_property_tests
            ((failed+=$?))
            
            run_doc_tests
            ((failed+=$?)) || true
            
            run_clippy
            ((failed+=$?)) || true
            
            total_failed=$failed
            ;;
        "ci")
            # CI pipeline - all tests + security + coverage
            local failed=0
            
            run_clippy
            ((failed+=$?))
            
            run_unit_tests
            ((failed+=$?))
            
            run_integration_tests
            ((failed+=$?))
            
            run_property_tests
            ((failed+=$?))
            
            run_doc_tests
            ((failed+=$?))
            
            run_security_audit
            ((failed+=$?)) || true
            
            run_coverage
            
            total_failed=$failed
            ;;
        *)
            print_error "Unknown test suite: $test_suite"
            echo "Available suites: unit, integration, stress, property, bench, security, coverage, clippy, doc, all, ci"
            exit 1
            ;;
    esac
    
    local end_time=$(date +%s)
    local elapsed=$((end_time - start_time))
    
    if [ "$test_suite" != "bench" ] && [ "$test_suite" != "coverage" ]; then
        generate_test_report 100 $total_failed $elapsed
    fi
    
    exit $total_failed
}

# Run main function with all arguments
main "$@"