#!/bin/bash
# Run SYNTHEX performance benchmarks

set -e

echo "=================================="
echo "SYNTHEX Performance Benchmarks"
echo "=================================="
echo ""

# Ensure we're in the rust_core directory
cd "$(dirname "$0")"

# Build in release mode first
echo "Building SYNTHEX in release mode..."
cargo build --release --features testing

echo ""
echo "Running SYNTHEX benchmarks..."
echo ""

# Run benchmarks with different configurations
echo "1. Running standard benchmarks..."
cargo bench --bench synthex_bench -- --verbose

echo ""
echo "2. Running with profiling output..."
cargo bench --bench synthex_bench -- --profile-time=10

echo ""
echo "3. Generating benchmark report..."
cargo bench --bench synthex_bench -- --save-baseline synthex_baseline

echo ""
echo "4. Memory usage analysis..."
echo "Running memory-focused benchmarks..."
cargo bench --bench synthex_bench synthex_memory -- --verbose

echo ""
echo "5. Concurrent operations analysis..."
cargo bench --bench synthex_bench synthex_concurrent -- --verbose

echo ""
echo "=================================="
echo "Benchmark Summary"
echo "=================================="

# Generate summary report
if [ -f "target/criterion/synthex_single_search/simple_query/base/estimates.json" ]; then
    echo ""
    echo "Single Search Performance:"
    echo "-------------------------"
    cat target/criterion/synthex_single_search/*/base/estimates.json 2>/dev/null | jq -r '.mean.point_estimate' | head -5
fi

if [ -f "target/criterion/synthex_concurrent_searches/100/base/estimates.json" ]; then
    echo ""
    echo "Concurrent Search Performance (100 concurrent):"
    echo "----------------------------------------------"
    cat target/criterion/synthex_concurrent_searches/100/base/estimates.json 2>/dev/null | jq -r '.throughput' | head -1
fi

echo ""
echo "Full benchmark results saved in: target/criterion/"
echo ""
echo "To compare with previous runs:"
echo "  cargo bench --bench synthex_bench -- --baseline synthex_baseline"
echo ""
echo "To generate HTML report:"
echo "  cargo bench --bench synthex_bench -- --output-format bencher"
echo ""