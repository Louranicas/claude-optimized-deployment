#!/bin/bash
# Continuous Performance Benchmarking Script
# Runs benchmarks, analyzes results, and updates tracking

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BENCHMARK_DIR="$PROJECT_ROOT/benchmarks"
RESULTS_DIR="$BENCHMARK_DIR/results"
BASELINE_FILE="$BENCHMARK_DIR/baseline/current.json"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
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

check_environment() {
    log_info "Checking benchmark environment..."
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is required but not installed"
        exit 1
    fi
    
    # Check system resources
    AVAILABLE_MEM=$(free -m | awk 'NR==2{printf "%.0f", $7}')
    if [ "$AVAILABLE_MEM" -lt 2048 ]; then
        log_warning "Low memory available: ${AVAILABLE_MEM}MB (recommended: 2048MB+)"
    fi
    
    # Check CPU load
    CPU_LOAD=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | tr -d ',')
    CPU_COUNT=$(nproc)
    if (( $(echo "$CPU_LOAD > $CPU_COUNT" | bc -l) )); then
        log_warning "High CPU load detected: $CPU_LOAD (cores: $CPU_COUNT)"
    fi
    
    # Create directories
    mkdir -p "$RESULTS_DIR" "$BENCHMARK_DIR/baseline" "$BENCHMARK_DIR/reports"
    
    log_success "Environment check completed"
}

run_benchmarks() {
    local categories="${1:-all}"
    local output_dir="$RESULTS_DIR/$TIMESTAMP"
    
    log_info "Starting benchmark suite (categories: $categories)..."
    
    # Run comprehensive benchmarks
    cd "$PROJECT_ROOT"
    python3 "$SCRIPT_DIR/run_comprehensive_benchmarks.py" \
        --output "$output_dir" \
        --categories $categories
    
    if [ $? -eq 0 ]; then
        log_success "Benchmarks completed successfully"
        echo "$output_dir"
    else
        log_error "Benchmark execution failed"
        exit 1
    fi
}

analyze_results() {
    local current_results="$1"
    local analysis_output="$2"
    
    log_info "Analyzing benchmark results..."
    
    # Check if baseline exists
    if [ ! -f "$BASELINE_FILE" ]; then
        log_warning "No baseline found. Creating baseline from current results..."
        cp "$current_results/benchmark_results_*.json" "$BASELINE_FILE"
        echo "{\"regression\": false, \"summary\": \"Baseline created\"}" > "$analysis_output"
        return 0
    fi
    
    # Find the results file
    RESULTS_FILE=$(find "$current_results" -name "benchmark_results_*.json" | head -1)
    
    if [ -z "$RESULTS_FILE" ]; then
        log_error "No results file found in $current_results"
        exit 1
    fi
    
    # Run analysis
    python3 "$SCRIPT_DIR/analyze_benchmarks.py" \
        --current "$RESULTS_FILE" \
        --baseline "$BASELINE_FILE" \
        --output "$analysis_output" \
        --generate-report
    
    return $?
}

update_tracking() {
    local results_dir="$1"
    local analysis_file="$2"
    
    log_info "Updating performance tracking..."
    
    # Store metrics in monitoring system (if available)
    if command -v curl &> /dev/null && [ -n "${PROMETHEUS_PUSHGATEWAY_URL:-}" ]; then
        log_info "Pushing metrics to Prometheus..."
        python3 "$SCRIPT_DIR/push_metrics.py" \
            --results "$results_dir" \
            --pushgateway "$PROMETHEUS_PUSHGATEWAY_URL"
    fi
    
    # Update dashboard (if configured)
    if [ -f "$SCRIPT_DIR/update_dashboard.py" ]; then
        python3 "$SCRIPT_DIR/update_dashboard.py" \
            --results "$analysis_file"
    fi
    
    # Archive results
    ARCHIVE_DIR="$BENCHMARK_DIR/archive/$(date +%Y/%m)"
    mkdir -p "$ARCHIVE_DIR"
    cp -r "$results_dir" "$ARCHIVE_DIR/"
    
    log_success "Tracking updated"
}

handle_regression() {
    local analysis_file="$1"
    
    # Check for regressions
    if grep -q '"regression": true' "$analysis_file"; then
        log_error "Performance regression detected!"
        
        # Extract regression details
        CRITICAL_COUNT=$(jq '.statistics.critical_regressions' "$analysis_file")
        WARNING_COUNT=$(jq '.statistics.warning_regressions' "$analysis_file")
        
        log_error "Critical regressions: $CRITICAL_COUNT"
        log_warning "Warning regressions: $WARNING_COUNT"
        
        # Notify (if configured)
        if [ -f "$SCRIPT_DIR/notify_regression.py" ]; then
            python3 "$SCRIPT_DIR/notify_regression.py" \
                --results "$analysis_file" \
                --channels "${NOTIFICATION_CHANNELS:-slack}"
        fi
        
        # Generate detailed report
        if [ -f "${analysis_file%.json}.md" ]; then
            log_info "Detailed report: ${analysis_file%.json}.md"
        fi
        
        return 1
    else
        log_success "No performance regressions detected"
        return 0
    fi
}

update_baseline() {
    local results_file="$1"
    
    read -p "Update baseline with current results? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cp "$results_file" "$BASELINE_FILE"
        log_success "Baseline updated"
    fi
}

generate_trend_report() {
    log_info "Generating trend report..."
    
    if [ -f "$SCRIPT_DIR/generate_trends.py" ]; then
        python3 "$SCRIPT_DIR/generate_trends.py" \
            --results-dir "$RESULTS_DIR" \
            --output "$BENCHMARK_DIR/reports/trend_report_$TIMESTAMP.html"
        
        log_success "Trend report generated"
    fi
}

# Main execution
main() {
    local categories="${1:-all}"
    local update_baseline_flag="${2:-false}"
    
    echo "🚀 Continuous Performance Benchmarking"
    echo "====================================="
    echo "Timestamp: $TIMESTAMP"
    echo "Categories: $categories"
    echo
    
    # Check environment
    check_environment
    
    # Run benchmarks
    RESULTS_PATH=$(run_benchmarks "$categories")
    
    # Find results file
    RESULTS_FILE=$(find "$RESULTS_PATH" -name "benchmark_results_*.json" | head -1)
    ANALYSIS_FILE="$RESULTS_PATH/analysis.json"
    
    # Analyze results
    if analyze_results "$RESULTS_PATH" "$ANALYSIS_FILE"; then
        REGRESSION_FOUND=false
    else
        REGRESSION_FOUND=true
    fi
    
    # Update tracking
    update_tracking "$RESULTS_PATH" "$ANALYSIS_FILE"
    
    # Handle regression
    if [ "$REGRESSION_FOUND" = true ]; then
        handle_regression "$ANALYSIS_FILE"
        EXIT_CODE=1
    else
        EXIT_CODE=0
        
        # Optionally update baseline
        if [ "$update_baseline_flag" = "update-baseline" ]; then
            update_baseline "$RESULTS_FILE"
        fi
    fi
    
    # Generate trend report
    generate_trend_report
    
    # Summary
    echo
    echo "====================================="
    log_info "Results: $RESULTS_PATH"
    log_info "Analysis: $ANALYSIS_FILE"
    
    if [ -f "${ANALYSIS_FILE%.json}.md" ]; then
        log_info "Report: ${ANALYSIS_FILE%.json}.md"
    fi
    
    exit $EXIT_CODE
}

# Parse arguments
CATEGORIES="${1:-all}"
UPDATE_BASELINE="${2:-}"

# Run main
main "$CATEGORIES" "$UPDATE_BASELINE"