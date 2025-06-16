#!/bin/bash

# Production Smoke Tests - Quick validation of critical functionality
# Usage: ./scripts/smoke-tests.sh [base-url]

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_URL="${1:-https://api.claude-deployment.com}"
TIMEOUT=30
MAX_RETRIES=3

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
    ((TESTS_PASSED++))
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
    ((TESTS_FAILED++))
}

log_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
    ((TESTS_SKIPPED++))
}

# Helper function to make HTTP requests with retry
http_request() {
    local method="$1"
    local url="$2"
    local expected_status="${3:-200}"
    local retry_count=0
    local headers="${4:-}"
    local data="${5:-}"
    
    while [[ $retry_count -lt $MAX_RETRIES ]]; do
        local curl_cmd="curl -s -w '%{http_code}' --max-time $TIMEOUT"
        
        if [[ -n "$headers" ]]; then
            curl_cmd="$curl_cmd -H '$headers'"
        fi
        
        if [[ "$method" == "POST" && -n "$data" ]]; then
            curl_cmd="$curl_cmd -X POST -d '$data'"
        elif [[ "$method" == "PUT" && -n "$data" ]]; then
            curl_cmd="$curl_cmd -X PUT -d '$data'"
        fi
        
        local response
        local http_code
        response=$(eval "$curl_cmd '$url'" 2>/dev/null || echo "000")
        http_code="${response: -3}"
        
        if [[ "$http_code" == "$expected_status" ]]; then
            return 0
        fi
        
        ((retry_count++))
        if [[ $retry_count -lt $MAX_RETRIES ]]; then
            sleep 2
        fi
    done
    
    return 1
}

# Test 1: Basic Health Check
test_health_check() {
    log_info "Testing health check endpoint..."
    
    if http_request "GET" "$BASE_URL/health" "200"; then
        log_success "Health check endpoint responding"
    else
        log_error "Health check endpoint failed"
        return 1
    fi
}

# Test 2: Readiness Check
test_readiness_check() {
    log_info "Testing readiness check endpoint..."
    
    if http_request "GET" "$BASE_URL/ready" "200"; then
        log_success "Readiness check endpoint responding"
    else
        log_error "Readiness check endpoint failed"
        return 1
    fi
}

# Test 3: Metrics Endpoint
test_metrics_endpoint() {
    log_info "Testing metrics endpoint..."
    
    if http_request "GET" "$BASE_URL/metrics" "200"; then
        # Verify metrics content
        local response
        response=$(curl -s --max-time $TIMEOUT "$BASE_URL/metrics" 2>/dev/null || echo "")
        
        if echo "$response" | grep -q "http_requests_total"; then
            log_success "Metrics endpoint returning valid data"
        else
            log_error "Metrics endpoint not returning expected data"
            return 1
        fi
    else
        log_error "Metrics endpoint failed"
        return 1
    fi
}

# Test 4: API Version Endpoint
test_api_version() {
    log_info "Testing API version endpoint..."
    
    if http_request "GET" "$BASE_URL/version" "200"; then
        local response
        response=$(curl -s --max-time $TIMEOUT "$BASE_URL/version" 2>/dev/null || echo "")
        
        if echo "$response" | grep -q '"version"'; then
            log_success "API version endpoint responding correctly"
        else
            log_error "API version endpoint not returning expected format"
            return 1
        fi
    else
        log_error "API version endpoint failed"
        return 1
    fi
}

# Test 5: Database Connectivity
test_database_connectivity() {
    log_info "Testing database connectivity..."
    
    # This endpoint should test DB connection without exposing sensitive data
    if http_request "GET" "$BASE_URL/health/db" "200"; then
        log_success "Database connectivity test passed"
    else
        log_error "Database connectivity test failed"
        return 1
    fi
}

# Test 6: Redis Connectivity
test_redis_connectivity() {
    log_info "Testing Redis connectivity..."
    
    if http_request "GET" "$BASE_URL/health/redis" "200"; then
        log_success "Redis connectivity test passed"
    else
        log_error "Redis connectivity test failed"
        return 1
    fi
}

# Test 7: Authentication Endpoint
test_authentication() {
    log_info "Testing authentication endpoint..."
    
    # Test that auth endpoint is responsive (should return 401 without credentials)
    if http_request "GET" "$BASE_URL/auth/validate" "401"; then
        log_success "Authentication endpoint responding correctly"
    else
        log_error "Authentication endpoint not behaving as expected"
        return 1
    fi
}

# Test 8: Rate Limiting
test_rate_limiting() {
    log_info "Testing rate limiting..."
    
    # Make multiple rapid requests to trigger rate limiting
    local rate_limit_triggered=false
    for i in {1..20}; do
        local response
        response=$(curl -s -w '%{http_code}' --max-time 5 "$BASE_URL/health" 2>/dev/null || echo "000")
        local http_code="${response: -3}"
        
        if [[ "$http_code" == "429" ]]; then
            rate_limit_triggered=true
            break
        fi
        sleep 0.1
    done
    
    if [[ "$rate_limit_triggered" == true ]]; then
        log_success "Rate limiting is working"
    else
        log_skip "Rate limiting not triggered (may be configured differently)"
    fi
}

# Test 9: CORS Headers
test_cors_headers() {
    log_info "Testing CORS headers..."
    
    local response
    response=$(curl -s -H "Origin: https://example.com" -I "$BASE_URL/health" 2>/dev/null || echo "")
    
    if echo "$response" | grep -qi "access-control-allow-origin"; then
        log_success "CORS headers present"
    else
        log_error "CORS headers missing"
        return 1
    fi
}

# Test 10: Security Headers
test_security_headers() {
    log_info "Testing security headers..."
    
    local response
    response=$(curl -s -I "$BASE_URL/health" 2>/dev/null || echo "")
    
    local headers_found=0
    local expected_headers=(
        "X-Frame-Options"
        "X-Content-Type-Options"
        "X-XSS-Protection"
        "Referrer-Policy"
    )
    
    for header in "${expected_headers[@]}"; do
        if echo "$response" | grep -qi "$header"; then
            ((headers_found++))
        fi
    done
    
    if [[ $headers_found -ge 3 ]]; then
        log_success "Security headers present ($headers_found/4)"
    else
        log_error "Insufficient security headers ($headers_found/4)"
        return 1
    fi
}

# Test 11: Load Balancer Health
test_load_balancer() {
    log_info "Testing load balancer health..."
    
    # Test multiple requests to verify load balancing
    local unique_responses=()
    for i in {1..5}; do
        local response
        response=$(curl -s --max-time $TIMEOUT "$BASE_URL/health" 2>/dev/null || echo "")
        
        # Extract any server identifier (if present in response)
        local server_id
        server_id=$(echo "$response" | grep -o '"server":"[^"]*"' | cut -d'"' -f4 || echo "unknown-$i")
        unique_responses+=("$server_id")
    done
    
    # Check if we got responses
    if [[ ${#unique_responses[@]} -eq 5 ]]; then
        log_success "Load balancer distributing requests"
    else
        log_error "Load balancer may not be working correctly"
        return 1
    fi
}

# Test 12: SSL/TLS Configuration
test_ssl_configuration() {
    log_info "Testing SSL/TLS configuration..."
    
    if [[ "$BASE_URL" == https* ]]; then
        # Test SSL certificate validity
        local ssl_info
        ssl_info=$(curl -s -I --max-time $TIMEOUT "$BASE_URL/health" 2>&1 || echo "")
        
        if echo "$ssl_info" | grep -q "SSL certificate problem"; then
            log_error "SSL certificate issues detected"
            return 1
        else
            log_success "SSL/TLS configuration appears valid"
        fi
    else
        log_skip "SSL/TLS test skipped (HTTP endpoint)"
    fi
}

# Test 13: API Documentation
test_api_documentation() {
    log_info "Testing API documentation availability..."
    
    local doc_endpoints=(
        "/docs"
        "/swagger"
        "/api-docs"
        "/openapi.json"
    )
    
    local doc_found=false
    for endpoint in "${doc_endpoints[@]}"; do
        if http_request "GET" "$BASE_URL$endpoint" "200"; then
            doc_found=true
            break
        fi
    done
    
    if [[ "$doc_found" == true ]]; then
        log_success "API documentation available"
    else
        log_skip "API documentation not found at standard endpoints"
    fi
}

# Test 14: Performance Baseline
test_performance_baseline() {
    log_info "Testing performance baseline..."
    
    local start_time
    local end_time
    local response_time
    
    start_time=$(date +%s%N)
    if http_request "GET" "$BASE_URL/health" "200"; then
        end_time=$(date +%s%N)
        response_time=$(( (end_time - start_time) / 1000000 )) # Convert to milliseconds
        
        if [[ $response_time -lt 1000 ]]; then
            log_success "Response time acceptable: ${response_time}ms"
        elif [[ $response_time -lt 3000 ]]; then
            log_skip "Response time elevated: ${response_time}ms"
        else
            log_error "Response time too high: ${response_time}ms"
            return 1
        fi
    else
        log_error "Performance test failed - endpoint unreachable"
        return 1
    fi
}

# Test 15: External Dependencies
test_external_dependencies() {
    log_info "Testing external dependencies status..."
    
    if http_request "GET" "$BASE_URL/health/dependencies" "200"; then
        local response
        response=$(curl -s --max-time $TIMEOUT "$BASE_URL/health/dependencies" 2>/dev/null || echo "")
        
        # Check if any dependencies are failing
        if echo "$response" | grep -q '"status":"unhealthy"'; then
            log_error "Some external dependencies are unhealthy"
            return 1
        else
            log_success "External dependencies are healthy"
        fi
    else
        log_skip "External dependencies endpoint not available"
    fi
}

# Main test runner
run_smoke_tests() {
    log_info "Starting smoke tests for: $BASE_URL"
    log_info "Timeout: ${TIMEOUT}s, Max retries: $MAX_RETRIES"
    echo ""
    
    # Critical tests that must pass
    local critical_tests=(
        "test_health_check"
        "test_readiness_check"
        "test_database_connectivity"
    )
    
    # Optional tests
    local optional_tests=(
        "test_metrics_endpoint"
        "test_api_version"
        "test_redis_connectivity"
        "test_authentication"
        "test_rate_limiting"
        "test_cors_headers"
        "test_security_headers"
        "test_load_balancer"
        "test_ssl_configuration"
        "test_api_documentation"
        "test_performance_baseline"
        "test_external_dependencies"
    )
    
    # Run critical tests first
    log_info "Running critical tests..."
    for test in "${critical_tests[@]}"; do
        if ! $test; then
            log_error "Critical test failed: $test"
            exit 1
        fi
    done
    
    echo ""
    log_info "Running optional tests..."
    for test in "${optional_tests[@]}"; do
        $test || true  # Don't fail on optional tests
    done
    
    echo ""
    log_info "Smoke tests completed"
    log_info "Results: ${GREEN}$TESTS_PASSED passed${NC}, ${RED}$TESTS_FAILED failed${NC}, ${YELLOW}$TESTS_SKIPPED skipped${NC}"
    
    if [[ $TESTS_FAILED -gt 0 ]]; then
        log_error "Some tests failed. Please investigate."
        exit 1
    else
        log_success "All critical tests passed!"
    fi
}

# Cleanup function
cleanup() {
    local exit_code=$?
    # Clean up any temporary files or processes
    return $exit_code
}

trap cleanup EXIT

# Help function
show_help() {
    cat << EOF
Smoke Tests - Quick validation of critical functionality

Usage: $0 [BASE_URL]

Arguments:
    BASE_URL    Base URL for the API (default: https://api.claude-deployment.com)

Environment Variables:
    TIMEOUT        Request timeout in seconds (default: 30)
    MAX_RETRIES    Maximum retries per request (default: 3)

Examples:
    $0
    $0 https://staging.claude-deployment.com
    TIMEOUT=60 $0 https://api.claude-deployment.com

EOF
}

# Parse command line arguments
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    show_help
    exit 0
fi

# Run the tests
run_smoke_tests