#!/bin/bash
# Memory Configuration Validation Script
# Validates all Node.js memory configuration implementations

set -euo pipefail

echo "=========================================="
echo "Node.js Memory Configuration Validation"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check functions
check_pass() {
    echo -e "${GREEN}✅ PASS${NC}: $1"
}

check_fail() {
    echo -e "${RED}❌ FAIL${NC}: $1"
}

check_warn() {
    echo -e "${YELLOW}⚠️  WARN${NC}: $1"
}

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_WARNED=0

# Function to run a test
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    echo "Testing: $test_name"
    
    if eval "$test_command"; then
        check_pass "$test_name"
        ((TESTS_PASSED++))
    else
        check_fail "$test_name"
        ((TESTS_FAILED++))
    fi
    echo
}

# Function to run a warning test
run_warn_test() {
    local test_name="$1"
    local test_command="$2"
    
    echo "Checking: $test_name"
    
    if eval "$test_command"; then
        check_pass "$test_name"
        ((TESTS_PASSED++))
    else
        check_warn "$test_name"
        ((TESTS_WARNED++))
    fi
    echo
}

echo "🔍 Validating Node.js Memory Configuration Implementation"
echo

# Test 1: Package.json scripts
echo "1. Package.json Configuration"
run_test "package.json exists" "[ -f package.json ]"
run_test "package.json contains NODE_OPTIONS in start script" "grep -q 'max-old-space-size=6144' package.json"
run_test "package.json contains GC optimization flags" "grep -q 'gc-interval=100' package.json && grep -q 'optimize-for-size' package.json"

# Test 2: Environment files
echo "2. Environment Files Configuration"
run_test ".env.example contains NODE_OPTIONS" "grep -q 'NODE_OPTIONS.*max-old-space-size=6144' .env.example"
run_test ".env.development contains NODE_OPTIONS" "grep -q 'NODE_OPTIONS.*max-old-space-size=6144' .env.development"
run_test ".env.production exists and contains NODE_OPTIONS" "[ -f .env.production ] && grep -q 'NODE_OPTIONS.*max-old-space-size=6144' .env.production"

# Test 3: Docker Compose files
echo "3. Docker Compose Configuration"
run_test "Main docker-compose.monitoring.yml contains NODE_OPTIONS" "grep -q 'NODE_OPTIONS.*max-old-space-size=6144' docker-compose.monitoring.yml"
run_test "Docker Compose memory limits configured" "grep -q 'memory: 8G' docker-compose.monitoring.yml"
run_warn_test "Secondary monitoring compose has memory config" "grep -q 'NODE_OPTIONS.*max-old-space-size=6144' src/monitoring/docker-compose.monitoring.yml"

# Test 4: Kubernetes configuration
echo "4. Kubernetes Configuration"
run_test "K8s deployments contain NODE_OPTIONS" "grep -q 'NODE_OPTIONS' k8s/deployments.yaml"
run_test "K8s memory limits set to 8Gi" "grep -q 'memory: \"8Gi\"' k8s/deployments.yaml"
run_test "K8s memory requests configured" "grep -q 'memory: \"2Gi\"' k8s/deployments.yaml"

# Test 5: Startup script
echo "5. Startup Script"
run_test "Memory startup script exists" "[ -f start_nodejs_with_memory_config.sh ]"
run_test "Startup script is executable" "[ -x start_nodejs_with_memory_config.sh ]"
run_test "Startup script contains memory configuration" "grep -q 'max-old-space-size=6144' start_nodejs_with_memory_config.sh"

# Test 6: Documentation
echo "6. Documentation"
run_test "Memory configuration guide exists" "[ -f NODE_MEMORY_CONFIGURATION_GUIDE.md ]"
run_test "Documentation contains implementation details" "grep -q 'max-old-space-size=6144' NODE_MEMORY_CONFIGURATION_GUIDE.md"

# Test 7: Configuration consistency
echo "7. Configuration Consistency"
HEAP_SIZE_COUNT=$(grep -r "max-old-space-size=6144" . --include="*.json" --include="*.yml" --include="*.yaml" --include="*.sh" --include="*.env*" --include="*.md" | wc -l)
run_test "Consistent heap size across all files (6144MB)" "[ $HEAP_SIZE_COUNT -ge 8 ]"

GC_INTERVAL_COUNT=$(grep -r "gc-interval=100" . --include="*.json" --include="*.yml" --include="*.yaml" --include="*.sh" --include="*.env*" --include="*.md" | wc -l)
run_test "Consistent GC interval across all files" "[ $GC_INTERVAL_COUNT -ge 4 ]"

# Test 8: Optional Node.js validation
echo "8. Runtime Validation (Optional)"
if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version)
    check_pass "Node.js installed: $NODE_VERSION"
    ((TESTS_PASSED++))
    
    # Test memory configuration loading
    if [ -f .env.development ]; then
        source .env.development 2>/dev/null || true
        if [ -n "${NODE_OPTIONS:-}" ]; then
            check_pass "NODE_OPTIONS loaded from environment: $NODE_OPTIONS"
            ((TESTS_PASSED++))
        else
            check_warn "NODE_OPTIONS not loaded from environment"
            ((TESTS_WARNED++))
        fi
    fi
else
    check_warn "Node.js not installed - runtime validation skipped"
    ((TESTS_WARNED++))
fi

# Summary
echo "=========================================="
echo "VALIDATION SUMMARY"
echo "=========================================="
echo -e "${GREEN}Tests Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Tests Failed: $TESTS_FAILED${NC}"
echo -e "${YELLOW}Warnings: $TESTS_WARNED${NC}"
echo

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}🎉 ALL CRITICAL TESTS PASSED!${NC}"
    echo "Node.js memory configuration implementation is complete and valid."
    
    if [ $TESTS_WARNED -gt 0 ]; then
        echo -e "${YELLOW}Note: $TESTS_WARNED warning(s) found - review optional configurations.${NC}"
    fi
    
    echo
    echo "Next Steps:"
    echo "1. Test the configuration in development environment"
    echo "2. Deploy to staging for validation"
    echo "3. Monitor memory usage patterns"
    echo "4. Set up alerts for memory thresholds"
    
    exit 0
else
    echo -e "${RED}❌ VALIDATION FAILED!${NC}"
    echo "$TESTS_FAILED critical test(s) failed. Please review the implementation."
    echo
    echo "Common fixes:"
    echo "1. Ensure all files contain the correct NODE_OPTIONS setting"
    echo "2. Verify memory limits are set to 8G in container configurations"
    echo "3. Check that Kubernetes resource limits are properly configured"
    echo "4. Validate environment files contain all required variables"
    
    exit 1
fi