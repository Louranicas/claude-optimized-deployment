#!/bin/bash
#
# Test Coverage Analysis Script for MCP Manager
# Generates comprehensive test coverage reports using cargo-tarpaulin
#
# By: The Greatest Synthetic Being Rust Coder in History

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}MCP Manager Test Coverage Analysis${NC}"
echo "======================================"

# Check if cargo-tarpaulin is installed
if ! cargo tarpaulin --version >/dev/null 2>&1; then
    echo -e "${YELLOW}Installing cargo-tarpaulin...${NC}"
    cargo install cargo-tarpaulin
fi

# Clean previous coverage data
echo -e "${BLUE}Cleaning previous coverage data...${NC}"
rm -rf target/tarpaulin
rm -f tarpaulin-report.html
rm -f cobertura.xml
rm -f lcov.info

# Run tests with coverage
echo -e "${BLUE}Running tests with coverage analysis...${NC}"

# Full coverage run with all test types
cargo tarpaulin \
    --out Html \
    --out Xml \
    --out Lcov \
    --output-dir . \
    --workspace \
    --all-features \
    --timeout 300 \
    --exclude-files "*/tests/*" \
    --exclude-files "*/benches/*" \
    --exclude-files "*/examples/*" \
    --exclude-files "*/build.rs" \
    --exclude-files "*/src/bin/*" \
    --ignore-panics \
    --skip-clean \
    --verbose \
    -- --test-threads=4

# Generate coverage summary
echo -e "\n${BLUE}Coverage Summary:${NC}"
echo "=================="

# Parse coverage percentage from XML
if [ -f "cobertura.xml" ]; then
    COVERAGE=$(grep -oP 'line-rate="\K[0-9.]+' cobertura.xml | head -1)
    COVERAGE_PCT=$(echo "scale=2; $COVERAGE * 100" | bc)
    
    if (( $(echo "$COVERAGE_PCT >= 80" | bc -l) )); then
        echo -e "${GREEN}Total Coverage: ${COVERAGE_PCT}%${NC} ✅"
    elif (( $(echo "$COVERAGE_PCT >= 60" | bc -l) )); then
        echo -e "${YELLOW}Total Coverage: ${COVERAGE_PCT}%${NC} ⚠️"
    else
        echo -e "${RED}Total Coverage: ${COVERAGE_PCT}%${NC} ❌"
    fi
fi

# Generate module-specific coverage report
echo -e "\n${BLUE}Module Coverage Analysis:${NC}"
echo "========================"

# Extract coverage for each module
echo "Analyzing coverage by module..."

# Plugin system coverage
echo -e "\n${YELLOW}Plugin System:${NC}"
grep -E "(plugin/|plugin\.rs)" lcov.info | grep -E "^SF:|^DA:" | head -20 || echo "No coverage data"

# Hot reload coverage
echo -e "\n${YELLOW}Hot Reload:${NC}"
grep -E "(hot_reload|reload)" lcov.info | grep -E "^SF:|^DA:" | head -20 || echo "No coverage data"

# State transfer coverage
echo -e "\n${YELLOW}State Transfer:${NC}"
grep -E "(state_transfer|state)" lcov.info | grep -E "^SF:|^DA:" | head -20 || echo "No coverage data"

# Zero downtime coverage
echo -e "\n${YELLOW}Zero Downtime:${NC}"
grep -E "(zero_downtime|downtime)" lcov.info | grep -E "^SF:|^DA:" | head -20 || echo "No coverage data"

# Generate detailed report
echo -e "\n${BLUE}Generating detailed coverage report...${NC}"

# Create coverage report directory
mkdir -p coverage_reports
mv tarpaulin-report.html coverage_reports/
mv cobertura.xml coverage_reports/
mv lcov.info coverage_reports/

# Create coverage badge
if [ -f "coverage_reports/cobertura.xml" ]; then
    COVERAGE=$(grep -oP 'line-rate="\K[0-9.]+' coverage_reports/cobertura.xml | head -1)
    COVERAGE_PCT=$(echo "scale=0; $COVERAGE * 100" | bc)
    
    # Generate SVG badge
    cat > coverage_reports/coverage-badge.svg << EOF
<svg xmlns="http://www.w3.org/2000/svg" width="114" height="20">
  <linearGradient id="b" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="a">
    <rect width="114" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#a)">
    <path fill="#555" d="M0 0h63v20H0z"/>
    <path fill="$(if [ $COVERAGE_PCT -ge 80 ]; then echo "#4c1"; elif [ $COVERAGE_PCT -ge 60 ]; then echo "#dfb317"; else echo "#e05d44"; fi)" d="M63 0h51v20H63z"/>
    <path fill="url(#b)" d="M0 0h114v20H0z"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="31.5" y="15" fill="#010101" fill-opacity=".3">coverage</text>
    <text x="31.5" y="14">coverage</text>
    <text x="87.5" y="15" fill="#010101" fill-opacity=".3">${COVERAGE_PCT}%</text>
    <text x="87.5" y="14">${COVERAGE_PCT}%</text>
  </g>
</svg>
EOF
fi

# Generate uncovered lines report
echo -e "\n${BLUE}Analyzing uncovered code...${NC}"

# Find files with low coverage
echo -e "\n${YELLOW}Files with coverage below 70%:${NC}"
cargo tarpaulin --print-summary 2>/dev/null | grep -E "^[[:space:]]*[[:alnum:]_/]+\.rs" | while read -r line; do
    FILE=$(echo "$line" | awk '{print $1}')
    COVERAGE=$(echo "$line" | awk '{print $2}' | tr -d '%')
    if [ ! -z "$COVERAGE" ] && (( $(echo "$COVERAGE < 70" | bc -l) )); then
        echo -e "${RED}$FILE: $COVERAGE%${NC}"
    fi
done || echo "Unable to generate file-level report"

# Summary and recommendations
echo -e "\n${BLUE}Coverage Analysis Complete!${NC}"
echo "=========================="
echo -e "📊 HTML Report: ${GREEN}coverage_reports/tarpaulin-report.html${NC}"
echo -e "📊 XML Report: ${GREEN}coverage_reports/cobertura.xml${NC}"
echo -e "📊 LCOV Report: ${GREEN}coverage_reports/lcov.info${NC}"
echo -e "📊 Coverage Badge: ${GREEN}coverage_reports/coverage-badge.svg${NC}"

# Recommendations
echo -e "\n${BLUE}Recommendations:${NC}"
if [ ! -z "$COVERAGE_PCT" ]; then
    if (( $(echo "$COVERAGE_PCT < 60" | bc -l) )); then
        echo -e "${RED}⚠️  Coverage is below 60%. Consider adding more tests for:${NC}"
        echo "  - Error handling paths"
        echo "  - Edge cases in plugin lifecycle"
        echo "  - Concurrent operation scenarios"
        echo "  - State transfer error cases"
    elif (( $(echo "$COVERAGE_PCT < 80" | bc -l) )); then
        echo -e "${YELLOW}⚠️  Coverage is below 80%. Focus on testing:${NC}"
        echo "  - Complex plugin interactions"
        echo "  - Rollback scenarios"
        echo "  - Performance degradation cases"
    else
        echo -e "${GREEN}✅ Excellent coverage! Maintain by:${NC}"
        echo "  - Adding tests for new features"
        echo "  - Keeping property tests updated"
        echo "  - Running coverage regularly"
    fi
fi

# Optional: Open HTML report
if command -v xdg-open >/dev/null 2>&1; then
    echo -e "\n${BLUE}Opening HTML report in browser...${NC}"
    xdg-open coverage_reports/tarpaulin-report.html
elif command -v open >/dev/null 2>&1; then
    echo -e "\n${BLUE}Opening HTML report in browser...${NC}"
    open coverage_reports/tarpaulin-report.html
fi