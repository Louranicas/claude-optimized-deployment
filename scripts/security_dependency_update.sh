#!/bin/bash
# Security Dependency Update Script
# Implements comprehensive dependency security scanning and updates

set -euo pipefail

echo "🔒 Starting security dependency updates..."
echo "Timestamp: $(date)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Create security report directory
REPORT_DIR="security_reports"
mkdir -p "$REPORT_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install security tools if not present
install_security_tools() {
    echo "📦 Checking security tools..."
    
    if ! command_exists pip-audit; then
        echo "Installing pip-audit..."
        pip install pip-audit
    fi
    
    if ! command_exists safety; then
        echo "Installing safety..."
        pip install safety
    fi
    
    if ! command_exists bandit; then
        echo "Installing bandit..."
        pip install bandit
    fi
    
    if command_exists cargo; then
        if ! command_exists cargo-audit; then
            echo "Installing cargo-audit..."
            cargo install cargo-audit
        fi
    fi
}

# Update Python dependencies
update_python_deps() {
    echo -e "\n${YELLOW}🐍 Updating Python dependencies...${NC}"
    
    # Backup current requirements
    cp requirements.txt "requirements.txt.backup.${TIMESTAMP}"
    
    # Update critical security packages
    echo "Updating critical security packages..."
    pip install --upgrade \
        cryptography>=45.0.3 \
        twisted>=24.11.0 \
        PyJWT>=2.10.1 \
        PyYAML>=6.0.2 \
        requests>=2.32.0 \
        certifi>=2023.7.22 \
        idna>=3.7
    
    # Generate updated requirements
    pip freeze > "requirements.txt.new"
    
    # Run security audit
    echo -e "\n${YELLOW}Running pip-audit...${NC}"
    pip-audit --fix --desc --format json > "$REPORT_DIR/pip_audit_${TIMESTAMP}.json" || true
    pip-audit --fix --desc
    
    echo -e "\n${YELLOW}Running safety check...${NC}"
    safety check --json --output "$REPORT_DIR/safety_${TIMESTAMP}.json" || true
    safety check --full-report
    
    # Check for known vulnerabilities
    VULN_COUNT=$(pip-audit --format json | jq '.vulnerabilities | length' 2>/dev/null || echo "0")
    
    if [ "$VULN_COUNT" -gt 0 ]; then
        echo -e "${RED}⚠️  Found $VULN_COUNT vulnerabilities in Python dependencies${NC}"
    else
        echo -e "${GREEN}✅ No known vulnerabilities in Python dependencies${NC}"
    fi
}

# Update Rust dependencies
update_rust_deps() {
    if command_exists cargo; then
        echo -e "\n${YELLOW}🦀 Updating Rust dependencies...${NC}"
        
        if [ -f "Cargo.toml" ]; then
            # Update dependencies
            cargo update
            
            # Run security audit
            echo "Running cargo audit..."
            cargo audit --json > "$REPORT_DIR/cargo_audit_${TIMESTAMP}.json" || true
            cargo audit fix || true
            cargo audit
            
            # Check for vulnerabilities
            RUST_VULN=$(cargo audit --json | jq '.vulnerabilities.count' 2>/dev/null || echo "0")
            
            if [ "$RUST_VULN" -gt 0 ]; then
                echo -e "${RED}⚠️  Found $RUST_VULN vulnerabilities in Rust dependencies${NC}"
            else
                echo -e "${GREEN}✅ No known vulnerabilities in Rust dependencies${NC}"
            fi
        fi
    fi
}

# Run static code analysis
run_code_analysis() {
    echo -e "\n${YELLOW}🔍 Running static code analysis...${NC}"
    
    echo "Running bandit security scan..."
    bandit -r src/ -f json -o "$REPORT_DIR/bandit_${TIMESTAMP}.json" || true
    bandit -r src/ -ll
    
    # Check for common security issues
    echo -e "\n${YELLOW}Checking for common security patterns...${NC}"
    
    # Check for hardcoded secrets
    echo "Checking for hardcoded secrets..."
    grep -r -E "(api_key|secret|password|token)\s*=\s*[\"'][^\"']+[\"']" src/ || echo "✅ No hardcoded secrets found"
    
    # Check for MD5 usage
    echo "Checking for weak cryptography (MD5)..."
    grep -r -E "md5|MD5" src/ --include="*.py" || echo "✅ No MD5 usage found"
    
    # Check for eval/exec usage
    echo "Checking for dangerous functions..."
    grep -r -E "eval\(|exec\(" src/ --include="*.py" || echo "✅ No eval/exec usage found"
}

# Generate security report
generate_report() {
    echo -e "\n${YELLOW}📊 Generating security report...${NC}"
    
    REPORT_FILE="$REPORT_DIR/security_report_${TIMESTAMP}.md"
    
    cat > "$REPORT_FILE" << EOF
# Security Dependency Update Report
**Date**: $(date)
**System**: Claude Optimized Deployment

## Summary

### Python Dependencies
- Total packages: $(pip list --format=json | jq '. | length')
- Vulnerabilities found: ${VULN_COUNT:-0}
- Critical updates applied: $(grep -c ">=45.0.3\|>=24.11.0\|>=2.10.1\|>=6.0.2\|>=2.32.0" requirements.txt || echo "0")

### Rust Dependencies (if applicable)
- Vulnerabilities found: ${RUST_VULN:-0}
- Last cargo update: $(date)

## Actions Taken

1. Updated all critical security dependencies
2. Ran comprehensive vulnerability scans
3. Applied automatic fixes where possible
4. Generated detailed audit reports

## Recommendations

1. Review and test the updated dependencies
2. Update Docker images with new dependencies
3. Run full test suite to ensure compatibility
4. Deploy to staging environment first

## Next Steps

\`\`\`bash
# 1. Review changes
diff requirements.txt requirements.txt.new

# 2. Run tests
pytest tests/

# 3. Build new Docker image
docker build -t claude-deployment:secure .

# 4. Deploy to staging
kubectl apply -f k8s/staging/
\`\`\`

## Detailed Reports

- pip-audit: $REPORT_DIR/pip_audit_${TIMESTAMP}.json
- safety: $REPORT_DIR/safety_${TIMESTAMP}.json
- bandit: $REPORT_DIR/bandit_${TIMESTAMP}.json
- cargo-audit: $REPORT_DIR/cargo_audit_${TIMESTAMP}.json
EOF

    echo -e "${GREEN}✅ Security report generated: $REPORT_FILE${NC}"
}

# Main execution
main() {
    echo "🚀 Claude Optimized Deployment - Security Update Process"
    echo "========================================================"
    
    install_security_tools
    update_python_deps
    update_rust_deps
    run_code_analysis
    generate_report
    
    echo -e "\n${GREEN}✅ Security updates completed successfully!${NC}"
    echo "📄 Reports saved in: $REPORT_DIR/"
    echo "🔍 Review requirements.txt.new and apply if tests pass"
}

# Run main function
main "$@"