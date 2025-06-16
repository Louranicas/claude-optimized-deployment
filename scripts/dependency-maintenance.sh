#!/bin/bash
# Dependency Maintenance and Update Script
# Automated dependency scanning, updating, and security monitoring

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +'%H:%M:%S')] $1${NC}"; }
warn() { echo -e "${YELLOW}[WARNING] $1${NC}"; }
error() { echo -e "${RED}[ERROR] $1${NC}"; }
info() { echo -e "${BLUE}[INFO] $1${NC}"; }

PROJECT_DIR="/home/louranicas/projects/claude-optimized-deployment"
REPORT_DIR="$PROJECT_DIR/reports/dependency-maintenance"
DATE=$(date +%Y%m%d_%H%M%S)

# Create report directory
mkdir -p "$REPORT_DIR"

# Security scan functions
scan_python_security() {
    log "🔒 Scanning Python dependencies for security vulnerabilities..."
    
    local environments=("venv" "venv_ai" "venv_mcp")
    
    for env in "${environments[@]}"; do
        if [[ -d "$PROJECT_DIR/$env" ]]; then
            info "Scanning $env environment..."
            
            source "$PROJECT_DIR/$env/bin/activate"
            
            # Run pip-audit
            if command -v pip-audit >/dev/null 2>&1; then
                pip-audit --format=json --output="$REPORT_DIR/pip-audit-$env-$DATE.json" || warn "pip-audit failed for $env"
            fi
            
            # Run safety check
            if command -v safety >/dev/null 2>&1; then
                safety check --json --output="$REPORT_DIR/safety-$env-$DATE.json" || warn "safety check failed for $env"
            fi
            
            # Run bandit for static analysis
            if command -v bandit >/dev/null 2>&1; then
                bandit -r "$PROJECT_DIR/src" -f json -o "$REPORT_DIR/bandit-$env-$DATE.json" || warn "bandit scan failed for $env"
            fi
            
            deactivate
        fi
    done
    
    log "✅ Python security scan complete"
}

scan_rust_security() {
    log "🦀 Scanning Rust dependencies for security vulnerabilities..."
    
    cd "$PROJECT_DIR"
    
    # Run cargo audit
    if command -v cargo-audit >/dev/null 2>&1; then
        cargo audit --format json --output "$REPORT_DIR/cargo-audit-$DATE.json" || warn "cargo audit failed"
    fi
    
    # Run cargo deny
    if command -v cargo-deny >/dev/null 2>&1; then
        cargo deny check --format json > "$REPORT_DIR/cargo-deny-$DATE.json" || warn "cargo deny failed"
    fi
    
    log "✅ Rust security scan complete"
}

scan_nodejs_security() {
    log "📦 Scanning Node.js dependencies for security vulnerabilities..."
    
    cd "$PROJECT_DIR"
    
    # Run npm audit
    if [[ -f "package.json" ]]; then
        npm audit --json > "$REPORT_DIR/npm-audit-$DATE.json" || warn "npm audit failed"
    fi
    
    # Check MCP development workspace
    if [[ -f "mcp_development/package.json" ]]; then
        cd "mcp_development"
        npm audit --json > "$REPORT_DIR/npm-audit-mcp-$DATE.json" || warn "npm audit failed for MCP workspace"
        cd ..
    fi
    
    log "✅ Node.js security scan complete"
}

# Dependency update functions
update_python_dependencies() {
    log "🐍 Updating Python dependencies..."
    
    local environments=("venv" "venv_ai" "venv_mcp")
    
    for env in "${environments[@]}"; do
        if [[ -d "$PROJECT_DIR/$env" ]]; then
            info "Updating $env environment..."
            
            source "$PROJECT_DIR/$env/bin/activate"
            
            # Create backup of current requirements
            pip freeze > "$REPORT_DIR/requirements-$env-backup-$DATE.txt"
            
            # Update pip and core tools
            pip install --upgrade pip setuptools wheel
            
            # Update packages (with caution)
            if [[ "$1" == "--aggressive" ]]; then
                pip list --outdated --format=json > "$REPORT_DIR/outdated-$env-$DATE.json"
                warn "Aggressive update mode - review outdated packages manually"
            else
                # Only update security patches
                info "Updating only security-critical packages..."
                pip install --upgrade \
                    cryptography \
                    twisted \
                    certifi \
                    idna \
                    pyjwt \
                    pyyaml \
                    requests || warn "Some security updates failed for $env"
            fi
            
            # Save updated requirements
            pip freeze > "$REPORT_DIR/requirements-$env-updated-$DATE.txt"
            
            deactivate
        fi
    done
    
    log "✅ Python dependencies updated"
}

update_rust_dependencies() {
    log "🦀 Updating Rust dependencies..."
    
    cd "$PROJECT_DIR"
    
    # Backup current lock file
    cp Cargo.lock "$REPORT_DIR/Cargo.lock.backup.$DATE" 2>/dev/null || true
    
    if [[ "$1" == "--aggressive" ]]; then
        # Update all dependencies
        cargo update
        warn "Aggressive Rust update - review changes carefully"
    else
        # Only update patch versions
        cargo update --precise
        info "Updated Rust dependencies with patch versions only"
    fi
    
    # Save updated lock file
    cp Cargo.lock "$REPORT_DIR/Cargo.lock.updated.$DATE" 2>/dev/null || true
    
    log "✅ Rust dependencies updated"
}

update_nodejs_dependencies() {
    log "📦 Updating Node.js dependencies..."
    
    cd "$PROJECT_DIR"
    
    # Backup package-lock.json
    cp package-lock.json "$REPORT_DIR/package-lock.json.backup.$DATE" 2>/dev/null || true
    
    if [[ "$1" == "--aggressive" ]]; then
        # Update all dependencies
        npm update
        warn "Aggressive npm update - review changes carefully"
    else
        # Only security updates
        npm audit fix || warn "npm audit fix failed"
        info "Applied npm security fixes only"
    fi
    
    # Update MCP workspace
    if [[ -d "mcp_development" ]]; then
        cd "mcp_development"
        cp package-lock.json "$REPORT_DIR/mcp-package-lock.json.backup.$DATE" 2>/dev/null || true
        
        if [[ "$1" == "--aggressive" ]]; then
            npm update
        else
            npm audit fix || warn "npm audit fix failed for MCP workspace"
        fi
        
        cp package-lock.json "$REPORT_DIR/mcp-package-lock.json.updated.$DATE" 2>/dev/null || true
        cd ..
    fi
    
    # Save updated package-lock.json
    cp package-lock.json "$REPORT_DIR/package-lock.json.updated.$DATE" 2>/dev/null || true
    
    log "✅ Node.js dependencies updated"
}

# System dependency management
update_system_dependencies() {
    log "🐧 Updating system dependencies..."
    
    # Update package lists
    sudo apt update
    
    # List upgradeable packages
    apt list --upgradeable > "$REPORT_DIR/system-upgradeable-$DATE.txt" 2>/dev/null || true
    
    if [[ "$1" == "--aggressive" ]]; then
        # Full system upgrade
        sudo apt upgrade -y
        sudo apt autoremove -y
        warn "Performed full system upgrade"
    else
        # Only security updates
        sudo apt upgrade -y --with-new-pkgs
        info "Applied security-only system updates"
    fi
    
    # Clean up
    sudo apt autoclean
    
    log "✅ System dependencies updated"
}

# License compliance check
check_license_compliance() {
    log "📄 Checking license compliance..."
    
    # Python license check
    for env in venv venv_ai venv_mcp; do
        if [[ -d "$PROJECT_DIR/$env" ]]; then
            source "$PROJECT_DIR/$env/bin/activate"
            
            if command -v pip-licenses >/dev/null 2>&1; then
                pip-licenses --format=json --output-file="$REPORT_DIR/licenses-$env-$DATE.json" || warn "License check failed for $env"
            else
                pip install pip-licenses
                pip-licenses --format=json --output-file="$REPORT_DIR/licenses-$env-$DATE.json"
            fi
            
            deactivate
        fi
    done
    
    # Rust license check
    cd "$PROJECT_DIR"
    if command -v cargo-license >/dev/null 2>&1; then
        cargo license --json > "$REPORT_DIR/rust-licenses-$DATE.json" || warn "Rust license check failed"
    fi
    
    # Node.js license check
    if command -v license-checker >/dev/null 2>&1; then
        license-checker --json --out "$REPORT_DIR/npm-licenses-$DATE.json" || warn "npm license check failed"
    fi
    
    log "✅ License compliance check complete"
}

# Generate dependency report
generate_dependency_report() {
    log "📊 Generating dependency report..."
    
    local report_file="$REPORT_DIR/dependency-report-$DATE.md"
    
    cat > "$report_file" << EOF
# Dependency Maintenance Report
Generated: $(date)

## Summary
- Project: Claude Optimized Deployment
- Scan Date: $DATE
- Report Location: $REPORT_DIR

## Security Scans
$(if [[ -f "$REPORT_DIR/pip-audit-venv-$DATE.json" ]]; then echo "✅ Python pip-audit completed"; else echo "❌ Python pip-audit failed"; fi)
$(if [[ -f "$REPORT_DIR/cargo-audit-$DATE.json" ]]; then echo "✅ Rust cargo audit completed"; else echo "❌ Rust cargo audit failed"; fi)
$(if [[ -f "$REPORT_DIR/npm-audit-$DATE.json" ]]; then echo "✅ Node.js npm audit completed"; else echo "❌ Node.js npm audit failed"; fi)

## Updates Applied
- Python environments: $(ls "$REPORT_DIR"/requirements-*-updated-$DATE.txt 2>/dev/null | wc -l) environments updated
- Rust dependencies: $(if [[ -f "$REPORT_DIR/Cargo.lock.updated.$DATE" ]]; then echo "Updated"; else echo "No changes"; fi)
- Node.js dependencies: $(if [[ -f "$REPORT_DIR/package-lock.json.updated.$DATE" ]]; then echo "Updated"; else echo "No changes"; fi)

## Files Generated
$(ls -la "$REPORT_DIR"/*$DATE* 2>/dev/null || echo "No files generated")

## Recommendations
1. Review security scan results for any HIGH or CRITICAL vulnerabilities
2. Test application functionality after dependency updates
3. Update documentation if API changes occurred
4. Consider dependency pinning for critical packages
5. Schedule next maintenance check

## Next Steps
- Review all generated reports in: $REPORT_DIR
- Test the application: ./scripts/run-tests.sh
- Commit changes if tests pass: git add . && git commit -m "deps: dependency maintenance $DATE"
EOF

    log "✅ Dependency report generated: $report_file"
}

# Main execution
show_usage() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  scan      - Run security scans only"
    echo "  update    - Update dependencies (security patches only)"
    echo "  update --aggressive - Update all dependencies (use with caution)"
    echo "  full      - Run full maintenance (scan + update + report)"
    echo "  report    - Generate dependency report only"
    echo "  licenses  - Check license compliance"
    echo ""
    echo "Examples:"
    echo "  $0 scan                    # Security scan only"
    echo "  $0 update                  # Security updates only"
    echo "  $0 update --aggressive     # Update all dependencies"
    echo "  $0 full                    # Complete maintenance cycle"
}

main() {
    local command=${1:-""}
    local option=${2:-""}
    
    case $command in
        "scan")
            log "🔍 Running security scans..."
            scan_python_security
            scan_rust_security
            scan_nodejs_security
            ;;
        "update")
            log "🔄 Updating dependencies..."
            update_python_dependencies "$option"
            update_rust_dependencies "$option"
            update_nodejs_dependencies "$option"
            if [[ "$option" == "--aggressive" ]]; then
                update_system_dependencies "$option"
            fi
            ;;
        "full")
            log "🚀 Running full dependency maintenance..."
            scan_python_security
            scan_rust_security
            scan_nodejs_security
            update_python_dependencies "$option"
            update_rust_dependencies "$option"
            update_nodejs_dependencies "$option"
            check_license_compliance
            generate_dependency_report
            ;;
        "report")
            generate_dependency_report
            ;;
        "licenses")
            check_license_compliance
            ;;
        *)
            show_usage
            exit 1
            ;;
    esac
    
    log "✅ Dependency maintenance complete!"
    info "Reports available in: $REPORT_DIR"
}

# Ensure we're in the right directory
cd "$PROJECT_DIR" || error "Could not change to project directory: $PROJECT_DIR"

main "$@"