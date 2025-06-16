#!/bin/bash
# MCP Dependency Management Script
# Manages Python dependencies using pip-tools for reproducible builds

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PATH="${PROJECT_ROOT}/venv_mcp_main"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}[DEPS]${NC} $1"
}

# Function to activate virtual environment
activate_venv() {
    if [ ! -f "$VENV_PATH/bin/activate" ]; then
        print_error "Virtual environment not found: $VENV_PATH"
        print_error "Run setup_mcp_environments.sh first"
        exit 1
    fi
    source "$VENV_PATH/bin/activate"
    print_status "Activated virtual environment: $VENV_PATH"
}

# Function to compile requirements
compile_requirements() {
    local input_file=$1
    local output_file=$2
    
    print_header "Compiling $input_file -> $output_file"
    
    pip-compile "$input_file" --output-file="$output_file" --strip-extras
    
    if [ $? -eq 0 ]; then
        print_status "Successfully compiled $output_file"
    else
        print_error "Failed to compile $output_file"
        return 1
    fi
}

# Function to sync environment with requirements
sync_requirements() {
    local requirements_file=$1
    
    print_header "Syncing environment with $requirements_file"
    
    pip-sync "$requirements_file"
    
    if [ $? -eq 0 ]; then
        print_status "Successfully synced environment"
    else
        print_error "Failed to sync environment"
        return 1
    fi
}

# Function to update all requirements
update_all() {
    print_header "Updating all dependency files"
    
    cd "$PROJECT_ROOT"
    
    # Compile main requirements
    compile_requirements "requirements.in" "requirements.txt"
    
    # Compile development requirements
    compile_requirements "requirements-dev.in" "requirements-dev.txt"
    
    # Compile MCP-specific requirements
    if [ -f "requirements-mcp-core.in" ]; then
        compile_requirements "requirements-mcp-core.in" "requirements-mcp-core.txt"
    fi
    
    if [ -f "requirements-mcp-servers.in" ]; then
        compile_requirements "requirements-mcp-servers.in" "requirements-mcp-servers.txt"
    fi
    
    if [ -f "requirements-mcp-testing.in" ]; then
        compile_requirements "requirements-mcp-testing.in" "requirements-mcp-testing.txt"
    fi
    
    if [ -f "requirements-mcp-development.in" ]; then
        compile_requirements "requirements-mcp-development.in" "requirements-mcp-development.txt"
    fi
    
    print_status "All requirement files updated"
}

# Function to upgrade specific package
upgrade_package() {
    local package_name=$1
    
    print_header "Upgrading package: $package_name"
    
    # Upgrade in .in files
    for req_file in requirements*.in; do
        if [ -f "$req_file" ]; then
            if grep -q "^$package_name" "$req_file"; then
                print_status "Found $package_name in $req_file"
                # Get the latest version
                latest_version=$(pip index versions "$package_name" | head -1 | sed 's/.*(//' | sed 's/).*//')
                if [ -n "$latest_version" ]; then
                    # Update the version constraint
                    sed -i "s/^$package_name>=.*/$package_name>=$latest_version/" "$req_file"
                    print_status "Updated $package_name to >=$latest_version in $req_file"
                fi
            fi
        fi
    done
    
    # Recompile all requirements
    update_all
}

# Function to add new package
add_package() {
    local package_name=$1
    local category=${2:-"main"}
    
    print_header "Adding package: $package_name to $category"
    
    case $category in
        "main"|"core")
            req_file="requirements.in"
            ;;
        "dev"|"development")
            req_file="requirements-dev.in"
            ;;
        "mcp-core")
            req_file="requirements-mcp-core.in"
            ;;
        "mcp-servers")
            req_file="requirements-mcp-servers.in"
            ;;
        "mcp-testing")
            req_file="requirements-mcp-testing.in"
            ;;
        "mcp-dev")
            req_file="requirements-mcp-development.in"
            ;;
        *)
            print_error "Unknown category: $category"
            print_error "Valid categories: main, dev, mcp-core, mcp-servers, mcp-testing, mcp-dev"
            return 1
            ;;
    esac
    
    if [ ! -f "$req_file" ]; then
        print_error "Requirements file not found: $req_file"
        return 1
    fi
    
    # Get the latest version
    latest_version=$(pip index versions "$package_name" | head -1 | sed 's/.*(//' | sed 's/).*//')
    if [ -n "$latest_version" ]; then
        echo "$package_name>=$latest_version" >> "$req_file"
        print_status "Added $package_name>=$latest_version to $req_file"
        
        # Recompile requirements
        update_all
    else
        print_error "Could not find package: $package_name"
        return 1
    fi
}

# Function to check for outdated packages
check_outdated() {
    print_header "Checking for outdated packages"
    
    pip list --outdated --format=json | python3 -c "
import json
import sys

data = json.load(sys.stdin)
if not data:
    print('All packages are up to date!')
else:
    print(f'Found {len(data)} outdated packages:')
    print()
    for pkg in data:
        print(f'  {pkg[\"name\"]:30} {pkg[\"version\"]:15} -> {pkg[\"latest_version\"]}')
"
}

# Function to generate dependency tree
show_tree() {
    print_header "Dependency tree"
    
    if command -v pipdeptree &> /dev/null; then
        pipdeptree
    else
        print_warning "pipdeptree not installed. Installing..."
        pip install pipdeptree
        pipdeptree
    fi
}

# Function to audit dependencies for security issues
audit_security() {
    print_header "Security audit of dependencies"
    
    if command -v pip-audit &> /dev/null; then
        pip-audit --format=table
    else
        print_warning "pip-audit not installed. Installing..."
        pip install pip-audit
        pip-audit --format=table
    fi
}

# Function to show help
show_help() {
    echo "MCP Dependency Management"
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  update                  Update all requirement files"
    echo "  sync [file]             Sync environment with requirements file"
    echo "  upgrade <package>       Upgrade specific package"
    echo "  add <package> [category] Add new package to requirements"
    echo "  outdated                Check for outdated packages"
    echo "  tree                    Show dependency tree"
    echo "  audit                   Security audit of dependencies"
    echo "  check                   Check all requirement files for issues"
    echo ""
    echo "Categories for add command:"
    echo "  main, core              Main requirements.in"
    echo "  dev, development        Development requirements"
    echo "  mcp-core               MCP core dependencies"
    echo "  mcp-servers            MCP server dependencies"
    echo "  mcp-testing            MCP testing dependencies"
    echo "  mcp-dev               MCP development dependencies"
    echo ""
    echo "Examples:"
    echo "  $0 update"
    echo "  $0 sync requirements.txt"
    echo "  $0 upgrade fastapi"
    echo "  $0 add requests main"
    echo "  $0 add pytest-mock mcp-testing"
}

# Function to check requirement files
check_requirements() {
    print_header "Checking requirement files for issues"
    
    local issues_found=0
    
    for req_file in requirements*.txt; do
        if [ -f "$req_file" ]; then
            print_status "Checking $req_file"
            
            # Check for duplicate packages
            duplicates=$(cut -d'=' -f1 "$req_file" | sort | uniq -d)
            if [ -n "$duplicates" ]; then
                print_warning "Duplicate packages in $req_file: $duplicates"
                ((issues_found++))
            fi
            
            # Check for packages with no version constraints
            no_version=$(grep -E '^[a-zA-Z0-9_-]+$' "$req_file" || true)
            if [ -n "$no_version" ]; then
                print_warning "Packages without version constraints in $req_file: $no_version"
                ((issues_found++))
            fi
        fi
    done
    
    if [ $issues_found -eq 0 ]; then
        print_status "No issues found in requirement files"
    else
        print_warning "Found $issues_found issues in requirement files"
    fi
    
    return $issues_found
}

# Main command processing
main() {
    cd "$PROJECT_ROOT"
    
    case "${1:-help}" in
        update)
            activate_venv
            update_all
            ;;
        sync)
            activate_venv
            if [ $# -lt 2 ]; then
                sync_requirements "requirements.txt"
            else
                sync_requirements "$2"
            fi
            ;;
        upgrade)
            if [ $# -lt 2 ]; then
                print_error "Package name required"
                exit 1
            fi
            activate_venv
            upgrade_package "$2"
            ;;
        add)
            if [ $# -lt 2 ]; then
                print_error "Package name required"
                exit 1
            fi
            activate_venv
            add_package "$2" "${3:-main}"
            ;;
        outdated)
            activate_venv
            check_outdated
            ;;
        tree)
            activate_venv
            show_tree
            ;;
        audit)
            activate_venv
            audit_security
            ;;
        check)
            check_requirements
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            print_error "Unknown command: $1"
            show_help
            exit 1
            ;;
    esac
}

# Run main function
main "$@"