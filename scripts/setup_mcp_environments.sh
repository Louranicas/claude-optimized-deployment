#!/bin/bash
# Setup Python Virtual Environments for MCP Servers
# This script creates isolated environments for MCP development and deployment

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_BASE_DIR="${PROJECT_ROOT}/venvs"
PYTHON_VERSION="python3.12"

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
    echo -e "${BLUE}[SETUP]${NC} $1"
}

# Check if Python is available
check_python() {
    print_header "Checking Python installation..."
    
    if ! command -v $PYTHON_VERSION &> /dev/null; then
        if ! command -v python3 &> /dev/null; then
            print_error "Python 3 is not installed or not in PATH"
            exit 1
        else
            PYTHON_VERSION="python3"
            print_warning "Using python3 instead of python3.12"
        fi
    fi
    
    PYTHON_PATH=$(which $PYTHON_VERSION)
    PYTHON_VER=$($PYTHON_VERSION --version)
    print_status "Using Python: $PYTHON_PATH ($PYTHON_VER)"
}

# Create virtual environment
create_venv() {
    local env_name=$1
    local env_path="${VENV_BASE_DIR}/${env_name}"
    
    print_header "Creating virtual environment: $env_name"
    
    if [ -d "$env_path" ]; then
        print_warning "Virtual environment $env_name already exists, removing..."
        rm -rf "$env_path"
    fi
    
    mkdir -p "$VENV_BASE_DIR"
    $PYTHON_VERSION -m venv "$env_path"
    print_status "Created virtual environment at: $env_path"
}

# Activate virtual environment and install dependencies
install_dependencies() {
    local env_name=$1
    local requirements_file=$2
    local env_path="${VENV_BASE_DIR}/${env_name}"
    
    print_header "Installing dependencies for $env_name"
    
    # Activate environment
    source "${env_path}/bin/activate"
    
    # Upgrade pip and setuptools
    pip install --upgrade pip setuptools wheel
    
    # Install requirements
    if [ -f "$requirements_file" ]; then
        print_status "Installing from $requirements_file"
        pip install -r "$requirements_file"
    else
        print_warning "Requirements file not found: $requirements_file"
    fi
    
    # Install project in development mode if in main environment
    if [ "$env_name" = "mcp_main" ]; then
        print_status "Installing project in development mode"
        pip install -e "${PROJECT_ROOT}[mcp_servers,mcp_dev]"
    fi
    
    # Deactivate environment
    deactivate
    
    print_status "Dependencies installed for $env_name"
}

# Create activation script
create_activation_script() {
    local env_name=$1
    local env_path="${VENV_BASE_DIR}/${env_name}"
    local script_path="${PROJECT_ROOT}/scripts/activate_${env_name}.sh"
    
    print_header "Creating activation script for $env_name"
    
    cat > "$script_path" << EOF
#!/bin/bash
# Activation script for $env_name virtual environment
# Usage: source scripts/activate_${env_name}.sh

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ -f "${env_path}/bin/activate" ]; then
    source "${env_path}/bin/activate"
    echo -e "\${GREEN}[ACTIVATED]\${NC} $env_name virtual environment"
    echo -e "\${YELLOW}[INFO]\${NC} Python: \$(which python)"
    echo -e "\${YELLOW}[INFO]\${NC} Pip: \$(which pip)"
    echo -e "\${YELLOW}[INFO]\${NC} To deactivate, run: deactivate"
else
    echo -e "\${RED}[ERROR]\${NC} Virtual environment not found: ${env_path}"
    exit 1
fi
EOF
    
    chmod +x "$script_path"
    print_status "Created activation script: $script_path"
}

# Create environment management script
create_management_script() {
    local script_path="${PROJECT_ROOT}/scripts/manage_mcp_envs.sh"
    
    print_header "Creating environment management script"
    
    cat > "$script_path" << 'EOF'
#!/bin/bash
# MCP Environment Management Script
# Manage multiple Python virtual environments for MCP development

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_BASE_DIR="${PROJECT_ROOT}/venvs"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

show_help() {
    echo "MCP Environment Management"
    echo "Usage: $0 [COMMAND] [ENVIRONMENT]"
    echo ""
    echo "Commands:"
    echo "  list                    List all virtual environments"
    echo "  activate <env>          Show activation command for environment"
    echo "  status <env>            Show environment status and packages"
    echo "  update <env>            Update packages in environment"
    echo "  remove <env>            Remove virtual environment"
    echo "  cleanup                 Remove all virtual environments"
    echo ""
    echo "Environments:"
    echo "  mcp_main               Main MCP development environment"
    echo "  mcp_bash_god           Bash God server environment"
    echo "  mcp_devops             DevOps server environment"
    echo "  mcp_quality            Quality server environment"
    echo "  mcp_development        Development server environment"
    echo "  mcp_testing            Testing environment"
}

list_envs() {
    echo -e "${BLUE}[ENVIRONMENTS]${NC} Available virtual environments:"
    
    if [ ! -d "$VENV_BASE_DIR" ]; then
        echo -e "${YELLOW}[INFO]${NC} No virtual environments found"
        return
    fi
    
    for env_dir in "$VENV_BASE_DIR"/*; do
        if [ -d "$env_dir" ]; then
            env_name=$(basename "$env_dir")
            if [ -f "$env_dir/bin/activate" ]; then
                echo -e "${GREEN}✓${NC} $env_name"
            else
                echo -e "${RED}✗${NC} $env_name (corrupted)"
            fi
        fi
    done
}

show_activation() {
    local env_name=$1
    local activation_script="${PROJECT_ROOT}/scripts/activate_${env_name}.sh"
    
    echo -e "${BLUE}[ACTIVATE]${NC} To activate $env_name environment:"
    echo "source scripts/activate_${env_name}.sh"
    echo ""
    echo "Or manually:"
    echo "source venvs/${env_name}/bin/activate"
}

show_status() {
    local env_name=$1
    local env_path="${VENV_BASE_DIR}/${env_name}"
    
    echo -e "${BLUE}[STATUS]${NC} Environment: $env_name"
    
    if [ ! -d "$env_path" ]; then
        echo -e "${RED}[ERROR]${NC} Environment not found: $env_path"
        return 1
    fi
    
    # Activate and show info
    source "${env_path}/bin/activate"
    
    echo "Python: $(which python)"
    echo "Python Version: $(python --version)"
    echo "Pip Version: $(pip --version)"
    echo ""
    echo "Installed packages:"
    pip list | head -20
    
    deactivate
}

update_env() {
    local env_name=$1
    local env_path="${VENV_BASE_DIR}/${env_name}"
    
    echo -e "${BLUE}[UPDATE]${NC} Updating environment: $env_name"
    
    if [ ! -d "$env_path" ]; then
        echo -e "${RED}[ERROR]${NC} Environment not found: $env_path"
        return 1
    fi
    
    source "${env_path}/bin/activate"
    
    echo "Upgrading pip and core packages..."
    pip install --upgrade pip setuptools wheel
    
    echo "Upgrading all packages..."
    pip list --outdated --format=freeze | grep -v '^\-e' | cut -d = -f 1 | xargs -n1 pip install -U
    
    deactivate
    
    echo -e "${GREEN}[SUCCESS]${NC} Environment $env_name updated"
}

remove_env() {
    local env_name=$1
    local env_path="${VENV_BASE_DIR}/${env_name}"
    
    echo -e "${YELLOW}[REMOVE]${NC} Removing environment: $env_name"
    
    if [ ! -d "$env_path" ]; then
        echo -e "${RED}[ERROR]${NC} Environment not found: $env_path"
        return 1
    fi
    
    read -p "Are you sure you want to remove $env_name? (y/N): " confirm
    if [[ $confirm =~ ^[Yy]$ ]]; then
        rm -rf "$env_path"
        rm -f "${PROJECT_ROOT}/scripts/activate_${env_name}.sh"
        echo -e "${GREEN}[SUCCESS]${NC} Environment $env_name removed"
    else
        echo "Cancelled"
    fi
}

cleanup_all() {
    echo -e "${YELLOW}[CLEANUP]${NC} Removing all virtual environments"
    
    read -p "Are you sure you want to remove ALL environments? (y/N): " confirm
    if [[ $confirm =~ ^[Yy]$ ]]; then
        if [ -d "$VENV_BASE_DIR" ]; then
            rm -rf "$VENV_BASE_DIR"
        fi
        rm -f "${PROJECT_ROOT}/scripts/activate_mcp_"*.sh
        echo -e "${GREEN}[SUCCESS]${NC} All environments removed"
    else
        echo "Cancelled"
    fi
}

# Main command processing
case "${1:-help}" in
    list)
        list_envs
        ;;
    activate)
        if [ $# -lt 2 ]; then
            echo -e "${RED}[ERROR]${NC} Environment name required"
            exit 1
        fi
        show_activation "$2"
        ;;
    status)
        if [ $# -lt 2 ]; then
            echo -e "${RED}[ERROR]${NC} Environment name required"
            exit 1
        fi
        show_status "$2"
        ;;
    update)
        if [ $# -lt 2 ]; then
            echo -e "${RED}[ERROR]${NC} Environment name required"
            exit 1
        fi
        update_env "$2"
        ;;
    remove)
        if [ $# -lt 2 ]; then
            echo -e "${RED}[ERROR]${NC} Environment name required"
            exit 1
        fi
        remove_env "$2"
        ;;
    cleanup)
        cleanup_all
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo -e "${RED}[ERROR]${NC} Unknown command: $1"
        show_help
        exit 1
        ;;
esac
EOF
    
    chmod +x "$script_path"
    print_status "Created management script: $script_path"
}

# Main setup function
main() {
    print_header "Setting up MCP Python Virtual Environments"
    
    # Check prerequisites
    check_python
    
    # Create base directory
    mkdir -p "$VENV_BASE_DIR"
    
    # Define environments and their requirements
    declare -A environments=(
        ["mcp_main"]="${PROJECT_ROOT}/requirements-mcp-core.txt"
        ["mcp_bash_god"]="${PROJECT_ROOT}/requirements-mcp-servers.txt"
        ["mcp_devops"]="${PROJECT_ROOT}/requirements-mcp-servers.txt"
        ["mcp_quality"]="${PROJECT_ROOT}/requirements-mcp-servers.txt"
        ["mcp_development"]="${PROJECT_ROOT}/requirements-mcp-servers.txt"
        ["mcp_testing"]="${PROJECT_ROOT}/requirements-mcp-testing.txt"
    )
    
    # Create environments
    for env_name in "${!environments[@]}"; do
        requirements_file="${environments[$env_name]}"
        
        create_venv "$env_name"
        install_dependencies "$env_name" "$requirements_file"
        create_activation_script "$env_name"
    done
    
    # Create management script
    create_management_script
    
    print_header "Setup Complete!"
    print_status "Virtual environments created in: $VENV_BASE_DIR"
    print_status "To activate an environment, run: source scripts/activate_<env_name>.sh"
    print_status "To manage environments, run: scripts/manage_mcp_envs.sh"
    
    echo ""
    print_header "Available environments:"
    for env_name in "${!environments[@]}"; do
        echo -e "  ${GREEN}$env_name${NC}"
    done
    
    echo ""
    print_header "Next steps:"
    echo "1. Activate main environment: source scripts/activate_mcp_main.sh"
    echo "2. Verify installation: python -c 'import mcp; print(\"MCP imported successfully\")'"
    echo "3. Run tests: pytest tests/"
}

# Run main function
main "$@"