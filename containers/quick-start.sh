#!/bin/bash
# Quick Start Script for Claude Optimized Deployment Containers
# Optimized for 32GB RAM and NVMe storage

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check system resources
check_resources() {
    print_status "Checking system resources..."
    
    # Check available memory
    TOTAL_MEM=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$TOTAL_MEM" -lt 30 ]; then
        print_warning "System has less than 30GB RAM. Performance may be affected."
    fi
    
    # Check Docker installation
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check Docker Compose installation
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    print_status "System check completed successfully."
}

# Create necessary directories
setup_directories() {
    print_status "Creating necessary directories..."
    
    # Development directories
    mkdir -p logs/dev
    mkdir -p data/dev
    mkdir -p cache/dev
    
    # Production directories
    mkdir -p logs/prod
    mkdir -p data/prod
    mkdir -p mcp_logs
    mkdir -p mcp_data
    mkdir -p mcp_config
    mkdir -p ssl
    
    # Set permissions
    chmod -R 755 logs data cache mcp_logs mcp_data
    
    print_status "Directories created successfully."
}

# Build development containers
build_dev_containers() {
    print_status "Building development containers..."
    
    # Build Rust development container
    print_status "Building Rust development container..."
    docker build -f development/Dockerfile.rust-dev -t claude-rust-dev:latest ..
    
    # Build Python ML container
    print_status "Building Python ML container..."
    docker build -f development/Dockerfile.python-ml -t claude-python-ml:latest ..
    
    # Build MCP server container
    print_status "Building MCP server container..."
    docker build -f development/Dockerfile.mcp-server -t claude-mcp-dev:latest ..
    
    print_status "Development containers built successfully."
}

# Build production containers
build_prod_containers() {
    print_status "Building production containers..."
    
    # Build Rust service
    print_status "Building Rust service container..."
    docker build -f production/Dockerfile.rust-service -t claude-rust-prod:latest ..
    
    # Build Python API
    print_status "Building Python API container..."
    docker build -f production/Dockerfile.python-api -t claude-python-api:latest ..
    
    # Build MCP servers
    print_status "Building MCP servers container..."
    docker build -f production/Dockerfile.mcp-server-prod -t claude-mcp-prod:latest ..
    
    print_status "Production containers built successfully."
}

# Start development environment
start_dev() {
    print_status "Starting development environment..."
    
    # Create network if it doesn't exist
    docker network create development 2>/dev/null || true
    
    # Start base services
    print_status "Starting base development services..."
    docker-compose -f development/docker-compose.dev.yml up -d
    
    # Wait for services to be ready
    print_status "Waiting for services to be ready..."
    sleep 10
    
    # Start MCP servers
    print_status "Starting MCP development servers..."
    docker-compose -f development/docker-compose.mcp.yml up -d
    
    print_status "Development environment started successfully."
    print_status "Services available at:"
    echo "  - Rust Dev: http://localhost:8000"
    echo "  - Python ML Jupyter: http://localhost:8888"
    echo "  - PostgreSQL: localhost:5432"
    echo "  - Redis: localhost:6379"
    echo "  - MCP Servers: localhost:3000-3009"
    echo "  - Grafana: http://localhost:3001 (admin/dev_password)"
}

# Start production environment
start_prod() {
    print_status "Starting production environment..."
    
    # Check for required environment variables
    if [ -z "$DB_PASSWORD" ] || [ -z "$SECRET_KEY" ] || [ -z "$ELASTIC_PASSWORD" ]; then
        print_error "Required environment variables not set. Please set:"
        echo "  - DB_PASSWORD"
        echo "  - SECRET_KEY"
        echo "  - ELASTIC_PASSWORD"
        exit 1
    fi
    
    # Create networks if they don't exist
    docker network create web 2>/dev/null || true
    docker network create internal 2>/dev/null || true
    
    # Start production services
    print_status "Starting production services..."
    docker-compose -f production/docker-compose.prod.yml up -d
    
    # Start MCP production services
    print_status "Starting MCP production servers..."
    docker-compose -f production/docker-compose.mcp-prod.yml up -d
    
    print_status "Production environment started successfully."
}

# Stop all containers
stop_all() {
    print_status "Stopping all containers..."
    
    # Stop development containers
    docker-compose -f development/docker-compose.dev.yml down
    docker-compose -f development/docker-compose.mcp.yml down
    
    # Stop production containers
    docker-compose -f production/docker-compose.prod.yml down
    docker-compose -f production/docker-compose.mcp-prod.yml down
    
    print_status "All containers stopped."
}

# Clean up resources
cleanup() {
    print_status "Cleaning up resources..."
    
    # Remove stopped containers
    docker container prune -f
    
    # Remove unused images
    docker image prune -f
    
    # Remove unused volumes (careful with this!)
    read -p "Remove unused volumes? This will delete data! (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker volume prune -f
    fi
    
    print_status "Cleanup completed."
}

# Run tests in containers
run_tests() {
    print_status "Running tests in containers..."
    
    # Run Rust tests
    print_status "Running Rust tests..."
    docker-compose -f development/docker-compose.dev.yml exec rust-dev cargo test
    
    # Run Python tests
    print_status "Running Python tests..."
    docker-compose -f development/docker-compose.dev.yml exec python-ml python -m pytest
    
    # Run MCP server tests
    print_status "Running MCP server tests..."
    docker-compose -f development/docker-compose.mcp.yml exec mcp-dev npm test
    
    print_status "All tests completed."
}

# Show usage
usage() {
    echo "Usage: $0 {check|setup|build-dev|build-prod|dev|prod|stop|cleanup|test}"
    echo ""
    echo "Commands:"
    echo "  check      - Check system resources and dependencies"
    echo "  setup      - Set up necessary directories"
    echo "  build-dev  - Build development containers"
    echo "  build-prod - Build production containers"
    echo "  dev        - Start development environment"
    echo "  prod       - Start production environment"
    echo "  stop       - Stop all containers"
    echo "  cleanup    - Clean up Docker resources"
    echo "  test       - Run tests in containers"
    echo ""
    echo "Quick start for development:"
    echo "  $0 check && $0 setup && $0 build-dev && $0 dev"
}

# Main script logic
case "$1" in
    check)
        check_resources
        ;;
    setup)
        setup_directories
        ;;
    build-dev)
        build_dev_containers
        ;;
    build-prod)
        build_prod_containers
        ;;
    dev)
        start_dev
        ;;
    prod)
        start_prod
        ;;
    stop)
        stop_all
        ;;
    cleanup)
        cleanup
        ;;
    test)
        run_tests
        ;;
    *)
        usage
        exit 1
        ;;
esac

exit 0