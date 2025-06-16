#!/bin/bash
# Quick MCP Production Deployment Script
# Agent 9 - Production Deployment Orchestration

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] ✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] ⚠️ $1${NC}"
}

log_error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ❌ $1${NC}"
}

# Check if script is run from correct directory
if [[ ! -f "deploy-mcp-production.py" ]]; then
    log_error "Please run this script from the project root directory"
    exit 1
fi

log "🚀 MCP Production Deployment Quick Start"
log "💻 Optimized for AMD Ryzen 7 7800X3D (16 cores, 32GB RAM)"

# Make the deployment script executable
chmod +x deploy-mcp-production.py

# Check Python availability
if ! command -v python3 &> /dev/null; then
    log_error "Python3 is required but not installed"
    exit 1
fi

# Check Docker availability
if ! command -v docker &> /dev/null; then
    log_error "Docker is required but not installed"
    exit 1
fi

# Check kubectl availability
if ! command -v kubectl &> /dev/null; then
    log_error "kubectl is required but not installed"
    exit 1
fi

# Check if Docker daemon is running
if ! docker info &> /dev/null; then
    log_error "Docker daemon is not running"
    exit 1
fi

# Check Kubernetes cluster connectivity
if ! kubectl cluster-info &> /dev/null; then
    log_error "Cannot connect to Kubernetes cluster"
    exit 1
fi

log_success "All prerequisites checked - ready for deployment"

# Option to run in different modes
case "${1:-full}" in
    "build-only")
        log "🐳 Building container images only..."
        docker build -f Dockerfile.python-production -t mcp-python-server:production .
        docker build -f mcp_servers/Dockerfile.typescript-production -t mcp-typescript-server:optimized ./mcp_servers/
        docker build -f Dockerfile.rust-production -t mcp-rust-server:amd-optimized . || log_warning "Rust build may fail if source is not available"
        log_success "Container images built successfully"
        ;;
    "deploy-only")
        log "☸️ Deploying to Kubernetes only..."
        kubectl apply -f k8s/mcp-namespace.yaml
        kubectl apply -f k8s/mcp-rbac.yaml
        kubectl apply -f k8s/mcp-services.yaml
        kubectl apply -f k8s/mcp-deployments.yaml
        kubectl apply -f k8s/mcp-hpa.yaml
        kubectl apply -f k8s/mcp-monitoring.yaml
        log_success "Kubernetes manifests applied successfully"
        ;;
    "full"|*)
        log "🎯 Running full production deployment orchestration..."
        python3 deploy-mcp-production.py
        ;;
esac

# Show deployment status
log "📊 Current deployment status:"
kubectl get pods -n mcp-production 2>/dev/null || log_warning "MCP production namespace not found"
kubectl get services -n mcp-production 2>/dev/null || log_warning "MCP services not found"
kubectl get hpa -n mcp-production 2>/dev/null || log_warning "MCP HPAs not found"

log_success "MCP Production Deployment completed!"
log "🔗 Next steps:"
log "  1. Check pod status: kubectl get pods -n mcp-production"
log "  2. View logs: kubectl logs -f deployment/mcp-typescript-server -n mcp-production"
log "  3. Access services: kubectl port-forward service/mcp-gateway 8080:80 -n mcp-production"
log "  4. Monitor metrics: Check Grafana dashboards for performance metrics"
log "  5. Scale if needed: kubectl scale deployment mcp-typescript-server --replicas=5 -n mcp-production"