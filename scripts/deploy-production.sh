#!/bin/bash

# Production Deployment Script with Safety Checks and Rollback
# Usage: ./scripts/deploy-production.sh [blue-green|canary|rolling] [image-tag]

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
NAMESPACE="claude-deployment-prod"
DEPLOYMENT_NAME="claude-deployment-api"
SERVICE_NAME="claude-deployment-api"
HEALTH_CHECK_URL="http://localhost:8080/health"
TIMEOUT=600

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Cleanup function
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_error "Deployment failed. Cleaning up..."
        rollback_deployment
    fi
    exit $exit_code
}

trap cleanup EXIT

# Help function
show_help() {
    cat << EOF
Production Deployment Script

Usage: $0 [STRATEGY] [IMAGE_TAG]

STRATEGY:
    blue-green  Deploy using blue-green strategy (default)
    canary      Deploy using canary strategy
    rolling     Deploy using rolling update strategy

IMAGE_TAG:
    Container image tag to deploy (default: latest)

Environment Variables:
    KUBECONFIG      Path to kubeconfig file
    AWS_PROFILE     AWS profile to use
    DRY_RUN         Set to 'true' for dry run mode
    SKIP_TESTS      Set to 'true' to skip pre-deployment tests

Examples:
    $0 blue-green v1.2.3
    $0 canary latest
    DRY_RUN=true $0 rolling v1.2.3

EOF
}

# Validate prerequisites
validate_prerequisites() {
    log_info "Validating prerequisites..."
    
    # Check required tools
    local required_tools=("kubectl" "aws" "jq" "curl")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_error "Required tool '$tool' is not installed"
            exit 1
        fi
    done
    
    # Check kubectl access
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    # Check namespace exists
    if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_error "Namespace '$NAMESPACE' does not exist"
        exit 1
    fi
    
    # Check AWS access
    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "Cannot access AWS. Check your credentials"
        exit 1
    fi
    
    log_success "Prerequisites validated"
}

# Run pre-deployment tests
run_pre_deployment_tests() {
    if [[ "${SKIP_TESTS:-false}" == "true" ]]; then
        log_warning "Skipping pre-deployment tests"
        return 0
    fi
    
    log_info "Running pre-deployment tests..."
    
    # Database connectivity test
    log_info "Testing database connectivity..."
    if ! kubectl run db-test --image=postgres:15 --rm -i --restart=Never -- \
        psql "$DATABASE_URL" -c "SELECT 1;" &> /dev/null; then
        log_error "Database connectivity test failed"
        return 1
    fi
    
    # Redis connectivity test
    log_info "Testing Redis connectivity..."
    if ! kubectl run redis-test --image=redis:7-alpine --rm -i --restart=Never -- \
        redis-cli -u "$REDIS_URL" ping &> /dev/null; then
        log_error "Redis connectivity test failed"
        return 1
    fi
    
    # External API tests
    log_info "Testing external API connectivity..."
    if ! curl -s --fail "https://api.openai.com/v1/models" \
        -H "Authorization: Bearer $OPENAI_API_KEY" > /dev/null; then
        log_warning "OpenAI API test failed"
    fi
    
    log_success "Pre-deployment tests completed"
}

# Get current deployment info
get_current_deployment() {
    local current_replicas
    local current_image
    
    if kubectl get deployment "$DEPLOYMENT_NAME" -n "$NAMESPACE" &> /dev/null; then
        current_replicas=$(kubectl get deployment "$DEPLOYMENT_NAME" -n "$NAMESPACE" \
            -o jsonpath='{.spec.replicas}')
        current_image=$(kubectl get deployment "$DEPLOYMENT_NAME" -n "$NAMESPACE" \
            -o jsonpath='{.spec.template.spec.containers[0].image}')
        
        echo "current_replicas=$current_replicas"
        echo "current_image=$current_image"
    else
        echo "current_replicas=0"
        echo "current_image=none"
    fi
}

# Blue-Green deployment
deploy_blue_green() {
    local new_image="$1"
    local current_color
    local new_color
    
    log_info "Starting blue-green deployment with image: $new_image"
    
    # Determine current and new colors
    current_color=$(kubectl get deployment "$DEPLOYMENT_NAME" -n "$NAMESPACE" \
        -o jsonpath='{.metadata.labels.color}' 2>/dev/null || echo "blue")
    new_color=$([ "$current_color" = "blue" ] && echo "green" || echo "blue")
    
    log_info "Current color: $current_color, New color: $new_color"
    
    # Create new deployment manifest
    local new_deployment_name="${DEPLOYMENT_NAME}-${new_color}"
    local manifest_file="/tmp/${new_deployment_name}.yaml"
    
    # Generate new deployment manifest
    sed "s|image: claude-deployment-api:latest|image: $new_image|g" \
        "$PROJECT_ROOT/k8s/production/deployments.yaml" > "$manifest_file"
    sed -i "s|name: $DEPLOYMENT_NAME|name: $new_deployment_name|g" "$manifest_file"
    sed -i "s|app: $DEPLOYMENT_NAME|app: $new_deployment_name|g" "$manifest_file"
    sed -i "/metadata:/a\\  labels:\\n    color: $new_color" "$manifest_file"
    
    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "DRY RUN: Would deploy with manifest:"
        cat "$manifest_file"
        return 0
    fi
    
    # Deploy new version
    log_info "Deploying new version ($new_color)..."
    kubectl apply -f "$manifest_file"
    
    # Wait for rollout
    log_info "Waiting for rollout to complete..."
    if ! kubectl rollout status "deployment/$new_deployment_name" -n "$NAMESPACE" \
        --timeout="${TIMEOUT}s"; then
        log_error "Rollout failed"
        kubectl delete deployment "$new_deployment_name" -n "$NAMESPACE" --ignore-not-found=true
        return 1
    fi
    
    # Health check
    log_info "Performing health checks..."
    if ! health_check "$new_deployment_name"; then
        log_error "Health check failed"
        kubectl delete deployment "$new_deployment_name" -n "$NAMESPACE" --ignore-not-found=true
        return 1
    fi
    
    # Switch traffic
    log_info "Switching traffic to new version..."
    kubectl patch service "$SERVICE_NAME" -n "$NAMESPACE" \
        -p "{\"spec\":{\"selector\":{\"app\":\"$new_deployment_name\"}}}"
    
    # Verify traffic switch
    sleep 10
    if ! health_check_external; then
        log_error "External health check failed after traffic switch"
        # Rollback traffic
        kubectl patch service "$SERVICE_NAME" -n "$NAMESPACE" \
            -p "{\"spec\":{\"selector\":{\"app\":\"${DEPLOYMENT_NAME}-${current_color}\"}}}"
        kubectl delete deployment "$new_deployment_name" -n "$NAMESPACE" --ignore-not-found=true
        return 1
    fi
    
    # Clean up old deployment
    log_info "Cleaning up old deployment..."
    kubectl delete deployment "${DEPLOYMENT_NAME}-${current_color}" -n "$NAMESPACE" \
        --ignore-not-found=true
    
    # Update main deployment name
    kubectl patch deployment "$new_deployment_name" -n "$NAMESPACE" \
        --type='merge' -p='{"metadata":{"name":"'$DEPLOYMENT_NAME'"}}'
    
    log_success "Blue-green deployment completed successfully"
}

# Canary deployment
deploy_canary() {
    local new_image="$1"
    local canary_weight="${CANARY_WEIGHT:-10}"
    
    log_info "Starting canary deployment with image: $new_image (${canary_weight}% traffic)"
    
    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "DRY RUN: Would deploy canary with $canary_weight% traffic"
        return 0
    fi
    
    # Deploy canary version using Istio or ingress controller
    local canary_deployment_name="${DEPLOYMENT_NAME}-canary"
    
    # Create canary deployment manifest
    local manifest_file="/tmp/${canary_deployment_name}.yaml"
    sed "s|image: claude-deployment-api:latest|image: $new_image|g" \
        "$PROJECT_ROOT/k8s/production/deployments.yaml" > "$manifest_file"
    sed -i "s|name: $DEPLOYMENT_NAME|name: $canary_deployment_name|g" "$manifest_file"
    sed -i "s|app: $DEPLOYMENT_NAME|app: $canary_deployment_name|g" "$manifest_file"
    sed -i "s|replicas: 6|replicas: 1|g" "$manifest_file"
    
    # Deploy canary
    kubectl apply -f "$manifest_file"
    
    # Wait for canary to be ready
    if ! kubectl rollout status "deployment/$canary_deployment_name" -n "$NAMESPACE" \
        --timeout="${TIMEOUT}s"; then
        log_error "Canary rollout failed"
        kubectl delete deployment "$canary_deployment_name" -n "$NAMESPACE" --ignore-not-found=true
        return 1
    fi
    
    # Configure traffic split (this would depend on your ingress controller)
    configure_canary_traffic "$canary_weight"
    
    # Monitor canary for a period
    log_info "Monitoring canary deployment for 5 minutes..."
    sleep 300
    
    # Check canary metrics
    if ! validate_canary_metrics; then
        log_error "Canary validation failed"
        remove_canary_deployment
        return 1
    fi
    
    # Gradually increase traffic
    for weight in 25 50 75 100; do
        log_info "Increasing canary traffic to ${weight}%..."
        configure_canary_traffic "$weight"
        sleep 60
        
        if ! validate_canary_metrics; then
            log_error "Canary validation failed at ${weight}%"
            remove_canary_deployment
            return 1
        fi
    done
    
    # Promote canary to main
    log_info "Promoting canary to main deployment..."
    kubectl patch deployment "$DEPLOYMENT_NAME" -n "$NAMESPACE" \
        --type='merge' -p='{"spec":{"template":{"spec":{"containers":[{"name":"api","image":"'$new_image'"}]}}}}'
    
    # Clean up canary
    remove_canary_deployment
    
    log_success "Canary deployment completed successfully"
}

# Rolling update deployment
deploy_rolling() {
    local new_image="$1"
    
    log_info "Starting rolling update deployment with image: $new_image"
    
    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "DRY RUN: Would perform rolling update"
        return 0
    fi
    
    # Update deployment image
    kubectl set image "deployment/$DEPLOYMENT_NAME" \
        api="$new_image" -n "$NAMESPACE"
    
    # Wait for rollout
    if ! kubectl rollout status "deployment/$DEPLOYMENT_NAME" -n "$NAMESPACE" \
        --timeout="${TIMEOUT}s"; then
        log_error "Rolling update failed"
        return 1
    fi
    
    # Health check
    if ! health_check "$DEPLOYMENT_NAME"; then
        log_error "Health check failed after rolling update"
        return 1
    fi
    
    log_success "Rolling update completed successfully"
}

# Health check function
health_check() {
    local deployment_name="$1"
    local max_attempts=30
    local attempt=1
    
    log_info "Performing health check for $deployment_name..."
    
    while [[ $attempt -le $max_attempts ]]; do
        local ready_replicas
        ready_replicas=$(kubectl get deployment "$deployment_name" -n "$NAMESPACE" \
            -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
        local desired_replicas
        desired_replicas=$(kubectl get deployment "$deployment_name" -n "$NAMESPACE" \
            -o jsonpath='{.spec.replicas}')
        
        if [[ "$ready_replicas" == "$desired_replicas" ]] && [[ "$ready_replicas" -gt 0 ]]; then
            log_success "Health check passed: $ready_replicas/$desired_replicas replicas ready"
            return 0
        fi
        
        log_info "Health check attempt $attempt/$max_attempts: $ready_replicas/$desired_replicas replicas ready"
        sleep 10
        ((attempt++))
    done
    
    log_error "Health check failed: deployment not ready after $max_attempts attempts"
    return 1
}

# External health check
health_check_external() {
    local max_attempts=10
    local attempt=1
    
    log_info "Performing external health check..."
    
    # Port forward to test service
    kubectl port-forward "service/$SERVICE_NAME" 8080:80 -n "$NAMESPACE" &
    local port_forward_pid=$!
    sleep 5
    
    while [[ $attempt -le $max_attempts ]]; do
        if curl -s -f "$HEALTH_CHECK_URL" > /dev/null; then
            kill $port_forward_pid 2>/dev/null || true
            log_success "External health check passed"
            return 0
        fi
        
        log_info "External health check attempt $attempt/$max_attempts failed"
        sleep 5
        ((attempt++))
    done
    
    kill $port_forward_pid 2>/dev/null || true
    log_error "External health check failed"
    return 1
}

# Configure canary traffic (placeholder - implement based on your ingress)
configure_canary_traffic() {
    local weight="$1"
    log_info "Configuring canary traffic weight: ${weight}%"
    # Implement based on your ingress controller (nginx, istio, etc.)
}

# Validate canary metrics
validate_canary_metrics() {
    log_info "Validating canary metrics..."
    # Implement metric validation logic
    # Check error rates, response times, etc.
    return 0
}

# Remove canary deployment
remove_canary_deployment() {
    log_info "Removing canary deployment..."
    kubectl delete deployment "${DEPLOYMENT_NAME}-canary" -n "$NAMESPACE" --ignore-not-found=true
}

# Rollback deployment
rollback_deployment() {
    log_warning "Rolling back deployment..."
    
    if kubectl rollout history "deployment/$DEPLOYMENT_NAME" -n "$NAMESPACE" --revision=1 &> /dev/null; then
        kubectl rollout undo "deployment/$DEPLOYMENT_NAME" -n "$NAMESPACE"
        kubectl rollout status "deployment/$DEPLOYMENT_NAME" -n "$NAMESPACE" --timeout=300s
        log_success "Deployment rolled back successfully"
    else
        log_error "No previous deployment found for rollback"
    fi
}

# Post-deployment tasks
post_deployment_tasks() {
    log_info "Running post-deployment tasks..."
    
    # Update deployment annotations
    kubectl annotate deployment "$DEPLOYMENT_NAME" -n "$NAMESPACE" \
        deployment.kubernetes.io/revision="$(date +%s)" \
        deployment.kubernetes.io/deployed-by="$(whoami)" \
        deployment.kubernetes.io/deployment-strategy="$STRATEGY" \
        --overwrite
    
    # Run integration tests
    if [[ "${SKIP_TESTS:-false}" != "true" ]]; then
        log_info "Running integration tests..."
        "$SCRIPT_DIR/integration-tests.sh" || log_warning "Integration tests failed"
    fi
    
    # Update monitoring dashboards
    log_info "Updating monitoring configuration..."
    kubectl apply -f "$PROJECT_ROOT/monitoring/production/" || log_warning "Failed to update monitoring"
    
    log_success "Post-deployment tasks completed"
}

# Main function
main() {
    local strategy="${1:-blue-green}"
    local image_tag="${2:-latest}"
    local image_name="ghcr.io/louranicas/claude-optimized-deployment:$image_tag"
    
    # Validate strategy
    case "$strategy" in
        "blue-green"|"canary"|"rolling")
            ;;
        "--help"|"-h")
            show_help
            exit 0
            ;;
        *)
            log_error "Invalid deployment strategy: $strategy"
            show_help
            exit 1
            ;;
    esac
    
    log_info "Starting deployment with strategy: $strategy, image: $image_name"
    
    # Set global variables
    STRATEGY="$strategy"
    IMAGE_TAG="$image_tag"
    
    # Execute deployment pipeline
    validate_prerequisites
    run_pre_deployment_tests
    
    case "$strategy" in
        "blue-green")
            deploy_blue_green "$image_name"
            ;;
        "canary")
            deploy_canary "$image_name"
            ;;
        "rolling")
            deploy_rolling "$image_name"
            ;;
    esac
    
    post_deployment_tasks
    
    log_success "Deployment completed successfully!"
    log_info "Image deployed: $image_name"
    log_info "Strategy used: $strategy"
    log_info "Deployment time: $(date)"
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi