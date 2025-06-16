#!/bin/bash
# Automated Container Build System
# Optimized for parallel builds on Ryzen 7 7800X3D

set -euo pipefail

# Configuration
REGISTRY="${REGISTRY:-localhost:5000}"
PROJECT_NAME="${PROJECT_NAME:-claude-optimized-deployment}"
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
VERSION="${VERSION:-latest}"
BUILD_ARGS="${BUILD_ARGS:-}"
PARALLEL_BUILDS="${PARALLEL_BUILDS:-4}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        exit 1
    fi
    
    if ! command -v buildah &> /dev/null; then
        log_warning "Buildah not found, using Docker build only"
    fi
    
    log_success "Prerequisites check passed"
}

# Build configuration matrix
declare -A CONTAINERS=(
    ["rust-dev"]="containers/development/Dockerfile.rust-dev"
    ["python-ml"]="containers/development/Dockerfile.python-ml"
    ["rust-service"]="containers/production/Dockerfile.rust-service"
    ["python-api"]="containers/production/Dockerfile.python-api"
)

# Build a single container
build_container() {
    local name=$1
    local dockerfile=$2
    local build_type=""
    
    if [[ $dockerfile == *"development"* ]]; then
        build_type="dev"
    else
        build_type="prod"
    fi
    
    local tag="${REGISTRY}/${PROJECT_NAME}/${name}:${VERSION}"
    local tag_latest="${REGISTRY}/${PROJECT_NAME}/${name}:latest"
    local tag_commit="${REGISTRY}/${PROJECT_NAME}/${name}:${GIT_COMMIT}"
    
    log_info "Building ${name} (${build_type})..."
    
    # Create build context
    local build_context="."
    if [[ $dockerfile == *"development"* ]]; then
        build_context="."
    fi
    
    # Build with Docker
    local build_cmd="docker build"
    build_cmd+=" --file ${dockerfile}"
    build_cmd+=" --tag ${tag}"
    build_cmd+=" --tag ${tag_latest}"
    build_cmd+=" --tag ${tag_commit}"
    build_cmd+=" --label org.opencontainers.image.created=${BUILD_DATE}"
    build_cmd+=" --label org.opencontainers.image.revision=${GIT_COMMIT}"
    build_cmd+=" --label org.opencontainers.image.version=${VERSION}"
    build_cmd+=" --label org.opencontainers.image.title=${PROJECT_NAME}-${name}"
    build_cmd+=" --build-arg BUILDKIT_INLINE_CACHE=1"
    build_cmd+=" --cache-from ${tag_latest}"
    
    # Add custom build args
    if [[ -n "${BUILD_ARGS}" ]]; then
        build_cmd+=" ${BUILD_ARGS}"
    fi
    
    build_cmd+=" ${build_context}"
    
    # Execute build with timeout
    log_info "Executing: ${build_cmd}"
    if timeout 1800 bash -c "${build_cmd}"; then
        log_success "Built ${name} successfully"
        
        # Security scan
        scan_container "${tag}"
        
        return 0
    else
        log_error "Failed to build ${name}"
        return 1
    fi
}

# Scan container for vulnerabilities
scan_container() {
    local image=$1
    local scan_output="security-reports/$(basename ${image}).json"
    
    log_info "Scanning ${image} for vulnerabilities..."
    
    mkdir -p security-reports
    
    # Trivy scan
    if command -v trivy &> /dev/null; then
        trivy image --format json --output "${scan_output}" "${image}" || {
            log_warning "Trivy scan failed for ${image}"
        }
    fi
    
    # Docker Scout scan (if available)
    if docker scout version &> /dev/null; then
        docker scout cves "${image}" --format json --output "${scan_output%.json}_scout.json" || {
            log_warning "Docker Scout scan failed for ${image}"
        }
    fi
    
    log_success "Security scan completed for ${image}"
}

# Build containers in parallel
build_all_parallel() {
    local build_type="${1:-all}"
    local pids=()
    local failed_builds=()
    
    log_info "Starting parallel builds (max ${PARALLEL_BUILDS} concurrent)"
    
    for name in "${!CONTAINERS[@]}"; do
        local dockerfile="${CONTAINERS[$name]}"
        
        # Filter by build type
        if [[ $build_type == "dev" && $dockerfile != *"development"* ]]; then
            continue
        elif [[ $build_type == "prod" && $dockerfile != *"production"* ]]; then
            continue
        fi
        
        # Wait if we've reached max parallel builds
        while (( ${#pids[@]} >= PARALLEL_BUILDS )); do
            for i in "${!pids[@]}"; do
                if ! kill -0 "${pids[$i]}" 2>/dev/null; then
                    wait "${pids[$i]}"
                    if [[ $? -ne 0 ]]; then
                        failed_builds+=("${name}")
                    fi
                    unset "pids[$i]"
                fi
            done
            sleep 1
        done
        
        # Start build in background
        (build_container "$name" "$dockerfile") &
        pids+=($!)
        
        log_info "Started build for ${name} (PID: $!)"
    done
    
    # Wait for all builds to complete
    for pid in "${pids[@]}"; do
        wait "$pid"
        if [[ $? -ne 0 ]]; then
            failed_builds+=("unknown")
        fi
    done
    
    # Report results
    if [[ ${#failed_builds[@]} -eq 0 ]]; then
        log_success "All builds completed successfully"
    else
        log_error "Failed builds: ${failed_builds[*]}"
        exit 1
    fi
}

# Push to registry
push_to_registry() {
    local build_type="${1:-all}"
    
    log_info "Pushing images to registry ${REGISTRY}..."
    
    for name in "${!CONTAINERS[@]}"; do
        local dockerfile="${CONTAINERS[$name]}"
        
        # Filter by build type
        if [[ $build_type == "dev" && $dockerfile != *"development"* ]]; then
            continue
        elif [[ $build_type == "prod" && $dockerfile != *"production"* ]]; then
            continue
        fi
        
        local tag="${REGISTRY}/${PROJECT_NAME}/${name}:${VERSION}"
        local tag_latest="${REGISTRY}/${PROJECT_NAME}/${name}:latest"
        local tag_commit="${REGISTRY}/${PROJECT_NAME}/${name}:${GIT_COMMIT}"
        
        log_info "Pushing ${name}..."
        docker push "${tag}" && \
        docker push "${tag_latest}" && \
        docker push "${tag_commit}" && \
        log_success "Pushed ${name}" || \
        log_error "Failed to push ${name}"
    done
}

# Clean up old images
cleanup_images() {
    log_info "Cleaning up old images..."
    
    # Remove dangling images
    docker image prune -f
    
    # Remove old versions (keep last 5)
    for name in "${!CONTAINERS[@]}"; do
        local images=$(docker images "${REGISTRY}/${PROJECT_NAME}/${name}" --format "table {{.Repository}}:{{.Tag}}\t{{.CreatedAt}}" | tail -n +2 | sort -k2 -r | tail -n +6 | awk '{print $1}')
        
        if [[ -n "${images}" ]]; then
            log_info "Removing old images for ${name}: ${images}"
            echo "${images}" | xargs -r docker rmi
        fi
    done
    
    log_success "Cleanup completed"
}

# Generate build report
generate_report() {
    local report_file="build-reports/build-report-$(date +%Y%m%d-%H%M%S).json"
    mkdir -p build-reports
    
    log_info "Generating build report: ${report_file}"
    
    cat > "${report_file}" << EOF
{
  "build_date": "${BUILD_DATE}",
  "git_commit": "${GIT_COMMIT}",
  "version": "${VERSION}",
  "registry": "${REGISTRY}",
  "containers": {
$(for name in "${!CONTAINERS[@]}"; do
    local dockerfile="${CONTAINERS[$name]}"
    local tag="${REGISTRY}/${PROJECT_NAME}/${name}:${VERSION}"
    local size=$(docker images --format "table {{.Size}}" "${tag}" | tail -n +2 | head -1)
    echo "    \"${name}\": {"
    echo "      \"dockerfile\": \"${dockerfile}\","
    echo "      \"tag\": \"${tag}\","
    echo "      \"size\": \"${size}\""
    echo "    },"
done | sed '$ s/,$//')
  },
  "system_info": {
    "docker_version": "$(docker --version)",
    "build_host": "$(hostname)",
    "cpu_cores": "$(nproc)",
    "memory": "$(free -h | awk '/^Mem:/ {print $2}')"
  }
}
EOF
    
    log_success "Build report generated: ${report_file}"
}

# Main execution
main() {
    local command="${1:-build}"
    local build_type="${2:-all}"
    
    case $command in
        "build")
            check_prerequisites
            build_all_parallel "$build_type"
            generate_report
            ;;
        "push")
            push_to_registry "$build_type"
            ;;
        "scan")
            for name in "${!CONTAINERS[@]}"; do
                scan_container "${REGISTRY}/${PROJECT_NAME}/${name}:${VERSION}"
            done
            ;;
        "cleanup")
            cleanup_images
            ;;
        "all")
            check_prerequisites
            build_all_parallel "$build_type"
            push_to_registry "$build_type"
            cleanup_images
            generate_report
            ;;
        "help")
            echo "Usage: $0 {build|push|scan|cleanup|all} [dev|prod|all]"
            echo ""
            echo "Commands:"
            echo "  build   - Build containers"
            echo "  push    - Push to registry"
            echo "  scan    - Security scan"
            echo "  cleanup - Clean old images"
            echo "  all     - Build, push, and cleanup"
            echo ""
            echo "Build types:"
            echo "  dev     - Development containers only"
            echo "  prod    - Production containers only"
            echo "  all     - All containers (default)"
            exit 0
            ;;
        *)
            log_error "Unknown command: $command"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"