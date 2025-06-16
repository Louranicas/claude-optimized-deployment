#!/bin/bash
# Container Management Script for Claude Optimized Deployment
# Advanced container operations and monitoring

set -e

# Configuration
COMPOSE_PROJECT_NAME="claude-optimized"
DOCKER_REGISTRY="${DOCKER_REGISTRY:-localhost:5000}"
TAG="${TAG:-latest}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check container health
check_health() {
    local container=$1
    local health=$(docker inspect --format='{{.State.Health.Status}}' "$container" 2>/dev/null || echo "none")
    
    case $health in
        healthy)
            echo -e "${GREEN}✓${NC} $container: Healthy"
            ;;
        unhealthy)
            echo -e "${RED}✗${NC} $container: Unhealthy"
            docker logs --tail 20 "$container"
            ;;
        starting)
            echo -e "${YELLOW}⟳${NC} $container: Starting..."
            ;;
        none)
            local running=$(docker inspect --format='{{.State.Running}}' "$container" 2>/dev/null || echo "false")
            if [ "$running" = "true" ]; then
                echo -e "${BLUE}●${NC} $container: Running (no health check)"
            else
                echo -e "${RED}○${NC} $container: Not running"
            fi
            ;;
    esac
}

# Monitor all containers
monitor_containers() {
    log_info "Monitoring container status..."
    
    while true; do
        clear
        echo "=== Claude Optimized Deployment - Container Status ==="
        echo "Time: $(date)"
        echo ""
        
        # Development containers
        echo "Development Environment:"
        for container in claude-rust-dev claude-python-ml claude-postgres-dev claude-redis-dev claude-mcp-dev; do
            check_health "$container"
        done
        
        echo ""
        echo "Production Environment:"
        for container in claude-rust-prod claude-api-prod claude-postgres-prod claude-redis-prod claude-mcp-prod; do
            check_health "$container"
        done
        
        echo ""
        echo "Press Ctrl+C to exit"
        sleep 5
    done
}

# Get container resource usage
resource_usage() {
    log_info "Container Resource Usage:"
    echo ""
    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}" \
        $(docker ps --format "{{.Names}}" | grep -E "^claude-")
}

# Backup container data
backup_data() {
    local env=$1
    local backup_dir="backups/$(date +%Y%m%d_%H%M%S)"
    
    log_info "Creating backup in $backup_dir..."
    mkdir -p "$backup_dir"
    
    # Backup PostgreSQL
    if [ "$env" = "dev" ]; then
        docker exec claude-postgres-dev pg_dump -U claude_dev claude_dev > "$backup_dir/postgres_dev.sql"
    else
        docker exec claude-postgres-prod pg_dump -U claude_prod claude_prod > "$backup_dir/postgres_prod.sql"
    fi
    
    # Backup Redis
    if [ "$env" = "dev" ]; then
        docker exec claude-redis-dev redis-cli BGSAVE
        sleep 2
        docker cp claude-redis-dev:/data/dump.rdb "$backup_dir/redis_dev.rdb"
    else
        docker exec claude-redis-prod redis-cli BGSAVE
        sleep 2
        docker cp claude-redis-prod:/data/dump.rdb "$backup_dir/redis_prod.rdb"
    fi
    
    # Backup volumes
    for volume in $(docker volume ls -q | grep -E "^${COMPOSE_PROJECT_NAME}_"); do
        log_info "Backing up volume: $volume"
        docker run --rm -v "$volume":/source -v "$(pwd)/$backup_dir":/backup alpine tar czf "/backup/${volume}.tar.gz" -C /source .
    done
    
    log_info "Backup completed: $backup_dir"
}

# Scale service
scale_service() {
    local service=$1
    local replicas=$2
    local compose_file=$3
    
    log_info "Scaling $service to $replicas replicas..."
    docker-compose -f "$compose_file" up -d --scale "$service=$replicas" --no-recreate "$service"
}

# Update containers with zero downtime
rolling_update() {
    local service=$1
    local compose_file=$2
    
    log_info "Performing rolling update for $service..."
    
    # Pull new image
    docker-compose -f "$compose_file" pull "$service"
    
    # Update one instance at a time
    local current_scale=$(docker-compose -f "$compose_file" ps -q "$service" | wc -l)
    
    for i in $(seq 1 "$current_scale"); do
        log_info "Updating instance $i of $current_scale..."
        docker-compose -f "$compose_file" up -d --no-deps --scale "$service=$((current_scale + 1))" "$service"
        sleep 10  # Wait for new instance to be ready
        docker-compose -f "$compose_file" stop -t 30 "$(docker-compose -f "$compose_file" ps -q "$service" | head -1)"
        docker-compose -f "$compose_file" rm -f "$(docker-compose -f "$compose_file" ps -q "$service" | head -1)"
    done
    
    docker-compose -f "$compose_file" up -d --scale "$service=$current_scale" "$service"
    log_info "Rolling update completed"
}

# Execute command in container
exec_in_container() {
    local container=$1
    shift
    local cmd="$@"
    
    log_info "Executing in $container: $cmd"
    docker exec -it "$container" $cmd
}

# Show container logs
show_logs() {
    local container=$1
    local lines=${2:-100}
    
    log_info "Showing last $lines lines from $container:"
    docker logs --tail "$lines" -f "$container"
}

# Clean up old images and volumes
cleanup_system() {
    log_warning "Cleaning up Docker system..."
    
    # Remove stopped containers
    docker container prune -f
    
    # Remove unused images
    docker image prune -a -f --filter "until=24h"
    
    # Remove unused volumes (interactive)
    echo "Do you want to remove unused volumes? This may delete important data!"
    read -p "Continue? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker volume prune -f
    fi
    
    # Remove unused networks
    docker network prune -f
    
    log_info "Cleanup completed"
}

# Build and push images to registry
push_to_registry() {
    log_info "Building and pushing images to registry..."
    
    # Build images
    docker build -f ../production/Dockerfile.rust-service -t "$DOCKER_REGISTRY/claude-rust:$TAG" ../..
    docker build -f ../production/Dockerfile.python-api -t "$DOCKER_REGISTRY/claude-api:$TAG" ../..
    docker build -f ../production/Dockerfile.mcp-server-prod -t "$DOCKER_REGISTRY/claude-mcp:$TAG" ../..
    
    # Push to registry
    docker push "$DOCKER_REGISTRY/claude-rust:$TAG"
    docker push "$DOCKER_REGISTRY/claude-api:$TAG"
    docker push "$DOCKER_REGISTRY/claude-mcp:$TAG"
    
    log_info "Images pushed to registry"
}

# Performance tuning
tune_performance() {
    log_info "Applying performance optimizations..."
    
    # Update container resource limits based on available system resources
    local total_mem=$(free -g | awk '/^Mem:/{print $2}')
    local total_cpu=$(nproc)
    
    log_info "System resources: ${total_mem}GB RAM, ${total_cpu} CPUs"
    
    # Apply sysctl optimizations for containers
    sudo sysctl -w vm.max_map_count=262144
    sudo sysctl -w net.core.somaxconn=65535
    sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535
    
    log_info "Performance tuning applied"
}

# Main menu
usage() {
    echo "Container Management for Claude Optimized Deployment"
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  monitor              - Monitor container health status"
    echo "  resources            - Show container resource usage"
    echo "  backup <env>         - Backup data (dev/prod)"
    echo "  scale <service> <n>  - Scale service to n replicas"
    echo "  update <service>     - Rolling update for service"
    echo "  exec <container>     - Execute command in container"
    echo "  logs <container> [n] - Show container logs (last n lines)"
    echo "  cleanup              - Clean up unused resources"
    echo "  push                 - Build and push to registry"
    echo "  tune                 - Apply performance optimizations"
    echo ""
    echo "Examples:"
    echo "  $0 monitor"
    echo "  $0 backup prod"
    echo "  $0 scale python-api 5"
    echo "  $0 exec claude-rust-dev bash"
    echo "  $0 logs claude-api-prod 200"
}

# Process commands
case "$1" in
    monitor)
        monitor_containers
        ;;
    resources)
        resource_usage
        ;;
    backup)
        backup_data "$2"
        ;;
    scale)
        if [ -z "$2" ] || [ -z "$3" ]; then
            log_error "Usage: $0 scale <service> <replicas>"
            exit 1
        fi
        scale_service "$2" "$3" "../production/docker-compose.prod.yml"
        ;;
    update)
        if [ -z "$2" ]; then
            log_error "Usage: $0 update <service>"
            exit 1
        fi
        rolling_update "$2" "../production/docker-compose.prod.yml"
        ;;
    exec)
        if [ -z "$2" ]; then
            log_error "Usage: $0 exec <container> [command]"
            exit 1
        fi
        container=$2
        shift 2
        exec_in_container "$container" "$@"
        ;;
    logs)
        if [ -z "$2" ]; then
            log_error "Usage: $0 logs <container> [lines]"
            exit 1
        fi
        show_logs "$2" "${3:-100}"
        ;;
    cleanup)
        cleanup_system
        ;;
    push)
        push_to_registry
        ;;
    tune)
        tune_performance
        ;;
    *)
        usage
        exit 1
        ;;
esac