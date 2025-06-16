#!/bin/bash
# Container Registry Setup and Management
# Supports Harbor, GitLab Registry, and local registry

set -euo pipefail

# Configuration
REGISTRY_TYPE="${REGISTRY_TYPE:-local}"
REGISTRY_HOST="${REGISTRY_HOST:-localhost}"
REGISTRY_PORT="${REGISTRY_PORT:-5000}"
REGISTRY_USER="${REGISTRY_USER:-admin}"
REGISTRY_PASS="${REGISTRY_PASS:-}"
PROJECT_NAME="${PROJECT_NAME:-claude-optimized-deployment}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Setup local Docker registry
setup_local_registry() {
    log_info "Setting up local Docker registry..."
    
    # Create registry directories
    mkdir -p registry/{data,certs,auth,config}
    
    # Generate self-signed certificate
    if [[ ! -f registry/certs/domain.crt ]]; then
        log_info "Generating self-signed certificate..."
        openssl req -newkey rsa:4096 -nodes -sha256 -keyout registry/certs/domain.key \
            -x509 -days 365 -out registry/certs/domain.crt \
            -config <(cat <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = State
L = City
O = Organization
CN = ${REGISTRY_HOST}

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${REGISTRY_HOST}
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF
)
    fi
    
    # Create auth file
    if [[ ! -f registry/auth/htpasswd ]]; then
        log_info "Creating registry authentication..."
        docker run --rm --entrypoint htpasswd httpd:2 -Bbn ${REGISTRY_USER} ${REGISTRY_PASS:-changeme} > registry/auth/htpasswd
    fi
    
    # Create registry configuration
    cat > registry/config/config.yml << 'EOF'
version: 0.1
log:
  fields:
    service: registry
  level: info
  formatter: text
  hooks:
    - type: mail
      disabled: true
storage:
  cache:
    blobdescriptor: inmemory
  filesystem:
    rootdirectory: /var/lib/registry
  delete:
    enabled: true
  maintenance:
    uploadpurging:
      enabled: true
      age: 168h
      interval: 24h
      dryrun: false
    readonly:
      enabled: false
http:
  addr: :5000
  headers:
    X-Content-Type-Options: [nosniff]
    Access-Control-Allow-Origin: ['*']
    Access-Control-Allow-Methods: ['HEAD', 'GET', 'OPTIONS', 'DELETE']
    Access-Control-Allow-Headers: ['Authorization', 'Accept', 'Cache-Control']
    Access-Control-Max-Age: [1728000]
    Access-Control-Allow-Credentials: [true]
    Access-Control-Expose-Headers: ['Docker-Content-Digest']
  tls:
    certificate: /certs/domain.crt
    key: /certs/domain.key
  debug:
    addr: :5001
    prometheus:
      enabled: true
      path: /metrics
auth:
  htpasswd:
    realm: basic-realm
    path: /auth/htpasswd
health:
  storagedriver:
    enabled: true
    interval: 10s
    threshold: 3
notifications:
  events:
    includereferences: true
EOF
    
    # Create Docker Compose for registry
    cat > registry/docker-compose.yml << EOF
version: '3.8'

services:
  registry:
    image: registry:2.8
    container_name: ${PROJECT_NAME}-registry
    restart: unless-stopped
    ports:
      - "${REGISTRY_PORT}:5000"
      - "5001:5001"  # Debug/metrics
    environment:
      REGISTRY_CONFIG_PATH: /etc/registry/config.yml
    volumes:
      - ./data:/var/lib/registry
      - ./certs:/certs:ro
      - ./auth:/auth:ro
      - ./config/config.yml:/etc/registry/config.yml:ro
    networks:
      - registry-net
    deploy:
      resources:
        limits:
          memory: 1G
          cpus: '1.0'
        reservations:
          memory: 256M
          cpus: '0.25'
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "https://localhost:5000/v2/"]
      interval: 30s
      timeout: 10s
      retries: 3

  registry-ui:
    image: joxit/docker-registry-ui:latest
    container_name: ${PROJECT_NAME}-registry-ui
    restart: unless-stopped
    ports:
      - "8080:80"
    environment:
      REGISTRY_TITLE: "${PROJECT_NAME} Registry"
      REGISTRY_URL: "https://registry:5000"
      DELETE_IMAGES: "true"
      SHOW_CONTENT_DIGEST: "true"
      NGINX_PROXY_PASS_URL: "https://registry:5000"
      NGINX_PROXY_PASS_HEADER: "true"
      NGINX_LISTEN_PORT: "80"
      SINGLE_REGISTRY: "true"
    depends_on:
      - registry
    networks:
      - registry-net

networks:
  registry-net:
    driver: bridge
EOF
    
    # Start registry
    log_info "Starting local registry..."
    cd registry && docker-compose up -d && cd ..
    
    # Wait for registry to be ready
    log_info "Waiting for registry to be ready..."
    timeout 60 bash -c 'until curl -k -f https://localhost:5000/v2/; do sleep 2; done'
    
    log_success "Local registry is running at https://${REGISTRY_HOST}:${REGISTRY_PORT}"
    log_info "Registry UI available at http://${REGISTRY_HOST}:8080"
    log_info "Username: ${REGISTRY_USER}, Password: ${REGISTRY_PASS:-changeme}"
}

# Setup Harbor registry
setup_harbor_registry() {
    log_info "Setting up Harbor registry..."
    
    # Download Harbor
    local harbor_version="v2.9.1"
    local harbor_dir="harbor"
    
    if [[ ! -d "${harbor_dir}" ]]; then
        log_info "Downloading Harbor ${harbor_version}..."
        wget "https://github.com/goharbor/harbor/releases/download/${harbor_version}/harbor-offline-installer-${harbor_version}.tgz"
        tar xvf "harbor-offline-installer-${harbor_version}.tgz"
        rm "harbor-offline-installer-${harbor_version}.tgz"
    fi
    
    cd "${harbor_dir}"
    
    # Create Harbor configuration
    if [[ ! -f harbor.yml ]]; then
        cp harbor.yml.tmpl harbor.yml
        
        # Configure Harbor
        sed -i "s/hostname: reg.mydomain.com/hostname: ${REGISTRY_HOST}/" harbor.yml
        sed -i "s/harbor_admin_password: Harbor12345/harbor_admin_password: ${REGISTRY_PASS:-Harbor12345}/" harbor.yml
        
        # Configure HTTPS
        sed -i "/^https:/,/^[[:space:]]*$/ {
            s|certificate: /your/certificate/path|certificate: ../registry/certs/domain.crt|
            s|private_key: /your/private/key/path|private_key: ../registry/certs/domain.key|
        }" harbor.yml
    fi
    
    # Install Harbor
    log_info "Installing Harbor..."
    sudo ./install.sh --with-trivy --with-chartmuseum
    
    cd ..
    
    log_success "Harbor registry is running at https://${REGISTRY_HOST}"
    log_info "Username: admin, Password: ${REGISTRY_PASS:-Harbor12345}"
}

# Login to registry
login_registry() {
    local registry_url="${REGISTRY_HOST}:${REGISTRY_PORT}"
    
    log_info "Logging into registry ${registry_url}..."
    
    case $REGISTRY_TYPE in
        "local"|"harbor")
            echo "${REGISTRY_PASS:-changeme}" | docker login "${registry_url}" -u "${REGISTRY_USER}" --password-stdin
            ;;
        "gitlab")
            echo "${REGISTRY_PASS}" | docker login "${registry_url}" -u "${REGISTRY_USER}" --password-stdin
            ;;
        *)
            log_error "Unknown registry type: ${REGISTRY_TYPE}"
            exit 1
            ;;
    esac
    
    log_success "Successfully logged into registry"
}

# Create project/namespace in registry
create_project() {
    local project_name="${1:-${PROJECT_NAME}}"
    
    log_info "Creating project ${project_name}..."
    
    case $REGISTRY_TYPE in
        "harbor")
            # Create Harbor project via API
            curl -X POST "https://${REGISTRY_HOST}/api/v2.0/projects" \
                -H "Content-Type: application/json" \
                -u "${REGISTRY_USER}:${REGISTRY_PASS}" \
                -d "{
                    \"project_name\": \"${project_name}\",
                    \"public\": false,
                    \"storage_limit\": -1,
                    \"metadata\": {
                        \"auto_scan\": \"true\",
                        \"severity\": \"low\",
                        \"reuse_sys_cve_allowlist\": \"true\"
                    }
                }" -k || log_warning "Project might already exist"
            ;;
        "local")
            log_info "Local registry doesn't require project creation"
            ;;
        "gitlab")
            log_info "GitLab projects should be created via GitLab UI"
            ;;
    esac
    
    log_success "Project setup completed"
}

# Test registry connectivity
test_registry() {
    local test_image="hello-world:latest"
    local registry_url="${REGISTRY_HOST}:${REGISTRY_PORT}"
    local test_tag="${registry_url}/${PROJECT_NAME}/test:latest"
    
    log_info "Testing registry connectivity..."
    
    # Pull test image
    docker pull "${test_image}"
    
    # Tag for registry
    docker tag "${test_image}" "${test_tag}"
    
    # Push to registry
    if docker push "${test_tag}"; then
        log_success "Successfully pushed test image"
        
        # Pull from registry
        docker rmi "${test_tag}"
        if docker pull "${test_tag}"; then
            log_success "Successfully pulled test image"
            docker rmi "${test_tag}"
        else
            log_error "Failed to pull test image"
            return 1
        fi
    else
        log_error "Failed to push test image"
        return 1
    fi
    
    log_success "Registry connectivity test passed"
}

# Setup monitoring for registry
setup_monitoring() {
    log_info "Setting up registry monitoring..."
    
    # Create Prometheus configuration for registry
    cat > monitoring/prometheus-registry.yml << 'EOF'
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'registry'
    static_configs:
      - targets: ['localhost:5001']
    metrics_path: /metrics
    scheme: http

  - job_name: 'harbor'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: /api/systeminfo/volumes
    scheme: https
    tls_config:
      insecure_skip_verify: true
EOF
    
    # Create Grafana dashboard for registry
    cat > monitoring/grafana-registry-dashboard.json << 'EOF'
{
  "dashboard": {
    "title": "Container Registry Metrics",
    "panels": [
      {
        "title": "Registry Storage Usage",
        "type": "stat",
        "targets": [
          {
            "expr": "registry_storage_usage_bytes",
            "legendFormat": "Storage Used"
          }
        ]
      },
      {
        "title": "Registry HTTP Requests",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(registry_http_requests_total[5m])",
            "legendFormat": "Requests/sec"
          }
        ]
      }
    ]
  }
}
EOF
    
    log_success "Registry monitoring setup completed"
}

# Cleanup registry data
cleanup_registry() {
    log_info "Cleaning up registry data..."
    
    case $REGISTRY_TYPE in
        "local")
            cd registry
            docker-compose down -v
            sudo rm -rf data/*
            docker-compose up -d
            cd ..
            ;;
        "harbor")
            cd harbor
            docker-compose down -v
            sudo ./install.sh --with-trivy --with-chartmuseum
            cd ..
            ;;
    esac
    
    log_success "Registry cleanup completed"
}

# Main execution
main() {
    local command="${1:-setup}"
    
    # Create directories
    mkdir -p {registry,monitoring,harbor}
    
    case $command in
        "setup")
            case $REGISTRY_TYPE in
                "local")
                    setup_local_registry
                    ;;
                "harbor")
                    setup_harbor_registry
                    ;;
                *)
                    log_error "Unsupported registry type: $REGISTRY_TYPE"
                    exit 1
                    ;;
            esac
            login_registry
            create_project
            test_registry
            setup_monitoring
            ;;
        "login")
            login_registry
            ;;
        "test")
            test_registry
            ;;
        "cleanup")
            cleanup_registry
            ;;
        "help")
            echo "Usage: $0 {setup|login|test|cleanup}"
            echo ""
            echo "Environment variables:"
            echo "  REGISTRY_TYPE   - local, harbor, gitlab (default: local)"
            echo "  REGISTRY_HOST   - Registry hostname (default: localhost)"
            echo "  REGISTRY_PORT   - Registry port (default: 5000)"
            echo "  REGISTRY_USER   - Registry username (default: admin)"
            echo "  REGISTRY_PASS   - Registry password"
            echo "  PROJECT_NAME    - Project name (default: claude-optimized-deployment)"
            exit 0
            ;;
        *)
            log_error "Unknown command: $command"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

main "$@"