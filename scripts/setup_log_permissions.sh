#!/bin/bash
# Setup proper permissions for log directories
# This ensures non-root containers can write logs properly

set -e

# Define the user ID we're using for containers
CONTAINER_UID=1000
CONTAINER_GID=1000

echo "Setting up log directory permissions for non-root containers..."

# Create log directories if they don't exist
LOG_DIRS=(
    "/var/log/claude-optimized-deployment"
    "/var/log/filebeat"
)

for dir in "${LOG_DIRS[@]}"; do
    if [ ! -d "$dir" ]; then
        echo "Creating directory: $dir"
        sudo mkdir -p "$dir"
    fi
    
    # Set ownership to the container user
    echo "Setting ownership of $dir to $CONTAINER_UID:$CONTAINER_GID"
    sudo chown -R $CONTAINER_UID:$CONTAINER_GID "$dir"
    
    # Set permissions to allow writing
    echo "Setting permissions for $dir"
    sudo chmod -R 755 "$dir"
done

# Handle Docker socket permissions (for filebeat metadata collection)
# Note: This requires the container user to be in the docker group
if [ -S "/var/run/docker.sock" ]; then
    echo "Checking Docker socket permissions..."
    DOCKER_GID=$(stat -c '%g' /var/run/docker.sock)
    echo "Docker socket GID: $DOCKER_GID"
    echo "Note: Container user needs to be in group $DOCKER_GID to access Docker socket"
fi

echo "Log directory permissions setup complete!"
echo ""
echo "Security improvements implemented:"
echo "- Filebeat now runs as non-root user (UID: 1000)"
echo "- Node-exporter runs as nobody user (UID: 65534)"
echo "- Log directories have proper permissions for non-root access"
echo ""
echo "To test the services, run:"
echo "  docker-compose -f infrastructure/logging/docker-compose.logging.yml up -d"
echo "  docker-compose -f docker-compose.monitoring.yml up -d"