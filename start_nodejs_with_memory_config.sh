#!/bin/bash
# Node.js Startup Script with Memory Configuration
# Prevents heap exhaustion by setting proper memory limits

set -euo pipefail

# Load environment variables
if [ -f ".env" ]; then
    source .env
elif [ -f ".env.production" ]; then
    source .env.production
elif [ -f ".env.development" ]; then
    source .env.development
fi

# Default memory configuration if not set in environment
export NODE_OPTIONS="${NODE_OPTIONS:---max-old-space-size=6144 --gc-interval=100 --optimize-for-size}"
export NODE_HEAP_SIZE_MB="${NODE_HEAP_SIZE_MB:-6144}"

echo "======================================"
echo "Starting Node.js with Memory Config"
echo "======================================"
echo "Environment: ${ENVIRONMENT:-development}"
echo "Node.js Options: $NODE_OPTIONS"
echo "Heap Size: ${NODE_HEAP_SIZE_MB}MB"
echo "======================================"

# Validate Node.js installation
if ! command -v node &> /dev/null; then
    echo "❌ Error: Node.js is not installed"
    exit 1
fi

NODE_VERSION=$(node --version)
echo "Node.js Version: $NODE_VERSION"

# Check if package.json exists
if [ ! -f "package.json" ]; then
    echo "❌ Error: package.json not found"
    exit 1
fi

# Install dependencies if node_modules doesn't exist
if [ ! -d "node_modules" ]; then
    echo "📦 Installing Node.js dependencies..."
    npm install
fi

# Start the application based on the argument provided
SCRIPT_NAME="${1:-start}"

echo "🚀 Starting application with script: $SCRIPT_NAME"

# Export memory configuration for child processes
export NODE_OPTIONS

# Start the application
exec npm run "$SCRIPT_NAME"