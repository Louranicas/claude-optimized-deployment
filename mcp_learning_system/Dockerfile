# Multi-stage Docker build for MCP Learning System
# Production-ready container with security hardening

# Stage 1: Build stage
FROM python:3.12-slim as builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt requirements-dev.txt ./

# Create virtual environment and install dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip setuptools wheel
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -r requirements-dev.txt

# Copy source code
COPY . .

# Install the package
RUN pip install --no-cache-dir .

# Stage 2: Production stage
FROM python:3.12-slim

# Security: Create non-root user
RUN groupadd -r mcpuser && useradd -r -g mcpuser mcpuser

# Install runtime dependencies and security tools
RUN apt-get update && apt-get install -y \
    curl \
    netcat-openbsd \
    jq \
    ca-certificates \
    dumb-init \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy application code
COPY --from=builder --chown=mcpuser:mcpuser /app .

# Create necessary directories
RUN mkdir -p /app/logs /app/data /app/config \
    && chown -R mcpuser:mcpuser /app

# Security: Remove sensitive files and set permissions
RUN find /app -name "*.pyc" -delete \
    && find /app -name "__pycache__" -type d -exec rm -rf {} + \
    && chmod -R 755 /app \
    && chmod 750 /app/bash_god_mcp_server.py

# Install health check script
COPY <<EOF /usr/local/bin/healthcheck.sh
#!/bin/bash
set -e
# Health check for MCP server
python3 -c "
import sys
import json
try:
    from bash_god_mcp_server import BashGodCommandLibrary
    library = BashGodCommandLibrary()
    if len(library.commands) >= 800:
        print('Health check passed: {} commands loaded'.format(len(library.commands)))
        sys.exit(0)
    else:
        print('Health check failed: {} commands loaded'.format(len(library.commands)))
        sys.exit(1)
except Exception as e:
    print('Health check failed:', str(e))
    sys.exit(1)
"
EOF

RUN chmod +x /usr/local/bin/healthcheck.sh

# Switch to non-root user
USER mcpuser

# Set environment variables
ENV PYTHONPATH="/app:$PYTHONPATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV MCP_SERVER_HOST=0.0.0.0
ENV MCP_SERVER_PORT=8000
ENV MCP_LOG_LEVEL=INFO

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /usr/local/bin/healthcheck.sh

# Set labels for metadata
LABEL \
    org.opencontainers.image.title="MCP Learning System" \
    org.opencontainers.image.description="Production-ready MCP server with 850+ bash commands" \
    org.opencontainers.image.version="1.0.0" \
    org.opencontainers.image.authors="Agent 10 - Production Certification" \
    org.opencontainers.image.source="https://github.com/company/mcp-learning-system" \
    org.opencontainers.image.licenses="MIT"

# Use dumb-init as PID 1 for proper signal handling
ENTRYPOINT ["/usr/bin/dumb-init", "--"]

# Default command
CMD ["python3", "bash_god_mcp_server.py"]