# Production Dockerfile for Claude Optimized Deployment
# Multi-stage build for security and size optimization

# Stage 1: Builder
FROM python:3.12-slim-bullseye AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Rust for building extensions
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build

# Copy and install Python dependencies
COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

# Copy source and build Rust extensions
COPY rust_core ./rust_core
RUN if [ -d "rust_core" ]; then \
        cd rust_core && \
        cargo build --release && \
        cd .. ; \
    fi

# Stage 2: Runtime
FROM python:3.12-slim-bullseye

# Security: Create non-root user
RUN groupadd -r appuser && \
    useradd -r -g appuser -u 1000 appuser && \
    mkdir -p /app /app/logs /app/data && \
    chown -R appuser:appuser /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy wheels from builder
COPY --from=builder /wheels /wheels

# Install Python packages from wheels
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --no-index --find-links=/wheels /wheels/* && \
    rm -rf /wheels

WORKDIR /app

# Copy application code
COPY --chown=appuser:appuser src ./src
COPY --chown=appuser:appuser scripts ./scripts

# Copy Rust artifacts if built
COPY --from=builder --chown=appuser:appuser /build/rust_core/target/release/*.so* ./src/ 2>/dev/null || true

# Security: Drop all capabilities
USER appuser

# Security configurations
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Non-root port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --retries=3 --start-period=40s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health').read()" || exit 1

# Security: Run with minimal privileges
ENTRYPOINT ["python", "-m"]
CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]