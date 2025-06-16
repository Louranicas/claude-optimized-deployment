FROM rust:1.75-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy Cargo files
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src/ ./src/

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -m -u 1001 bridge

# Create app directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/target/release/bridge-server /app/bridge-server

# Copy any additional files needed
COPY ai_docs/ /app/ai_docs/

# Change ownership
RUN chown -R bridge:bridge /app

# Switch to app user
USER bridge

# Expose port
EXPOSE 8671

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8671/bridge/health || exit 1

# Set environment variables
ENV RUST_LOG=info
ENV BRIDGE_PORT=8671
ENV BRIDGE_HOST=0.0.0.0

# Run the application
CMD ["./bridge-server"]