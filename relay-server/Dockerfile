# Build stage
FROM rust:1.95.0-slim-bookworm@sha256:d7482085ff5b415f84dba5647ae71606650bdef00db7aeb69f4b3d170c3e4082 AS builder

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Build the application
RUN cargo build --locked --release

# Runtime stage
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

# Install CA certificates for HTTPS
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from the builder
COPY --from=builder /app/target/release/relay-server /app/relay-server

# Expose port 8081 (default) - can be overridden with PORT env var
EXPOSE 8081

# ALLOWED_GATEWAY_DOMAINS is required at runtime; never authorize gateways by default.
ENV RUST_LOG=relay_server=info \
    PORT=8081

# The relay needs neither root nor writable runtime state.
USER 65532:65532

# Run the binary
CMD ["/app/relay-server"]
