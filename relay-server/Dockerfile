# Build stage
FROM rust:1.83-slim AS builder

WORKDIR /app

# Copy manifests
COPY Cargo.toml ./

# Copy source code
COPY src ./src

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

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

# Run the binary
CMD ["/app/relay-server"]
