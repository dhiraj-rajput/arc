# Multi-stage build for Rust arc-relay
FROM rust:slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/arc
COPY . .

# Build the release binary specifically for arc-relay
RUN cargo build --release --bin arc-relay

# Final runtime image
FROM debian:bookworm-slim

# Install runtime SSL certificates for secure outbound/inbound HTTPS/WSS
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/arc/target/release/arc-relay /usr/local/bin/arc-relay

# Render dynamically assigns a port via the PORT env var (defaults to 10000 on Render)
EXPOSE 10000

ENV ARC_RELAY_PORT=10000
ENV ARC_RELAY_BIND=0.0.0.0

CMD ["arc-relay"]
