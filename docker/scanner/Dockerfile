# Multi-stage Dockerfile for Zond Scanner
# Stage 1: Build the binary inside a compatible environment
FROM rust:1.93-slim-bookworm AS builder

WORKDIR /app
COPY . .
RUN cargo build --release

# Stage 2: Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    iproute2 \
    iptables \
    net-tools \
    iputils-ping \
    tcpdump \
    netcat-openbsd \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary and assets from the builder stage
COPY --from=builder /app/target/release/zond /app/zond
COPY --from=builder /app/assets /app/assets

ENV PATH="/app:${PATH}"
CMD ["tail", "-f", "/dev/null"]
