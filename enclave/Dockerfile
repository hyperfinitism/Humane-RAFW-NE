FROM rust:1.90-bookworm AS builder
WORKDIR /workspace

# Native deps (bindgen/crypto crates) + certs
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    libclang-dev \
    llvm-dev \
    pkg-config \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Copy sources
COPY . /workspace

# Release build
RUN cargo build --release

# Minimal runtime image
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /workspace/target/release/rafwne-enclave /usr/local/bin/rafwne-enclave

# Run in foreground (PID 1) and receive SIGTERM properly
ENTRYPOINT ["/usr/local/bin/rafwne-enclave"]
