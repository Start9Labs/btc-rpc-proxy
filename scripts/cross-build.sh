#!/bin/bash
set -euo pipefail

# Cross-compilation script for multi-architecture Docker builds
# TARGETARCH is set by Docker Buildx

: "${TARGETARCH:?TARGETARCH environment variable must be set}"

# Map Docker architecture to Rust target and linker
case "$TARGETARCH" in
    amd64)
        RUST_TARGET="x86_64-unknown-linux-gnu"
        ;;
    arm64)
        RUST_TARGET="aarch64-unknown-linux-gnu"
        export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
        ;;
    riscv64)
        RUST_TARGET="riscv64gc-unknown-linux-gnu"
        export CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER=riscv64-linux-gnu-gcc
        ;;
    *)
        echo "Unsupported architecture: $TARGETARCH" >&2
        exit 1
        ;;
esac

echo "Building for $TARGETARCH (Rust target: $RUST_TARGET)"

rustup target add "$RUST_TARGET"
cargo build --release --target "$RUST_TARGET"

# Copy to predictable location for Dockerfile
cp "target/$RUST_TARGET/release/btc_rpc_proxy" /app/btc_rpc_proxy
