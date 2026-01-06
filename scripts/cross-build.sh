#!/bin/bash
set -euo pipefail

# Cross-compilation script for multi-architecture Docker builds using cargo-zigbuild
# TARGETARCH is set by Docker Buildx

: "${TARGETARCH:?TARGETARCH environment variable must be set}"

# Map Docker architecture to Rust target
case "$TARGETARCH" in
    amd64)
        RUST_TARGET="x86_64-unknown-linux-gnu"
        ;;
    arm64)
        RUST_TARGET="aarch64-unknown-linux-gnu"
        ;;
    riscv64)
        RUST_TARGET="riscv64gc-unknown-linux-gnu"
        ;;
    *)
        echo "Unsupported architecture: $TARGETARCH" >&2
        exit 1
        ;;
esac

echo "Building for $TARGETARCH (Rust target: $RUST_TARGET)"
echo "$RUST_TARGET" > /tmp/rust_target

cargo zigbuild --release --target "$RUST_TARGET"
