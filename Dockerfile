# syntax=docker/dockerfile:1

# Builder - runs on native platform for fast cross-compilation
FROM --platform=$BUILDPLATFORM rust:1.85 AS builder

RUN apt-get update && apt-get install -y \
    gcc-aarch64-linux-gnu \
    gcc-riscv64-linux-gnu \
    libc6-dev-arm64-cross \
    libc6-dev-riscv64-cross

WORKDIR /app
COPY . .

ARG TARGETARCH
RUN ./scripts/cross-build.sh

# Final - runs on target platform
FROM debian:trixie-slim

COPY --from=builder /app/btc_rpc_proxy /usr/bin/btc_rpc_proxy
RUN chmod +x /usr/bin/btc_rpc_proxy

SHELL [ "/bin/bash", "-c" ]
ENTRYPOINT chmod 600 /etc/btc_rpc_proxy/btc_rpc_proxy.toml && exec /usr/bin/btc_rpc_proxy --conf /etc/btc_rpc_proxy/btc_rpc_proxy.toml
