# syntax=docker/dockerfile:1

# Builder - runs on native platform using cargo-zigbuild for cross-compilation
FROM --platform=$BUILDPLATFORM start9/cargo-zigbuild AS builder

WORKDIR /app
COPY . .

ARG TARGETARCH
RUN ./scripts/cross-build.sh && \
    ln -s /app/target/$(cat /tmp/rust_target)/release/btc_rpc_proxy /app/btc_rpc_proxy

# Final - runs on target platform
FROM debian:trixie-slim

COPY --from=builder /app/btc_rpc_proxy /usr/bin/btc_rpc_proxy
RUN chmod +x /usr/bin/btc_rpc_proxy

SHELL [ "/bin/bash", "-c" ]
ENTRYPOINT chmod 600 /etc/btc_rpc_proxy/btc_rpc_proxy.toml && exec /usr/bin/btc_rpc_proxy --conf /etc/btc_rpc_proxy/btc_rpc_proxy.toml
