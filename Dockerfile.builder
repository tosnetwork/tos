# TOS Builder Base Image
# Pre-installs Clang 21 + uv so CI workflows don't need external downloads.
# Rebuild only when updating toolchain versions.
#
# One stage, Ubuntu 24.04, built natively for linux/amd64 and linux/arm64 by
# .github/workflows/build-builder-image.yml and published as one
# multi-architecture tag, ghcr.io/tosnetwork/tos-builder:ubuntu-24.04. The node
# image (Dockerfile) builds FROM that tag on both architectures, so the builder
# must exist for every platform the node image is released for.
#
# Local build: docker build -f Dockerfile.builder --target builder-24 -t tos-builder:ubuntu-24.04 .

FROM ubuntu:24.04 AS builder-24
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y build-essential git cmake ninja-build pkg-config \
    autoconf automake libtool libjemalloc-dev ccache gperf ripgrep jq wget curl \
    lsb-release software-properties-common gnupg python3 python3-dev \
    libgmp-dev libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Use the same authenticated package boundary for both base distributions.
COPY scripts/install-llvm-toolchain.sh /opt/tos/scripts/
COPY scripts/keys/apt-llvm-org.asc /opt/tos/scripts/keys/
RUN bash /opt/tos/scripts/install-llvm-toolchain.sh 21 all && rm -rf /var/lib/apt/lists/*

ENV CC=/usr/bin/clang-21
ENV CXX=/usr/bin/clang++-21

# Install uv (pinned version). TARGETARCH is set by BuildKit for the platform
# being built; each architecture has its own pinned digest in build-tool-pins.json.
ARG TARGETARCH
COPY scripts/verify-build-tool.py scripts/build-tool-pins.json /opt/tos/scripts/
RUN set -eu; \
    case "${TARGETARCH:-$(dpkg --print-architecture)}" in \
      amd64) UV_ARCH=x86_64 ;; \
      arm64) UV_ARCH=aarch64 ;; \
      *) echo "no pinned uv for architecture ${TARGETARCH:-unknown}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "$(python3 /opt/tos/scripts/verify-build-tool.py --url "uv-${UV_ARCH}")" -o /tmp/uv.tar.gz && \
    python3 /opt/tos/scripts/verify-build-tool.py "uv-${UV_ARCH}" /tmp/uv.tar.gz && \
    tar -xzf /tmp/uv.tar.gz -C /tmp && \
    install -m 0755 "/tmp/uv-${UV_ARCH}-unknown-linux-gnu/uv" /usr/local/bin/uv && \
    install -m 0755 "/tmp/uv-${UV_ARCH}-unknown-linux-gnu/uvx" /usr/local/bin/uvx && \
    rm -rf /tmp/uv.tar.gz "/tmp/uv-${UV_ARCH}-unknown-linux-gnu"
ENV PATH="/root/.local/bin:$PATH"

RUN clang-21 --version && uv --version
