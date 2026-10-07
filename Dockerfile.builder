# TOS Builder Base Image
# Pre-installs Clang 21 + uv so CI workflows don't need external downloads.
# Rebuild only when updating toolchain versions.
#
# Build:  docker build -f Dockerfile.builder -t ghcr.io/tosnetwork/tos-builder:latest .
# Push:   docker push ghcr.io/tosnetwork/tos-builder:latest

FROM ubuntu:22.04 AS builder-22
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y build-essential git cmake ninja-build pkg-config \
    autoconf automake libtool libjemalloc-dev ccache gperf jq wget curl \
    lsb-release software-properties-common gnupg python3 python3-dev \
    libgmp-dev libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Ubuntu 22.04 apt ripgrep is built without PCRE2; install the musl release
# binary which bundles PCRE2 statically. Pin version + SHA256 for reproducibility.
RUN set -eux; \
    RG_VERSION=14.1.1; \
    RG_SHA256=4cf9f2741e6c465ffdb7c26f38056a59e2a2544b51f7cc128ef28337eeae4d8e; \
    curl -fsSL "https://github.com/BurntSushi/ripgrep/releases/download/${RG_VERSION}/ripgrep-${RG_VERSION}-x86_64-unknown-linux-musl.tar.gz" \
        -o /tmp/rg.tar.gz && \
    echo "${RG_SHA256}  /tmp/rg.tar.gz" | sha256sum -c - && \
    tar -xz -f /tmp/rg.tar.gz -C /tmp && \
    mv "/tmp/ripgrep-${RG_VERSION}-x86_64-unknown-linux-musl/rg" /usr/local/bin/rg && \
    chmod +x /usr/local/bin/rg && \
    rm -rf /tmp/rg.tar.gz "/tmp/ripgrep-${RG_VERSION}-x86_64-unknown-linux-musl" && \
    rg --pcre2-version

# Use a repository-pinned signing key and apt's authenticated packages.
COPY scripts/install-llvm-toolchain.sh /opt/tos/scripts/
COPY scripts/keys/apt-llvm-org.asc /opt/tos/scripts/keys/
RUN bash /opt/tos/scripts/install-llvm-toolchain.sh 21 all && rm -rf /var/lib/apt/lists/*

ENV CC=/usr/bin/clang-21
ENV CXX=/usr/bin/clang++-21

# Install uv (pinned version)
COPY scripts/verify-build-tool.py scripts/build-tool-pins.json /opt/tos/scripts/
RUN curl -fsSL https://github.com/astral-sh/uv/releases/download/0.11.7/uv-x86_64-unknown-linux-gnu.tar.gz -o /tmp/uv.tar.gz && \
    python3 /opt/tos/scripts/verify-build-tool.py uv-x86_64 /tmp/uv.tar.gz && \
    tar -xzf /tmp/uv.tar.gz -C /tmp && \
    install -m 0755 /tmp/uv-x86_64-unknown-linux-gnu/uv /usr/local/bin/uv && \
    install -m 0755 /tmp/uv-x86_64-unknown-linux-gnu/uvx /usr/local/bin/uvx && \
    rm -rf /tmp/uv.tar.gz /tmp/uv-x86_64-unknown-linux-gnu
ENV PATH="/root/.local/bin:$PATH"

# Verify tools
RUN clang-21 --version && uv --version

# ---

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

# Install uv (pinned version)
COPY scripts/verify-build-tool.py scripts/build-tool-pins.json /opt/tos/scripts/
RUN curl -fsSL https://github.com/astral-sh/uv/releases/download/0.11.7/uv-x86_64-unknown-linux-gnu.tar.gz -o /tmp/uv.tar.gz && \
    python3 /opt/tos/scripts/verify-build-tool.py uv-x86_64 /tmp/uv.tar.gz && \
    tar -xzf /tmp/uv.tar.gz -C /tmp && \
    install -m 0755 /tmp/uv-x86_64-unknown-linux-gnu/uv /usr/local/bin/uv && \
    install -m 0755 /tmp/uv-x86_64-unknown-linux-gnu/uvx /usr/local/bin/uvx && \
    rm -rf /tmp/uv.tar.gz /tmp/uv-x86_64-unknown-linux-gnu
ENV PATH="/root/.local/bin:$PATH"

RUN clang-21 --version && uv --version
