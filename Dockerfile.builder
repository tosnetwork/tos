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
    autoconf automake libtool libjemalloc-dev ccache gperf wget curl \
    lsb-release software-properties-common gnupg python3 python3-dev && \
    rm -rf /var/lib/apt/lists/*

# Install Clang 21 (pinned — no runtime download needed by CI)
RUN wget -q https://apt.llvm.org/llvm.sh && \
    chmod +x llvm.sh && \
    ./llvm.sh 21 all && \
    rm llvm.sh && \
    rm -rf /var/lib/apt/lists/*

ENV CC=/usr/bin/clang-21
ENV CXX=/usr/bin/clang++-21

# Install uv (pinned version)
RUN curl -LsSf https://astral.sh/uv/0.7.12/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"

# Verify tools
RUN clang-21 --version && uv --version

# ---

FROM ubuntu:24.04 AS builder-24
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y build-essential git cmake ninja-build pkg-config \
    autoconf automake libtool libjemalloc-dev ccache gperf wget curl \
    lsb-release software-properties-common gnupg python3 python3-dev && \
    rm -rf /var/lib/apt/lists/*

# Install Clang 21
RUN wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \
    echo "deb http://apt.llvm.org/noble/ llvm-toolchain-noble-21 main" | tee /etc/apt/sources.list.d/llvm.list && \
    apt-get update && \
    apt-get install -y clang-21 && \
    rm -rf /var/lib/apt/lists/*

ENV CC=/usr/bin/clang-21
ENV CXX=/usr/bin/clang++-21

# Install uv (pinned version)
RUN curl -LsSf https://astral.sh/uv/0.7.12/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"

RUN clang-21 --version && uv --version
