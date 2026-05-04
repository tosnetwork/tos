# TOS Builder Base Image
# Pre-installs Clang 21 + uv so CI workflows don't need external downloads.
# Rebuild only when updating toolchain versions.
#
# Build:  docker build -f Dockerfile.builder -t ghcr.io/tosnetwork/tos-builder:latest .
# Push:   docker push ghcr.io/tosnetwork/tos-builder:latest

FROM ubuntu:22.04 AS builder-22
ARG DEBIAN_FRONTEND=noninteractive
# Pinned liboqs commit — must match uno/crypto/LIBOQS_VERSION.md and
# .github/workflows/uno-ci.yml's LIBOQS_COMMIT env var.
ARG LIBOQS_COMMIT=3cb781fd4737c900ad755ee0bb9e1949d0f68955
RUN apt-get update && \
    apt-get install -y build-essential git cmake ninja-build pkg-config \
    autoconf automake libtool libjemalloc-dev ccache gperf wget curl \
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

# Install Clang 21 (pinned — no runtime download needed by CI)
RUN wget -q https://apt.llvm.org/llvm.sh && \
    chmod +x llvm.sh && \
    ./llvm.sh 21 all && \
    rm llvm.sh && \
    rm -rf /var/lib/apt/lists/*

ENV CC=/usr/bin/clang-21
ENV CXX=/usr/bin/clang++-21

# Build + install liboqs at the pinned commit (ML-KEM-768 only, static).
# CMake's default find_path/find_library picks it up from /usr/local without
# extra hints (see uno/CMakeLists.txt §liboqs detection).
RUN git clone https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs-src && \
    cd /tmp/liboqs-src && \
    git checkout "${LIBOQS_COMMIT}" && \
    cmake -S . -B /tmp/liboqs-build \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_ENABLE_KEM_ML_KEM=ON \
        -DBUILD_SHARED_LIBS=OFF \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DCMAKE_BUILD_TYPE=Release && \
    cmake --build /tmp/liboqs-build -j"$(nproc)" && \
    cmake --install /tmp/liboqs-build && \
    test -f /usr/local/lib/liboqs.a && \
    test -f /usr/local/include/oqs/oqs.h && \
    rm -rf /tmp/liboqs-src /tmp/liboqs-build

# Install uv (pinned version)
RUN curl -LsSf https://astral.sh/uv/0.11.7/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"

# Verify tools
RUN clang-21 --version && uv --version

# ---

FROM ubuntu:24.04 AS builder-24
ARG DEBIAN_FRONTEND=noninteractive
# Pinned liboqs commit — must match uno/crypto/LIBOQS_VERSION.md and
# .github/workflows/uno-ci.yml's LIBOQS_COMMIT env var.
ARG LIBOQS_COMMIT=3cb781fd4737c900ad755ee0bb9e1949d0f68955
RUN apt-get update && \
    apt-get install -y build-essential git cmake ninja-build pkg-config \
    autoconf automake libtool libjemalloc-dev ccache gperf ripgrep wget curl \
    lsb-release software-properties-common gnupg python3 python3-dev \
    libgmp-dev libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Install Clang 21
RUN wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \
    echo "deb http://apt.llvm.org/noble/ llvm-toolchain-noble-21 main" | tee /etc/apt/sources.list.d/llvm.list && \
    apt-get update && \
    apt-get install -y clang-21 lld-21 && \
    rm -rf /var/lib/apt/lists/*

ENV CC=/usr/bin/clang-21
ENV CXX=/usr/bin/clang++-21

# Build + install liboqs at the pinned commit (ML-KEM-768 only, static).
# CMake's default find_path/find_library picks it up from /usr/local without
# extra hints (see uno/CMakeLists.txt §liboqs detection).
RUN git clone https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs-src && \
    cd /tmp/liboqs-src && \
    git checkout "${LIBOQS_COMMIT}" && \
    cmake -S . -B /tmp/liboqs-build \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_ENABLE_KEM_ML_KEM=ON \
        -DBUILD_SHARED_LIBS=OFF \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DCMAKE_BUILD_TYPE=Release && \
    cmake --build /tmp/liboqs-build -j"$(nproc)" && \
    cmake --install /tmp/liboqs-build && \
    test -f /usr/local/lib/liboqs.a && \
    test -f /usr/local/include/oqs/oqs.h && \
    rm -rf /tmp/liboqs-src /tmp/liboqs-build

# Install uv (pinned version)
RUN curl -LsSf https://astral.sh/uv/0.11.7/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"

RUN clang-21 --version && uv --version
