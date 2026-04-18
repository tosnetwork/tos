# =============================================================================
# Phase G.3 — Hive client image for the TOS validator
# =============================================================================
#
# Goal: produce a single-validator container that exposes Ethereum JSON-RPC on
# port 8545 (the port hive's `rpc-compat` simulator probes by default), so we
# can run hive against our validator without speaking devp2p.
#
# Two-stage build:
#   stage 1 (builder): clones nothing, just compiles tos-validator-engine and
#                      its sibling tools from a source bind mount or COPY of
#                      the workchain tree at $TOS_SRC (default /tos).
#   stage 2 (runtime): minimal ubuntu:22.04 with only the shared libs the
#                      binary actually needs (see ldd output: gsl, blas, gmp,
#                      gmpxx, stdc++, m, gcc_s, gslcblas).
#
# Build-time argument:
#   TOS_SRC   absolute path inside the build context that contains the source
#             tree (default: ".") — passed via `docker build --build-arg`.
#
# A 30-minute fresh compile from source is the conservative path. A faster
# alternative — short-circuit stage 1 entirely by COPYing a host-built binary
# — is documented in clients/tos/tos.cmd. Both flows produce the same runtime
# image.
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1 — builder
# -----------------------------------------------------------------------------
FROM ubuntu:22.04 AS build
ARG DEBIAN_FRONTEND=noninteractive

# Toolchain. Mirrors Dockerfile.builder so the resulting binary is ABI-
# compatible with what the host CI produces.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        ninja-build \
        clang-14 \
        lld-14 \
        git \
        ca-certificates \
        pkg-config \
        zlib1g-dev \
        libssl-dev \
        libsodium-dev \
        libmicrohttpd-dev \
        liblz4-dev \
        libjemalloc-dev \
        libgsl-dev \
        libgmp-dev \
        libreadline-dev \
        libblas-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tos
COPY . /tos

RUN mkdir build && cd build && \
    CC=clang-14 CXX=clang++-14 cmake -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DPORTABLE=1 \
        -DTOS_USE_JEMALLOC=ON \
        .. && \
    ninja validator-engine generate-random-id create-state dht-server \
          validator-engine-console lite-client

# -----------------------------------------------------------------------------
# Stage 2 — runtime
# -----------------------------------------------------------------------------
FROM ubuntu:22.04 AS runtime
ARG DEBIAN_FRONTEND=noninteractive

# Runtime libraries only — keep this list in sync with `ldd tos-validator-engine`.
# Plus jq + curl for the entrypoint shim.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libstdc++6 \
        libgcc-s1 \
        libgmp10 \
        libgmpxx4ldbl \
        libgsl27 \
        libgslcblas0 \
        libblas3 \
        libssl3 \
        libsodium23 \
        libmicrohttpd12 \
        liblz4-1 \
        libjemalloc2 \
        ca-certificates \
        jq \
        curl \
        netcat \
        python3 \
    && rm -rf /var/lib/apt/lists/*

# Binaries from the build stage.
COPY --from=build /tos/build/validator-engine/validator-engine                   /usr/local/bin/tos-validator-engine
COPY --from=build /tos/build/dht-server/dht-server                               /usr/local/bin/tos-dht-server
COPY --from=build /tos/build/validator-engine-console/validator-engine-console   /usr/local/bin/tos-validator-console
COPY --from=build /tos/build/lite-client/lite-client                             /usr/local/bin/tos-lite-client
COPY --from=build /tos/build/utils/generate-random-id                            /usr/local/bin/tos-genkey
COPY --from=build /tos/build/crypto/create-state                                 /usr/local/bin/tos-create-state

# Fift / smartcontract runtime data (validator-engine reads from -f).
COPY --from=build /tos/crypto/fift/lib       /usr/local/share/tos/fift/lib
COPY --from=build /tos/crypto/smartcont      /usr/local/share/tos/smartcont

# Entrypoint shim and minimal config templates.
COPY test/conformance/hive/clients/tos/tos.cmd               /usr/local/bin/tos.cmd
COPY test/conformance/hive/clients/tos/tos-rpc-proxy.py      /usr/local/bin/tos-rpc-proxy.py
COPY test/conformance/hive/clients/tos/chain-rlp-replay.py   /usr/local/bin/tos-chain-rlp-replay
COPY test/conformance/hive/clients/tos/translate-genesis.py  /usr/local/bin/tos-translate-genesis
COPY test/conformance/hive/clients/tos/mapper.jq             /etc/tos/mapper.jq
COPY test/conformance/hive/clients/tos/genesis.tmpl.json     /etc/tos/genesis.tmpl.json
RUN chmod +x /usr/local/bin/tos.cmd \
             /usr/local/bin/tos-rpc-proxy.py \
             /usr/local/bin/tos-chain-rlp-replay \
             /usr/local/bin/tos-translate-genesis

# Hive's expected JSON-RPC port. Engine API (8551) and devp2p (30303) are NOT
# exposed — see README.md "What's still missing".
EXPOSE 8545

# State lives under /data — keep it ephemeral by default; hive mounts a volume.
WORKDIR /data
ENV TOS_DATA=/data \
    TOS_FIFT_DIR=/usr/local/share/tos/fift/lib \
    TOS_JSONRPC_BIND=0.0.0.0:8545 \
    TOS_INITIAL_SYNC_DELAY=0

ENTRYPOINT ["/usr/local/bin/tos.cmd"]
