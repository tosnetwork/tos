FROM rust:slim AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    make \
    clang \
    libssl-dev \
    libzstd-dev \
    libgoogle-perftools-dev

COPY tosctl/src/ /workspace/tosctl/src/
COPY tl/generate/scheme/lite_api.tl tl/generate/scheme/tos_api.tl tl/generate/scheme/toslib_api.tl /workspace/tl/generate/scheme/
COPY crypto/smartcont/prediction-market-v1.boc.base64 /workspace/crypto/smartcont/
WORKDIR /workspace/tosctl/src

ARG GIT_BRANCH
ARG GIT_COMMIT
ARG GIT_COMMIT_DATE

ENV GIT_BRANCH=${GIT_BRANCH}
ENV GIT_COMMIT=${GIT_COMMIT}
ENV GIT_COMMIT_DATE=${GIT_COMMIT_DATE}

RUN cargo build --release --bin node --bin console

FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3t64 \
    libzstd1 \
    libgoogle-perftools4t64 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /workspace/tosctl/src/target/release/node /usr/local/bin/
COPY --from=builder /workspace/tosctl/src/target/release/console /usr/local/bin/

WORKDIR /node
