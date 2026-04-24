# TOS Miner Release Process

This document explains how to cut a tagged release that produces pre-built
miner binaries for all supported platforms, and how to verify those artifacts.

## Overview

Three GitHub Actions workflows fire automatically on any `v*` tag push:

| Workflow | File | Artifact |
|---|---|---|
| Release TOS pow-miner | `.github/workflows/release-tos-pow-miner.yml` | `tos-pow-miner-{platform}-{version}.tar.gz` |
| Release tosctl | `.github/workflows/release-tosctl.yml` | `tosctl-{platform}-{version}.tar.gz` |
| Release eTOS miner config | `.github/workflows/release-etos-miner-config.yml` | `etos-miner-config-{version}.tar.gz` |

Each artifact is accompanied by a `.sha256` checksum file.

## Platform Matrix

| Platform identifier | Runner | Notes |
|---|---|---|
| `linux-x64` | `ubuntu-22.04` | Standard x86-64 Linux |
| `macos-x64` | `macos-15-intel` | Intel Mac (Rosetta-compatible) |
| `macos-arm64` | `macos-14` | Apple Silicon (M1/M2) |

## How to Cut a Release

### Step 1 — Prepare the codebase

Ensure `main` (or your release branch) is in the state you want to ship.
Run the full CI suite locally or check that all branch CI jobs are green.

### Step 2 — Push a version tag

Tags must match the pattern `v*` (e.g. `v0.1.0`, `v1.0.0-rc2`).

```bash
# Create and push a signed annotated tag (preferred)
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0

# Or a lightweight tag if you do not use GPG signing
git tag v0.1.0
git push origin v0.1.0
```

### Step 3 — Monitor CI

Navigate to the repository's **Actions** tab on GitHub. Three workflow runs
named "Release TOS pow-miner", "Release tosctl", and "Release eTOS miner
config" will start. Each workflow uploads its artifacts to the GitHub Release
that GitHub auto-creates for the tag.

Expected completion time:

- `release-tos-pow-miner.yml` — ~15–30 min per platform (C++ build)
- `release-tosctl.yml` — ~10–20 min per platform (Rust release build)
- `release-etos-miner-config.yml` — ~1–2 min (no compilation)

### Step 4 — Publish the release

If you use GitHub's draft release feature, navigate to **Releases**, find
the draft, edit the release notes, and click **Publish**. If you push the
tag without a pre-created draft release, GitHub auto-publishes it; you can
edit the notes afterwards.

## Artifact Locations

After all three workflows complete, the GitHub Release page for the tag will
contain:

```
tos-pow-miner-linux-x64-v0.1.0.tar.gz
tos-pow-miner-linux-x64-v0.1.0.tar.gz.sha256
tos-pow-miner-macos-x64-v0.1.0.tar.gz
tos-pow-miner-macos-x64-v0.1.0.tar.gz.sha256
tos-pow-miner-macos-arm64-v0.1.0.tar.gz
tos-pow-miner-macos-arm64-v0.1.0.tar.gz.sha256

tosctl-linux-x64-v0.1.0.tar.gz
tosctl-linux-x64-v0.1.0.tar.gz.sha256
tosctl-macos-x64-v0.1.0.tar.gz
tosctl-macos-x64-v0.1.0.tar.gz.sha256
tosctl-macos-arm64-v0.1.0.tar.gz
tosctl-macos-arm64-v0.1.0.tar.gz.sha256

etos-miner-config-v0.1.0.tar.gz
etos-miner-config-v0.1.0.tar.gz.sha256
```

## How to Verify Release Artifacts

### Download the artifact and its checksum

```bash
VERSION=v0.1.0
PLATFORM=linux-x64

# pow-miner
curl -LO "https://github.com/tosnetwork/tos/releases/download/${VERSION}/tos-pow-miner-${PLATFORM}-${VERSION}.tar.gz"
curl -LO "https://github.com/tosnetwork/tos/releases/download/${VERSION}/tos-pow-miner-${PLATFORM}-${VERSION}.tar.gz.sha256"

# tosctl
curl -LO "https://github.com/tosnetwork/tos/releases/download/${VERSION}/tosctl-${PLATFORM}-${VERSION}.tar.gz"
curl -LO "https://github.com/tosnetwork/tos/releases/download/${VERSION}/tosctl-${PLATFORM}-${VERSION}.tar.gz.sha256"
```

### Verify the SHA256 checksum

```bash
# Linux / macOS with GNU coreutils
sha256sum --check tos-pow-miner-${PLATFORM}-${VERSION}.tar.gz.sha256

# macOS with BSD sha256 (if sha256sum is not available)
shasum -a 256 -c tos-pow-miner-${PLATFORM}-${VERSION}.tar.gz.sha256
```

Expected output: `tos-pow-miner-linux-x64-v0.1.0.tar.gz: OK`

### Extract and run

```bash
tar -xzf tos-pow-miner-${PLATFORM}-${VERSION}.tar.gz
./pow-miner --help
```

## eTOS Miner Config

The eTOS release contains configuration templates only — no binary.

```bash
VERSION=v0.1.0
curl -LO "https://github.com/tosnetwork/tos/releases/download/${VERSION}/etos-miner-config-${VERSION}.tar.gz"
sha256sum --check "etos-miner-config-${VERSION}.tar.gz.sha256"
tar -xzf "etos-miner-config-${VERSION}.tar.gz"
ls "etos-miner-config-${VERSION}/"
```

See `evm/contracts/etos-miner-config/README.md` for configuration
instructions.

## Reproducing a Build Locally

All three workflows pin exact compiler and toolchain versions. To reproduce a
Linux x86-64 build:

### pow-miner (C++)

```bash
# Requirements: cmake, ninja, clang-21, libssl-dev, Rust 1.91.1
git checkout v0.1.0
cmake -S . -B build \
  -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang-21 \
  -DCMAKE_CXX_COMPILER=clang++-21
cmake --build build --target pow-miner -j"$(nproc)"
```

### tosctl (Rust)

```bash
# Requirements: Rust 1.91.1 (rustup toolchain install 1.91.1)
git checkout v0.1.0
cd tosctl/uno
cargo +1.91.1 build --release
```

## Notes on pow-miner Status

The `pow-miner` C++ source (`crypto/util/pow-miner-*.cpp`) is inherited from
the TON codebase (Task #11). Once that source and its CMake target are merged,
the `release-tos-pow-miner.yml` workflow will build it automatically on each
tag push. Until then, the workflow will fail at the "Build pow-miner" step
and can be re-triggered once the source is in place.

## Related Documents

- `doc/Mining-Design.md` — full mining economics and parameters for all three coins
- `doc/tos-release-policy.md` — TOS release stability and compatibility policy
- `evm/contracts/etos-miner-config/README.md` — eTOS miner quick start
