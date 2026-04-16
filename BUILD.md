# Build

This document describes the build flow verified on Ubuntu 22.04.

## Verified Environment

- OS: Ubuntu 22.04
- Generator: `Ninja` or `Make`
- Build system: `CMake` 3.16+
- Compiler: `clang-21` / `clang++-21` (auto-detected by CMakeLists)
- Build directory: out-of-source

## Install Dependencies

```bash
sudo apt update
sudo apt install -y \
  build-essential \
  git \
  cmake \
  ninja-build \
  ccache \
  autoconf \
  automake \
  libtool \
  texinfo \
  pkg-config \
  python3 \
  python3-dev \
  libgflags-dev \
  libreadline-dev \
  libgsl-dev \
  libblas-dev \
  libgslcblas0 \
  libjemalloc-dev \
  libgmp-dev \
  gawk \
  wget \
  lsb-release \
  software-properties-common \
  gnupg
```

Install `clang-21` if not already available:

```bash
cd /tmp
rm -f llvm.sh
wget -q https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 21
```

Verify:

```bash
clang-21 --version
clang++-21 --version
```

## Configure

The build system auto-detects clang if available. No need to specify the compiler explicitly.

```bash
cd /path/to/tos
mkdir -p build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
```

If you want to use a specific compiler:

```bash
cmake .. -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang-21 \
  -DCMAKE_CXX_COMPILER=clang++-21
```

## Build

```bash
cd build
make -j$(nproc)
```

Or with Ninja:

```bash
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release
ninja -j$(nproc)
```

## EVM Workchain Tests

Run the EVM workchain test suite (10 tests):

```bash
cd build
./crypto/block/evm-workchain/test-evm-executor
```

Expected output: `All tests passed.`

Tests cover:
- ETH value transfer
- Contract CREATE and CALL with SSTORE/SLOAD
- 28 eth_* RPC methods including eth_call and eth_estimateGas
- secp256k1 signed transaction (full RLP encode → decode → sender recovery → execute)
- Persistent state (RocksDB write → close → reopen → read)
- ConfigParam 12 WorkchainDescr TLB validation
- bn254 ecadd precompile (G+G = correct 2*G)
- Deterministic replay (same tx sequence → identical state)
- Event LOG emission and log indexing

## Full Test Suite

```bash
cd build
ctest --output-on-failure -j$(nproc)
```

## Wallet Integration Test

With the node running (validator-engine with `--json-rpc`):

```bash
node test/evm-workchain/wallet-test.js http://127.0.0.1:8081
```

Tests 16 RPC methods that MetaMask probes during connection.

## Dependencies

### System packages

| Package | Purpose |
|---------|---------|
| `libgmp-dev` | GMP big integer library (modexp precompile, libff) |
| `libreadline-dev` | Fift/FunC interactive tools |
| `libjemalloc-dev` | Optional memory allocator |

### Vendored third-party (no external downloads needed)

| Directory | Source | Purpose |
|-----------|--------|---------|
| `third-party/evmone/` | erigontech/evmone | EVM bytecode execution (evmone 0.11.0) |
| `third-party/intx/` | chfast/intx | 256-bit integer arithmetic |
| `third-party/ethash/` | chfast/ethash | Keccak hashing |
| `third-party/silkworm/core/` | erigontech/silkworm | Ethereum types, RLP, state, execution |
| `third-party/libff/` | erigontech/libff | alt_bn128 pairing (ecpairing precompile) |
| `third-party/compat/` | local | Shims for magic_enum, GSL, tl-expected, nlohmann_json |
| `third-party/rocksdb/` | facebook/rocksdb | Key-value storage (original dependency) |
| `third-party/secp256k1/` | bitcoin-core/secp256k1 | ECDSA signature recovery (original dependency) |
| `third-party/blst/` | supranational/blst | BLS/bn254 elliptic curve (original dependency) |

All vendored code is physically embedded — no git submodules, no external fetching during build.

## Compiler Notes

- **clang 21+**: Recommended. The CMakeLists auto-detects and prefers clang.
- **GCC 11**: Not supported. C++20 coroutine bug (`co_return {}` ambiguity).
- **GCC 12**: Not supported. Same coroutine issue + constexpr bug.
- **GCC 15**: Partial. Coroutine fix applied (`co_return td::Unit{}`), but has template strictness issues in upstream modules.
