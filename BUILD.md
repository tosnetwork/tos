# Build

This document describes the Linux build flow that was verified in this repository on Ubuntu 22.04.

## Verified Environment

- OS: Ubuntu 22.04
- Generator: `Ninja`
- Build system: `CMake`
- Compiler: `clang-21` / `clang++-21`
- Build directory: out-of-source, for example `build-clang21`

## Install Dependencies

Install the base toolchain and libraries:

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
  gawk \
  wget \
  lsb-release \
  software-properties-common \
  gnupg
```

Install `clang-21` if it is not already available:

```bash
cd /tmp
rm -f llvm.sh
wget -q https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 21
```

Verify the compiler:

```bash
clang-21 --version
clang++-21 --version
```

## Configure

Always use an out-of-source build:

```bash
cd /path/to/tos
rm -rf build-clang21
mkdir -p build-clang21
cd build-clang21

cmake .. \
  -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang-21 \
  -DCMAKE_CXX_COMPILER=clang++-21
```

## Build

This project builds successfully with `clang-21`.

Example with a fixed parallelism of `128` jobs:

```bash
cd /path/to/tos/build-clang21
ninja -j128
```

If you want to size parallelism to the machine, using about two thirds of CPU threads is a reasonable default:

```bash
JOBS=$(( $(nproc) * 2 / 3 ))
cd /path/to/tos/build-clang21
ninja -j"${JOBS}"
```

## Test

List available tests:

```bash
cd /path/to/tos/build-clang21
ctest -N
```

Run the test suite:

```bash
cd /path/to/tos/build-clang21
ctest --output-on-failure -j128
```

Or use the same two-thirds parallelism rule:

```bash
JOBS=$(( $(nproc) * 2 / 3 ))
cd /path/to/tos/build-clang21
ctest --output-on-failure -j"${JOBS}"
```

## Verified Result

The following flow was verified successfully in this repository:

```bash
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang-21 -DCMAKE_CXX_COMPILER=clang++-21
ninja -j128
ctest --output-on-failure -j128
```

Observed result:

- Build: success
- Tests: `31/31` passed

## Notes

- The build downloads or builds several bundled dependencies from `third-party` during configuration and compilation.
- `clang-14` was not sufficient for this tree; `clang-21` was used for the verified build.
- If you have already modified branding or file names in the source tree, keep include paths and Fift library names consistent before building.
