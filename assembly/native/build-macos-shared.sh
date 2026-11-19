#!/bin/bash
# macOS on Apple silicon or Intel: the same targets as build-ubuntu-shared.sh,
# built with Apple clang against the selected SDK (BUILD.md, macOS Development Build).
# There are no macOS release artifacts, so this script has no artifact step.

with_tests=false
with_ccache=false

while getopts 'tc' flag; do
  case "${flag}" in
    t) with_tests=true ;;
    c) with_ccache=true ;;
    *) break
       ;;
  esac
done

test "$(uname -s)" = Darwin || { echo "this script builds on macOS only"; exit 1; }
# The CPU level a CI build is fixed to, and the hardware SHA-256 backend a
# validator on this architecture must verify with (doc/Validator.md).
case "$(uname -m)" in
  arm64) CI_ARCH=armv8-a SLHDSA_BACKEND=TOS_SLHDSA_ARMV8_SHA2 ;;
  x86_64) CI_ARCH=x86-64-v2 SLHDSA_BACKEND=TOS_SLHDSA_SHA_NI ;;
  *) echo "this script builds on arm64 or x86_64 only"; exit 1 ;;
esac

# Homebrew's GNU ar (binutils) writes archives Apple's linker rejects, and
# Homebrew LLVM fails the QUIC library's OpenSSL probe: keep both, and GNU
# coreutils, off PATH, and put the system tools first.
PATH="$(echo "$PATH" | tr ':' '\n' | grep -v -E 'binutils|llvm|coreutils' | paste -sd: -)"
export PATH="/usr/bin:$PATH"

SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"
test -d "$SDKROOT" || { echo "no macOS SDK"; exit 1; }
export SDKROOT
CC="$(xcrun --find clang)"
CXX="$(xcrun --find clang++)"
echo "Using SDKROOT=$SDKROOT CC=$CC CXX=$CXX"

if [ "$with_ccache" = true ]; then
  mkdir -p ~/.ccache
  export CCACHE_DIR="${CCACHE_DIR:-$HOME/.ccache}"
  ccache -M "${CCACHE_MAXSIZE:-0}"
  test $? -eq 0 || { echo "ccache not installed"; exit 1; }
else
  export CCACHE_DISABLE=1
fi

# Avoid -march=native with a shared CI ccache.
CMAKE_EXTRA_ARGS=()
if [ "${GITHUB_ACTIONS}" = "true" ] || [ "$with_ccache" = true ]; then
  CMAKE_EXTRA_ARGS+=(-DTOS_ARCH="$CI_ARCH")
fi

if [ ! -d "build" ]; then
  mkdir build
  cd build
else
  cd build || exit
  rm -rf .ninja* CMakeCache.txt
fi

cmake -GNinja .. \
-DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" -DCMAKE_SYSROOT="$SDKROOT" \
-DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$(pwd)/install" \
"${CMAKE_EXTRA_ARGS[@]}" | tee configure.txt
test "${PIPESTATUS[0]}" -eq 0 || { echo "Can't configure tos"; exit 1; }
# A validator on macOS must verify with the hardware SHA-256 backend
# (doc/Validator.md); a build without it is refused here.
grep -Fx -- "-- SLH-DSA SHA-256 backend: $SLHDSA_BACKEND=ON" configure.txt \
  || { echo "the hardware SHA-256 backend $SLHDSA_BACKEND is not enabled"; exit 1; }

if [ "$with_tests" = true ]; then
ninja storage-daemon storage-daemon-cli fift func tol toslib toslibjson toslib-cli \
      validator-engine tos-rpc tos-wallet-index lite-client validator-engine-console blockchain-explorer \
      generate-random-id json2tlo dht-server http-proxy rldp-http-proxy dht-ping-servers dht-resolve \
 create-state emulator proxy-liteserver tos-pq-consensus-key tos-pq-vote all-tests install
      test $? -eq 0 || { echo "Can't compile tos"; exit 1; }
else
ninja storage-daemon storage-daemon-cli fift func tol toslib toslibjson toslib-cli \
      validator-engine tos-rpc tos-wallet-index lite-client validator-engine-console blockchain-explorer \
      generate-random-id json2tlo dht-server http-proxy rldp-http-proxy \
 create-state emulator proxy-liteserver tos-pq-consensus-key tos-pq-vote dht-ping-servers dht-resolve
      test $? -eq 0 || { echo "Can't compile tos"; exit 1; }
fi

# The post-quantum key tool is a separate CMake project, so its signer stays out
# of every node target's link graph. It links the static OpenSSL the main build
# just produced and therefore needs no system libcrypto.
rm -rf pq-key
cmake -GNinja -S ../crypto/pq/tools -B pq-key \
-DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" -DCMAKE_SYSROOT="$SDKROOT" -DCMAKE_BUILD_TYPE=Release \
-DOPENSSL_ROOT_DIR="$(pwd)/third-party/openssl" -DOPENSSL_USE_STATIC_LIBS=TRUE
test $? -eq 0 || { echo "Can't configure tos-pq-key"; exit 1; }
ninja -C pq-key tos-pq-key
test $? -eq 0 || { echo "Can't compile tos-pq-key"; exit 1; }

# simple binaries' test
./storage/storage-daemon/storage-daemon -V || exit 1
./validator-engine/validator-engine -V || exit 1
./lite-client/lite-client -V || exit 1
./crypto/fift  -V || exit 1

otool -L ./validator-engine/validator-engine || exit 1

cd ..
