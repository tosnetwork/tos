# Execute these prerequisites first
# sudo apt update
# sudo apt install -y build-essential git make cmake ninja-build clang libgflags-dev \
#                    libreadline-dev pkg-config libgsl-dev python3 python3-dev python3-pip \
#                    nodejs automake libtool libjemalloc-dev ccache

# sudo scripts/install-llvm-toolchain.sh 21

with_artifacts=false
scratch_new=false

while getopts 'af' flag; do
  case "${flag}" in
    a) with_artifacts=true ;;
    f) scratch_new=true ;;
    *) break
       ;;
  esac
done

export CC=$(which clang-21)
export CXX=$(which clang++-21)
export CCACHE_DISABLE=1
ROOT_DIR=$(pwd)
EMSCRIPTEN_3PP_DIR="$ROOT_DIR/build/3pp_emscripten"

echo `pwd`
if [ "$scratch_new" = true ]; then
  echo Compiling openssl zlib lz4 emsdk libsodium emsdk tos
  rm -rf openssl zlib lz4 emsdk libsodium build openssl_em 3pp_emscripten
fi

if [ ! -d "build" ]; then
  mkdir build
  cd build
  cmake -GNinja -DTOS_USE_JEMALLOC=ON .. \
  -DCMAKE_BUILD_TYPE=Release

  test $? -eq 0 || { echo "Can't configure TOS build"; exit 1; }
  ninja fift smc-envelope
  test $? -eq 0 || { echo "Can't compile fift "; exit 1; }
  rm -rf * .ninja* CMakeCache.txt
  cd ..
else
  echo cleaning build...
  rm -rf build/* build/.ninja* build/CMakeCache.txt
fi

mkdir -p "$EMSCRIPTEN_3PP_DIR"

# Third-party sources are built and executed (configure scripts, make), so each
# is pinned to a reviewed commit. A fresh clone must be at that commit with no
# modified tracked file. A directory left by an earlier local build is reused
# only at the pinned commit, and its build output is not re-verified; run with
# -f for a clean, verified build.
clone_pinned() {
  local url="$1" dir="$2" commit="$3"
  if [ ! -d "$dir" ]; then
    git clone --no-checkout "$url" "$dir" || exit 1
    git -C "$dir" checkout --detach "$commit" || exit 1
    if [ "$(git -C "$dir" rev-parse HEAD)" != "$commit" ] || ! git -C "$dir" diff --quiet HEAD --; then
      echo "$dir does not match the pinned commit $commit" >&2
      exit 1
    fi
    return 0
  fi
  if [ "$(git -C "$dir" rev-parse HEAD 2>/dev/null)" != "$commit" ]; then
    echo "$dir is not at the pinned commit $commit; run with -f to rebuild it" >&2
    exit 1
  fi
  echo "cached $(basename "$dir") build output is reused without re-verifying it; run with -f for a clean verified build" >&2
  return 1
}

OPENSSL_COMMIT=c1eeb9406b6142148f267594197d853403d10208 # openssl-3.5.4
ZLIB_COMMIT=51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf    # v1.3.1
LZ4_COMMIT=5ff839680134437dbf4678f3d0c7b371d84f4964     # v1.9.4
SODIUM_COMMIT=940ef42797baa0278df6b7fd9e67c7590f87744b  # 1.0.18-RELEASE

# emsdk is executed below, so it is pinned to a reviewed commit (tag 4.0.17)
# and refused if the checked-out commit or any tracked file differs.
EMSDK_COMMIT=dadf06a88d62a20b4f711250b8447409352aa4d7
if [ ! -d "emsdk" ]; then
  git clone https://github.com/emscripten-core/emsdk.git || exit 1
else
  echo Using cloned emsdk
fi
if [ "$(git -C emsdk rev-parse HEAD)" != "$EMSDK_COMMIT" ]; then
  git -C emsdk fetch --depth 1 origin "$EMSDK_COMMIT" || exit 1
  git -C emsdk checkout --detach "$EMSDK_COMMIT" || exit 1
fi
if [ "$(git -C emsdk rev-parse HEAD)" != "$EMSDK_COMMIT" ] || ! git -C emsdk diff --quiet HEAD --; then
  echo "emsdk checkout does not match the pinned commit $EMSDK_COMMIT" >&2
  exit 1
fi

cd emsdk || exit
./emsdk install 4.0.17
./emsdk activate 4.0.17
EMSDK_DIR=`pwd`

. $EMSDK_DIR/emsdk_env.sh
export CC=$(which emcc)
export CXX=$(which em++)
export CCACHE_DISABLE=1

cd ..

if clone_pinned https://github.com/openssl/openssl "$EMSCRIPTEN_3PP_DIR/openssl_em" "$OPENSSL_COMMIT"; then
  cd "$EMSCRIPTEN_3PP_DIR/openssl_em" || exit
  # AF_ALG is a Linux kernel interface; it has no meaning in wasm.
  emconfigure ./Configure linux-generic32 no-shared no-dso no-unit-test no-tests no-fuzz-afl no-fuzz-libfuzzer no-afalgeng enable-quic
  sed -i 's/CROSS_COMPILE=.*/CROSS_COMPILE=/g' Makefile
  sed -i 's/-ldl//g' Makefile
  sed -i 's/-O3/-Os/g' Makefile
  emmake make depend
  emmake make -j$(nproc)
  test $? -eq 0 || { echo "Can't compile OpenSSL with emmake "; exit 1; }
  opensslPath=`pwd`
  cd "$ROOT_DIR"
else
  opensslPath="$EMSCRIPTEN_3PP_DIR/openssl_em"
  echo Using compiled with empscripten openssl at $opensslPath
fi

if clone_pinned https://github.com/madler/zlib.git "$EMSCRIPTEN_3PP_DIR/zlib" "$ZLIB_COMMIT"; then
  cd "$EMSCRIPTEN_3PP_DIR/zlib" || exit
  ZLIB_DIR=`pwd`
  emconfigure ./configure --static
  emmake make -j$(nproc)
  test $? -eq 0 || { echo "Can't compile zlib with emmake "; exit 1; }
  cd "$ROOT_DIR"
else
  ZLIB_DIR="$EMSCRIPTEN_3PP_DIR/zlib"
  echo Using compiled zlib with emscripten at $ZLIB_DIR
fi

if clone_pinned https://github.com/lz4/lz4.git "$EMSCRIPTEN_3PP_DIR/lz4" "$LZ4_COMMIT"; then
  cd "$EMSCRIPTEN_3PP_DIR/lz4" || exit
  LZ4_DIR=`pwd`
  emmake make -j$(nproc)
  test $? -eq 0 || { echo "Can't compile lz4 with emmake "; exit 1; }
  cd "$ROOT_DIR"
else
  LZ4_DIR="$EMSCRIPTEN_3PP_DIR/lz4"
  echo Using compiled lz4 with emscripten at $LZ4_DIR
fi

if clone_pinned https://github.com/jedisct1/libsodium "$EMSCRIPTEN_3PP_DIR/libsodium" "$SODIUM_COMMIT"; then
  cd "$EMSCRIPTEN_3PP_DIR/libsodium" || exit
  SODIUM_DIR=`pwd`
  emconfigure ./configure --disable-ssp
  emmake make -j$(nproc)
  test $? -eq 0 || { echo "Can't compile libsodium with emmake "; exit 1; }
  cd "$ROOT_DIR"
else
  SODIUM_DIR="$EMSCRIPTEN_3PP_DIR/libsodium"
  echo Using compiled libsodium with emscripten at $SODIUM_DIR
fi

cd build || exit

emcmake cmake -DUSE_EMSCRIPTEN=ON -DCMAKE_BUILD_TYPE=Release -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON \
-DZLIB_FOUND=1 \
-DZLIB_LIBRARIES=$ZLIB_DIR/libz.a \
-DZLIB_INCLUDE_DIR=$ZLIB_DIR \
-DLZ4_FOUND=1 \
-DLZ4_LIBRARIES=$LZ4_DIR/lib/liblz4.a \
-DLZ4_INCLUDE_DIRS=$LZ4_DIR/lib \
-DOPENSSL_FOUND=1 \
-DOPENSSL_INCLUDE_DIR=$opensslPath/include \
-DOPENSSL_CRYPTO_LIBRARY=$opensslPath/libcrypto.a \
-DCMAKE_TOOLCHAIN_FILE=$EMSDK_DIR/upstream/emscripten/cmake/Modules/Platform/Emscripten.cmake \
-DCMAKE_CXX_FLAGS="-sUSE_ZLIB=1" \
-DSODIUM_FOUND=1 \
-DSODIUM_INCLUDE_DIR=$SODIUM_DIR/src/libsodium/include \
-DSODIUM_USE_STATIC_LIBS=1 \
-DSODIUM_LIBRARY_RELEASE=$SODIUM_DIR/src/libsodium/.libs/libsodium.a \
..

test $? -eq 0 || { echo "Can't configure TOS with emmake "; exit 1; }
cp -R ../crypto/smartcont ../crypto/fift/lib crypto

emmake make -j$(nproc) funcfiftlib func fift tlbc emulator-emscripten

test $? -eq 0 || { echo "Can't compile TOS with emmake "; exit 1; }

if [ "$with_artifacts" = true ]; then
  echo "Creating artifacts..."
  cd ..
  rm -rf artifacts
  mkdir artifacts
  ls build/crypto
  cp build/crypto/fift* artifacts
  cp build/crypto/func* artifacts
  cp build/crypto/tlbc* artifacts
  cp build/emulator/emulator-emscripten* artifacts
  cp -R crypto/smartcont artifacts
  cp -R crypto/fift/lib artifacts
fi
