# Uno Workchain — TOS-side adapter for the wc=2 shielded-pool execution domain.
#
# Organised in four source directories:
#   core/          state, compute-phase, transaction codec, genesis
#   crypto/        primitives: Goldilocks, Poseidon2, Ristretto255, ML-KEM,
#                  hybrid-KEM, Plonky3 verifier bridge, note encryption
#   rpc/           uno_* JSON-RPC handlers and filter-service
#   plonky3-ffi/   Rust crate exposing the Plonky3 Transfer AIR verifier
#                  (and reference prover) over C ABI
#
# core/ and rpc/ are symbolically circular (rpc handlers depend on state;
# compute-phase writes events consumed by subscriptions), so they compile
# into one static library `uno_workchain`. Mirrors the evm_workchain
# convention exactly (see ~/tos/evm/CMakeLists.txt).

# Full file list (§11.4 of doc/uno-workchain.md). Items marked (agent-N)
# are owned by other agents; they will appear in their respective worktrees.
# This CMakeLists.txt will compile whichever of them are present — we use
# file-existence guards so agent-5's skeleton build succeeds before the
# other agents merge.

set(UNO_CORE_AGENT5
  core/transaction.cpp
  core/compute-phase.cpp
  core/parallel-verify.cpp
  core/cell-codec.cpp
  core/init.cpp
)

set(UNO_CORE_AGENT1
  core/state.cpp
  core/cell-state.cpp
  core/config-param.cpp
  core/genesis.cpp
)

set(UNO_CORE_AGENT2
  core/commitment-tree.cpp
  core/nullifier-set.cpp
  core/anchor-window.cpp
  core/block-filter.cpp
)

set(UNO_CRYPTO_AGENT3
  crypto/goldilocks.cpp
  crypto/poseidon2.cpp
  crypto/ristretto255.cpp
  crypto/schnorr-ristretto.cpp
  crypto/mlkem768.cpp
  crypto/hybrid-kem.cpp
  crypto/stealth-address.cpp
  crypto/note-encryption.cpp
  crypto/internal/blake3_adapter.cpp
  # K-bech32m: §2.6 AddressEnvelope Bech32m codec — shared between wallet
  # CLI, RPC validation, and the genesis-loader "address" alternative.
  crypto/bech32m.cpp
)

set(UNO_CRYPTO_AGENT4
  crypto/plonky3-verifier.cpp
)

set(UNO_RPC_AGENT6
  rpc/handlers.cpp
  rpc/filter-service.cpp
  rpc/subscriptions.cpp
  # K-uno-metrics: Prometheus text-format exposition backing uno_getMetrics.
  rpc/metrics.cpp
)

# Assemble only files that are actually present on disk. Once every agent
# has merged, every candidate will exist and this loop reduces to the
# exact list in §11.4. Skeleton builds (just agent 5's files) succeed
# today.
set(UNO_SRC "")
foreach(SRC IN LISTS UNO_CORE_AGENT5
                     UNO_CORE_AGENT1
                     UNO_CORE_AGENT2
                     UNO_CRYPTO_AGENT3
                     UNO_CRYPTO_AGENT4
                     UNO_RPC_AGENT6)
  if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${SRC}")
    list(APPEND UNO_SRC "${SRC}")
  else()
    message(STATUS "uno_workchain: skipping not-yet-landed source ${SRC}")
  endif()
endforeach()

add_library(uno_workchain STATIC ${UNO_SRC})

target_include_directories(uno_workchain
  PUBLIC
    ${CMAKE_SOURCE_DIR}                                     # for "uno/core/*.h", "uno/crypto/*.h", "uno/rpc/*.h"
    ${CMAKE_SOURCE_DIR}/crypto                              # for "block/*.h" (dispatcher header)
    ${CMAKE_SOURCE_DIR}/crypto/vm                           # for "vm/cells/*.h"
    ${CMAKE_CURRENT_SOURCE_DIR}/plonky3-ffi/include         # for cbindgen-generated "uno_plonky3_ffi.h"
)

# -----------------------------------------------------------------------------
# liboqs detection for ML-KEM-768.
#
# A3's mlkem768.{h,cpp} supports two build modes:
#   - Production: links against system `liboqs` (Open Quantum Safe).
#   - Stub: -DUNO_MLKEM_STUB=1 — all ML-KEM ops fatal-abort at runtime.
#
# The stub keeps the skeleton build green on hosts without liboqs installed;
# I-C / full-build CI should install liboqs-dev and drop the stub.
#
# Probe order:
#   1. Honour caller-provided LIBOQS_INCLUDE_DIR / LIBOQS_LIBRARY (for CI and
#      non-root installs into user prefixes such as $HOME/.local).
#   2. find_path / find_library against the default system prefixes.
#
# When liboqs is located we additionally probe for the FIPS 203 deterministic
# derand symbols and surface them to mlkem768.cpp via preprocessor defines
# (OQS_HAVE_ML_KEM_KEYPAIR_DERAND / OQS_HAVE_ML_KEM_ENCAPS_DERAND). The header
# declares these unconditionally in recent liboqs (>= 0.10), but the probe
# keeps the wiring explicit and future-proofs against older packaged builds.
#
# Version pin for the liboqs commit this TOS-side has been validated against
# is recorded in uno/crypto/LIBOQS_VERSION.md. CI and validator builds MUST
# pin that exact commit rather than track liboqs `main`.
# -----------------------------------------------------------------------------
find_path(LIBOQS_INCLUDE_DIR oqs/oqs.h)
find_library(LIBOQS_LIBRARY NAMES oqs)

if (LIBOQS_INCLUDE_DIR AND LIBOQS_LIBRARY)
  message(STATUS "uno_workchain: found liboqs at ${LIBOQS_LIBRARY}")
  target_include_directories(uno_workchain PRIVATE ${LIBOQS_INCLUDE_DIR})
  target_link_libraries(uno_workchain PUBLIC ${LIBOQS_LIBRARY})

  # Probe the kem_ml_kem.h header for the FIPS 203 derand prototypes and
  # surface their availability to mlkem768.cpp. liboqs >= 0.10 exposes both.
  #
  # Compile-only probe (no link): we cast the function designator to void
  # pointer inside a conditional that is never executed — this forces the
  # compiler to resolve the declaration (fails if not declared) without
  # emitting a relocation to the symbol, so the check does not require
  # linking against liboqs (which would drag in OpenSSL as a transitive
  # dependency of liboqs.a).
  include(CheckCXXSourceCompiles)
  set(CMAKE_REQUIRED_INCLUDES_SAVED ${CMAKE_REQUIRED_INCLUDES})
  set(CMAKE_REQUIRED_INCLUDES ${LIBOQS_INCLUDE_DIR})
  check_cxx_source_compiles("
    #include <oqs/oqs.h>
    #include <oqs/kem_ml_kem.h>
    int main() {
      // Declaration-only probe: sizeof(&fn) forces the compiler to resolve
      // the prototype but does not emit a reference to the symbol body.
      return sizeof(&OQS_KEM_ml_kem_768_keypair_derand) > 0 ? 0 : 1;
    }
  " UNO_OQS_HAS_ML_KEM_KEYPAIR_DERAND)
  check_cxx_source_compiles("
    #include <oqs/oqs.h>
    #include <oqs/kem_ml_kem.h>
    int main() {
      return sizeof(&OQS_KEM_ml_kem_768_encaps_derand) > 0 ? 0 : 1;
    }
  " UNO_OQS_HAS_ML_KEM_ENCAPS_DERAND)
  set(CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES_SAVED})

  if (UNO_OQS_HAS_ML_KEM_KEYPAIR_DERAND)
    message(STATUS "uno_workchain: liboqs exposes OQS_KEM_ml_kem_768_keypair_derand")
    target_compile_definitions(uno_workchain PRIVATE OQS_HAVE_ML_KEM_KEYPAIR_DERAND=1)
  else()
    message(STATUS "uno_workchain: liboqs build lacks ML-KEM-768 derand keypair — deterministic keygen will error at runtime")
  endif()
  if (UNO_OQS_HAS_ML_KEM_ENCAPS_DERAND)
    message(STATUS "uno_workchain: liboqs exposes OQS_KEM_ml_kem_768_encaps_derand")
    target_compile_definitions(uno_workchain PRIVATE OQS_HAVE_ML_KEM_ENCAPS_DERAND=1)
  else()
    message(STATUS "uno_workchain: liboqs build lacks ML-KEM-768 derand encaps — deterministic encap will error at runtime")
  endif()
else()
  message(STATUS "uno_workchain: liboqs not found — ML-KEM-768 built with UNO_MLKEM_STUB=1 (runtime abort). "
                 "Install liboqs-dev, or build liboqs from source (see uno/crypto/LIBOQS_VERSION.md) and re-configure with "
                 "-DLIBOQS_INCLUDE_DIR=<prefix>/include -DLIBOQS_LIBRARY=<prefix>/lib/liboqs.a.")
  target_compile_definitions(uno_workchain PRIVATE UNO_MLKEM_STUB=1)
endif()

# -----------------------------------------------------------------------------
# Rust FFI crate: uno_plonky3_ffi. Wired via corrosion-rs — the canonical
# way to consume Cargo crates from CMake. Corrosion is vendored at
# `third-party/corrosion/` (see README.uno.md there) and its subdirectory
# is added from the repo-root CMakeLists.txt before `add_subdirectory(uno)`.
#
# `corrosion_import_crate(...)` registers a CMake target named after the
# `[lib].name` in `plonky3-ffi/Cargo.toml` (= `uno_plonky3_ffi`). Linking it
# PUBLIC into uno_workchain propagates the archive through every downstream
# consumer (validator-engine, create-hardfork, test-tos-collator, every
# test-uno-* binary) — they all resolve `uno_plonky3_*` and
# `uno_poseidon2_goldilocks_permute_t8` against the real Rust symbols
# instead of the weak-symbol stubs in uno/core/parallel-verify.cpp.
#
# Graceful fallback: if corrosion is missing (e.g. somebody wiped
# `third-party/corrosion/` in a stripped checkout), `find_package` returns
# not-found and we keep the weak-symbol stubs. The build still succeeds,
# just with verify() fatal-aborting at runtime.
# -----------------------------------------------------------------------------
# Corrosion is consumed via `add_subdirectory(third-party/corrosion)` from the
# repo-root CMakeLists.txt; that path makes `corrosion_import_crate` a defined
# CMake function in the global scope, but does NOT set `Corrosion_FOUND` in
# the find_package sense. Probe for the function directly so the same block
# handles both the vendored-subdirectory and the out-of-tree-install paths.
find_package(Corrosion QUIET)
if (NOT Corrosion_FOUND AND COMMAND corrosion_import_crate)
  set(Corrosion_FOUND TRUE)
endif()
if (Corrosion_FOUND AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/plonky3-ffi/Cargo.toml")
  message(STATUS "uno_workchain: Corrosion found — linking libuno_plonky3_ffi.a into uno_workchain")
  # Build the release profile by default: the verifier is on the validator
  # hot path (§13 P.3) and the reference prover in dev mode is ~50x slower.
  corrosion_import_crate(
    MANIFEST_PATH plonky3-ffi/Cargo.toml
    PROFILE release
    CRATE_TYPES staticlib
  )
  target_link_libraries(uno_workchain PUBLIC uno_plonky3_ffi)
else()
  message(STATUS "uno_workchain: Corrosion not found or plonky3-ffi crate absent "
                 "— Plonky3 verifier bridge will fall back to weak-symbol stubs "
                 "in uno/core/parallel-verify.cpp (verify() will fatal-abort at "
                 "runtime). Install corrosion at third-party/corrosion/ to enable "
                 "the real Rust verifier.")
endif()

target_link_libraries(uno_workchain
  PUBLIC
    tos_crypto           # cells, vm types, block types, dispatcher
    Threads::Threads     # §13 P.3: std::thread in uno/core/parallel-verify.cpp
)

# -----------------------------------------------------------------------------
# BLAKE3 backend — decision #41: UNO_BLAKE3_AVATAR.
# avatar is in-house code (100% team-authored) vendored into
# `third-party/avatar-crypto/` so the tos repo is self-contained — no sibling
# avatar checkout needed for build, CI, or audit. See
# `third-party/avatar-crypto/README.uno.md` for upstream pin + refresh policy.
#
# Baseline compiles at_blake3.c + at_blake3_ref.c (portable reference kernel).
# x86 hosts can add at_blake3_{sse41,avx2,avx512}.c and set AT_HAS_SSE /
# AT_HAS_AVX / AT_HAS_AVX512 compile definitions to enable SIMD dispatch.
# -----------------------------------------------------------------------------
set(AVATAR_CRYPTO_ROOT "${CMAKE_SOURCE_DIR}/third-party/avatar-crypto"
    CACHE PATH "Path to the vendored avatar crypto tree (self-contained in tos repo)")
if (EXISTS "${AVATAR_CRYPTO_ROOT}/src/crypto/blake3/at_blake3.c" AND
    EXISTS "${AVATAR_CRYPTO_ROOT}/include/at/crypto/at_blake3.h")
  message(STATUS "uno_workchain: using vendored avatar BLAKE3 at ${AVATAR_CRYPTO_ROOT}")
  target_sources(uno_workchain PRIVATE
    ${AVATAR_CRYPTO_ROOT}/src/crypto/blake3/at_blake3.c
    ${AVATAR_CRYPTO_ROOT}/src/crypto/blake3/at_blake3_ref.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto/internal/avatar_log_stubs.c  # minimal at_log_* stubs
  )
  target_include_directories(uno_workchain PRIVATE
    ${AVATAR_CRYPTO_ROOT}/include              # for "at/infra/at_util.h"
    ${AVATAR_CRYPTO_ROOT}/include/at/crypto    # so at_blake3.c finds "at_blake3_private.h" sibling
    ${AVATAR_CRYPTO_ROOT}/src/crypto/blake3    # compile-time workspace
  )
  target_compile_definitions(uno_workchain PUBLIC UNO_BLAKE3_AVATAR=1)
else()
  message(FATAL_ERROR "uno_workchain: vendored avatar BLAKE3 missing at "
                      "${AVATAR_CRYPTO_ROOT}. Check third-party/avatar-crypto/ or "
                      "override with -DAVATAR_CRYPTO_ROOT=<path>.")
endif()

# Optional subdirs — Agent 6 owns tests; include only when present.
if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test/CMakeLists.txt")
  add_subdirectory(test)
endif()
