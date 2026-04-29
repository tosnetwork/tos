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
  # Phase 1: MineUno tx kind skeleton (data structures + constants).
  # Phase 2 will add decode/encode/apply implementations here.
  core/mine_uno.cpp
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
# TOS_DEV_STUBS — opt-in: allow the build to silently fall back to runtime-
# aborting cryptographic stubs when the real backends (liboqs for ML-KEM,
# Corrosion + the plonky3-ffi crate for the Plonky3 verifier) are not
# available at configure time. Production validators must NOT ship with
# stubs — a missing crypto dep would cause every Uno proof verification
# to either fatal-abort the daemon (ML-KEM stub) or reject every Uno
# transfer as BadPlonky3Proof (Plonky3 stub). Default OFF: missing deps
# are a hard CMake error so this can never happen by accident.
# -----------------------------------------------------------------------------
option(TOS_DEV_STUBS
       "Allow falling back to crypto/proof runtime-abort stubs when deps are missing (NOT for production)"
       OFF)
if (TOS_DEV_STUBS)
  message(WARNING
    "uno_workchain: TOS_DEV_STUBS=ON — missing liboqs / Corrosion / "
    "plonky3-ffi will be tolerated and replaced with runtime-abort stubs. "
    "This binary MUST NOT be deployed to a network you do not control.")
endif()

# -----------------------------------------------------------------------------
# liboqs detection for ML-KEM-768.
#
# A3's mlkem768.{h,cpp} supports two build modes:
#   - Production: links against system `liboqs` (Open Quantum Safe).
#   - Stub: -DUNO_MLKEM_STUB=1 — all ML-KEM ops fatal-abort at runtime.
#
# Stub mode is gated behind TOS_DEV_STUBS=ON; production builds (the
# default) require liboqs to be present at configure time and FATAL_ERROR
# otherwise.
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

set(TOS_VENDORED_LIBOQS_DIR "${CMAKE_SOURCE_DIR}/third-party/liboqs")
set(TOS_USING_VENDORED_LIBOQS OFF)
if (NOT (LIBOQS_INCLUDE_DIR AND LIBOQS_LIBRARY) AND EXISTS "${TOS_VENDORED_LIBOQS_DIR}/CMakeLists.txt")
  message(STATUS "uno_workchain: system liboqs not found; using vendored liboqs at ${TOS_VENDORED_LIBOQS_DIR}")
  include(ExternalProject)
  set(TOS_VENDORED_LIBOQS_BINARY_DIR "${CMAKE_BINARY_DIR}/third-party/liboqs")
  set(TOS_VENDORED_LIBOQS_INCLUDE_DIR "${TOS_VENDORED_LIBOQS_BINARY_DIR}/include")
  set(TOS_VENDORED_LIBOQS_ARCHIVE
      "${TOS_VENDORED_LIBOQS_BINARY_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}oqs${CMAKE_STATIC_LIBRARY_SUFFIX}")

  file(MAKE_DIRECTORY "${TOS_VENDORED_LIBOQS_INCLUDE_DIR}")
  if (NOT TARGET tos_vendored_liboqs)
    ExternalProject_Add(tos_vendored_liboqs
      SOURCE_DIR "${TOS_VENDORED_LIBOQS_DIR}"
      BINARY_DIR "${TOS_VENDORED_LIBOQS_BINARY_DIR}"
      CMAKE_ARGS
        "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
        "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}"
        "-DCMAKE_ASM_COMPILER=${CMAKE_ASM_COMPILER}"
        "-DCMAKE_POSITION_INDEPENDENT_CODE=ON"
        "-DBUILD_SHARED_LIBS=OFF"
        "-DOQS_BUILD_ONLY_LIB=ON"
        "-DOQS_MINIMAL_BUILD=KEM_ml_kem_768"
        "-DOQS_ENABLE_KEM_ML_KEM=ON"
        "-DOQS_USE_CUPQC=OFF"
        "-DOQS_USE_ICICLE=OFF"
        "-DOQS_BUILD_FUZZ_TESTS=OFF"
        "-DOPENSSL_ROOT_DIR=${OPENSSL_BINARY_DIR}"
        "-DOPENSSL_INCLUDE_DIR=${OPENSSL_INCLUDE_DIR}"
        "-DOPENSSL_CRYPTO_LIBRARY=${OPENSSL_CRYPTO_LIBRARY}"
      INSTALL_COMMAND ""
      BUILD_BYPRODUCTS "${TOS_VENDORED_LIBOQS_ARCHIVE}"
      DEPENDS OpenSSL)
  endif()
  if (NOT TARGET tos_vendored_liboqs_oqs)
    add_library(tos_vendored_liboqs_oqs STATIC IMPORTED GLOBAL)
    set_target_properties(tos_vendored_liboqs_oqs PROPERTIES
      IMPORTED_LOCATION "${TOS_VENDORED_LIBOQS_ARCHIVE}"
      INTERFACE_INCLUDE_DIRECTORIES "${TOS_VENDORED_LIBOQS_INCLUDE_DIR}")
    add_dependencies(tos_vendored_liboqs_oqs tos_vendored_liboqs)
  endif()

  set(LIBOQS_INCLUDE_DIR "${TOS_VENDORED_LIBOQS_INCLUDE_DIR}")
  set(LIBOQS_LIBRARY tos_vendored_liboqs_oqs)
  set(TOS_USING_VENDORED_LIBOQS ON)
endif()

if (LIBOQS_INCLUDE_DIR AND LIBOQS_LIBRARY)
  if (TOS_USING_VENDORED_LIBOQS)
    message(STATUS "uno_workchain: using vendored liboqs target ${LIBOQS_LIBRARY}")
  else()
    message(STATUS "uno_workchain: found liboqs at ${LIBOQS_LIBRARY}")
  endif()
  target_include_directories(uno_workchain PRIVATE ${LIBOQS_INCLUDE_DIR})
  if (TARGET ${LIBOQS_LIBRARY})
    target_link_libraries(uno_workchain PUBLIC ${LIBOQS_LIBRARY})
    add_dependencies(uno_workchain ${LIBOQS_LIBRARY})
  else()
    target_link_libraries(uno_workchain PUBLIC ${LIBOQS_LIBRARY})
  endif()

  if (TOS_USING_VENDORED_LIBOQS)
    message(STATUS "uno_workchain: vendored liboqs pin exposes OQS_KEM_ml_kem_768_keypair_derand")
    target_compile_definitions(uno_workchain PRIVATE OQS_HAVE_ML_KEM_KEYPAIR_DERAND=1)
    message(STATUS "uno_workchain: vendored liboqs pin exposes OQS_KEM_ml_kem_768_encaps_derand")
    target_compile_definitions(uno_workchain PRIVATE OQS_HAVE_ML_KEM_ENCAPS_DERAND=1)
  else()
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
  endif()
else()
  if (TOS_DEV_STUBS)
    message(STATUS "uno_workchain: liboqs not found — ML-KEM-768 built with UNO_MLKEM_STUB=1 (runtime abort). "
                   "Install liboqs-dev, or build liboqs from source (see uno/crypto/LIBOQS_VERSION.md) and re-configure with "
                   "-DLIBOQS_INCLUDE_DIR=<prefix>/include -DLIBOQS_LIBRARY=<prefix>/lib/liboqs.a.")
    target_compile_definitions(uno_workchain PRIVATE UNO_MLKEM_STUB=1)
  else()
    message(FATAL_ERROR
      "uno_workchain: liboqs is required for production validator builds but was "
      "not found. Install liboqs-dev or build from source (see "
      "uno/crypto/LIBOQS_VERSION.md) and re-configure with "
      "-DLIBOQS_INCLUDE_DIR=<prefix>/include -DLIBOQS_LIBRARY=<prefix>/lib/liboqs.a. "
      "If you are knowingly building a non-production binary that does not need "
      "real ML-KEM (e.g. an early skeleton-build CI job), pass -DTOS_DEV_STUBS=ON "
      "to fall back to a runtime-abort stub instead.")
  endif()
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
# When TOS_DEV_STUBS=ON: if corrosion is missing (e.g. somebody wiped
# `third-party/corrosion/` in a stripped checkout), `find_package` returns
# not-found and we keep the weak-symbol stubs. The build still succeeds,
# just with verify() fatal-aborting (or returning BadPlonky3Proof) at
# runtime. Default: missing corrosion / plonky3-ffi is a FATAL_ERROR.
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
  if (TOS_DEV_STUBS)
    message(STATUS "uno_workchain: Corrosion not found or plonky3-ffi crate absent "
                   "— Plonky3 verifier bridge will fall back to weak-symbol stubs "
                   "in uno/core/parallel-verify.cpp (verify() will fatal-abort at "
                   "runtime). Install corrosion at third-party/corrosion/ to enable "
                   "the real Rust verifier.")
  else()
    message(FATAL_ERROR
      "uno_workchain: the Plonky3 verifier FFI is required for production "
      "validator builds. Either Corrosion was not found or "
      "${CMAKE_CURRENT_SOURCE_DIR}/plonky3-ffi/Cargo.toml is missing. Install "
      "Corrosion (vendored at third-party/corrosion/ — re-clone the tos repo "
      "without stripping submodules) and confirm uno/plonky3-ffi/ exists. "
      "If you are knowingly building a non-production binary that does not need "
      "the real verifier, pass -DTOS_DEV_STUBS=ON to fall back to weak-symbol "
      "stubs instead.")
  endif()
endif()

target_link_libraries(uno_workchain
  PUBLIC
    tos_crypto           # cells, vm types, block types, dispatcher
    Threads::Threads     # §13 P.3: std::thread in uno/core/parallel-verify.cpp
)

# -----------------------------------------------------------------------------
# UNO_DEVNET_ALLOW_ENV_TARGET — opt-in escape hatch that lets the
# `UNO_INIT_MINE_TARGET_HEX` environment variable override the initial
# MineUno difficulty target on validators built from this tree. The target
# is consensus-critical: validators that disagree on it split the chain at
# the first MineUno transaction, so production builds MUST leave this OFF
# and rely on the global_id-driven `select_init_mine_target()` fallback
# (kInitMineTargetBE for mainnet/public-testnet, kDevMineTargetBE for
# local dev). Only enable this for ad-hoc devnet bring-up where a single
# operator controls every validator binary.
# -----------------------------------------------------------------------------
option(UNO_DEVNET_ALLOW_ENV_TARGET
       "Allow UNO_INIT_MINE_TARGET_HEX env override of MineUno target (devnet only)"
       OFF)

# Audit #10 (2026-04-26): production / public-testnet build flag. CI release
# jobs MUST configure with `-DTOS_PRODUCTION_BUILD=ON`. When that flag is on,
# any opt-in that compromises consensus determinism (currently
# UNO_DEVNET_ALLOW_ENV_TARGET) is a hard CMake error so that a misconfigured
# release artifact cannot ship.
option(TOS_PRODUCTION_BUILD
       "Production / public-testnet build — refuse devnet escape hatches"
       OFF)

if (UNO_DEVNET_ALLOW_ENV_TARGET)
  if (TOS_PRODUCTION_BUILD)
    message(FATAL_ERROR
      "uno_workchain: TOS_PRODUCTION_BUILD=ON forbids UNO_DEVNET_ALLOW_ENV_TARGET=ON. "
      "The UNO_INIT_MINE_TARGET_HEX env var lets each validator override the MineUno "
      "difficulty target independently; mixing differently-configured validators on "
      "the same network splits the chain at the first MineUno tx. Either turn the "
      "env-target flag off or do not configure with TOS_PRODUCTION_BUILD=ON.")
  endif()
  message(WARNING
    "uno_workchain: UNO_DEVNET_ALLOW_ENV_TARGET=ON — the UNO_INIT_MINE_TARGET_HEX "
    "env var will override the MineUno difficulty target at runtime. This is a "
    "consensus-critical parameter; do NOT ship this binary to a network you do "
    "not fully control.")
  target_compile_definitions(uno_workchain PRIVATE UNO_DEVNET_ALLOW_ENV_TARGET=1)
endif()

if (TOS_PRODUCTION_BUILD)
  target_compile_definitions(uno_workchain PRIVATE TOS_PRODUCTION_BUILD=1)
  message(STATUS "uno_workchain: TOS_PRODUCTION_BUILD=ON — devnet escape hatches refused")
endif()

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
