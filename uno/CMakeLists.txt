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
)

set(UNO_CRYPTO_AGENT4
  crypto/plonky3-verifier.cpp
)

set(UNO_RPC_AGENT6
  rpc/handlers.cpp
  rpc/filter-service.cpp
  rpc/subscriptions.cpp
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
# -----------------------------------------------------------------------------
find_path(LIBOQS_INCLUDE_DIR oqs/oqs.h)
find_library(LIBOQS_LIBRARY NAMES oqs)

if (LIBOQS_INCLUDE_DIR AND LIBOQS_LIBRARY)
  message(STATUS "uno_workchain: found liboqs at ${LIBOQS_LIBRARY}")
  target_include_directories(uno_workchain PRIVATE ${LIBOQS_INCLUDE_DIR})
  target_link_libraries(uno_workchain PUBLIC ${LIBOQS_LIBRARY})
else()
  message(STATUS "uno_workchain: liboqs not found — ML-KEM-768 built with UNO_MLKEM_STUB=1 (runtime abort)")
  target_compile_definitions(uno_workchain PRIVATE UNO_MLKEM_STUB=1)
endif()

# -----------------------------------------------------------------------------
# Rust FFI crate: uno_plonky3_ffi (Agent 4 owns the crate; agent-5 owns this
# integration point). Wired via corrosion-rs — the canonical way to consume
# Cargo crates from CMake.
#
# Integration recipe (to be activated when Agent 4's crate lands):
#
#   find_package(Corrosion QUIET)
#   if (Corrosion_FOUND AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/plonky3-ffi/Cargo.toml")
#     corrosion_import_crate(MANIFEST_PATH plonky3-ffi/Cargo.toml)
#     target_link_libraries(uno_workchain PUBLIC uno_plonky3_ffi)
#   else()
#     message(STATUS "uno_workchain: Corrosion not found or plonky3-ffi crate not present "
#                    "— Plonky3 verifier bridge will be stubbed at link time")
#   endif()
#
# Corrosion is vendored as a submodule / FetchContent — the uno branch will
# add `third-party/corrosion/` and an `include(third-party/corrosion/cmake/Corrosion.cmake)`
# call at the top-level CMakeLists.txt when Agent 4 merges.
#
# For today's skeleton build, we keep the block commented so builds succeed
# without the Rust crate (the weak-symbol fallbacks in compute-phase.cpp take
# over). Flip this block on when `find_package(Corrosion)` returns OK.
# -----------------------------------------------------------------------------
# TODO(uno-integration, agent-5 + agent-4): uncomment once corrosion + crate are in.
# find_package(Corrosion QUIET)
# if (Corrosion_FOUND AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/plonky3-ffi/Cargo.toml")
#   corrosion_import_crate(MANIFEST_PATH plonky3-ffi/Cargo.toml)
# endif()

target_link_libraries(uno_workchain
  PUBLIC
    tos_crypto           # cells, vm types, block types, dispatcher
)

# Optional subdirs — Agent 6 owns tests; include only when present.
if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test/CMakeLists.txt")
  add_subdirectory(test)
endif()
