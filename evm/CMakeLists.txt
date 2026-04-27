# EVM Workchain — TOS-side adapter for the wc=1 EVM execution domain.
#
# The code is organised in two source directories:
#   core/   silkworm/evmone integration: state, executor, cell codec,
#           compute-phase hook, transaction decode, predeploys.
#   rpc/    JSON-RPC handlers (eth_*, debug_*, net_*) + side-channel
#           cache DB + eth_subscribe pub/sub.
#
# core/ and rpc/ are circular at the symbol level (compute-phase.cpp
# writes receipts via the cache DB; cache-db.cpp serialises types
# defined in core), so they compile into one static library
# `evm_workchain`. The directory split is purely for code organisation.

set(EVM_SRC
  # core/
  core/access-list-tracer.cpp
  core/block-context.cpp
  core/bridge.cpp
  core/cell-codec.cpp
  core/cell-state.cpp
  core/compute-phase.cpp
  core/config-param.cpp
  core/executor.cpp
  core/external-message.cpp
  core/incremental-trie.cpp
  core/init.cpp
  core/mpt-prover.cpp
  core/mpt-trie.cpp
  core/post-accept.cpp
  core/state.cpp
  core/state-root.cpp
  core/tracer.cpp
  core/transaction.cpp
  # rpc/
  rpc/cache-codec.cpp
  rpc/cache-db.cpp
  rpc/handlers.cpp
  rpc/subscriptions.cpp
)

add_library(evm_workchain STATIC ${EVM_SRC})

target_compile_options(evm_workchain PRIVATE
  $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wno-cast-qual>
  $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wno-deprecated-literal-operator>
  $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wno-missing-field-initializers>
)

# Test-only instrumentation: lightweight atomic counters that prove the lazy
# state-load and lazy storage-witness-index hot paths stay O(touched) rather
# than O(global state). The counters are O(1) per touched entry and cheap,
# but production binaries must not ship code that exposes test hooks. By
# default the macro is OFF so `evm_workchain` builds without instrumentation;
# the dedicated test library `evm_workchain_test` (below) re-builds the same
# sources with the macro defined and is the only target the unit tests link.
option(TOS_EVM_TEST_INSTRUMENTATION
       "Enable EVM lazy-load + MPT walk counters used by tests" OFF)
if(TOS_EVM_TEST_INSTRUMENTATION)
  target_compile_definitions(evm_workchain PUBLIC TOS_EVM_TEST_INSTRUMENTATION=1)
endif()

# Optional expensive EVM compute-phase invariant check. When enabled, every
# EVM tx re-loads the persisted cell state + trie witness and re-derives the
# Ethereum stateRoot to verify the witness is internally consistent. This
# scales with witness size and reintroduces full StrictRecursive validation
# per tx, so it MUST be opt-in. Default OFF: production / public testnet
# builds (with or without NDEBUG) never pay this cost. Enable locally with
# `-DTOS_EVM_STRICT_COMPUTE_INVARIANTS=ON` while debugging witness drift.
option(TOS_EVM_STRICT_COMPUTE_INVARIANTS
       "Enable expensive EVM compute invariant checks" OFF)
if(TOS_EVM_STRICT_COMPUTE_INVARIANTS)
  target_compile_definitions(evm_workchain PRIVATE TOS_EVM_STRICT_COMPUTE_INVARIANTS=1)
endif()

target_include_directories(evm_workchain
  PUBLIC
    ${CMAKE_SOURCE_DIR}             # for "evm/core/*.h", "evm/rpc/*.h"
    ${CMAKE_SOURCE_DIR}/crypto      # for "block/*.h"
    ${CMAKE_SOURCE_DIR}/crypto/vm   # for "vm/cells/*.h"
)

target_link_libraries(evm_workchain
  PUBLIC
    silkworm_core
    tos_crypto   # cells, vm types, block types
    tddb         # RocksDB wrapper for the side-channel cache
)

# Dedicated test-instrumented build of the same EVM sources. The unit tests
# link against this library so the lazy-load / MPT-walk counters defined in
# `evm/core/cell-state.{h,cpp}` are available without forcing every
# production-side consumer of `evm_workchain` to ship them. Compile flags
# and link dependencies must mirror `evm_workchain` exactly so behaviour is
# identical apart from the instrumentation macro.
add_library(evm_workchain_test STATIC ${EVM_SRC})

target_compile_options(evm_workchain_test PRIVATE
  $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wno-cast-qual>
  $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wno-deprecated-literal-operator>
  $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wno-missing-field-initializers>
)

target_compile_definitions(evm_workchain_test PUBLIC TOS_EVM_TEST_INSTRUMENTATION=1)

target_include_directories(evm_workchain_test
  PUBLIC
    ${CMAKE_SOURCE_DIR}             # for "evm/core/*.h", "evm/rpc/*.h"
    ${CMAKE_SOURCE_DIR}/crypto      # for "block/*.h"
    ${CMAKE_SOURCE_DIR}/crypto/vm   # for "vm/cells/*.h"
)

target_link_libraries(evm_workchain_test
  PUBLIC
    silkworm_core
    tos_crypto   # cells, vm types, block types
    tddb         # RocksDB wrapper for the side-channel cache
)

# Third variant: same EVM sources as `evm_workchain_test`, additionally
# compiled with `TOS_ENABLE_EVM_DEBUG_RPC=1`. The debug-method coverage
# tests (e.g. `test_m03_validator_minimal_disables_debug_methods`) need
# the dispatcher in `rpc/handlers.cpp` to compile in the debug_*
# branches; flipping the macro on the test executable alone is not
# sufficient because `is_eth_rpc_method` and the profile gate live in
# the library's translation unit. Production binaries continue to link
# `evm_workchain` (no debug surface), the default unit tests link
# `evm_workchain_test` (no debug surface), and only
# `test-evm-executor-debug` links this library.
add_library(evm_workchain_test_debug STATIC ${EVM_SRC})

target_compile_options(evm_workchain_test_debug PRIVATE
  $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wno-cast-qual>
  $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wno-deprecated-literal-operator>
  $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wno-missing-field-initializers>
)

target_compile_definitions(evm_workchain_test_debug
  PUBLIC
    TOS_EVM_TEST_INSTRUMENTATION=1
    TOS_ENABLE_EVM_DEBUG_RPC=1
)

target_include_directories(evm_workchain_test_debug
  PUBLIC
    ${CMAKE_SOURCE_DIR}             # for "evm/core/*.h", "evm/rpc/*.h"
    ${CMAKE_SOURCE_DIR}/crypto      # for "block/*.h"
    ${CMAKE_SOURCE_DIR}/crypto/vm   # for "vm/cells/*.h"
)

target_link_libraries(evm_workchain_test_debug
  PUBLIC
    silkworm_core
    tos_crypto   # cells, vm types, block types
    tddb         # RocksDB wrapper for the side-channel cache
)

add_subdirectory(test)
