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

# Expose lightweight test-only counters for the lazy state-load and lazy
# storage-witness-index paths. The atomic increments are O(1) per touched
# entry and have negligible runtime cost; tests rely on the counters to
# prove that hot-path operations stay O(touched) instead of O(global state).
target_compile_definitions(evm_workchain PUBLIC TOS_EVM_TEST_INSTRUMENTATION=1)

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

add_subdirectory(test)
