# EVM Workchain module — host-chain adapter for EVM execution.
#
# This library provides:
#   - workchain identification (evm-workchain.h)
#   - canonical transaction decoding (evm-transaction.h/cpp)
#   - EVM state adapter (evm-state.h/cpp)
#   - block context mapping (evm-block-context.h/cpp)
#   - EVM executor (evm-executor.h/cpp)
#   - compute phase hook (evm-compute-phase.h/cpp)

set(EVM_WORKCHAIN_SRC
  evm-transaction.cpp
  evm-state.cpp
  evm-state-root.cpp
  evm-block-context.cpp
  evm-executor.cpp
  evm-compute-phase.cpp
  evm-init.cpp
  evm-rpc.cpp
  evm-config-param.cpp
  evm-external-message.cpp
  evm-bridge.cpp
  evm-tracer.cpp
  evm-subscriptions.cpp
  evm-incremental-trie.cpp
  evm-cell-codec.cpp
  evm-cell-state.cpp
  evm-rpc-cache-codec.cpp
  evm-rpc-cache-db.cpp
  evm-access-list-tracer.cpp
  evm-mpt-prover.cpp
)

add_library(evm_workchain STATIC ${EVM_WORKCHAIN_SRC})

target_include_directories(evm_workchain
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}             # for "evm-workchain.h" etc.
    ${CMAKE_SOURCE_DIR}/crypto              # for "block/transaction.h" etc.
    ${CMAKE_SOURCE_DIR}/crypto/vm           # for "vm/cells/CellSlice.h" etc.
    ${CMAKE_SOURCE_DIR}                     # for top-level includes
)

target_link_libraries(evm_workchain
  PUBLIC
    silkworm_core
    tos_crypto   # host-chain crypto library (cells, vm types, block types)
    tddb         # RocksDB wrapper for persistent EVM state
)

# --- Test executable ---
add_executable(test-evm-executor test-evm-executor.cpp)
target_link_libraries(test-evm-executor PRIVATE evm_workchain)
target_include_directories(test-evm-executor PRIVATE ${SECP256K1_INCLUDE_DIR})
if (COMMAND tos_test)
  tos_test(test-evm-executor)
else()
  add_test(NAME test-evm-executor COMMAND test-evm-executor)
endif()
