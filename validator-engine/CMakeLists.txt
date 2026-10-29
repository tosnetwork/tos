add_library(control-getter STATIC control-getter.h control-getter.cpp control-getter-executor.h control-getter-executor.cpp control-getter-read.h control-getter-read.cpp control-getter-service.h control-getter-service.cpp)
target_include_directories(control-getter PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/.. ${CMAKE_CURRENT_SOURCE_DIR}/../crypto)
target_link_libraries(control-getter PUBLIC tos_crypto tdutils tl_api tdactor)

# Pure, actor-free parsers for chain data served through JSON-RPC. Kept in a
# separate library so they can be unit tested with hostile inputs
# (see test/test-json-rpc-parse.cpp).
add_library(json-rpc-parse STATIC
  json-rpc-contract.h
  json-rpc-contract.cpp
  json-rpc-server-parse.h
  json-rpc-server-parse.cpp
  json-rpc-server-runresult.h
  json-rpc-server-runresult.cpp
)
target_include_directories(json-rpc-parse PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
target_link_libraries(json-rpc-parse PUBLIC tos_crypto tdutils tl_lite_api)

# An account's storage metadata as served by the JSON-RPC (see
# test/test-json-rpc-storage.cpp, which holds it to block::Account).
add_library(json-rpc-storage STATIC
  json-rpc-server-storage.h
  json-rpc-server-storage.cpp
)
target_include_directories(json-rpc-storage PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
target_link_libraries(json-rpc-storage PUBLIC tos_block tos_crypto tdutils)

# The external message sendQuery submits and the import fee estimateFee prices
# for it (see emulator/test/json-rpc-import-fee-fixture.cpp, which holds the fee
# to the executor's import of the same message).
add_library(json-rpc-fee STATIC
  json-rpc-server-fee.h
  json-rpc-server-fee.cpp
)
target_include_directories(json-rpc-fee PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
target_link_libraries(json-rpc-fee PUBLIC smc-envelope tos_block tos_crypto tdutils)

find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(TOS_EXPLORER_QUANTUM_NETWORK_TAG "4242424242424242424242424242424242424242424242424242424242424242" CACHE STRING "Registered review Quantum wallet network tag")
file(GLOB EXPLORER_REGISTRY_SOURCES CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/crypto/smartcont/*.fc")
set(EXPLORER_REGISTRY "${CMAKE_BINARY_DIR}/generated/explorer-pq-registry.inc")
add_custom_command(OUTPUT ${EXPLORER_REGISTRY}
  BYPRODUCTS ${CMAKE_BINARY_DIR}/generated/explorer-pq-registry.json
    ${CMAKE_BINARY_DIR}/generated/pq_highload_mldsa44_v1.boc
    ${CMAKE_BINARY_DIR}/generated/mldsa44_auth_module_v1.boc
    ${CMAKE_BINARY_DIR}/generated/falcon512_padded_auth_module_v1.boc
    ${CMAKE_BINARY_DIR}/generated/quantum_fee_vault_v3.boc
    ${CMAKE_BINARY_DIR}/generated/quantum_module_v1.boc
    ${CMAKE_BINARY_DIR}/generated/quantum_wallet_v4.boc
    ${CMAKE_BINARY_DIR}/generated/quantum_self_pay_v1.boc
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/scripts/build-explorer-pq-registry.py
    --func $<TARGET_FILE:func> --fift $<TARGET_FILE:fift> --output ${EXPLORER_REGISTRY}
    --network-tag ${TOS_EXPLORER_QUANTUM_NETWORK_TAG}
  DEPENDS func fift ${EXPLORER_REGISTRY_SOURCES} ${CMAKE_SOURCE_DIR}/scripts/build-explorer-pq-registry.py
    ${CMAKE_SOURCE_DIR}/test/auth-extensions/native.py ${CMAKE_SOURCE_DIR}/test/auth-extensions/cells.py
  VERBATIM)
add_library(json-rpc-explorer STATIC json-rpc-explorer.cpp json-rpc-explorer.h json-rpc-explorer-account.cpp json-rpc-explorer-finality.cpp ${EXPLORER_REGISTRY})
target_include_directories(json-rpc-explorer PRIVATE ${CMAKE_BINARY_DIR}/generated)
target_link_libraries(json-rpc-explorer PUBLIC control-getter tos_block tos_crypto tdutils tl_lite_api json-rpc-parse lite-client-common)
target_include_directories(json-rpc-explorer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

set(VALIDATOR_ENGINE_JSON_RPC_SOURCE
  json-rpc-server.h
  json-rpc-server-internal.h
  json-rpc-server.cpp
  json-rpc-server-accounts.cpp
  json-rpc-server-account-capability.cpp
  json-rpc-server-blocks.cpp
  json-rpc-server-transactions.cpp
  json-rpc-server-runmethod.cpp
  json-rpc-server-send.cpp
  json-rpc-server-config.cpp
  json-rpc-server-explorer.cpp
  json-rpc-server-token.cpp
  json-rpc-server-utils.cpp
  json-rpc-server-shared.cpp
  json-rpc-server-wc0index.cpp
  wallet-index.h
  wallet-index.cpp
  wallet-index-snapshot.h
  wallet-index-snapshot.cpp
  wallet-index-writer.h
  wallet-index-writer.cpp
)

set(VALIDATOR_ENGINE_SOURCE
  validator-engine.hpp
  validator-engine.cpp
  validator-engine-control-getters.cpp
)

add_library(json-rpc-account-model STATIC
  json-rpc-account-model.h
  json-rpc-account-model.cpp
)
target_link_libraries(json-rpc-account-model PUBLIC smc-envelope tos_crypto tdutils)
target_include_directories(json-rpc-account-model PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# The JSON-RPC server as a library, so a test can run the real server and its
# listener without the rest of the engine (see test/test-json-rpc-transport.cpp).
add_library(validator-engine-json-rpc STATIC ${VALIDATOR_ENGINE_JSON_RPC_SOURCE})
target_compile_options(validator-engine-json-rpc PRIVATE
  $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wno-cast-qual>
  $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wno-deprecated-literal-operator>
)
target_include_directories(validator-engine-json-rpc PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(validator-engine-json-rpc PUBLIC metrics overlay tdutils tdactor adnl tl_api dht
  rldp2 quic full-node validator tos_validator validator toshttp
  fift-lib smc-envelope json-rpc-parse json-rpc-account-model json-rpc-storage json-rpc-fee json-rpc-explorer control-getter lite-client-common)

add_executable(validator-engine ${VALIDATOR_ENGINE_SOURCE})
target_compile_options(validator-engine PRIVATE
  $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wno-cast-qual>
  $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wno-deprecated-literal-operator>
)
target_link_libraries(validator-engine validator-engine-json-rpc metrics overlay tdutils tdactor adnl tl_api dht
  rldp2 quic full-node validator tos_validator validator
  fift-lib memprof git tos_pq_consensus_signer tos_pq_consensus_key_lock ${JEMALLOC_LIBRARIES})

target_link_libraries(validator-engine smc-envelope json-rpc-parse json-rpc-account-model control-getter)
if (JEMALLOC_FOUND)
  # Name the jemalloc header by full path instead of adding JEMALLOC_INCLUDE_DIR to the
  # search path: that directory is often a shared prefix (e.g. /opt/homebrew/include)
  # whose other libraries would shadow the vendored headers this target is built against.
  target_compile_definitions(validator-engine PRIVATE -DTOS_USE_JEMALLOC=1
                             TOS_JEMALLOC_HEADER="${JEMALLOC_INCLUDE_DIR}/jemalloc/jemalloc.h")
endif()

install(TARGETS validator-engine RUNTIME DESTINATION bin)
