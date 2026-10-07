# Pure, actor-free parsers for chain data served through JSON-RPC. Kept in a
# separate library so they can be unit tested with hostile inputs
# (see test/test-json-rpc-parse.cpp).
add_library(json-rpc-parse STATIC
  json-rpc-server-parse.h
  json-rpc-server-parse.cpp
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
  json-rpc-server-token.cpp
  json-rpc-server-utils.cpp
  json-rpc-server-shared.cpp
  json-rpc-server-wc0index.cpp
  wallet-index.h
  wallet-index.cpp
  wallet-index-writer.h
  wallet-index-writer.cpp
)

set(VALIDATOR_ENGINE_SOURCE
  validator-engine.hpp
  validator-engine.cpp
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
  fift-lib smc-envelope json-rpc-parse json-rpc-account-model json-rpc-storage)

add_executable(validator-engine ${VALIDATOR_ENGINE_SOURCE})
target_compile_options(validator-engine PRIVATE
  $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wno-cast-qual>
  $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wno-deprecated-literal-operator>
)
target_link_libraries(validator-engine validator-engine-json-rpc metrics overlay tdutils tdactor adnl tl_api dht
  rldp2 quic full-node validator tos_validator validator
  fift-lib memprof git tos_pq_consensus_signer ${JEMALLOC_LIBRARIES})

target_link_libraries(validator-engine smc-envelope json-rpc-parse json-rpc-account-model)
if (JEMALLOC_FOUND)
  # Name the jemalloc header by full path instead of adding JEMALLOC_INCLUDE_DIR to the
  # search path: that directory is often a shared prefix (e.g. /opt/homebrew/include)
  # whose other libraries would shadow the vendored headers this target is built against.
  target_compile_definitions(validator-engine PRIVATE -DTOS_USE_JEMALLOC=1
                             TOS_JEMALLOC_HEADER="${JEMALLOC_INCLUDE_DIR}/jemalloc/jemalloc.h")
endif()

install(TARGETS validator-engine RUNTIME DESTINATION bin)
