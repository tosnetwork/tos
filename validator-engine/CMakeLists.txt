# Pure, actor-free parsers for chain data served through JSON-RPC. Kept in a
# separate library so they can be unit tested with hostile inputs
# (see test/test-json-rpc-parse.cpp).
add_library(json-rpc-parse STATIC
  json-rpc-server-parse.h
  json-rpc-server-parse.cpp
)
target_include_directories(json-rpc-parse PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
target_link_libraries(json-rpc-parse PUBLIC tos_crypto tdutils)

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
  ${VALIDATOR_ENGINE_JSON_RPC_SOURCE}
)

add_executable(validator-engine ${VALIDATOR_ENGINE_SOURCE})
target_compile_options(validator-engine PRIVATE
  $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wno-cast-qual>
  $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wno-deprecated-literal-operator>
)
target_link_libraries(validator-engine metrics overlay tdutils tdactor adnl tl_api dht
  rldp rldp2 quic full-node validator tos_validator validator
  fift-lib memprof git ${JEMALLOC_LIBRARIES})

target_link_libraries(validator-engine smc-envelope json-rpc-parse)
if (JEMALLOC_FOUND)
  target_include_directories(validator-engine PRIVATE ${JEMALLOC_INCLUDE_DIR})
  target_compile_definitions(validator-engine PRIVATE -DTOS_USE_JEMALLOC=1)
endif()

install(TARGETS validator-engine RUNTIME DESTINATION bin)
