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
  rldp rldp2 quic catchain validatorsession full-node validator tos_validator validator
  fift-lib memprof git ${JEMALLOC_LIBRARIES})

target_link_libraries(validator-engine evm_workchain)
target_link_libraries(validator-engine uno_workchain)
if (JEMALLOC_FOUND)
  target_include_directories(validator-engine PRIVATE ${JEMALLOC_INCLUDE_DIR})
  target_compile_definitions(validator-engine PRIVATE -DTOS_USE_JEMALLOC=1)
endif()

add_executable(test-json-rpc-cache test-json-rpc-cache.cpp ${VALIDATOR_ENGINE_JSON_RPC_SOURCE})
target_compile_options(test-json-rpc-cache PRIVATE
  $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wno-cast-qual>
  $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wno-deprecated-literal-operator>
)
target_link_libraries(test-json-rpc-cache metrics overlay tdutils tdactor adnl tl_api dht
  rldp rldp2 quic catchain validatorsession full-node validator tos_validator validator
  fift-lib memprof git ${JEMALLOC_LIBRARIES})
target_link_libraries(test-json-rpc-cache evm_workchain)
target_link_libraries(test-json-rpc-cache uno_workchain)
if (JEMALLOC_FOUND)
  target_include_directories(test-json-rpc-cache PRIVATE ${JEMALLOC_INCLUDE_DIR})
  target_compile_definitions(test-json-rpc-cache PRIVATE -DTOS_USE_JEMALLOC=1)
endif()

install(TARGETS validator-engine RUNTIME DESTINATION bin)
