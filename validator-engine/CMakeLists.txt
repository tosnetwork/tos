set(VALIDATOR_ENGINE_SOURCE
  validator-engine.hpp
  validator-engine.cpp
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

add_executable(validator-engine ${VALIDATOR_ENGINE_SOURCE})
target_link_libraries(validator-engine metrics overlay tdutils tdactor adnl tl_api dht
  rldp rldp2 quic catchain validatorsession full-node validator tos_validator validator
  fift-lib memprof git ${JEMALLOC_LIBRARIES})
if (JEMALLOC_FOUND)
  target_include_directories(validator-engine PRIVATE ${JEMALLOC_INCLUDE_DIR})
  target_compile_definitions(validator-engine PRIVATE -DTOS_USE_JEMALLOC=1)
endif()

install(TARGETS validator-engine RUNTIME DESTINATION bin)
