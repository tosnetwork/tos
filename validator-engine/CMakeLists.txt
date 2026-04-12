set(VALIDATOR_ENGINE_SOURCE
  validator-engine.hpp
  validator-engine.cpp
  json-rpc-server.h
  json-rpc-server.cpp
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
