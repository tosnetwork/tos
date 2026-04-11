set(TOS_VALIDATOR_SOURCE
  accept-block.cpp
  block.cpp
  check-proof.cpp
  collator.cpp
  config.cpp
  external-message.cpp
  ext-message-pool.cpp
  fabric.cpp
  ihr-message.cpp
  liteserver.cpp
  message-queue.cpp
  out-msg-queue-proof.cpp
  proof.cpp
  shard.cpp
  top-shard-descr.cpp
  validate-query.cpp

  accept-block.hpp
  block.hpp
  check-proof.hpp
  collator-impl.h
  config.hpp
  external-message.hpp
  ext-message-pool.hpp
  ihr-message.hpp
  liteserver.hpp
  liteserver-cache.hpp
  message-queue.hpp
  out-msg-queue-proof.hpp
  proof.hpp
  shard.hpp
  top-shard-descr.hpp
  validate-query.hpp)

add_library(tos_validator STATIC ${TOS_VALIDATOR_SOURCE})

target_include_directories(tos_validator PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/..
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/../crypto
  ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(tos_validator PRIVATE tdutils tdactor adnl tl_api tl_lite_api tl-lite-utils dht tdfec
  overlay catchain validatorsession tos_crypto tos_block)
