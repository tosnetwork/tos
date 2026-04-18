# evm/test — EVM workchain unit tests + Pyspec walkers.

add_executable(test-evm-executor test-executor.cpp)
target_link_libraries(test-evm-executor PRIVATE evm_workchain)
target_include_directories(test-evm-executor PRIVATE ${SECP256K1_INCLUDE_DIR})

if (COMMAND tos_test)
  tos_test(test-evm-executor)
else()
  add_test(NAME test-evm-executor COMMAND test-evm-executor)
endif()
