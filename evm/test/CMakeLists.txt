# evm/test — EVM workchain unit tests + Pyspec walkers.

add_executable(test-evm-executor test-executor.cpp)
# Link the test-instrumented EVM library so the lazy-load/MPT-walk counters
# referenced by the regression tests resolve. Production binaries continue
# to link `evm_workchain`, which is built without TOS_EVM_TEST_INSTRUMENTATION.
target_link_libraries(test-evm-executor PRIVATE evm_workchain_test)
target_include_directories(test-evm-executor PRIVATE ${SECP256K1_INCLUDE_DIR})

if (COMMAND tos_test)
  tos_test(test-evm-executor)
else()
  add_test(NAME test-evm-executor COMMAND test-evm-executor)
endif()

add_executable(test-evm-compute-purity test-evm-compute-purity.cpp)
target_link_libraries(test-evm-compute-purity PRIVATE evm_workchain_test)
target_include_directories(test-evm-compute-purity PRIVATE ${SECP256K1_INCLUDE_DIR})

if (COMMAND tos_test)
  tos_test(test-evm-compute-purity)
else()
  add_test(NAME test-evm-compute-purity COMMAND test-evm-compute-purity)
endif()
