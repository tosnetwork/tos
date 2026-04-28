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

# Debug-RPC-enabled sibling of test-evm-executor. Links against
# `evm_workchain_test_debug`, which rebuilds every EVM source with
# `TOS_ENABLE_EVM_DEBUG_RPC=1` (in addition to the
# `TOS_EVM_TEST_INSTRUMENTATION=1` already on the regular test
# library). The debug-method coverage tests
# (e.g. `test_m03_validator_minimal_disables_debug_methods`) exercise
# the dispatcher in `rpc/handlers.cpp` — flipping the macro only on
# this executable's translation unit would leave `is_eth_rpc_method`
# and the profile gate (compiled into the library) without their
# `debug_*` branches, so the dispatcher would silently treat the
# methods as unknown. The macro propagates to this executable
# transitively from the library's PUBLIC compile-definitions.
add_executable(test-evm-executor-debug test-executor.cpp)
target_link_libraries(test-evm-executor-debug PRIVATE evm_workchain_test_debug)
target_include_directories(test-evm-executor-debug PRIVATE ${SECP256K1_INCLUDE_DIR})

if (COMMAND tos_test)
  tos_test(test-evm-executor-debug)
else()
  add_test(NAME test-evm-executor-debug COMMAND test-evm-executor-debug)
endif()

add_executable(test-evm-compute-purity test-evm-compute-purity.cpp)
target_link_libraries(test-evm-compute-purity PRIVATE evm_workchain_test)
target_include_directories(test-evm-compute-purity PRIVATE ${SECP256K1_INCLUDE_DIR})

if (COMMAND tos_test)
  tos_test(test-evm-compute-purity)
else()
  add_test(NAME test-evm-compute-purity COMMAND test-evm-compute-purity)
endif()

# Optional coverage-guided fuzz harnesses (libFuzzer + AddressSanitizer).
#
# Gated behind TOS_BUILD_LIBFUZZER so default builds remain unaffected.
# libFuzzer + the `-fsanitize=fuzzer,address` instrumentation pair is a
# clang-only feature; we fail the configure step explicitly when a
# non-clang compiler is in use rather than silently producing a binary
# that is missing `LLVMFuzzerTestOneInput`'s entry-point glue.
#
# These targets are NOT registered with `tos_test` / `add_test` — they
# are not unit tests; they are long-running fuzz drivers. CI should
# launch them via `scripts/run-libfuzzer.sh` for a bounded duration
# and treat any `crash-*` artifact in the corpus directory as a
# security incident.
if(TOS_BUILD_LIBFUZZER)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR
      "TOS_BUILD_LIBFUZZER requires clang (got ${CMAKE_CXX_COMPILER_ID}). "
      "Reconfigure with -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++.")
  endif()

  add_executable(test-boc-libfuzzer test-boc-libfuzzer.cpp)
  target_link_libraries(test-boc-libfuzzer
    PRIVATE
      tos_crypto
      tdutils
  )
  target_compile_options(test-boc-libfuzzer PRIVATE -fsanitize=fuzzer,address)
  target_link_options(test-boc-libfuzzer PRIVATE -fsanitize=fuzzer,address)
endif()
