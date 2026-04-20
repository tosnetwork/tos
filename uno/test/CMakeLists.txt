# uno/test — Uno Workchain unit tests.
#
# Agent 5 owns uno/CMakeLists.txt. From there, this subdirectory is included
# via `add_subdirectory(test)` once the `uno_workchain` static library target
# exists. Each test below links against that library and relies on the
# headers exposed by it (uno/rpc/*.h).
#
# The three tests in scope for Agent 6:
#   test-uno-transfer       — round-trip smoke for uno_sendTransfer plumbing
#   test-uno-determinism    — P.5 determinism scaffold (RPC-scope only until
#                             UnoShardState accessors are wired)
#   test-uno-filter         — compact-filter service plumbing + tag match
#
# Any test whose required upstream interface has not yet been bound prints
# a `SKIP:` line for that specific assertion and keeps the test binary
# exit-status 0.

add_executable(test-uno-transfer              test-transfer.cpp)
add_executable(test-uno-determinism           test-determinism.cpp)
add_executable(test-uno-filter                test-filter.cpp)
# Decision #5 cross-impl parity gate for the Plonky3 public-input byte
# encoding. Driven by uno/test/golden/public-inputs-v1.hex; Rust side is
# uno/plonky3-ffi/tests/public_input_fixture.rs. Both implementations
# MUST produce byte-identical output for every fixture record.
add_executable(test-uno-public-input-fixture  test-public-input-fixture.cpp)
# P.3 parallel verify pool (§13 P.3): determinism vs serial reference,
# repeat-under-thread-pressure invariant, and a min-of-3 scaling
# micro-benchmark for the 4-core ≥ 3.5x ideal target from §1.4.
add_executable(test-uno-parallel-verify       test-parallel-verify.cpp)

foreach(_t test-uno-transfer
           test-uno-determinism
           test-uno-filter
           test-uno-public-input-fixture
           test-uno-parallel-verify)
  target_link_libraries(${_t} PRIVATE uno_workchain)
  target_include_directories(${_t} PRIVATE ${CMAKE_SOURCE_DIR})
  if (COMMAND tos_test)
    tos_test(${_t})
  else()
    add_test(NAME ${_t} COMMAND ${_t})
  endif()
endforeach()

# test-uno-parallel-verify spins up std::thread workers from the pool;
# make sure it links against the system's pthread runtime.
target_link_libraries(test-uno-parallel-verify PRIVATE Threads::Threads)

# Pass the canonical in-tree fixture path to the fixture test so ctest can
# run from the build directory without a cwd hack.
set_tests_properties(test-uno-public-input-fixture PROPERTIES
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}")
