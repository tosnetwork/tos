# The tosctl Rust VM and executor as a conformance target (docs/tosvm.md): the frozen vectors, the
# REL-02 chain replay and the controls of the comparison, run against the Rust adapter. Building the
# adapter needs cargo, so these tests carry their own label, conformance-tosvm.
find_program(CONFORMANCE_CARGO cargo)
if (NOT CONFORMANCE_CARGO)
  message(STATUS "conformance: cargo not found, conformance-tosvm tests not added")
  return()
endif()

set(CONFORMANCE_TOSVM_TARGET_DIR ${CMAKE_BINARY_DIR}/test/conformance/tosvm-target)
set(CONFORMANCE_TOSVM ${CONFORMANCE_TOSVM_TARGET_DIR}/release/examples/conformance-target)

add_test(NAME conformance-tosvm-build
  COMMAND ${CMAKE_COMMAND} -E env CARGO_TARGET_DIR=${CONFORMANCE_TOSVM_TARGET_DIR}
    ${CONFORMANCE_CARGO} build --release --locked -p tos_executor --example conformance-target
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tosctl/src)
set_tests_properties(conformance-tosvm-build PROPERTIES
  LABELS "conformance-tosvm" TIMEOUT 3600 FIXTURES_SETUP conformance-tosvm-target)

add_test(NAME conformance-tosvm-vectors
  COMMAND ${Python3_EXECUTABLE} -B ${CONFORMANCE_DIR}/runner/conformance.py run
    --target ${CONFORMANCE_TOSVM} ${CONFORMANCE_DIR}/vectors)
set_tests_properties(conformance-tosvm-vectors PROPERTIES
  LABELS "conformance-tosvm" TIMEOUT 1800 FIXTURES_REQUIRED conformance-tosvm-target)

add_test(NAME conformance-tosvm-controls
  COMMAND ${Python3_EXECUTABLE} -B ${CONFORMANCE_DIR}/runner/tosvm_controls.py
    ${CONFORMANCE_TOSVM} ${CONFORMANCE_DIR}/vectors)
set_tests_properties(conformance-tosvm-controls PROPERTIES
  LABELS "conformance-tosvm" TIMEOUT 600 FIXTURES_REQUIRED conformance-tosvm-target)

if (TARGET test-epoch-replay)
  add_test(NAME conformance-tosvm-rel02-chain
    COMMAND ${Python3_EXECUTABLE} -B ${CONFORMANCE_DIR}/migrate/rel02.py chain
      $<TARGET_FILE:test-epoch-replay> ${CONFORMANCE_TOSVM} ${CMAKE_SOURCE_DIR}/test/rel02/corpus)
  set_tests_properties(conformance-tosvm-rel02-chain PROPERTIES
    LABELS "conformance-tosvm" TIMEOUT 1800 FIXTURES_REQUIRED conformance-tosvm-target)
endif()
