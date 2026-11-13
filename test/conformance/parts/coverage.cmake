# Coverage gate (coverage/handlers.py): with an instrumented build, every fixture and the REL-02 replay run
# through the reference, and the result must keep every VM instruction handler in coverage/vm-handlers-covered.txt
# executed and each component's line coverage at its baseline. Configure a separate build directory with
#   -DCMAKE_C_FLAGS="-fprofile-instr-generate -fcoverage-mapping" -DCMAKE_CXX_FLAGS=<same>
#   -DCMAKE_EXE_LINKER_FLAGS=-fprofile-instr-generate -DCMAKE_SHARED_LINKER_FLAGS=-fprofile-instr-generate
#   -DCONFORMANCE_COVERAGE=ON
option(CONFORMANCE_COVERAGE "Add the coverage gate (needs an instrumented build directory)" OFF)
if (NOT CONFORMANCE_COVERAGE)
  return()
endif()
if (NOT CMAKE_CXX_FLAGS MATCHES "-fprofile-instr-generate" OR NOT CMAKE_CXX_FLAGS MATCHES "-fcoverage-mapping")
  message(FATAL_ERROR "CONFORMANCE_COVERAGE needs CMAKE_CXX_FLAGS with -fprofile-instr-generate -fcoverage-mapping")
endif()
set(CONFORMANCE_COVERAGE_REPORT ${CMAKE_CURRENT_BINARY_DIR}/coverage-report.json)
add_test(NAME conformance-coverage-measure
  COMMAND ${Python3_EXECUTABLE} -B ${CONFORMANCE_DIR}/coverage/handlers.py measure
    --build-dir ${CMAKE_BINARY_DIR} --source-dir ${CMAKE_SOURCE_DIR} --out ${CONFORMANCE_COVERAGE_REPORT})
set_tests_properties(conformance-coverage-measure PROPERTIES
  LABELS "coverage" TIMEOUT 7200 FIXTURES_SETUP conformance-coverage-report)
add_test(NAME conformance-coverage-check
  COMMAND ${Python3_EXECUTABLE} -B ${CONFORMANCE_DIR}/coverage/handlers.py check ${CONFORMANCE_COVERAGE_REPORT})
set_tests_properties(conformance-coverage-check PROPERTIES
  LABELS "coverage" TIMEOUT 300 FIXTURES_REQUIRED conformance-coverage-report)
