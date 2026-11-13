# Conformance vectors (README.md). The reference library is built from every ref/*.cpp except the CLI,
# so a new harness is one new ref/harness-<name>.cpp. Further targets and tests live in parts/*.cmake,
# one file per component, included in name order.

if (USE_EMSCRIPTEN)
  return()
endif()

set(CONFORMANCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(CONFORMANCE_REF_DIR ${CONFORMANCE_DIR}/ref)
file(GLOB CONFORMANCE_REF_SOURCES CONFIGURE_DEPENDS ${CONFORMANCE_REF_DIR}/*.cpp)
list(REMOVE_ITEM CONFORMANCE_REF_SOURCES ${CONFORMANCE_REF_DIR}/conformance-ref-cli.cpp)

add_library(conformance-ref SHARED ${CONFORMANCE_REF_SOURCES})
target_include_directories(conformance-ref PRIVATE ${CMAKE_SOURCE_DIR}/emulator PUBLIC ${CONFORMANCE_REF_DIR})
target_link_libraries(conformance-ref PRIVATE emulator git)
# Export only the conformance_* entry points. The library carries static copies of node code next to
# libemulator.so; exported inline symbols of one copy would interpose on the other and the two would run
# against different globals (seen as wrong gas on two REL-02 elector transactions).
set_target_properties(conformance-ref PROPERTIES CXX_VISIBILITY_PRESET hidden VISIBILITY_INLINES_HIDDEN ON)
target_link_options(conformance-ref PRIVATE -Wl,--exclude-libs,ALL)
add_executable(conformance-ref-cli ${CONFORMANCE_REF_DIR}/conformance-ref-cli.cpp)
target_link_libraries(conformance-ref-cli PRIVATE conformance-ref)

set(CONFORMANCE_VECTORS_DIR "" CACHE PATH "Checkout of the conformance vectors repository at the commit pinned in test/conformance/VECTORS")

# The runner's own checks, then every frozen fixture against the reference built from this tree. A
# behaviour change fails here until the fixtures are regenerated in the same change.
add_test(NAME conformance-runner
  COMMAND ${Python3_EXECUTABLE} -B -m unittest discover -s ${CONFORMANCE_DIR}/runner -p "test_*.py" -t ${CONFORMANCE_DIR}/runner
  WORKING_DIRECTORY ${CONFORMANCE_DIR}/runner)
set_tests_properties(conformance-runner PROPERTIES LABELS "conformance" TIMEOUT 300)
if (CONFORMANCE_VECTORS_DIR)
  set_tests_properties(conformance-runner PROPERTIES ENVIRONMENT "CONFORMANCE_VECTORS_DIR=${CONFORMANCE_VECTORS_DIR}")
endif()
add_test(NAME conformance-vectors
  COMMAND ${Python3_EXECUTABLE} -B ${CONFORMANCE_DIR}/runner/conformance.py run
    --target $<TARGET_FILE:conformance-ref-cli> ${CONFORMANCE_DIR}/vectors)
set_tests_properties(conformance-vectors PROPERTIES LABELS "conformance" TIMEOUT 1800)

# The external vectors repository pinned in VECTORS (fetch-vectors.sh checks it out). Its tests check the
# pin first, then run every fixture there. Without a checkout they are reported as skipped, not passed.
if (CONFORMANCE_VECTORS_DIR)
  add_test(NAME conformance-vectors-pin
    COMMAND ${Python3_EXECUTABLE} -B ${CONFORMANCE_DIR}/runner/vectors_pin.py check ${CONFORMANCE_VECTORS_DIR})
  set_tests_properties(conformance-vectors-pin PROPERTIES LABELS "conformance" FIXTURES_SETUP conformance-vectors-checkout TIMEOUT 600)
  add_test(NAME conformance-vectors-external
    COMMAND ${Python3_EXECUTABLE} -B ${CONFORMANCE_DIR}/runner/conformance.py run
      --target $<TARGET_FILE:conformance-ref-cli> ${CONFORMANCE_VECTORS_DIR})
  set_tests_properties(conformance-vectors-external PROPERTIES LABELS "conformance" FIXTURES_REQUIRED conformance-vectors-checkout TIMEOUT 7200)
else()
  add_test(NAME conformance-vectors-external
    COMMAND ${Python3_EXECUTABLE} -c "print('CONFORMANCE_VECTORS_DIR is not set: external vectors not run (see test/conformance/fetch-vectors.sh)'); raise SystemExit(77)")
  set_tests_properties(conformance-vectors-external PROPERTIES LABELS "conformance" SKIP_RETURN_CODE 77)
endif()

file(GLOB CONFORMANCE_PARTS CONFIGURE_DEPENDS ${CONFORMANCE_DIR}/parts/*.cmake)
list(SORT CONFORMANCE_PARTS)
foreach(part ${CONFORMANCE_PARTS})
  include(${part})
endforeach()
