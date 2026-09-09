# Include through CMAKE_PROJECT_TOS_INCLUDE to build the private acceptance target.
# This does not change any workchain activation option.
if(NOT CONSTRUCTION_ISOLATION_SOURCE)
  set(CONSTRUCTION_ISOLATION_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/test-workchain-construction-isolation.cpp")
endif()
add_executable(test-workchain-construction-isolation "${CONSTRUCTION_ISOLATION_SOURCE}")
# Measurement copies affect this private target only; production targets retain
# their normal source and include paths.
if(CONSTRUCTION_ISOLATION_HEADER_DIR)
  target_include_directories(test-workchain-construction-isolation BEFORE PRIVATE "${CONSTRUCTION_ISOLATION_HEADER_DIR}")
endif()
set_target_properties(test-workchain-construction-isolation PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
target_link_libraries(test-workchain-construction-isolation PRIVATE tos_crypto)
# Existing private regressions always use their committed sources and headers.
set(I13_ACCEPTANCE_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/test-workchain-i13-acceptance.cpp")
set(I13_ACCEPTANCE_HEADER_DIR "")
include("${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/workchain-i13-acceptance.cmake")
set(I13_USAGE_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/test-workchain-i13-usage-acceptance.cpp")
include("${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/workchain-i13-usage-acceptance.cmake")

# Registration is opt-in with this module; missing dependencies fail configuration
# or the driver. The child build cannot rewrite this parent CTest registry.
find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_test(NAME test-workchain-construction-isolation-gates COMMAND ${Python3_EXECUTABLE}
  "${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/workchain-construction-isolation.py"
  --build "${CMAKE_CURRENT_BINARY_DIR}/workchain-i13-ctest/construction/build"
  --ctest-root "${CMAKE_CURRENT_BINARY_DIR}/workchain-i13-ctest/construction/runs")
set_tests_properties(test-workchain-construction-isolation-gates PROPERTIES
  TIMEOUT 7200 RESOURCE_LOCK workchain_i13_measurements LABELS "private;workchain;i13")
