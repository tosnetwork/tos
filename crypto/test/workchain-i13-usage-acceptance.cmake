# Independent private target; no activation option is changed.
if(NOT I13_USAGE_SOURCE)
  set(I13_USAGE_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/test-workchain-i13-usage-acceptance.cpp")
endif()
add_executable(test-workchain-i13-usage-acceptance "${I13_USAGE_SOURCE}")
set_target_properties(test-workchain-i13-usage-acceptance PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
target_link_libraries(test-workchain-i13-usage-acceptance PRIVATE tos_crypto)

# Registration is opt-in with this module; missing dependencies fail configuration
# or the driver. The child build cannot rewrite this parent CTest registry.
find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_test(NAME test-workchain-i13-usage-acceptance-gates COMMAND ${Python3_EXECUTABLE}
  "${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/workchain-i13-usage-acceptance.py"
  --build "${CMAKE_CURRENT_BINARY_DIR}/workchain-i13-ctest/usage/build"
  --ctest-root "${CMAKE_CURRENT_BINARY_DIR}/workchain-i13-ctest/usage/runs")
set_tests_properties(test-workchain-i13-usage-acceptance-gates PROPERTIES
  TIMEOUT 3600 RESOURCE_LOCK workchain_i13_measurements LABELS "private;workchain;i13")
