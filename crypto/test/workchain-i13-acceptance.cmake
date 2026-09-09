# Include through CMAKE_PROJECT_TOS_INCLUDE to build the private acceptance target.
# This does not change any workchain activation option.
if(NOT I13_ACCEPTANCE_SOURCE)
  set(I13_ACCEPTANCE_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/test-workchain-i13-acceptance.cpp")
endif()
add_executable(test-workchain-i13-acceptance "${I13_ACCEPTANCE_SOURCE}")
# Measurement copies affect this private target only; production targets retain
# their normal source and include paths.
if(I13_ACCEPTANCE_HEADER_DIR)
  target_include_directories(test-workchain-i13-acceptance BEFORE PRIVATE "${I13_ACCEPTANCE_HEADER_DIR}")
endif()
set_target_properties(test-workchain-i13-acceptance PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
target_link_libraries(test-workchain-i13-acceptance PRIVATE tos_crypto)

# Registration is opt-in with this module; missing dependencies fail configuration
# or the driver. The child build cannot rewrite this parent CTest registry.
find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_test(NAME test-workchain-i13-acceptance-gates COMMAND ${Python3_EXECUTABLE}
  "${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/workchain-i13-acceptance.py"
  --build "${CMAKE_CURRENT_BINARY_DIR}/workchain-i13-ctest/coverage/build"
  --ctest-root "${CMAKE_CURRENT_BINARY_DIR}/workchain-i13-ctest/coverage/runs")
set_tests_properties(test-workchain-i13-acceptance-gates PROPERTIES
  TIMEOUT 3600 RESOURCE_LOCK workchain_i13_measurements LABELS "private;workchain;i13")
