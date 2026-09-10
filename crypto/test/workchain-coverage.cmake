# Explicit private coverage/phase checks only; no default registration.
add_executable(test-workchain-coverage "${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/test-workchain-coverage.cpp")
target_link_libraries(test-workchain-coverage PRIVATE tos_crypto)
set_target_properties(test-workchain-coverage PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_test(NAME test-workchain-coverage-gates COMMAND "${Python3_EXECUTABLE}"
  "${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/workchain-coverage.py"
  --binary "$<TARGET_FILE:test-workchain-coverage>")
set_tests_properties(test-workchain-coverage-gates PROPERTIES TIMEOUT 60
  RESOURCE_LOCK workchain_i13_measurements LABELS "private;workchain;i13")
