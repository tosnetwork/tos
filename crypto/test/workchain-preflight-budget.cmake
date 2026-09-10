# Explicit C3 host-contract tests, not production registration or activation.
add_executable(test-workchain-preflight-budget
  "${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/test-workchain-preflight-budget.cpp")
target_include_directories(test-workchain-preflight-budget PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/crypto")
target_link_libraries(test-workchain-preflight-budget PRIVATE tdutils)
set_target_properties(test-workchain-preflight-budget PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_test(NAME test-workchain-preflight-budget-gates COMMAND "${Python3_EXECUTABLE}"
  "${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/workchain-preflight-budget.py"
  --binary "$<TARGET_FILE:test-workchain-preflight-budget>")
set_tests_properties(test-workchain-preflight-budget-gates PROPERTIES TIMEOUT 60
  RESOURCE_LOCK workchain_preflight_measurements LABELS "private;workchain;c3")
