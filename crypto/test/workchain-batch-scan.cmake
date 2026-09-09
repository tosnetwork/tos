# Explicit private mechanism only; no activation or default build change.
if(NOT WORKCHAIN_SCAN_SOURCE)
  set(WORKCHAIN_SCAN_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/test-workchain-batch-scan.cpp")
endif()
if(NOT WORKCHAIN_SCAN_HEADER_DIR)
  set(WORKCHAIN_SCAN_HEADER_DIR "${CMAKE_CURRENT_SOURCE_DIR}/crypto")
endif()
if(NOT WORKCHAIN_SCAN_DRIVER)
  set(WORKCHAIN_SCAN_DRIVER "${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/workchain-batch-scan.py")
endif()
add_executable(test-workchain-batch-scan "${WORKCHAIN_SCAN_SOURCE}")
target_include_directories(test-workchain-batch-scan BEFORE PRIVATE "${WORKCHAIN_SCAN_HEADER_DIR}")
target_link_libraries(test-workchain-batch-scan PRIVATE tos_crypto)
set_target_properties(test-workchain-batch-scan PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(workchain_scan_arguments)
if(WORKCHAIN_SCAN_LATER_ONLY)
  list(APPEND workchain_scan_arguments --later-only)
endif()
add_test(NAME test-workchain-batch-scan-gates COMMAND "${Python3_EXECUTABLE}"
  "${WORKCHAIN_SCAN_DRIVER}" --binary "$<TARGET_FILE:test-workchain-batch-scan>" --build "${CMAKE_BINARY_DIR}"
  ${workchain_scan_arguments})
set_tests_properties(test-workchain-batch-scan-gates PROPERTIES TIMEOUT 60
  RESOURCE_LOCK workchain_i13_measurements LABELS "private;workchain;i13")
