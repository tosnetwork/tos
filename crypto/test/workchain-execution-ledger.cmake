# Explicit private mechanism check; no root build or activation change.
if(NOT WORKCHAIN_LEDGER_SOURCE)
  set(WORKCHAIN_LEDGER_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/test-workchain-execution-ledger.cpp")
endif()
if(NOT WORKCHAIN_LEDGER_HEADER_DIR)
  set(WORKCHAIN_LEDGER_HEADER_DIR "${CMAKE_CURRENT_SOURCE_DIR}/crypto")
endif()
if(NOT WORKCHAIN_LEDGER_DRIVER)
  set(WORKCHAIN_LEDGER_DRIVER "${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/workchain-execution-ledger.py")
endif()
add_executable(test-workchain-execution-ledger "${WORKCHAIN_LEDGER_SOURCE}")
target_include_directories(test-workchain-execution-ledger BEFORE PRIVATE "${WORKCHAIN_LEDGER_HEADER_DIR}")
target_include_directories(test-workchain-execution-ledger PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/crypto")
target_link_libraries(test-workchain-execution-ledger PRIVATE tdactor tdutils)
set_target_properties(test-workchain-execution-ledger PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_test(NAME test-workchain-execution-ledger-gates COMMAND "${Python3_EXECUTABLE}"
  "${WORKCHAIN_LEDGER_DRIVER}"
  --binary "$<TARGET_FILE:test-workchain-execution-ledger>" --build "${CMAKE_BINARY_DIR}")
set_tests_properties(test-workchain-execution-ledger-gates PROPERTIES TIMEOUT 60
  RESOURCE_LOCK workchain_i13_measurements LABELS "private;workchain;i13")
