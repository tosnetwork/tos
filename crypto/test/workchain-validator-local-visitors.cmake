# Explicit opt-in prepared decisions, never a production gate change.
find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_executable(test-workchain-validator-local-visitors
  "${PROJECT_SOURCE_DIR}/crypto/test/test-workchain-validator-local-visitors.cpp")
target_link_libraries(test-workchain-validator-local-visitors PRIVATE tos_block tos_crypto)
add_test(NAME test-workchain-validator-local-visitors
  COMMAND "${Python3_EXECUTABLE}"
    "${PROJECT_SOURCE_DIR}/crypto/test/workchain-validator-prepared-expiry.py"
    --repo "${PROJECT_SOURCE_DIR}"
    --probe $<TARGET_FILE:test-workchain-validator-local-visitors>
    --fixture "${PROJECT_SOURCE_DIR}/doc/measurements/uno-local-profile/run-3/state/zerostate.boc")
set_tests_properties(test-workchain-validator-local-visitors PROPERTIES
  TIMEOUT 60 LABELS "private;workchain;prepared-not-connected")
