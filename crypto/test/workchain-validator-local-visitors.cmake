# Explicit opt-in local-expression coverage; this does not open an execution gate.
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(_validator_visitors "${CMAKE_CURRENT_BINARY_DIR}/validator-local-visitors")
add_custom_command(
  OUTPUT "${_validator_visitors}/validator-custom-visitor.inc"
         "${_validator_visitors}/validator-ready-visitor.inc"
  COMMAND "${Python3_EXECUTABLE}"
          "${PROJECT_SOURCE_DIR}/crypto/test/workchain-validator-local-visitors.py"
          --repo "${PROJECT_SOURCE_DIR}" --out "${_validator_visitors}"
  DEPENDS "${PROJECT_SOURCE_DIR}/validator/impl/validate-query.cpp"
          "${PROJECT_SOURCE_DIR}/crypto/test/workchain-validator-local-visitors.py"
  VERBATIM)
add_executable(test-workchain-validator-local-visitors
  "${PROJECT_SOURCE_DIR}/crypto/test/test-workchain-validator-local-visitors.cpp"
  "${_validator_visitors}/validator-custom-visitor.inc"
  "${_validator_visitors}/validator-ready-visitor.inc")
target_include_directories(test-workchain-validator-local-visitors PRIVATE "${_validator_visitors}")
target_link_libraries(test-workchain-validator-local-visitors PRIVATE tos_block tos_crypto)
add_test(NAME test-workchain-validator-local-visitors
  COMMAND test-workchain-validator-local-visitors
    "${PROJECT_SOURCE_DIR}/doc/measurements/uno-local-profile/run-3/state/zerostate.boc")
set_tests_properties(test-workchain-validator-local-visitors PROPERTIES TIMEOUT 60 LABELS "private;workchain;local-visitor")
