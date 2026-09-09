# Explicit inclusion only. This calibrates infrastructure, not live activation.
add_executable(test-workchain-activation-control
  "${PROJECT_SOURCE_DIR}/crypto/test/test-workchain-activation-control.cpp")
target_link_libraries(test-workchain-activation-control PRIVATE "-Wl,--start-group" tos_crypto tos_block tos_crypto_core "-Wl,--end-group")
if(NOT WORKCHAIN_ACTIVATION_HELPER)
  set(WORKCHAIN_ACTIVATION_HELPER "${PROJECT_SOURCE_DIR}/crypto/test/workchain-activation-rejection.py")
endif()
find_package(Python3 REQUIRED COMPONENTS Interpreter)
foreach(mode missing-capability old-version)
  add_test(NAME test-workchain-genesis-activation-${mode} COMMAND ${Python3_EXECUTABLE}
    "${PROJECT_SOURCE_DIR}/crypto/test/workchain-genesis-activation.py"
    --repo "${PROJECT_SOURCE_DIR}" --probe $<TARGET_FILE:test-workchain-activation-control> --mode ${mode})
  set_tests_properties(test-workchain-genesis-activation-${mode} PROPERTIES
    TIMEOUT 60 LABELS "private;workchain;genesis")
endforeach()
add_test(NAME test-workchain-activation-control-gates COMMAND ${Python3_EXECUTABLE}
  "${PROJECT_SOURCE_DIR}/crypto/test/workchain-activation-control-check.py"
  --probe "$<TARGET_FILE:test-workchain-activation-control>" --repo "${PROJECT_SOURCE_DIR}"
  --shared-helper "${WORKCHAIN_ACTIVATION_HELPER}")
set_tests_properties(test-workchain-activation-control-gates PROPERTIES
  TIMEOUT 120 RESOURCE_LOCK workchain_i13_measurements LABELS "private;workchain;i13")
