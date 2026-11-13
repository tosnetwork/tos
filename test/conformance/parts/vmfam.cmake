# The migrated VM families (docs/vmfam.md): the frozen fixtures must keep equal the original C++
# drivers' output on the scenarios this tree generates, the authored assertions must hold on the
# frozen effects, and a tampered fixture of each batch must fail the runner.
# These families live in the external vectors repository (CONFORMANCE_VECTORS_DIR).
if (NOT CONFORMANCE_VECTORS_DIR)
  return()
endif()
set(VMFAM_FIXTURES ${CONFORMANCE_VECTORS_DIR}/vm/fixtures)
if (TARGET test-vm-endstate AND TARGET test-pq-suite-parity AND TARGET test-vm-opcode-table)
  add_test(NAME conformance-vmfam-crosscheck
    COMMAND ${Python3_EXECUTABLE} -B ${CONFORMANCE_DIR}/migrate/vmfam.py crosscheck
      ${CMAKE_BINARY_DIR} ${VMFAM_FIXTURES} ${CMAKE_CURRENT_BINARY_DIR}/vmfam-crosscheck)
  set_tests_properties(conformance-vmfam-crosscheck PROPERTIES LABELS "conformance" FIXTURES_REQUIRED conformance-vectors-checkout TIMEOUT 1800)
endif()
add_test(NAME conformance-vmfam-authored
  COMMAND ${Python3_EXECUTABLE} -B ${CONFORMANCE_DIR}/migrate/vmfam.py authored
    ${VMFAM_FIXTURES} ${CMAKE_CURRENT_BINARY_DIR}/vmfam-authored
    --seed-dir ${CONFORMANCE_DIR}/vectors/vm/fixtures)
set_tests_properties(conformance-vmfam-authored PROPERTIES LABELS "conformance" FIXTURES_REQUIRED conformance-vectors-checkout TIMEOUT 300)
add_test(NAME conformance-vmfam-tamper
  COMMAND ${Python3_EXECUTABLE} -B ${CONFORMANCE_DIR}/migrate/vmfam.py tamper-control
    $<TARGET_FILE:conformance-ref-cli> ${VMFAM_FIXTURES} ${CMAKE_CURRENT_BINARY_DIR}/vmfam-tamper
    vm-prefix pq-v16-parity rtos-opcode-gates)
set_tests_properties(conformance-vmfam-tamper PROPERTIES LABELS "conformance" FIXTURES_REQUIRED conformance-vectors-checkout TIMEOUT 900)
