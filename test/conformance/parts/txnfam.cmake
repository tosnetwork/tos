# Migrated transaction families: re-run the families that need only the C++ emulator under the
# native-call recorder and require the reference, the family's own records and the frozen fixtures to
# agree (migrate/txnfam_selfcheck.py).
if (TARGET emulator)
  add_test(NAME conformance-txnfam-selfcheck
    COMMAND ${Python3_EXECUTABLE} -B ${CONFORMANCE_DIR}/migrate/txnfam_selfcheck.py
      $<TARGET_FILE:emulator> $<TARGET_FILE:conformance-ref-cli> ${CONFORMANCE_DIR}/vectors)
  set_tests_properties(conformance-txnfam-selfcheck PROPERTIES LABELS "conformance" TIMEOUT 1800)
endif()
