# Every REL-02 transaction run through the txn harness must reproduce its on-chain transaction and account
# hashes: recorded history has to keep replaying after a C++ change.
if (TARGET test-epoch-replay)
  add_test(NAME conformance-rel02-chain
    COMMAND ${Python3_EXECUTABLE} -B ${CONFORMANCE_DIR}/migrate/rel02.py chain
      $<TARGET_FILE:test-epoch-replay> $<TARGET_FILE:conformance-ref-cli> ${CMAKE_SOURCE_DIR}/test/rel02/corpus)
  set_tests_properties(conformance-rel02-chain PROPERTIES LABELS "conformance" TIMEOUT 1800)
endif()
