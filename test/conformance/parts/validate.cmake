# validate harness (docs/validate.md): the node's ValidateQuery, run offline in the reference library on
# a test-only validator manager (ref/validate-offline.cpp). The factory that starts it also references
# the apply and download queries, whose implementations are in validator-common.
target_link_libraries(conformance-ref PRIVATE tos_validator validator-common validator-db)
target_include_directories(conformance-ref PRIVATE ${CMAKE_SOURCE_DIR})

# Contexts from archived history: blocks applied from the zero states, each target validated with
# usage-tracked states and kept with Merkle proofs of the states it read (migrate/validate-export.cpp).
add_executable(conformance-validate-export ${CONFORMANCE_DIR}/migrate/validate-export.cpp
  ${CONFORMANCE_REF_DIR}/validate-offline.cpp)
target_include_directories(conformance-validate-export PRIVATE ${CMAKE_SOURCE_DIR} ${CONFORMANCE_REF_DIR})
target_link_libraries(conformance-validate-export PRIVATE tos_validator validator-common validator-db tos_block
  tos_crypto)

# A bounded slice of real history from the epoch-6 genesis: every block of masterchain 1..N and the
# shard blocks referencing them, validated by the reference, all accepted (the chain is the oracle).
# Reads archives present only on hosts that retain them; skips visibly without them.
add_test(NAME conformance-validate-epoch6-slice
  COMMAND ${Python3_EXECUTABLE} -B ${CONFORMANCE_DIR}/migrate/validate_families.py slice
    $<TARGET_FILE:conformance-validate-export> $<TARGET_FILE:conformance-ref-cli>
    ${CMAKE_CURRENT_BINARY_DIR}/conformance-validate/epoch6-slice
    --packs ${CONFORMANCE_ARCHIVE_EPOCH6}=${CONFORMANCE_ARCHIVE_INPUTS}/epoch-6/archive-packs.SHA256SUMS
    --zerostate ${CONFORMANCE_ARCHIVE_INPUTS}/epoch-6/zerostate.boc
    --basestate ${CONFORMANCE_ARCHIVE_INPUTS}/epoch-6/basestate0.boc
    --mc-limit ${CONFORMANCE_ARCHIVE_SLICE})
set_tests_properties(conformance-validate-epoch6-slice PROPERTIES
  LABELS "history-replay" TIMEOUT 1800 SKIP_RETURN_CODE 77)
