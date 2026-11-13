# consensus harness (ref/harness-consensus.cpp): it calls the proof, signature-set and session-identity code
# of the block library directly, and the validator's PQ finality header, so the reference library needs both.
target_link_libraries(conformance-ref PRIVATE tos_block tl_lite_api)
target_include_directories(conformance-ref PRIVATE ${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/crypto)

# Consistency of the consensus fixtures with each other and with the chain they came from (the ops agree on
# the session a block was signed in, and real signatures verify). Frozen effects are compared by the
# conformance-vectors test like every other family.
add_test(NAME conformance-consensus-crosscheck
  COMMAND ${Python3_EXECUTABLE} -B ${CONFORMANCE_DIR}/migrate/consensus_contexts.py check
    --reference $<TARGET_FILE:conformance-ref-cli> ${CONFORMANCE_DIR}/vectors/consensus)
set_tests_properties(conformance-consensus-crosscheck PROPERTIES LABELS "conformance" TIMEOUT 600)

# Network scenarios start validator processes, so they run only on request: label conformance-network,
# and skipped unless CONFORMANCE_NETWORK=1 (ctest -L treats its argument as a regex, so -L conformance
# also selects this test; it then reports it skipped). They need the repository's Python environment
# (tostester), hence uv.
find_program(CONFORMANCE_UV uv)
if (TARGET validator-engine AND CONFORMANCE_UV)
  add_test(NAME conformance-network-scenarios
    COMMAND ${CONFORMANCE_UV} run python ${CONFORMANCE_DIR}/scenarios/run_scenarios.py
      --build-dir ${CMAKE_BINARY_DIR} --source-dir ${CMAKE_SOURCE_DIR}
      --work-dir ${CMAKE_BINARY_DIR}/conformance-network
      --reference $<TARGET_FILE:conformance-ref-cli>
      --node cpp:$<TARGET_FILE:validator-engine> --nodes 4 --only-if-env CONFORMANCE_NETWORK
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
  set_tests_properties(conformance-network-scenarios PROPERTIES LABELS "conformance-network" TIMEOUT 3600 SKIP_RETURN_CODE 77)
endif()
