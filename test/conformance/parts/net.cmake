# net harness (docs/net.md): the network wire layer through the node's own ADNL, key, overlay, RLDP2 and FEC
# code. The reference library already reaches most of these through the validator; they are named here so
# the harness does not depend on that.
target_link_libraries(conformance-ref PRIVATE adnl keys overlay rldp2 fec tdfec)
target_include_directories(conformance-ref PRIVATE ${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/tdfec)

# Consistency of the net fixtures with the data they were built from and with each other (known answers,
# both ends of a channel, encode and decode, the node's RLDP2 sender and the datagrams the generator built).
# Frozen effects are compared by the conformance-vectors test like every other family.
add_test(NAME conformance-net-crosscheck
  COMMAND ${Python3_EXECUTABLE} -B ${CONFORMANCE_DIR}/migrate/net_contexts.py check ${CONFORMANCE_DIR}/vectors/net)
set_tests_properties(conformance-net-crosscheck PROPERTIES LABELS "conformance" TIMEOUT 600)

# Out-of-bound contexts (a zero FEC symbol size) are refused, and the process keeps answering.
add_test(NAME conformance-net-bounds
  COMMAND ${Python3_EXECUTABLE} -B ${CONFORMANCE_DIR}/migrate/net_bounds.py $<TARGET_FILE:conformance-ref-cli>)
set_tests_properties(conformance-net-bounds PROPERTIES LABELS "conformance" TIMEOUT 300)
