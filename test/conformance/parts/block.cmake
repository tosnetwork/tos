# block and get_method harness contexts from the REL-02 corpus, and the block chain cross-check: every
# corpus block applied by the block harness must reproduce its on-chain state, transaction and account
# hashes.
add_executable(conformance-block-export ${CONFORMANCE_DIR}/migrate/block-export.cpp)
target_include_directories(conformance-block-export PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(conformance-block-export PRIVATE emulator_static fift-lib)

add_test(NAME conformance-block-chain
  COMMAND ${Python3_EXECUTABLE} -B ${CONFORMANCE_DIR}/migrate/block_chain.py chain
    $<TARGET_FILE:conformance-block-export> $<TARGET_FILE:conformance-ref-cli> ${CMAKE_SOURCE_DIR}/test/rel02/corpus)
set_tests_properties(conformance-block-chain PROPERTIES LABELS "conformance" TIMEOUT 1800)
