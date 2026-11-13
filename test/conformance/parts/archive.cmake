# Offline whole-history replay of archived chain history (docs/archive.md). The REL-02 replay uses the
# committed corpus and runs with label conformance. The slice tests read archives that exist only on hosts
# that retain them (set CONFORMANCE_ARCHIVE_EPOCH5/_EPOCH6/_INPUTS), carry label history-replay, and skip
# visibly (ctest "Skipped") without them.
add_executable(conformance-archive-replay ${CONFORMANCE_DIR}/replay/archive-replay.cpp)
target_link_libraries(conformance-archive-replay PRIVATE emulator_static)

set(CONFORMANCE_ARCHIVE_EPOCH5 "" CACHE PATH "epoch-5 archive packages (archive replay slice)")
set(CONFORMANCE_ARCHIVE_EPOCH6 "" CACHE PATH
  "epoch-6 archive packages (archive replay slice)")
set(CONFORMANCE_ARCHIVE_INPUTS "" CACHE PATH
  "zero states and SHA-256 lists of the archived networks (archive replay slice)")
set(CONFORMANCE_ARCHIVE_SLICE 2000 CACHE STRING "masterchain blocks replayed from genesis by the archive slice tests")
set(CONFORMANCE_ARCHIVE_WORK ${CMAKE_CURRENT_BINARY_DIR}/conformance-archive)

# The committed REL-02 corpus, replayed without a starting state: every block's identity and state hashes
# and every transaction must equal the corpus oracle.
add_test(NAME conformance-archive-rel02
  COMMAND ${Python3_EXECUTABLE} -B ${CONFORMANCE_DIR}/migrate/archive.py rel02
    $<TARGET_FILE:conformance-archive-replay> ${CMAKE_SOURCE_DIR}/test/rel02/corpus ${CONFORMANCE_ARCHIVE_WORK}/rel02)
set_tests_properties(conformance-archive-rel02 PROPERTIES LABELS "conformance" TIMEOUT 1800)

# A bounded slice of real history from each genesis: replayed from the zero state, then every exported
# transaction context is run through the txn harness of the reference CLI and checked against the chain.
foreach(epoch 5 6)
  if (epoch EQUAL 5)
    set(packs "${CONFORMANCE_ARCHIVE_EPOCH5}/node-a-genesis-packages=${CONFORMANCE_ARCHIVE_INPUTS}/epoch-5/node-a-genesis-packages.SHA256SUMS")
  else()
    set(packs "${CONFORMANCE_ARCHIVE_EPOCH6}=${CONFORMANCE_ARCHIVE_INPUTS}/epoch-6/archive-packs.SHA256SUMS")
  endif()
  add_test(NAME conformance-archive-epoch${epoch}-slice
    COMMAND ${Python3_EXECUTABLE} -B ${CONFORMANCE_DIR}/migrate/archive.py slice
      $<TARGET_FILE:conformance-archive-replay> $<TARGET_FILE:conformance-ref-cli>
      ${CONFORMANCE_ARCHIVE_WORK}/epoch${epoch}-slice --source epoch-${epoch}-slice --packs ${packs}
      --zerostate ${CONFORMANCE_ARCHIVE_INPUTS}/epoch-${epoch}/zerostate.boc
      --basestate ${CONFORMANCE_ARCHIVE_INPUTS}/epoch-${epoch}/basestate0.boc
      --mc-limit ${CONFORMANCE_ARCHIVE_SLICE})
  set_tests_properties(conformance-archive-epoch${epoch}-slice PROPERTIES
    LABELS "history-replay" TIMEOUT 1800 SKIP_RETURN_CODE 77)
endforeach()
