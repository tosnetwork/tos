# Coverage-guided fuzz targets (the compiler's fuzzing runtime), built only with -DTOS_BUILD_FUZZERS=ON, which
# instruments the whole tree for coverage. Configure them together with the sanitizers:
#
#   cmake -S . -B build-fuzz -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
#     -DCMAKE_C_COMPILER=clang-21 -DCMAKE_CXX_COMPILER=clang++-21 \
#     -DTOS_BUILD_FUZZERS=ON -DTOS_USE_ASAN=ON -DTOS_USE_UBSAN=ON
#   cmake --build build-fuzz --target fuzzers
#
# Each target's source states what it covers, its input layout, the invariants it checks
# and its one-line run command. Seed corpora live in corpus/<target>; fuzz-seed-corpus
# writes them from committed fixtures.

add_custom_target(fuzzers)

function(tos_fuzzer NAME)
  add_executable(${NAME} ${NAME}.cpp)
  set_target_properties(${NAME} PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/fuzz")
  target_include_directories(${NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/crypto)
  target_link_options(${NAME} PRIVATE -fsanitize=fuzzer)
  target_link_libraries(${NAME} PRIVATE ${ARGN})
  add_dependencies(fuzzers ${NAME})
endfunction()

tos_fuzzer(fuzz-boc tos_crypto tdutils)
tos_fuzzer(fuzz-ext-message tos_external_message_parser tos_block tos_crypto tdutils)
tos_fuzzer(fuzz-state-import tos_crypto tdutils)
tos_fuzzer(fuzz-finality-signatures tos_block tos_crypto tos_mldsa44 tos_pq_consensus_signer tos_pq_consensus
  tl_api tl_lite_api tl-utils)
tos_fuzzer(fuzz-simplex-certificate validator tos_validator tos_block adnl overlay dht tl_api tl-utils tos_crypto
  tos_pq_consensus_signer tos_pq_consensus tos_mldsa44 tdactor tdutils)
tos_fuzzer(fuzz-fec fec tdfec tl_api tdutils)
tos_fuzzer(fuzz-rldp2 rldp2 adnl fec tdfec tdutils)
tos_fuzzer(fuzz-slhdsa-verify tos_slhdsa128s tdutils)

# Not a fuzzer: writes the committed seed corpora from committed fixtures.
add_executable(fuzz-seed-corpus fuzz-seed-corpus.cpp)
set_target_properties(fuzz-seed-corpus PROPERTIES
  CXX_STANDARD 20
  CXX_STANDARD_REQUIRED ON
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/fuzz")
target_include_directories(fuzz-seed-corpus PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}
  ${PROJECT_SOURCE_DIR}/crypto)
target_link_libraries(fuzz-seed-corpus PRIVATE validator tos_validator tos_block adnl overlay dht rldp2 fec tdfec
  tl_api tl_lite_api tl-utils tos_crypto tos_pq_consensus_signer tos_pq_consensus tos_mldsa44 tos_wallet_pq_signer
  tdactor tdutils)
add_dependencies(fuzzers fuzz-seed-corpus)
