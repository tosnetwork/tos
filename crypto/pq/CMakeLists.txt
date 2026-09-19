# The same verifier can be tested without building the node.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  cmake_minimum_required(VERSION 3.16)
  project(tos_pq_verifier LANGUAGES C CXX)
  enable_testing()
endif()

# The backend is vendored under third-party/, like every other dependency here,
# so configuring this repository never reaches the network. See its PROVENANCE.md
# for the upstream revision and what was imported.
set(TOS_MLDSA_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../third-party/mldsa-native")
if(NOT EXISTS "${TOS_MLDSA_SOURCE_DIR}/mldsa/mldsa_native.c")
  message(FATAL_ERROR "Vendored ML-DSA backend is missing: ${TOS_MLDSA_SOURCE_DIR}")
endif()

add_library(tos_mldsa_native STATIC "${TOS_MLDSA_SOURCE_DIR}/mldsa/mldsa_native.c")
set_target_properties(tos_mldsa_native PROPERTIES C_STANDARD 90 C_STANDARD_REQUIRED YES
  POSITION_INDEPENDENT_CODE ON)
target_include_directories(tos_mldsa_native PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}"
  "${TOS_MLDSA_SOURCE_DIR}/mldsa")
target_compile_definitions(tos_mldsa_native PRIVATE MLD_CONFIG_FILE="mldsa44-config.h")

add_library(tos_mldsa44 STATIC mldsa44.cpp)
set_target_properties(tos_mldsa44 PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_features(tos_mldsa44 PUBLIC cxx_std_17)
target_include_directories(tos_mldsa44 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}"
  PRIVATE "${TOS_MLDSA_SOURCE_DIR}/mldsa")
target_compile_definitions(tos_mldsa44 PRIVATE MLD_CONFIG_FILE="mldsa44-config.h")
target_link_libraries(tos_mldsa44 PRIVATE tos_mldsa_native)

# PQ-native consensus identity primitives (N1): consensus algorithm id, key/signature
# value types, stable key-id derivation, structural bounds. Verify-only; the signer is
# a separate target.
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
add_library(tos_pq_consensus STATIC pq-consensus.cpp)
set_target_properties(tos_pq_consensus PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_features(tos_pq_consensus PUBLIC cxx_std_20)
target_include_directories(tos_pq_consensus PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(tos_pq_consensus PUBLIC tos_mldsa44 PRIVATE OpenSSL::Crypto)

# Validator CONSENSUS PQ signer: a separate sign-enabled backend (own namespace),
# never linked into the consensus verify path or the ADNL keyring.
add_library(tos_pq_consensus_signer_backend STATIC "${TOS_MLDSA_SOURCE_DIR}/mldsa/mldsa_native.c")
set_target_properties(tos_pq_consensus_signer_backend PROPERTIES C_STANDARD 90 C_STANDARD_REQUIRED YES POSITION_INDEPENDENT_CODE ON)
target_include_directories(tos_pq_consensus_signer_backend PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}" "${TOS_MLDSA_SOURCE_DIR}/mldsa")
target_compile_definitions(tos_pq_consensus_signer_backend PRIVATE MLD_CONFIG_FILE="consensus-signer-config.h")

add_library(tos_pq_consensus_signer STATIC consensus-pq-signer.cpp)
set_target_properties(tos_pq_consensus_signer PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_features(tos_pq_consensus_signer PUBLIC cxx_std_20)
target_include_directories(tos_pq_consensus_signer PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}" PRIVATE "${TOS_MLDSA_SOURCE_DIR}/mldsa")
target_compile_definitions(tos_pq_consensus_signer PRIVATE MLD_CONFIG_FILE="consensus-signer-config.h")
target_link_libraries(tos_pq_consensus_signer PUBLIC tos_pq_consensus PRIVATE tos_pq_consensus_signer_backend OpenSSL::Crypto)

set(PQ_TEST_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-mldsa44")
add_executable(test-pq-mldsa44-wrapper "${PQ_TEST_DIR}/test.cpp")
target_link_libraries(test-pq-mldsa44-wrapper PRIVATE tos_mldsa44)

add_executable(test-pq-consensus "${PQ_TEST_DIR}/pq-consensus-test.cpp")
set_target_properties(test-pq-consensus PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
target_link_libraries(test-pq-consensus PRIVATE tos_pq_consensus)
add_test(NAME pq-consensus COMMAND test-pq-consensus)

add_executable(test-pq-signer "${PQ_TEST_DIR}/pq-signer-test.cpp")
set_target_properties(test-pq-signer PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
target_link_libraries(test-pq-signer PRIVATE tos_pq_consensus_signer tos_pq_consensus tos_mldsa44)
add_test(NAME pq-signer COMMAND test-pq-signer)
if(TARGET tos_crypto)
  target_sources(tos_crypto PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../vm/pqops.cpp")
  target_link_libraries(tos_crypto PRIVATE tos_mldsa44)
  add_executable(test-pq-mldsa44 "${PQ_TEST_DIR}/test.cpp")
  add_executable(test-pq-bytes "${PQ_TEST_DIR}/pq-bytes-test.cpp")
  set_target_properties(test-pq-bytes PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(test-pq-bytes PRIVATE tos_block tos_crypto)
  target_compile_definitions(test-pq-bytes PRIVATE PQ_BYTES_VECTORS="${PQ_TEST_DIR}/pq-bytes-vectors.txt")
  add_test(NAME pq-bytes COMMAND test-pq-bytes)
  add_executable(validator-set-hash-vectors-gen "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/validator-set-hash-vectors-gen.cpp")
  set_target_properties(validator-set-hash-vectors-gen PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(validator-set-hash-vectors-gen PRIVATE tos_block tos_crypto keys)
  add_executable(validator-session-vectors-gen "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/validator-session-vectors-gen.cpp")
  set_target_properties(validator-session-vectors-gen PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(validator-session-vectors-gen PRIVATE tos_block tos_crypto keys tl-utils)
  add_executable(validator-set-cases-gen "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/validator-set-cases-gen.cpp")
  set_target_properties(validator-set-cases-gen PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(validator-set-cases-gen PRIVATE tos_block tos_crypto keys)
  add_executable(test-config43 "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/config43-test.cpp")
  set_target_properties(test-config43 PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(test-config43 PRIVATE tos_block tos_crypto)
  target_compile_definitions(test-config43 PRIVATE
    CONFIG43_VECTORS_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/config43-vectors.tsv")
  add_test(NAME config43-vectors COMMAND test-config43)
  # Descriptors and the verdicts the node reaches about them.
  add_executable(n3-descriptor-vectors-gen "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/n3-descriptor-vectors-gen.cpp")
  set_target_properties(n3-descriptor-vectors-gen PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(n3-descriptor-vectors-gen PRIVATE tos_block tos_crypto keys)
  # The bytes each post-quantum authorisation signs.
  add_executable(n3-preimage-vectors-gen "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/n3-preimage-vectors-gen.cpp")
  set_target_properties(n3-preimage-vectors-gen PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(n3-preimage-vectors-gen PRIVATE tos_block tos_crypto)
  add_executable(test-n3-preimage "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/n3-preimage-test.cpp")
  set_target_properties(test-n3-preimage PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(test-n3-preimage PRIVATE tos_block tos_crypto)
  target_compile_definitions(test-n3-preimage PRIVATE
    N3_PREIMAGE_VECTORS_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/n3-preimage-vectors.tsv")
  add_test(NAME n3-preimage-vectors COMMAND test-n3-preimage)
  # What a validator controller's post-quantum root signs.
  add_executable(n3-controller-auth-vectors-gen
    "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/n3-controller-auth-vectors-gen.cpp")
  set_target_properties(n3-controller-auth-vectors-gen PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(n3-controller-auth-vectors-gen PRIVATE tos_block tos_crypto)
  add_executable(test-n3-controller-auth
    "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/n3-controller-auth-test.cpp")
  set_target_properties(test-n3-controller-auth PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(test-n3-controller-auth PRIVATE tos_block tos_crypto tos_mldsa44)
  target_compile_definitions(test-n3-controller-auth PRIVATE
    N3_CONTROLLER_AUTH_VECTORS_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/n3-controller-auth-vectors.tsv")
  add_test(NAME n3-controller-auth-vectors COMMAND test-n3-controller-auth)
  # Configuration parameter 43 encodings both implementations must read identically.
  add_executable(config43-vectors-gen "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/config43-vectors-gen.cpp")
  set_target_properties(config43-vectors-gen PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(config43-vectors-gen PRIVATE tos_block tos_crypto)
  # What a post-quantum validator set and elector cost in masterchain account state,
  # measured before contract storage is designed around a shape that may not fit.
  add_executable(n3-state-measure "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/n3-state-measure.cpp")
  set_target_properties(n3-state-measure PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(n3-state-measure PRIVATE tos_block tos_crypto keys)
  add_executable(test-validator-identity "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/validator-identity-test.cpp")
  set_target_properties(test-validator-identity PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(test-validator-identity PRIVATE tos_block tos_crypto keys tl-utils)
  target_compile_definitions(test-validator-identity PRIVATE
    SET_HASH_VECTORS_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/validator-set-hash-vectors.txt"
    SET_CASES_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/validator-set-cases.txt"
    FROZEN_CONSTANTS_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/frozen-constants.tsv")
  add_test(NAME validator-identity COMMAND test-validator-identity)
  add_executable(validator-descr-vectors-gen "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/validator-descr-vectors-gen.cpp")
  set_target_properties(validator-descr-vectors-gen PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(validator-descr-vectors-gen PRIVATE tos_block tos_crypto)
  add_executable(test-validator-descr-tags "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/validator-descr-tags-test.cpp")
  set_target_properties(test-validator-descr-tags PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(test-validator-descr-tags PRIVATE tos_block tos_crypto)
  target_compile_definitions(test-validator-descr-tags PRIVATE
    DESCR_TAGS_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/validator-descr-tags.tsv")
  add_test(NAME validator-descr-tags COMMAND test-validator-descr-tags)
  add_executable(pq-bytes-vectors-gen "${PQ_TEST_DIR}/pq-bytes-vectors-gen.cpp")
  set_target_properties(pq-bytes-vectors-gen PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(pq-bytes-vectors-gen PRIVATE tos_block tos_crypto)
  target_compile_definitions(test-pq-mldsa44 PRIVATE TOS_PQ_TEST_VM=1)
  target_link_libraries(test-pq-mldsa44 PRIVATE tos_crypto tos_mldsa44)
  add_executable(test-pq-v16-parity "${PQ_TEST_DIR}/../pq-readiness/parity.cpp")
  target_link_libraries(test-pq-v16-parity PRIVATE tos_crypto)
endif()

install(FILES "${TOS_MLDSA_SOURCE_DIR}/LICENSE"
  DESTINATION share/tos/licenses/mldsa-native)
