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

# PQ-native consensus identity primitives: consensus algorithm id, key/signature
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

add_library(tos_pq_consensus_signer STATIC consensus-pq-signer.cpp consensus-key-file.cpp)
set_target_properties(tos_pq_consensus_signer PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_features(tos_pq_consensus_signer PUBLIC cxx_std_20)
target_include_directories(tos_pq_consensus_signer PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}" PRIVATE "${TOS_MLDSA_SOURCE_DIR}/mldsa")
target_compile_definitions(tos_pq_consensus_signer PRIVATE MLD_CONFIG_FILE="consensus-signer-config.h")
target_link_libraries(tos_pq_consensus_signer PUBLIC tos_pq_consensus PRIVATE tos_pq_consensus_signer_backend OpenSSL::Crypto)

# The offline controller-root domain. A separate library on purpose: the boundary the offline-root split
# created is between two machines, so it is a link boundary here. validator-engine links
# tos_pq_consensus_signer and must never link this, which
# scripts/check-root-authority-off-the-node.sh enforces.
add_library(tos_pq_controller_root STATIC controller-root-signer.cpp controller-root-file.cpp)
set_target_properties(tos_pq_controller_root PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_features(tos_pq_controller_root PUBLIC cxx_std_20)
target_include_directories(tos_pq_controller_root PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}" PRIVATE "${TOS_MLDSA_SOURCE_DIR}/mldsa")
target_compile_definitions(tos_pq_controller_root PRIVATE MLD_CONFIG_FILE="consensus-signer-config.h")
target_link_libraries(tos_pq_controller_root PUBLIC tos_pq_consensus PRIVATE tos_pq_consensus_signer_backend OpenSSL::Crypto)

# Provisioning for the node's consensus key. It links the same library the node loads
# the key with, so the two cannot disagree about what a valid key file is.
add_executable(tos-pq-consensus-key "${CMAKE_CURRENT_SOURCE_DIR}/consensus-key-tool.cpp")
set_target_properties(tos-pq-consensus-key PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
target_link_libraries(tos-pq-consensus-key PRIVATE tos_pq_consensus_signer tos_pq_consensus)
add_test(NAME consensus-key-tool
         COMMAND "${CMAKE_COMMAND}" -E env python3
                 "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-mldsa44/consensus_key_tool_test.py"
                 --tool "$<TARGET_FILE:tos-pq-consensus-key>")

set(PQ_TEST_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-mldsa44")
add_executable(test-pq-mldsa44-wrapper "${PQ_TEST_DIR}/test.cpp")
target_link_libraries(test-pq-mldsa44-wrapper PRIVATE tos_mldsa44)

add_executable(test-pq-consensus "${PQ_TEST_DIR}/pq-consensus-test.cpp")
set_target_properties(test-pq-consensus PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
target_link_libraries(test-pq-consensus PRIVATE tos_pq_consensus)
add_test(NAME pq-consensus COMMAND test-pq-consensus)

add_executable(test-consensus-key-file "${PQ_TEST_DIR}/consensus-key-file-test.cpp")
set_target_properties(test-consensus-key-file PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
target_link_libraries(test-consensus-key-file PRIVATE tos_pq_consensus_signer tos_pq_consensus)
add_test(NAME consensus-key-file COMMAND test-consensus-key-file)

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
  add_executable(test-pq-vote-body "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/vote-body-test.cpp")
  set_target_properties(test-pq-vote-body PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(test-pq-vote-body PRIVATE tos_block tos_crypto)
  add_test(NAME pq-vote-body COMMAND test-pq-vote-body)
  add_executable(validator-set-hash-vectors-gen "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/validator-set-hash-vectors-gen.cpp")
  set_target_properties(validator-set-hash-vectors-gen PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(validator-set-hash-vectors-gen PRIVATE tos_block tos_crypto keys)
  add_executable(validator-session-vectors-gen "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/validator-session-vectors-gen.cpp")
  set_target_properties(validator-session-vectors-gen PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(validator-session-vectors-gen PRIVATE tos_block tos_crypto keys tl-utils)
  add_executable(validator-session-derivation-vectors-gen
    "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/validator-session-derivation-vectors-gen.cpp")
  set_target_properties(validator-session-derivation-vectors-gen PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_include_directories(validator-session-derivation-vectors-gen PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../../common")
  target_link_libraries(validator-session-derivation-vectors-gen PRIVATE validator tos_block tos_crypto tl-utils)
  target_compile_definitions(validator-session-derivation-vectors-gen PRIVATE
    SHARD_STATE_BOC_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../tosctl/src/block/src/tests/data/shard_state.boc")
  add_test(NAME validator-session-derivation
    COMMAND validator-session-derivation-vectors-gen
            "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/validator-session-derivation-vectors.tsv")
  foreach(check_name param30 global-id local-override governing-snapshot session-path constructor-selection
                     manager-assembly state-global-id)
    add_test(NAME validator-session-${check_name}
      COMMAND validator-session-derivation-vectors-gen
              "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/validator-session-derivation-vectors.tsv"
              ${check_name})
  endforeach()
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
  add_executable(descriptor-verdict-vectors-gen "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/descriptor-verdict-vectors-gen.cpp")
  set_target_properties(descriptor-verdict-vectors-gen PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(descriptor-verdict-vectors-gen PRIVATE tos_block tos_crypto keys)
  # The bytes each post-quantum authorisation signs.
  add_executable(authorisation-preimage-vectors-gen "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/authorisation-preimage-vectors-gen.cpp")
  set_target_properties(authorisation-preimage-vectors-gen PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(authorisation-preimage-vectors-gen PRIVATE tos_block tos_crypto)
  add_executable(vote-carrier-vectors-gen "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/vote-carrier-vectors-gen.cpp")
  set_target_properties(vote-carrier-vectors-gen PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(vote-carrier-vectors-gen PRIVATE tos_block tos_crypto)
  add_executable(test-authorisation-preimage "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/authorisation-preimage-test.cpp")
  set_target_properties(test-authorisation-preimage PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(test-authorisation-preimage PRIVATE tos_block tos_crypto)
  target_compile_definitions(test-authorisation-preimage PRIVATE
    AUTHORISATION_PREIMAGE_VECTORS_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/authorisation-preimage-vectors.tsv")
  add_test(NAME authorisation-preimage-vectors COMMAND test-authorisation-preimage)
  add_executable(test-vote-carrier "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/vote-carrier-test.cpp")
  set_target_properties(test-vote-carrier PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(test-vote-carrier PRIVATE tos_block tos_crypto)
  target_compile_definitions(test-vote-carrier PRIVATE
    VOTE_CARRIER_VECTORS_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/vote-carrier-vectors.tsv"
    VOTE_CARRIER_TOOLING_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/vote-carrier-vectors-tooling.tsv")
  add_test(NAME vote-carrier-vectors COMMAND test-vote-carrier)
  # What a validator controller's post-quantum root signs.
  add_executable(controller-auth-vectors-gen
    "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/controller-auth-vectors-gen.cpp")
  set_target_properties(controller-auth-vectors-gen PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(controller-auth-vectors-gen PRIVATE tos_block tos_crypto)
  add_executable(test-controller-auth
    "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/controller-auth-test.cpp")
  set_target_properties(test-controller-auth PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(test-controller-auth PRIVATE tos_block tos_crypto tos_mldsa44)
  target_compile_definitions(test-controller-auth PRIVATE
    CONTROLLER_AUTH_VECTORS_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/controller-auth-vectors.tsv")
  add_test(NAME controller-auth-vectors COMMAND test-controller-auth)
  # The one routine the node and the operator tool both call to sign a stake.
  add_executable(test-stake-authorisation "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/stake-authorisation-test.cpp")
  set_target_properties(test-stake-authorisation PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(test-stake-authorisation PRIVATE tos_block tos_crypto tos_mldsa44
    tos_pq_consensus_signer tos_pq_consensus)
  add_test(NAME stake-authorisation COMMAND test-stake-authorisation)
  # What a post-quantum Simplex vote and certificate cost on the wire and the CPU,
  # measured on the real signer and the real consensus TL before consensus is converted.
  add_executable(simplex-carrier-measure "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/simplex-carrier-measure.cpp")
  set_target_properties(simplex-carrier-measure PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(simplex-carrier-measure PRIVATE tos_block tos_crypto tos_mldsa44
    tos_pq_consensus_signer tos_pq_consensus tl_api tl-utils)
  # The frozen Simplex carrier hard bound and its max/max+1 gate.
  add_executable(test-simplex-carrier-bound "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/simplex-carrier-bound-test.cpp")
  set_target_properties(test-simplex-carrier-bound PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(test-simplex-carrier-bound PRIVATE tos_block tos_crypto tos_mldsa44 tl_api tl-utils)
  add_test(NAME simplex-carrier-bound COMMAND test-simplex-carrier-bound)
  # Exact cell/BOC and network-TL costs of the persisted post-quantum finality carrier.
  add_executable(block-signature-carrier-measure
    "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/block-signature-carrier-measure.cpp")
  set_target_properties(block-signature-carrier-measure PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(block-signature-carrier-measure PRIVATE tos_block tos_crypto tos_mldsa44
    tos_pq_consensus_signer tos_pq_consensus tl_api tl_lite_api tl-utils tl-lite-utils)
  target_include_directories(block-signature-carrier-measure PRIVATE "${TOS_MLDSA_SOURCE_DIR}/mldsa")
  target_compile_definitions(block-signature-carrier-measure PRIVATE MLD_CONFIG_FILE="consensus-signer-config.h")
  target_compile_definitions(block-signature-carrier-measure PRIVATE
    MEASUREMENTS_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/block-signature-carrier-measurements.tsv"
    TOS_API_SCHEMA_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../tl/generate/scheme/tos_api.tl"
    LITE_API_SCHEMA_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../tl/generate/scheme/lite_api.tl")
  add_test(NAME block-signature-carrier-measure COMMAND block-signature-carrier-measure)
  add_executable(test-block-signature-carrier-bound
    "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/block-signature-carrier-bound-test.cpp")
  set_target_properties(test-block-signature-carrier-bound PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(test-block-signature-carrier-bound PRIVATE tos_block tos_crypto tos_mldsa44
    tos_pq_consensus_signer tos_pq_consensus tl_api tl-utils)
  target_include_directories(test-block-signature-carrier-bound PRIVATE "${TOS_MLDSA_SOURCE_DIR}/mldsa")
  target_compile_definitions(test-block-signature-carrier-bound PRIVATE MLD_CONFIG_FILE="consensus-signer-config.h")
  add_test(NAME block-signature-carrier-bound COMMAND test-block-signature-carrier-bound)
  # Production admission limits for every route that will carry the persisted signature object.
  add_executable(test-block-signature-carrier-routes
    "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/block-signature-carrier-routes-test.cpp")
  set_target_properties(test-block-signature-carrier-routes PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(test-block-signature-carrier-routes PRIVATE tl_api tl-utils)
  target_compile_definitions(test-block-signature-carrier-routes PRIVATE
    ROUTES_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/block-signature-carrier-routes.tsv"
    MEASUREMENTS_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/block-signature-carrier-measurements.tsv"
    SOURCE_ROOT="${CMAKE_CURRENT_SOURCE_DIR}/../..")
  add_test(NAME block-signature-carrier-routes COMMAND test-block-signature-carrier-routes)
  # Design section 6.5's node and lite capacity gates.  The code names describe
  # their subjects and intentionally do not carry execution-plan stage labels.
  add_executable(test-pq-carrier-capacity
    "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/pq-carrier-capacity-test.cpp")
  set_target_properties(test-pq-carrier-capacity PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(test-pq-carrier-capacity PRIVATE tos_block tos_crypto tos_mldsa44
    tos_pq_consensus_signer tos_pq_consensus tl_api tl_lite_api tl-utils tl-lite-utils overlay adnl)
  target_include_directories(test-pq-carrier-capacity PRIVATE "${TOS_MLDSA_SOURCE_DIR}/mldsa")
  target_compile_definitions(test-pq-carrier-capacity PRIVATE MLD_CONFIG_FILE="consensus-signer-config.h"
    ROUTES_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/block-signature-carrier-routes.tsv"
    MEASUREMENTS_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/block-signature-carrier-measurements.tsv")
  add_test(NAME pq-node-finality-carrier-capacity COMMAND test-pq-carrier-capacity node)
  add_test(NAME pq-lite-forward-proof-carrier-capacity COMMAND test-pq-carrier-capacity lite)
  add_executable(test-pq-broadcast-semantics
    "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/pq-broadcast-semantics-test.cpp")
  set_target_properties(test-pq-broadcast-semantics PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(test-pq-broadcast-semantics PRIVATE full-node tos_validator tos_block tos_crypto tos_mldsa44
    tos_pq_consensus_signer tos_pq_consensus tl_api tl-utils overlay)
  target_include_directories(test-pq-broadcast-semantics PRIVATE "${TOS_MLDSA_SOURCE_DIR}/mldsa"
    "${CMAKE_CURRENT_SOURCE_DIR}/../.." "${CMAKE_CURRENT_SOURCE_DIR}/../../common")
  target_compile_definitions(test-pq-broadcast-semantics PRIVATE MLD_CONFIG_FILE="consensus-signer-config.h"
    ROUTES_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/block-signature-carrier-routes.tsv")
  add_test(NAME pq-broadcast-semantic-roundtrip COMMAND test-pq-broadcast-semantics)
  add_executable(test-pq-signature-tl-vectors
    "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/pq-signature-tl-vectors-test.cpp")
  set_target_properties(test-pq-signature-tl-vectors PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(test-pq-signature-tl-vectors PRIVATE tos_block tos_crypto tos_mldsa44
    tos_pq_consensus_signer tos_pq_consensus tl_api tl_lite_api tl-utils tl-lite-utils)
  target_include_directories(test-pq-signature-tl-vectors PRIVATE "${TOS_MLDSA_SOURCE_DIR}/mldsa")
  target_compile_definitions(test-pq-signature-tl-vectors PRIVATE MLD_CONFIG_FILE="consensus-signer-config.h"
    VECTORS_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/pq-signature-tl-vectors.txt")
  add_test(NAME pq-signature-tl-vectors COMMAND test-pq-signature-tl-vectors)
  add_executable(test-pq-block-signature-vectors
    "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/pq-block-signature-vectors-test.cpp")
  set_target_properties(test-pq-block-signature-vectors PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(test-pq-block-signature-vectors PRIVATE tos_block tos_crypto tos_mldsa44
    tos_pq_consensus_signer tos_pq_consensus tl_api tl_lite_api tl-utils)
  target_include_directories(test-pq-block-signature-vectors PRIVATE "${TOS_MLDSA_SOURCE_DIR}/mldsa")
  target_compile_definitions(test-pq-block-signature-vectors PRIVATE MLD_CONFIG_FILE="consensus-signer-config.h")
  target_compile_definitions(test-pq-block-signature-vectors PRIVATE
    VECTORS_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/pq-block-signature-vectors.txt")
  add_test(NAME pq-block-signature-vectors COMMAND test-pq-block-signature-vectors)
  add_executable(test-pq-block-signature-conformance
    "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/pq-block-signature-conformance-test.cpp")
  set_target_properties(test-pq-block-signature-conformance PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(test-pq-block-signature-conformance PRIVATE tos_block tos_crypto tos_mldsa44
    tos_pq_consensus_signer tos_pq_consensus tl_api tl_lite_api tl-utils)
  target_include_directories(test-pq-block-signature-conformance PRIVATE "${TOS_MLDSA_SOURCE_DIR}/mldsa")
  target_compile_definitions(test-pq-block-signature-conformance PRIVATE
    MLD_CONFIG_FILE="consensus-signer-config.h")
  add_test(NAME pq-block-signature-conformance COMMAND test-pq-block-signature-conformance)
  add_test(NAME pq-finality-boundary-source
    COMMAND "${CMAKE_COMMAND}" -E env python3
            ${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/check-pq-finality-boundary.py)
  add_executable(test-pq-block-signature-no-legacy
    "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/pq-block-signature-no-legacy-test.cpp")
  set_target_properties(test-pq-block-signature-no-legacy PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(test-pq-block-signature-no-legacy PRIVATE tos_block tos_crypto tos_mldsa44
    tos_pq_consensus_signer tos_pq_consensus tl_api tl_lite_api tl-utils)
  target_include_directories(test-pq-block-signature-no-legacy PRIVATE "${TOS_MLDSA_SOURCE_DIR}/mldsa")
  target_compile_definitions(test-pq-block-signature-no-legacy PRIVATE
    MLD_CONFIG_FILE="consensus-signer-config.h")
  add_test(NAME pq-block-signature-no-legacy COMMAND test-pq-block-signature-no-legacy)
  # Configuration parameter 43 encodings both implementations must read identically.
  add_executable(config43-vectors-gen "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/config43-vectors-gen.cpp")
  set_target_properties(config43-vectors-gen PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(config43-vectors-gen PRIVATE tos_block tos_crypto)
  # What a post-quantum validator set and elector cost in masterchain account state,
  # measured before contract storage is designed around a shape that may not fit.
  add_executable(validator-state-measure "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-native/validator-state-measure.cpp")
  set_target_properties(validator-state-measure PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
  target_link_libraries(validator-state-measure PRIVATE tos_block tos_crypto keys)
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
