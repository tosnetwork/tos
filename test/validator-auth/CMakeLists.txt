# The conformance test for the live Simplex entrypoints lives with the code it exercises,
# in test/validator/consensus/test-certificate-conformance.cpp. It could not stay here:
# it was written against Ed25519 validator descriptors and a PeerValidator that carried a
# classical verify key, and consensus now signs and verifies with ML-DSA-44 only.
#
# What remains in this directory is the isolated candidate-authentication experiment, which
# never depended on the consensus types and is still a separate translation unit from any
# production path.

# The signer is a separate test library. Production verification remains verify-only.
set(MLDSA_TEST_SOURCE "${PROJECT_SOURCE_DIR}/third-party/mldsa-native/mldsa")
add_library(validator-auth-test-signer STATIC "${MLDSA_TEST_SOURCE}/mldsa_native.c")
target_include_directories(validator-auth-test-signer PRIVATE "${MLDSA_TEST_SOURCE}" "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_definitions(validator-auth-test-signer PRIVATE MLD_CONFIG_FILE="signer-config.h")
set_target_properties(validator-auth-test-signer PROPERTIES C_STANDARD 90 C_STANDARD_REQUIRED ON)
add_executable(test-validator-auth-experimental test-experimental.cpp)
target_include_directories(test-validator-auth-experimental PRIVATE "${PROJECT_SOURCE_DIR}" "${MLDSA_TEST_SOURCE}" "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_definitions(test-validator-auth-experimental PRIVATE MLD_CONFIG_FILE="signer-config.h")
target_link_libraries(test-validator-auth-experimental PRIVATE validator-auth-test-signer tos_mldsa44 tos_crypto tdutils)
add_test(NAME validator-auth-experimental COMMAND test-validator-auth-experimental)
