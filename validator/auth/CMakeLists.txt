add_library(tos_validator_auth STATIC crypto.cpp verify.cpp cells.cpp lifecycle.cpp transfer.cpp object-store.cpp transport.cpp api-semantics.cpp state.cpp context.cpp governance.cpp service-auth.cpp)
target_include_directories(tos_validator_auth PUBLIC "${PROJECT_SOURCE_DIR}" "${SODIUM_INCLUDE_DIR}")
target_link_libraries(tos_validator_auth PUBLIC ${SODIUM_LIBRARY_RELEASE} tos_crypto tos_validator_auth_crypto)
set_target_properties(tos_validator_auth PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
if(TARGET sodium)
  add_dependencies(tos_validator_auth sodium)
endif()

add_library(tos_validator_auth_native STATIC manager-session-binding.cpp native-session-committee.cpp native-evidence.cpp native-config-context.cpp native-header.cpp native-transaction.cpp native-registry.cpp native-history.cpp native-apply.cpp owner-proof.cpp native-proof.cpp native-committee.cpp native-session-id.cpp registry-view.cpp committee-proof.cpp certificate-proof.cpp)
target_link_libraries(tos_validator_auth_native PUBLIC tos_validator_auth tos_block tl-utils keys)
set_target_properties(tos_validator_auth_native PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)

add_library(tos_validator_auth_session STATIC native-session-continuity.cpp)
target_link_libraries(tos_validator_auth_session PUBLIC tos_validator_auth_native tdutils)
set_target_properties(tos_validator_auth_session PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)

if(UNIX)
  add_library(tos_validator_auth_signer STATIC durable-log.cpp witness.cpp safety-ledger.cpp operation-ledger.cpp c0-provider.cpp signer-service.cpp admin-service.cpp api-service.cpp service-issuer.cpp local-channel.cpp provider-channel.cpp)
  target_link_libraries(tos_validator_auth_signer PUBLIC tos_validator_auth)
  set_target_properties(tos_validator_auth_signer PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
endif()

if(UNIX)
  target_sources(tos_validator_auth_signer PRIVATE key-isolation.cpp)
  add_library(tos_validator_auth_rpc STATIC native-rpc.cpp native-node-history.cpp)
  target_link_libraries(tos_validator_auth_rpc PUBLIC tos_validator_auth_native tos_validator_auth_signer)
  set_target_properties(tos_validator_auth_rpc PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
endif()

if(TOS_BUILD_P0_IMPLEMENTATION_TESTS)
  add_executable(test-p0-native-session-id EXCLUDE_FROM_ALL
    "${PROJECT_SOURCE_DIR}/test/validator-auth-implementation/native-session-id-test.cpp")
  target_link_libraries(test-p0-native-session-id PRIVATE tos_validator_auth_native)
  set_target_properties(test-p0-native-session-id PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)

  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/native-session-id.cpp"
                 "${CMAKE_CURRENT_BINARY_DIR}/mutated-native-session-id.cpp" COPYONLY)
  add_executable(test-p0-native-session-id-mutant EXCLUDE_FROM_ALL
    "${PROJECT_SOURCE_DIR}/test/validator-auth-implementation/native-session-id-test.cpp"
    "${CMAKE_CURRENT_BINARY_DIR}/mutated-native-session-id.cpp")
  target_include_directories(test-p0-native-session-id-mutant PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
  target_link_libraries(test-p0-native-session-id-mutant PRIVATE tos_validator_auth tos_block tl-utils keys)
  set_target_properties(test-p0-native-session-id-mutant PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)

  add_executable(test-p0-native-session-history EXCLUDE_FROM_ALL
    "${PROJECT_SOURCE_DIR}/test/validator-auth-implementation/native-session-history-test.cpp")
  target_link_libraries(test-p0-native-session-history PRIVATE tos_validator_auth_native)
  set_target_properties(test-p0-native-session-history PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)

  set(P0_SESSION_HISTORY_MUTANT_ROOT
      "${CMAKE_CURRENT_BINARY_DIR}/session-history-mutant")
  file(MAKE_DIRECTORY "${P0_SESSION_HISTORY_MUTANT_ROOT}/validator/auth")
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/native-session-history.h"
                 "${P0_SESSION_HISTORY_MUTANT_ROOT}/validator/auth/native-session-history.h" COPYONLY)
  add_executable(test-p0-native-session-history-mutant EXCLUDE_FROM_ALL
    "${PROJECT_SOURCE_DIR}/test/validator-auth-implementation/native-session-history-test.cpp")
  target_include_directories(test-p0-native-session-history-mutant BEFORE PRIVATE
    "${P0_SESSION_HISTORY_MUTANT_ROOT}")
  # The copied header includes its siblings by bare name and they are not beside
  # the copy. The mutant root stays first, so validator/auth/... still resolves
  # to the mutated header; this only lets those siblings be found.
  target_include_directories(test-p0-native-session-history-mutant PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}")
  target_link_libraries(test-p0-native-session-history-mutant PRIVATE tos_validator_auth_native)
  set_target_properties(test-p0-native-session-history-mutant PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)

  add_executable(test-p0-native-session-committee EXCLUDE_FROM_ALL
    "${PROJECT_SOURCE_DIR}/test/validator-auth-implementation/session-committee-ownership-test.cpp")
  target_link_libraries(test-p0-native-session-committee PRIVATE tos_validator_auth_native)
  set_target_properties(test-p0-native-session-committee PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)

  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/native-session-committee.cpp"
                 "${CMAKE_CURRENT_BINARY_DIR}/mutated-native-session-committee.cpp" COPYONLY)
  add_executable(test-p0-native-session-committee-mutant EXCLUDE_FROM_ALL
    "${PROJECT_SOURCE_DIR}/test/validator-auth-implementation/session-committee-ownership-test.cpp"
    "${CMAKE_CURRENT_BINARY_DIR}/mutated-native-session-committee.cpp")
  target_include_directories(test-p0-native-session-committee-mutant PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}")
  target_link_libraries(test-p0-native-session-committee-mutant PRIVATE tos_validator_auth_native)
  set_target_properties(test-p0-native-session-committee-mutant PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)

  add_executable(test-p0-native-session-continuity EXCLUDE_FROM_ALL
    "${PROJECT_SOURCE_DIR}/test/validator-auth-implementation/session-continuity-test.cpp")
  target_link_libraries(test-p0-native-session-continuity PRIVATE tos_validator_auth_session)
  set_target_properties(test-p0-native-session-continuity PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)

  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/native-session-continuity.cpp"
                 "${CMAKE_CURRENT_BINARY_DIR}/mutated-native-session-continuity.cpp" COPYONLY)
  add_executable(test-p0-native-session-continuity-mutant EXCLUDE_FROM_ALL
    "${PROJECT_SOURCE_DIR}/test/validator-auth-implementation/session-continuity-test.cpp"
    "${CMAKE_CURRENT_BINARY_DIR}/mutated-native-session-continuity.cpp")
  target_include_directories(test-p0-native-session-continuity-mutant PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}")
  target_link_libraries(test-p0-native-session-continuity-mutant PRIVATE
    tos_validator_auth_native tdutils)
  set_target_properties(test-p0-native-session-continuity-mutant PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
endif()
