add_library(td-test-main test-td-main.cpp)
target_link_libraries(td-test-main PRIVATE tdutils)

add_subdirectory(tdactor)
add_subdirectory(tdutils)
add_subdirectory(toslib)
add_subdirectory(validator)

# The model checks the production quorum arithmetic, not cryptographic signatures.
add_executable(test-validator-auth-policy test-validator-auth-policy.cpp)
target_link_libraries(test-validator-auth-policy PRIVATE tos_crypto tdutils)
target_include_directories(test-validator-auth-policy PRIVATE ${PROJECT_SOURCE_DIR})
set_target_properties(test-validator-auth-policy PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
add_test(NAME test-validator-auth-policy COMMAND test-validator-auth-policy
  "${PROJECT_SOURCE_DIR}/test/validator-auth-policy/policy-cases.json")

# Future signature experiments are not linked into production node targets.
option(TOS_BUILD_VALIDATOR_AUTH_TESTS "Build isolated validator signature conformance tests" OFF)
if(TOS_BUILD_VALIDATOR_AUTH_TESTS)
  add_subdirectory(validator-auth)
endif()

option(TOS_BUILD_P0_IMPLEMENTATION_TESTS "Build production P0 integration checks" OFF)
if(TOS_BUILD_P0_IMPLEMENTATION_TESTS)
  add_subdirectory(validator-auth-implementation)
endif()
