# Shared proof verification core and its installed command-line front end.
# The engine accepts borrowed in-memory material and has no transport/file API.
add_library(proof-verify-engine STATIC proof-verify.cpp proof-verify.h embedded.cpp embedded.h)
target_include_directories(proof-verify-engine PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>)
target_link_libraries(proof-verify-engine PUBLIC lite-client-proof-common tos_block smc-envelope tl_api tl_lite_api
  tl-lite-utils tdutils)

# Desktop acquisition/storage adapters remain outside the embedded engine.
add_library(proof-verify-core STATIC material.cpp material.h)
target_link_libraries(proof-verify-core PUBLIC proof-verify-engine lite-client-common tdactor)

add_executable(tos-proof-verify main.cpp)
target_link_libraries(tos-proof-verify PRIVATE proof-verify-core)

install(TARGETS tos-proof-verify RUNTIME DESTINATION bin)

add_executable(test-proof-verify-embedded ../../test/pq-native/proof-verify-embedded-test.cpp)
target_link_libraries(test-proof-verify-embedded PRIVATE proof-verify-core)

add_test(NAME proof-verify-embedded COMMAND test-proof-verify-embedded
  ${PROJECT_SOURCE_DIR}/test/pq-native/data/proof-verify-real)
