# Shared proof verification core and its installed command-line front end.
add_library(proof-verify-core STATIC proof-verify.cpp proof-verify.h material.cpp material.h)
target_include_directories(proof-verify-core PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>)
target_link_libraries(proof-verify-core PUBLIC lite-client-common tos_block smc-envelope tl_api tl_lite_api
  tl-lite-utils tdactor tdutils)

add_executable(tos-proof-verify main.cpp)
target_link_libraries(tos-proof-verify PRIVATE proof-verify-core)

install(TARGETS tos-proof-verify RUNTIME DESTINATION bin)
