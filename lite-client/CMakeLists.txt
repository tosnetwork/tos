add_library(lite-client-proof-common STATIC lite-client-common.cpp lite-client-common.h)
target_link_libraries(lite-client-proof-common PUBLIC tos_block tl_api tl_lite_api tl-lite-utils tdutils)

add_library(lite-client-common STATIC ext-client.cpp ext-client.h
  query-utils.hpp query-utils.cpp)
target_link_libraries(lite-client-common PUBLIC lite-client-proof-common tdactor adnllite tl_api tl_lite_api tl-lite-utils tos_crypto)

add_executable(lite-client lite-client.cpp lite-client.h ext-client.h ext-client.cpp)
target_link_libraries(lite-client tdutils tdactor adnllite tl_api tl_lite_api tl-lite-utils terminal lite-client-common git)

install(TARGETS lite-client RUNTIME DESTINATION bin)

add_subdirectory(proof-verify)
