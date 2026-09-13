set(KEYRING_SOURCE
  keyring.h
  keyring.hpp
  keyring.cpp
  keyring-isolation.cpp
)

add_library(keyring STATIC ${KEYRING_SOURCE})

target_include_directories(keyring PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>)
target_link_libraries(keyring PUBLIC tdactor tos_crypto tl_api common )
target_link_libraries(keyring PRIVATE tos_validator_auth_signer)
target_link_libraries(keyring PUBLIC keys)
set_target_properties(keyring PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
