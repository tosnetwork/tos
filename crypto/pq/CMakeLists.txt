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

set(PQ_TEST_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../test/pq-mldsa44")
add_executable(test-pq-mldsa44-wrapper "${PQ_TEST_DIR}/test.cpp")
target_link_libraries(test-pq-mldsa44-wrapper PRIVATE tos_mldsa44)
if(TARGET tos_crypto)
  target_sources(tos_crypto PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../vm/pqops.cpp")
  target_link_libraries(tos_crypto PRIVATE tos_mldsa44)
  add_executable(test-pq-mldsa44 "${PQ_TEST_DIR}/test.cpp")
  target_compile_definitions(test-pq-mldsa44 PRIVATE TOS_PQ_TEST_VM=1)
  target_link_libraries(test-pq-mldsa44 PRIVATE tos_crypto tos_mldsa44)
  add_executable(test-pq-v16-parity "${PQ_TEST_DIR}/../pq-readiness/parity.cpp")
  target_link_libraries(test-pq-v16-parity PRIVATE tos_crypto)
endif()

install(FILES "${TOS_MLDSA_SOURCE_DIR}/LICENSE"
  DESTINATION share/tos/licenses/mldsa-native)
