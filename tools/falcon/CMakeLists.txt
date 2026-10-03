cmake_minimum_required(VERSION 3.16)
project(tos_offline_falcon LANGUAGES C)
set(FALCON "${CMAKE_CURRENT_SOURCE_DIR}/../../third-party/falcon-reference")
add_library(tos_falcon_offline SHARED signer.c
  ${FALCON}/falcon.c ${FALCON}/codec.c ${FALCON}/common.c ${FALCON}/shake.c
  ${FALCON}/vrfy.c ${FALCON}/keygen.c ${FALCON}/sign.c ${FALCON}/fft.c
  ${FALCON}/fpr.c ${FALCON}/rng.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../crypto/pq/falcon512-native.c)
target_include_directories(tos_falcon_offline PRIVATE ${FALCON}
  ${CMAKE_CURRENT_SOURCE_DIR}/../../crypto/pq)
target_compile_definitions(tos_falcon_offline PRIVATE FALCON_FPEMU=1 FALCON_FPNATIVE=0
  FALCON_AVX2=0 FALCON_FMA=0 FALCON_PREFIX=tos_falcon_inner
  FALCON_RAND_GETENTROPY=0 FALCON_RAND_URANDOM=0 FALCON_RAND_WIN32=0)
set_target_properties(tos_falcon_offline PROPERTIES C_STANDARD 99)

option(FALCON_BUILD_OFFICIAL_TESTS "Build the unmodified upstream conformance suite" OFF)
if(FALCON_BUILD_OFFICIAL_TESTS)
  add_executable(test_falcon ${FALCON}/test_falcon.c)
  target_include_directories(test_falcon PRIVATE ${FALCON})
  target_compile_definitions(test_falcon PRIVATE FALCON_FPEMU=1 FALCON_FPNATIVE=0
    FALCON_AVX2=0 FALCON_FMA=0 FALCON_PREFIX=tos_falcon_inner FALCON_KG_CHACHA20=0
    FALCON_RAND_GETENTROPY=0 FALCON_RAND_URANDOM=0 FALCON_RAND_WIN32=0)
  target_link_libraries(test_falcon PRIVATE tos_falcon_offline)
  if(UNIX)
    target_link_libraries(test_falcon PRIVATE m)
  endif()
  set_target_properties(test_falcon PROPERTIES C_STANDARD 99)
endif()
