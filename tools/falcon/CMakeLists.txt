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
