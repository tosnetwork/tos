cmake_minimum_required(VERSION 3.16)
project(tos_bench_pq_signer LANGUAGES C CXX)
# Batch ML-DSA-44 signer for the local performance bench. It links the same
# backend and parameter configuration as the standalone key tool and signs only
# public test material derived from bench seeds.
set(BACKEND "${CMAKE_CURRENT_SOURCE_DIR}/../../third-party/mldsa-native/mldsa")
set(TOOL_CONFIG "${CMAKE_CURRENT_SOURCE_DIR}/../../crypto/pq/tools")
find_package(Threads REQUIRED)
add_library(bench_pq_backend STATIC "${BACKEND}/mldsa_native.c")
target_include_directories(bench_pq_backend PRIVATE "${BACKEND}" "${TOOL_CONFIG}")
target_compile_definitions(bench_pq_backend PRIVATE MLD_CONFIG_FILE="signer-config.h")
add_executable(bench-pq-signer pq-signer.cpp)
target_compile_features(bench-pq-signer PRIVATE cxx_std_17)
target_include_directories(bench-pq-signer PRIVATE "${BACKEND}" "${TOOL_CONFIG}")
target_compile_definitions(bench-pq-signer PRIVATE MLD_CONFIG_FILE="signer-config.h")
target_link_libraries(bench-pq-signer PRIVATE bench_pq_backend Threads::Threads)
