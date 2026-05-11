# JVM workchain core.
#
# Provides jvm_workchain_core: JvmNativeEngine registration plus the
# init_jvm_workchain() entry point called once at validator startup.
#
# run_compute() fails closed until init installs a real Avata runtime; tests can
# inject a deterministic JvmComputeRuntime to exercise the full compute-output
# path.  The core target depends on avata_interpreter so the main TOS build
# produces the canonical interpreter archive, rt.jar, and api.jar.

set(JVM_CORE_SRC
  avata-execution.cpp
  avata-runtime.cpp
  cell-codec.cpp
  class-manifest.cpp
  config-param.cpp
  crypto-host.cpp
  deploy-abi.cpp
  dispatch-engine.cpp
  event-host.cpp
  inbound-parse.cpp
  init.cpp
  message-abi.cpp
  rpc.cpp
  storage-cell-host.cpp
  zerostate.cpp
)

add_library(jvm_workchain_core STATIC ${JVM_CORE_SRC})

target_include_directories(jvm_workchain_core PUBLIC
    ${CMAKE_SOURCE_DIR}
)

target_link_libraries(jvm_workchain_core PUBLIC
    tos_block
    avata_interpreter
)

# Phase B of the rt.jar gap plan: link the production crypto libs used
# by jvm/core/crypto-host.cpp.  tos_block transitively exposes
# tos_crypto_core (which publicly links secp256k1 + sodium); blst is
# private on tos_crypto so we add its include path + static archive
# directly.  These names come from CMake/{BuildBLST,BuildSECP256K1,
# FindSodium}.cmake at the top level.
target_include_directories(jvm_workchain_core PRIVATE
    ${BLST_INCLUDE_DIR}
    ${SECP256K1_INCLUDE_DIR}
    ${SODIUM_INCLUDE_DIR}
)
target_link_libraries(jvm_workchain_core PRIVATE
    ${BLST_LIB}
    ${SECP256K1_LIBRARY}
    ${SODIUM_LIBRARY_RELEASE}
)
