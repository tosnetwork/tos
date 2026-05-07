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
  deploy-abi.cpp
  dispatch-engine.cpp
  event-host.cpp
  init.cpp
  message-abi.cpp
  storage-cell-host.cpp
)

add_library(jvm_workchain_core STATIC ${JVM_CORE_SRC})

target_include_directories(jvm_workchain_core PUBLIC
    ${CMAKE_SOURCE_DIR}
)

target_link_libraries(jvm_workchain_core PUBLIC
    tos_block
    avata_interpreter
)
