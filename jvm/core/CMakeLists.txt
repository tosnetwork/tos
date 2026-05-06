# JVM workchain core — Phase 2 scaffold.
#
# Provides jvm_workchain_core: JvmNativeEngine registration stub plus the
# init_jvm_workchain() entry point called once at validator startup.
#
# run_compute() returns NOT_READY until Phase 4 (JvmCellCodec) is wired.
# TODO(Phase 2): link avata_interpreter once jvm/avata/CMakeLists.txt exports it.

set(JVM_CORE_SRC
  dispatch-engine.cpp
  init.cpp
)

add_library(jvm_workchain_core STATIC ${JVM_CORE_SRC})

target_include_directories(jvm_workchain_core PUBLIC
    ${CMAKE_SOURCE_DIR}
)

target_link_libraries(jvm_workchain_core PUBLIC
    tos_block
    # TODO(Phase 2): avata_interpreter
)
