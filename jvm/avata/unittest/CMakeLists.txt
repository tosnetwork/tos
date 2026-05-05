
include_directories (${CMAKE_CURRENT_SOURCE_DIR})

add_executable (avata_unittest
  test-harness.cpp

  codegen/assembler-test.cpp
  codegen/registers-test.cpp

  util/arg-parser-test.cpp
)

target_link_libraries (avata_unittest
  avata_codegen
  avata_codegen_x86
  avata_system
  avata_heap
  avata_util
  ${PLATFORM_LIBS}
)

add_test(NAME avata_unittest COMMAND avata_unittest)
add_dependencies(check avata_unittest)
