if(TARGET test-p0-native)
  return()
endif()
# Inject a test-only target without modifying production targets or schemas.
get_filename_component(P0_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
set(P0_GENERATED "${CMAKE_BINARY_DIR}/p0-native")
# The profile grammar now lives in the production schema, so that schema is the
# only source compiled here. Appending the design artifact as well would redefine
# every profile constructor; the two are kept identical by check_production.py
# rather than by being concatenated.
file(READ "${P0_ROOT}/crypto/block/block.tlb" P0_BASE_TLB)
file(WRITE "${CMAKE_BINARY_DIR}/p0-combined.tlb" "${P0_BASE_TLB}")
add_custom_command(OUTPUT "${P0_GENERATED}.h" "${P0_GENERATED}.cpp"
  COMMAND $<TARGET_FILE:tlbc> -h -z -n p0wire -o p0-native p0-combined.tlb
  COMMAND $<TARGET_FILE:tlbc> -c -z -n p0wire -o p0-native p0-combined.tlb
  WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
  DEPENDS tlbc "${P0_ROOT}/crypto/block/block.tlb")
add_executable(test-p0-native "${P0_ROOT}/test/validator-auth-p0/native-boc.cpp" "${P0_GENERATED}.cpp")
target_include_directories(test-p0-native PRIVATE "${P0_ROOT}" "${P0_ROOT}/crypto" "${CMAKE_BINARY_DIR}")
target_link_libraries(test-p0-native PRIVATE tos_block tos_crypto tdutils)

set_target_properties(test-p0-native PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
# The existing generator emits narrowing aggregate initialization for nat fields.
set_source_files_properties("${P0_GENERATED}.cpp" PROPERTIES COMPILE_OPTIONS "-Wno-narrowing")
