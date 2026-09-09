# Include through CMAKE_PROJECT_TOS_INCLUDE to build the private acceptance target.
# This does not change any workchain activation option.
if(NOT CONSTRUCTION_ISOLATION_SOURCE)
  set(CONSTRUCTION_ISOLATION_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/test-workchain-construction-isolation.cpp")
endif()
add_executable(test-workchain-construction-isolation "${CONSTRUCTION_ISOLATION_SOURCE}")
# Measurement copies affect this private target only; production targets retain
# their normal source and include paths.
if(CONSTRUCTION_ISOLATION_HEADER_DIR)
  target_include_directories(test-workchain-construction-isolation BEFORE PRIVATE "${CONSTRUCTION_ISOLATION_HEADER_DIR}")
endif()
set_target_properties(test-workchain-construction-isolation PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
target_link_libraries(test-workchain-construction-isolation PRIVATE tos_crypto)
# Existing private regressions always use their committed sources and headers.
set(I13_ACCEPTANCE_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/test-workchain-i13-acceptance.cpp")
set(I13_ACCEPTANCE_HEADER_DIR "")
include("${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/workchain-i13-acceptance.cmake")
set(I13_USAGE_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/test-workchain-i13-usage-acceptance.cpp")
include("${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/workchain-i13-usage-acceptance.cmake")
