# Independent private target; no activation option is changed.
if(NOT I13_USAGE_SOURCE)
  set(I13_USAGE_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/test-workchain-i13-usage-acceptance.cpp")
endif()
add_executable(test-workchain-i13-usage-acceptance "${I13_USAGE_SOURCE}")
set_target_properties(test-workchain-i13-usage-acceptance PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
target_link_libraries(test-workchain-i13-usage-acceptance PRIVATE tos_crypto)
