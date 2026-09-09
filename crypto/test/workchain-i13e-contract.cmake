# Proposed contract, pending real host adapter. With no adapter the executable
# must fail to link; building the object target alone is only a syntax check.
add_library(i13e-contract-assertions OBJECT
  "${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/test-workchain-i13e-contract.cpp")
set_target_properties(i13e-contract-assertions PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
add_executable(test-workchain-i13e-contract $<TARGET_OBJECTS:i13e-contract-assertions>)
set_target_properties(test-workchain-i13e-contract PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
if(I13E_REAL_ADAPTER_SOURCE)
  target_sources(test-workchain-i13e-contract PRIVATE "${I13E_REAL_ADAPTER_SOURCE}")
  target_include_directories(test-workchain-i13e-contract PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/crypto/test")
  target_link_libraries(test-workchain-i13e-contract PRIVATE tos_crypto)
endif()
