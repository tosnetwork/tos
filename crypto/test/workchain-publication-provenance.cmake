# Manual source calibration, not another CI mutation driver. The included
# publication module still registers its ordinary private acceptance gate.
include("${PROJECT_SOURCE_DIR}/crypto/test/workchain-publication-recovery.cmake")
add_executable(test-workchain-publication-provenance
  "${PROJECT_SOURCE_DIR}/crypto/test/test-workchain-publication-provenance.cpp")
set_target_properties(test-workchain-publication-provenance PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
target_include_directories(test-workchain-publication-provenance PRIVATE "${PROJECT_SOURCE_DIR}/crypto/test")
target_link_libraries(test-workchain-publication-provenance PRIVATE workchain-private-publication)
target_link_options(test-workchain-publication-provenance PRIVATE "-Wl,--wrap=_ZN2td7RocksDb3setENS_5SliceES1_")
