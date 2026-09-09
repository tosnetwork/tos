# Explicit private publication/recovery target; no activation or validator wiring.
if(NOT PUBLICATION_SOURCE)
  set(PUBLICATION_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/crypto/block/workchain-candidate-publication.cpp")
endif()
if(NOT PUBLICATION_TEST_SOURCE)
  set(PUBLICATION_TEST_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/test-workchain-publication-recovery.cpp")
endif()
add_library(workchain-private-publication STATIC "${PUBLICATION_SOURCE}")
set_target_properties(workchain-private-publication PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
target_link_libraries(workchain-private-publication PUBLIC tos_crypto tddb)
if(NOT PUBLICATION_SET_FAULT_SOURCE)
  set(PUBLICATION_SET_FAULT_SOURCE "${PROJECT_SOURCE_DIR}/crypto/test/workchain-publication-set-fault.cpp")
endif()
add_executable(test-workchain-publication-recovery "${PUBLICATION_TEST_SOURCE}" "${PUBLICATION_SET_FAULT_SOURCE}")
target_link_options(test-workchain-publication-recovery PRIVATE
  "-Wl,--wrap=_ZN2td7RocksDb3setENS_5SliceES1_")
set_target_properties(test-workchain-publication-recovery PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
target_include_directories(test-workchain-publication-recovery PRIVATE "${PROJECT_SOURCE_DIR}/crypto/test")
target_link_libraries(test-workchain-publication-recovery PRIVATE workchain-private-publication ${CMAKE_DL_LIBS})
if(NOT PUBLICATION_FAULT_SOURCE)
  set(PUBLICATION_FAULT_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/workchain-publication-io-fault.cpp")
endif()
add_library(workchain-publication-io-fault SHARED "${PUBLICATION_FAULT_SOURCE}")
find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_test(NAME test-workchain-publication-recovery-gates COMMAND ${Python3_EXECUTABLE}
  "${PROJECT_SOURCE_DIR}/crypto/test/workchain-publication-recovery.py"
  --build "${CMAKE_BINARY_DIR}/workchain-publication-ctest/build"
  --ctest-root "${CMAKE_BINARY_DIR}/workchain-publication-ctest")
set_tests_properties(test-workchain-publication-recovery-gates PROPERTIES
  TIMEOUT 7200 RESOURCE_LOCK workchain_i13_measurements LABELS "private;workchain;i13")
