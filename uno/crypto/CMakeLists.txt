if (CMAKE_CROSSCOMPILING OR NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "UNO crypto prototype tests currently require a native Linux build")
endif()
find_program(UNO_CRYPTO_CARGO cargo)
if (NOT UNO_CRYPTO_CARGO)
  message(FATAL_ERROR "UNO crypto prototype tests require cargo and the pinned Rust toolchain")
endif()
include("${CMAKE_CURRENT_SOURCE_DIR}/RequireCargo.cmake")
uno_require_cargo("${UNO_CRYPTO_CARGO}" "${CMAKE_CURRENT_SOURCE_DIR}")
find_package(Threads REQUIRED)
set(UNO_CRYPTO_BUILD_JOBS 48 CACHE STRING "Parallel Rust build jobs for UNO prototype tests")
if (NOT UNO_CRYPTO_BUILD_JOBS MATCHES "^[1-9][0-9]*$")
  message(FATAL_ERROR "UNO_CRYPTO_BUILD_JOBS must be a positive integer")
endif()
set(UNO_CRYPTO_TARGET_DIR "${CMAKE_CURRENT_BINARY_DIR}/cargo-target")
set(UNO_CRYPTO_ARCHIVE "${UNO_CRYPTO_TARGET_DIR}/release/libtos_uno_crypto_prototype.a")

# Let the locked build tool track its complete dependency graph on every invocation.
add_custom_target(uno-crypto-rust
  COMMAND ${CMAKE_COMMAND} -E env "CARGO_NET_OFFLINE=true" "CARGO_TARGET_DIR=${UNO_CRYPTO_TARGET_DIR}"
    ${UNO_CRYPTO_CARGO} build --locked --offline --release -j${UNO_CRYPTO_BUILD_JOBS}
  BYPRODUCTS "${UNO_CRYPTO_ARCHIVE}"
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  VERBATIM)

foreach(kind smoke real tree)
  add_executable(test-uno-crypto-abi-${kind} tests/abi-${kind}.cpp)
  target_include_directories(test-uno-crypto-abi-${kind} PRIVATE include)
  target_compile_features(test-uno-crypto-abi-${kind} PRIVATE cxx_std_17)
  target_link_libraries(test-uno-crypto-abi-${kind} PRIVATE "${UNO_CRYPTO_ARCHIVE}" Threads::Threads ${CMAKE_DL_LIBS} m)
  add_dependencies(test-uno-crypto-abi-${kind} uno-crypto-rust)
  add_dependencies(all-tests test-uno-crypto-abi-${kind})
endforeach()

target_compile_definitions(test-uno-crypto-abi-real PRIVATE UNO_TEST_HOST_ADAPTER=1)
target_include_directories(test-uno-crypto-abi-real PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../..")
target_link_libraries(test-uno-crypto-abi-real PRIVATE tos_crypto)

add_executable(test-uno-crypto-cost EXCLUDE_FROM_ALL tests/abi-cost.cpp)
target_include_directories(test-uno-crypto-cost PRIVATE include)
target_compile_features(test-uno-crypto-cost PRIVATE cxx_std_17)
target_link_libraries(test-uno-crypto-cost PRIVATE "${UNO_CRYPTO_ARCHIVE}" Threads::Threads ${CMAKE_DL_LIBS} m)
add_dependencies(test-uno-crypto-cost uno-crypto-rust)
add_dependencies(all-tests test-uno-crypto-cost)
add_test(NAME test-uno-crypto-cost-self COMMAND test-uno-crypto-cost --self-test)

add_executable(test-uno-tree-cell ../../test/test-td-main.cpp tests/tree-cell.cpp tests/note-state.cpp)
target_include_directories(test-uno-tree-cell PRIVATE ../..)
target_link_libraries(test-uno-tree-cell PRIVATE tos_crypto "${UNO_CRYPTO_ARCHIVE}" Threads::Threads ${CMAKE_DL_LIBS} m)
add_dependencies(test-uno-tree-cell uno-crypto-rust)
add_dependencies(all-tests test-uno-tree-cell)
add_test(NAME test-uno-tree-cell COMMAND test-uno-tree-cell)

add_executable(measure-uno-note-component ../../test/test-td-main.cpp tests/note-measurement.cpp)
target_include_directories(measure-uno-note-component PRIVATE ../..)
target_link_libraries(measure-uno-note-component PRIVATE tos_crypto "${UNO_CRYPTO_ARCHIVE}" Threads::Threads ${CMAKE_DL_LIBS} m)
add_dependencies(measure-uno-note-component uno-crypto-rust)
add_executable(test-uno-real-history ../../test/test-td-main.cpp tests/continuous-history.cpp)
target_include_directories(test-uno-real-history PRIVATE ../..)
target_compile_definitions(test-uno-real-history PRIVATE
  UNO_HISTORY_DIRECTORY="${CMAKE_CURRENT_SOURCE_DIR}/testdata/continuous-history")
target_link_libraries(test-uno-real-history PRIVATE tos_crypto "${UNO_CRYPTO_ARCHIVE}" Threads::Threads ${CMAKE_DL_LIBS} m)
add_dependencies(test-uno-real-history uno-crypto-rust)
add_dependencies(all-tests test-uno-real-history)
add_test(NAME test-uno-real-history COMMAND test-uno-real-history)
set_tests_properties(test-uno-real-history PROPERTIES TIMEOUT 60
  FAIL_REGULAR_EXPRESSION "0 test[(]s[)] passed")
add_dependencies(all-tests measure-uno-note-component)
add_test(NAME test-uno-note-component-smoke COMMAND ${CMAKE_COMMAND} -E env
  TOS_UNO_NOTE_KEYS=8 TOS_UNO_NOTE_WINDOW=3 TOS_UNO_NOTE_HISTORY=owners
  $<TARGET_FILE:measure-uno-note-component> --filter ExistingComponentEnvelope)
set_tests_properties(test-uno-note-component-smoke PROPERTIES TIMEOUT 60
  FAIL_REGULAR_EXPRESSION "0 test[(]s[)] passed")
add_test(NAME test-uno-note-continuous-history COMMAND measure-uno-note-component
  --filter ContinuousComponentHistory)
set_tests_properties(test-uno-note-continuous-history PROPERTIES TIMEOUT 60
  FAIL_REGULAR_EXPRESSION "0 test[(]s[)] passed")

add_executable(test-uno-tree-errors ../../test/test-td-main.cpp tests/tree-errors.cpp)
target_include_directories(test-uno-tree-errors PRIVATE ../..)
target_link_libraries(test-uno-tree-errors PRIVATE tos_crypto)
add_dependencies(all-tests test-uno-tree-errors)
add_test(NAME test-uno-tree-errors COMMAND test-uno-tree-errors)

add_test(NAME test-uno-crypto-rust
  COMMAND ${CMAKE_COMMAND} -E env "CARGO_NET_OFFLINE=true" "CARGO_TARGET_DIR=${UNO_CRYPTO_TARGET_DIR}"
    ${UNO_CRYPTO_CARGO} test --locked --offline --release -j${UNO_CRYPTO_BUILD_JOBS} --lib)
set_tests_properties(test-uno-crypto-rust PROPERTIES WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  RESOURCE_LOCK uno_crypto_cargo TIMEOUT 600)
add_test(NAME test-uno-crypto-abi-smoke COMMAND test-uno-crypto-abi-smoke)
add_test(NAME test-uno-crypto-abi-tree COMMAND test-uno-crypto-abi-tree)
add_test(NAME test-uno-crypto-abi-real
  COMMAND ${CMAKE_COMMAND}
    "-DUNO_CRYPTO_CARGO=${UNO_CRYPTO_CARGO}"
    "-DUNO_CRYPTO_SOURCE=${CMAKE_CURRENT_SOURCE_DIR}"
    "-DUNO_CRYPTO_TARGET_DIR=${UNO_CRYPTO_TARGET_DIR}"
    "-DUNO_CRYPTO_BUILD_JOBS=${UNO_CRYPTO_BUILD_JOBS}"
    "-DUNO_CRYPTO_FIXTURE_ROOT=${CMAKE_CURRENT_BINARY_DIR}/fixtures"
    "-DUNO_CRYPTO_ABI_EXE=$<TARGET_FILE:test-uno-crypto-abi-real>"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/RunRealAbiTest.cmake")
set_tests_properties(test-uno-crypto-abi-real PROPERTIES RESOURCE_LOCK uno_crypto_cargo TIMEOUT 600)

add_test(NAME test-uno-crypto-header-guard
  COMMAND ${CMAKE_COMMAND}
    "-DUNO_CRYPTO_SOURCE=${CMAKE_CURRENT_SOURCE_DIR}"
    "-DUNO_CRYPTO_TARGET_DIR=${UNO_CRYPTO_TARGET_DIR}"
    "-DUNO_CRYPTO_CARGO=${UNO_CRYPTO_CARGO}"
    "-DUNO_CRYPTO_BUILD_JOBS=${UNO_CRYPTO_BUILD_JOBS}"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/TestHeaderGuard.cmake")
set_tests_properties(test-uno-crypto-header-guard PROPERTIES RESOURCE_LOCK uno_crypto_cargo TIMEOUT 600)
