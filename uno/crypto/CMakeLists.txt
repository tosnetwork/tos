include("${CMAKE_CURRENT_SOURCE_DIR}/RequireCargo.cmake")
option(TOS_UNO_CRYPTO_NODE_LINK "Link the experimental confidential kernel into the node without enabling execution" OFF)
string(TOUPPER "${TOS_UNO_CRYPTO_PROTOTYPE_TESTS}" _uno_crypto_tests_mode)
if (NOT _uno_crypto_tests_mode STREQUAL "AUTO" AND
    NOT _uno_crypto_tests_mode STREQUAL "ON" AND
    NOT _uno_crypto_tests_mode STREQUAL "OFF")
  message(FATAL_ERROR "TOS_UNO_CRYPTO_PROTOTYPE_TESTS must be AUTO, ON, or OFF; got '${TOS_UNO_CRYPTO_PROTOTYPE_TESTS}'")
endif()

if (_uno_crypto_tests_mode STREQUAL "OFF" AND NOT TOS_UNO_CRYPTO_NODE_LINK)
  message(STATUS "UNO crypto prototype tests disabled by TOS_UNO_CRYPTO_PROTOTYPE_TESTS=OFF")
  return()
endif()

if (_uno_crypto_tests_mode STREQUAL "ON" OR TOS_UNO_CRYPTO_NODE_LINK)
  uno_require_cargo("${CMAKE_CURRENT_SOURCE_DIR}" UNO_CRYPTO_CARGO)
else()
  uno_probe_cargo("${CMAKE_CURRENT_SOURCE_DIR}" _uno_crypto_cargo_available _uno_crypto_cargo_reason UNO_CRYPTO_CARGO)
  if (NOT _uno_crypto_cargo_available)
    message(STATUS "Skipping UNO crypto prototype tests in AUTO mode: ${_uno_crypto_cargo_reason}")
    return()
  endif()
endif()
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

add_library(confidential-crypto-kernel STATIC IMPORTED GLOBAL)
set_target_properties(confidential-crypto-kernel PROPERTIES
  IMPORTED_LOCATION "${UNO_CRYPTO_ARCHIVE}"
  INTERFACE_LINK_LIBRARIES "Threads::Threads;${CMAKE_DL_LIBS};m")
add_dependencies(confidential-crypto-kernel uno-crypto-rust)

function(link_confidential_kernel_into_node node)
  # Linkage only: no engine registration, RPC, opcode or execution permission.
  # Native Linux toolchain availability was checked before creating the archive.
  target_link_libraries(${node} confidential-crypto-kernel)
  target_link_options(${node} PRIVATE
    "LINKER:--undefined=uno_crypto_verify_v2"
    "LINKER:--undefined=uno_crypto_system_encrypt_v1"
    "LINKER:--undefined=uno_crypto_system_verify_v1")
  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  add_test(NAME test-uno-crypto-node-link COMMAND "${Python3_EXECUTABLE}"
    "${PROJECT_SOURCE_DIR}/uno/crypto/tests/node-link.py"
    --expect present $<TARGET_FILE:${node}>)
  set_tests_properties(test-uno-crypto-node-link PROPERTIES TIMEOUT 60)
  add_dependencies(all-tests ${node})
endfunction()

if (_uno_crypto_tests_mode STREQUAL "OFF")
  message(STATUS "Confidential kernel node link enabled; prototype tests remain explicitly disabled")
  return()
endif()

add_executable(test-uno-crypto-abi-real tests/balance-abi.cpp)
target_include_directories(test-uno-crypto-abi-real PRIVATE include)
target_compile_features(test-uno-crypto-abi-real PRIVATE cxx_std_17)
target_link_libraries(test-uno-crypto-abi-real PRIVATE "${UNO_CRYPTO_ARCHIVE}" Threads::Threads ${CMAKE_DL_LIBS} m)
add_dependencies(test-uno-crypto-abi-real uno-crypto-rust)
add_dependencies(all-tests test-uno-crypto-abi-real)
add_test(NAME test-uno-crypto-abi-real COMMAND test-uno-crypto-abi-real
  "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/balance-kernel-v2.txt")
set_tests_properties(test-uno-crypto-abi-real PROPERTIES TIMEOUT 120)

add_test(NAME test-uno-crypto-rust
  COMMAND ${CMAKE_COMMAND} -E env "CARGO_NET_OFFLINE=true" "CARGO_TARGET_DIR=${UNO_CRYPTO_TARGET_DIR}"
    ${UNO_CRYPTO_CARGO} test --locked --offline --release -j${UNO_CRYPTO_BUILD_JOBS} --lib)
set_tests_properties(test-uno-crypto-rust PROPERTIES WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  RESOURCE_LOCK uno_crypto_cargo TIMEOUT 600 FAIL_REGULAR_EXPRESSION "running 0 tests")

find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_test(NAME test-uno-crypto-symbols COMMAND "${Python3_EXECUTABLE}"
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/kernel-symbols.py" $<TARGET_FILE:test-uno-crypto-abi-real>)
set_tests_properties(test-uno-crypto-symbols PROPERTIES TIMEOUT 60)
add_test(NAME test-uno-crypto-kernel-gates COMMAND "${Python3_EXECUTABLE}"
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/kernel-gates.py")
set_tests_properties(test-uno-crypto-kernel-gates PROPERTIES
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}" TIMEOUT 180)

add_test(NAME test-uno-crypto-header-guard
  COMMAND ${CMAKE_COMMAND}
    "-DUNO_CRYPTO_SOURCE=${CMAKE_CURRENT_SOURCE_DIR}"
    "-DUNO_CRYPTO_TARGET_DIR=${UNO_CRYPTO_TARGET_DIR}"
    "-DUNO_CRYPTO_CARGO=${UNO_CRYPTO_CARGO}"
    "-DUNO_CRYPTO_BUILD_JOBS=${UNO_CRYPTO_BUILD_JOBS}"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/TestHeaderGuard.cmake")
set_tests_properties(test-uno-crypto-header-guard PROPERTIES RESOURCE_LOCK uno_crypto_cargo TIMEOUT 600)
