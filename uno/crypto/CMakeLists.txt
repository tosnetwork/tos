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


add_executable(test-uno-crypto-abi-real tests/balance-abi.cpp)
target_include_directories(test-uno-crypto-abi-real PRIVATE include)
target_compile_features(test-uno-crypto-abi-real PRIVATE cxx_std_17)
target_link_libraries(test-uno-crypto-abi-real PRIVATE "${UNO_CRYPTO_ARCHIVE}" Threads::Threads ${CMAKE_DL_LIBS} m)
add_dependencies(test-uno-crypto-abi-real uno-crypto-rust)
add_dependencies(all-tests test-uno-crypto-abi-real)
add_test(NAME test-uno-crypto-abi-real COMMAND test-uno-crypto-abi-real
  "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/balance-kernel-v1.txt")
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
