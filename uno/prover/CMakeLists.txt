cmake_minimum_required(VERSION 3.16)
project(ConfidentialWalletTests LANGUAGES NONE)
enable_testing()

# This is a standalone test project, never a subdirectory of the node build.
include("${CMAKE_CURRENT_SOURCE_DIR}/../crypto/RequireCargo.cmake")
uno_require_cargo("${CMAKE_CURRENT_SOURCE_DIR}" WALLET_CARGO)
find_package(Python3 REQUIRED COMPONENTS Interpreter)

add_test(NAME wallet-prover-rust
  COMMAND "${CMAKE_COMMAND}" -E env "CARGO_NET_OFFLINE=true"
    "CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR}/cargo-target"
    "${WALLET_CARGO}" test --manifest-path "${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml"
    --locked --offline --release --lib)
set_tests_properties(wallet-prover-rust PROPERTIES
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  TIMEOUT 600 FAIL_REGULAR_EXPRESSION "running 0 tests")

add_test(NAME wallet-prover-source-gates
  COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/source-gates.py")
set_tests_properties(wallet-prover-source-gates PROPERTIES
  TIMEOUT 180 FAIL_REGULAR_EXPRESSION "Ran 0 tests")

add_test(NAME wallet-prover-registration
  COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test-registration.py")
set_tests_properties(wallet-prover-registration PROPERTIES
  TIMEOUT 120 FAIL_REGULAR_EXPRESSION "Ran 0 tests")
