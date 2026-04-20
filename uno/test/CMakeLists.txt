# uno/test — Uno Workchain unit tests.
#
# Agent 5 owns uno/CMakeLists.txt. From there, this subdirectory is included
# via `add_subdirectory(test)` once the `uno_workchain` static library target
# exists. Each test below links against that library and relies on the
# headers exposed by it (uno/rpc/*.h).
#
# The three tests in scope for Agent 6:
#   test-uno-transfer       — round-trip smoke for uno_sendTransfer plumbing
#   test-uno-determinism    — P.5 determinism scaffold (RPC-scope only until
#                             UnoShardState accessors are wired)
#   test-uno-filter         — compact-filter service plumbing + tag match
#
# Any test whose required upstream interface has not yet been bound prints
# a `SKIP:` line for that specific assertion and keeps the test binary
# exit-status 0.

add_executable(test-uno-transfer              test-transfer.cpp)
add_executable(test-uno-determinism           test-determinism.cpp)
add_executable(test-uno-filter                test-filter.cpp)
# M-codec: round-trip encode/decode across the full 1..4 × 1..4 shape
# envelope of §4.1. Pins the wire-codec invariant that unblocks §12 P.3
# state-transition golden fixtures + tosctl uno send integration.
add_executable(test-uno-codec-shapes          test-codec-shapes.cpp)
# Decision #5 cross-impl parity gate for the Plonky3 public-input byte
# encoding. Driven by uno/test/golden/public-inputs-v1.hex; Rust side is
# uno/plonky3-ffi/tests/public_input_fixture.rs. Both implementations
# MUST produce byte-identical output for every fixture record.
add_executable(test-uno-public-input-fixture  test-public-input-fixture.cpp)
# P.3 parallel verify pool (§13 P.3): determinism vs serial reference,
# repeat-under-thread-pressure invariant, and a min-of-3 scaling
# micro-benchmark for the 4-core ≥ 3.5x ideal target from §1.4.
add_executable(test-uno-parallel-verify       test-parallel-verify.cpp)
# P.5 done-when gate (§13): two-wallet end-to-end demo that drives the full
# prove → admission → verify → scan → audit lifecycle against the real A1/A2
# state, A3 crypto primitives, and A5 codec. Plonky3 verify is covered by
# a test-only override (install_test_proof_override_for_test) because A4's
# prover is not in scope for P.5.
#
# K-p7-fixtures: the valid-Transfer builder (DemoWallet / make_wallet /
# build_transfer) originally inline in test-uno-end-to-end.cpp lives in
# uno/test/fixtures/valid_transfer_fixture.{h,cpp}. Shared with the
# mandatory-negatives test so the §4.3-step-2 / step-4 reject paths
# (replay / cross-chain / inflation) can be exercised end-to-end.
add_executable(test-uno-end-to-end
               test-uno-end-to-end.cpp
               fixtures/valid_transfer_fixture.cpp)

# --- §12 test matrix (owner: N-P7) -----------------------------------------
# Added under P.7 scaffolding: primitive parity (§12 P.1), state-transition
# golden fixtures (§12 P.3), restart survival (§12 P.4), mandatory negatives
# (§12 end-of-section list).
#
# Each target builds unconditionally (per the task build-verification
# contract). Runtime assertions inside each binary are guarded by compile-
# time UNO_*_READY flags and emit explicit SKIP lines until the full verify
# pipeline + valid-tx generator are available end-to-end. This is the
# "deterministic GTEST_SKIP is preferred over hardcoded wrong-proof
# fixtures" discipline recorded in doc §12 P.3.
add_executable(test-uno-primitive-parity         test-primitive-parity.cpp)
add_executable(test-uno-state-transition-golden  test-state-transition-golden.cpp)
add_executable(test-uno-restart-survival         test-restart-survival.cpp)
# K-p7-fixtures: mandatory-negatives now shares the valid-Transfer builder
# with test-uno-end-to-end (see uno/test/fixtures/).
add_executable(test-uno-mandatory-negatives
               test-mandatory-negatives.cpp
               fixtures/valid_transfer_fixture.cpp)

# Build-only helper: regenerates uno/test/golden/state-transitions-v1.hex.
# NOT registered with ctest — invocation is a manual operator step (see the
# file's own doc comment). Links against uno_workchain for encode_transfer.
add_executable(generate-state-transitions-v1     generate-state-transitions-v1.cpp)
target_link_libraries(generate-state-transitions-v1 PRIVATE uno_workchain)
target_include_directories(generate-state-transitions-v1 PRIVATE ${CMAKE_SOURCE_DIR})

foreach(_t test-uno-transfer
           test-uno-determinism
           test-uno-filter
           test-uno-codec-shapes
           test-uno-public-input-fixture
           test-uno-parallel-verify
           test-uno-end-to-end
           test-uno-primitive-parity
           test-uno-state-transition-golden
           test-uno-restart-survival
           test-uno-mandatory-negatives)
  target_link_libraries(${_t} PRIVATE uno_workchain)
  target_include_directories(${_t} PRIVATE ${CMAKE_SOURCE_DIR})
  if (COMMAND tos_test)
    tos_test(${_t})
  else()
    add_test(NAME ${_t} COMMAND ${_t})
  endif()
endforeach()

# test-uno-parallel-verify spins up std::thread workers from the pool;
# make sure it links against the system's pthread runtime.
target_link_libraries(test-uno-parallel-verify PRIVATE Threads::Threads)

# Propagate the UNO_MLKEM_STUB flag from the library to the §12 tests that
# check for it at runtime. uno_workchain sets it PRIVATE (so upstream libs
# don't inherit it), but the test-side SKIP guard needs to know. The parent
# uno/CMakeLists.txt's LIBOQS_INCLUDE_DIR / LIBOQS_LIBRARY cache vars
# (populated by find_path / find_library) are the source of truth; re-check
# them here rather than re-running find_* because PARENT_SCOPE visibility
# is not guaranteed.
if (NOT LIBOQS_INCLUDE_DIR OR NOT LIBOQS_LIBRARY)
  target_compile_definitions(test-uno-primitive-parity PRIVATE UNO_MLKEM_STUB=1)
endif()

# BLAKE3 backend is active when uno_workchain was built with UNO_BLAKE3_AVATAR
# (decision #41). Flip the hybrid-KEM gate so the pinned KAT runs instead of
# SKIPping. Vendor tree is at `third-party/avatar-crypto/`; check its presence
# (symmetric with uno/CMakeLists.txt).
if (EXISTS "${AVATAR_CRYPTO_ROOT}/src/crypto/blake3/at_blake3.c")
  target_compile_definitions(test-uno-primitive-parity PRIVATE UNO_P1_HYBRID_KEM_READY=1)
endif()

# Poseidon2 FFI surface is active when the uno_plonky3_ffi crate is present
# in-tree (Agent 4 K-poseidon2-ffi). The `uno_poseidon2_goldilocks_permute_t{8,16}`
# C-ABI entry points are exported by `uno/plonky3-ffi/src/permute.rs` and
# regenerated into `include/uno_plonky3_ffi.h` by build.rs. Flipping the gate
# activates the `test_poseidon2_reference_vector` + `test_nullifier_derivation`
# self-consistency assertions; the test-TU carries weak-symbol stubs so the
# link works before Corrosion is fully wired (the stubs are overridden when
# the real static-lib is linked).
if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../plonky3-ffi/Cargo.toml")
  target_compile_definitions(test-uno-primitive-parity PRIVATE UNO_P1_POSEIDON2_READY=1)
endif()

# Fixture-backed tests need ctest's cwd set to CMAKE_SOURCE_DIR so they can
# find the golden/*.hex files via relative paths. Each test's `find_fixture_path`
# probes a handful of candidate prefixes, but setting WORKING_DIRECTORY makes
# the first candidate hit reliably under ctest.
set_tests_properties(
    test-uno-public-input-fixture
    test-uno-state-transition-golden
    PROPERTIES
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}")
