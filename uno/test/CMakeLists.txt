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
# K-determinism-v2: test-uno-determinism now drives §12 P.5 4-node mempool
# permutation against real `verify_transfer_serial` + apply-phase mutations on
# A2's CommitmentTree / NullifierSet / AnchorWindow. Shares the K-p7-fixtures
# valid-Transfer builder with test-uno-end-to-end and test-uno-mandatory-
# negatives. Does NOT include state.h / cell-state.h — see the file-header
# note in test-determinism.cpp for the ODR-collision rationale.
add_executable(test-uno-determinism
               test-determinism.cpp
               fixtures/valid_transfer_fixture.cpp)
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
# K-restart-survival-drive: full apply / serialize / deserialize round-trip
# against a real UnoShardState via the opaque restart_survival_adapter. The
# adapter TU is compiled here (not in uno/core/) because state.h and
# compute-phase.h both declare a class named `UnoState` in the same
# namespace, so the test TU can only pull one of them; the adapter bridges.
add_executable(test-uno-restart-survival
               test-restart-survival.cpp
               restart_survival_adapter.cpp
               fixtures/valid_transfer_fixture.cpp)
# K-p7-fixtures: mandatory-negatives now shares the valid-Transfer builder
# with test-uno-end-to-end (see uno/test/fixtures/).
add_executable(test-uno-mandatory-negatives
               test-mandatory-negatives.cpp
               fixtures/valid_transfer_fixture.cpp)

# K-nullifier-warm-lru: pins the §5.9 post-cold-start warm-up contract for
# NullifierSet::warm_lru(k) — tail-k most-recent coverage, older-entries
# absence, and the k==0 / k>=N edge cases. Lightweight: no fixtures, no
# Plonky3 dependency; links against the nullifier-set TU in uno_workchain.
add_executable(test-uno-nullifier-warm-lru
               test-nullifier-warm-lru.cpp)

# K-genesis-loader: exercises load_genesis_distribution() + build_genesis_state()
# against a 3-note fixture + canonical reject paths (malformed address envelope,
# short rseed, negative value, supply mismatch). See test file header for scope.
add_executable(test-uno-genesis-loader           test-genesis-loader.cpp)

# K-bech32m: §2.6 AddressEnvelope codec round-trips and reject paths (bad HRP,
# HRP/network mismatch, flipped checksum symbol, flipped payload byte, short
# payload, unknown version, mixed case, illegal charset). Also pins the
# uppercase-tolerant BIP-173 decode path.
add_executable(test-uno-bech32m-envelope         test-bech32m-envelope.cpp)

# K-subs-test: closes the loop on the three N-P5 `uno_subscribe_*` channels
# (IncludedTx / NewHead / NewAnchor) by driving valid-Transfer fixtures
# through the end-of-block notify hooks and asserting shape + ordering of
# the events that subscribers observe. Consumes the same
# `global_uno_subscription_manager()` API the production JSON-RPC handlers
# for uno_subscribe_* use — test-local subscriptions are installed through
# the hook-registration API, not by patching the notify path.
add_executable(test-uno-subscriptions
               test-uno-subscriptions.cpp
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
           test-uno-mandatory-negatives
           test-uno-nullifier-warm-lru
           test-uno-genesis-loader
           test-uno-bech32m-envelope
           test-uno-subscriptions)
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

# K-state-golden-unskip: flip the UNO_P3_DRIVER_READY gate on now that
# M-P2's full 1..4×1..4 Transfer AIR + cell-state serialize_state /
# deserialize_state have landed. With this set, test_state_transition_apply
# iterates populated fixtures and drives `verify_transfer_serial` against a
# per-record FakeUnoState configured to reproduce the declared verdict,
# rather than emitting a blanket SKIP. Ok-record byte-equality remains
# opt-in behind UNO_RUN_PROVE_FIXTURES=1 because the fixture generator
# still leaves valid-record blobs empty pending a prove-path regeneration.
target_compile_definitions(test-uno-state-transition-golden
                           PRIVATE UNO_P3_DRIVER_READY=1)

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
    test-uno-genesis-loader
    PROPERTIES
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}")
