/*
    Uno Workchain — §12 P.4 restart-survival test.

    Per §12 P.4 of doc/uno-workchain.md, a validator that restarts from a
    serialised UnoShardState MUST replay to byte-identical state: the
    commitment-tree root, nullifier set, anchor window, and stats must all
    match pre-crash. This is the core consensus property the chain relies
    on when validators crash-recover.

    Test strategy:
      1. Construct a fresh UnoShardState (= empty genesis).
      2. Apply a mixed batch of 1000 valid + 100 invalid Transfer records.
         The exact valid:invalid interleaving is randomised within each run,
         since §4.3 reject paths are side-effect-free and their ordering
         does not change the resulting state.
      3. Serialise the state to bytes (uno/core/cell-state.cpp).
      4. Deserialise into a fresh state object.
      5. Re-serialise and byte-compare with (3) — the serialiser must be
         idempotent under round-trip.
      6. Assert the "state root" (i.e., the cell hash of the root cell)
         matches pre-round-trip.
      7. Randomise the apply order of invalid txs + check the final root
         again — invalid txs commit no state and their order is immaterial.

    Ready-state gates:
      - UnoShardState + cell-state serialise/deserialise     (Agent 1)
      - verify_transfer + apply_transfer                     (Agent 5)
      - A working Transfer generator producing BOTH valid AND invalid txs
        deterministically (a tosctl CLI subcommand + a P.3 reject AIR).

    Until those are all compiling, this test SKIPs with a clear reason.
    The scaffolding code (mix-and-shuffle, byte-compare, root-cell-hash
    extraction) is laid down here so that a single symbol-flip enables it.

    Per N-P7 scope: "Deterministic GTEST_SKIP is preferred over hardcoded
    fixtures with wrong proofs." We honour that.
*/
#include <array>
#include <atomic>
#include <cassert>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

// ----- Tracked-printf harness -----------------------------------------------

static std::atomic<int> g_failures{0};
static std::atomic<int> g_skips{0};
static std::atomic<int> g_passes{0};

static int tracked_printf(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    va_list copy;
    va_copy(copy, args);
    int needed = std::vsnprintf(nullptr, 0, fmt, copy);
    va_end(copy);
    std::string rendered;
    if (needed >= 0) {
        rendered.resize((size_t)needed + 1);
        va_copy(copy, args);
        std::vsnprintf(rendered.data(), rendered.size(), fmt, copy);
        va_end(copy);
        rendered.resize((size_t)needed);
    }
    int written = std::vprintf(fmt, args);
    va_end(args);
    if (!rendered.empty()) {
        if (rendered.find("FAILED") != std::string::npos) g_failures.fetch_add(1);
        if (rendered.find("SKIP")    != std::string::npos) g_skips.fetch_add(1);
        if (rendered.find("PASSED")  != std::string::npos) g_passes.fetch_add(1);
    }
    return written;
}
#define tprintf tracked_printf

// ---------------------------------------------------------------------------
// The test body is behind a compile-time guard so it only activates once
// all dependencies are fully bound. Individual dependencies become available
// at slightly different times (Agent 1's state cell-state.cpp is already
// skeletonised; Agent 5's compute-phase.cpp body is scaffolded; the wallet
// tx-generator is P.6). When the full chain is live, flip UNO_P4_READY on
// from the build system.
// ---------------------------------------------------------------------------

#ifdef UNO_P4_READY
#include "uno/core/cell-state.h"
#include "uno/core/compute-phase.h"
#include "uno/core/state.h"
#include "uno/core/transaction.h"
#endif

[[maybe_unused]] static constexpr int kValidTxCount   = 1000;
[[maybe_unused]] static constexpr int kInvalidTxCount = 100;

// Deterministic RNG seed — same across runs so failures are reproducible.
[[maybe_unused]] static constexpr uint64_t kRestartSurvivalSeed = 0x1234567890abcdefULL;

static void test_restart_survival_round_trip() {
    tprintf("[TEST] test_restart_survival_round_trip (1000 valid + 100 invalid)\n");

#ifndef UNO_P4_READY
    tprintf("  SKIP: UNO_P4_READY not defined. Depends on:\n"
            "        • uno/core/cell-state.h    :: serialize_state / deserialize_state (A1)\n"
            "        • uno/core/compute-phase.h :: verify_transfer + apply_transfer    (A5)\n"
            "        • tosctl or equivalent     :: deterministic valid-tx generator    (P.6)\n"
            "        • Plonky3 AIR              :: to emit proofs accepted by verifier (P.2)\n"
            "        All skeletons exist; enable by defining -DUNO_P4_READY=1 once the\n"
            "        above chain compiles end-to-end.\n");
    return;
#else
    using uno_workchain::UnoShardState;

    std::mt19937_64 rng(kRestartSurvivalSeed);

    // (1) Fresh state.
    UnoShardState state = UnoShardState::make_empty();

    // (2) Build the mixed batch. The valid-tx generator is a TODO; until it
    //     exists we cannot run this path even under UNO_P4_READY.
    //
    // Structure the batch as "ordered by insertion", with a companion vector
    // of `is_valid` flags. At apply-time we permute the sequence but retain
    // the subsequence of valid-tx positions: those are the consensus-ordered
    // ones, whose relative order MUST be preserved (the nullifier-set state
    // depends on it — tx[i] may spend a commitment produced by tx[j<i]).
    //
    // Invalid-tx positions can be rotated freely across the batch because
    // verify-reject is stateless and produces no state delta.

    // TODO(P6-wallet, P2-AIR): populate `valid`, `invalid` with real bytes.
    std::vector<std::vector<uint8_t>> valid;    valid.reserve(kValidTxCount);
    std::vector<std::vector<uint8_t>> invalid;  invalid.reserve(kInvalidTxCount);
    // ...
    if (valid.size() != (size_t)kValidTxCount ||
        invalid.size() != (size_t)kInvalidTxCount) {
        tprintf("  SKIP: valid/invalid generator not yet producing %d+%d txs\n",
                kValidTxCount, kInvalidTxCount);
        return;
    }

    // (3) Apply run #1: valid in canonical order, invalid interleaved
    //     pseudo-randomly. Record the resulting serialised state.
    auto apply_batch = [&](UnoShardState& s,
                           std::vector<std::vector<uint8_t>> ordered_valid,
                           std::vector<std::vector<uint8_t>> shuffled_invalid) {
        // TODO(uno-integration): build an apply sequence that interleaves
        // shuffled_invalid among ordered_valid at pseudo-random slots, then
        // call verify_transfer + apply_transfer for each.
        (void)s; (void)ordered_valid; (void)shuffled_invalid;
    };

    // run #1
    auto invalid_shuffled_1 = invalid;
    std::shuffle(invalid_shuffled_1.begin(), invalid_shuffled_1.end(), rng);
    apply_batch(state, valid, invalid_shuffled_1);
    td::Ref<vm::Cell> cell_1 = uno_workchain::serialize_state(state);
    auto root_hash_1 = cell_1.is_null()
                         ? std::array<uint8_t, 32>{}
                         : cell_1->get_hash().bits().as_array<32>();

    // (4) round-trip: deserialise into a fresh state, re-serialise, compare.
    UnoShardState state_rt;
    if (!uno_workchain::deserialize_state(cell_1, state_rt)) {
        tprintf("  FAILED: deserialize_state returned false\n");
        return;
    }
    td::Ref<vm::Cell> cell_rt = uno_workchain::serialize_state(state_rt);
    auto root_hash_rt = cell_rt.is_null()
                          ? std::array<uint8_t, 32>{}
                          : cell_rt->get_hash().bits().as_array<32>();
    if (root_hash_1 != root_hash_rt) {
        tprintf("  FAILED: state-root drift after round-trip\n");
        return;
    }

    // (5) run #2: fresh state, same valid order, different invalid shuffle.
    UnoShardState state_2 = UnoShardState::make_empty();
    auto invalid_shuffled_2 = invalid;
    std::shuffle(invalid_shuffled_2.begin(), invalid_shuffled_2.end(), rng);
    apply_batch(state_2, valid, invalid_shuffled_2);
    td::Ref<vm::Cell> cell_2 = uno_workchain::serialize_state(state_2);
    auto root_hash_2 = cell_2.is_null()
                         ? std::array<uint8_t, 32>{}
                         : cell_2->get_hash().bits().as_array<32>();

    if (root_hash_1 != root_hash_2) {
        tprintf("  FAILED: invalid-tx ordering affects state root (consensus bug!)\n");
        return;
    }

    tprintf("  PASSED (1000v + 100i; root hash stable across serialise RT and invalid shuffle)\n");
#endif  // UNO_P4_READY
}

int main() {
    tprintf("Uno Workchain — §12 P.4 restart-survival\n");
    tprintf("=========================================\n\n");

    test_restart_survival_round_trip();

    tprintf("\nTotal: passed=%d, failures=%d, skips=%d\n",
            g_passes.load(), g_failures.load(), g_skips.load());
    return g_failures.load() == 0 ? 0 : 1;
}
