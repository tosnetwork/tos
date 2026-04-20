/*
    Uno Workchain — module initialisation implementation.

    Mirrors evm/core/init.cpp: wires up the dispatcher handler, loads state,
    pre-loads the Plonky3 verifier, warms LRU, installs end-of-block hook.

    Source: TOS-specific adapter.
*/
#include "uno/core/init.h"
#include "uno/core/compute-phase.h"

#include <memory>

#include "block/uno-workchain-dispatch.h"
#include "td/utils/logging.h"

namespace uno_workchain {

// Forward-declared from compute-phase.cpp (Agent 1 owns the real definition
// in uno/core/state.{h,cpp}). The minimal shape used by the compute path is
// pinned in compute-phase.cpp's class UnoState. Until Agent 1 lands a
// concrete implementation, `global_uno_state()` returns a hand-stubbed
// subclass that treats every anchor as unknown and every nullifier as
// unspent — enough to keep the handler registered and dispatcher-reachable
// in a skeleton build, while guaranteeing every tx rejects on anchor.
//
// TODO(uno-integration): replace with `#include "uno/core/state.h"` and
// `std::make_unique<CellUnoState>(db_root)` once Agent 1 lands.

namespace {

class StubUnoState : public UnoState {
public:
    bool anchor_window_contains(const td::Bits256&) const override { return false; }
    bool nullifier_is_spent(const td::Bits256&) const override { return false; }
    void append_commitment(const td::Bits256&) override {}
    void insert_nullifier(const td::Bits256&) override {}
    void accumulate_filter_tag(uint16_t) override {}
    void bump_stats(uint64_t, uint64_t) override {}
    td::Ref<vm::Cell> serialize_to_cell() const override { return {}; }

    uint32_t expected_chain_id() const override     { return 0; }
    uint64_t current_block_seqno() const override   { return 0; }
    uint32_t expiry_window_blocks() const override  { return 64; }
    uint64_t min_fee_nano() const override          { return 0; }
    uint64_t fee_per_byte_nano() const override     { return 0; }
    uint64_t fee_per_spend_nano() const override    { return 0; }
    uint64_t fee_per_output_nano() const override   { return 0; }
};

std::unique_ptr<UnoState> g_uno_state;

}  // anonymous namespace

UnoState& global_uno_state() {
    return *g_uno_state;
}

void init_uno_workchain(const std::string& db_root) {
    LOG(WARNING) << "uno-workchain: initialising (workchain_id=2, db_root='"
                 << db_root << "')";

    // Step 1. State. Agent 1's CellUnoState will replace the stub. Until
    // then, we install the skeleton so the dispatcher can be reached in
    // tests; the stub rejects every tx on anchor which is the safest
    // default for a not-yet-finished build.
    g_uno_state = std::make_unique<StubUnoState>();
    // TODO(uno-integration): wire Agent 1 here:
    //   g_uno_state = std::make_unique<CellUnoState>(db_root);
    //   g_uno_state->load_from_celldb();

    // Step 2. End-of-block hook. Agent 1 exposes an install point for
    // "after last tx of block N" callbacks. We register a callback that
    // pushes state.commitment_tree_root into the anchor window and compiles
    // the per-block compact filter (§2.8, §9.1).
    //
    // TODO(uno-integration): call Agent 1's register_end_of_block_hook once
    // the hook API lands. Placeholder logged for traceability.
    LOG(INFO) << "uno-workchain: end-of-block hook registration deferred "
                 "(Agent 1 pending)";

    // Step 3. Pre-load Plonky3 verifier state. Agent 4's FFI crate exposes a
    // process-lifetime initializer for FRI parameters, Poseidon2 constants,
    // and AIR precomputations; we call it once here so per-tx verify cost is
    // memory-bandwidth bound rather than parse-time bound (§8.3 point 4).
    //
    // TODO(uno-integration): declare and call
    //   extern "C" int uno_plonky3_ffi_init_verifier(void);
    // once Agent 4's cbindgen header exists. Calling this early surfaces
    // build-time linking problems (bad FRI parameter file, missing AIR
    // precompute) as node-start crashes rather than first-tx consensus
    // faults.
    LOG(INFO) << "uno-workchain: Plonky3 verifier pre-load deferred "
                 "(Agent 4 pending)";

    // Step 4. Warm the nullifier LRU (M2, §5.3). Scan the last K blocks of
    // nullifier inserts and prefill the LRU. K defaults to 1000; tunable
    // via ConfigParam 84.
    //
    // TODO(uno-integration): call Agent 2's warm_nullifier_lru(K) once
    // nullifier-set.h lands.
    LOG(INFO) << "uno-workchain: nullifier LRU warm-up deferred "
                 "(Agent 2 pending)";

    // Step 5. Register the real compute handler with the dispatcher.
    uno_workchain_dispatch::set_uno_compute_handler(
        [](block::ComputePhase& cp,
           vm::CellSlice& in_msg_body,
           uint64_t gas_limit,
           uint64_t block_seqno,
           uint64_t timestamp,
           const uint8_t rand_seed[32]) -> bool {
            return run_compute_phase(
                cp, in_msg_body, gas_limit,
                *g_uno_state,
                block_seqno, timestamp, rand_seed);
        });

    LOG(WARNING) << "uno-workchain: handler registered (wc=2 compute path live)";
}

}  // namespace uno_workchain
