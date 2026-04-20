/*
    Uno Workchain — compute phase adapter.

    Bridges the host-chain transaction lifecycle to the Uno shielded-pool
    state machine. Implements `verify_transfer` + `apply_transfer` per §4.3
    of doc/uno-workchain.md.

    `run_compute_phase()` is registered with `uno_workchain_dispatch` at
    startup (see `uno/core/init.{h,cpp}`). When the host chain identifies a
    transaction on wc=2, it calls the dispatcher → this function instead of
    running TVM. The function:

      1. Extracts the `Transfer` envelope from the message body.
      2. Runs the full §4.3 deterministic verify chain:
         a. cheap syntax + anchor-window membership
         b. nullifier-set not-spent
         c. Schnorr-on-Ristretto255 spend-auth sigs
         d. Plonky3 proof verify (public inputs pinned by
            `uno_workchain::build_plonky3_public_inputs`)
      3. On Ok: runs `apply_transfer` (appends commitments, inserts
         nullifiers, bumps stats). On any failure: zero state delta.
      4. Writes the result back into the host-chain ComputePhase structure.

    Source: TOS-specific adapter.
*/
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "block/transaction.h"  // block::ComputePhase
#include "td/utils/UInt.h"
#include "vm/cells/Cell.h"
#include "vm/cells/CellSlice.h"

namespace uno_workchain {

struct Transfer;  // uno/core/transaction.h — full def used by
                  // `run_compute_phase_batch` (§13 P.3).


// ---------------------------------------------------------------------------
// UnoState — minimal surface consumed by the compute phase.
//
// This class is the contract between compute-phase (owned by Agent 5) and
// the concrete state implementation (owned by Agent 1). The full UnoShardState
// struct in `uno/core/state.h` will derive from this and add the cell-native
// serializer, block-filter accumulator, and so on.
//
// Keep this base class small and pure-virtual — it is the stable compile-time
// coupling point. All mutation methods are only ever called from
// apply_transfer; verify only reads.
// ---------------------------------------------------------------------------
class UnoState {
public:
    virtual ~UnoState() = default;

    // §5.4 anchor window — returns true iff `anchor` matches one of the last
    // N commitment_tree_roots.
    virtual bool anchor_window_contains(const td::Bits256& anchor) const = 0;

    // §5.3 nullifier set — bool: has-been-spent. Consults LRU, falls back to
    // the cell-dict for LRU misses (see §5.3).
    virtual bool nullifier_is_spent(const td::Bits256& nf) const = 0;

    // Mutators (only called from apply_transfer; never from verify).
    virtual void append_commitment(const td::Bits256& cm) = 0;
    virtual void insert_nullifier(const td::Bits256& nf) = 0;
    virtual void accumulate_filter_tag(uint16_t filter_tag) = 0;
    virtual void bump_stats(uint64_t fee, uint64_t note_count_delta) = 0;

    // Serialization entry point for cp.new_data. Agent 1 owns cell-state.cpp.
    // Returns a cell whose root is the canonical UnoShardState (§5.1).
    virtual td::Ref<vm::Cell> serialize_to_cell() const = 0;

    // Consensus-visible config view. These come from ConfigParam 84 (§10.2)
    // snapshotted into the state at block start.
    virtual uint32_t expected_chain_id() const    = 0;
    virtual uint64_t current_block_seqno() const  = 0;
    virtual uint32_t expiry_window_blocks() const = 0;
    virtual uint64_t min_fee_nano() const         = 0;
    virtual uint64_t fee_per_byte_nano() const    = 0;
    virtual uint64_t fee_per_spend_nano() const   = 0;
    virtual uint64_t fee_per_output_nano() const  = 0;
};

/// The return of `verify_transfer`. `Ok` means all §4.3 checks passed and
/// `apply_transfer` may safely mutate state. Any other value is a
/// deterministic reject — no partial apply.
enum class VerifyResult : int {
    Ok                          = 0,
    // cheap-syntax rejects (§4.3 step 1)
    BadVersion                  = 1,
    BadSchemeId                 = 2,
    BadChainId                  = 3,
    ExpiryOutOfRange            = 4,
    BadSpendCount               = 5,
    BadOutputCount              = 6,
    InsufficientFee             = 7,
    UnknownAnchor               = 8,
    DuplicateNullifierInTx      = 9,
    DuplicateCommitmentInTx     = 10,
    BadRistrettoPoint           = 11,
    // nullifier set (§4.3 step 2)
    NullifierAlreadySpent       = 20,
    // sig verify (§4.3 step 3)
    BadSpendAuthSig             = 30,
    // proof verify (§4.3 step 4)
    BadPlonky3Proof             = 40,
    // catch-all (decode / codec)
    DecodeError                 = 90,
};

const char* verify_result_name(VerifyResult r) noexcept;

/// Run the Uno compute phase for a transaction targeting wc=2.
///
/// Called from the dispatcher (installed at startup by `init_uno_workchain`).
///
/// @param cp          ComputePhase structure to populate with results.
/// @param in_msg_body Body cell slice (Transfer wire payload per §4.1).
/// @param gas_limit   Advisory gas limit (Uno has no VM; see §8.4).
/// @param state       Mutable UnoShardState (Agent 1's in-memory struct).
/// @param block_seqno Host-chain block sequence number.
/// @param timestamp   Host-chain block Unix timestamp.
/// @param rand_seed   Host-chain 256-bit block random seed (unused; Uno is
///                    deterministic).
/// @return            true if the compute phase completed (even on reject);
///                    false only on infrastructure failure.
bool run_compute_phase(
    block::ComputePhase& cp,
    vm::CellSlice& in_msg_body,
    uint64_t gas_limit,
    UnoState& state,
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32]);

// ---------------------------------------------------------------------------
// Batch entry point — §13 P.3 parallel verify.
//
// `run_compute_phase_batch` is the block-level compute phase used by a
// collator that has a list of N pre-decoded Transfers in hand. It:
//
//   1. Dispatches the §4.3 step 1–4 verify of every Transfer through the
//      installed `ParallelVerifyPool` (falling back to serial verify if
//      no pool is installed).
//   2. Serially applies `apply_transfer` in declared tx-order for every
//      result == Ok. Tx-order preservation is the load-bearing invariant
//      that §12 P.5 "Cross-validator determinism" depends on.
//
// Returns the per-tx VerifyResults in input order, one per Transfer. The
// caller populates the per-tx `ComputePhase` records from these results;
// the host-chain tx-lifecycle loop already ran `decode_transfer` and set
// up the `ComputePhase` skeleton for each tx.
//
// Thread safety: callers MUST hold a unique_lock on the backing
// `UnoState::mutex()` for the duration of the call. Parallel verify
// reads through the `const UnoState&` surface only; the serial apply
// path then does the mutations under the same lock.
// ---------------------------------------------------------------------------
std::vector<VerifyResult> run_compute_phase_batch(
    UnoState&               state,
    const Transfer*         txs,
    std::size_t             n_txs);

}  // namespace uno_workchain
