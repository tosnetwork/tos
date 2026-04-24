/*
    Uno Workchain — compute phase implementation.

    Runs the full §4.3 verify chain, then apply. Verify-before-mutate is a
    hard invariant: on any failure, zero state delta (no rollback needed).

    Delegates to:
      - Agent 1's `UnoState` (anchor window, nullifier set, commitment tree,
        stats, block-filter accumulator) via the forward-declared shape
        expected by §5.1.
      - Agent 2's commitment-tree / nullifier-set / anchor-window modules
        (`uno/core/commitment-tree.h`, `nullifier-set.h`, `anchor-window.h`,
        `block-filter.h`).
      - Agent 3's off-circuit Schnorr-on-Ristretto255 verifier and Ristretto
        decompression check (`uno/crypto/schnorr-ristretto.h`,
        `uno/crypto/ristretto255.h`).
      - Agent 4's Plonky3 verifier bridge (`uno/crypto/plonky3-verifier.h`,
        Rust FFI via `uno/plonky3-ffi/`).

    Source: TOS-specific adapter.
*/
#include "uno/core/compute-phase.h"

#include <cstdint>
#include <string>
#include <vector>

#include "block/transaction.h"
#include "td/utils/UInt.h"
#include "td/utils/logging.h"
#include "vm/cells/CellBuilder.h"

#include "uno/core/mine_uno.h"
#include "uno/core/parallel-verify.h"
#include "uno/core/transaction.h"
#include "uno/rpc/metrics.h"

// =============================================================================
// Namespace-scope forward declarations for the subscription hooks owned by
// init.cpp (P.5). These fire once per included tx and once per block, so the
// wallet subscription channels (`includedTx`, `newHead`, `newAnchor`) see
// every state change without coupling compute-phase.cpp to the concrete
// LiveUnoState class.
// =============================================================================
namespace uno_workchain {
void on_included_tx_from_compute(const uint8_t tx_hash[32],
                                  uint64_t fee_nano,
                                  uint64_t n_outputs);
void on_end_of_block_from_compute();
}  // namespace uno_workchain

// =============================================================================
// A3 crypto primitives (decision #15).
//
// Decision #15 replaces the original weak-symbol `uno_crypto_fwd::` forward
// declarations with real A3 headers. A3 delivered under the
// `uno_workchain::crypto` namespace (points / signatures) and
// `uno::crypto::Plonky3Verifier` (FFI handle). A thin adapter namespace
// `uno_crypto` keeps the verify call sites signature-compatible with A5's
// original boolean-returning shape so no consensus-relevant logic moved.
//
// §13 P.3 note: the inline `verify_transfer` that used to live in this TU
// has been promoted to `uno_workchain::verify_transfer_serial` in
// `parallel-verify.{h,cpp}`, and the Plonky3 / Schnorr / Ristretto step of
// each block is now routed through `ParallelVerifyPool::verify_batch` when
// a pool is installed. When no pool is installed (skeleton builds / unit
// tests that don't call `install_parallel_verify_pool`) we fall back to
// `verify_transfer_serial`. Byte-for-byte identical post-state — the test
// in `uno/test/test-parallel-verify.cpp` pins this invariant.
// =============================================================================
// §13 P.3: ristretto255.h / schnorr-ristretto.h / plonky3-verifier.h are
// consumed only by parallel-verify.cpp after P.3. They remain transitively
// available via uno/core/parallel-verify.h → <uno_workchain API>; we keep
// the explicit includes below so this TU stays self-documenting about its
// dependency on A3 + A4 at the §4.3 verify seam.
#include "uno/crypto/ristretto255.h"       // NOLINT(unused-include) — documentary
#include "uno/crypto/schnorr-ristretto.h"  // NOLINT(unused-include) — documentary
#include "uno/crypto/plonky3-verifier.h"   // NOLINT(unused-include) — documentary

namespace uno_workchain {

namespace uno_crypto {
// Test-only proof-verify override. When non-null, parallel-verify and the
// inline single-tx path use this callback instead of the real Plonky3
// verifier. Exists ONLY for the P.5 two-wallet end-to-end demo
// (test-uno-end-to-end), which exercises the compute-phase + state-machine
// path without needing a valid Plonky3 proof (full A4 prover is P.2 work).
// Never installed in production.
using TestProofOverrideFn = bool(*)(td::Slice pi, td::Slice proof);
std::atomic<TestProofOverrideFn> g_test_proof_override{nullptr};
}  // namespace uno_crypto


// =============================================================================
// verify_result_name
// =============================================================================

const char* verify_result_name(VerifyResult r) noexcept {
    switch (r) {
        case VerifyResult::Ok:                      return "ok";
        case VerifyResult::BadVersion:              return "bad-version";
        case VerifyResult::BadSchemeId:             return "bad-scheme-id";
        case VerifyResult::BadChainId:              return "bad-chain-id";
        case VerifyResult::ExpiryOutOfRange:        return "expiry-out-of-range";
        case VerifyResult::BadSpendCount:           return "bad-spend-count";
        case VerifyResult::BadOutputCount:          return "bad-output-count";
        case VerifyResult::InsufficientFee:         return "insufficient-fee";
        case VerifyResult::UnknownAnchor:           return "unknown-anchor";
        case VerifyResult::DuplicateNullifierInTx:  return "duplicate-nullifier-in-tx";
        case VerifyResult::DuplicateCommitmentInTx: return "duplicate-commitment-in-tx";
        case VerifyResult::BadRistrettoPoint:       return "bad-ristretto-point";
        case VerifyResult::BadPublicInput:          return "bad-public-input";
        case VerifyResult::NullifierAlreadySpent:   return "nullifier-already-spent";
        case VerifyResult::BadSpendAuthSig:         return "bad-spend-auth-sig";
        case VerifyResult::BadPlonky3Proof:         return "bad-plonky3-proof";
        case VerifyResult::EpochRaceDetected:       return "epoch-race-detected";
        case VerifyResult::RemainingRaceDetected:   return "remaining-race-detected";
        case VerifyResult::BadMineTarget:           return "bad-mine-target";
        case VerifyResult::InvalidHalvingReward:    return "invalid-halving-reward";
        case VerifyResult::BadMineConservation:     return "bad-mine-conservation";
        case VerifyResult::UnknownTxKind:           return "unknown-tx-kind";
        case VerifyResult::PowHashAboveTarget:      return "pow-hash-above-target";
        case VerifyResult::DecodeError:             return "decode-error";
    }
    return "unknown";
}

// =============================================================================
// verify_transfer (§4.3 steps 1–4) — dispatched to the parallel verify pool
//
// When `install_parallel_verify_pool` has been called (production init path,
// §13 P.3), a single-tx verify routes through a batch-of-one call to the
// pool. This keeps the control-flow of `run_compute_phase` identical to
// the pre-P.3 version while exercising the same code path as the batch
// entry point used by collators that feed N-tx blocks through
// `run_compute_phase_batch`.
//
// When no pool is installed (skeleton builds / unit tests that don't wire
// init) we fall back to `verify_transfer_serial`, defined in
// `parallel-verify.cpp`. Byte-for-byte identical semantics — the test
// `test-uno-parallel-verify` pins that invariant by running both paths
// against a fixed tx stream and diffing the post-state cells.
// =============================================================================

namespace {

VerifyResult verify_transfer(const UnoState& state, const Transfer& tx) {
    // K-uno-metrics: per-tx compute-phase verify latency is measured one
    // level down — either in `verify_transfer_serial` (non-pool path) or
    // in the parallel-verify worker loop (pool path). Measuring here too
    // would double-count, so this wrapper just forwards.
    ParallelVerifyPool* pool = global_parallel_verify_pool();
    if (pool == nullptr) {
        return verify_transfer_serial(state, tx);
    }
    auto results = pool->verify_batch(state, &tx, 1);
    return results.empty() ? VerifyResult::DecodeError : results[0];
}

// =============================================================================
// apply_transfer (§4.3 step 5)
// =============================================================================

void apply_transfer(UnoState& state, const Transfer& tx) {
    // K-uno-metrics: measure the §4.3 step 5 apply duration. Apply is all
    // in-memory state mutation; under healthy load this is sub-millisecond,
    // but the histogram catches regressions in the commitment-tree /
    // nullifier-LRU paths early.
    ScopedApplyTimer _t(global_metrics_registry());

    // Declared-order application, matching §4.3 step 5. Stats are bumped once
    // at the end.
    for (const auto& o : tx.outputs) {
        state.append_commitment(o.cm);
        state.accumulate_filter_tag(o.filter_tag);
    }
    for (const auto& s : tx.spends) {
        state.insert_nullifier(s.nullifier);
    }
    state.bump_stats(tx.fee, tx.outputs.size());
}

bool has_live_nullifier_conflict(const UnoState& state, const Transfer& tx) {
    for (const auto& s : tx.spends) {
        if (state.nullifier_is_spent(s.nullifier)) {
            return true;
        }
    }
    return false;
}

// =============================================================================
// ComputePhase population (§8.4 gas reporting)
// =============================================================================

constexpr uint64_t kFixedVerifyCost    = 10'000;
constexpr uint64_t kPerByteCost        = 2;
constexpr uint64_t kPerSpendCost       = 2'000;
constexpr uint64_t kPerOutputCost      = 2'000;
constexpr int      kExitCodeRejectBase = 100;  // 100 + VerifyResult

uint64_t compute_gas_used(const Transfer& tx) noexcept {
    return kFixedVerifyCost
         + kPerByteCost   * tx.wire_size_bytes
         + kPerSpendCost  * tx.spends.size()
         + kPerOutputCost * tx.outputs.size();
}

}  // anonymous namespace

// =============================================================================
// Dispatcher entry point
// =============================================================================

// ---------------------------------------------------------------------------
// MineUno helpers (uno-mine-v1 §3 / §4)
//
// The dispatch path peeks at byte 0 of the in_msg_body slice to distinguish
// Transfer (version=0x01 as byte 0) from MineUno (tx_kind=0x02 as byte 0).
// Any other value is rejected with VerifyResult::UnknownTxKind.
// ---------------------------------------------------------------------------

namespace {

// Peek at byte 0 without advancing the slice. Returns std::nullopt if the
// slice has fewer than 8 bits.
bool peek_first_byte(const vm::CellSlice& cs, uint8_t& out) noexcept {
    if (!cs.have(8u)) return false;
    out = static_cast<uint8_t>(cs.prefetch_ulong(8));
    return true;
}

// Populate `cp` for a rejected tx with a given VerifyResult. Mirrors the
// Transfer reject-path shape exactly (same field assignments in the same
// order), so dashboards / JSON-RPC consumers see identical cp records.
void populate_reject_cp(block::ComputePhase& cp,
                        VerifyResult vr,
                        uint64_t gas_used,
                        uint64_t gas_limit) {
    cp.success    = false;
    cp.accepted   = true;
    cp.gas_used   = gas_used;
    cp.gas_limit  = gas_limit;
    cp.gas_credit = 0;
    cp.gas_max    = gas_limit;
    cp.exit_code  = kExitCodeRejectBase + static_cast<int>(vr);
    cp.vm_steps   = 1;
    cp.vm_init_state_hash.set_zero();
    cp.vm_final_state_hash.set_zero();
    cp.vm_log = std::string("uno: reject ") + verify_result_name(vr);
}

// ---- MineUno dispatch -------------------------------------------------------

bool run_mine_uno_compute_phase(
    block::ComputePhase& cp,
    vm::CellSlice& in_msg_body,
    uint64_t gas_limit,
    UnoState& state) {

    auto decoded = decode_mine_uno(in_msg_body);
    if (auto* err_ptr = std::get_if<MineUnoDecodeError>(&decoded)) {
        global_metrics_registry().inc_transfers_rejected(
            RejectReason::DecodeError);
        LOG(WARNING) << "uno-workchain(mine): decode failed: " << err_ptr->reason;
        cp.skip_reason = block::ComputePhase::sk_bad_state;
        populate_reject_cp(cp, VerifyResult::DecodeError, 0, gas_limit);
        cp.vm_log = std::string("uno-mine: ") + err_ptr->reason;
        return true;
    }
    MineUno tx = std::move(std::get<MineUno>(decoded));
    const uint64_t gas_used = compute_gas_used_mine_uno(tx);

    VerifyResult vr = apply_mine_uno(state, tx);
    if (vr != VerifyResult::Ok) {
        global_metrics_registry().inc_transfers_rejected(
            reject_reason_from_verify_result(static_cast<int>(vr)));
        auto h = canonical_mine_uno_hash(tx);
        LOG(INFO) << "uno-workchain(mine): reject tx=" << h.to_hex()
                  << " reason=" << verify_result_name(vr);
        populate_reject_cp(cp, vr, gas_used, gas_limit);
        return true;
    }

    // K-uno-metrics: count accepted MineUnos. We reuse
    // `inc_transfers_admitted()` rather than adding a new counter so the
    // existing `uno_transfers_admitted_total` dashboard-bound metric
    // reflects the total mined + transferred tx volume. A future K-mine-
    // metrics task can split these into two counters.
    global_metrics_registry().inc_transfers_admitted();
    auto tx_hash = canonical_mine_uno_hash(tx);
    LOG(INFO) << "uno-workchain(mine): apply tx=" << tx_hash.to_hex()
              << " epoch=" << tx.public_inputs.epoch
              << " value_nano=" << tx.public_inputs.value_nano;

    // Fire the same subscription hook Transfer uses so wallets see the
    // MineUno land in their includedTx channel. Fee = 0, outputs = 1.
    on_included_tx_from_compute(
        reinterpret_cast<const uint8_t*>(tx_hash.data()),
        /*fee=*/0,
        /*n_outputs=*/1);

    cp.new_data = state.serialize_to_cell();
    cp.actions  = vm::CellBuilder{}.finalize();
    cp.success    = true;
    cp.accepted   = true;
    cp.gas_used   = gas_used;
    cp.gas_limit  = gas_limit;
    cp.gas_credit = 0;
    cp.gas_max    = gas_limit;
    cp.exit_code  = 0;
    cp.vm_steps   = 1;
    cp.vm_init_state_hash.set_zero();
    cp.vm_final_state_hash.set_zero();
    return true;
}

}  // anonymous namespace

bool run_compute_phase(
    block::ComputePhase& cp,
    vm::CellSlice& in_msg_body,
    uint64_t gas_limit,
    UnoState& state,
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32]) {
    (void)timestamp;
    (void)rand_seed;
    (void)block_seqno;  // Uno uses state.current_block_seqno() for determinism.

    // --- Step 0: Dispatch on byte-0 discriminator ---
    // Transfer's byte 0 is `version=0x01`; MineUno's byte 0 is
    // `tx_kind=0x02`. Anything else is rejected with UnknownTxKind.
    uint8_t disc = 0;
    if (!peek_first_byte(in_msg_body, disc)) {
        global_metrics_registry().inc_transfers_rejected(
            RejectReason::DecodeError);
        LOG(WARNING) << "uno-workchain: empty / sub-byte body; cannot dispatch";
        cp.skip_reason = block::ComputePhase::sk_bad_state;
        populate_reject_cp(cp, VerifyResult::DecodeError, 0, gas_limit);
        cp.vm_log = "uno: empty body";
        return true;
    }
    if (disc == kTxKindMineUno) {
        return run_mine_uno_compute_phase(cp, in_msg_body, gas_limit, state);
    }
    if (disc != kTransferVersion) {
        global_metrics_registry().inc_transfers_rejected(
            RejectReason::Malformed);
        LOG(WARNING) << "uno-workchain: unknown tx discriminator byte 0x"
                     << std::hex << static_cast<int>(disc);
        cp.skip_reason = block::ComputePhase::sk_bad_state;
        populate_reject_cp(cp, VerifyResult::UnknownTxKind, 0, gas_limit);
        cp.vm_log = "uno: unknown tx kind";
        return true;
    }

    // --- Step 1: Decode Transfer wire body ---
    auto decoded = decode_transfer(in_msg_body);
    if (auto* err_ptr = std::get_if<TransferDecodeError>(&decoded)) {
        // K-uno-metrics: count decode failures under the `decode_error` label.
        global_metrics_registry().inc_transfers_rejected(
            RejectReason::DecodeError);
        LOG(WARNING) << "uno-workchain: decode failed: " << err_ptr->reason;
        cp.skip_reason = block::ComputePhase::sk_bad_state;
        cp.success = false;
        cp.accepted = true;
        cp.gas_used = 0;
        cp.gas_limit = gas_limit;
        cp.exit_code = kExitCodeRejectBase + static_cast<int>(VerifyResult::DecodeError);
        cp.vm_steps = 1;
        cp.vm_init_state_hash.set_zero();
        cp.vm_final_state_hash.set_zero();
        cp.vm_log = "uno: " + err_ptr->reason;
        return true;
    }

    Transfer tx = std::move(std::get<Transfer>(decoded));
    const uint64_t gas_used = compute_gas_used(tx);

    // --- Step 2: verify (no mutation) ---
    VerifyResult vr = verify_transfer(state, tx);

    if (vr != VerifyResult::Ok) {
        // K-uno-metrics: bump the rejected counter with the reason label.
        global_metrics_registry().inc_transfers_rejected(
            reject_reason_from_verify_result(static_cast<int>(vr)));

        LOG(INFO) << "uno-workchain: reject tx=" << tx.tx_hash.to_hex()
                  << " reason=" << verify_result_name(vr);
        cp.success    = false;
        cp.accepted   = true;
        cp.gas_used   = gas_used;
        cp.gas_limit  = gas_limit;
        cp.gas_credit = 0;
        cp.gas_max    = gas_limit;
        cp.exit_code  = kExitCodeRejectBase + static_cast<int>(vr);
        cp.vm_steps   = 1;
        cp.vm_init_state_hash.set_zero();
        cp.vm_final_state_hash.set_zero();
        cp.vm_log = std::string("uno: reject ") + verify_result_name(vr);

        // Verify-before-mutate invariant (§4.3): no state delta on reject.
        // We still set new_data so the host chain's state hash cycles on the
        // block's gen_utime — but the contents are the unchanged serialized
        // state, which means TOS's CellDb de-duplicates and no real write
        // happens. Cheaper to just leave cp.new_data null and let the host
        // chain preserve prior state; TODO confirm with Agent 1's cell-state
        // serializer contract.
        return true;
    }

    // --- Step 3: apply (mutate) ---
    apply_transfer(state, tx);
    // K-uno-metrics: count accepted Transfers.
    global_metrics_registry().inc_transfers_admitted();
    LOG(INFO) << "uno-workchain: apply tx=" << tx.tx_hash.to_hex()
              << " spends=" << tx.spends.size()
              << " outputs=" << tx.outputs.size()
              << " fee=" << tx.fee;

    // --- End-of-tx subscription notify (P.5) ---
    // §9.1 `includedTx` channel: wakes wallet subscribers that are watching
    // for their own txs to land. Payload is { tx_hash, block_seqno, fee };
    // neither amounts nor note metadata leak (the subscription manager owns
    // the JSON shape in subscriptions.cpp::notify_included_tx).
    on_included_tx_from_compute(
        reinterpret_cast<const uint8_t*>(tx.tx_hash.data()),
        tx.fee,
        tx.outputs.size());

    // --- Step 4: serialize updated state into cp.new_data (§8.4) ---
    // Agent 1's UnoState::serialize_to_cell() returns a cell whose root is
    // the canonical UnoShardState cell (§5.1). End-of-block, the state is
    // snapshotted exactly once; compute-phase writes the same "live" root on
    // every tx. TOS's CellDb WriteBatch dedupes identical cells, so the per-
    // tx write overhead is a single ref + the delta cells only.
    cp.new_data = state.serialize_to_cell();
    cp.actions  = vm::CellBuilder{}.finalize();  // Uno emits no actions

    // --- Step 5: ComputePhase bookkeeping ---
    cp.success    = true;
    cp.accepted   = true;
    cp.gas_used   = gas_used;
    cp.gas_limit  = gas_limit;
    cp.gas_credit = 0;
    cp.gas_max    = gas_limit;
    cp.exit_code  = 0;
    cp.vm_steps   = 1;
    cp.vm_init_state_hash.set_zero();
    cp.vm_final_state_hash.set_zero();

    return true;
}

// =============================================================================
// Batch entry point (§13 P.3)
//
// Collator-facing: given N pre-decoded Transfers, run the §4.3 step 1–4
// verify in parallel and apply successful ones serially in declared order.
//
// Pool verification is speculative against the block pre-state. Apply then
// sweeps the results vector linearly; for every speculative `Ok`, it first
// re-checks live nullifier state after all earlier accepted txs have mutated
// it. That preserves the same double-spend semantics as a sequential block
// execution while still parallelising proof/signature work.
//
// `Transfer`s whose verify returned an error, or whose nullifier collides
// with an earlier accepted tx in the same batch, leave the state untouched
// (the per-tx ComputePhase record — constructed by the caller — flags
// them as rejected; this function only reports the result vector).
// =============================================================================
std::vector<VerifyResult> run_compute_phase_batch(
    UnoState&               state,
    const Transfer*         txs,
    std::size_t             n_txs) {

    std::vector<VerifyResult> results;
    if (n_txs == 0) return results;

    ParallelVerifyPool* pool = global_parallel_verify_pool();
    if (pool != nullptr) {
        results = pool->verify_batch(state, txs, n_txs);
    } else {
        // No pool installed — serial fallback. Keeps skeleton / test builds
        // green and guarantees identical semantics to the parallel path.
        results.reserve(n_txs);
        for (std::size_t i = 0; i < n_txs; ++i) {
            results.push_back(verify_transfer_serial(state, txs[i]));
        }
    }

    // Serial apply in declared tx-order. Any tx whose verify failed, or whose
    // nullifier was inserted by an earlier accepted tx in this batch, contributes
    // zero state delta — the verify-before-mutate invariant of §4.3 is preserved
    // per-tx just as in the pre-P.3 per-tx `run_compute_phase`.
    //
    // K-uno-metrics: same bookkeeping as `run_compute_phase`'s single-tx
    // path — a batched collator path should report identical admitted /
    // rejected counters.
    auto& mreg = global_metrics_registry();
    for (std::size_t i = 0; i < n_txs; ++i) {
        if (results[i] == VerifyResult::Ok) {
            if (has_live_nullifier_conflict(state, txs[i])) {
                results[i] = VerifyResult::NullifierAlreadySpent;
                mreg.inc_transfers_rejected(reject_reason_from_verify_result(
                    static_cast<int>(results[i])));
                continue;
            }
            apply_transfer(state, txs[i]);
            mreg.inc_transfers_admitted();
        } else {
            mreg.inc_transfers_rejected(reject_reason_from_verify_result(
                static_cast<int>(results[i])));
        }
    }

    return results;
}

// =============================================================================
// MineUno batch entry point (uno-mine-v1 §4.3 strategy (a) — separate batch
// per tx kind)
//
// Collator-facing: given N pre-decoded MineUnos, run the §3 chain checks +
// STARK verify (via `apply_mine_uno`) serially in declared order. No
// parallel-verify pool is installed for MineUno yet — the STARK verify is
// fast enough (small AIR, single-thread) that the first pass serialises
// apply + verify together. A future K-mine-parallel-verify task can split
// these lanes apart.
//
// Tx-order preservation matters for epoch race protection: miner A's tx
// lands first → `state.mine_epoch` advances → miner B's tx sees stale
// epoch → rejected with EpochRaceDetected. This exactly mirrors Transfer's
// nullifier-already-spent semantics.
// =============================================================================
std::vector<VerifyResult> run_compute_phase_batch_mine_uno(
    UnoState&          state,
    const MineUno*     txs,
    std::size_t        n_txs) {

    std::vector<VerifyResult> results;
    if (n_txs == 0) return results;
    results.reserve(n_txs);

    auto& mreg = global_metrics_registry();
    for (std::size_t i = 0; i < n_txs; ++i) {
        VerifyResult r = apply_mine_uno(state, txs[i]);
        results.push_back(r);
        if (r == VerifyResult::Ok) {
            mreg.inc_transfers_admitted();
        } else {
            mreg.inc_transfers_rejected(
                reject_reason_from_verify_result(static_cast<int>(r)));
        }
    }
    return results;
}

// ---------------------------------------------------------------------------
// End-of-block entry point (P.5). Thin forwarder to init.cpp's hook so the
// test harness and validator-engine integration code have a single public
// symbol to call.
// ---------------------------------------------------------------------------
void end_of_block_hook() {
    on_end_of_block_from_compute();
}

// ---------------------------------------------------------------------------
// Test-only: install a proof-verify override. Passing nullptr restores the
// real Rust verifier. Used by focused C++ tests that need to drive
// post-proof compute/apply paths without carrying real Plonky3 witnesses.
// ---------------------------------------------------------------------------
void install_test_proof_override_for_test(
    bool(*fn)(td::Slice public_inputs, td::Slice proof)) {
    uno_crypto::g_test_proof_override.store(
        reinterpret_cast<uno_crypto::TestProofOverrideFn>(fn),
        std::memory_order_release);
}

}  // namespace uno_workchain
