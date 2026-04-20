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

#include "uno/core/parallel-verify.h"
#include "uno/core/transaction.h"

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
        case VerifyResult::NullifierAlreadySpent:   return "nullifier-already-spent";
        case VerifyResult::BadSpendAuthSig:         return "bad-spend-auth-sig";
        case VerifyResult::BadPlonky3Proof:         return "bad-plonky3-proof";
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

    // --- Step 1: Decode Transfer wire body ---
    auto decoded = decode_transfer(in_msg_body);
    if (auto* err_ptr = std::get_if<TransferDecodeError>(&decoded)) {
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
    LOG(INFO) << "uno-workchain: apply tx=" << tx.tx_hash.to_hex()
              << " spends=" << tx.spends.size()
              << " outputs=" << tx.outputs.size()
              << " fee=" << tx.fee;

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
// The pool guarantees that `results[i]` is the outcome of
// `verify_transfer_serial(state, txs[i])` — byte-for-byte identical to a
// simple for-loop over `verify_transfer_serial`. Apply then sweeps the
// results vector linearly; for every `Ok` we mutate state in tx-order.
// `Transfer`s whose verify returned an error leave the state untouched
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

    // Serial apply in declared tx-order. Any tx whose verify failed
    // contributes zero state delta — the verify-before-mutate invariant
    // of §4.3 is preserved per-tx just as in the pre-P.3 per-tx
    // `run_compute_phase`.
    for (std::size_t i = 0; i < n_txs; ++i) {
        if (results[i] == VerifyResult::Ok) {
            apply_transfer(state, txs[i]);
        }
    }

    return results;
}

}  // namespace uno_workchain
