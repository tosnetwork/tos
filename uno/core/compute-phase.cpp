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
#include <exception>
#include <new>
#include <string>
#include <vector>

#include "block/transaction.h"
#include "td/utils/UInt.h"
#include "td/utils/logging.h"
#include "vm/cells/CellBuilder.h"
#include "vm/excno.hpp"

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
// Stage one OutputDescription's wire bytes for the light-wallet output
// index, keyed by the commitment-tree global index. Called from
// compute-phase after `apply_transfer` has appended the commitments —
// the global index that a wallet will see for output `i` is
// `base_global_index + i` where `base_global_index` is the value of
// `state.next_output_global_index()` captured BEFORE the apply.
void stage_output_bytes_from_compute(uint64_t global_index, std::string bytes);
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
        case VerifyResult::PiHeaderMismatch:        return "pi-header-mismatch";
        case VerifyResult::ZeroValueMineUno:        return "zero-value-mine-uno";
        case VerifyResult::TimestampNotMonotonic:   return "timestamp-not-monotonic";
        case VerifyResult::DecodeError:             return "decode-error";
        case VerifyResult::StateSerializationFailed: return "state-serialization-failed";
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

// Round 75 HIGH fix: gas_used → gas_fees (nanotomis) conversion rate.
// Pre-fix every accepted Uno compute path reported `cp.gas_fees` as
// null, which the wc=2 dispatch adapter (`uno/core/dispatch-engine.cpp:70`)
// mapped to `td::zero_refint()`.  The host then debited zero from the
// singleton executor's balance for any tx whose body decoded but whose
// verify (verify_transfer / apply_mine_uno) failed, even though the
// transaction was billed gas_used > 0 and the validator had already
// performed the Plonky3 verification work.  An attacker could repeat
// "valid envelope, invalid Plonky3 proof" Transfers and force every
// validator to verify an attacker-chosen proof for free.
//
// Charging `gas_fees = gas_used * kUnoGasPriceNano` plugs the leak.
// With the current cost constants a typical Transfer (~10 000 gas) bills
// 100 000 nano-units which matches `kDefaultMinFeeNano`, so successful
// Transfers do not cross-subsidise more than the existing min-fee floor.
constexpr uint64_t kUnoGasPriceNano    = 10;

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
//
// Security hardening round 1 (M-01): the `accepted` flag must be **false** for every
// failure that lands here BEFORE successful body decode (DecodeError,
// UnknownTxKind, empty body). Marking such failures as `accepted=true`
// with `gas_used=0` mirrors the EVM bug closed under audit #2 — it
// admits malformed wc=2 messages as free-blockspace transactions and
// lets a raw-BOC attacker spam the executor with zero-fee no-ops.
//
// Post-decode verify failures (verify_transfer / apply_mine_uno
// returning non-Ok on a parsed tx) are charged real `gas_used` and
// remain `accepted=true` so the verifier work is not unbilled.
void populate_reject_cp(block::ComputePhase& cp,
                        VerifyResult vr,
                        uint64_t gas_used,
                        uint64_t gas_limit,
                        bool accepted) {
    cp.success    = false;
    cp.accepted   = accepted;
    cp.gas_used   = gas_used;
    cp.gas_limit  = gas_limit;
    cp.gas_credit = 0;
    cp.gas_max    = gas_limit;
    cp.exit_code  = kExitCodeRejectBase + static_cast<int>(vr);
    cp.vm_steps   = 1;
    cp.vm_init_state_hash.set_zero();
    cp.vm_final_state_hash.set_zero();
    cp.vm_log = std::string("uno: reject ") + verify_result_name(vr);
    // Round 75 HIGH fix: bill the singleton executor for accepted-but-
    // failed verification work.  `accepted=false` paths leave gas_fees
    // null so the host's compute-phase charging block (transaction.cpp
    // `Transaction::prepare_compute_phase` custom-engine branch) skips
    // them; `accepted=true` paths must report a non-zero fee so the
    // host actually debits it from balance.
    if (accepted && gas_used > 0) {
        cp.gas_fees = td::make_refint(gas_used) * kUnoGasPriceNano;
    } else {
        cp.gas_fees = td::zero_refint();
    }
}

bool populate_serialization_failure_cp(block::ComputePhase& cp,
                                       uint64_t gas_limit,
                                       const char* phase,
                                       const char* reason) {
    cp.skip_reason = block::ComputePhase::sk_bad_state;
    populate_reject_cp(cp, VerifyResult::StateSerializationFailed, 0, gas_limit,
                       /*accepted=*/false);
    cp.vm_log = std::string("uno: state serialization failed during ") + phase +
                ": " + reason;
    return false;
}

// Round 76 HIGH fix: project gas_fees from gas_used and check against
// the singleton balance.  Returns true when the balance can cover the
// projected fees; on false the caller short-circuits and emits a
// sk_no_gas / accepted=false cp without applying state mutations or
// firing subscription side effects.
//
// Centralised so Transfer and MineUno paths share one canonical
// affordability gate; the rate (`kUnoGasPriceNano`) lives next to
// populate_reject_cp / populate_success_cp.
bool affordable_or_reject(block::ComputePhase& cp,
                          uint64_t gas_used,
                          uint64_t gas_limit,
                          const td::RefInt256& balance_nanotomis) {
    if (gas_used == 0) {
        return true;
    }
    const td::RefInt256 fees = td::make_refint(gas_used) * kUnoGasPriceNano;
    if (balance_nanotomis.is_null() ||
        td::cmp(balance_nanotomis, fees) < 0) {
        cp.skip_reason = block::ComputePhase::sk_no_gas;
        // Match the host's rejection shape: accepted=false, gas_used=0,
        // gas_fees=0 so `apply_custom_compute_output` does not double-
        // bill, and the collator's external-msg path returns -701.
        populate_reject_cp(cp, VerifyResult::InsufficientFee, 0, gas_limit,
                           /*accepted=*/false);
        cp.vm_log = "uno: insufficient singleton balance for projected fees";
        return false;
    }
    return true;
}

bool populate_success_cp(block::ComputePhase& cp,
                         UnoState& state,
                         uint64_t gas_used,
                         uint64_t gas_limit,
                         const char* phase) {
    td::Ref<vm::Cell> new_data;
    td::Ref<vm::Cell> actions;
    try {
        new_data = state.serialize_to_cell();
        if (new_data.is_null()) {
            LOG(ERROR) << "uno-workchain: serialize_to_cell returned null during " << phase;
            return populate_serialization_failure_cp(
                cp, gas_limit, phase, "serialize_to_cell returned null");
        }
        actions = vm::CellBuilder{}.finalize();
        if (actions.is_null()) {
            LOG(ERROR) << "uno-workchain: failed to build empty action cell during " << phase;
            return populate_serialization_failure_cp(
                cp, gas_limit, phase, "empty action cell build returned null");
        }
    } catch (vm::VmError&) {
        LOG(ERROR) << "uno-workchain: VM error while serializing state during " << phase;
        return populate_serialization_failure_cp(
            cp, gas_limit, phase, "vm::VmError");
    } catch (const std::bad_alloc&) {
        LOG(ERROR) << "uno-workchain: allocation failure while serializing state during " << phase;
        return populate_serialization_failure_cp(
            cp, gas_limit, phase, "std::bad_alloc");
    } catch (const std::exception& e) {
        LOG(ERROR) << "uno-workchain: exception while serializing state during "
                   << phase << ": " << e.what();
        return populate_serialization_failure_cp(
            cp, gas_limit, phase, e.what());
    }

    cp.new_data = std::move(new_data);
    cp.actions  = std::move(actions);
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
    // Round 75 HIGH fix: mirror the populate_reject_cp accepting path.
    // Pre-fix, the singleton executor balance was never debited for
    // successful Transfers either — the bug was symmetric, the
    // accepted-failure path just made it the cheapest attack.
    cp.gas_fees = (gas_used > 0)
                      ? td::make_refint(gas_used) * kUnoGasPriceNano
                      : td::zero_refint();
    return true;
}

// ---- MineUno dispatch -------------------------------------------------------

bool run_mine_uno_compute_phase(
    block::ComputePhase& cp,
    vm::CellSlice& in_msg_body,
    uint64_t gas_limit,
    UnoState& state,
    uint32_t  gen_utime,
    const td::RefInt256& balance_nanotomis) {

    auto decoded = decode_mine_uno(in_msg_body);
    if (auto* err_ptr = std::get_if<MineUnoDecodeError>(&decoded)) {
        global_metrics_registry().inc_transfers_rejected(
            RejectReason::DecodeError);
        LOG(WARNING) << "uno-workchain(mine): decode failed: " << err_ptr->reason;
        cp.skip_reason = block::ComputePhase::sk_bad_state;
        // Security hardening round 1 (M-01): pre-decode failure → cp.accepted=false.
        populate_reject_cp(cp, VerifyResult::DecodeError, 0, gas_limit,
                           /*accepted=*/false);
        cp.vm_log = std::string("uno-mine: ") + err_ptr->reason;
        return true;
    }
    MineUno tx = std::move(std::get<MineUno>(decoded));
    const uint64_t gas_used = compute_gas_used_mine_uno(tx);

    // Round 76 HIGH fix: pre-check the singleton balance BEFORE
    // apply_mine_uno mutates state and BEFORE on_included_tx_from_compute
    // fires subscription/output side effects.  When the host would
    // later reset the cp to sk_no_gas, the side effects are
    // unrecoverable from RPC consumers' point of view.
    if (!affordable_or_reject(cp, gas_used, gas_limit, balance_nanotomis)) {
        global_metrics_registry().inc_transfers_rejected(
            RejectReason::InsufficientFee);
        return true;
    }

    VerifyResult vr = apply_mine_uno(state, tx, gen_utime);
    if (vr != VerifyResult::Ok) {
        global_metrics_registry().inc_transfers_rejected(
            reject_reason_from_verify_result(static_cast<int>(vr)));
        auto h = canonical_mine_uno_hash(tx);
        LOG(INFO) << "uno-workchain(mine): reject tx=" << h.to_hex()
                  << " reason=" << verify_result_name(vr);
        // Security hardening round 1 (M-01): post-decode verify failure → still
        // cp.accepted=true so the verifier cycles are billed.
        populate_reject_cp(cp, vr, gas_used, gas_limit, /*accepted=*/true);
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

    return populate_success_cp(cp, state, gas_used, gas_limit, "MineUno");
}

}  // anonymous namespace

bool run_compute_phase(
    block::ComputePhase& cp,
    vm::CellSlice& in_msg_body,
    uint64_t gas_limit,
    UnoState& state,
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32],
    const td::RefInt256& balance_nanotomis) {
    (void)rand_seed;
    (void)block_seqno;  // Uno uses state.current_block_seqno() for determinism.

    // Masterchain `gen_utime` for the block containing this tx. Threaded
    // through to `apply_mine_uno` so the timestamp-monotonicity check and
    // the 144-solve retarget window can use a deterministic, validator-
    // shared time source. The host-chain `timestamp` field is the
    // unix-second `gen_utime` (block-auto.tlb: gen_utime:uint32). We
    // narrow to u32 here — values above 2^32 would represent dates past
    // year 2106 and are accepted only as the explicit consensus rule
    // that any future-date block-time must fit u32.
    const uint32_t gen_utime = static_cast<uint32_t>(timestamp);

    // --- Step 0: Dispatch on byte-0 discriminator ---
    // Transfer's byte 0 is `version=0x01`; MineUno's byte 0 is
    // `tx_kind=0x02`. Anything else is rejected with UnknownTxKind.
    uint8_t disc = 0;
    if (!peek_first_byte(in_msg_body, disc)) {
        global_metrics_registry().inc_transfers_rejected(
            RejectReason::DecodeError);
        LOG(WARNING) << "uno-workchain: empty / sub-byte body; cannot dispatch";
        cp.skip_reason = block::ComputePhase::sk_bad_state;
        // Security hardening round 1 (M-01): pre-decode failure → cp.accepted=false.
        populate_reject_cp(cp, VerifyResult::DecodeError, 0, gas_limit,
                           /*accepted=*/false);
        cp.vm_log = "uno: empty body";
        return true;
    }
    if (disc == kTxKindMineUno) {
        return run_mine_uno_compute_phase(cp, in_msg_body, gas_limit, state, gen_utime,
                                          balance_nanotomis);
    }
    if (disc != kTransferVersion) {
        global_metrics_registry().inc_transfers_rejected(
            RejectReason::Malformed);
        LOG(WARNING) << "uno-workchain: unknown tx discriminator byte 0x"
                     << std::hex << static_cast<int>(disc);
        cp.skip_reason = block::ComputePhase::sk_bad_state;
        // Security hardening round 1 (M-01): pre-decode failure → cp.accepted=false.
        populate_reject_cp(cp, VerifyResult::UnknownTxKind, 0, gas_limit,
                           /*accepted=*/false);
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
        // Security hardening round 1 (M-01): pre-decode failure → cp.accepted=false so
        // a malformed Transfer body cannot be admitted as a free
        // zero-gas transaction. Mirror the EVM audit #2 fix.
        cp.success = false;
        cp.accepted = false;
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

    // Round 76 HIGH fix: pre-check the singleton balance BEFORE
    // verify_transfer (so an undercollateralised tx never reaches
    // Plonky3 verification) and BEFORE apply_transfer (so we never
    // fire on_included_tx_from_compute / stage_output_bytes side
    // effects only to have the host roll the cp back to sk_no_gas).
    if (!affordable_or_reject(cp, gas_used, gas_limit, balance_nanotomis)) {
        global_metrics_registry().inc_transfers_rejected(
            RejectReason::InsufficientFee);
        return true;
    }

    // --- Step 2: verify (no mutation) ---
    VerifyResult vr = verify_transfer(state, tx);

    if (vr != VerifyResult::Ok) {
        // K-uno-metrics: bump the rejected counter with the reason label.
        global_metrics_registry().inc_transfers_rejected(
            reject_reason_from_verify_result(static_cast<int>(vr)));

        LOG(INFO) << "uno-workchain: reject tx=" << tx.tx_hash.to_hex()
                  << " reason=" << verify_result_name(vr);
        // Round 75 HIGH fix: route through populate_reject_cp so the
        // accepted-but-failed Transfer path bills the singleton
        // executor for its Plonky3 verification work.  Pre-fix this
        // inline block left `cp.gas_fees` null and the host debited
        // zero from balance.  populate_reject_cp now sets gas_fees =
        // gas_used * kUnoGasPriceNano whenever accepted=true.
        populate_reject_cp(cp, vr, gas_used, gas_limit,
                           /*accepted=*/true);

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
    // Capture the base global index BEFORE apply_transfer increments it
    // per-commitment so we can stage the per-output wire bytes with the
    // correct keys for the light-wallet output index.
    const uint64_t base_global_index = state.next_output_global_index();
    apply_transfer(state, tx);
    // K-uno-metrics: count accepted Transfers.
    global_metrics_registry().inc_transfers_admitted();
    LOG(INFO) << "uno-workchain: apply tx=" << tx.tx_hash.to_hex()
              << " spends=" << tx.spends.size()
              << " outputs=" << tx.outputs.size()
              << " fee=" << tx.fee;

    // --- Stage per-output wire bytes for the light-wallet output index.
    //     The wallet calls `uno_getOutputsAtBlock(seqno, ...)` to retrieve
    //     these bytes and trial-decrypt against its IVK; without this
    //     staging the RPC returns empty `bytes` fields and shielded notes
    //     are invisible to receiving wallets. The included-tx hook below
    //     drains the staged buffer into the per-block outputs slab.
    for (size_t i = 0; i < tx.outputs.size(); ++i) {
        std::string bytes = encode_output_description_to_bytes(tx.outputs[i]);
        if (!bytes.empty()) {
            stage_output_bytes_from_compute(base_global_index + i, std::move(bytes));
        }
    }

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
    return populate_success_cp(cp, state, gas_used, gas_limit, "Transfer");
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
    std::size_t        n_txs,
    uint32_t           gen_utime) {

    std::vector<VerifyResult> results;
    if (n_txs == 0) return results;
    results.reserve(n_txs);

    auto& mreg = global_metrics_registry();
    for (std::size_t i = 0; i < n_txs; ++i) {
        VerifyResult r = apply_mine_uno(state, txs[i], gen_utime);
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
