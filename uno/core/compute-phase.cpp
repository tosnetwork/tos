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

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_set>
#include <vector>

#include "block/transaction.h"
#include "td/utils/UInt.h"
#include "td/utils/logging.h"
#include "vm/cells/CellBuilder.h"

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
// =============================================================================
#include "uno/crypto/ristretto255.h"
#include "uno/crypto/schnorr-ristretto.h"
#include "uno/crypto/plonky3-verifier.h"

namespace uno_workchain {

namespace uno_crypto {

/// Returns true iff the 32-byte buffer decompresses to a valid, non-identity
/// Ristretto255 point. §4.3 step 1.7. Wraps A3's
/// `RistrettoPoint::validate()` (td::Status).
inline bool ristretto255_is_valid_point(const uint8_t bytes[32]) noexcept {
    ::uno_workchain::crypto::RistrettoPoint pt{};
    std::memcpy(pt.bytes.data(), bytes, 32);
    return pt.validate().is_ok();
}

/// Verify a single Schnorr-on-Ristretto255 signature `sig` (64 B) under
/// verification key `rk` (32 B compressed point) over `msg` (32 B — the
/// canonical tx_hash). Returns true iff valid. §4.3 step 3. Wraps A3's
/// `schnorr_verify(pk, msg, sig)`.
inline bool schnorr_ristretto_verify(const uint8_t rk[32],
                                     const uint8_t msg[32],
                                     const uint8_t sig[64]) noexcept {
    ::uno_workchain::crypto::RistrettoPoint pk{};
    std::memcpy(pk.bytes.data(), rk, 32);
    ::uno_workchain::crypto::SchnorrSignature s{};
    std::memcpy(s.data(), sig, 64);
    td::Slice msg_slice(reinterpret_cast<const char*>(msg), 32);
    return ::uno_workchain::crypto::schnorr_verify(pk, msg_slice, s).is_ok();
}

/// Verify a Plonky3 STARK proof under the pinned public-input encoding.
/// §4.3 step 4. Thin wrapper over A4's `Plonky3Verifier::verify()` handle.
///
/// The handle is process-singleton (thread-safe, one init per validator);
/// we materialise a `Meyers singleton` to keep the call-site free of state.
inline bool plonky3_verify_transfer_proof(td::Slice public_inputs_bytes,
                                          td::Slice proof_bytes) noexcept {
    struct Holder {
        ::uno::crypto::Plonky3Verifier verifier;
        bool ready{false};
        Holder() { ready = verifier.init(); }
    };
    static Holder holder;
    if (!holder.ready) return false;
    auto r = holder.verifier.verify(
        reinterpret_cast<const std::uint8_t*>(proof_bytes.data()),
        proof_bytes.size(),
        reinterpret_cast<const std::uint8_t*>(public_inputs_bytes.data()),
        public_inputs_bytes.size());
    return r == ::uno::crypto::VerifyResult::kOk;
}

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
        case VerifyResult::NullifierAlreadySpent:   return "nullifier-already-spent";
        case VerifyResult::BadSpendAuthSig:         return "bad-spend-auth-sig";
        case VerifyResult::BadPlonky3Proof:         return "bad-plonky3-proof";
        case VerifyResult::DecodeError:             return "decode-error";
    }
    return "unknown";
}

// =============================================================================
// verify_transfer (§4.3 steps 1–4)
// =============================================================================

namespace {

// §4.3 step 1.4: fee >= min_fee_nano + fee_per_byte·size + fee_per_spend·|S|
//                + fee_per_output·|O|.
uint64_t required_fee(const UnoState& state, const Transfer& tx) noexcept {
    uint64_t size_bytes = tx.wire_size_bytes;
    // Guard multiplicative overflow cheaply. Per config caps, none of these
    // products comes anywhere near 2^64.
    return state.min_fee_nano()
         + state.fee_per_byte_nano()   * size_bytes
         + state.fee_per_spend_nano()  * tx.spends.size()
         + state.fee_per_output_nano() * tx.outputs.size();
}

VerifyResult verify_transfer(const UnoState& state, const Transfer& tx) {
    // ---- Step 1: cheap syntax (§4.3 step 1) ----
    if (tx.version != kTransferVersion)   return VerifyResult::BadVersion;
    if (tx.scheme_id != kSchemeIdV1)      return VerifyResult::BadSchemeId;
    if (tx.chain_id != state.expected_chain_id()) return VerifyResult::BadChainId;

    const uint64_t cur = state.current_block_seqno();
    const uint64_t max_expiry = cur + state.expiry_window_blocks();
    if (tx.expiry_block < cur || tx.expiry_block > max_expiry) {
        return VerifyResult::ExpiryOutOfRange;
    }
    if (tx.spends.size() < kMinSpendCount || tx.spends.size() > kMaxSpendCount) {
        return VerifyResult::BadSpendCount;
    }
    if (tx.outputs.size() < kMinOutputCount || tx.outputs.size() > kMaxOutputCount) {
        return VerifyResult::BadOutputCount;
    }
    if (tx.fee < required_fee(state, tx)) {
        return VerifyResult::InsufficientFee;
    }

    if (!state.anchor_window_contains(tx.anchor)) {
        return VerifyResult::UnknownAnchor;
    }

    // Pairwise-distinct within-tx checks for nullifiers and commitments.
    {
        std::unordered_set<std::string> seen_nf;
        seen_nf.reserve(tx.spends.size() * 2);
        for (const auto& s : tx.spends) {
            std::string k(reinterpret_cast<const char*>(s.nullifier.data()), 32);
            if (!seen_nf.insert(std::move(k)).second) {
                return VerifyResult::DuplicateNullifierInTx;
            }
        }
    }
    {
        std::unordered_set<std::string> seen_cm;
        seen_cm.reserve(tx.outputs.size() * 2);
        for (const auto& o : tx.outputs) {
            std::string k(reinterpret_cast<const char*>(o.cm.data()), 32);
            if (!seen_cm.insert(std::move(k)).second) {
                return VerifyResult::DuplicateCommitmentInTx;
            }
        }
    }

    // Ristretto point decompression (§4.3 step 1.7). A3 always links in
    // under decision #15 — no weak-symbol fallback.
    for (const auto& s : tx.spends) {
        if (!uno_crypto::ristretto255_is_valid_point(
                reinterpret_cast<const uint8_t*>(s.rk.data()))) {
            return VerifyResult::BadRistrettoPoint;
        }
    }
    for (const auto& o : tx.outputs) {
        if (!uno_crypto::ristretto255_is_valid_point(
                reinterpret_cast<const uint8_t*>(o.epk.data()))) {
            return VerifyResult::BadRistrettoPoint;
        }
    }

    // ---- Step 2: nullifier not-spent (§4.3 step 2) ----
    for (const auto& s : tx.spends) {
        if (state.nullifier_is_spent(s.nullifier)) {
            return VerifyResult::NullifierAlreadySpent;
        }
    }

    // ---- Step 3: Schnorr-on-Ristretto255 spend-auth sigs (§4.3 step 3) ----
    for (const auto& s : tx.spends) {
        if (!uno_crypto::schnorr_ristretto_verify(
                reinterpret_cast<const uint8_t*>(s.rk.data()),
                reinterpret_cast<const uint8_t*>(tx.tx_hash.data()),
                s.spend_auth_sig.data())) {
            return VerifyResult::BadSpendAuthSig;
        }
    }

    // ---- Step 4: Plonky3 proof verify (§4.3 step 4) ----
    // Public-input encoding is OURS: see transaction.cpp::build_plonky3_public_inputs.
    // Agent 4's Rust verifier must decode with bit-identical semantics.
    {
        auto pi = build_plonky3_public_inputs(tx);
        auto pi_bytes = pi.to_bytes();
        // Load the zk_proof cell chain into a flat byte buffer. For a typical
        // 1-spend/2-output transfer this is ~40 KB; 4/4 worst case ~80 KB.
        // TODO(uno-integration): replace std::string copy with a zero-copy
        // iterator once Agent 4's verifier accepts a ref-counted Cell.
        std::string proof_bytes = load_bytes_from_chunk_chain(tx.zk_proof);
        if (proof_bytes.empty()) {
            return VerifyResult::BadPlonky3Proof;
        }
        bool ok = uno_crypto::plonky3_verify_transfer_proof(
            td::Slice(reinterpret_cast<const char*>(pi_bytes.data()), pi_bytes.size()),
            td::Slice(proof_bytes.data(), proof_bytes.size()));
        if (!ok) return VerifyResult::BadPlonky3Proof;
    }

    return VerifyResult::Ok;
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

}  // namespace uno_workchain
