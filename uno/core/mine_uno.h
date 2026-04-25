/*
    Uno Workchain — MineUno transaction kind data structures (§UNO Mining).

    `MineUno` is the second transaction kind in the wc=2 protocol, alongside the
    existing `Transfer`. A MineUno transaction mints fresh UNO by solving a
    Poseidon2-over-Goldilocks proof-of-work challenge and proving the solution
    inside a Plonky3 STARK.

    Wire discriminator: tx_kind = 0x02 (see kTxKindMineUno below). Transfer
    does not carry an explicit tx_kind byte in its current v1 wire format
    (§4.1); MineUno introduces a one-byte discriminator at offset 0 of the
    MineUno envelope so dispatch can distinguish the two kinds before full decode.

    Source of truth: doc/Mining-Design.md §"UNO Mining (wc=2 STARK / Privacy)"
    AIR constraint spec: doc/uno-mine-air-constraints.md

    Phase 1 deliverable: data structures + constants only.
    Phase 2 (separate PR): Plonky3 AIR cells and constraint implementation.
    See doc/uno-mine-air-constraints.md §"Implementation Phase 2 plan" for the
    list of files to create in uno/plonky3-ffi/src/.

    Mirror: tosctl/uno/src/mine_uno.rs — field names, byte widths, and ordering
    must match exactly. Any divergence is a consensus fault.
*/
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "td/utils/Slice.h"          // td::Slice / td::BufferSlice
#include "td/utils/Status.h"         // td::Result
#include "td/utils/UInt.h"           // td::Bits256
#include "td/utils/buffer.h"         // td::BufferSlice
#include "vm/cells/Cell.h"           // td::Ref<vm::Cell>
#include "vm/cells/CellSlice.h"      // vm::CellSlice

#include "uno/core/genesis.h"        // GenesisAddress (recipient type)
#include "uno/core/mine_constants.h" // kMineHashTag, mine_reward_for_era, …
#include "uno/core/workchain.h"      // kSchemeIdV1, kHashBytes, …

namespace uno_workchain {

// ---------------------------------------------------------------------------
// Tx-kind discriminator
// ---------------------------------------------------------------------------

/// Discriminator byte occupying offset 0 of any MineUno envelope cell.
/// The Transfer kind (tx_kind = 0x01) is implied by the existing wire format
/// (its `version` byte plays the same role); MineUno introduces tx_kind as
/// a true discriminant at the envelope level so validators can dispatch
/// before parsing the rest of the header.
///
/// Wire dispatch rule (Phase 2 — `uno/core/compute-phase.cpp`):
///   byte 0 == 0x01 → decode_transfer()
///   byte 0 == 0x02 → decode_mine_uno()
///   otherwise      → reject (unknown tx kind)
constexpr uint8_t kTxKindTransfer = 0x01;   // existing; mirrored here for clarity
constexpr uint8_t kTxKindMineUno  = 0x02;   // new MineUno kind

/// Schema version for the MineUno wire envelope (analogous to
/// kTransferVersion = 1 for Transfer). Version 1 is the initial definition;
/// bumping requires a scheme_id change (§2.0) and a new AIR.
constexpr uint8_t kMineUnoVersion = 1;

// ---------------------------------------------------------------------------
// Witness (private inputs to the STARK prover)
// ---------------------------------------------------------------------------

/// MineUnoWitness carries the private data the Plonky3 prover needs to
/// generate a MineUno proof. None of these fields appear on-chain; only
/// MineUnoPublicInputs is published. The prover holds this in local memory
/// and discards it after proof generation.
///
/// Field correspondence with AIR constraints (doc/uno-mine-air-constraints.md):
///   - nonce        → Constraint 1 (PoW preimage)
///   - recipient    → Constraint 2 (cm well-form), Constraint 6 (addr valid)
///   - rseed        → Constraint 2 (rcm derivation)
///   - epoch        → Constraint 1 (PoW preimage), Constraint 3 (halving table)
///   - value_nano   → Constraint 3 (halving check), Constraint 4 (conservation)
///
/// Rust mirror: `mine_uno::MineUnoWitness` in tosctl/uno/src/mine_uno.rs.
struct MineUnoWitness {
    /// Current mining epoch (= cumulative successful solves so far).
    /// Public — included in MineUnoPublicInputs and absorbed into the AIR.
    /// The era is derived as `era_from_epoch(epoch)`.
    uint32_t epoch{0};

    /// 32-byte proof-of-work nonce (private). The miner searches for a nonce
    /// such that:
    ///   Poseidon2("uno-mine-v1" ‖ epoch ‖ nonce ‖ output_cm) < target
    /// This is the inner loop of `tosctl uno mine` (Phase 2 tosctl command).
    std::array<uint8_t, 32> nonce{};

    /// Recipient's Uno address (1259 bytes total, §2.6 layout):
    ///   11 B diversifier `d`
    ///   32 B compressed Ristretto `pk_d`
    ///   32 B `ivk_commitment = Poseidon2("uno-ivk-cm-v1", ivk, d)`
    ///   1184 B ML-KEM-768 `pk_mlkem`
    /// The address is used to derive `output_cm` (Constraint 2) and to verify
    /// field-size validity (Constraint 6). It is PRIVATE — only `output_cm`
    /// appears on-chain.
    GenesisAddress recipient;

    /// Mint amount in nano-UNO. Must equal `mine_reward_for_epoch(epoch)`.
    /// Checked by AIR Constraint 3 against the baked-in halving table.
    uint64_t value_nano{0};

    /// 32-byte randomness seed for commitment derivation.
    /// `rcm = Poseidon2("uno-rcm-v1", rseed)` (§3.1), then
    /// `output_cm = Poseidon2("uno-cm-v1", d, pk_d, ivk_commitment,
    ///                        value_nano, rcm)` (§3.2 / Constraint 2).
    /// `rseed` is private; `output_cm` is public.
    std::array<uint8_t, 32> rseed{};

    // Note: halving_era is DERIVED from epoch, not a separate field.
    // Use `era_from_epoch(epoch)` to obtain it.
};

// ---------------------------------------------------------------------------
// Public inputs (visible on-chain, included in proof verification)
// ---------------------------------------------------------------------------

/// MineUnoPublicInputs contains all data that appears on-chain alongside
/// the STARK proof. The verifier binds these fields into the proof's Fiat-
/// Shamir transcript so they cannot be swapped without invalidating the proof.
///
/// All fields are used by AIR constraints (see doc/uno-mine-air-constraints.md):
///   epoch          → Constraints 1, 3
///   target         → Constraint 1
///   value_nano     → Constraints 3, 4, 5
///   output_cm      → Constraints 1, 2
///   remaining_pre  → Constraints 4, 5
///   remaining_post → Constraints 4, 5
///
/// Rust mirror: `mine_uno::MineUnoPublicInputs` in tosctl/uno/src/mine_uno.rs.
struct MineUnoPublicInputs {
    /// Current mining epoch (= cumulative solve count before this solve).
    /// The chain's `mine_epoch` at the time of proof generation must equal
    /// this value — any mismatch is rejected in the apply step (Phase 2).
    uint32_t epoch{0};

    /// 32-byte PoW difficulty target (big-endian threshold).
    /// The PoW constraint is: Poseidon2(tag ‖ epoch ‖ nonce ‖ output_cm) < target.
    /// Sourced from chain state `mine_target` at proof-generation time.
    /// Difficulty retargeting (Phase 2) adjusts this field every solve per
    /// the [3/4, 4/3] factor bounds (kRetargetMinNum/Den, kRetargetMaxNum/Den).
    std::array<uint8_t, 32> target{};

    /// Mint amount in nano-UNO. Must match `mine_reward_for_epoch(epoch)`.
    /// Committed on-chain; re-derived in AIR Constraint 3 from the halving
    /// table, which is baked into the AIR circuit as constants.
    uint64_t value_nano{0};

    /// Note commitment for the newly minted output note.
    /// `output_cm = Poseidon2("uno-cm-v1", d, pk_d, ivk_commitment,
    ///                        value_nano, rcm)` (§3.2).
    /// This commitment is appended to the commitment tree on-chain when the
    /// MineUno tx is applied (Phase 2, `apply_mine_uno`).
    std::array<uint8_t, 32> output_cm{};

    /// Chain's `mine_remaining` counter BEFORE this transaction.
    /// Sourced from chain state at block-assembly time. The apply step checks
    /// `remaining_pre == current chain state mine_remaining`; a mismatch
    /// (race condition — another miner won first) causes the tx to fail.
    uint64_t remaining_pre{0};

    /// Chain's `mine_remaining` counter AFTER this transaction.
    /// Must satisfy: `remaining_post == remaining_pre - value_nano`.
    /// Must satisfy: `remaining_post <= remaining_pre` (no overflow, Constraint 5).
    /// The apply step writes `remaining_post` into chain state on success.
    uint64_t remaining_post{0};
};

// ---------------------------------------------------------------------------
// Full MineUno transaction envelope
// ---------------------------------------------------------------------------

/// A fully decoded MineUno transaction. This is the in-memory representation
/// after `decode_mine_uno()` (Phase 2). The witness fields are absent — they
/// are consumed by the prover before submission and discarded.
///
/// Wire layout (Phase 2 spec — not yet implemented):
///   tx_kind:uint8 = 0x02
///   version:uint8 = 1
///   scheme_id:uint8 = 0x01
///   chain_id:uint32
///   epoch:uint32
///   target:bits256
///   value_nano:uint64
///   output_cm:bits256
///   remaining_pre:uint64
///   remaining_post:uint64
///   zk_proof:^Cell   (Plonky3 STARK proof; chunk-tree layout per §4.1a)
///
/// Total inline header: 1+1+1+4+4+32+8+32+8+8 = 99 bytes (< 1023-bit cell).
struct MineUno {
    uint8_t  tx_kind{kTxKindMineUno};
    uint8_t  version{kMineUnoVersion};
    uint8_t  scheme_id{kSchemeIdV1};
    uint32_t chain_id{0};
    MineUnoPublicInputs public_inputs;

    /// Phase 2: the zk_proof ref is carried as a parsed concatenated blob
    /// `[u32 LE proof_len][proof_bytes][96 B Plonky3 PI]` — mirrors the
    /// layout emitted by the Rust `uno_mine_uno_prove` FFI (see
    /// uno/plonky3-ffi/src/lib.rs line 977). The `encode_mine_uno` path
    /// passes this blob into `store_bytes_as_chunk_chain` to build the
    /// canonical 4-ary chunk tree for the root cell's ref[0].
    std::vector<uint8_t> proof_blob{};

    // Populated by decoder (Phase 2):
    size_t      wire_size_bytes{0};
    // tx_hash is not defined for MineUno in the same way as Transfer
    // (MineUno has no spend_auth_sig). The AIR binds chain_id + epoch +
    // target + output_cm + remaining_pre + remaining_post + zk_proof.
    // A canonical MineUno message hash (for mempool dedup) is defined as:
    //   BLAKE3(tx_kind ‖ version ‖ scheme_id ‖ chain_id ‖ epoch ‖
    //          target ‖ value_nano ‖ output_cm ‖ remaining_pre ‖
    //          remaining_post)
    // Implementation: canonical_mine_uno_hash (mine_uno.cpp).
};

// ---------------------------------------------------------------------------
// Error descriptor
// ---------------------------------------------------------------------------

struct MineUnoDecodeError {
    std::string reason;
};

using MineUnoDecodeResult = std::variant<MineUno, MineUnoDecodeError>;

// ---------------------------------------------------------------------------
// Validation helpers (Phase 1 — off-circuit checks callable without a proof)
// ---------------------------------------------------------------------------

/// Check that `pi.value_nano` matches the expected halving-table reward for
/// `pi.epoch`. This is the off-circuit pre-check run by the validator before
/// invoking the STARK verifier; if it fails, the verifier is never called
/// (saves ~50ms verify time on a clearly-wrong input).
///
/// Returns true iff `pi.value_nano == mine_reward_for_epoch(pi.epoch)`.
///
/// In Phase 2 this check is performed in `apply_mine_uno()` as step 1 of the
/// tx application sequence.
inline bool check_value_matches_halving(const MineUnoPublicInputs& pi) noexcept {
    return pi.value_nano == mine_reward_for_epoch(pi.epoch);
}

/// Check that `pi.remaining_post == pi.remaining_pre - pi.value_nano` and
/// that the subtraction does not underflow (remaining_pre >= value_nano).
///
/// Returns true iff both conditions hold. A false return means:
///   - Either remaining_pre < value_nano (over-mint / cap violation, Constraint 5), or
///   - remaining_post was tampered with (conservation violation, Constraint 4).
inline bool check_conservation(const MineUnoPublicInputs& pi) noexcept {
    if (pi.remaining_pre < pi.value_nano) { return false; }
    return pi.remaining_post == (pi.remaining_pre - pi.value_nano);
}

// ---------------------------------------------------------------------------
// Phase 2 codec + hash entry points (doc/uno-mine-cpp-integration-spec.md)
// ---------------------------------------------------------------------------

/// Decode a MineUno from a message-body CellSlice. The body carries the
/// canonical §1 wire envelope: 99-byte inline header + 1 ref to the
/// zk_proof chunk tree. Returns a variant carrying either the decoded
/// MineUno (with `proof_blob` populated from the chunk tree) or a
/// `MineUnoDecodeError` with a short reason string.
MineUnoDecodeResult decode_mine_uno(vm::CellSlice body) noexcept;

/// Convenience overload for raw byte buffers (RPC / mempool admission).
MineUnoDecodeResult decode_mine_uno_bytes(td::Slice raw_bytes) noexcept;

/// Serialize a MineUno into a root cell, using the supplied `proof_blob`
/// as the zk_proof chunk-tree payload. The blob layout is
/// `[u32 LE proof_len][proof_bytes][96 B Plonky3 PI]` — identical to
/// what `uno_mine_uno_prove` returns. Round-trips cleanly with
/// `decode_mine_uno`.
td::Result<td::Ref<vm::Cell>> encode_mine_uno(const MineUno& tx,
                                              td::Slice proof_blob) noexcept;

/// BoC-wrap the result of `encode_mine_uno`. Pairs with
/// `decode_mine_uno_bytes` for JSON-RPC / mempool storage.
td::Result<td::BufferSlice> encode_mine_uno_to_boc(const MineUno& tx,
                                                   td::Slice proof_blob) noexcept;

/// Canonical RPC / mempool transaction-identity hash. Binds both the
/// 99-byte canonical header and the proof blob, so two MineUno
/// submissions that share a header but carry different proofs map to
/// distinct hashes.
///
/// Computed as
///   BLAKE3("uno-mine-tx-v1" || header(99 B) || BLAKE3(proof_blob))
/// where the header is `tx_kind || version || scheme_id || chain_id ||
/// epoch || target || value_nano || output_cm || remaining_pre ||
/// remaining_post` (multi-byte fields big-endian). The leading 14-byte
/// domain-separation prefix tags this as a v1 transaction-identity hash;
/// any future format change must rev the prefix.
td::Bits256 canonical_mine_uno_hash(const MineUno& tx) noexcept;

// ---------------------------------------------------------------------------
// Difficulty retarget helpers (uno-mine-v1 Phase 2 retarget)
// ---------------------------------------------------------------------------

/// Multiply a 256-bit big-endian unsigned integer by `mul` (u64) and divide
/// the result by `div` (u64), returning the quotient as a 256-bit big-endian
/// unsigned integer. The intermediate product is held in 320 bits so the
/// 256×64 multiply never overflows.
///
/// On overflow of the final quotient (i.e. the true quotient does not fit in
/// 256 bits) the result is saturated to 0xFF...FF and `out_overflow` is set
/// to true; otherwise `out_overflow` is false. `div == 0` is treated as
/// overflow (saturate, set flag).
///
/// Deterministic: pure integer arithmetic, no floats, identical on every
/// validator. Used by the difficulty retarget step to compute
/// `old_target * actual_seconds / expected_seconds`.
std::array<uint8_t, 32> mul_div_u256_be(const std::array<uint8_t, 32>& target,
                                        uint64_t mul,
                                        uint64_t div,
                                        bool& out_overflow) noexcept;

/// Compute the new PoW target after a retarget window closes, applying the
/// Bitcoin-style clamp to [old * kRetargetMinNum/kRetargetMinDen,
///                        old * kRetargetMaxNum/kRetargetMaxDen].
///
/// The unclamped formula is
///   `new = old * actual_seconds / kRetargetExpectedSeconds`.
///
/// `actual_seconds == 0` is treated as "max hashrate, clamp to floor"
/// (the floor is `old * kRetargetMinNum / kRetargetMinDen`, i.e. 3/4 of
/// old → harder).
///
/// Returns the post-clamp target. Pure function over the inputs; safe to
/// call from any consensus path.
std::array<uint8_t, 32> compute_retargeted_pow_target(
    const std::array<uint8_t, 32>& old_target,
    uint64_t actual_seconds) noexcept;

}  // namespace uno_workchain
