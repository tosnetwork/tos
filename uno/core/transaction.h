/*
    Uno Workchain — Transfer wire codec.

    Decode / encode the `Transfer` transaction envelope per §4.1 of
    doc/uno-workchain.md, plus canonical `tx_hash` computation (the message
    signed by each `spend_auth_sig` and the Plonky3 public-input digest
    anchor).

    Layout recap (logical §4.1 field order):
      version:uint8 = 1
      scheme_id:uint8 = 0x01
      chain_id:uint32
      anchor:bits256
      expiry_block:uint64
      fee:uint64
      spend_count:uint8   (1..4)
      output_count:uint8  (1..4)
      spends[spend_count]:SpendDescription
      outputs[output_count]:OutputDescription
      zk_proof:^Cell   (Plonky3 STARK proof; canonical §4.1a chunk tree)

    SpendDescription (128 B payload):
      nullifier:bits256 || rk:bits256 || spend_auth_sig:bits512

    OutputDescription (146 B inline payload + 2 refs):
      cm:bits256 || epk:bits256 || filter_tag:bits16
      enc_ciphertext:^Cell
      mlkem_ct:^Cell
      out_ciphertext:bytes[80]

    Physical BoC shape (§17 ≤5-level-walk constraint — fan-out instead of a
    deep linear chain):

      root cell (448 bits inline = §4.1 header exactly)
        ref[0] → spends_root (empty inline, `spend_count` refs)
                  ref[i] → per_spend[i]
                             inline: first 127 B of the 128 B spend payload
                             ref[0] → 1-byte continuation cell (8 bits, 0 refs)
        ref[1] → outputs_root (empty inline, `output_count` refs)
                  ref[j] → per_output[j]
                             inline: first 127 B of the 146 B output inline payload
                             ref[0] → 19-byte continuation cell (152 bits, 0 refs)
                             ref[1] → enc_ciphertext
                             ref[2] → mlkem_ct
        ref[2] → zk_proof chunk tree

    Max walk depth from root (not counting the enc_ct / mlkem_ct / zk_proof
    internal chunk trees, which own their own depth budgets per §17.1): **4**
    levels — tight under the ≤5 bound for all 1..4 × 1..4 shapes.

    Source: TOS-specific adapter — consensus-critical codec.
*/
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "td/utils/SharedSlice.h"
#include "td/utils/Slice.h"
#include "td/utils/buffer.h"
#include "td/utils/UInt.h"
#include "vm/cells/Cell.h"
#include "vm/cells/CellSlice.h"

namespace uno_workchain {

// ---------------------------------------------------------------------------
// Fixed wire constants (mirror §4.1)
// ---------------------------------------------------------------------------

// `kTransferVersion` and `kSchemeIdV1` are canonically defined in
// `uno/core/workchain.h`. We gate the transaction.h-local copies behind
// a guard so a TU that pulls in BOTH headers (compute-phase.cpp after
// the MineUno dispatch addition — transaction.h + mine_uno.h → workchain.h)
// does not see a duplicate-definition error. TUs that include transaction.h
// without workchain.h (older test files) still get the constant via the
// fallback branch; the numeric value is identical.
#ifndef UNO_WORKCHAIN_H_  // defined by uno/core/workchain.h
constexpr uint8_t  kTransferVersion       = 1;       // byte 0
constexpr uint8_t  kSchemeIdV1            = 0x01;    // byte 1 — Plonky3 / Goldilocks / Poseidon2
#endif
constexpr uint8_t  kMaxSpendCount         = 4;       // §10.2
constexpr uint8_t  kMaxOutputCount        = 4;       // §10.2
constexpr uint8_t  kMinSpendCount         = 1;
constexpr uint8_t  kMinOutputCount        = 1;
constexpr size_t   kOutCiphertextBytes    = 80;      // inline AEAD-encrypted memo (ovk-recoverable)
constexpr size_t   kSpendInlineBytes      = 32 + 32 + 64;     // 128
constexpr size_t   kOutputInlineBytes     = 32 + 32 + 2 + 80; // 146 (incl. filter_tag, excl. refs)
constexpr size_t   kTransferHeaderBytes   = 1 + 1 + 4 + 32 + 8 + 8 + 1 + 1; // 56

// ---------------------------------------------------------------------------
// Structured types
// ---------------------------------------------------------------------------

struct SpendDescription {
    td::Bits256 nullifier;
    td::Bits256 rk;                          // compressed Ristretto255 point
    std::array<uint8_t, 64> spend_auth_sig;  // Schnorr-on-Ristretto255 over tx_hash
};

struct OutputDescription {
    td::Bits256 cm;
    td::Bits256 epk;                              // compressed Ristretto255 point
    uint16_t    filter_tag;
    td::Ref<vm::Cell> enc_ciphertext;             // ~580 B ChaCha20-Poly1305 payload
    td::Ref<vm::Cell> mlkem_ct;                   // 1088 B ML-KEM-768 ciphertext
    std::array<uint8_t, kOutCiphertextBytes> out_ciphertext;
};

struct Transfer {
    uint8_t  version{kTransferVersion};
    uint8_t  scheme_id{kSchemeIdV1};
    uint32_t chain_id{0};
    td::Bits256 anchor;
    uint64_t expiry_block{0};
    uint64_t fee{0};                              // plaintext, native nano-units
    std::vector<SpendDescription>  spends;
    std::vector<OutputDescription> outputs;
    td::Ref<vm::Cell> zk_proof;                   // Plonky3 STARK proof chunk tree

    // Filled by the decoder so apply_transfer / gas accounting can re-use them
    // without re-serializing.
    size_t      wire_size_bytes{0};               // full inline+ref tx size in bytes (§4.3 step 1.4)
    td::Bits256 tx_hash{};                        // canonical hash per §4.1
};

// ---------------------------------------------------------------------------
// Error descriptor
// ---------------------------------------------------------------------------

struct TransferDecodeError {
    std::string reason;
};

using DecodeResult = std::variant<Transfer, TransferDecodeError>;

// ---------------------------------------------------------------------------
// Decode / encode
// ---------------------------------------------------------------------------

/// Decode a Transfer from a message-body CellSlice.
///
/// The body is the CellSlice the dispatcher hands to the compute phase. Layout
/// matches §4.1: `56 B header + spends + outputs + ^zk_proof`. Inline data
/// may overflow into continuation cells via the TOS cell chain; this decoder
/// transparently walks refs if needed. Large cell-refs (enc_ciphertext,
/// mlkem_ct, zk_proof) are captured as `Ref<Cell>` handles — actual content
/// read happens downstream (verifier side).
///
/// On success, `Transfer::tx_hash` is populated via canonical_tx_hash().
/// On failure, returns TransferDecodeError with a short reason string.
DecodeResult decode_transfer(vm::CellSlice body) noexcept;

/// Convenience overload for raw byte buffers (JSON-RPC admission path).
DecodeResult decode_transfer_bytes(td::Slice raw_bytes) noexcept;

/// Serialize a Transfer into a CellSlice-friendly root cell, matching §4.1's
/// wire layout. Used by wallets / test fixtures and the JSON-RPC admission
/// path; not called from verify/apply.
td::Result<td::Ref<vm::Cell>> encode_transfer(const Transfer& tx) noexcept;

/// Serialize a Transfer into a standard BoC byte string (the on-the-wire
/// envelope). Pairs with `decode_transfer_bytes` — `encode_transfer_to_boc(tx)`
/// followed by `decode_transfer_bytes(...)` yields a Transfer whose
/// `encode_transfer_to_boc` output is byte-identical to the original.
///
/// Used by:
///   - JSON-RPC `uno_sendTransfer` (external-message envelope over hex bytes).
///   - Mempool persistence (RocksDB / on-disk encoded Transfers).
///   - Cross-validator tx-hash agreement (the BoC bytes are the hashable unit
///     above the `canonical_tx_hash` preimage level).
///
/// Mirrors the `vm::std_boc_serialize` pattern used by `evm_workchain` on
/// wc=1 (`evm/rpc/cache-db.cpp` etc.).
td::Result<td::BufferSlice> encode_transfer_to_boc(const Transfer& tx) noexcept;

// ---------------------------------------------------------------------------
// Canonical tx hash (§4.1)
// ---------------------------------------------------------------------------

/// Compute the canonical tx_hash per §4.1. Excludes spend_auth_sig[i] and the
/// ^zk_proof ref. Large fields (enc_ciphertext, mlkem_ct) are represented by
/// their cell-root hashes to keep the hash O(inline).
///
///   tx_hash = BLAKE3(
///       version(1) || scheme_id(1) || chain_id(4) || anchor(32) ||
///       expiry_block(8) || fee(8) || spend_count(1) || output_count(1) ||
///       for each spend:   nullifier(32) || rk(32)
///       for each output:  cm(32) || epk(32) || filter_tag(2) ||
///                         cell_hash(enc_ciphertext) ||
///                         cell_hash(mlkem_ct) ||
///                         out_ciphertext(80)
///   )
///
/// Deterministic, endian-stable. `chain_id`, `expiry_block`, `fee` and
/// `filter_tag` are encoded big-endian for cross-platform reproducibility.
td::Bits256 canonical_tx_hash(const Transfer& tx) noexcept;

// ---------------------------------------------------------------------------
// Note commitment (§3.2; decision #1)
// ---------------------------------------------------------------------------
//
// Wire format: `OutputDescription::cm` is a 32-byte field. The wire layout
// is UNCHANGED by decision #1; only the preimage feeding `cm` is changed
// (the four-arg `(d, pk_d, value, rcm)` form is retracted in favour of the
// five-arg form below).
//
// Per §3.2 the preimage is:
//
//     cm = Poseidon2("uno-cm-v1", d, pk_d.bytes, ivk_commitment, value, rcm)
//
// where `ivk_commitment = Poseidon2("uno-ivk-cm-v1", ivk, d)` is copied
// from the recipient's Address and `rcm = Poseidon2("uno-rcm-v1", rseed)`.
// Total Poseidon2 input: 15 Goldilocks field elements packed as in §3.2
// (d → 2 fes; pk_d.bytes → 4 fes; ivk_commitment → 4 fes; value → 1 fe;
// rcm → 4 fes). Output is truncated to 4 field elements (256 bits = 32 B).
//
// The helper below is the off-circuit computation a sender uses at
// encrypt-time; the Plonky3 AIR re-evaluates the same expression over the
// private witness to attest claim 2 (§4.2). Prover and verifier MUST agree
// bit-identically — the domain tag and absorb order here pin that contract.

/// 32-byte packed form of `rcm` (4 Goldilocks limbs, canonical LE).
struct NoteCommitmentInputs {
    std::array<uint8_t, 11>  d{};            // diversifier, 11 B
    std::array<uint8_t, 32>  pk_d_bytes{};   // compressed Ristretto255
    std::array<uint8_t, 32>  ivk_commitment{}; // decision #1, §2.6 / §3.2
    uint64_t                 value{0};       // UNO nano-units
    std::array<uint8_t, 32>  rcm{};          // Poseidon2("uno-rcm-v1", rseed)
};

/// Off-circuit `cm` computation per §3.2 (decision #1). Returns the 32-byte
/// canonical wire form (byte-identical to what the Transfer AIR opens in
/// claim 2 / claim 6). Implementation is in transaction.cpp and lives
/// alongside the codec so the cm formula and the wire format evolve
/// together.
std::array<uint8_t, 32> compute_note_commitment(
    const NoteCommitmentInputs& in) noexcept;

// ---------------------------------------------------------------------------
// Plonky3 public-input builder (§4.3 step 4, decision #5)
// ---------------------------------------------------------------------------
//
// Decision #5 (`doc/uno-workchain.md` §16): the public-input byte encoding
// is Plonky3-canonical — each Goldilocks element serializes as 8 bytes
// little-endian u64; 256-bit inputs split into 4 × u64 chunks in LE order,
// each reduced mod `p_Goldilocks = 2^64 - 2^32 + 1`. Consensus-binding;
// cross-implementation parity enforced by the golden fixture at
// `uno/test/golden/public-inputs-v1.hex` (produced by this encoder and by
// the Rust encoder in `plonky3-ffi/src/lib.rs`, consumed by both).
//
// Element order per §4.3 step 4:
//
//   1. scheme_id               (1 Goldilocks element, zero-extended)
//   2. chain_id                (1 elt)
//   3. expiry_block            (1 elt, u64 — asserted `< p_Goldilocks`)
//   4. fee                     (1 elt, u64 — asserted `< p_Goldilocks`)
//   5. anchor                  (4 elts — 256 bits in 4 × 64-bit limbs, each
//                                        reduced mod p_G)
//   6. for each spend i:       nf_i (4 elts), rk_i (4 elts)
//   7. for each output j:      cm_j (4 elts), epk_j (4 elts),
//                              filter_tag_j (1 elt, 16 bits zero-extended)
//
// Total count: 8 + 8 * spend_count + 9 * output_count Goldilocks field elts.
// Total byte length: 64 + 64·spend_count + 72·output_count bytes.

struct Plonky3PublicInputs {
    /// Canonical Goldilocks limbs (each already < p_Goldilocks).
    std::vector<uint64_t> elements;

    /// Concatenated little-endian byte encoding (for FFI hand-off). Matches
    /// §4.3 step 4 byte-for-byte; consumed by the Rust verifier via
    /// `uno_plonky3_verify(proof, public_inputs, len)`.
    std::vector<uint8_t> to_bytes() const noexcept;
};

Plonky3PublicInputs build_plonky3_public_inputs(const Transfer& tx) noexcept;

/// Return true iff every scalar that is encoded as a single Goldilocks
/// public-input element is already in canonical field range. This must be
/// checked before `build_plonky3_public_inputs()` on untrusted Transfers;
/// otherwise a malformed `fee` or `expiry_block` would reach `encode_u64()`.
bool public_input_scalars_fit_field(const Transfer& tx) noexcept;

// ---------------------------------------------------------------------------
// §4.3 step 4 encoding primitives (decision #5)
// ---------------------------------------------------------------------------

/// Goldilocks prime p = 2^64 - 2^32 + 1. Mirrors `crypto/goldilocks.h` so
/// transaction.h need not pull that header into every TU that includes it.
inline constexpr uint64_t kPGoldilocks = 0xFFFFFFFF00000001ULL;

/// Encode a u64 as one Goldilocks limb. `x` MUST satisfy `x < p_Goldilocks`;
/// an out-of-range value is a consensus fault (adversary-controlled
/// `expiry_block` / `fee` values are checked before public-input assembly per
/// §4.3 step 4 rationale). Returns `x` unchanged when in range; aborts
/// otherwise.
uint64_t encode_u64(uint64_t x) noexcept;

/// Encode a 32-byte field as 4 Goldilocks limbs (little-endian per §4.3
/// step 4). Each 8-byte chunk is read as u64-LE and reduced mod
/// p_Goldilocks; the returned 32 bytes are the canonical form (byte order
/// unchanged after reduction — each chunk's bytes are rewritten to its
/// canonical limb's LE encoding). For cryptographically-random 256-bit
/// inputs (Poseidon2 / Schnorr / hybrid-KEM outputs) the per-limb
/// reduction rate is 2^-32; aggregate 2^-30 bias is negligible for the
/// soundness analysis per decision #35.
std::array<uint8_t, 32> encode_256(const uint8_t bytes[32]) noexcept;

// ---------------------------------------------------------------------------
// Raw chunk-tree helpers (used internally; exposed for tests)
// ---------------------------------------------------------------------------

/// Store a byte blob of arbitrary length into the canonical §4.1a 4-ary
/// chunk tree. Leaves pack 1..127 bytes with 0 refs; internal cells carry
/// 0 data bits and 1..4 refs. Returns a null ref for empty input.
td::Ref<vm::Cell> store_bytes_as_chunk_chain(td::Slice bytes) noexcept;

/// Walk a chunk tree produced by `store_bytes_as_chunk_chain` and return the
/// concatenated bytes. Bounded walk (rejects malformed, non-canonical, or
/// oversized trees). Returns empty string on malformed input or null root.
std::string load_bytes_from_chunk_chain(td::Ref<vm::Cell> root) noexcept;

}  // namespace uno_workchain
