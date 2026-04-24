/*
    Uno Workchain — MineUno wire codec + compute-phase apply (Phase 2).

    Mirror: tosctl/uno/src/mine_uno.rs (byte-identical wire layout).
    Spec:   doc/uno-mine-cpp-integration-spec.md (661-line §1–§10).

    Functions implemented:
      decode_mine_uno / decode_mine_uno_bytes   (§1 wire format)
      encode_mine_uno / encode_mine_uno_to_boc  (§1 inverse)
      canonical_mine_uno_hash                   (§2 dedup / anti-replay)
      apply_mine_uno                            (§3 9-step sequence)

    Wire layout (§1.1 — matches mine_uno.h line 179):
      Inline 99 bytes in the root cell:
        [0]       tx_kind   = 0x02       (1 byte)
        [1]       version   = 0x01       (1 byte)
        [2]       scheme_id = 0x01       (1 byte)
        [3..6]    chain_id               (4 B BE)
        [7..10]   epoch                  (4 B BE)
        [11..42]  target                 (32 B BE)
        [43..50]  value_nano             (8 B BE)
        [51..82]  output_cm              (32 B)
        [83..90]  remaining_pre          (8 B BE)
        [91..98]  remaining_post         (8 B BE)
      ref[0] → zk_proof chunk tree       (postcard-encoded blob:
                                          [u32 LE proof_len][proof][PI bytes])
    Total: 99 B inline = 792 bits, fits a single TOS cell.

    Big-endian byte order throughout (matches Transfer and Rust's
    to_wire_bytes).

    Deviations from spec:
      - Spec §1.1 mentions 106 B / 105 B inline header; the struct layout in
        `mine_uno.h` line 192 (source of truth) declares 99 B
        (1+1+1+4+4+32+8+32+8+8). Rust's `encode_header` also produces 99 B.
        We follow the header.
      - Spec §1.3 claims 96 B Plonky3 public inputs; the actual Plonky3
        AIR PI shape is 12 Goldilocks fes = 96 B but the on-wire PI in
        `MineUnoPublicInputs` is 92 B BE. The 96-byte PI is produced by
        the Rust prover (`prove_mine_uno`) and concatenated into the proof
        blob (`[u32 LE proof_len][proof][96 B PI]`). The C++ apply path
        extracts both halves from the proof cell and passes them to
        `uno_mine_uno_verify` as-is; it does NOT reconstruct the 96-byte
        Plonky3 PI from the wire BE fields because the AIR PI contains a
        derived `pow_hash` field that only the prover knows.
*/
#include "uno/core/mine_uno.h"

#include <array>
#include <cstring>
#include <string>
#include <vector>

#include "td/utils/Slice.h"
#include "td/utils/logging.h"
#include "vm/boc.h"
#include "vm/cells/Cell.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"

#include "uno/core/compute-phase.h"        // UnoState, VerifyResult
#include "uno/core/transaction.h"          // store_bytes_as_chunk_chain,
                                           // load_bytes_from_chunk_chain
#include "uno/crypto/internal/blake3_adapter.h"  // canonical hash
#include "uno/crypto/plonky3-verifier.h"         // Plonky3ProofBytes / PI
extern "C" {
#include "uno_plonky3_ffi.h"                     // uno_mine_uno_verify
}

namespace uno_workchain {

namespace {

// ---------------------------------------------------------------------------
// Big-endian scalar helpers (mirrored from transaction.cpp local anonymous NS;
// kept duplicated to avoid pulling transaction.cpp internals into this TU).
// ---------------------------------------------------------------------------

inline void write_be_u32(uint8_t* p, uint32_t v) noexcept {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

inline void write_be_u64(uint8_t* p, uint64_t v) noexcept {
    for (int i = 7; i >= 0; --i) {
        p[i] = static_cast<uint8_t>(v);
        v >>= 8;
    }
}

inline uint32_t read_be_u32(const uint8_t* p) noexcept {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

inline uint64_t read_be_u64(const uint8_t* p) noexcept {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | uint64_t(p[i]);
    }
    return v;
}

// ---------------------------------------------------------------------------
// Inline header byte offsets (total 99 B). Must stay in sync with
// `encode_header` in tosctl/uno/src/mine_uno.rs.
// ---------------------------------------------------------------------------

constexpr size_t kMineUnoHeaderBytes  = 99;
constexpr size_t kMineUnoOffTxKind    = 0;     // 1 B
constexpr size_t kMineUnoOffVersion   = 1;     // 1 B
constexpr size_t kMineUnoOffSchemeId  = 2;     // 1 B
constexpr size_t kMineUnoOffChainId   = 3;     // 4 B BE
constexpr size_t kMineUnoOffEpoch     = 7;     // 4 B BE
constexpr size_t kMineUnoOffTarget    = 11;    // 32 B
constexpr size_t kMineUnoOffValueNano = 43;    // 8 B BE
constexpr size_t kMineUnoOffOutputCm  = 51;    // 32 B
constexpr size_t kMineUnoOffRemPre    = 83;    // 8 B BE
constexpr size_t kMineUnoOffRemPost   = 91;    // 8 B BE
static_assert(kMineUnoOffRemPost + 8 == kMineUnoHeaderBytes,
              "MineUno header layout must total 99 bytes");

MineUnoDecodeError decode_err(const char* s) {
    return MineUnoDecodeError{std::string{s}};
}

// Pack the 99-byte canonical header into a contiguous buffer. Used by both
// `encode_mine_uno` and `canonical_mine_uno_hash` so the preimage is
// byte-identical across the two paths.
void pack_header(const MineUno& tx, uint8_t out[kMineUnoHeaderBytes]) noexcept {
    out[kMineUnoOffTxKind]   = tx.tx_kind;
    out[kMineUnoOffVersion]  = tx.version;
    out[kMineUnoOffSchemeId] = tx.scheme_id;
    write_be_u32(out + kMineUnoOffChainId, tx.chain_id);
    write_be_u32(out + kMineUnoOffEpoch, tx.public_inputs.epoch);
    std::memcpy(out + kMineUnoOffTarget, tx.public_inputs.target.data(), 32);
    write_be_u64(out + kMineUnoOffValueNano, tx.public_inputs.value_nano);
    std::memcpy(out + kMineUnoOffOutputCm, tx.public_inputs.output_cm.data(), 32);
    write_be_u64(out + kMineUnoOffRemPre, tx.public_inputs.remaining_pre);
    write_be_u64(out + kMineUnoOffRemPost, tx.public_inputs.remaining_post);
}

// Decode the 99-byte header into a MineUno. Does not set the `zk_proof`
// cell ref or `wire_size_bytes`.
MineUnoDecodeResult decode_header_into(const uint8_t buf[kMineUnoHeaderBytes]) noexcept {
    MineUno tx;
    tx.tx_kind   = buf[kMineUnoOffTxKind];
    if (tx.tx_kind != kTxKindMineUno) {
        return decode_err("tx_kind byte != 0x02");
    }
    tx.version   = buf[kMineUnoOffVersion];
    if (tx.version != kMineUnoVersion) {
        return decode_err("version byte != kMineUnoVersion");
    }
    tx.scheme_id = buf[kMineUnoOffSchemeId];
    if (tx.scheme_id != kSchemeIdV1) {
        return decode_err("scheme_id byte != kSchemeIdV1");
    }
    tx.chain_id = read_be_u32(buf + kMineUnoOffChainId);
    tx.public_inputs.epoch      = read_be_u32(buf + kMineUnoOffEpoch);
    std::memcpy(tx.public_inputs.target.data(), buf + kMineUnoOffTarget, 32);
    tx.public_inputs.value_nano = read_be_u64(buf + kMineUnoOffValueNano);
    std::memcpy(tx.public_inputs.output_cm.data(), buf + kMineUnoOffOutputCm, 32);
    tx.public_inputs.remaining_pre  = read_be_u64(buf + kMineUnoOffRemPre);
    tx.public_inputs.remaining_post = read_be_u64(buf + kMineUnoOffRemPost);
    return tx;
}

// Safe wrapper: load ordinary cell slice; rejects special cells and catches
// any stray exceptions (mirrors the helper in transaction.cpp).
bool load_ordinary_cell_slice(const td::Ref<vm::Cell>& cell,
                              vm::CellSlice& out) noexcept {
    if (cell.is_null()) return false;
    try {
        bool is_special = false;
        out = vm::load_cell_slice_special(cell, is_special);
        if (is_special) return false;
        return true;
    } catch (...) {
        return false;
    }
}

// ---------------------------------------------------------------------------
// Proof-blob layout (§1.4)
//
// The proof cell carries a postcard-encoded Plonky3 STARK proof
// concatenated with the 96-byte Plonky3 public-input encoding. The layout
// (produced by `uno_mine_uno_prove` on the Rust side — see lib.rs line 977)
// is:
//     [u32 LE proof_len] [proof_bytes ... proof_len] [pi_bytes ... 96 B]
//
// This function pulls both slices out of the concatenated blob. Returns
// false if the blob is malformed or shorter than the expected PI length.
// ---------------------------------------------------------------------------
constexpr size_t kMineUnoPlonky3PiBytes = 96;

bool split_proof_blob(const std::string& blob,
                      td::Slice& out_proof,
                      td::Slice& out_pi) noexcept {
    if (blob.size() < 4 + kMineUnoPlonky3PiBytes) return false;
    const uint8_t* p = reinterpret_cast<const uint8_t*>(blob.data());
    uint32_t proof_len =
        (uint32_t(p[0])      ) |
        (uint32_t(p[1]) <<  8) |
        (uint32_t(p[2]) << 16) |
        (uint32_t(p[3]) << 24);
    // Guard against overflow — proof_len should fit the blob.
    if (4 + static_cast<uint64_t>(proof_len) + kMineUnoPlonky3PiBytes
            != blob.size()) {
        return false;
    }
    out_proof = td::Slice(reinterpret_cast<const char*>(p + 4), proof_len);
    out_pi = td::Slice(reinterpret_cast<const char*>(p + 4 + proof_len),
                       kMineUnoPlonky3PiBytes);
    return true;
}

}  // anonymous namespace

// ===========================================================================
// §1. decode_mine_uno / decode_mine_uno_bytes
// ===========================================================================

MineUnoDecodeResult decode_mine_uno(vm::CellSlice body) noexcept {
    // Inline header is 99 B = 792 bits; cell max is 1023 bits so it all
    // fits inline. Then one ref → proof chunk tree.
    if (!body.have(kMineUnoHeaderBytes * 8u)) {
        return decode_err("short inline header");
    }
    uint8_t buf[kMineUnoHeaderBytes];
    if (!body.fetch_bytes(buf, kMineUnoHeaderBytes)) {
        return decode_err("fetch_bytes failed on header");
    }

    auto decoded = decode_header_into(buf);
    if (auto* err = std::get_if<MineUnoDecodeError>(&decoded)) {
        return *err;
    }
    MineUno tx = std::move(std::get<MineUno>(decoded));

    // Require exactly 1 trailing ref (zk_proof) and no trailing inline bits.
    if (body.size() != 0) {
        return decode_err("root cell: unexpected trailing inline data");
    }
    if (body.size_refs() != 1) {
        return decode_err("root cell: expected exactly 1 ref (zk_proof)");
    }

    auto zk_ref = body.prefetch_ref(0);
    if (zk_ref.is_null()) {
        return decode_err("root cell: null zk_proof ref");
    }
    body.advance_refs(1);

    // Validate the chunk tree by decoding; same shape check Transfer uses.
    std::string proof_blob = load_bytes_from_chunk_chain(zk_ref);
    if (proof_blob.empty()) {
        return decode_err("zk_proof: malformed or empty chunk tree");
    }
    // Basic blob shape check — [u32 LE proof_len][proof][PI].
    {
        td::Slice unused_proof, unused_pi;
        if (!split_proof_blob(proof_blob, unused_proof, unused_pi)) {
            return decode_err(
                "zk_proof: blob does not match [u32 LE proof_len][proof][96 B PI]");
        }
    }

    tx.proof_blob.assign(proof_blob.begin(), proof_blob.end());
    tx.wire_size_bytes = kMineUnoHeaderBytes + proof_blob.size();
    return tx;
}

MineUnoDecodeResult decode_mine_uno_bytes(td::Slice raw_bytes) noexcept {
    if (raw_bytes.empty()) {
        return decode_err("decode_mine_uno_bytes: empty BoC input");
    }
    auto cell_r = vm::std_boc_deserialize(raw_bytes);
    if (cell_r.is_error()) {
        return decode_err("decode_mine_uno_bytes: std_boc_deserialize failed");
    }
    auto root = cell_r.move_as_ok();
    if (root.is_null()) {
        return decode_err("decode_mine_uno_bytes: null root cell from BoC");
    }
    vm::CellSlice cs;
    if (!load_ordinary_cell_slice(root, cs)) {
        return decode_err(
            "decode_mine_uno_bytes: root must be an ordinary cell");
    }
    return decode_mine_uno(cs);
}

// ===========================================================================
// §1. encode_mine_uno / encode_mine_uno_to_boc
// ===========================================================================
//
// These are declared in uno/core/transaction.h for Transfer's twin functions;
// MineUno's analogues are not yet declared in mine_uno.h. We surface them
// with the same free-function shape so unit tests / wallets can construct
// wire-format MineUno blobs for the compute-phase dispatcher.
// ---------------------------------------------------------------------------

td::Result<td::Ref<vm::Cell>> encode_mine_uno(const MineUno& tx,
                                              td::Slice proof_blob) noexcept {
    // Layout (inline 99 B, 1 ref):
    //   root.inline = 99 B canonical header
    //   root.ref[0] = zk_proof chunk tree (canonical §4.1a 4-ary)
    if (tx.tx_kind != kTxKindMineUno) {
        return td::Status::Error("encode_mine_uno: tx_kind must be 0x02");
    }
    if (proof_blob.empty()) {
        return td::Status::Error("encode_mine_uno: proof_blob must be non-empty");
    }

    uint8_t buf[kMineUnoHeaderBytes];
    pack_header(tx, buf);

    auto proof_cell = store_bytes_as_chunk_chain(proof_blob);
    if (proof_cell.is_null()) {
        return td::Status::Error(
            "encode_mine_uno: store_bytes_as_chunk_chain returned null");
    }

    vm::CellBuilder cb;
    cb.store_bytes(reinterpret_cast<const char*>(buf), kMineUnoHeaderBytes);
    cb.store_ref(proof_cell);
    return cb.finalize();
}

td::Result<td::BufferSlice> encode_mine_uno_to_boc(const MineUno& tx,
                                                   td::Slice proof_blob) noexcept {
    auto root_r = encode_mine_uno(tx, proof_blob);
    if (root_r.is_error()) return root_r.move_as_error();
    auto root = root_r.move_as_ok();
    if (root.is_null()) {
        return td::Status::Error(
            "encode_mine_uno_to_boc: encode_mine_uno returned null root");
    }
    return vm::std_boc_serialize(root);
}

// ===========================================================================
// §2. canonical_mine_uno_hash (BLAKE3 over the 99-byte preimage)
// ===========================================================================

td::Bits256 canonical_mine_uno_hash(const MineUno& tx) noexcept {
    uint8_t buf[kMineUnoHeaderBytes];
    pack_header(tx, buf);
    td::Bits256 out{};
    ::uno_workchain::crypto::internal::blake3_hash(
        td::Slice(reinterpret_cast<const char*>(buf), kMineUnoHeaderBytes),
        reinterpret_cast<uint8_t*>(out.data()));
    return out;
}

// ===========================================================================
// §3. apply_mine_uno / verify_mine_uno_chain_checks
// ===========================================================================
//
// verify_mine_uno_chain_checks is the off-circuit step sequence that DOES
// NOT require the Rust Plonky3 verifier. It is safe to call from a batch
// dispatcher as the "cheap" pre-verify lane. `apply_mine_uno` runs these
// checks first, then the FFI verify, then mutates state. State is never
// partially mutated — either all mutations apply or none do.
// ---------------------------------------------------------------------------

VerifyResult verify_mine_uno_chain_checks(const UnoState& state,
                                          const MineUno&  tx) noexcept {
    // ---- Step 0: version / scheme / chain identity ----
    if (tx.tx_kind != kTxKindMineUno)     return VerifyResult::UnknownTxKind;
    if (tx.version != kMineUnoVersion)    return VerifyResult::BadVersion;
    if (tx.scheme_id != kSchemeIdV1)      return VerifyResult::BadSchemeId;
    if (tx.chain_id != state.expected_chain_id()) {
        return VerifyResult::BadChainId;
    }

    const auto& pi = tx.public_inputs;

    // ---- Step 1: epoch race protection ----
    if (pi.epoch != state.mine_epoch()) {
        return VerifyResult::EpochRaceDetected;
    }

    // ---- Step 2: remaining balance race protection ----
    if (pi.remaining_pre != state.mine_remaining()) {
        return VerifyResult::RemainingRaceDetected;
    }

    // ---- Step 2b: target binding ----
    // The 32-byte BE target declared in the tx header must equal the live
    // chain target. This binds the proof's pow_hash (computed via the AIR
    // against no explicit target) to the current difficulty. Without this
    // check, a miner could submit a proof that passed easy-target mining
    // against a stale target. AIR does NOT include target in PI by design
    // (target is chain-state, not witness) — enforcement happens here.
    {
        const auto chain_target = state.mine_target();
        if (pi.target != chain_target) {
            return VerifyResult::BadMineTarget;
        }
    }

    // ---- Step 2c: post-cap guard ----
    // Reject value_nano == 0: after the cap era, mine_reward_for_epoch
    // returns 0 and conservation/halving both hold trivially for a no-op
    // tx (remaining_post == remaining_pre, value == 0). Without this gate
    // any party with a valid STARK proof could flood wc=2 with accepted-
    // but-free MineUno txs, each appending an output commitment cell and
    // growing state unboundedly. Also catches the degenerate case where a
    // prover accidentally proves value==0 mid-era.
    if (pi.value_nano == 0) {
        return VerifyResult::ZeroValueMineUno;
    }

    // ---- Step 5: conservation (redundant with AIR but cheap off-circuit) ----
    if (!check_conservation(pi)) {
        return VerifyResult::BadMineConservation;
    }

    // ---- Step 6: halving table / value validation ----
    if (!check_value_matches_halving(pi)) {
        return VerifyResult::InvalidHalvingReward;
    }

    return VerifyResult::Ok;
}

VerifyResult apply_mine_uno(UnoState& state, const MineUno& tx) noexcept {
    // Steps 0/1/2/5/6 live in verify_mine_uno_chain_checks.
    VerifyResult chain_r = verify_mine_uno_chain_checks(state, tx);
    if (chain_r != VerifyResult::Ok) {
        return chain_r;
    }

    // ---- Step 3: split proof blob + bind PI to header (cheap) BEFORE the
    //              expensive STARK verify, so a forged-header replay
    //              attack can't force every validator to pay the full
    //              proof-verification cost (~50ms+) on a tx that's
    //              guaranteed to fail later. PI/header binding is O(1)
    //              memcmp; do it first.
    //
    // PI layout (public_inputs_bytes, 12 × 8 = 96 LE bytes):
    //   [ 0.. 8) PI_EPOCH          u64 LE
    //   [ 8..16) PI_VALUE           u64 LE
    //   [16..48) PI_OUTPUT_CM_BASE  4 fes × 8 B LE (= 32 B cm bytes)
    //   [48..80) PI_POW_HASH_BASE   (checked in step 4 below)
    //   [80..88) PI_REMAINING_PRE   u64 LE
    //   [88..96) PI_REMAINING_POST  u64 LE
    //
    // `::Plonky3PublicInputs` / `::Plonky3ProofBytes` are the C FFI structs
    // from uno_plonky3_ffi.h (global namespace). The unqualified names
    // inside `uno_workchain` would otherwise bind to the Transfer-side
    // `uno_workchain::Plonky3PublicInputs` from transaction.h, which is a
    // completely different struct (vector<uint64_t> elements). We use
    // fully-qualified names to avoid the collision.
    {
        std::string tmp(tx.proof_blob.begin(), tx.proof_blob.end());
        td::Slice proof_slice, pi_slice;
        if (!split_proof_blob(tmp, proof_slice, pi_slice)) {
            return VerifyResult::BadPlonky3Proof;
        }
        if (pi_slice.size() != 96) {
            return VerifyResult::BadPlonky3Proof;
        }

        // ---- Step 3a: PI ↔ header binding (PRE-verify, cheap O(1)) ----
        // The STARK verifier only checks the proof against the 96-byte
        // PI blob — it does not compare those 12 Goldilocks field elements
        // to any of the per-tx header fields. Without an explicit binding
        // check, a single valid (proof, pi) pair could be submitted with
        // an arbitrarily-tampered MineUno header: the chain would run the
        // PoW/target check on the PI's pow_hash (from the proof) while
        // mutating state using `tx.public_inputs.output_cm` /
        // `remaining_post` from the header — a replay-with-forged-outputs
        // attack. Verify each non-`pow_hash` PI field byte-for-byte
        // against the header before trusting either half.
        auto pi_read_u64_le = [&](size_t off) -> uint64_t {
            uint64_t v = 0;
            for (size_t i = 0; i < 8; ++i) {
                v |= static_cast<uint64_t>(static_cast<uint8_t>(pi_slice[off + i])) << (8 * i);
            }
            return v;
        };
        const uint64_t pi_epoch          = pi_read_u64_le(0);
        const uint64_t pi_value          = pi_read_u64_le(8);
        const uint64_t pi_remaining_pre  = pi_read_u64_le(80);
        const uint64_t pi_remaining_post = pi_read_u64_le(88);
        if (pi_epoch != static_cast<uint64_t>(tx.public_inputs.epoch) ||
            pi_value != tx.public_inputs.value_nano ||
            pi_remaining_pre != tx.public_inputs.remaining_pre ||
            pi_remaining_post != tx.public_inputs.remaining_post) {
            return VerifyResult::PiHeaderMismatch;
        }
        if (std::memcmp(pi_slice.data() + 16,
                        tx.public_inputs.output_cm.data(),
                        32) != 0) {
            return VerifyResult::PiHeaderMismatch;
        }

        // ---- Step 3c: PoW difficulty threshold (cheap, BEFORE FFI verify) ----
        // pow_hash is committed in the STARK PI at indices 6..9 (4
        // Goldilocks field elements). PI wire format = N_PUBLIC_INPUTS ×
        // u64 LE (96 bytes total). pow_hash occupies bytes [48..80). The
        // miner's off-circuit `compute_mine_pow_hash` / `hash_below_target`
        // use the same byte layout and a big-endian lexicographic
        // comparison (`hash < target`). Mirror it here so the chain
        // rejects any proof whose hash does not satisfy the difficulty,
        // regardless of whether the AIR itself allowed it. AIR does not
        // constrain hash < target because target is chain-state, not
        // witness — this C++ gate is the only place difficulty is enforced.
        //
        // This check is O(1) memcmp; run it BEFORE the expensive STARK
        // verify so a non-winning but otherwise valid proof can't force
        // every validator to pay full STARK verification cost on a tx
        // that's guaranteed to fail. Combined with step 3a (PI/header
        // bind) the cheap-rejects-first-then-expensive pattern caps the
        // worst-case validator CPU per malicious submission at O(1).
        static constexpr size_t kPowHashPiOffset = 6 * 8;  // PI_POW_HASH_BASE × 8
        if (pi_slice.size() < kPowHashPiOffset + 32) {
            return VerifyResult::BadPlonky3Proof;
        }
        std::array<uint8_t, 32> pow_hash{};
        std::memcpy(pow_hash.data(), pi_slice.data() + kPowHashPiOffset, 32);
        if (!(pow_hash < tx.public_inputs.target)) {
            // pow_hash >= target — difficulty not met.
            return VerifyResult::PowHashAboveTarget;
        }

        // ---- Step 3d: FFI verify (Rust Plonky3 STARK) — expensive ----
        // Now that header/PI consistency + PoW threshold are proven, pay
        // the STARK cost. AIR enforces that the committed pow_hash IS
        // the correct Poseidon2 output for (epoch, nonce, output_cm) so
        // an attacker can't forge a low pow_hash without a valid proof.
        ::Plonky3ProofBytes fp{
            reinterpret_cast<const uint8_t*>(proof_slice.data()),
            proof_slice.size()
        };
        ::Plonky3PublicInputs fpi{
            reinterpret_cast<const uint8_t*>(pi_slice.data()),
            pi_slice.size()
        };
        int32_t rc = uno_mine_uno_verify(fp, fpi);
        if (rc != 0) {
            return VerifyResult::BadPlonky3Proof;
        }
    }

    // ---- Step 7: output commitment uniqueness ----
    // The AIR already enforces output_cm derivation from a fresh
    // (nonce, rseed) pair, so a collision requires a Poseidon2 collision.
    // We intentionally do not scan the commitment tree here (O(N) work);
    // the abstract UnoState has no `contains_commitment` method, and
    // CommitmentTree's frontier encoding does not preserve a membership
    // index. Deferred to a future tree-wide membership index.

    // ---- Step 8: state mutations (epoch + remaining + commitment) ----
    state.advance_mine_state(tx.public_inputs.remaining_post);
    state.append_commitment(tx.public_inputs.output_cm);

    // ---- Step 9: block-filter accumulation + stats ----
    // MineUno has no explicit filter_tag (unlike Transfer's per-output
    // 16-bit tag); we use the low 16 bits of output_cm as a deterministic,
    // AIR-verifiable proxy so miner-produced notes still appear in the
    // block filter for recipient wallet scans. Fee is 0 (no explicit fee
    // field on MineUno; miners are compensated by the minting itself).
    uint16_t filter_tag = static_cast<uint16_t>(
        (uint16_t(tx.public_inputs.output_cm[0]) << 8) |
        uint16_t(tx.public_inputs.output_cm[1]));
    state.accumulate_filter_tag(filter_tag);
    state.bump_stats(/*fee=*/0, /*note_count_delta=*/1);

    return VerifyResult::Ok;
}

// ===========================================================================
// §4.3 gas costing (matches compute_gas_used for Transfer)
// ===========================================================================
//
// MineUno has no variable-length vectors (spends / outputs): the only
// variable size is `wire_size_bytes`, which already subsumes the zk_proof
// chunk tree's byte count. We charge a fixed STARK verify cost (chosen to
// roughly match the Transfer verify cost for 1/1 shape) plus a small
// per-byte surcharge mirroring Transfer's k_PerByteCost.
// ---------------------------------------------------------------------------

uint64_t compute_gas_used_mine_uno(const MineUno& tx) noexcept {
    constexpr uint64_t kMineFixedVerifyCost = 40'000;
    constexpr uint64_t kMinePerByteCost     = 2;
    return kMineFixedVerifyCost + kMinePerByteCost * tx.wire_size_bytes;
}

}  // namespace uno_workchain
