/*
    Uno Workchain — Transfer wire codec implementation.

    Implements §4.1 decode / encode and the canonical `tx_hash` formula.

    Source: TOS-specific adapter — consensus-critical codec.
*/
#include "uno/core/transaction.h"

#include <algorithm>
#include <cstring>
#include <vector>

#include "td/utils/Slice.h"
#include "td/utils/logging.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"

// Decision #15: BLAKE3 via A3's adapter (uno/crypto/internal/blake3_adapter.h).
// A3 has landed; the sha256 fallback path (gated by `UNO_BLAKE3_AVAILABLE`)
// is removed — tx_hash MUST be BLAKE3 per §4.1, anything else would silently
// diverge on the wire.
#include "uno/crypto/internal/blake3_adapter.h"

// Decision #1: note commitment preimage uses Poseidon2 with ivk_commitment
// bound in. compute_note_commitment() below is the off-circuit computation.
// Note: we intentionally do NOT include "uno/core/workchain.h" here —
// `transaction.h` and `workchain.h` both declare `kSchemeIdV1` /
// `kTransferVersion` as internal-scope constants, and pulling both into one
// TU triggers redefinition. The two domain-separator strings we need
// ("uno-cm-v1" for cm; see transaction.h / workchain.h::kDomainSepCmV1) are
// reproduced verbatim inside compute_note_commitment() so this TU stays
// independent of workchain.h. The strings are consensus-binding; any drift
// is caught by the golden fixture (decision #5).
#include "uno/crypto/goldilocks.h"
#include "uno/crypto/poseidon2.h"

namespace uno_workchain {

namespace {

inline void hash_blake3_or_fallback(td::Slice in, td::MutableSlice out) {
    // §4.1: tx_hash = BLAKE3(canonical-preimage). Always-on under decision #15.
    ::uno_workchain::crypto::internal::blake3_hash(
        in, reinterpret_cast<uint8_t*>(out.data()));
}

// ---------------------------------------------------------------------------
// Big-endian integer helpers (wire format)
// ---------------------------------------------------------------------------

inline void write_be_u16(uint8_t* p, uint16_t v) noexcept {
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v);
}

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

// Chunk-tree leaf max bytes per cell (mirror EVM bytecode chunk convention).
// 127 B = 1016 bits ≤ CellTraits::max_bits (1023).
constexpr size_t kChunkBytes = 127;
// Fanout of the 4-ary chunk tree (§4.1a). Bounded above by
// CellTraits::max_refs = 4.
constexpr size_t kChunkTreeFanout = 4;
// Bound total leaf count during decode. Covers worst-case v1 zk_proof
// (4/4 shape, ~915 KB → ~7,370 leaves) with ~10 % headroom. Pre-V1-3c
// this was a bound on linear chain length; the 4-ary tree (§4.1a) replaces
// the linear layout but we keep the same numerical bound — it now bounds
// cumulative leaf count during DFS traversal, equivalent in role (caps
// CPU/memory exposure against malicious oversized trees).
constexpr size_t kChunkChainMaxChunks = 8192;

}  // anonymous namespace

// ---------------------------------------------------------------------------
// Chunk tree helpers (§4.1a — balanced 4-ary chunk tree)
// ---------------------------------------------------------------------------
//
// Wire format (consensus-binding; see doc/uno-workchain.md §4.1a):
//   - Leaf cell:     L ∈ [1..127] bytes inline, 0 refs. Identified by 0 refs.
//   - Internal cell: 0 data bits, 1..4 refs left-to-right in byte order.
//                    Identified by ≥ 1 ref.
//   - Empty input:   null Ref.
//
// Canonical construction:
//   1. Split bytes into 127-byte chunks left-to-right (last chunk may be 1..127 B).
//   2. Build leaf cells in order → level[0].
//   3. While level.size() > 1: group by 4 left-to-right, build one internal per
//      group, last group may have 1..4 children → level[k+1].
//   4. Return level[final][0] (root).
//
// Depth = ⌈log₄(N)⌉ where N = leaf count. At v1 worst case (915 KB zk_proof,
// 7370 leaves) depth = 7, well under CellTraits::max_depth = 1024.
//
// V1-3c-gamma rationale: the pre-V1-3c linear chain produced depth = N-1,
// hitting the 1024 cap for any zk_proof > ~127 KB. See §17.3 amendment
// history.

td::Ref<vm::Cell> store_bytes_as_chunk_chain(td::Slice bytes) noexcept {
    if (bytes.empty()) return {};

    // Step 1: build leaf cells in byte order.
    const size_t total = bytes.size();
    const size_t n_leaves = (total + kChunkBytes - 1) / kChunkBytes;
    std::vector<td::Ref<vm::Cell>> level;
    level.reserve(n_leaves);
    for (size_t i = 0; i < n_leaves; ++i) {
        const size_t start = i * kChunkBytes;
        const size_t end = std::min(start + kChunkBytes, total);
        const size_t len = end - start;
        vm::CellBuilder cb;
        cb.store_bytes(bytes.data() + start, len);
        level.push_back(cb.finalize());
    }

    // Step 2: fold 4-ary bottom-up until a single root remains.
    while (level.size() > 1) {
        std::vector<td::Ref<vm::Cell>> next_level;
        next_level.reserve((level.size() + kChunkTreeFanout - 1) / kChunkTreeFanout);
        for (size_t i = 0; i < level.size(); i += kChunkTreeFanout) {
            const size_t group_end = std::min(i + kChunkTreeFanout, level.size());
            vm::CellBuilder cb;
            for (size_t j = i; j < group_end; ++j) {
                cb.store_ref(level[j]);
            }
            next_level.push_back(cb.finalize());
        }
        level = std::move(next_level);
    }
    return level[0];
}

std::string load_bytes_from_chunk_chain(td::Ref<vm::Cell> root) noexcept {
    if (root.is_null()) return {};
    std::string out;
    size_t leaf_count = 0;
    std::vector<td::Ref<vm::Cell>> stack;
    stack.push_back(root);
    while (!stack.empty()) {
        auto cell = std::move(stack.back());
        stack.pop_back();
        if (cell.is_null()) return {};  // malformed: null ref inside tree
        auto cs = vm::load_cell_slice(cell);
        const unsigned bits = cs.size();
        const unsigned n_refs = cs.size_refs();
        if (n_refs == 0) {
            // Leaf: 1..127 B inline, byte-aligned.
            if (++leaf_count > kChunkChainMaxChunks) return {};
            if (bits == 0 || bits % 8 != 0) return {};
            const unsigned data_bytes = bits / 8;
            if (data_bytes > kChunkBytes) return {};
            const size_t off = out.size();
            out.resize(off + data_bytes);
            cs.fetch_bytes(reinterpret_cast<unsigned char*>(out.data() + off), data_bytes);
        } else {
            // Internal: 0 bits, 1..4 refs. Push children in reverse so DFS
            // visits them left-to-right on the next iterations.
            if (bits != 0) return {};
            if (n_refs > kChunkTreeFanout) return {};
            for (unsigned k = n_refs; k-- > 0; ) {
                auto child = cs.prefetch_ref(k);
                if (child.is_null()) return {};
                stack.push_back(std::move(child));
            }
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// Note commitment (§3.2, decision #1)
// ---------------------------------------------------------------------------
//
// Pack the five Poseidon2 inputs per §3.2 into 15 Goldilocks field elements
// and hash with domain tag "uno-cm-v1". Output is truncated to 4 field
// elements (32 bytes canonical LE) and returned.
//
// Packing order (consensus-binding; matches the Transfer AIR claim 2 absorb
// ordering in `transfer_air.rs` when the full P.2 AIR lands):
//
//   [0..1]   d (11 B) → 2 fes (LE packed, last 5 bytes of fe[1] are zero).
//   [2..5]   pk_d.bytes (32 B) → 4 fes (each fe = LE u64 of 8 bytes, mod p).
//   [6..9]   ivk_commitment (32 B) → 4 fes (same packing as pk_d).
//   [10]     value (u64) → 1 fe (value < 2^64 < p + 2^32; canonical-reduce).
//   [11..14] rcm (32 B) → 4 fes (same packing as pk_d).
//
// Why `mod p_Goldilocks` per limb: identical to §4.3 step 4 reasoning —
// pk_d.bytes / ivk_commitment / rcm are cryptographic digests, uniformly
// pseudo-random by construction; per-limb bias is 2^-32 and the combined
// collision surface is negligible.

std::array<uint8_t, 32>
compute_note_commitment(const NoteCommitmentInputs& in) noexcept {
    using ::uno_workchain::crypto::Fp;
    using ::uno_workchain::crypto::Digest;
    using ::uno_workchain::crypto::fp_from_u64;
    using ::uno_workchain::crypto::poseidon2_hash_tagged;

    auto pack_bytes32_as_4 = [](const std::array<uint8_t, 32>& src,
                                Fp out[4]) noexcept {
        for (int limb = 0; limb < 4; ++limb) {
            uint64_t v = 0;
            for (int j = 0; j < 8; ++j) {
                v |= static_cast<uint64_t>(src[limb * 8 + j]) << (8 * j);
            }
            out[limb] = fp_from_u64(v);  // fp_from_u64 reduces mod p
        }
    };

    Fp inputs[15];

    // --- d (11 B) as 2 fes; LE, zero-padded ---
    {
        uint8_t pad[16] = {0};
        std::memcpy(pad, in.d.data(), in.d.size());
        uint64_t w0 = 0, w1 = 0;
        std::memcpy(&w0, pad, 8);
        std::memcpy(&w1, pad + 8, 8);
        inputs[0] = fp_from_u64(w0);
        inputs[1] = fp_from_u64(w1);
    }

    // --- pk_d.bytes (32 B) → 4 fes ---
    pack_bytes32_as_4(in.pk_d_bytes, &inputs[2]);

    // --- ivk_commitment (32 B) → 4 fes  (decision #1) ---
    pack_bytes32_as_4(in.ivk_commitment, &inputs[6]);

    // --- value (u64) → 1 fe ---
    inputs[10] = fp_from_u64(in.value);

    // --- rcm (32 B) → 4 fes ---
    pack_bytes32_as_4(in.rcm, &inputs[11]);

    // Domain separator kDomainSepCmV1 ("uno-cm-v1"), duplicated here to
    // avoid pulling in workchain.h (see top-of-file comment).
    static constexpr char kCmV1Tag[] = "uno-cm-v1";
    Digest h = poseidon2_hash_tagged(
        td::Slice{kCmV1Tag, sizeof(kCmV1Tag) - 1},
        inputs, 15);

    std::array<uint8_t, 32> out{};
    h.to_bytes({reinterpret_cast<char*>(out.data()), out.size()});
    return out;
}

// ---------------------------------------------------------------------------
// Canonical tx_hash (§4.1)
// ---------------------------------------------------------------------------

td::Bits256 canonical_tx_hash(const Transfer& tx) noexcept {
    // Stream-assemble the preimage into a std::string buffer. Total length is
    // bounded: 56 (header) + 64 B/spend + (32+32+2+32+32+80) B/output — fits
    // comfortably in a few hundred bytes for worst-case 4/4.
    std::string buf;
    buf.reserve(kTransferHeaderBytes + tx.spends.size() * 64 + tx.outputs.size() * (32 + 32 + 2 + 32 + 32 + 80));

    auto append_byte = [&](uint8_t b) { buf.push_back(static_cast<char>(b)); };
    auto append_bytes = [&](const uint8_t* p, size_t n) {
        buf.append(reinterpret_cast<const char*>(p), n);
    };
    auto append_be_u16 = [&](uint16_t v) {
        uint8_t tmp[2]; write_be_u16(tmp, v); append_bytes(tmp, 2);
    };
    auto append_be_u32 = [&](uint32_t v) {
        uint8_t tmp[4]; write_be_u32(tmp, v); append_bytes(tmp, 4);
    };
    auto append_be_u64 = [&](uint64_t v) {
        uint8_t tmp[8]; write_be_u64(tmp, v); append_bytes(tmp, 8);
    };
    auto append_bits256 = [&](const td::Bits256& b) {
        append_bytes(reinterpret_cast<const uint8_t*>(b.data()), 32);
    };
    auto append_cell_hash = [&](const td::Ref<vm::Cell>& c) {
        // Cell-root hash is 32 bytes. Null cell is disallowed at decode, but
        // we zero-fill defensively here rather than abort.
        if (c.is_null()) {
            uint8_t zeros[32] = {};
            append_bytes(zeros, 32);
            return;
        }
        auto slice = c->get_hash().as_slice();
        append_bytes(reinterpret_cast<const uint8_t*>(slice.data()), 32);
    };

    // --- inline header ---
    append_byte(tx.version);
    append_byte(tx.scheme_id);
    append_be_u32(tx.chain_id);
    append_bits256(tx.anchor);
    append_be_u64(tx.expiry_block);
    append_be_u64(tx.fee);
    append_byte(static_cast<uint8_t>(tx.spends.size()));
    append_byte(static_cast<uint8_t>(tx.outputs.size()));

    // --- per-spend (exclude spend_auth_sig, per §4.1) ---
    for (const auto& s : tx.spends) {
        append_bits256(s.nullifier);
        append_bits256(s.rk);
    }

    // --- per-output ---
    for (const auto& o : tx.outputs) {
        append_bits256(o.cm);
        append_bits256(o.epk);
        append_be_u16(o.filter_tag);
        append_cell_hash(o.enc_ciphertext);
        append_cell_hash(o.mlkem_ct);
        append_bytes(o.out_ciphertext.data(), kOutCiphertextBytes);
    }

    td::Bits256 out{};
    hash_blake3_or_fallback(td::Slice(buf.data(), buf.size()),
                            td::MutableSlice(reinterpret_cast<char*>(out.data()), 32));
    return out;
}

// ---------------------------------------------------------------------------
// Plonky3 public-input builder (§4.3 step 4, decision #5)
// ---------------------------------------------------------------------------
//
// Byte encoding is consensus-binding. Each Goldilocks element serializes as
// 8 bytes little-endian u64. 256-bit inputs split into 4 × u64 LE chunks,
// each reduced mod p_Goldilocks = 2^64 - 2^32 + 1. Adversary-controlled
// scalar inputs (scheme_id, chain_id, expiry_block, fee, filter_tag) are
// asserted in-range by `encode_u64` below — a consensus fault otherwise.
//
// Cross-impl parity is enforced by the golden fixture
// `uno/test/golden/public-inputs-v1.hex`; see test-public-input-fixture.cpp
// (C++ side) and `tests/public_input_fixture.rs` (Rust side).

uint64_t encode_u64(uint64_t x) noexcept {
    // Per decision #5: u64 public inputs (expiry_block, fee) must satisfy
    // `x < p_Goldilocks`; out-of-range implies a malformed adversarial
    // transaction that should have been caught at admission. We abort so
    // no silent wire-encoding drift reaches the verifier.
    if (x >= kPGoldilocks) {
        // The admission path asserts `fee <= some_cap` and `expiry_block
        // <= current + window`, both bounded well below p. A value larger
        // than p here is a serious invariant break.
        LOG(ERROR) << "uno/public-input: u64 value " << x
                   << " >= p_Goldilocks; aborting (should have been "
                      "rejected at admission).";
        std::abort();
    }
    return x;
}

std::array<uint8_t, 32> encode_256(const uint8_t bytes[32]) noexcept {
    // Split into 4 × u64 LE chunks, reduce each mod p_Goldilocks, then
    // write each canonical limb back in the same byte slot (LE). The
    // output byte order matches §4.3 step 4 exactly.
    std::array<uint8_t, 32> out{};
    for (int limb = 0; limb < 4; ++limb) {
        uint64_t v = 0;
        for (int j = 0; j < 8; ++j) {
            v |= static_cast<uint64_t>(bytes[limb * 8 + j]) << (8 * j);
        }
        // Reduce. At 2^-32 per limb this is a rare branch on uniform input.
        if (v >= kPGoldilocks) {
            v -= kPGoldilocks;
            // One subtraction suffices: p_Goldilocks > 2^63, so u64 - p fits.
        }
        for (int j = 0; j < 8; ++j) {
            out[limb * 8 + j] = static_cast<uint8_t>(v >> (8 * j));
        }
    }
    return out;
}

namespace {

// Pack a 256-bit blob into 4 × 64-bit little-endian limbs, each reduced
// mod p_Goldilocks (decision #5). Uses encode_256() internally to keep the
// reduction rule in one place.
inline void pack_bits256_as_4_limbs(const td::Bits256& src, std::vector<uint64_t>& out) {
    auto canonical = encode_256(reinterpret_cast<const uint8_t*>(src.data()));
    for (int limb = 0; limb < 4; ++limb) {
        uint64_t v = 0;
        for (int j = 0; j < 8; ++j) {
            v |= static_cast<uint64_t>(canonical[limb * 8 + j]) << (8 * j);
        }
        out.push_back(v);
    }
}

}  // anonymous namespace

Plonky3PublicInputs build_plonky3_public_inputs(const Transfer& tx) noexcept {
    // Layout per §4.3 step 4 (decision #5):
    //   [scheme_id, chain_id, expiry_block, fee]    (4 elts)
    //   [anchor as 4 limbs]                         (4 elts)
    //   per spend: [nf_i 4 limbs, rk_i 4 limbs]     (8 elts)
    //   per output:[cm_j 4 limbs, epk_j 4 limbs,
    //               filter_tag_j 1 elt]             (9 elts)
    // Total: 8 + 8*spends + 9*outputs.  Byte length: 64 + 64·spends + 72·outputs.
    Plonky3PublicInputs pi;
    pi.elements.reserve(8 + 8 * tx.spends.size() + 9 * tx.outputs.size());

    // u8 / u16 / u32 always fit (they're < 2^32 < p). u64 is asserted.
    pi.elements.push_back(static_cast<uint64_t>(tx.scheme_id));
    pi.elements.push_back(static_cast<uint64_t>(tx.chain_id));
    pi.elements.push_back(encode_u64(tx.expiry_block));
    pi.elements.push_back(encode_u64(tx.fee));

    pack_bits256_as_4_limbs(tx.anchor, pi.elements);

    for (const auto& s : tx.spends) {
        pack_bits256_as_4_limbs(s.nullifier, pi.elements);
        pack_bits256_as_4_limbs(s.rk, pi.elements);
    }
    for (const auto& o : tx.outputs) {
        pack_bits256_as_4_limbs(o.cm, pi.elements);
        pack_bits256_as_4_limbs(o.epk, pi.elements);
        pi.elements.push_back(static_cast<uint64_t>(o.filter_tag));
    }
    return pi;
}

std::vector<uint8_t> Plonky3PublicInputs::to_bytes() const noexcept {
    std::vector<uint8_t> buf;
    buf.resize(elements.size() * 8);
    for (size_t i = 0; i < elements.size(); ++i) {
        uint64_t v = elements[i];
        uint8_t* p = buf.data() + i * 8;
        for (int j = 0; j < 8; ++j) {
            p[j] = static_cast<uint8_t>(v);
            v >>= 8;
        }
    }
    return buf;
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

namespace {

// Root-level inline fetch (no cross-cell continuation — the root cell has a
// fixed 448-bit header and the spec never spills header bytes into a
// continuation cell). The per-spend / per-output chunk-chains are walked
// separately via walk_two_chunk_payload() below.
bool fetch_bytes_checked(vm::CellSlice& cs, uint8_t* out, unsigned bytes) {
    if (!cs.have(bytes * 8u)) {
        return false;
    }
    return cs.fetch_bytes(out, bytes);
}

bool fetch_u8(vm::CellSlice& cs, uint8_t& out) {
    uint8_t b;
    if (!fetch_bytes_checked(cs, &b, 1)) return false;
    out = b;
    return true;
}

bool fetch_be_u32(vm::CellSlice& cs, uint32_t& out) {
    uint8_t tmp[4];
    if (!fetch_bytes_checked(cs, tmp, 4)) return false;
    out = 0;
    for (int i = 0; i < 4; ++i) {
        out = (out << 8) | tmp[i];
    }
    return true;
}

bool fetch_be_u64(vm::CellSlice& cs, uint64_t& out) {
    uint8_t tmp[8];
    if (!fetch_bytes_checked(cs, tmp, 8)) return false;
    out = 0;
    for (int i = 0; i < 8; ++i) {
        out = (out << 8) | tmp[i];
    }
    return true;
}

bool fetch_bits256(vm::CellSlice& cs, td::Bits256& out) {
    return fetch_bytes_checked(cs, reinterpret_cast<uint8_t*>(out.data()), 32);
}

TransferDecodeError err(const char* s) { return TransferDecodeError{std::string{s}}; }

// ---------------------------------------------------------------------------
// Per-item chunk-chain packing (encode/decode helpers)
// ---------------------------------------------------------------------------
//
// Both spends (128 B) and outputs (146 B inline) exceed the 1023-bit cell
// budget and must be split. We keep the split deterministic and shallow: the
// first cell holds up to 127 B inline and, if more bytes remain, a single
// ref[0] to a "continuation" cell with the residual bytes inline and zero
// refs. For the output cell the post-split frees up ref[1] and ref[2] for
// enc_ciphertext / mlkem_ct respectively.
//
// This keeps walk depth at **2** per per-item subtree (root → item_cell →
// continuation), which combined with the spends_root / outputs_root fan-out
// layer puts the whole Transfer at a total walk depth of 4 from the root —
// comfortably under the §17 ≤5-level constraint for every 1..4 × 1..4 shape.

// First 127 B of each item go inline; residual (1 B for a spend, 19 B for an
// output's inline payload) spills into a single continuation cell.
constexpr size_t kItemInlineHeadBytes = 127;

// Encode a byte payload of length `len` <= 127 + 127 as either (a) single
// cell inline when len <= 127 or (b) a 127-byte head cell with a single
// continuation-ref holding the residual bytes inline. Returns the builder
// seeded with the head cell's inline bytes; caller is responsible for
// appending additional refs (e.g. enc_ct / mlkem_ct) or calling finalize().
void append_item_head_and_continuation(vm::CellBuilder& item_cb,
                                       const uint8_t* bytes,
                                       size_t len) {
    const size_t head = std::min<size_t>(len, kItemInlineHeadBytes);
    item_cb.store_bytes(reinterpret_cast<const char*>(bytes), head);
    if (head < len) {
        vm::CellBuilder cont_cb;
        cont_cb.store_bytes(reinterpret_cast<const char*>(bytes + head), len - head);
        item_cb.store_ref(cont_cb.finalize());
    }
}

// Read a `len`-byte payload out of an item cell that was built by
// append_item_head_and_continuation(). `head_slice` must be the item cell's
// slice positioned at the start of its inline bytes. Consumes the inline
// bytes and — if `len > 127` — the first ref of `head_slice`.
bool load_item_chunked(vm::CellSlice& head_slice, uint8_t* out, size_t len) {
    const size_t head = std::min<size_t>(len, kItemInlineHeadBytes);
    if (!fetch_bytes_checked(head_slice, out, static_cast<unsigned>(head))) {
        return false;
    }
    if (head >= len) return true;
    if (head_slice.size_refs() < 1) return false;
    auto cont_ref = head_slice.prefetch_ref(0);
    head_slice.advance_refs(1);
    if (cont_ref.is_null()) return false;
    auto cont_cs = vm::load_cell_slice(cont_ref);
    const size_t rest = len - head;
    // Enforce shape: continuation cell holds exactly `rest` bytes inline and
    // zero refs. Extra data / refs is a malformed tx.
    if (cont_cs.size() != rest * 8u) return false;
    if (cont_cs.size_refs() != 0) return false;
    return cont_cs.fetch_bytes(out + head, static_cast<unsigned>(rest));
}

// §17 structural-walk-depth assertion — invoked by the decoder after
// all refs have been captured. Bounds the STRUCTURAL ref tree of the
// Transfer (root → spends_root / outputs_root → per-item → cont),
// EXCLUDING the enc_ciphertext / mlkem_ct / zk_proof chunk-chain
// subtrees which carry their own `kChunkChainMaxChunks` bound.
//
// V1-3c-gamma fix (2026-04-22): the previous `cell_depth_bounded`
// helper below used `Cell::get_depth()`, which per TOS cell-depth
// semantics descends into ALL refs — including chunk-chain subtrees.
// On real v1 shapes (mlkem_ct ≥ 2 cells, enc_ct ~5 cells,
// zk_proof ~4096 cells) the old gate computed
// outputs_root.get_depth() ≥ 10 and rejected honest Transfers with
// "ref-tree depth exceeds §17 5-level bound". The bug was latent
// (no C++ test exercised realistic shapes through this gate, and
// the pre-V1 value kChunkChainMaxChunks = 2048 kept zk_proof
// off-chain in the witness_commitment shape) until V1-3c's cross-
// language parity bridge surfaced it.
//
// The new walker follows ONLY:
//   spends_root  → per_spend   → cont (ref [0] if any)
//   outputs_root → per_output  → cont (ref [0] if any)
// and explicitly SKIPS refs [1] / [2] on per_output cells (enc_ct,
// mlkem_ct). For spends_root, per_spend cells only have ref [0]
// (cont), so the skip is a no-op there.
//
// Defense-in-depth posture: the per-shape decode checks above
// (`load_item_chunked` + exact inline-bit counts + exact trailing-
// ref counts) already bound the structural tree to the encoder's
// exact shape. This gate is redundant with those checks in the
// honest-prover case but catches adversarial trees that might slip
// through a load_item_chunked call if a future refactor weakens a
// per-shape check.
constexpr unsigned kMaxTransferRefDepth = 5;

unsigned structural_walk_depth(const td::Ref<vm::Cell>& items_root_ref) {
    if (items_root_ref.is_null()) return 0;
    auto root_cs = vm::load_cell_slice(items_root_ref);
    unsigned max_child = 0;
    for (unsigned i = 0; i < root_cs.size_refs(); ++i) {
        auto item_ref = root_cs.prefetch_ref(i);
        if (item_ref.is_null()) continue;
        auto item_cs = vm::load_cell_slice(item_ref);
        // per-item cell counts as 1 level. It may carry a `cont` ref at
        // index 0 (another level). We explicitly do NOT descend into
        // refs [1] and [2] on per_output cells — those are enc_ct and
        // mlkem_ct chunk-chain roots, bounded by kChunkChainMaxChunks.
        unsigned item_depth = 1;
        if (item_cs.size_refs() > 0) {
            auto cont_ref = item_cs.prefetch_ref(0);
            if (cont_ref.not_null()) {
                // cont cell has 0 refs (enforced by load_item_chunked).
                item_depth = 2;
            }
        }
        max_child = std::max(max_child, item_depth);
    }
    // items_root contributes 1 level (inline + refs).
    return max_child + 1;
}

// Approximate wire_size_bytes for the fee calculation in §4.3 step 1.4.
// Inline: 56 header + 128 * spend_count + 146 * output_count.
// Ref-carried bytes for cells are not known without traversal; we use the
// CellString-style estimated overhead (128 B/cell over the chain roots).
// This is a deterministic function of (spend_count, output_count, chunk
// counts), identical on every validator.
size_t estimate_wire_size(const Transfer& tx) {
    size_t n = kTransferHeaderBytes
             + tx.spends.size()  * kSpendInlineBytes
             + tx.outputs.size() * kOutputInlineBytes;
    auto count_chain = [](td::Ref<vm::Cell> root) -> size_t {
        if (root.is_null()) return 0;
        size_t bytes = 0;
        auto cell = root;
        for (size_t i = 0; i < kChunkChainMaxChunks; ++i) {
            if (cell.is_null()) break;
            auto cs = vm::load_cell_slice(cell);
            unsigned bits = cs.size();
            if (bits < 1 || (bits - 1) % 8 != 0) return bytes;
            bytes += (bits - 1) / 8;
            unsigned has_next = 0;
            auto tmp = cs;
            tmp.advance(bits - 1);
            has_next = static_cast<unsigned>(tmp.fetch_ulong(1));
            if (has_next == 0) break;
            if (cs.size_refs() == 0) break;
            cell = cs.prefetch_ref(0);
        }
        return bytes;
    };
    for (const auto& o : tx.outputs) {
        n += count_chain(o.enc_ciphertext);
        n += count_chain(o.mlkem_ct);
    }
    n += count_chain(tx.zk_proof);
    return n;
}

}  // anonymous namespace

DecodeResult decode_transfer(vm::CellSlice body) noexcept {
    Transfer tx;

    // --- inline 448-bit header (root cell) ---
    if (!fetch_u8(body, tx.version))      return err("short header: version");
    if (!fetch_u8(body, tx.scheme_id))    return err("short header: scheme_id");
    if (!fetch_be_u32(body, tx.chain_id)) return err("short header: chain_id");
    if (!fetch_bits256(body, tx.anchor))  return err("short header: anchor");
    if (!fetch_be_u64(body, tx.expiry_block)) return err("short header: expiry_block");
    if (!fetch_be_u64(body, tx.fee))      return err("short header: fee");

    uint8_t sc = 0, oc = 0;
    if (!fetch_u8(body, sc)) return err("short header: spend_count");
    if (!fetch_u8(body, oc)) return err("short header: output_count");

    if (sc < kMinSpendCount  || sc > kMaxSpendCount)  return err("spend_count out of range");
    if (oc < kMinOutputCount || oc > kMaxOutputCount) return err("output_count out of range");

    tx.spends.resize(sc);
    tx.outputs.resize(oc);

    // Root cell layout: 3 refs (spends_root, outputs_root, zk_proof).
    if (body.size_refs() < 3) return err("missing spends_root / outputs_root / zk_proof refs");

    auto spends_root_ref  = body.prefetch_ref(0);
    auto outputs_root_ref = body.prefetch_ref(1);
    auto zk_proof_ref     = body.prefetch_ref(2);
    body.advance_refs(3);

    if (spends_root_ref.is_null())  return err("null spends_root ref");
    if (outputs_root_ref.is_null()) return err("null outputs_root ref");
    if (zk_proof_ref.is_null())     return err("null zk_proof ref");

    // --- spends array (spends_root → per_spend[i] → cont) ---
    {
        auto spends_root = vm::load_cell_slice(spends_root_ref);
        if (spends_root.size() != 0) return err("spends_root: unexpected inline data");
        if (spends_root.size_refs() != sc) {
            return err("spends_root: ref count does not match spend_count");
        }
        for (uint8_t i = 0; i < sc; ++i) {
            auto spend_ref = spends_root.prefetch_ref(i);
            if (spend_ref.is_null()) return err("spends_root: null per-spend ref");
            auto spend_cs = vm::load_cell_slice(spend_ref);
            uint8_t buf[kSpendInlineBytes] = {0};
            if (!load_item_chunked(spend_cs, buf, kSpendInlineBytes)) {
                return err("per-spend cell: malformed chunked payload");
            }
            // Disallow extra trailing inline data / refs so re-encode is bit-identical.
            if (spend_cs.size() != 0) return err("per-spend cell: unexpected trailing inline data");
            if (spend_cs.size_refs() != 0) return err("per-spend cell: unexpected trailing refs");

            auto& s = tx.spends[i];
            std::memcpy(s.nullifier.data(), buf + 0,  32);
            std::memcpy(s.rk.data(),        buf + 32, 32);
            std::memcpy(s.spend_auth_sig.data(), buf + 64, 64);
        }
    }

    // --- outputs array (outputs_root → per_output[j] → cont + enc_ct + mlkem_ct) ---
    {
        auto outputs_root = vm::load_cell_slice(outputs_root_ref);
        if (outputs_root.size() != 0) return err("outputs_root: unexpected inline data");
        if (outputs_root.size_refs() != oc) {
            return err("outputs_root: ref count does not match output_count");
        }
        for (uint8_t j = 0; j < oc; ++j) {
            auto out_ref = outputs_root.prefetch_ref(j);
            if (out_ref.is_null()) return err("outputs_root: null per-output ref");
            auto out_cs = vm::load_cell_slice(out_ref);
            uint8_t buf[kOutputInlineBytes];
            if (!load_item_chunked(out_cs, buf, kOutputInlineBytes)) {
                return err("per-output cell: malformed chunked inline payload");
            }
            // After chunked load: 2 remaining refs (enc_ct, mlkem_ct) and 0 bits.
            if (out_cs.size() != 0) return err("per-output cell: unexpected trailing inline data");
            if (out_cs.size_refs() != 2) return err("per-output cell: expected 2 trailing refs (enc_ct, mlkem_ct)");

            auto& o = tx.outputs[j];
            std::memcpy(o.cm.data(),  buf +  0, 32);
            std::memcpy(o.epk.data(), buf + 32, 32);
            o.filter_tag = static_cast<uint16_t>((uint16_t(buf[64]) << 8) | buf[65]);
            std::memcpy(o.out_ciphertext.data(), buf + 66, kOutCiphertextBytes);

            o.enc_ciphertext = out_cs.prefetch_ref(0);
            o.mlkem_ct       = out_cs.prefetch_ref(1);
            if (o.enc_ciphertext.is_null()) return err("per-output cell: null enc_ciphertext");
            if (o.mlkem_ct.is_null())       return err("per-output cell: null mlkem_ct");
        }
    }

    tx.zk_proof = zk_proof_ref;

    // §17 structural-walk-depth gate: reject malformed trees that exceed
    // the 5-level budget on the STRUCTURAL tree (root → items_root →
    // per_item → cont), EXCLUDING the bounded enc_ct / mlkem_ct /
    // zk_proof chunk-chain subtrees. See comment on
    // `structural_walk_depth` above for the V1-3c-gamma fix rationale
    // (the previous cell_depth_bounded(get_depth) check fired on honest
    // v1 Transfers because it descended into chunk chains).
    //
    // Depth budget: items_root depth = 3 (items_root + per_item + cont);
    // +1 for the Transfer root = 4 total. Under the 5-level bound.
    // Anything larger came from a hand-crafted adversary cell tree —
    // refuse to admit.
    auto gate = [](const td::Ref<vm::Cell>& c, unsigned bound) -> bool {
        if (c.is_null()) return true;
        return structural_walk_depth(c) + 1u <= bound;
    };
    if (!gate(spends_root_ref,  kMaxTransferRefDepth) ||
        !gate(outputs_root_ref, kMaxTransferRefDepth)) {
        return err("ref-tree depth exceeds §17 5-level bound");
    }

    // Trailing bits / extra refs on the root are disallowed so re-encode
    // yields byte-identical output.
    if (body.size() != 0) return err("root cell: unexpected trailing inline data");
    if (body.size_refs() != 0) return err("root cell: unexpected trailing refs");

    // tx_hash is derived from the decoded form.
    tx.tx_hash = canonical_tx_hash(tx);
    tx.wire_size_bytes = estimate_wire_size(tx);
    return tx;
}

DecodeResult decode_transfer_bytes(td::Slice raw_bytes) noexcept {
    // Admission / mempool / RPC path: the caller has encode_transfer()'d the
    // Transfer into its root cell, then BoC-serialised that root via
    // `vm::std_boc_serialize`. JSON-RPC `uno_sendTransfer` decodes hex →
    // raw_bytes → here; mempool persistence round-trips Transfers through
    // the same byte string so validators hash byte-identical units across
    // process restart. Mirrors the `std_boc_deserialize` pattern used by
    // `evm_workchain` (see evm/rpc/cache-db.cpp).
    if (raw_bytes.empty()) {
        return err("decode_transfer_bytes: empty BoC input");
    }
    auto cell_r = vm::std_boc_deserialize(raw_bytes);
    if (cell_r.is_error()) {
        return err("decode_transfer_bytes: std_boc_deserialize failed");
    }
    auto root = cell_r.move_as_ok();
    if (root.is_null()) {
        return err("decode_transfer_bytes: null root cell from BoC");
    }
    auto cs = vm::load_cell_slice(root);
    return decode_transfer(cs);
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

td::Result<td::Ref<vm::Cell>> encode_transfer(const Transfer& tx) noexcept {
    // Physical BoC shape (§17 ≤5-level walk bound — we fan out instead of
    // chaining linearly). Root cell inline is the fixed 448-bit §4.1 header
    // exactly; spends and outputs are carried by two parallel subtrees
    // referenced from the root.
    //
    //   root cell (448 bits inline, 3 refs)
    //     inline: version ‖ scheme_id ‖ chain_id ‖ anchor ‖ expiry ‖ fee ‖ sc ‖ oc
    //     ref[0] → spends_root (empty inline, `sc` refs)
    //                each ref → per_spend cell: 127 B head + 1 ref → 1 B cont
    //     ref[1] → outputs_root (empty inline, `oc` refs)
    //                each ref → per_output cell:
    //                            127 B head (of the 146 B output inline)
    //                            ref[0] → 19 B continuation (inline, 0 refs)
    //                            ref[1] → enc_ciphertext
    //                            ref[2] → mlkem_ct
    //     ref[2] → zk_proof
    //
    // Walk depth from root to any leaf (exclusive of enc_ct / mlkem_ct /
    // zk_proof's own internal chains, which have their own depth budgets per
    // §17.1): 4 for every 1..4 × 1..4 shape — tight under the ≤5 bound.

    if (tx.spends.size() < kMinSpendCount || tx.spends.size() > kMaxSpendCount) {
        return td::Status::Error("spend_count out of range");
    }
    if (tx.outputs.size() < kMinOutputCount || tx.outputs.size() > kMaxOutputCount) {
        return td::Status::Error("output_count out of range");
    }
    if (tx.zk_proof.is_null()) {
        return td::Status::Error("encode_transfer: zk_proof must be non-null");
    }
    for (const auto& o : tx.outputs) {
        if (o.enc_ciphertext.is_null()) {
            return td::Status::Error("encode_transfer: enc_ciphertext must be non-null");
        }
        if (o.mlkem_ct.is_null()) {
            return td::Status::Error("encode_transfer: mlkem_ct must be non-null");
        }
    }

    // --- spends_root: fan-out cell with one ref per spend ---
    vm::CellBuilder spends_root_cb;
    for (const auto& s : tx.spends) {
        uint8_t buf[kSpendInlineBytes];
        std::memcpy(buf +  0, s.nullifier.data(),       32);
        std::memcpy(buf + 32, s.rk.data(),              32);
        std::memcpy(buf + 64, s.spend_auth_sig.data(),  64);
        vm::CellBuilder item_cb;
        append_item_head_and_continuation(item_cb, buf, kSpendInlineBytes);
        spends_root_cb.store_ref(item_cb.finalize());
    }
    auto spends_root = spends_root_cb.finalize();

    // --- outputs_root: fan-out cell with one ref per output ---
    vm::CellBuilder outputs_root_cb;
    for (const auto& o : tx.outputs) {
        uint8_t buf[kOutputInlineBytes];
        std::memcpy(buf +  0, o.cm.data(),  32);
        std::memcpy(buf + 32, o.epk.data(), 32);
        buf[64] = static_cast<uint8_t>(o.filter_tag >> 8);
        buf[65] = static_cast<uint8_t>(o.filter_tag & 0xFF);
        std::memcpy(buf + 66, o.out_ciphertext.data(), kOutCiphertextBytes);
        vm::CellBuilder item_cb;
        append_item_head_and_continuation(item_cb, buf, kOutputInlineBytes);
        // Trailing refs (enc_ct, mlkem_ct) after the inline continuation ref —
        // decoder reads refs in this exact order (ref[0]=cont, ref[1]=enc_ct,
        // ref[2]=mlkem_ct).
        item_cb.store_ref(o.enc_ciphertext);
        item_cb.store_ref(o.mlkem_ct);
        outputs_root_cb.store_ref(item_cb.finalize());
    }
    auto outputs_root = outputs_root_cb.finalize();

    // --- root cell: 448-bit header + 3 refs ---
    vm::CellBuilder root;
    root.store_long(tx.version, 8);
    root.store_long(tx.scheme_id, 8);
    root.store_long(tx.chain_id, 32);
    root.store_bytes(reinterpret_cast<const char*>(tx.anchor.data()), 32);
    root.store_long(tx.expiry_block, 64);
    root.store_long(tx.fee, 64);
    root.store_long(static_cast<long long>(tx.spends.size()), 8);
    root.store_long(static_cast<long long>(tx.outputs.size()), 8);
    root.store_ref(spends_root);
    root.store_ref(outputs_root);
    root.store_ref(tx.zk_proof);

    return root.finalize();
}

td::Result<td::BufferSlice> encode_transfer_to_boc(const Transfer& tx) noexcept {
    // BoC envelope: `encode_transfer` produces the §4.1 root cell; we wrap it
    // in a standard BoC via `vm::std_boc_serialize` so the byte string is
    // suitable for JSON-RPC `uno_sendTransfer`, mempool persistence, and
    // cross-validator tx-hash agreement. The inverse is `decode_transfer_bytes`
    // above — together they pin the round-trip invariant that
    // test-uno-codec-shapes exercises across every 1..4 × 1..4 shape.
    auto root_r = encode_transfer(tx);
    if (root_r.is_error()) return root_r.move_as_error();
    auto root = root_r.move_as_ok();
    if (root.is_null()) {
        return td::Status::Error("encode_transfer_to_boc: encode_transfer returned null root");
    }
    return vm::std_boc_serialize(root);
}

}  // namespace uno_workchain
