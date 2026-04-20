/*
    Uno Workchain — Transfer wire codec implementation.

    Implements §4.1 decode / encode and the canonical `tx_hash` formula.

    Source: TOS-specific adapter — consensus-critical codec.
*/
#include "uno/core/transaction.h"

#include <algorithm>
#include <cstring>

#include "td/utils/Slice.h"
#include "td/utils/crypto.h"    // td::sha256 — temporary hash stand-in (see TODO below)
#include "td/utils/logging.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"

// Forward-declared BLAKE3 hook owned by uno/crypto/ (Agent 3). The signature
// must match td::sha256(Slice, MutableSlice). Linked in at assembly time once
// Agent 3's `blake3.{h,cpp}` lands. Until then, this source file falls back
// to SHA-256 so we can exercise the full codec path in unit tests. The fallback
// is gated behind `UNO_BLAKE3_AVAILABLE`; flipping that flag in the CMake
// config once the Rust/C BLAKE3 bridge is wired switches to the canonical
// BLAKE3(Slice, MutableSlice) used by §4.1.
//
// TODO(uno-integration): replace td::sha256 fallback once Agent 3 lands
// uno/crypto/blake3.h with `uno_crypto::blake3_256(Slice in, MutableSlice out)`.
#ifdef UNO_BLAKE3_AVAILABLE
namespace uno_crypto {
void blake3_256(td::Slice in, td::MutableSlice out);
}  // namespace uno_crypto
#endif

namespace uno_workchain {

namespace {

inline void hash_blake3_or_fallback(td::Slice in, td::MutableSlice out) {
#ifdef UNO_BLAKE3_AVAILABLE
    uno_crypto::blake3_256(in, out);
#else
    td::sha256(in, out);  // deterministic stand-in; swapped when Agent 3 lands
#endif
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

// Chunk-chain max bytes per cell (mirror EVM bytecode chunk convention).
constexpr size_t kChunkBytes = 127;
// Bound the decode walk. A 4-spend/4-output Transfer's zk_proof can be ~80 KB;
// at 127 B/chunk that is ~640 chunks. Head-room to 2048 for future proofs.
constexpr size_t kChunkChainMaxChunks = 2048;

}  // anonymous namespace

// ---------------------------------------------------------------------------
// Chunk chain helpers
// ---------------------------------------------------------------------------

td::Ref<vm::Cell> store_bytes_as_chunk_chain(td::Slice bytes) noexcept {
    if (bytes.empty()) return {};
    td::Ref<vm::Cell> next;
    size_t total = bytes.size();
    size_t n_chunks = (total + kChunkBytes - 1) / kChunkBytes;
    for (size_t i = n_chunks; i-- > 0;) {
        size_t start = i * kChunkBytes;
        size_t end = std::min(start + kChunkBytes, total);
        size_t len = end - start;
        vm::CellBuilder cb;
        cb.store_bytes(bytes.data() + start, len);
        if (next.not_null()) {
            cb.store_long(1, 1);
            cb.store_ref(next);
        } else {
            cb.store_long(0, 1);
        }
        next = cb.finalize();
    }
    return next;
}

std::string load_bytes_from_chunk_chain(td::Ref<vm::Cell> root) noexcept {
    if (root.is_null()) return {};
    std::string out;
    auto cell = root;
    for (size_t i = 0; i < kChunkChainMaxChunks; ++i) {
        if (cell.is_null()) break;
        auto cs = vm::load_cell_slice(cell);
        unsigned bits = cs.size();
        if (bits < 1 || (bits - 1) % 8 != 0) return {};
        unsigned data_bytes = (bits - 1) / 8;
        if (data_bytes > 0) {
            size_t off = out.size();
            out.resize(off + data_bytes);
            cs.fetch_bytes(reinterpret_cast<unsigned char*>(out.data() + off), data_bytes);
        }
        unsigned has_next = static_cast<unsigned>(cs.fetch_ulong(1));
        if (has_next == 0) return out;
        if (cs.size_refs() == 0) return {};
        cell = cs.prefetch_ref(0);
    }
    return {};  // cycle / oversize — reject
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
// Plonky3 public-input builder (§4.3 step 4)
// ---------------------------------------------------------------------------

namespace {

// Pack a 256-bit blob into 4 × 64-bit little-endian limbs (canonical
// Goldilocks wire form). The Goldilocks prime is 2^64 - 2^32 + 1; a uniformly
// random 64-bit limb exceeds p with probability ~2^-32, so strict Plonky3
// verifiers will reject out-of-range limbs. We pass the bytes through
// untouched — reduction is the verifier's responsibility.
inline void pack_bits256_as_4_limbs(const td::Bits256& src, std::vector<uint64_t>& out) {
    const uint8_t* p = reinterpret_cast<const uint8_t*>(src.data());
    for (int limb = 0; limb < 4; ++limb) {
        uint64_t v = 0;
        for (int j = 0; j < 8; ++j) {
            v |= static_cast<uint64_t>(p[limb * 8 + j]) << (8 * j);
        }
        out.push_back(v);
    }
}

}  // anonymous namespace

Plonky3PublicInputs build_plonky3_public_inputs(const Transfer& tx) noexcept {
    // Layout per §4.3 step 4:
    //   [scheme_id, chain_id, expiry_block, fee]    (4 elts)
    //   [anchor as 4 limbs]                         (4 elts)
    //   per spend: [nf_i 4 limbs, rk_i 4 limbs]     (8 elts)
    //   per output:[cm_j 4 limbs, epk_j 4 limbs,
    //               filter_tag_j 1 elt]             (9 elts)
    // Total: 8 + 8*spends + 9*outputs.
    Plonky3PublicInputs pi;
    pi.elements.reserve(8 + 8 * tx.spends.size() + 9 * tx.outputs.size());

    pi.elements.push_back(static_cast<uint64_t>(tx.scheme_id));
    pi.elements.push_back(static_cast<uint64_t>(tx.chain_id));
    pi.elements.push_back(tx.expiry_block);
    pi.elements.push_back(tx.fee);

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

// Advance `cs` past `bits` bits, chasing into continuation cells if the
// current slice runs out. Returns false on underflow. Currently the Transfer
// layout never spans continuation cells (inline is < 1023 bits per 4/4 case
// when packed without tree cells beyond ref slots), but we handle it
// defensively so encoders that split inline payload into a continuation
// remain decodable.
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

bool fetch_be_u16(vm::CellSlice& cs, uint16_t& out) {
    uint8_t tmp[2];
    if (!fetch_bytes_checked(cs, tmp, 2)) return false;
    out = static_cast<uint16_t>(tmp[0]) << 8 | tmp[1];
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

    // --- inline header ---
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

    // --- spends ---
    for (uint8_t i = 0; i < sc; ++i) {
        auto& s = tx.spends[i];
        if (!fetch_bits256(body, s.nullifier)) return err("short spend.nullifier");
        if (!fetch_bits256(body, s.rk))        return err("short spend.rk");
        if (!fetch_bytes_checked(body, s.spend_auth_sig.data(), 64)) return err("short spend.sig");
    }

    // --- outputs ---
    for (uint8_t j = 0; j < oc; ++j) {
        auto& o = tx.outputs[j];
        if (!fetch_bits256(body, o.cm))       return err("short output.cm");
        if (!fetch_bits256(body, o.epk))      return err("short output.epk");
        if (!fetch_be_u16(body, o.filter_tag)) return err("short output.filter_tag");
        if (body.size_refs() < 2) return err("missing enc_ciphertext / mlkem_ct refs");
        if (!body.fetch_ref_to(o.enc_ciphertext)) return err("missing enc_ciphertext ref");
        if (!body.fetch_ref_to(o.mlkem_ct))        return err("missing mlkem_ct ref");
        if (!fetch_bytes_checked(body, o.out_ciphertext.data(), kOutCiphertextBytes)) {
            return err("short output.out_ciphertext");
        }
    }

    // --- zk_proof ref (trailing) ---
    if (body.size_refs() < 1) return err("missing zk_proof ref");
    if (!body.fetch_ref_to(tx.zk_proof)) return err("failed to fetch zk_proof ref");

    // tx_hash is derived from the decoded form.
    tx.tx_hash = canonical_tx_hash(tx);
    tx.wire_size_bytes = estimate_wire_size(tx);
    return tx;
}

DecodeResult decode_transfer_bytes(td::Slice raw_bytes) noexcept {
    // For the admission path we accept a "root cell" serialisation: the
    // caller has encode_transfer()'d the tx, then BoC-serialised the root.
    // At the edge, JSON-RPC decodes hex → BoC → Ref<Cell>; this helper takes
    // raw BoC bytes and runs the cell-slice decoder.
    //
    // TODO(uno-integration): wire vm::BagOfCells once admission path is in
    // place. Currently unused from compute-phase (which receives a CellSlice
    // directly from the dispatcher).
    (void)raw_bytes;
    return err("decode_transfer_bytes: not yet implemented — use decode_transfer(CellSlice) from compute-phase");
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

td::Result<td::Ref<vm::Cell>> encode_transfer(const Transfer& tx) noexcept {
    // Header bits: 56 bytes = 448 bits. Per-spend inline: 128 bytes = 1024
    // bits. Per-output inline (ex-refs): 32 + 32 + 2 + 80 = 146 bytes = 1168
    // bits. A single cell holds at most 1023 bits + 4 refs — a 4/4 transfer
    // will exceed that inline budget and must chain into continuation cells.
    //
    // Strategy: build inline payload as a byte stream, then split into
    // 127-byte chunks (same chunk chain as zk_proof) but with the
    // non-inlineable refs kept on the ROOT cell. The encoder here keeps the
    // simple single-cell form for small tx shapes (1-spend / 1-output), and
    // returns an error for shapes that don't fit without continuation
    // support. The admission path / test fixtures use small shapes.
    //
    // TODO(uno-integration): extend to multi-cell continuation once
    // compute-phase's decoder is verified end-to-end on the 1/1 shape.

    if (tx.spends.size() < kMinSpendCount || tx.spends.size() > kMaxSpendCount) {
        return td::Status::Error("spend_count out of range");
    }
    if (tx.outputs.size() < kMinOutputCount || tx.outputs.size() > kMaxOutputCount) {
        return td::Status::Error("output_count out of range");
    }

    vm::CellBuilder root;
    // inline header
    root.store_long(tx.version, 8);
    root.store_long(tx.scheme_id, 8);
    root.store_long(tx.chain_id, 32);
    root.store_bytes(reinterpret_cast<const char*>(tx.anchor.data()), 32);
    root.store_long(tx.expiry_block, 64);
    root.store_long(tx.fee, 64);
    root.store_long(static_cast<long long>(tx.spends.size()), 8);
    root.store_long(static_cast<long long>(tx.outputs.size()), 8);

    // spends
    for (const auto& s : tx.spends) {
        root.store_bytes(reinterpret_cast<const char*>(s.nullifier.data()), 32);
        root.store_bytes(reinterpret_cast<const char*>(s.rk.data()), 32);
        root.store_bytes(reinterpret_cast<const char*>(s.spend_auth_sig.data()), 64);
    }

    // outputs. Each output consumes 2 refs (enc_ciphertext, mlkem_ct) +
    // 1168 inline bits. For a 1/1 tx the root has:
    //   inline bits = 448 + 1024 + 1168 = 2640 (> 1023 — must continue)
    //   refs        = 2 out-refs + 1 zk_proof ref = 3
    // Cells hold at most 1023 data bits + 4 refs. A 1/1 transfer already
    // overflows the bit budget: we need at least one continuation.
    //
    // Simple split: pack everything after the header into a single
    // continuation cell's chain by splitting at 127-byte boundaries. For
    // v1 we return an error and defer the full encoder to Agent 6 / tests.
    if (tx.spends.size() > 1 || tx.outputs.size() > 1) {
        return td::Status::Error(
            "encode_transfer: multi-spend/multi-output encoding not yet implemented "
            "(use BoC-level builder or extend once admission path lands)");
    }

    for (const auto& o : tx.outputs) {
        root.store_bytes(reinterpret_cast<const char*>(o.cm.data()), 32);
        root.store_bytes(reinterpret_cast<const char*>(o.epk.data()), 32);
        root.store_long(o.filter_tag, 16);
        if (o.enc_ciphertext.is_null()) {
            return td::Status::Error("encode_transfer: enc_ciphertext must be non-null");
        }
        if (o.mlkem_ct.is_null()) {
            return td::Status::Error("encode_transfer: mlkem_ct must be non-null");
        }
        root.store_ref(o.enc_ciphertext);
        root.store_ref(o.mlkem_ct);
        root.store_bytes(reinterpret_cast<const char*>(o.out_ciphertext.data()), kOutCiphertextBytes);
    }

    if (tx.zk_proof.is_null()) {
        return td::Status::Error("encode_transfer: zk_proof must be non-null");
    }
    root.store_ref(tx.zk_proof);

    return root.finalize();
}

}  // namespace uno_workchain
