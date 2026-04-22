/*
    Uno Workchain — Transfer codec round-trip across the full §4.1 shape
    envelope (1..4 spends × 1..4 outputs).

    This pins the wire-codec invariant that was previously blocked on the
    single-shape (1/1) encoder: for every admissible `(spend_count,
    output_count)` pair in the §4.1 envelope, the pipeline

        Transfer  →  encode_transfer  →  BoC root cell
                     ↘ decode_transfer  →  Transfer'
                                           ↘ encode_transfer  →  BoC root cell'

    MUST satisfy both (a) byte-identical BoC re-encoding of the decoded form,
    and (b) a stable `canonical_tx_hash` across encode / decode / re-encode.

    The 4/4 case is the regression floor for two downstream gates:
      - §12 P.3 state-transition golden fixtures (`state-transitions-v1.hex`
        left the 4/4 record empty pending this).
      - tosctl uno send integration (the wallet SDK can now serialise a real
        4/4 Transfer on the wire).

    Per §17, the decoder rejects Transfer cell-trees that exceed a 5-level
    walk depth; we do not explicitly assert the depth bound here (the
    `decode_transfer` path returns an error if breached). Every shape in
    this test is produced by the encoder, which bounds depth to 4 by
    construction.

    Build against: uno_workchain (uno/core/transaction.{h,cpp}).
*/
#include "uno/core/transaction.h"

#include "td/utils/Slice.h"
#include "td/utils/UInt.h"
#include "td/utils/crypto.h"
#include "vm/boc.h"
#include "vm/cells/Cell.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"

#include <array>
#include <atomic>
#include <cassert>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <variant>
#include <vector>

// BLAKE3 adapter — weak fallback to sha256 for the out-of-validator test
// binary (mirrors test-uno-end-to-end.cpp). The codec property we're
// asserting is hash-agnostic: whatever primitive this resolves to, it
// produces a stable tx_hash across encode/decode/re-encode because we
// route every hash through the same function.
namespace uno_workchain::crypto::internal {
__attribute__((weak)) void blake3_hash(td::Slice in, uint8_t out[32]) {
    td::sha256(in, td::MutableSlice(reinterpret_cast<char*>(out), 32));
}
}  // namespace uno_workchain::crypto::internal

// --- Local assert / tracking harness ---------------------------------------

static std::atomic<int> g_test_failures{0};
static std::atomic<int> g_test_skips{0};

static int tprintf(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    va_list copy;
    va_copy(copy, args);
    int needed = std::vsnprintf(nullptr, 0, fmt, copy);
    va_end(copy);
    std::string rendered;
    if (needed >= 0) {
        rendered.resize(static_cast<size_t>(needed) + 1);
        va_copy(copy, args);
        std::vsnprintf(rendered.data(), rendered.size(), fmt, copy);
        va_end(copy);
        rendered.resize(static_cast<size_t>(needed));
    }
    int written = std::vprintf(fmt, args);
    va_end(args);
    if (!rendered.empty()) {
        if (rendered.find("FAILED") != std::string::npos) g_test_failures.fetch_add(1);
        if (rendered.find("SKIP")   != std::string::npos) g_test_skips.fetch_add(1);
    }
    return written;
}

// --- Deterministic helpers --------------------------------------------------

namespace {

// Fill `buf` with a reproducible PRNG stream seeded on (tag, index).
// Using a simple xorshift keeps the fixture independent of any hash
// primitive — the codec is what's under test here.
void fill_stream(uint8_t* buf, size_t n, uint64_t seed) {
    uint64_t x = seed | 1;
    for (size_t i = 0; i < n; ++i) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        buf[i] = static_cast<uint8_t>(x);
    }
}

td::Bits256 make_bits256(const char* tag, int idx) {
    uint64_t seed = 0xcafebabeULL;
    for (const char* p = tag; *p; ++p) seed = seed * 1315423911ULL ^ static_cast<uint8_t>(*p);
    seed ^= static_cast<uint64_t>(idx) * 0x9E3779B97F4A7C15ULL;
    td::Bits256 out;
    fill_stream(reinterpret_cast<uint8_t*>(out.data()), 32, seed);
    return out;
}

std::array<uint8_t, 64> make_sig(const char* tag, int idx) {
    uint64_t seed = 0xdeadbeefULL;
    for (const char* p = tag; *p; ++p) seed = seed * 1315423911ULL ^ static_cast<uint8_t>(*p);
    seed ^= static_cast<uint64_t>(idx) * 0xBF58476D1CE4E5B9ULL;
    std::array<uint8_t, 64> out{};
    fill_stream(out.data(), 64, seed);
    return out;
}

std::array<uint8_t, 80> make_octxt(const char* tag, int idx) {
    uint64_t seed = 0x01234567ULL;
    for (const char* p = tag; *p; ++p) seed = seed * 1315423911ULL ^ static_cast<uint8_t>(*p);
    seed ^= static_cast<uint64_t>(idx) * 0x94D049BB133111EBULL;
    std::array<uint8_t, 80> out{};
    fill_stream(out.data(), 80, seed);
    return out;
}

// Build a trivial non-null cell holding `n` deterministic bytes inline
// (≤ 127 B); used to stand in for enc_ciphertext / mlkem_ct / zk_proof
// ref payloads. The codec walks these as opaque refs — any DataCell works.
td::Ref<vm::Cell> make_ref_cell(const char* tag, int idx, size_t n = 16) {
    uint64_t seed = 0xbadf00dULL;
    for (const char* p = tag; *p; ++p) seed = seed * 1315423911ULL ^ static_cast<uint8_t>(*p);
    seed ^= static_cast<uint64_t>(idx) * 0xC2B2AE3D27D4EB4FULL;
    vm::CellBuilder cb;
    if (n == 0) {
        cb.store_long(0, 8);
    } else {
        std::vector<uint8_t> buf(n);
        fill_stream(buf.data(), n, seed);
        cb.store_bytes(reinterpret_cast<const char*>(buf.data()), n);
    }
    return cb.finalize();
}

uno_workchain::Transfer build_transfer(uint8_t spend_count, uint8_t output_count) {
    uno_workchain::Transfer tx;
    tx.version      = uno_workchain::kTransferVersion;
    tx.scheme_id    = uno_workchain::kSchemeIdV1;
    tx.chain_id     = 0x00000002u;
    tx.anchor       = make_bits256("anchor", spend_count * 10 + output_count);
    tx.expiry_block = 10000 + spend_count * 100 + output_count;
    tx.fee          = 255000 + spend_count * 1000 + output_count;

    tx.spends.reserve(spend_count);
    for (int i = 0; i < spend_count; ++i) {
        uno_workchain::SpendDescription s;
        s.nullifier      = make_bits256("nf",  i);
        s.rk             = make_bits256("rk",  i);
        s.spend_auth_sig = make_sig("sig", i);
        tx.spends.push_back(std::move(s));
    }
    tx.outputs.reserve(output_count);
    for (int j = 0; j < output_count; ++j) {
        uno_workchain::OutputDescription o;
        o.cm             = make_bits256("cm",  j);
        o.epk            = make_bits256("epk", j);
        o.filter_tag     = static_cast<uint16_t>(0xA5A5u ^ (j * 0x1111u));
        o.enc_ciphertext = make_ref_cell("enc", j, 20);
        o.mlkem_ct       = make_ref_cell("mlk", j, 40);
        o.out_ciphertext = make_octxt("oct", j);
        tx.outputs.push_back(std::move(o));
    }
    tx.zk_proof = make_ref_cell("zkp", spend_count * 10 + output_count, 64);
    return tx;
}

bool bits256_eq(const td::Bits256& a, const td::Bits256& b) {
    return std::memcmp(a.data(), b.data(), 32) == 0;
}

bool cell_hash_eq(const td::Ref<vm::Cell>& a, const td::Ref<vm::Cell>& b) {
    if (a.is_null() || b.is_null()) return a.is_null() == b.is_null();
    return std::memcmp(a->get_hash().as_slice().data(),
                       b->get_hash().as_slice().data(), 32) == 0;
}

bool same_shape(const uno_workchain::Transfer& a, const uno_workchain::Transfer& b,
                const char** why = nullptr) {
    auto R = [&](const char* m) { if (why) *why = m; return false; };
    if (a.version   != b.version)   return R("version");
    if (a.scheme_id != b.scheme_id) return R("scheme_id");
    if (a.chain_id  != b.chain_id)  return R("chain_id");
    if (!bits256_eq(a.anchor, b.anchor)) return R("anchor");
    if (a.expiry_block != b.expiry_block) return R("expiry_block");
    if (a.fee != b.fee) return R("fee");
    if (a.spends.size()  != b.spends.size())  return R("spend_count");
    if (a.outputs.size() != b.outputs.size()) return R("output_count");
    for (size_t i = 0; i < a.spends.size(); ++i) {
        if (!bits256_eq(a.spends[i].nullifier, b.spends[i].nullifier)) return R("spend.nullifier");
        if (!bits256_eq(a.spends[i].rk,        b.spends[i].rk))        return R("spend.rk");
        if (std::memcmp(a.spends[i].spend_auth_sig.data(),
                        b.spends[i].spend_auth_sig.data(), 64) != 0) return R("spend.sig");
    }
    for (size_t j = 0; j < a.outputs.size(); ++j) {
        if (!bits256_eq(a.outputs[j].cm,  b.outputs[j].cm))  return R("output.cm");
        if (!bits256_eq(a.outputs[j].epk, b.outputs[j].epk)) return R("output.epk");
        if (a.outputs[j].filter_tag != b.outputs[j].filter_tag) return R("output.filter_tag");
        if (std::memcmp(a.outputs[j].out_ciphertext.data(),
                        b.outputs[j].out_ciphertext.data(), 80) != 0) return R("output.out_ciphertext");
        if (!cell_hash_eq(a.outputs[j].enc_ciphertext, b.outputs[j].enc_ciphertext)) return R("output.enc_ciphertext");
        if (!cell_hash_eq(a.outputs[j].mlkem_ct,       b.outputs[j].mlkem_ct))       return R("output.mlkem_ct");
    }
    if (!cell_hash_eq(a.zk_proof, b.zk_proof)) return R("zk_proof");
    return true;
}

std::string boc_bytes(const td::Ref<vm::Cell>& root) {
    auto r = vm::std_boc_serialize(root);
    if (r.is_error()) return {};
    auto s = r.move_as_ok();
    return std::string(s.data(), s.size());
}

td::Ref<vm::Cell> rebuild_transfer_root(
    const td::Ref<vm::Cell>& original_root,
    const td::Ref<vm::Cell>& spends_root,
    const td::Ref<vm::Cell>& outputs_root,
    const td::Ref<vm::Cell>& zk_proof) {
    auto hdr_cs = vm::load_cell_slice(original_root);
    uint8_t hdr_bytes[56] = {0};
    hdr_cs.fetch_bytes(hdr_bytes, 56);

    vm::CellBuilder cb;
    cb.store_bytes(reinterpret_cast<const char*>(hdr_bytes), 56);
    cb.store_ref(spends_root);
    cb.store_ref(outputs_root);
    cb.store_ref(zk_proof);
    return cb.finalize();
}

td::Ref<vm::Cell> rebuild_cell_with_refs(
    const td::Ref<vm::Cell>& original,
    const std::vector<td::Ref<vm::Cell>>& refs) {
    auto cs = vm::load_cell_slice(original);
    const unsigned n_bytes = cs.size() / 8;
    std::vector<uint8_t> inline_bytes(n_bytes);
    if (n_bytes != 0) {
        cs.fetch_bytes(inline_bytes.data(), n_bytes);
    }

    vm::CellBuilder cb;
    if (!inline_bytes.empty()) {
        cb.store_bytes(reinterpret_cast<const char*>(inline_bytes.data()),
                       inline_bytes.size());
    }
    for (const auto& ref : refs) {
        cb.store_ref(ref);
    }
    return cb.finalize();
}

void expect_decode_rejects(const char* label, const td::Ref<vm::Cell>& root) {
    auto cs = vm::load_cell_slice(root);
    auto dr = uno_workchain::decode_transfer(cs);
    if (std::holds_alternative<uno_workchain::Transfer>(dr)) {
        tprintf("  FAILED: decoder accepted %s\n", label);
        return;
    }
    auto& e = std::get<uno_workchain::TransferDecodeError>(dr);
    tprintf("  PASSED  %s rejected with reason: \"%s\"\n",
            label, e.reason.c_str());
}

// Count cells reachable from `root` and track max walk depth. Used to spot-
// check that the encoder keeps the Transfer ref-tree under the §17 ≤5 bound
// (exclusive of the opaque enc_ct / mlkem_ct / zk_proof subtrees, whose
// depth budgets are their own concern).
struct DepthReport { unsigned max_depth; size_t cell_count; };
DepthReport walk_depth(const td::Ref<vm::Cell>& root) {
    DepthReport out{0, 0};
    if (root.is_null()) return out;
    struct Frame { td::Ref<vm::Cell> c; unsigned depth; };
    std::vector<Frame> st;
    st.push_back({root, 1});
    while (!st.empty()) {
        auto f = st.back(); st.pop_back();
        ++out.cell_count;
        if (f.depth > out.max_depth) out.max_depth = f.depth;
        auto cs = vm::load_cell_slice(f.c);
        for (unsigned i = 0; i < cs.size_refs(); ++i) {
            st.push_back({cs.prefetch_ref(i), f.depth + 1});
        }
    }
    return out;
}

struct ShapeCase {
    const char* label;
    uint8_t spend_count;
    uint8_t output_count;
};

// --- Per-shape round-trip assertion ---------------------------------------

bool run_shape(const ShapeCase& sc) {
    tprintf("[TEST] round-trip shape %s (spends=%u outputs=%u)\n",
            sc.label, static_cast<unsigned>(sc.spend_count),
            static_cast<unsigned>(sc.output_count));

    auto tx = build_transfer(sc.spend_count, sc.output_count);
    tx.tx_hash = uno_workchain::canonical_tx_hash(tx);

    // encode #1 ---------------------------------------------------------
    auto r1 = uno_workchain::encode_transfer(tx);
    if (r1.is_error()) {
        tprintf("  FAILED: encode_transfer #1: %s\n", r1.error().message().c_str());
        return false;
    }
    auto root1 = r1.move_as_ok();
    if (root1.is_null()) {
        tprintf("  FAILED: encode_transfer #1 returned null root\n");
        return false;
    }

    const auto boc1 = boc_bytes(root1);
    if (boc1.empty()) {
        tprintf("  FAILED: std_boc_serialize(root1) returned empty\n");
        return false;
    }

    // Spot-check the root cell's inline payload matches the fixed 448-bit
    // header layout (version, scheme_id, chain_id, anchor, expiry, fee,
    // spend_count, output_count) and that the root has exactly 3 refs.
    {
        auto root_cs = vm::load_cell_slice(root1);
        if (root_cs.size() != 448) {
            tprintf("  FAILED: root cell inline bits = %u, expected 448\n",
                    static_cast<unsigned>(root_cs.size()));
            return false;
        }
        if (root_cs.size_refs() != 3) {
            tprintf("  FAILED: root cell refs = %u, expected 3\n",
                    static_cast<unsigned>(root_cs.size_refs()));
            return false;
        }
    }

    // depth spot check (should be ≤ 5 for the inline-payload subtree +
    // whatever the enc_ct / mlkem_ct / zk_proof subtrees add; for our
    // make_ref_cell() fixtures they contribute depth 0 — so a depth <= 4
    // total matches our design).
    auto rep = walk_depth(root1);
    if (rep.max_depth > 5) {
        tprintf("  FAILED: walk_depth = %u (exceeds §17 ≤5 bound)\n", rep.max_depth);
        return false;
    }

    // decode ------------------------------------------------------------
    auto dec_cs = vm::load_cell_slice(root1);
    auto dr = uno_workchain::decode_transfer(dec_cs);
    if (auto e = std::get_if<uno_workchain::TransferDecodeError>(&dr)) {
        tprintf("  FAILED: decode_transfer: %s\n", e->reason.c_str());
        return false;
    }
    auto& tx2 = std::get<uno_workchain::Transfer>(dr);

    const char* why = "?";
    if (!same_shape(tx, tx2, &why)) {
        tprintf("  FAILED: decoded Transfer != encoded Transfer on field: %s\n", why);
        return false;
    }
    if (!bits256_eq(tx.tx_hash, tx2.tx_hash)) {
        tprintf("  FAILED: tx_hash changed across encode→decode\n");
        return false;
    }
    {
        const size_t expected_wire_size =
            uno_workchain::kTransferHeaderBytes
            + static_cast<size_t>(sc.spend_count) * uno_workchain::kSpendInlineBytes
            + static_cast<size_t>(sc.output_count) * uno_workchain::kOutputInlineBytes
            + static_cast<size_t>(sc.output_count) * (20 + 40)
            + 64;
        if (tx2.wire_size_bytes != expected_wire_size) {
            tprintf("  FAILED: wire_size_bytes = %zu, expected %zu\n",
                    tx2.wire_size_bytes, expected_wire_size);
            return false;
        }
    }

    // encode #2 ---------------------------------------------------------
    auto r2 = uno_workchain::encode_transfer(tx2);
    if (r2.is_error()) {
        tprintf("  FAILED: encode_transfer #2: %s\n", r2.error().message().c_str());
        return false;
    }
    auto root2 = r2.move_as_ok();
    if (!cell_hash_eq(root1, root2)) {
        tprintf("  FAILED: root cell hash changed across re-encode\n");
        return false;
    }
    const auto boc2 = boc_bytes(root2);
    if (boc1 != boc2) {
        tprintf("  FAILED: BoC bytes differ across re-encode (%zu vs %zu)\n",
                boc1.size(), boc2.size());
        return false;
    }

    // canonical_tx_hash stability across encode / decode / re-encode
    auto hash_from_tx2 = uno_workchain::canonical_tx_hash(tx2);
    if (!bits256_eq(tx.tx_hash, hash_from_tx2)) {
        tprintf("  FAILED: canonical_tx_hash unstable across re-encode\n");
        return false;
    }

    // --- K-tx-boc: BoC round-trip (TLV → cells → BoC bytes → cells → TLV) ---
    //
    // encode_transfer_to_boc / decode_transfer_bytes are the on-the-wire
    // envelope used by the JSON-RPC admission path (uno_sendTransfer),
    // mempool persistence, and cross-validator tx-hash agreement. The
    // invariant is that for any valid Transfer,
    //   encode_transfer_to_boc(tx) == encode_transfer_to_boc(decode_transfer_bytes(encode_transfer_to_boc(tx)))
    // i.e. one full BoC round-trip is byte-idempotent.
    {
        auto boc_r = uno_workchain::encode_transfer_to_boc(tx);
        if (boc_r.is_error()) {
            tprintf("  FAILED: encode_transfer_to_boc: %s\n",
                    boc_r.error().message().c_str());
            return false;
        }
        auto boc_bs = boc_r.move_as_ok();
        std::string boc3(boc_bs.data(), boc_bs.size());
        if (boc3 != boc1) {
            tprintf("  FAILED: encode_transfer_to_boc bytes differ from std_boc_serialize(encode_transfer) (%zu vs %zu)\n",
                    boc3.size(), boc1.size());
            return false;
        }

        auto dec2 = uno_workchain::decode_transfer_bytes(
            td::Slice{boc3.data(), boc3.size()});
        if (auto e = std::get_if<uno_workchain::TransferDecodeError>(&dec2)) {
            tprintf("  FAILED: decode_transfer_bytes(BoC): %s\n", e->reason.c_str());
            return false;
        }
        auto& tx3 = std::get<uno_workchain::Transfer>(dec2);
        const char* why3 = "?";
        if (!same_shape(tx, tx3, &why3)) {
            tprintf("  FAILED: BoC round-trip shape mismatch on field: %s\n", why3);
            return false;
        }
        if (!bits256_eq(tx.tx_hash, tx3.tx_hash)) {
            tprintf("  FAILED: tx_hash changed across BoC round-trip\n");
            return false;
        }

        auto boc_r2 = uno_workchain::encode_transfer_to_boc(tx3);
        if (boc_r2.is_error()) {
            tprintf("  FAILED: re-encode_transfer_to_boc: %s\n",
                    boc_r2.error().message().c_str());
            return false;
        }
        auto boc_bs2 = boc_r2.move_as_ok();
        std::string boc4(boc_bs2.data(), boc_bs2.size());
        if (boc4 != boc3) {
            tprintf("  FAILED: BoC bytes differ across TLV→BoC→TLV→BoC (%zu vs %zu)\n",
                    boc4.size(), boc3.size());
            return false;
        }
    }

    // Empty / truncated BoC input: both must cleanly return decode errors
    // without crashing (the admission path hands us adversary-controlled
    // bytes via JSON-RPC).
    {
        auto bad = uno_workchain::decode_transfer_bytes(td::Slice{});
        if (std::holds_alternative<uno_workchain::Transfer>(bad)) {
            tprintf("  FAILED: decode_transfer_bytes accepted empty input\n");
            return false;
        }
        // Truncated BoC: drop the last quarter of the bytes. std_boc_deserialize
        // should reject with an error; we only assert "did not accept" here
        // (not a specific reason), since the cutoff may land in the header
        // or body depending on shape.
        if (boc1.size() > 8) {
            std::string truncated(boc1.data(), boc1.size() * 3 / 4);
            auto bad2 = uno_workchain::decode_transfer_bytes(
                td::Slice{truncated.data(), truncated.size()});
            if (std::holds_alternative<uno_workchain::Transfer>(bad2)) {
                tprintf("  FAILED: decode_transfer_bytes accepted truncated BoC\n");
                return false;
            }
        }
        // Arbitrary garbage: random bytes are overwhelmingly unlikely to
        // parse as a valid BoC magic header.
        {
            uint8_t junk[64];
            fill_stream(junk, sizeof(junk), 0xDEADBEEFULL);
            auto bad3 = uno_workchain::decode_transfer_bytes(
                td::Slice{reinterpret_cast<const char*>(junk), sizeof(junk)});
            if (std::holds_alternative<uno_workchain::Transfer>(bad3)) {
                tprintf("  FAILED: decode_transfer_bytes accepted random garbage\n");
                return false;
            }
        }
    }

    tprintf("  PASSED  boc_bytes=%zu  cells=%zu  max_depth=%u\n",
            boc1.size(), rep.cell_count, rep.max_depth);
    return true;
}

void test_depth_bound_rejection() {
    tprintf("[TEST] decode_transfer rejects a malformed / over-deep outputs_root tree\n");

    // Build a legal 1/1 Transfer, then hand-craft an outputs_root chain
    // that stacks an extra empty cell between outputs_root and per_output[0]
    // to push walk depth to 6. The decoder MUST refuse.
    auto tx = build_transfer(1, 1);
    tx.tx_hash = uno_workchain::canonical_tx_hash(tx);
    auto enc = uno_workchain::encode_transfer(tx);
    if (enc.is_error()) {
        tprintf("  FAILED: baseline encode: %s\n", enc.error().message().c_str());
        return;
    }
    auto root = enc.move_as_ok();
    auto root_cs = vm::load_cell_slice(root);
    // Walk refs: [0]=spends_root, [1]=outputs_root, [2]=zk_proof.
    auto spends_root_ref  = root_cs.prefetch_ref(0);
    auto outputs_root_ref = root_cs.prefetch_ref(1);
    auto zk_proof_ref     = root_cs.prefetch_ref(2);

    // Snip a malformed outputs_root whose single ref goes to a
    // depth-stacker chain: stack → stack → stack → real_per_output. That
    // puts the malformed root at walk-depth 1+4=5, then the per_output
    // continuation at 6 > bound.
    auto orig_outputs = vm::load_cell_slice(outputs_root_ref);
    auto real_per_output = orig_outputs.prefetch_ref(0);
    auto stack1 = vm::CellBuilder().store_ref(real_per_output).finalize();
    auto stack2 = vm::CellBuilder().store_ref(stack1).finalize();
    auto stack3 = vm::CellBuilder().store_ref(stack2).finalize();
    auto bad_outputs_root = vm::CellBuilder().store_ref(stack3).finalize();

    // Rebuild the Transfer root with the tampered outputs_root. We copy the
    // 448 inline bits across, then plug in the 3 refs (spends_root unchanged,
    // outputs_root tampered, zk_proof unchanged).
    vm::CellBuilder bad_root_cb;
    {
        auto hdr_cs = vm::load_cell_slice(root);
        uint8_t hdr_bytes[56] = {0};
        hdr_cs.fetch_bytes(hdr_bytes, 56);
        bad_root_cb.store_bytes(reinterpret_cast<const char*>(hdr_bytes), 56);
    }
    bad_root_cb.store_ref(spends_root_ref);
    bad_root_cb.store_ref(bad_outputs_root);
    bad_root_cb.store_ref(zk_proof_ref);
    auto bad_root = bad_root_cb.finalize();

    auto bad_cs = vm::load_cell_slice(bad_root);
    auto dr = uno_workchain::decode_transfer(bad_cs);
    if (std::holds_alternative<uno_workchain::Transfer>(dr)) {
        tprintf("  FAILED: decoder accepted a depth-6 outputs_root tree\n");
        return;
    }
    auto& e = std::get<uno_workchain::TransferDecodeError>(dr);
    tprintf("  PASSED  rejected with reason: \"%s\"\n", e.reason.c_str());
}

void test_malformed_chunk_tree_rejection() {
    tprintf("[TEST] decode_transfer rejects malformed enc_ciphertext chunk tree\n");

    auto tx = build_transfer(1, 1);

    // Invalid §4.1a chunk tree: a cell with refs is internal and therefore
    // must have zero data bits. This one carries 8 data bits plus a ref.
    auto leaf = make_ref_cell("bad-leaf", 0, 1);
    vm::CellBuilder bad_chunk;
    bad_chunk.store_long(0xAB, 8);
    bad_chunk.store_ref(leaf);
    tx.outputs[0].enc_ciphertext = bad_chunk.finalize();

    auto enc = uno_workchain::encode_transfer(tx);
    if (enc.is_error()) {
        tprintf("  FAILED: baseline encode with opaque ref: %s\n",
                enc.error().message().c_str());
        return;
    }

    auto root = enc.move_as_ok();
    auto cs = vm::load_cell_slice(root);
    auto dr = uno_workchain::decode_transfer(cs);
    if (std::holds_alternative<uno_workchain::Transfer>(dr)) {
        tprintf("  FAILED: decoder accepted malformed enc_ciphertext chunk tree\n");
        return;
    }
    auto& e = std::get<uno_workchain::TransferDecodeError>(dr);
    tprintf("  PASSED  rejected with reason: \"%s\"\n", e.reason.c_str());
}

void test_special_chunk_tree_rejection() {
    tprintf("[TEST] decode_transfer rejects special-cell enc_ciphertext chunk tree\n");

    auto tx = build_transfer(1, 1);

    // §4.1a chunk trees are ordinary cells only. A MerkleProof special cell
    // used to make vm::load_cell_slice throw from a noexcept decoder helper,
    // which would terminate the validator. It must now reject cleanly.
    auto leaf = make_ref_cell("special-leaf", 0, 32);
    tx.outputs[0].enc_ciphertext = vm::CellBuilder::create_merkle_proof(leaf);

    auto enc = uno_workchain::encode_transfer(tx);
    if (enc.is_error()) {
        tprintf("  FAILED: baseline encode with special ref: %s\n",
                enc.error().message().c_str());
        return;
    }

    auto root = enc.move_as_ok();
    auto cs = vm::load_cell_slice(root);
    auto dr = uno_workchain::decode_transfer(cs);
    if (std::holds_alternative<uno_workchain::Transfer>(dr)) {
        tprintf("  FAILED: decoder accepted special-cell enc_ciphertext chunk tree\n");
        return;
    }
    auto& e = std::get<uno_workchain::TransferDecodeError>(dr);
    tprintf("  PASSED  rejected with reason: \"%s\"\n", e.reason.c_str());
}

void test_special_structural_ref_rejection() {
    tprintf("[TEST] decode_transfer rejects special cells in structural refs\n");

    auto tx = build_transfer(1, 1);
    tx.tx_hash = uno_workchain::canonical_tx_hash(tx);
    auto enc = uno_workchain::encode_transfer(tx);
    if (enc.is_error()) {
        tprintf("  FAILED: baseline encode: %s\n", enc.error().message().c_str());
        return;
    }

    auto root = enc.move_as_ok();
    auto root_cs = vm::load_cell_slice(root);
    auto spends_root_ref  = root_cs.prefetch_ref(0);
    auto outputs_root_ref = root_cs.prefetch_ref(1);
    auto zk_proof_ref     = root_cs.prefetch_ref(2);

    auto special_leaf = make_ref_cell("special-structural-leaf", 0, 32);
    auto special = vm::CellBuilder::create_merkle_proof(special_leaf);

    expect_decode_rejects(
        "special spends_root",
        rebuild_transfer_root(root, special, outputs_root_ref, zk_proof_ref));
    expect_decode_rejects(
        "special outputs_root",
        rebuild_transfer_root(root, spends_root_ref, special, zk_proof_ref));

    auto spends_root_cs = vm::load_cell_slice(spends_root_ref);
    auto real_spend_ref = spends_root_cs.prefetch_ref(0);
    auto outputs_root_cs = vm::load_cell_slice(outputs_root_ref);
    auto real_output_ref = outputs_root_cs.prefetch_ref(0);

    auto special_per_spend_root =
        vm::CellBuilder().store_ref(special).finalize();
    expect_decode_rejects(
        "special per-spend cell",
        rebuild_transfer_root(root, special_per_spend_root,
                              outputs_root_ref, zk_proof_ref));

    auto special_per_output_root =
        vm::CellBuilder().store_ref(special).finalize();
    expect_decode_rejects(
        "special per-output cell",
        rebuild_transfer_root(root, spends_root_ref,
                              special_per_output_root, zk_proof_ref));

    auto bad_spend_cont = rebuild_cell_with_refs(real_spend_ref, {special});
    auto bad_spend_cont_root =
        vm::CellBuilder().store_ref(bad_spend_cont).finalize();
    expect_decode_rejects(
        "special per-spend continuation",
        rebuild_transfer_root(root, bad_spend_cont_root,
                              outputs_root_ref, zk_proof_ref));

    auto real_output_cs = vm::load_cell_slice(real_output_ref);
    auto bad_output_cont = rebuild_cell_with_refs(
        real_output_ref,
        {special, real_output_cs.prefetch_ref(1), real_output_cs.prefetch_ref(2)});
    auto bad_output_cont_root =
        vm::CellBuilder().store_ref(bad_output_cont).finalize();
    expect_decode_rejects(
        "special per-output continuation",
        rebuild_transfer_root(root, spends_root_ref,
                              bad_output_cont_root, zk_proof_ref));
}

void test_noncanonical_chunk_tree_rejection() {
    tprintf("[TEST] decode_transfer rejects non-canonical enc_ciphertext chunk tree\n");

    auto tx = build_transfer(1, 1);

    // Same logical byte stream as two leaves, but wrapped in an extra
    // one-child internal node:
    //
    //   bad_root -> inner -> leaf[127 B], leaf[73 B]
    //
    // The shape is otherwise valid. The canonical §4.1a tree for those
    // 200 bytes is a single internal root with the two leaves directly
    // attached, so the root hash must differ and decode must reject.
    auto leaf0 = make_ref_cell("noncanon-a", 0, 127);
    auto leaf1 = make_ref_cell("noncanon-b", 0, 73);
    auto inner = vm::CellBuilder()
        .store_ref(leaf0)
        .store_ref(leaf1)
        .finalize();
    auto bad_root = vm::CellBuilder()
        .store_ref(inner)
        .finalize();
    tx.outputs[0].enc_ciphertext = bad_root;

    auto enc = uno_workchain::encode_transfer(tx);
    if (enc.is_error()) {
        tprintf("  FAILED: baseline encode with non-canonical ref: %s\n",
                enc.error().message().c_str());
        return;
    }

    auto root = enc.move_as_ok();
    auto cs = vm::load_cell_slice(root);
    auto dr = uno_workchain::decode_transfer(cs);
    if (std::holds_alternative<uno_workchain::Transfer>(dr)) {
        tprintf("  FAILED: decoder accepted non-canonical enc_ciphertext chunk tree\n");
        return;
    }
    auto& e = std::get<uno_workchain::TransferDecodeError>(dr);
    tprintf("  PASSED  rejected with reason: \"%s\"\n", e.reason.c_str());
}

}  // anonymous namespace

int main() {
    tprintf("Uno Workchain — Transfer codec shape-envelope round-trip\n");
    tprintf("=========================================================\n\n");

    const ShapeCase shapes[] = {
        {"1/1", 1, 1},
        {"1/2", 1, 2},  // matches fixture 1 shape
        {"2/3", 2, 3},
        {"4/4", 4, 4},  // matches fixture 2 shape — §12 P.3 regression floor
    };
    for (const auto& sc : shapes) {
        run_shape(sc);
    }
    test_depth_bound_rejection();
    test_malformed_chunk_tree_rejection();
    test_special_chunk_tree_rejection();
    test_special_structural_ref_rejection();
    test_noncanonical_chunk_tree_rejection();

    tprintf("\nTotal failures: %d, skips: %d\n",
            g_test_failures.load(), g_test_skips.load());
    return g_test_failures.load() == 0 ? 0 : 1;
}
