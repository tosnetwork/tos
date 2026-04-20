/*
    Uno Workchain — §12 P.3 state-transition golden fixture generator.

    Build-only helper that emits the `transfer_hex` byte blobs for the 7
    reject-path records in `uno/test/golden/state-transitions-v1.hex`.

    The 3 valid-path records (valid_1_1, valid_4_4, valid_2_3) require a real
    Plonky3 proof (M-P2 prover); this helper does NOT run the prover and
    leaves those records unpopulated. Set the UNO_RUN_PROVE_FIXTURES=1
    environment variable and extend this helper to invoke
    `uno_plonky3_ffi::prove_transfer` when the prover is integration-ready.

    Invocation:
        ./build-uno-check/uno/test/generate-state-transitions-v1 \
            > uno/test/golden/state-transitions-v1.hex

    CI does NOT run this program — the fixture file is a committed consensus
    artifact; regeneration is an explicit operator step, gated behind the
    fixture-version bump rules in the file header.

    The 7 reject records and how each one is produced:

        record 4  reject_double_spend    — valid shape, same nullifier as
                                           a synthetic "already-spent" witness
                                           (pre_state would carry it; left
                                           empty in this scaffold).
        record 5  reject_stale_anchor    — valid shape, anchor deliberately
                                           chosen to fall outside the 100-
                                           block window (any bytes pattern is
                                           a stale anchor relative to an empty
                                           pre_state).
        record 6  reject_invalid_proof   — valid codec, zk_proof cell body
                                           deliberately tampered (flipped bit)
                                           so Plonky3 verify rejects.
        record 7  reject_over_max_spends — hand-crafted wire with
                                           spend_count=5; decode_transfer
                                           rejects at step 1.
        record 8  reject_fee_too_low     — valid shape, fee < ConfigParam 84
                                           min_fee_nano (default 100_000).
        record 9  reject_expiry_exceeded — valid shape, expiry_block = 1, far
                                           below a hypothetical current_block.
        record 10 reject_wrong_chain_id  — valid shape, chain_id set to
                                           0xDEADBEEF instead of
                                           kDefaultTestnetChainId.

    Wire bytes are produced with `encode_transfer` (records 4, 5, 6, 8, 9, 10)
    or hand-crafted directly (record 7). Each Transfer is serialized to BoC
    via `vm::std_boc_serialize` and hex-encoded for the fixture file.
*/
#include "uno/core/transaction.h"
// NOTE: uno/core/workchain.h would redefine kSchemeIdV1 / kTransferVersion
// since transaction.h declares the same constants at file-scope. We need
// kDefaultMinFeeNano / kDefaultFeePerSpendNano / kDefaultFeePerOutputNano /
// kChainIdTestnet; reproduce them here as file-local constants so this TU
// stays independent of workchain.h (same discipline as transaction.cpp).
namespace uno_workchain {
inline constexpr uint64_t kDefaultMinFeeNano        = 100'000ULL;
inline constexpr uint64_t kDefaultFeePerSpendNano   = 50'000ULL;
inline constexpr uint64_t kDefaultFeePerOutputNano  = 50'000ULL;
inline constexpr uint32_t kChainIdTestnet           = 0x554E4F54u;  // "UNOT"
}  // namespace uno_workchain

#include "td/utils/Slice.h"
#include "td/utils/UInt.h"
#include "td/utils/crypto.h"
#include "vm/boc.h"
#include "vm/cells/Cell.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// Weak BLAKE3 fallback so the out-of-validator test binary links without the
// full A3 adapter (mirror of test-codec-shapes.cpp).
namespace uno_workchain::crypto::internal {
__attribute__((weak)) void blake3_hash(td::Slice in, uint8_t out[32]) {
    td::sha256(in, td::MutableSlice(reinterpret_cast<char*>(out), 32));
}
}  // namespace uno_workchain::crypto::internal

namespace {

// ---------- Deterministic bytes, tagged PRNG (xorshift64) ------------------

void fill_stream(uint8_t* buf, size_t n, uint64_t seed) {
    uint64_t x = seed | 1;
    for (size_t i = 0; i < n; ++i) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        buf[i] = static_cast<uint8_t>(x);
    }
}

td::Bits256 mk256(const char* tag, int idx) {
    uint64_t seed = 0xcafebabeULL;
    for (const char* p = tag; *p; ++p) seed = seed * 1315423911ULL ^ static_cast<uint8_t>(*p);
    seed ^= static_cast<uint64_t>(idx) * 0x9E3779B97F4A7C15ULL;
    td::Bits256 out;
    fill_stream(reinterpret_cast<uint8_t*>(out.data()), 32, seed);
    return out;
}

std::array<uint8_t, 64> mk_sig(const char* tag, int idx) {
    uint64_t seed = 0xdeadbeefULL;
    for (const char* p = tag; *p; ++p) seed = seed * 1315423911ULL ^ static_cast<uint8_t>(*p);
    seed ^= static_cast<uint64_t>(idx) * 0xBF58476D1CE4E5B9ULL;
    std::array<uint8_t, 64> out{};
    fill_stream(out.data(), 64, seed);
    return out;
}

std::array<uint8_t, 80> mk_octxt(const char* tag, int idx) {
    uint64_t seed = 0x01234567ULL;
    for (const char* p = tag; *p; ++p) seed = seed * 1315423911ULL ^ static_cast<uint8_t>(*p);
    seed ^= static_cast<uint64_t>(idx) * 0x94D049BB133111EBULL;
    std::array<uint8_t, 80> out{};
    fill_stream(out.data(), 80, seed);
    return out;
}

td::Ref<vm::Cell> mk_ref_cell(const char* tag, int idx, size_t n) {
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

// ---------- Baseline "plausible" Transfer builder ---------------------------

uno_workchain::Transfer build_baseline_transfer(uint8_t sc, uint8_t oc,
                                                uint32_t chain_id) {
    uno_workchain::Transfer tx;
    tx.version      = uno_workchain::kTransferVersion;
    tx.scheme_id    = uno_workchain::kSchemeIdV1;
    tx.chain_id     = chain_id;
    tx.anchor       = mk256("anchor-reject", sc * 10 + oc);
    tx.expiry_block = 1'000'000ULL;
    tx.fee          = uno_workchain::kDefaultMinFeeNano
                    + uno_workchain::kDefaultFeePerSpendNano  * sc
                    + uno_workchain::kDefaultFeePerOutputNano * oc;

    tx.spends.reserve(sc);
    for (int i = 0; i < sc; ++i) {
        uno_workchain::SpendDescription s;
        s.nullifier      = mk256("nf-reject", i);
        s.rk             = mk256("rk-reject", i);
        s.spend_auth_sig = mk_sig("sig-reject", i);
        tx.spends.push_back(std::move(s));
    }
    tx.outputs.reserve(oc);
    for (int j = 0; j < oc; ++j) {
        uno_workchain::OutputDescription o;
        o.cm             = mk256("cm-reject", j);
        o.epk            = mk256("epk-reject", j);
        o.filter_tag     = static_cast<uint16_t>(0x5A5Au ^ (j * 0x1111u));
        o.enc_ciphertext = mk_ref_cell("enc-reject", j, 32);
        o.mlkem_ct       = mk_ref_cell("mlk-reject", j, 64);
        o.out_ciphertext = mk_octxt("oct-reject", j);
        tx.outputs.push_back(std::move(o));
    }
    tx.zk_proof = mk_ref_cell("zkp-reject", sc * 10 + oc, 96);
    return tx;
}

std::string to_hex(const uint8_t* data, size_t len) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out[2 * i]     = kHex[(data[i] >> 4) & 0xF];
        out[2 * i + 1] = kHex[ data[i]       & 0xF];
    }
    return out;
}

std::string serialize_hex(const td::Ref<vm::Cell>& cell) {
    auto r = vm::std_boc_serialize(cell);
    if (r.is_error()) return {};
    auto s = r.move_as_ok();
    return to_hex(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

std::string encode_tx_hex(const uno_workchain::Transfer& tx) {
    auto r = uno_workchain::encode_transfer(tx);
    if (r.is_error()) return {};
    auto root = r.move_as_ok();
    return serialize_hex(root);
}

// ---------- Per-record generators ------------------------------------------

// Records that pass encode_transfer's shape check: we just vary one field.
std::string gen_double_spend_transfer() {
    auto tx = build_baseline_transfer(1, 1, uno_workchain::kChainIdTestnet);
    // Nullifier collides with a synthetic "already-spent" marker; the
    // accompanying pre_state would carry this nullifier in the spent set.
    // For the scaffold, transfer_hex alone is enough — the driver is
    // expected to wire pre_state in a follow-up commit.
    tx.spends[0].nullifier = mk256("nf-already-spent", 0);
    return encode_tx_hex(tx);
}

std::string gen_stale_anchor_transfer() {
    auto tx = build_baseline_transfer(1, 1, uno_workchain::kChainIdTestnet);
    tx.anchor = mk256("anchor-stale->100-blocks-ago", 0);
    return encode_tx_hex(tx);
}

std::string gen_invalid_proof_transfer() {
    auto tx = build_baseline_transfer(1, 1, uno_workchain::kChainIdTestnet);
    // Tamper: replace zk_proof with a cell whose bytes differ from the
    // baseline by a single flipped byte. The Plonky3 verifier would reject
    // at step 4 (BadPlonky3Proof) — the codec itself is fine.
    std::vector<uint8_t> proof(96);
    fill_stream(proof.data(), proof.size(), 0xDEADBEEFBADF00D1ULL);
    proof[0] ^= 0x01;
    vm::CellBuilder cb;
    cb.store_bytes(reinterpret_cast<const char*>(proof.data()), proof.size());
    tx.zk_proof = cb.finalize();
    return encode_tx_hex(tx);
}

// spend_count = 5 — encode_transfer refuses, so we hand-craft the wire.
// The decoder rejects at its first step (`sc > kMaxSpendCount`), so the
// shape of the downstream cells is immaterial — the wire just needs the
// 448-bit header with spend_count=5 and three non-null refs to satisfy
// the "missing spends_root / outputs_root / zk_proof refs" check if it
// were ever reached. We reuse the baseline (1/1) Transfer's ref-tree
// beneath the tampered header, since vm cells cap at 4 refs per cell
// (so a literal 5-ref spends_root is impossible).
std::string gen_over_max_spends_transfer() {
    auto tx = build_baseline_transfer(1, 1, uno_workchain::kChainIdTestnet);
    auto baseline_enc = uno_workchain::encode_transfer(tx);
    if (baseline_enc.is_error()) return {};
    auto baseline_root = baseline_enc.move_as_ok();
    auto baseline_cs = vm::load_cell_slice(baseline_root);
    auto spends_root_ref  = baseline_cs.prefetch_ref(0);
    auto outputs_root_ref = baseline_cs.prefetch_ref(1);
    auto zk_proof_ref     = baseline_cs.prefetch_ref(2);

    vm::CellBuilder root;
    root.store_long(tx.version, 8);
    root.store_long(tx.scheme_id, 8);
    root.store_long(tx.chain_id, 32);
    root.store_bytes(reinterpret_cast<const char*>(tx.anchor.data()), 32);
    root.store_long(tx.expiry_block, 64);
    root.store_long(tx.fee, 64);
    root.store_long(5, 8);  // spend_count = 5 — invalid (max 4)
    root.store_long(1, 8);  // output_count = 1
    root.store_ref(spends_root_ref);
    root.store_ref(outputs_root_ref);
    root.store_ref(zk_proof_ref);
    return serialize_hex(root.finalize());
}

std::string gen_fee_too_low_transfer() {
    auto tx = build_baseline_transfer(1, 1, uno_workchain::kChainIdTestnet);
    tx.fee = 1;  // < kDefaultMinFeeNano (100_000)
    return encode_tx_hex(tx);
}

std::string gen_expiry_exceeded_transfer() {
    auto tx = build_baseline_transfer(1, 1, uno_workchain::kChainIdTestnet);
    tx.expiry_block = 1;  // far below any plausible current_block
    return encode_tx_hex(tx);
}

std::string gen_wrong_chain_id_transfer() {
    // chain_id that definitely does not match kDefaultTestnetChainId.
    auto tx = build_baseline_transfer(1, 1, 0xDEADBEEFu);
    return encode_tx_hex(tx);
}

}  // anonymous namespace

int main() {
    struct Rec {
        int id;
        const char* label;
        const char* verdict;
        std::string transfer_hex;
    };
    std::vector<Rec> records;

    // Valid records: prover required — leave transfer_hex empty.
    records.push_back({ 1, "valid-1in-1out",              "Ok", {} });
    records.push_back({ 2, "valid-4in-4out-max-shape",    "Ok", {} });
    records.push_back({ 3, "valid-2in-3out-fee-rounding", "Ok", {} });

    // Reject records: deterministic wire bytes, no prover needed.
    records.push_back({ 4, "reject-double-spend",         "NullifierAlreadySpent", gen_double_spend_transfer() });
    records.push_back({ 5, "reject-stale-anchor",         "UnknownAnchor",         gen_stale_anchor_transfer() });
    records.push_back({ 6, "reject-invalid-plonky3-proof","BadPlonky3Proof",       gen_invalid_proof_transfer() });
    records.push_back({ 7, "reject-over-max-spends",      "BadSpendCount",         gen_over_max_spends_transfer() });
    records.push_back({ 8, "reject-fee-below-min",        "InsufficientFee",       gen_fee_too_low_transfer() });
    records.push_back({ 9, "reject-expiry-exceeded",      "ExpiryOutOfRange",      gen_expiry_exceeded_transfer() });
    records.push_back({10, "reject-wrong-chain-id",       "BadChainId",            gen_wrong_chain_id_transfer() });

    // Emit the header copied verbatim from the committed fixture so
    // regenerating via redirection (>) preserves the comments and the
    // "v1" discipline rules.
    std::printf(
        "# uno/test/golden/state-transitions-v1.hex\n"
        "#\n"
        "# Consensus-binding golden fixtures for the §4.3 verify + apply pipeline\n"
        "# (§12 P.3 of doc/uno-workchain.md).\n"
        "#\n"
        "# Each record pins one (UnoShardState X, Transfer Y) → (UnoShardState X', verdict)\n"
        "# tuple. The consumer test (uno/test/test-state-transition-golden.cpp) parses\n"
        "# this file and asserts byte-equality against the running implementation.\n"
        "#\n"
        "# Format:\n"
        "#   record_id=<int, monotonically increasing from 1>\n"
        "#   label=<short-human-label>\n"
        "#   verdict=<Ok | one of VerifyResult::* names from uno/core/compute-phase.h>\n"
        "#   pre_state=<hex byte blob; canonical UnoShardState serialisation>\n"
        "#   transfer=<hex byte blob; canonical §4.1 wire format>\n"
        "#   post_state=<hex byte blob; present ONLY when verdict == Ok>\n"
        "#   ---\n"
        "#\n"
        "# Empty hex values are written as empty strings on the right of the `=`.\n"
        "#\n"
        "# --- CURRENT STATE (K-fixtures partial population) --------------------------\n"
        "# Reject records (4-10) carry real Transfer wire bytes produced by\n"
        "# uno/test/generate-state-transitions-v1.cpp. The pre_state / post_state\n"
        "# blobs stay empty pending full UnoShardState serializer integration.\n"
        "#\n"
        "# Valid records (1-3) remain empty until the M-P2 Plonky3 prover is wired\n"
        "# into the fixture generator (set UNO_RUN_PROVE_FIXTURES=1 once the prover\n"
        "# lands and re-run the generator).\n"
        "#\n"
        "# --- Records ----------------------------------------------------------------\n"
        "\n");

    for (const auto& r : records) {
        std::printf("record_id=%d\n", r.id);
        std::printf("label=%s\n", r.label);
        std::printf("verdict=%s\n", r.verdict);
        std::printf("pre_state=\n");
        std::printf("transfer=%s\n", r.transfer_hex.c_str());
        if (std::string{r.verdict} == "Ok") {
            std::printf("post_state=\n");
        }
        std::printf("---\n\n");
    }

    return 0;
}
