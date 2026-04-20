/*
    Uno Workchain — K-codec-parity: cross-impl byte-parity test for the
    §4.1 Transfer codec primitives.

    This is the C++ half of the Rust ↔ C++ parity gate for every
    consensus-binding byte the validator emits. It reads the golden
    fixture at `uno/test/golden/codec-parity-v1.hex` (produced by the Rust
    integration test `uno/plonky3-ffi/tests/codec_parity_goldens.rs`) and
    asserts that, for each of the four pinned shapes (1/1, 1/2, 2/3, 4/4):

      * `build_plonky3_public_inputs(tx).to_bytes()` matches the recorded
        `pubinput_hex` byte-for-byte (already covered by
        test-uno-public-input-fixture; replayed here so a single target
        exercises the full derived-field surface).

      * The recorded `cm_hex` matches an independent recomputation via
        `uno_workchain::compute_note_commitment` from the fixture's
        `d / pk_d / ivk_commitment / value / rcm` inputs.

      * The recorded `ivk_commitment_hex` matches a recomputation via the
        Poseidon2 sponge under tag `uno-ivk-cm-v1`, with inputs packed as
        `ivk (32 B → 4 fes) || d (11 B padded to 16 B → 2 fes)` — byte-
        identical to `tosctl/uno/src/keygen.rs::ivk_commitment` and to the
        Transfer AIR's claim-3 row-0 binding.

      * The recorded `nf_hex` matches a recomputation via the Poseidon2
        sponge under tag `uno-nf-v1`, with inputs packed as
        `nk (32 B → 4 fes) || cm_input_for_nf (32 B → 4 fes) || pos (1 fe)`.

      * The recorded `tx_hash_hex` matches a BLAKE3 over the §4.1
        canonical preimage assembled from the decoded Transfer fields plus
        the pinned `enc_ct_hash` / `mlkem_ct_hash` values (plugged in at
        the cell-hash slots so the BLAKE3 input is a pure function of the
        fixture's recorded bytes — no TOS Cell machinery involved).

    K-genesis-distribution found a pre-existing divergence in
    `"uno-rcm-v1"` tag handling that was invisible because no such parity
    test existed. This file is the defence-in-depth: a single missing /
    extra byte anywhere in any of the five derived-field encoders above
    trips an explicit FAILED line here.

    Source: TOS-specific adapter — consensus-critical codec parity.
*/
#include "uno/core/transaction.h"
#include "uno/crypto/goldilocks.h"
#include "uno/crypto/internal/blake3_adapter.h"
#include "uno/crypto/poseidon2.h"

#include <array>
#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {

// ----- Pass/fail harness ----------------------------------------------------

std::atomic<int> g_failures{0};
std::atomic<int> g_passes{0};

static void fail(const std::string& msg) {
    std::fprintf(stderr, "FAILED: %s\n", msg.c_str());
    g_failures.fetch_add(1);
}
static void pass(const std::string& msg) {
    std::printf("ok: %s\n", msg.c_str());
    g_passes.fetch_add(1);
}

// ----- Hex helpers ----------------------------------------------------------

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static bool parse_hex(const std::string& s, std::vector<uint8_t>& out) {
    out.clear();
    if (s.size() % 2 != 0) return false;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        int hi = hex_nibble(s[i]);
        int lo = hex_nibble(s[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

static std::string to_hex(const uint8_t* p, size_t n) {
    static const char d[] = "0123456789abcdef";
    std::string out(n * 2, '0');
    for (size_t i = 0; i < n; ++i) {
        out[2 * i + 0] = d[p[i] >> 4];
        out[2 * i + 1] = d[p[i] & 0xF];
    }
    return out;
}

static inline uint16_t read_le_u16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | (uint16_t(p[1]) << 8));
}
static inline uint32_t read_le_u32(const uint8_t* p) {
    return uint32_t(p[0])
         | (uint32_t(p[1]) << 8)
         | (uint32_t(p[2]) << 16)
         | (uint32_t(p[3]) << 24);
}
static inline uint64_t read_le_u64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= uint64_t(p[i]) << (8 * i);
    return v;
}

// ----- Fixture record -------------------------------------------------------

struct FixtureOutputInputs {
    std::array<uint8_t, 11> d{};
    std::array<uint8_t, 32> pk_d{};
    std::array<uint8_t, 32> ivk_commitment{};
    uint64_t value{0};
    std::array<uint8_t, 32> rcm{};
    std::array<uint8_t, 32> ivk{};
    std::array<uint8_t, 32> rseed{};
    std::array<uint8_t, 32> enc_ct_hash{};
    std::array<uint8_t, 32> mlkem_ct_hash{};
};

struct FixtureSpendInputs {
    std::array<uint8_t, 32> nk{};
    std::array<uint8_t, 32> cm_input_for_nf{};
    uint64_t pos{0};
};

struct FixtureRecord {
    uint8_t  n_spends{0};
    uint8_t  n_outputs{0};
    uno_workchain::Transfer tx;
    std::vector<uint8_t> pubinput_expected;
    std::vector<uint8_t> tx_hash_expected;                   // 32 B
    std::vector<std::array<uint8_t, 32>> cm_expected;        // per output
    std::vector<std::array<uint8_t, 32>> ivk_cm_expected;    // per output
    std::vector<std::array<uint8_t, 32>> nf_expected;        // per spend
    std::vector<FixtureOutputInputs> output_inputs;          // per output
    std::vector<FixtureSpendInputs>  spend_inputs;           // per spend
    int line_no{0};
};

// Parse the fixture-internal Transfer layout documented at the top of the
// golden fixture. Populates both the `uno_workchain::Transfer` struct that
// the C++ codec consumes AND the `*_inputs` side-tables the parity test
// uses to re-derive the cm / ivk_cm / nf values.
static bool decode_fixture_transfer(const std::vector<uint8_t>& bytes,
                                    FixtureRecord& rec) {
    auto& tx = rec.tx;
    size_t off = 0;
    const size_t hdr = 1 + 4 + 8 + 8 + 1 + 1 + 32;
    if (bytes.size() < hdr) return false;

    tx.version      = uno_workchain::kTransferVersion;
    tx.scheme_id    = bytes[off++];
    tx.chain_id     = read_le_u32(&bytes[off]); off += 4;
    tx.expiry_block = read_le_u64(&bytes[off]); off += 8;
    tx.fee          = read_le_u64(&bytes[off]); off += 8;
    uint8_t sc = bytes[off++];
    uint8_t oc = bytes[off++];
    std::memcpy(tx.anchor.data(), &bytes[off], 32); off += 32;

    if (sc < uno_workchain::kMinSpendCount  || sc > uno_workchain::kMaxSpendCount)  return false;
    if (oc < uno_workchain::kMinOutputCount || oc > uno_workchain::kMaxOutputCount) return false;

    const size_t per_spend  = 32 + 32 + 32 + 32 + 8; // nf || rk || nk || cm_for_nf || pos
    const size_t per_output = 32 + 32 + 2 + 80 + 32 + 32
                             + 11 + 32 + 32 + 8 + 32 + 32 + 32;
    const size_t need = off + size_t(sc) * per_spend + size_t(oc) * per_output;
    if (bytes.size() < need) return false;

    rec.n_spends  = sc;
    rec.n_outputs = oc;
    tx.spends.resize(sc);
    tx.outputs.resize(oc);
    rec.spend_inputs.resize(sc);
    rec.output_inputs.resize(oc);

    for (uint8_t i = 0; i < sc; ++i) {
        auto& s  = tx.spends[i];
        auto& si = rec.spend_inputs[i];
        std::memcpy(s.nullifier.data(), &bytes[off], 32); off += 32;
        std::memcpy(s.rk.data(),        &bytes[off], 32); off += 32;
        std::memcpy(si.nk.data(),       &bytes[off], 32); off += 32;
        std::memcpy(si.cm_input_for_nf.data(), &bytes[off], 32); off += 32;
        si.pos = read_le_u64(&bytes[off]); off += 8;
        // spend_auth_sig not pinned by this fixture (excluded from tx_hash
        // per §4.1). Zero-fill is safe; it does NOT enter the preimage.
        s.spend_auth_sig.fill(0);
    }
    for (uint8_t j = 0; j < oc; ++j) {
        auto& o  = tx.outputs[j];
        auto& oi = rec.output_inputs[j];
        std::memcpy(o.cm.data(),  &bytes[off], 32); off += 32;
        std::memcpy(o.epk.data(), &bytes[off], 32); off += 32;
        o.filter_tag = read_le_u16(&bytes[off]); off += 2;
        std::memcpy(o.out_ciphertext.data(), &bytes[off], 80); off += 80;
        std::memcpy(oi.enc_ct_hash.data(),   &bytes[off], 32); off += 32;
        std::memcpy(oi.mlkem_ct_hash.data(), &bytes[off], 32); off += 32;
        std::memcpy(oi.d.data(),    &bytes[off], 11); off += 11;
        std::memcpy(oi.pk_d.data(), &bytes[off], 32); off += 32;
        std::memcpy(oi.ivk_commitment.data(), &bytes[off], 32); off += 32;
        oi.value = read_le_u64(&bytes[off]); off += 8;
        std::memcpy(oi.rcm.data(),   &bytes[off], 32); off += 32;
        std::memcpy(oi.ivk.data(),   &bytes[off], 32); off += 32;
        std::memcpy(oi.rseed.data(), &bytes[off], 32); off += 32;

        // The `uno_workchain::Transfer` only carries 32-byte cm/epk and the
        // two refs — the refs are intentionally null here (we don't build
        // real Cell trees for this parity test; build_plonky3_public_inputs
        // does not read them, and the tx_hash path in this test bypasses
        // canonical_tx_hash() to avoid depending on Cell::get_hash()).
    }
    return off == bytes.size();
}

// ----- Canonical tx_hash preimage (pure; no Cell refs) ---------------------
//
// Mirrors uno/core/transaction.cpp :: canonical_tx_hash, but takes pinned
// 32-byte cell-hash values as inputs instead of walking `td::Ref<vm::Cell>`.
// This is consensus-equivalent for the BLAKE3 output iff
// `get_hash()` of the C++ Transfer's real cells produces exactly these
// pinned values — a claim the §12 P.4 / P.3 golden fixtures already pin
// elsewhere, and not the property this test is measuring. What THIS test
// measures is the preimage assembly + BLAKE3 output byte-for-byte against
// the Rust generator.

static void write_be_u16(uint8_t* p, uint16_t v) { p[0] = uint8_t(v >> 8); p[1] = uint8_t(v); }
static void write_be_u32(uint8_t* p, uint32_t v) {
    p[0] = uint8_t(v >> 24); p[1] = uint8_t(v >> 16);
    p[2] = uint8_t(v >>  8); p[3] = uint8_t(v);
}
static void write_be_u64(uint8_t* p, uint64_t v) {
    for (int i = 7; i >= 0; --i) { p[i] = uint8_t(v); v >>= 8; }
}

static std::vector<uint8_t> build_tx_hash_preimage(const FixtureRecord& rec) {
    const auto& tx = rec.tx;
    std::vector<uint8_t> buf;
    buf.reserve(56 + rec.n_spends * 64 + rec.n_outputs * (32 + 32 + 2 + 32 + 32 + 80));
    auto push = [&](const uint8_t* p, size_t n) {
        buf.insert(buf.end(), p, p + n);
    };
    buf.push_back(tx.version);
    buf.push_back(tx.scheme_id);
    {
        uint8_t tmp[4]; write_be_u32(tmp, tx.chain_id); push(tmp, 4);
    }
    push(reinterpret_cast<const uint8_t*>(tx.anchor.data()), 32);
    {
        uint8_t tmp[8]; write_be_u64(tmp, tx.expiry_block); push(tmp, 8);
    }
    {
        uint8_t tmp[8]; write_be_u64(tmp, tx.fee); push(tmp, 8);
    }
    buf.push_back(rec.n_spends);
    buf.push_back(rec.n_outputs);
    for (const auto& s : tx.spends) {
        push(reinterpret_cast<const uint8_t*>(s.nullifier.data()), 32);
        push(reinterpret_cast<const uint8_t*>(s.rk.data()),        32);
    }
    for (uint8_t j = 0; j < rec.n_outputs; ++j) {
        const auto& o  = tx.outputs[j];
        const auto& oi = rec.output_inputs[j];
        push(reinterpret_cast<const uint8_t*>(o.cm.data()),  32);
        push(reinterpret_cast<const uint8_t*>(o.epk.data()), 32);
        {
            uint8_t tmp[2]; write_be_u16(tmp, o.filter_tag); push(tmp, 2);
        }
        push(oi.enc_ct_hash.data(),   32);
        push(oi.mlkem_ct_hash.data(), 32);
        push(o.out_ciphertext.data(), 80);
    }
    return buf;
}

static std::array<uint8_t, 32> blake3_32(const std::vector<uint8_t>& in) {
    std::array<uint8_t, 32> out{};
    ::uno_workchain::crypto::internal::blake3_hash(
        td::Slice(reinterpret_cast<const char*>(in.data()), in.size()),
        out.data());
    return out;
}

// ----- ivk_commitment / nf recomputation (pure Poseidon2) -------------------
//
// Input packing rules mirror the Rust generator (and, for ivk_commitment,
// `tosctl/uno/src/keygen.rs::ivk_commitment`):
//   ivk_commitment: fes = bytes_to_fes_wrapped(ivk, 4) || bytes_to_fes_wrapped(d_padded_to_16, 2)
//                   hash_tagged("uno-ivk-cm-v1", fes)   (6 fes)
//   nf:             fes = bytes_to_fes_wrapped(nk, 4) || bytes_to_fes_wrapped(cm, 4) || pos_fe
//                   hash_tagged("uno-nf-v1", fes)       (9 fes — iterated branch)
//
// `bytes_to_fes_wrapped` performs a wrapped-load: `v >= p ? v - p : v`.
// `fp_from_u64` is the C++-side equivalent; both rely on the same
// `kGoldilocksPrime` constant.

static std::array<uint8_t, 32> recompute_ivk_commitment(
    const std::array<uint8_t, 32>& ivk,
    const std::array<uint8_t, 11>& d) {
    using uno_workchain::crypto::Fp;
    using uno_workchain::crypto::fp_from_u64;
    using uno_workchain::crypto::Digest;
    using uno_workchain::crypto::poseidon2_hash_tagged;

    std::array<Fp, 6> fes{};
    for (int limb = 0; limb < 4; ++limb) {
        uint64_t v = 0;
        for (int k = 0; k < 8; ++k) v |= uint64_t(ivk[limb * 8 + k]) << (8 * k);
        fes[limb] = fp_from_u64(v);
    }
    std::array<uint8_t, 16> padded{};
    std::memcpy(padded.data(), d.data(), 11);
    for (int limb = 0; limb < 2; ++limb) {
        uint64_t v = 0;
        for (int k = 0; k < 8; ++k) v |= uint64_t(padded[limb * 8 + k]) << (8 * k);
        fes[4 + limb] = fp_from_u64(v);
    }
    Digest h = poseidon2_hash_tagged(
        td::Slice("uno-ivk-cm-v1"), fes.data(), fes.size());
    std::array<uint8_t, 32> out{};
    h.to_bytes({reinterpret_cast<char*>(out.data()), out.size()});
    return out;
}

static std::array<uint8_t, 32> recompute_nullifier(
    const std::array<uint8_t, 32>& nk,
    const std::array<uint8_t, 32>& cm,
    uint64_t pos) {
    using uno_workchain::crypto::Fp;
    using uno_workchain::crypto::fp_from_u64;
    using uno_workchain::crypto::Digest;
    using uno_workchain::crypto::poseidon2_hash_tagged;

    std::array<Fp, 9> fes{};
    for (int limb = 0; limb < 4; ++limb) {
        uint64_t v = 0;
        for (int k = 0; k < 8; ++k) v |= uint64_t(nk[limb * 8 + k]) << (8 * k);
        fes[limb] = fp_from_u64(v);
    }
    for (int limb = 0; limb < 4; ++limb) {
        uint64_t v = 0;
        for (int k = 0; k < 8; ++k) v |= uint64_t(cm[limb * 8 + k]) << (8 * k);
        fes[4 + limb] = fp_from_u64(v);
    }
    fes[8] = fp_from_u64(pos);
    Digest h = poseidon2_hash_tagged(
        td::Slice("uno-nf-v1"), fes.data(), fes.size());
    std::array<uint8_t, 32> out{};
    h.to_bytes({reinterpret_cast<char*>(out.data()), out.size()});
    return out;
}

// ----- Fixture file parser --------------------------------------------------

struct RawRecord {
    int line_no{0};
    int n_spends{0};
    int n_outputs{0};
    std::string transfer_hex;
    std::string pubinput_hex;
    std::string tx_hash_hex;
    std::string cm_hex;
    std::string ivk_commitment_hex;
    std::string nf_hex;
};

static bool parse_fixture_file(const std::string& path,
                               std::vector<RawRecord>& out) {
    std::ifstream in(path);
    if (!in) return false;
    out.clear();
    RawRecord cur;
    bool any_field = false;
    int line_no = 0;
    std::string line;
    auto maybe_emit = [&]() {
        if (cur.transfer_hex.empty() && cur.pubinput_hex.empty() &&
            cur.tx_hash_hex.empty()   && cur.cm_hex.empty() &&
            cur.ivk_commitment_hex.empty() && cur.nf_hex.empty()) {
            return;
        }
        out.push_back(std::move(cur));
        cur = RawRecord{};
        any_field = false;
    };
    while (std::getline(in, line)) {
        ++line_no;
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ' ||
                                 line.back() == '\t' || line.back() == '\n')) {
            line.pop_back();
        }
        if (line.empty()) { maybe_emit(); continue; }
        if (line[0] == '#') continue;

        auto consume = [&](const char* prefix) -> std::string {
            size_t plen = std::strlen(prefix);
            if (line.size() < plen) return {};
            if (line.compare(0, plen, prefix) != 0) return {};
            size_t pos = plen;
            while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t')) ++pos;
            return line.substr(pos);
        };
        if (auto v = consume("shape:"); !v.empty()) {
            if (!any_field) cur.line_no = line_no;
            // Parse "n_s,n_o"
            size_t comma = v.find(',');
            if (comma == std::string::npos) {
                std::fprintf(stderr,
                    "FAILED: golden fixture: bad shape spec on line %d\n", line_no);
                return false;
            }
            cur.n_spends = std::stoi(v.substr(0, comma));
            cur.n_outputs = std::stoi(v.substr(comma + 1));
            any_field = true;
        } else if (auto v = consume("transfer_hex:"); !v.empty()) {
            if (!any_field) cur.line_no = line_no;
            cur.transfer_hex = v; any_field = true;
        } else if (auto v = consume("pubinput_hex:"); !v.empty()) {
            cur.pubinput_hex = v; any_field = true;
        } else if (auto v = consume("tx_hash_hex:"); !v.empty()) {
            cur.tx_hash_hex = v; any_field = true;
        } else if (auto v = consume("cm_hex:"); !v.empty()) {
            cur.cm_hex = v; any_field = true;
        } else if (auto v = consume("ivk_commitment_hex:"); !v.empty()) {
            cur.ivk_commitment_hex = v; any_field = true;
        } else if (auto v = consume("nf_hex:"); !v.empty()) {
            cur.nf_hex = v; any_field = true;
        } else {
            std::fprintf(stderr,
                "FAILED: golden fixture: unrecognized line %d: '%s'\n",
                line_no, line.c_str());
            return false;
        }
    }
    // Emit trailing record (no blank line at EOF).
    maybe_emit();
    return true;
}

// Discover the golden fixture by walking a few candidate roots. Same
// convention as test-public-input-fixture / test-state-transition-golden.
static std::string find_fixture_path() {
    const char* candidates[] = {
        "uno/test/golden/codec-parity-v1.hex",
        "../uno/test/golden/codec-parity-v1.hex",
        "../../uno/test/golden/codec-parity-v1.hex",
        "../../../uno/test/golden/codec-parity-v1.hex",
    };
    for (const char* c : candidates) {
        std::ifstream probe(c);
        if (probe) return c;
    }
    return candidates[0];  // let the open fail with a useful diagnostic
}

}  // anonymous namespace

int main(int argc, char** argv) {
    std::string path = find_fixture_path();
    if (argc > 1) path = argv[1];
    std::printf("test-codec-parity: using %s\n", path.c_str());

    std::vector<RawRecord> raw_records;
    if (!parse_fixture_file(path, raw_records)) {
        fail("parse_fixture_file failed");
        std::printf("FAILED: %d test errors, %d passes\n",
                    g_failures.load(), g_passes.load());
        return 1;
    }
    if (raw_records.empty()) {
        fail("fixture file contained zero records");
        std::printf("FAILED: 1 test errors\n");
        return 1;
    }

    // Each shape (1/1, 1/2, 2/3, 4/4) contributes this many atomic checks:
    //   pubinput (1) + tx_hash (1) + cm per-output (n_o) +
    //   ivk_commitment per-output (n_o) + nf per-spend (n_s)
    //   = 2 + n_s + 2·n_o
    size_t total_checks_expected = 0;
    for (const auto& rec : raw_records) {
        total_checks_expected += 2 + size_t(rec.n_spends) + 2 * size_t(rec.n_outputs);
    }

    size_t idx = 0;
    for (const auto& raw : raw_records) {
        ++idx;
        std::printf("  record %zu (line %d): shape=%d/%d\n",
                    idx, raw.line_no, raw.n_spends, raw.n_outputs);

        if (raw.transfer_hex.empty() || raw.pubinput_hex.empty() ||
            raw.tx_hash_hex.empty()  || raw.cm_hex.empty() ||
            raw.ivk_commitment_hex.empty() || raw.nf_hex.empty()) {
            fail("record missing one of the 6 hex fields");
            continue;
        }

        std::vector<uint8_t> transfer_bytes, pubinput_expected, tx_hash_expected,
                             cm_concat, ivk_cm_concat, nf_concat;
        if (!parse_hex(raw.transfer_hex, transfer_bytes)) { fail("transfer_hex not valid hex"); continue; }
        if (!parse_hex(raw.pubinput_hex, pubinput_expected)) { fail("pubinput_hex not valid hex"); continue; }
        if (!parse_hex(raw.tx_hash_hex, tx_hash_expected)) { fail("tx_hash_hex not valid hex"); continue; }
        if (!parse_hex(raw.cm_hex, cm_concat)) { fail("cm_hex not valid hex"); continue; }
        if (!parse_hex(raw.ivk_commitment_hex, ivk_cm_concat)) { fail("ivk_commitment_hex not valid hex"); continue; }
        if (!parse_hex(raw.nf_hex, nf_concat)) { fail("nf_hex not valid hex"); continue; }

        if (tx_hash_expected.size() != 32) { fail("tx_hash length != 32"); continue; }
        if (cm_concat.size() != size_t(raw.n_outputs) * 32) {
            fail("cm_hex length != 32·n_outputs"); continue;
        }
        if (ivk_cm_concat.size() != size_t(raw.n_outputs) * 32) {
            fail("ivk_commitment_hex length != 32·n_outputs"); continue;
        }
        if (nf_concat.size() != size_t(raw.n_spends) * 32) {
            fail("nf_hex length != 32·n_spends"); continue;
        }

        FixtureRecord rec;
        if (!decode_fixture_transfer(transfer_bytes, rec)) {
            fail("decode_fixture_transfer failed");
            continue;
        }
        if (rec.n_spends != raw.n_spends || rec.n_outputs != raw.n_outputs) {
            fail("decoded shape disagrees with record header");
            continue;
        }

        // ---- Public-input bytes (duplicates test-uno-public-input-fixture) ----
        {
            auto pi = uno_workchain::build_plonky3_public_inputs(rec.tx);
            auto got = pi.to_bytes();
            const size_t want_len =
                64 + 64 * rec.n_spends + 72 * rec.n_outputs;
            if (got.size() != want_len || got.size() != pubinput_expected.size() ||
                std::memcmp(got.data(), pubinput_expected.data(), got.size()) != 0) {
                std::ostringstream os;
                os << "record " << idx << ": pubinput byte mismatch\n"
                   << "  got:      " << to_hex(got.data(), got.size()) << "\n"
                   << "  expected: " << to_hex(pubinput_expected.data(), pubinput_expected.size());
                fail(os.str());
            } else {
                pass("pubinput_hex");
            }
        }

        // ---- tx_hash: BLAKE3 over the canonical preimage with pinned cell hashes ----
        {
            auto preimage = build_tx_hash_preimage(rec);
            auto got = blake3_32(preimage);
            if (std::memcmp(got.data(), tx_hash_expected.data(), 32) != 0) {
                std::ostringstream os;
                os << "record " << idx << ": tx_hash mismatch\n"
                   << "  got:      " << to_hex(got.data(), 32) << "\n"
                   << "  expected: " << to_hex(tx_hash_expected.data(), 32);
                fail(os.str());
            } else {
                pass("tx_hash_hex");
            }
        }

        // ---- cm[j]: independent recomputation via compute_note_commitment ----
        for (uint8_t j = 0; j < rec.n_outputs; ++j) {
            const auto& oi = rec.output_inputs[j];
            uno_workchain::NoteCommitmentInputs in;
            in.d              = oi.d;
            in.pk_d_bytes     = oi.pk_d;
            in.ivk_commitment = oi.ivk_commitment;
            in.value          = oi.value;
            in.rcm            = oi.rcm;
            auto got = uno_workchain::compute_note_commitment(in);
            const uint8_t* want = cm_concat.data() + j * 32;
            if (std::memcmp(got.data(), want, 32) != 0) {
                std::ostringstream os;
                os << "record " << idx << ": cm[" << int(j) << "] mismatch\n"
                   << "  got:      " << to_hex(got.data(), 32) << "\n"
                   << "  expected: " << to_hex(want, 32);
                fail(os.str());
            } else {
                std::ostringstream os; os << "cm[" << int(j) << "]";
                pass(os.str());
            }
            // Also sanity: the Transfer struct's wire `cm` (decoded from
            // transfer_hex) must equal the recomputation — i.e., the
            // generator's on-wire value IS the note commitment.
            if (std::memcmp(rec.tx.outputs[j].cm.data(), got.data(), 32) != 0) {
                std::ostringstream os;
                os << "record " << idx << ": wire cm[" << int(j)
                   << "] != compute_note_commitment";
                fail(os.str());
            }
        }

        // ---- ivk_commitment[j]: Poseidon2("uno-ivk-cm-v1", ivk, d) ----
        for (uint8_t j = 0; j < rec.n_outputs; ++j) {
            const auto& oi = rec.output_inputs[j];
            auto got = recompute_ivk_commitment(oi.ivk, oi.d);
            const uint8_t* want = ivk_cm_concat.data() + j * 32;
            if (std::memcmp(got.data(), want, 32) != 0) {
                std::ostringstream os;
                os << "record " << idx << ": ivk_commitment[" << int(j)
                   << "] mismatch\n  got:      " << to_hex(got.data(), 32)
                   << "\n  expected: " << to_hex(want, 32);
                fail(os.str());
            } else {
                std::ostringstream os; os << "ivk_commitment[" << int(j) << "]";
                pass(os.str());
            }
            // Consistency: recompute matches the fixture's `ivk_commitment`
            // side-table bytes (which feed into cm). This closes the loop —
            // a divergence here would mean either the Poseidon2 sponge OR
            // the `uno-ivk-cm-v1` tag bytes drifted.
            if (std::memcmp(got.data(), oi.ivk_commitment.data(), 32) != 0) {
                std::ostringstream os;
                os << "record " << idx << ": ivk_commitment[" << int(j)
                   << "] != side-table ivk_commitment";
                fail(os.str());
            }
        }

        // ---- nf[i]: Poseidon2("uno-nf-v1", nk, cm_input_for_nf, pos) ----
        for (uint8_t i = 0; i < rec.n_spends; ++i) {
            const auto& si = rec.spend_inputs[i];
            auto got = recompute_nullifier(si.nk, si.cm_input_for_nf, si.pos);
            const uint8_t* want = nf_concat.data() + i * 32;
            if (std::memcmp(got.data(), want, 32) != 0) {
                std::ostringstream os;
                os << "record " << idx << ": nf[" << int(i)
                   << "] mismatch\n  got:      " << to_hex(got.data(), 32)
                   << "\n  expected: " << to_hex(want, 32);
                fail(os.str());
            } else {
                std::ostringstream os; os << "nf[" << int(i) << "]";
                pass(os.str());
            }
            // Wire-level cross-check: Transfer::spends[i].nullifier must
            // equal the independent recomputation — i.e., the generator's
            // on-wire `nullifier` IS `derive_nullifier(nk, cm_for_nf, pos)`.
            if (std::memcmp(rec.tx.spends[i].nullifier.data(), got.data(), 32) != 0) {
                std::ostringstream os;
                os << "record " << idx << ": wire nullifier[" << int(i)
                   << "] != recompute";
                fail(os.str());
            }
        }
    }

    int failures = g_failures.load();
    int passes   = g_passes.load();
    if (failures == 0) {
        std::printf("test-codec-parity: %d checks PASSED across %zu shape records"
                    " (expected %zu)\n",
                    passes, raw_records.size(), total_checks_expected);
        if (size_t(passes) != total_checks_expected) {
            std::printf("note: pass count %d != expected %zu (soft)\n",
                        passes, total_checks_expected);
        }
        return 0;
    }
    std::printf("FAILED: %d test errors, %d passes\n", failures, passes);
    return 1;
}
