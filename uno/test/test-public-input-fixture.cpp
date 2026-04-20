/*
    Uno Workchain — golden fixture cross-check for the Plonky3 public-input
    byte encoding (decision #5, §4.3 step 4 of doc/uno-workchain.md).

    This test reads `uno/test/golden/public-inputs-v1.hex`, decodes each
    `transfer_hex` into a `Transfer` struct (using the fixture-internal
    linear byte layout documented in the fixture header, NOT the §4.1 BoC
    wire format — the wire encoder currently only handles the 1/1 shape
    and the consensus property we are pinning is a pure function of the
    Transfer struct fields that the public-input builder reads), calls
    `build_plonky3_public_inputs(tx).to_bytes()`, and asserts byte-equality
    against the recorded `pubinput_hex`.

    A drift here is a consensus-breaking change to scheme_id = 0x01 and
    triggers a scheme_id bump. This file is the C++ half of the
    cross-implementation parity gate; the Rust half lives in
    `uno/plonky3-ffi/tests/public_input_fixture.rs`.

    Source: TOS-specific adapter; see doc/uno-workchain.md §4.3 / §16
    decision #5 / §12 P.1.
*/
#include "uno/core/transaction.h"

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

std::atomic<int> g_failures{0};

static void fail(const std::string& msg) {
    std::fprintf(stderr, "FAILED: %s\n", msg.c_str());
    g_failures.fetch_add(1);
}

// Hex helpers -------------------------------------------------------------

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

// Fixture-internal decoder ------------------------------------------------
//
// Layout (little-endian throughout):
//   u8  scheme_id
//   u32 chain_id
//   u64 expiry_block
//   u64 fee
//   u8  spend_count
//   u8  output_count
//   32 B anchor
//   for each spend:  32 B nullifier, 32 B rk
//   for each output: 32 B cm, 32 B epk, u16 filter_tag

static uint16_t read_le_u16(const uint8_t* p) {
    return static_cast<uint16_t>(
        static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8));
}

static uint32_t read_le_u32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

static uint64_t read_le_u64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[i]) << (8 * i);
    return v;
}

static bool decode_fixture_transfer(const std::vector<uint8_t>& bytes,
                                    uno_workchain::Transfer& out) {
    size_t off = 0;
    if (bytes.size() < 1 + 4 + 8 + 8 + 1 + 1 + 32) return false;

    out.version = uno_workchain::kTransferVersion;
    out.scheme_id = bytes[off++];
    out.chain_id = read_le_u32(&bytes[off]); off += 4;
    out.expiry_block = read_le_u64(&bytes[off]); off += 8;
    out.fee = read_le_u64(&bytes[off]); off += 8;
    uint8_t sc = bytes[off++];
    uint8_t oc = bytes[off++];

    std::memcpy(out.anchor.data(), &bytes[off], 32); off += 32;

    if (sc < uno_workchain::kMinSpendCount || sc > uno_workchain::kMaxSpendCount) return false;
    if (oc < uno_workchain::kMinOutputCount || oc > uno_workchain::kMaxOutputCount) return false;

    size_t need = off + sc * 64 + oc * (32 + 32 + 2);
    if (bytes.size() < need) return false;

    out.spends.resize(sc);
    for (uint8_t i = 0; i < sc; ++i) {
        std::memcpy(out.spends[i].nullifier.data(), &bytes[off], 32); off += 32;
        std::memcpy(out.spends[i].rk.data(),         &bytes[off], 32); off += 32;
        out.spends[i].spend_auth_sig.fill(0);  // not needed for PI builder
    }
    out.outputs.resize(oc);
    for (uint8_t j = 0; j < oc; ++j) {
        std::memcpy(out.outputs[j].cm.data(),   &bytes[off], 32); off += 32;
        std::memcpy(out.outputs[j].epk.data(),  &bytes[off], 32); off += 32;
        out.outputs[j].filter_tag = read_le_u16(&bytes[off]); off += 2;
        out.outputs[j].out_ciphertext.fill(0);  // not needed for PI builder
    }
    return off == bytes.size();
}

// Fixture parser ----------------------------------------------------------

struct FixtureRecord {
    std::string transfer_hex;
    std::string pubinput_hex;
    int line_no{0};   // starting line of this record (for error messages)
};

static bool parse_fixture_file(const std::string& path,
                               std::vector<FixtureRecord>& out) {
    std::ifstream in(path);
    if (!in) return false;
    out.clear();
    FixtureRecord cur;
    bool have_t = false, have_p = false;
    int line_no = 0;
    std::string line;
    while (std::getline(in, line)) {
        ++line_no;
        // Strip trailing whitespace.
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ' ||
                                 line.back() == '\t' || line.back() == '\n')) {
            line.pop_back();
        }
        if (line.empty() || line[0] == '#') continue;
        auto consume_prefix = [&](const char* prefix) -> std::string {
            size_t plen = std::strlen(prefix);
            if (line.size() < plen) return {};
            if (line.compare(0, plen, prefix) != 0) return {};
            size_t pos = plen;
            while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t')) ++pos;
            return line.substr(pos);
        };
        if (auto v = consume_prefix("transfer_hex:"); !v.empty()) {
            if (!have_t) cur.line_no = line_no;
            cur.transfer_hex = v;
            have_t = true;
        } else if (auto v = consume_prefix("pubinput_hex:"); !v.empty()) {
            cur.pubinput_hex = v;
            have_p = true;
        } else {
            // Unknown non-comment line — reject, forces fixture discipline.
            std::fprintf(stderr,
                "FAILED: golden fixture: unrecognized line %d: '%s'\n",
                line_no, line.c_str());
            return false;
        }
        if (have_t && have_p) {
            out.push_back(std::move(cur));
            cur = FixtureRecord{};
            have_t = false;
            have_p = false;
        }
    }
    if (have_t || have_p) {
        std::fprintf(stderr,
            "FAILED: golden fixture: trailing unpaired transfer_hex/pubinput_hex\n");
        return false;
    }
    return true;
}

}  // anonymous namespace

int main(int argc, char** argv) {
    // Default fixture path is relative to the uno/test/ directory. CI
    // invokes this with the explicit path; local dev falls through to the
    // in-tree canonical location.
    std::string path = "uno/test/golden/public-inputs-v1.hex";
    if (argc > 1) path = argv[1];

    std::printf("test-public-input-fixture: using %s\n", path.c_str());

    std::vector<FixtureRecord> records;
    if (!parse_fixture_file(path, records)) {
        fail("parse_fixture_file failed");
        std::printf("FAILED: 1 test errors\n");
        return 1;
    }
    if (records.empty()) {
        fail("fixture file contained zero records");
        std::printf("FAILED: 1 test errors\n");
        return 1;
    }

    size_t record_index = 0;
    for (const auto& rec : records) {
        ++record_index;
        std::printf("  record %zu (line %d): transfer=%zu hex, pubinput=%zu hex\n",
                    record_index, rec.line_no,
                    rec.transfer_hex.size(), rec.pubinput_hex.size());

        std::vector<uint8_t> tx_bytes, expected_bytes;
        if (!parse_hex(rec.transfer_hex, tx_bytes)) {
            fail("transfer_hex not valid hex");
            continue;
        }
        if (!parse_hex(rec.pubinput_hex, expected_bytes)) {
            fail("pubinput_hex not valid hex");
            continue;
        }

        uno_workchain::Transfer tx;
        if (!decode_fixture_transfer(tx_bytes, tx)) {
            fail("decode_fixture_transfer failed");
            continue;
        }

        auto pi = uno_workchain::build_plonky3_public_inputs(tx);
        auto got_bytes = pi.to_bytes();

        // Sanity: length matches the formula in §4.3 step 4 / decision #5.
        size_t expected_len = 64 + 64 * tx.spends.size() + 72 * tx.outputs.size();
        if (got_bytes.size() != expected_len) {
            std::ostringstream oss;
            oss << "record " << record_index << ": encoder produced "
                << got_bytes.size() << " bytes, expected " << expected_len
                << " per §4.3 step 4 formula";
            fail(oss.str());
            continue;
        }
        if (expected_bytes.size() != expected_len) {
            std::ostringstream oss;
            oss << "record " << record_index << ": fixture pubinput_hex is "
                << expected_bytes.size() << " bytes, expected " << expected_len;
            fail(oss.str());
            continue;
        }

        if (got_bytes.size() != expected_bytes.size() ||
            std::memcmp(got_bytes.data(), expected_bytes.data(), got_bytes.size()) != 0) {
            std::ostringstream oss;
            oss << "record " << record_index << ": byte mismatch.\n"
                << "  got:      " << to_hex(got_bytes.data(), got_bytes.size()) << "\n"
                << "  expected: " << to_hex(expected_bytes.data(), expected_bytes.size());
            fail(oss.str());
            continue;
        }

        std::printf("    ok: %zu bytes match\n", got_bytes.size());
    }

    int failures = g_failures.load();
    if (failures == 0) {
        std::printf("test-public-input-fixture: all %zu fixture records matched\n",
                    records.size());
        return 0;
    }
    std::printf("FAILED: %d test errors\n", failures);
    return 1;
}
