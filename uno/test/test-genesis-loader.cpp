/*
    Uno Workchain — genesis zerostate-notes JSON loader test (K-genesis-loader).

    Drives `load_genesis_distribution()` + `build_genesis_state()` end-to-end
    against a 3-note fixture plus a small battery of malformed inputs:

      * Happy path: 3 notes load, recompute `cm` via §3.2, append them to a
        fresh `CommitmentTree`, seed the `AnchorWindow` with the
        post-genesis root. Tree root must be deterministic (second run is
        byte-identical) and must equal the root we reproduce independently
        by driving `CommitmentTree::append()` directly with the same `cm`
        values. Anchor window must contain that root and have exactly one
        live entry after the build.

      * Reject paths:
          - Malformed address envelope (here: short `recipient.pk_d`). Since
            `uno-bech32-v1` is not yet in-tree, the loader's address surface
            is the hex block; a short field is the canonical "malformed
            envelope" reject the task enumerates.
          - Short `rseed` (31 bytes instead of 32).
          - Negative `value` (JSON number with leading `-`).

    Tests are structured as a sequence of `test_*()` functions. Each function
    prints `PASSED` / `FAILED` (/ `SKIP` where applicable); the main driver
    tallies via the tracked_printf harness and exits 0 iff no FAILED line
    was emitted.

    Poseidon2 FFI symbols are linked in via the real `uno_plonky3_ffi`
    library when Corrosion resolves it; otherwise the weak stubs in
    `uno/core/parallel-verify.cpp` fire. Both paths produce a DETERMINISTIC
    tree root (the test only requires determinism, not agreement with any
    external reference vector), which is all K-genesis-loader pins.
*/

#include <array>
#include <atomic>
#include <cassert>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "td/utils/Slice.h"
#include "td/utils/Status.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/path.h"

#include "uno/core/genesis.h"
#include "uno/core/state.h"
#include "uno/core/commitment-tree.h"
#include "uno/core/anchor-window.h"
#include "uno/core/workchain.h"
#include "uno/crypto/bech32m.h"

// ----- Tracked-printf harness -----------------------------------------------

static std::atomic<int> g_failures{0};
static std::atomic<int> g_passes{0};
static std::atomic<int> g_skips{0};

static int tracked_printf(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    va_list copy;
    va_copy(copy, args);
    int needed = std::vsnprintf(nullptr, 0, fmt, copy);
    va_end(copy);
    std::string rendered;
    if (needed >= 0) {
        rendered.resize((size_t)needed + 1);
        va_copy(copy, args);
        std::vsnprintf(rendered.data(), rendered.size(), fmt, copy);
        va_end(copy);
        rendered.resize((size_t)needed);
    }
    int written = std::vprintf(fmt, args);
    va_end(args);
    if (!rendered.empty()) {
        if (rendered.find("FAILED") != std::string::npos) g_failures.fetch_add(1);
        if (rendered.find("PASSED") != std::string::npos) g_passes.fetch_add(1);
        if (rendered.find("SKIP")   != std::string::npos) g_skips.fetch_add(1);
    }
    return written;
}
#define tprintf tracked_printf

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

// Build the hex string for a 2-digit lowercase byte, N times.
static std::string hex_repeat(uint8_t b, size_t n_bytes) {
    static const char* kHexDigits = "0123456789abcdef";
    std::string out;
    out.reserve(n_bytes * 2);
    for (size_t i = 0; i < n_bytes; ++i) {
        out.push_back(kHexDigits[(b >> 4) & 0xF]);
        out.push_back(kHexDigits[b & 0xF]);
    }
    return out;
}

// Emit one recipient-block JSON for the given "flavour" byte.
// Per-note diversity is injected via `d` which byte-varies per index.
static std::string mk_recipient_json(uint8_t d_byte, uint8_t pkd_byte,
                                     uint8_t ivkcm_byte, uint8_t mlkem_byte) {
    std::string out = "{";
    out += "\"d\":\"";              out += hex_repeat(d_byte, 11);      out += "\",";
    out += "\"pk_d\":\"";           out += hex_repeat(pkd_byte, 32);    out += "\",";
    out += "\"ivk_commitment\":\""; out += hex_repeat(ivkcm_byte, 32);  out += "\",";
    out += "\"pk_mlkem\":\"";       out += hex_repeat(mlkem_byte, 1184);out += "\"";
    out += "}";
    return out;
}

static std::string mk_note_json(uint8_t d_byte, uint64_t value, uint8_t rseed_byte) {
    std::string out = "{";
    out += "\"recipient\":";
    out += mk_recipient_json(d_byte, /*pkd=*/0x22, /*ivkcm=*/0x33, /*mlkem=*/0x44);
    out += ",\"value\":";
    out += std::to_string(value);
    out += ",\"rseed\":\"";
    out += hex_repeat(rseed_byte, 32);
    out += "\"}";
    return out;
}

static std::string mk_fixture_json() {
    // 3 notes; each has a distinct `d[0]` so each `cm` is unique.
    std::string out = "{";
    out += "\"scheme_id\":1,";
    out += "\"chain_id\":\"UNOT\",";
    out += "\"total_supply_nano\":\"3000000000\",";
    out += "\"notes\":[";
    out += mk_note_json(/*d=*/0x01, /*value=*/1'000'000'000ULL, /*rseed=*/0xA1);
    out += ",";
    out += mk_note_json(/*d=*/0x02, /*value=*/1'000'000'000ULL, /*rseed=*/0xA2);
    out += ",";
    out += mk_note_json(/*d=*/0x03, /*value=*/1'000'000'000ULL, /*rseed=*/0xA3);
    out += "]}";
    return out;
}

// Writes `body` to a one-off temp-file under /tmp and returns the path.
// The file is NOT unlinked — test binaries run once, fresh; keeping the
// artefact around makes debugging failures straightforward.
static td::Result<std::string> write_tmp(const std::string& body,
                                         const std::string& tag) {
    std::string path = "/tmp/uno-genesis-loader-" + tag + ".json";
    auto status = td::write_file(path, body);
    if (status.is_error()) return status.move_as_error();
    return path;
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

static void test_load_and_build_happy_path() {
    tprintf("[TEST] test_load_and_build_happy_path\n");

    auto path_r = write_tmp(mk_fixture_json(), "happy");
    if (path_r.is_error()) {
        tprintf("  FAILED: tmp write: %s\n", path_r.error().message().c_str());
        return;
    }
    auto path = path_r.move_as_ok();

    auto dist_r = uno_workchain::load_genesis_distribution(path);
    if (dist_r.is_error()) {
        tprintf("  FAILED: load_genesis_distribution: %s\n",
                dist_r.error().message().c_str());
        return;
    }
    auto dist = dist_r.move_as_ok();

    if (dist.notes.size() != 3) {
        tprintf("  FAILED: expected 3 notes, got %zu\n", dist.notes.size());
        return;
    }
    if (dist.chain_id != uno_workchain::kChainIdTestnet) {
        tprintf("  FAILED: chain_id mismatch: got 0x%08x, expected 0x%08x\n",
                dist.chain_id, uno_workchain::kChainIdTestnet);
        return;
    }
    if (dist.total_supply_nano != 3'000'000'000ULL) {
        tprintf("  FAILED: total_supply_nano mismatch: got %llu\n",
                (unsigned long long)dist.total_supply_nano);
        return;
    }
    // Loader must have populated `cm`.
    for (size_t i = 0; i < 3; ++i) {
        bool any_nonzero = false;
        for (uint8_t b : dist.notes[i].cm) {
            if (b != 0) { any_nonzero = true; break; }
        }
        if (!any_nonzero) {
            tprintf("  FAILED: notes[%zu].cm not populated\n", i);
            return;
        }
    }
    // Every cm must be distinct (d[0] differs per note → distinct
    // Poseidon2 pre-image).
    if (dist.notes[0].cm == dist.notes[1].cm ||
        dist.notes[0].cm == dist.notes[2].cm ||
        dist.notes[1].cm == dist.notes[2].cm) {
        tprintf("  FAILED: cm collision across distinct notes\n");
        return;
    }

    // Build the initial shard state from the loaded distribution.
    auto state = uno_workchain::build_zerostate_state(dist);
    if (state.is_empty()) {
        tprintf("  FAILED: build_zerostate_state returned empty\n");
        return;
    }
    if (!state.commitment_tree || !state.anchor_window) {
        tprintf("  FAILED: build_zerostate_state left sub-objects null\n");
        return;
    }

    // next_position must equal the number of appended notes.
    if (state.next_position != 3) {
        tprintf("  FAILED: next_position=%llu, expected 3\n",
                (unsigned long long)state.next_position);
        return;
    }
    // stats.note_count must match too.
    if (state.stats.note_count != 3) {
        tprintf("  FAILED: stats.note_count=%llu, expected 3\n",
                (unsigned long long)state.stats.note_count);
        return;
    }

    // Reproduce the expected root by driving CommitmentTree::append()
    // independently with the same cm sequence. This catches any drift
    // between `build_zerostate_state` and the canonical append order.
    uno_workchain::CommitmentTree ref;
    uno_workchain::NoteHash last_root{};
    for (const auto& note : dist.notes) {
        uno_workchain::NoteHash cm_hash{};
        std::copy(note.cm.begin(), note.cm.end(), cm_hash.begin());
        last_root = ref.append(cm_hash);
    }

    // `commitment_tree_root` on the built state must match.
    for (size_t i = 0; i < last_root.size(); ++i) {
        if (last_root[i] != state.commitment_tree_root[i]) {
            tprintf("  FAILED: commitment_tree_root mismatch at byte %zu\n", i);
            return;
        }
    }

    // Determinism: load + build a second time and compare byte-for-byte.
    auto dist2 = uno_workchain::load_genesis_distribution(path).move_as_ok();
    auto state2 = uno_workchain::build_zerostate_state(dist2);
    if (state.commitment_tree_root != state2.commitment_tree_root) {
        tprintf("  FAILED: second-run root differs from first (determinism)\n");
        return;
    }

    // Anchor window contains exactly the post-genesis root.
    if (state.anchor_window->size() != 1) {
        tprintf("  FAILED: anchor window size=%zu, expected 1\n",
                state.anchor_window->size());
        return;
    }
    if (!state.anchor_window->contains(last_root)) {
        tprintf("  FAILED: anchor window missing post-genesis root\n");
        return;
    }

    // Cross-check via the build_genesis_state convenience wrapper, which
    // takes a bare std::vector<GenesisNote>.
    auto state3 = uno_workchain::build_genesis_state(dist.notes);
    if (state3.is_empty() ||
        state3.commitment_tree_root != state.commitment_tree_root) {
        tprintf("  FAILED: build_genesis_state root disagrees with "
                "build_zerostate_state\n");
        return;
    }

    tprintf("  PASSED (3 notes loaded, tree deterministic, anchor seeded, "
            "build_genesis_state matches)\n");
}

// ---------------------------------------------------------------------------
// Reject: malformed Bech32m / address envelope
//
// Since `uno-bech32-v1` is not yet in-tree, the address surface this loader
// exposes is the hex `recipient` block. A malformed envelope in that
// surface is a short / truncated / non-hex field. Here: `pk_d` missing
// one byte.
// ---------------------------------------------------------------------------

static void test_reject_malformed_envelope() {
    tprintf("[TEST] test_reject_malformed_envelope\n");

    // 31 B pk_d (62 hex chars) instead of 32 B.
    std::string bad_recipient = "{";
    bad_recipient += "\"d\":\"";              bad_recipient += hex_repeat(0x01, 11); bad_recipient += "\",";
    bad_recipient += "\"pk_d\":\"";           bad_recipient += hex_repeat(0x22, 31); bad_recipient += "\",";
    bad_recipient += "\"ivk_commitment\":\""; bad_recipient += hex_repeat(0x33, 32); bad_recipient += "\",";
    bad_recipient += "\"pk_mlkem\":\"";       bad_recipient += hex_repeat(0x44, 1184); bad_recipient += "\"";
    bad_recipient += "}";

    std::string body = "{";
    body += "\"scheme_id\":1,\"chain_id\":\"UNOT\",\"notes\":[";
    body += "{\"recipient\":";
    body += bad_recipient;
    body += ",\"value\":1000,\"rseed\":\"";
    body += hex_repeat(0xA1, 32);
    body += "\"}]}";

    auto path = write_tmp(body, "bad-envelope").move_as_ok();
    auto r = uno_workchain::load_genesis_distribution(path);
    if (r.is_ok()) {
        tprintf("  FAILED: accepted short pk_d\n");
        return;
    }
    tprintf("  PASSED (rejected: %s)\n", r.error().message().c_str());
}

// ---------------------------------------------------------------------------
// Reject: short rseed
// ---------------------------------------------------------------------------

static void test_reject_short_rseed() {
    tprintf("[TEST] test_reject_short_rseed\n");

    // 30 B rseed instead of 32 B.
    std::string body = "{";
    body += "\"scheme_id\":1,\"chain_id\":\"UNOT\",\"notes\":[";
    body += "{\"recipient\":";
    body += mk_recipient_json(0x01, 0x22, 0x33, 0x44);
    body += ",\"value\":1000,\"rseed\":\"";
    body += hex_repeat(0xA1, 30);
    body += "\"}]}";

    auto path = write_tmp(body, "bad-rseed").move_as_ok();
    auto r = uno_workchain::load_genesis_distribution(path);
    if (r.is_ok()) {
        tprintf("  FAILED: accepted short rseed\n");
        return;
    }
    tprintf("  PASSED (rejected: %s)\n", r.error().message().c_str());
}

// ---------------------------------------------------------------------------
// Reject: negative value
// ---------------------------------------------------------------------------

static void test_reject_negative_value() {
    tprintf("[TEST] test_reject_negative_value\n");

    // JSON number "-1" in the `value` field.
    std::string body = "{";
    body += "\"scheme_id\":1,\"chain_id\":\"UNOT\",\"notes\":[";
    body += "{\"recipient\":";
    body += mk_recipient_json(0x01, 0x22, 0x33, 0x44);
    body += ",\"value\":-1,\"rseed\":\"";
    body += hex_repeat(0xA1, 32);
    body += "\"}]}";

    auto path = write_tmp(body, "neg-value").move_as_ok();
    auto r = uno_workchain::load_genesis_distribution(path);
    if (r.is_ok()) {
        tprintf("  FAILED: accepted negative value\n");
        return;
    }
    tprintf("  PASSED (rejected: %s)\n", r.error().message().c_str());
}

// ---------------------------------------------------------------------------
// Reject: total_supply_nano disagreement
// ---------------------------------------------------------------------------

static void test_reject_supply_mismatch() {
    tprintf("[TEST] test_reject_supply_mismatch\n");

    // Declared total = 999 but the single note pays 1000.
    std::string body = "{";
    body += "\"scheme_id\":1,\"chain_id\":\"UNOT\",";
    body += "\"total_supply_nano\":\"999\",";
    body += "\"notes\":[";
    body += "{\"recipient\":";
    body += mk_recipient_json(0x01, 0x22, 0x33, 0x44);
    body += ",\"value\":1000,\"rseed\":\"";
    body += hex_repeat(0xA1, 32);
    body += "\"}]}";

    auto path = write_tmp(body, "supply-mismatch").move_as_ok();
    auto r = uno_workchain::load_genesis_distribution(path);
    if (r.is_ok()) {
        tprintf("  FAILED: accepted supply mismatch\n");
        return;
    }
    tprintf("  PASSED (rejected: %s)\n", r.error().message().c_str());
}

// ---------------------------------------------------------------------------
// Envelope-form recipient: feed a note whose address is supplied as a
// Bech32m "address": "unot1..." string (§2.6). The loader MUST accept this
// alternative and produce the same GenesisAddress it would have built from
// the explicit hex block.
// ---------------------------------------------------------------------------

static void test_load_address_envelope_form() {
    tprintf("[TEST] test_load_address_envelope_form\n");

    // Build an envelope whose payload layout mirrors mk_recipient_json:
    //   d      = 0x01 × 11
    //   pk_d   = 0x22 × 32
    //   ivk_cm = 0x33 × 32
    //   pk_ml  = 0x44 × 1184
    ::uno_workchain::crypto::AddressEnvelope env{};
    env.version_tag = ::uno_workchain::crypto::kAddressEnvelopeVersionV1;
    env.network_tag = ::uno_workchain::crypto::kAddressNetworkTestnet;
    std::memset(env.payload.data() +   0, 0x01,   11);
    std::memset(env.payload.data() +  11, 0x22,   32);
    std::memset(env.payload.data() +  43, 0x33,   32);
    std::memset(env.payload.data() +  75, 0x44, 1184);
    std::string encoded = ::uno_workchain::crypto::encode_address_envelope(env);
    if (encoded.empty()) {
        tprintf("  FAILED: encode_address_envelope returned empty\n");
        return;
    }

    // Note object uses `"address"` instead of the `"recipient"` hex block.
    std::string body = "{";
    body += "\"scheme_id\":1,\"chain_id\":\"UNOT\",\"notes\":[{";
    body += "\"address\":\""; body += encoded; body += "\",";
    body += "\"value\":1000,\"rseed\":\"";
    body += hex_repeat(0xA1, 32);
    body += "\"}]}";

    auto path = write_tmp(body, "address-envelope").move_as_ok();
    auto dist_r = uno_workchain::load_genesis_distribution(path);
    if (dist_r.is_error()) {
        tprintf("  FAILED: envelope-form load: %s\n",
                dist_r.error().message().c_str());
        return;
    }
    auto dist = dist_r.move_as_ok();
    if (dist.notes.size() != 1) {
        tprintf("  FAILED: expected 1 note, got %zu\n", dist.notes.size());
        return;
    }
    const auto& addr = dist.notes[0].recipient;
    for (size_t i = 0; i <   11; ++i) if (addr.diversifier[i]     != 0x01) { tprintf("  FAILED: d[%zu] != 0x01\n", i); return; }
    for (size_t i = 0; i <   32; ++i) if (addr.pk_d_compressed[i] != 0x22) { tprintf("  FAILED: pk_d[%zu] != 0x22\n", i); return; }
    for (size_t i = 0; i <   32; ++i) if (addr.ivk_commitment[i]  != 0x33) { tprintf("  FAILED: ivk_cm[%zu] != 0x33\n", i); return; }
    if (addr.pk_mlkem.size() != 1184)                                       { tprintf("  FAILED: pk_mlkem size=%zu\n", addr.pk_mlkem.size()); return; }
    for (size_t i = 0; i < 1184; ++i) if (addr.pk_mlkem[i]        != 0x44) { tprintf("  FAILED: pk_mlkem[%zu] != 0x44\n", i); return; }

    // Also: swap in a corrupted envelope (flip last char) and confirm
    // the loader rejects at parse time.
    std::string corrupted = encoded;
    corrupted.back() = (corrupted.back() == 'q' ? 'p' : 'q');
    std::string bad_body = "{";
    bad_body += "\"scheme_id\":1,\"chain_id\":\"UNOT\",\"notes\":[{";
    bad_body += "\"address\":\""; bad_body += corrupted; bad_body += "\",";
    bad_body += "\"value\":1000,\"rseed\":\"";
    bad_body += hex_repeat(0xA1, 32);
    bad_body += "\"}]}";
    auto bad_path = write_tmp(bad_body, "address-envelope-bad").move_as_ok();
    auto bad_r = uno_workchain::load_genesis_distribution(bad_path);
    if (bad_r.is_ok()) {
        tprintf("  FAILED: accepted corrupted Bech32m envelope\n");
        return;
    }

    tprintf("  PASSED (envelope unpacked to the expected payload; "
            "flipped-checksum envelope rejected: %s)\n",
            bad_r.error().message().c_str());
}

// ---------------------------------------------------------------------------
// K-genesis-distribution: §10.3 60/25/15 builder round-trip.
//
// Feeds a 6-entry distribution summing exactly to 200 M UNO through
// `build_genesis_notes_json`, parses the resulting JSON via
// `load_genesis_distribution`, and asserts:
//   - the loader accepts the builder's output byte-for-byte (schema parity)
//   - the canonical sort: each per-category block is sorted by
//     canonical_address_hash ascending, and the three blocks are
//     concatenated airdrop || treasury || team
//   - rseed[i] == BLAKE2b-256("uno-genesis-rseed-v1" || u32_be(i))
//   - `build_zerostate_state` produces a populated tree with note_count = 6
// ---------------------------------------------------------------------------

static uno_workchain::GenesisAddress mk_genesis_address_bytes(uint8_t seed_byte) {
    uno_workchain::GenesisAddress out;
    for (size_t i = 0; i < out.diversifier.size(); ++i)
        out.diversifier[i]     = seed_byte ^ static_cast<uint8_t>(0x10 + i);
    for (size_t i = 0; i < out.pk_d_compressed.size(); ++i)
        out.pk_d_compressed[i] = seed_byte ^ static_cast<uint8_t>(0x40 + i);
    for (size_t i = 0; i < out.ivk_commitment.size(); ++i)
        out.ivk_commitment[i]  = seed_byte ^ static_cast<uint8_t>(0x80 + i);
    out.pk_mlkem.assign(1184, seed_byte);
    return out;
}

static void test_build_and_roundtrip_60_25_15() {
    tprintf("[TEST] test_build_and_roundtrip_60_25_15\n");

    using uno_workchain::DistributionRecipient;
    using uno_workchain::GenesisDistributionInputs;
    using uno_workchain::kGenesisAirdropNano;
    using uno_workchain::kGenesisTreasuryNano;
    using uno_workchain::kGenesisTeamNano;
    using uno_workchain::kGenesisTotalSupplyNano;

    GenesisDistributionInputs inp;
    inp.chain_id = uno_workchain::kChainIdTestnet;

    // Airdrop: 3 entries summing to 12.6 M × 10^9
    inp.airdrop = {
        DistributionRecipient{mk_genesis_address_bytes(0x11), kGenesisAirdropNano / 2},
        DistributionRecipient{mk_genesis_address_bytes(0x22), kGenesisAirdropNano / 4},
        DistributionRecipient{mk_genesis_address_bytes(0x33), kGenesisAirdropNano / 4},
    };
    // Treasury: 2 entries summing to 5.25 M × 10^9
    inp.treasury = {
        DistributionRecipient{mk_genesis_address_bytes(0x44), kGenesisTreasuryNano / 2},
        DistributionRecipient{mk_genesis_address_bytes(0x55), kGenesisTreasuryNano / 2},
    };
    // Team: 1 entry = 3.15 M × 10^9
    inp.team = {
        DistributionRecipient{mk_genesis_address_bytes(0x66), kGenesisTeamNano},
    };

    auto json_r = uno_workchain::build_genesis_notes_json(inp);
    if (json_r.is_error()) {
        tprintf("  FAILED: build_genesis_notes_json: %s\n",
                json_r.error().message().c_str());
        return;
    }
    auto json = json_r.move_as_ok();

    auto path = write_tmp(json, "builder-roundtrip").move_as_ok();
    auto dist_r = uno_workchain::load_genesis_distribution(path);
    if (dist_r.is_error()) {
        tprintf("  FAILED: loader rejects builder output: %s\n",
                dist_r.error().message().c_str());
        return;
    }
    auto dist = dist_r.move_as_ok();

    if (dist.notes.size() != 6) {
        tprintf("  FAILED: expected 6 notes, got %zu\n", dist.notes.size());
        return;
    }
    if (dist.total_supply_nano != kGenesisTotalSupplyNano) {
        tprintf("  FAILED: total_supply_nano=%llu, expected %llu\n",
                (unsigned long long)dist.total_supply_nano,
                (unsigned long long)kGenesisTotalSupplyNano);
        return;
    }

    // Per-section sort check: within airdrop [0..3] and treasury [3..5],
    // canonical_address_hash is monotonically increasing.
    auto check_sorted = [&](size_t lo, size_t hi, const char* name) -> bool {
        for (size_t i = lo + 1; i < hi; ++i) {
            auto a = uno_workchain::canonical_address_hash(dist.notes[i - 1].recipient);
            auto b = uno_workchain::canonical_address_hash(dist.notes[i].recipient);
            if (!(a < b)) {
                tprintf("  FAILED: %s section not sorted at index %zu\n", name, i);
                return false;
            }
        }
        return true;
    };
    if (!check_sorted(0, 3, "airdrop")) return;
    if (!check_sorted(3, 5, "treasury")) return;

    // rseed[i] == derive_genesis_rseed(i)
    for (size_t i = 0; i < dist.notes.size(); ++i) {
        auto expected = uno_workchain::derive_genesis_rseed(static_cast<uint32_t>(i));
        if (dist.notes[i].rseed != expected) {
            tprintf("  FAILED: rseed mismatch at index %zu\n", i);
            return;
        }
    }

    // Category-sum check: airdrop-slice [0..3] sums to kGenesisAirdropNano.
    uint64_t ai = 0, tr = 0, tm = 0;
    for (size_t i = 0; i < 3; ++i) ai += dist.notes[i].value;
    for (size_t i = 3; i < 5; ++i) tr += dist.notes[i].value;
    for (size_t i = 5; i < 6; ++i) tm += dist.notes[i].value;
    if (ai != kGenesisAirdropNano || tr != kGenesisTreasuryNano || tm != kGenesisTeamNano) {
        tprintf("  FAILED: per-category sum mismatch: "
                "ai=%llu tr=%llu tm=%llu\n",
                (unsigned long long)ai, (unsigned long long)tr,
                (unsigned long long)tm);
        return;
    }

    // Feed through the commitment-tree builder and require a populated state.
    auto state = uno_workchain::build_zerostate_state(dist);
    if (state.is_empty() || !state.commitment_tree || !state.anchor_window) {
        tprintf("  FAILED: build_zerostate_state returned empty / nulls\n");
        return;
    }
    if (state.stats.note_count != 6 || state.next_position != 6) {
        tprintf("  FAILED: state counters off: note_count=%llu, next_position=%llu\n",
                (unsigned long long)state.stats.note_count,
                (unsigned long long)state.next_position);
        return;
    }
    if (state.anchor_window->size() != 1) {
        tprintf("  FAILED: anchor window size %zu != 1\n",
                state.anchor_window->size());
        return;
    }

    tprintf("  PASSED (6-entry 60/25/15 split validates, sorts, rseed matches, "
            "loader round-trips, state counters correct)\n");
}

static void test_build_rejects_sum_mismatch() {
    tprintf("[TEST] test_build_rejects_sum_mismatch\n");

    using uno_workchain::DistributionRecipient;
    using uno_workchain::GenesisDistributionInputs;
    using uno_workchain::kGenesisAirdropNano;
    using uno_workchain::kGenesisTreasuryNano;
    using uno_workchain::kGenesisTeamNano;

    GenesisDistributionInputs inp;
    // Airdrop short by 1 nano.
    inp.airdrop = {
        DistributionRecipient{mk_genesis_address_bytes(0x11), kGenesisAirdropNano - 1},
    };
    inp.treasury = {
        DistributionRecipient{mk_genesis_address_bytes(0x22), kGenesisTreasuryNano},
    };
    inp.team = {
        DistributionRecipient{mk_genesis_address_bytes(0x33), kGenesisTeamNano},
    };

    auto r = uno_workchain::build_genesis_notes_json(inp);
    if (r.is_ok()) {
        tprintf("  FAILED: accepted sum mismatch\n");
        return;
    }
    tprintf("  PASSED (rejected: %s)\n", r.error().message().c_str());
}

static void test_build_rejects_duplicate_address() {
    tprintf("[TEST] test_build_rejects_duplicate_address\n");

    using uno_workchain::DistributionRecipient;
    using uno_workchain::GenesisDistributionInputs;
    using uno_workchain::kGenesisAirdropNano;
    using uno_workchain::kGenesisTreasuryNano;
    using uno_workchain::kGenesisTeamNano;

    auto dup_addr = mk_genesis_address_bytes(0x77);
    GenesisDistributionInputs inp;
    inp.airdrop = {
        DistributionRecipient{dup_addr, kGenesisAirdropNano / 2},
        DistributionRecipient{dup_addr, kGenesisAirdropNano / 2},
    };
    inp.treasury = {
        DistributionRecipient{mk_genesis_address_bytes(0x22), kGenesisTreasuryNano},
    };
    inp.team = {
        DistributionRecipient{mk_genesis_address_bytes(0x33), kGenesisTeamNano},
    };

    auto r = uno_workchain::build_genesis_notes_json(inp);
    if (r.is_ok()) {
        tprintf("  FAILED: accepted duplicate address\n");
        return;
    }
    tprintf("  PASSED (rejected: %s)\n", r.error().message().c_str());
}

static void test_build_rejects_empty_airdrop() {
    tprintf("[TEST] test_build_rejects_empty_airdrop\n");

    using uno_workchain::DistributionRecipient;
    using uno_workchain::GenesisDistributionInputs;
    using uno_workchain::kGenesisTreasuryNano;
    using uno_workchain::kGenesisTeamNano;

    GenesisDistributionInputs inp;  // empty airdrop
    inp.treasury = {
        DistributionRecipient{mk_genesis_address_bytes(0x22), kGenesisTreasuryNano},
    };
    inp.team = {
        DistributionRecipient{mk_genesis_address_bytes(0x33), kGenesisTeamNano},
    };

    auto r = uno_workchain::build_genesis_notes_json(inp);
    if (r.is_ok()) {
        tprintf("  FAILED: accepted empty airdrop\n");
        return;
    }
    tprintf("  PASSED (rejected: %s)\n", r.error().message().c_str());
}

// K-genesis-distribution: load the golden fixture produced by the Rust
// builder (`tosctl/uno/tests/genesis_build_golden.rs`). Asserts both
// implementations accept the same byte payload — any schema drift between
// the two builders will surface here as a loader reject, and any loader
// drift will surface in the Rust integration test.
static void test_load_rust_golden_fixture() {
    tprintf("[TEST] test_load_rust_golden_fixture\n");

    // Search a couple of plausible cwd positions so the test works under
    // both `ctest` (cwd = CMAKE_SOURCE_DIR) and direct invocation.
    const char* candidates[] = {
        "uno/test/golden/genesis-distribution-v1.json",
        "../uno/test/golden/genesis-distribution-v1.json",
        "../../uno/test/golden/genesis-distribution-v1.json",
        "../../../uno/test/golden/genesis-distribution-v1.json",
    };
    std::string found;
    for (const char* c : candidates) {
        auto r = td::read_file(td::CSlice(c));
        if (r.is_ok()) { found = c; break; }
    }
    if (found.empty()) {
        tprintf("  SKIP: golden fixture not found in any candidate path "
                "(regenerate via `UNO_GENESIS_REGEN=1 cargo test --release "
                "--test genesis_build_golden`)\n");
        return;
    }

    auto dist_r = uno_workchain::load_genesis_distribution(found);
    if (dist_r.is_error()) {
        tprintf("  FAILED: loader rejects Rust golden: %s\n",
                dist_r.error().message().c_str());
        return;
    }
    auto dist = dist_r.move_as_ok();
    if (dist.notes.size() != 6) {
        tprintf("  FAILED: expected 6 notes, got %zu\n", dist.notes.size());
        return;
    }
    if (dist.total_supply_nano != uno_workchain::kGenesisTotalSupplyNano) {
        tprintf("  FAILED: total_supply_nano=%llu\n",
                (unsigned long long)dist.total_supply_nano);
        return;
    }
    // rseed[i] must match the canonical derivation.
    for (size_t i = 0; i < dist.notes.size(); ++i) {
        auto want = uno_workchain::derive_genesis_rseed(static_cast<uint32_t>(i));
        if (dist.notes[i].rseed != want) {
            tprintf("  FAILED: rseed mismatch at index %zu\n", i);
            return;
        }
    }
    tprintf("  PASSED (loader accepts Rust-produced golden; rseed parity verified)\n");
}

static void test_build_rejects_zero_value() {
    tprintf("[TEST] test_build_rejects_zero_value\n");

    using uno_workchain::DistributionRecipient;
    using uno_workchain::GenesisDistributionInputs;
    using uno_workchain::kGenesisAirdropNano;
    using uno_workchain::kGenesisTreasuryNano;
    using uno_workchain::kGenesisTeamNano;

    GenesisDistributionInputs inp;
    inp.airdrop = {
        DistributionRecipient{mk_genesis_address_bytes(0x11), 0},
        DistributionRecipient{mk_genesis_address_bytes(0x12), kGenesisAirdropNano},
    };
    inp.treasury = {
        DistributionRecipient{mk_genesis_address_bytes(0x22), kGenesisTreasuryNano},
    };
    inp.team = {
        DistributionRecipient{mk_genesis_address_bytes(0x33), kGenesisTeamNano},
    };

    auto r = uno_workchain::build_genesis_notes_json(inp);
    if (r.is_ok()) {
        tprintf("  FAILED: accepted zero-value entry\n");
        return;
    }
    tprintf("  PASSED (rejected: %s)\n", r.error().message().c_str());
}

// ---------------------------------------------------------------------------
// K-genesis-distribution: cross-impl Poseidon2 parity gate.
//
// Forward-declares the bits of uno_workchain / uno_workchain::crypto we need
// to re-implement `compute_rcm` locally — the production `compute_rcm` lives
// in an anonymous namespace inside genesis.cpp, and pulling in poseidon2.h
// here trips the noexcept disagreement documented at the top of genesis.cpp.
namespace uno_workchain {
struct NoteCommitmentInputs {
    std::array<uint8_t, 11>  d{};
    std::array<uint8_t, 32>  pk_d_bytes{};
    std::array<uint8_t, 32>  ivk_commitment{};
    uint64_t                 value{0};
    std::array<uint8_t, 32>  rcm{};
};
std::array<uint8_t, 32> compute_note_commitment(const NoteCommitmentInputs& in) noexcept;
}
#include "uno/crypto/goldilocks.h"
namespace uno_workchain::crypto {
Digest poseidon2_hash_tagged(td::Slice tag, const Fp* inputs, size_t n_inputs);
}

// C++ compute_rcm reimplementation (the production `compute_rcm` is in an
// anonymous namespace inside genesis.cpp, so we re-expose it here via the
// same Poseidon2 helper the loader uses).
static std::array<uint8_t, 32> compute_rcm_reference(
        const std::array<uint8_t, 32>& rseed) {
    using ::uno_workchain::crypto::Fp;
    using ::uno_workchain::crypto::Digest;
    using ::uno_workchain::crypto::fp_from_u64;
    using ::uno_workchain::crypto::poseidon2_hash_tagged;
    Fp inputs[4];
    for (int limb = 0; limb < 4; ++limb) {
        uint64_t w = 0;
        for (int j = 0; j < 8; ++j) {
            w |= static_cast<uint64_t>(rseed[limb * 8 + j]) << (8 * j);
        }
        inputs[limb] = fp_from_u64(w);
    }
    static constexpr char kRcmTag[] = "uno-rcm-v1";
    Digest d = poseidon2_hash_tagged(
        td::Slice(kRcmTag, sizeof(kRcmTag) - 1), inputs, 4);
    std::array<uint8_t, 32> out{};
    d.to_bytes({reinterpret_cast<char*>(out.data()), out.size()});
    return out;
}

// K-genesis-distribution: cross-impl parity of rcm/cm between the C++
// loader path and the Rust wallet. Pins the tag-length fix applied under
// this commit — the §3.1 tag "uno-rcm-v1" is 10 bytes, not 9; a prior
// revision silently truncated to 9 and diverged from the Rust wallet.
static void test_cm_parity_with_rust_reference() {
    tprintf("[TEST] test_cm_parity_with_rust_reference\n");

    static const uint8_t rseed_bytes[32] = {
        0x63,0xfb,0xbb,0x4d,0xb2,0xd6,0xba,0x85,0xb8,0x8e,0x94,0xfe,0x0c,0xbb,0xd3,0x92,
        0xde,0xdb,0x4d,0x04,0xe6,0x30,0xe4,0x9f,0x24,0xc2,0x36,0x56,0xcc,0xc9,0x4a,0x90,
    };
    // Rust-computed rcm for the above rseed (pinned from
    // `tosctl/uno/tests/genesis_build_golden.rs`).
    static const uint8_t rust_rcm_expected[32] = {
        0x30,0x54,0x66,0x29,0xd5,0x37,0xa1,0x89,0x32,0x80,0xae,0x98,0xc7,0x14,0x19,0x35,
        0x8e,0x76,0x26,0xcc,0x83,0xb7,0x5d,0xa5,0xbe,0xa5,0x02,0x14,0x42,0x33,0x34,0x65,
    };
    // Rust-computed cm for (d=0x02×11, pk_d=38c30afe..., ivk_cm=3f3260d4...,
    // value=3_150_000_000_000_000, rcm=rust_rcm_expected).
    static const uint8_t rust_cm_expected[32] = {
        0xf8,0xc1,0x8b,0x14,0x1c,0x8e,0x63,0x92,0x34,0x40,0x20,0xb6,0x8c,0x9f,0xce,0xd4,
        0x2e,0xf2,0xd9,0x4e,0x40,0xf2,0x30,0x00,0xbd,0x4d,0x27,0x08,0x4a,0xe1,0xe1,0x6d,
    };

    std::array<uint8_t, 32> rseed{};
    std::memcpy(rseed.data(), rseed_bytes, 32);
    auto cpp_rcm = compute_rcm_reference(rseed);
    for (size_t i = 0; i < 32; ++i) {
        if (cpp_rcm[i] != rust_rcm_expected[i]) {
            tprintf("  FAILED: C++ rcm disagrees with Rust at byte %zu "
                    "(tag-length bug resurfaced?)\n", i);
            return;
        }
    }

    uno_workchain::NoteCommitmentInputs nci{};
    for (int i = 0; i < 11; ++i) nci.d[i] = 0x02;
    static const uint8_t pkd[32] = {
        0x38,0xc3,0x0a,0xfe,0x72,0x35,0xd7,0x68,0x73,0x43,0xae,0x1e,0xe2,0xba,0xc3,0x76,
        0xeb,0xce,0x04,0xda,0xc6,0x61,0xc3,0x8f,0xeb,0xb8,0x57,0xee,0xe7,0xfe,0x61,0x7c,
    };
    std::memcpy(nci.pk_d_bytes.data(), pkd, 32);
    static const uint8_t ivk[32] = {
        0x3f,0x32,0x60,0xd4,0x80,0xbd,0x0f,0x40,0xc1,0x6f,0xc3,0x7c,0x10,0x6f,0x90,0x53,
        0x40,0xb7,0x47,0x98,0xcf,0x37,0x85,0xc3,0x6b,0x90,0x52,0x1b,0xec,0x84,0xde,0x51,
    };
    std::memcpy(nci.ivk_commitment.data(), ivk, 32);
    nci.value = 3'150'000'000'000'000ULL;
    std::memcpy(nci.rcm.data(), cpp_rcm.data(), 32);
    auto cpp_cm = uno_workchain::compute_note_commitment(nci);
    for (size_t i = 0; i < 32; ++i) {
        if (cpp_cm[i] != rust_cm_expected[i]) {
            tprintf("  FAILED: C++ cm disagrees with Rust at byte %zu\n", i);
            return;
        }
    }
    tprintf("  PASSED (rcm + cm byte-identical across Rust / C++)\n");
}

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    tprintf("Uno Workchain — K-genesis-loader test\n");
    tprintf("======================================\n\n");

    test_cm_parity_with_rust_reference();
    test_load_and_build_happy_path();
    test_reject_malformed_envelope();
    test_reject_short_rseed();
    test_reject_negative_value();
    test_reject_supply_mismatch();
    test_load_address_envelope_form();

    // K-genesis-distribution: §10.3 60/25/15 builder round-trips.
    test_build_and_roundtrip_60_25_15();
    test_build_rejects_sum_mismatch();
    test_build_rejects_duplicate_address();
    test_build_rejects_empty_airdrop();
    test_build_rejects_zero_value();
    test_load_rust_golden_fixture();

    tprintf("\nTotal: passed=%d, failures=%d, skips=%d\n",
            g_passes.load(), g_failures.load(), g_skips.load());
    return g_failures.load() == 0 ? 0 : 1;
}
