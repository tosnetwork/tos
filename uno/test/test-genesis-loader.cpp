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

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    tprintf("Uno Workchain — K-genesis-loader test\n");
    tprintf("======================================\n\n");

    test_load_and_build_happy_path();
    test_reject_malformed_envelope();
    test_reject_short_rseed();
    test_reject_negative_value();
    test_reject_supply_mismatch();

    tprintf("\nTotal: passed=%d, failures=%d, skips=%d\n",
            g_passes.load(), g_failures.load(), g_skips.load());
    return g_failures.load() == 0 ? 0 : 1;
}
