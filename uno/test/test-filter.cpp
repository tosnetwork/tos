/*
    Uno Workchain — compact-filter serving + match-correctness smoke test.

    RPC-scope coverage:
      * fetch_block_filter() returns std::nullopt when no backend is
        registered, and the RPC layer renders that as a JSON-RPC
        "not ready" error with the correct error code.
      * Once a backend is bound, fetch_block_filter() routes through
        correctly and the RPC response surfaces the blob's
        (seqno, filter_tag_bits, p, gcs-hex) fields.
      * A trivial in-test GCS-like membership round-trip — we
        install a linear-scan filter backend and assert that fetching,
        then matching a known tag, returns the expected hit.
      * Paginated output fetch: same registration + routing.

    The full GCS compaction (Agent 2's uno/core/block-filter.*) is not in
    scope for this test; we only prove the plumbing is deterministic and
    that the RPC layer hands a caller the bytes the backend produced.
*/
#include "uno/rpc/filter-service.h"
#include "uno/rpc/handlers.h"

#include <atomic>
#include <cassert>
#include <cstdarg>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

// ----- Harness --------------------------------------------------------------

static std::atomic<int> g_test_failures{0};
static std::atomic<int> g_test_skips{0};

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
        if (rendered.find("FAILED") != std::string::npos) g_test_failures.fetch_add(1);
        if (rendered.find("SKIP")   != std::string::npos) g_test_skips.fetch_add(1);
    }
    return written;
}
#define tprintf tracked_printf

// ----- Fake filter backend --------------------------------------------------
//
// The backend serves a single canned block: seqno=10 has a trivial filter
// carrying three 16-bit tags as raw LE bytes (no real GCS compaction — we
// test plumbing, not compression here). This shape is compatible with
// Agent 2's `BlockFilterBlob` contract.

static std::optional<uno_workchain::BlockFilterBlob> fake_filter_fetch(uint64_t seqno) {
    if (seqno != 10) return std::nullopt;
    uno_workchain::BlockFilterBlob b;
    b.block_seqno = 10;
    b.filter_tag_bits = 16;
    b.p_param = 19;  // canonical Zcash GCS P for 16-bit tag; demo value only
    // Tags: 0x1234, 0xCAFE, 0x0BAD — packed little-endian.
    uint16_t tags[3] = { 0x1234, 0xCAFE, 0x0BAD };
    b.gcs_bytes.resize(sizeof(tags));
    std::memcpy(b.gcs_bytes.data(), tags, sizeof(tags));
    return b;
}

static std::optional<uno_workchain::OutputsPage> fake_outputs_fetch(
    uint64_t seqno, uint64_t from_index, uint64_t limit) {
    if (seqno != 10) return std::nullopt;
    uno_workchain::OutputsPage p;
    p.block_seqno = 10;
    p.from_index = from_index;
    p.total_in_block = 3;
    uint64_t i_end = std::min<uint64_t>(3, from_index + limit);
    for (uint64_t i = from_index; i < i_end; ++i) {
        uno_workchain::OutputRecord r;
        r.global_index = 1000 + i;
        // Three stylised "bytes" — just marker payloads so the round-trip
        // through the RPC layer is observable.
        r.bytes = "OUT" + std::to_string(i);
        p.outputs.push_back(r);
    }
    return p;
}

// ----- Tests ----------------------------------------------------------------

static void test_filter_fetch_without_backend_reports_not_ready() {
    tprintf("[TEST] test_filter_fetch_without_backend_reports_not_ready\n");
    uno_workchain::reset_uno_rpc_state_for_test();
    auto r = uno_workchain::handle_uno_rpc("uno_getBlockFilter", "[10]", "1");
    if (!r)            { tprintf("  FAILED: nullopt\n"); return; }
    if (!r->is_error)  { tprintf("  FAILED: expected is_error; got %s\n", r->json.c_str()); return; }
    if (r->json.find("-32011") == std::string::npos) {
        tprintf("  FAILED: expected kErrNotReadyYet (-32011) in body: %s\n", r->json.c_str());
        return;
    }
    tprintf("  PASSED\n");
}

static void test_filter_fetch_with_backend_rpc_roundtrip() {
    tprintf("[TEST] test_filter_fetch_with_backend_rpc_roundtrip\n");
    uno_workchain::reset_uno_rpc_state_for_test();
    uno_workchain::set_filter_fetch_backend(fake_filter_fetch);

    auto r = uno_workchain::handle_uno_rpc("uno_getBlockFilter", "[10]", "2");
    if (!r || r->is_error) {
        tprintf("  FAILED: unexpected: %s\n", r ? r->json.c_str() : "(nullopt)");
        return;
    }
    // Check all four of our documented fields appear. The GCS-hex payload
    // is the LE packing of { 0x1234, 0xCAFE, 0x0BAD } = "3412fecaad0b".
    for (const char* k : { "\"seqno\":10", "\"filter_tag_bits\":16",
                            "\"p\":19", "\"gcs\":\"3412fecaad0b\"" }) {
        if (r->json.find(k) == std::string::npos) {
            tprintf("  FAILED: body missing %s: %s\n", k, r->json.c_str());
            return;
        }
    }

    // Unknown seqno still produces the not-ready error.
    auto r2 = uno_workchain::handle_uno_rpc("uno_getBlockFilter", "[99]", "3");
    if (!r2 || !r2->is_error) {
        tprintf("  FAILED: expected not-ready for seqno=99\n");
        return;
    }
    tprintf("  PASSED\n");
}

static void test_filter_match_correctness_on_raw_tags() {
    tprintf("[TEST] test_filter_match_correctness_on_raw_tags\n");
    uno_workchain::reset_filter_service_for_test();
    uno_workchain::set_filter_fetch_backend(fake_filter_fetch);

    auto blob = uno_workchain::fetch_block_filter(10);
    if (!blob) { tprintf("  FAILED: backend returned nullopt\n"); return; }

    // Given our test backend packs raw LE u16 tags, "match" reduces to a
    // 16-bit scan. Real code does GCS decode + bucket walk; this assertion
    // is only here to prove the byte lane from backend ⇒ caller is intact.
    auto find_tag = [&](uint16_t t) -> bool {
        size_t n = blob->gcs_bytes.size();
        if (n % 2 != 0) return false;
        for (size_t i = 0; i < n; i += 2) {
            uint16_t v = (uint16_t)(uint8_t)blob->gcs_bytes[i] |
                         (uint16_t)((uint8_t)blob->gcs_bytes[i+1] << 8);
            if (v == t) return true;
        }
        return false;
    };
    if (!find_tag(0x1234) || !find_tag(0xCAFE) || !find_tag(0x0BAD)) {
        tprintf("  FAILED: expected tags missing from filter bytes\n");
        return;
    }
    if (find_tag(0xDEAD)) {
        tprintf("  FAILED: unexpected tag 0xDEAD matched\n");
        return;
    }
    tprintf("  PASSED\n");
}

static void test_outputs_at_block_pagination() {
    tprintf("[TEST] test_outputs_at_block_pagination\n");
    uno_workchain::reset_uno_rpc_state_for_test();
    uno_workchain::set_outputs_fetch_backend(fake_outputs_fetch);

    auto r = uno_workchain::handle_uno_rpc(
        "uno_getOutputsAtBlock", "[10, 0, 2]", "10");
    if (!r || r->is_error) {
        tprintf("  FAILED: page fetch failed: %s\n", r ? r->json.c_str() : "(nullopt)");
        return;
    }
    // Expect 2 outputs, indices 1000 and 1001.
    if (r->json.find("\"total_in_block\":3") == std::string::npos ||
        r->json.find("\"index\":1000") == std::string::npos ||
        r->json.find("\"index\":1001") == std::string::npos) {
        tprintf("  FAILED: body missing expected indices: %s\n", r->json.c_str());
        return;
    }
    if (r->json.find("\"index\":1002") != std::string::npos) {
        tprintf("  FAILED: third output appeared in paginated slice\n");
        return;
    }

    auto r2 = uno_workchain::handle_uno_rpc(
        "uno_getOutputsAtBlock", "[10, 2, 5]", "11");
    if (!r2 || r2->is_error) {
        tprintf("  FAILED: tail fetch failed\n");
        return;
    }
    if (r2->json.find("\"index\":1002") == std::string::npos) {
        tprintf("  FAILED: tail missing expected index 1002\n");
        return;
    }
    tprintf("  PASSED\n");
}

static void test_full_gcs_compile_skipped() {
    tprintf("[TEST] test_full_gcs_compile (Agent 2's block-filter.cpp)\n");
    // The real GCS-compile + match pipeline is in uno/core/block-filter.{h,cpp}
    // (Agent 2). When that lands we run the compiled filter against a known
    // tag set and assert no false negatives.
    tprintf("  SKIP: waiting on uno/core/block-filter.{h,cpp}\n");
}

int main() {
    tprintf("Uno Workchain — compact filter service test\n");
    tprintf("============================================\n\n");

    test_filter_fetch_without_backend_reports_not_ready();
    test_filter_fetch_with_backend_rpc_roundtrip();
    test_filter_match_correctness_on_raw_tags();
    test_outputs_at_block_pagination();
    test_full_gcs_compile_skipped();

    tprintf("\nTotal failures: %d, skips: %d\n",
            g_test_failures.load(), g_test_skips.load());
    return g_test_failures.load() == 0 ? 0 : 1;
}
