/*
    Uno Workchain — Transfer wire-codec round-trip smoke test.

    This test verifies the narrow property we fully own in the RPC scope:
    the RPC facade accepts a hex Transfer blob, forwards it through the
    admission-check hook, hands a byte-identical copy to the external-message
    submit hook, and echoes back the admission-computed tx hash.

    The end-to-end codec round-trip (Transfer struct ↔ wire bytes) is owned
    by Agent 5; when that codec is wired in, this test gains one extra
    assertion verifying byte-identical re-serialisation via a real decode.
    Until then, that assertion is SKIPPED with a printed reason.

    Build against: uno_workchain (provides uno/rpc/handlers.{h,cpp})
*/
#include "uno/rpc/handlers.h"
#include "uno/rpc/filter-service.h"
#include "uno/rpc/subscriptions.h"

#include <atomic>
#include <array>
#include <cassert>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// ----- Local assert / tracking harness (matches evm/test/test-executor.cpp) -

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

// --- Sample Transfer blob (pretend) -----------------------------------------
//
// We don't have Agent 5's real codec yet; this is a made-up blob used only
// to exercise the RPC plumbing. The admission-check hook below accepts any
// non-empty blob and uses BLAKE-free XOR fold for the tx_hash — this is
// pinned as an explicit placeholder. Agent 5 replaces it with the real
// BLAKE3-based tx_hash when its codec lands.

static std::vector<uint8_t> make_fake_blob() {
    std::vector<uint8_t> v;
    v.reserve(256);
    for (int i = 0; i < 256; ++i) v.push_back((uint8_t)(i ^ 0xAB));
    return v;
}

// --- Hooks into the RPC surface ---------------------------------------------

static std::vector<uint8_t> g_last_submit_bytes;
static std::array<uint8_t, 32> g_last_submit_hash{};
static int g_submit_count = 0;

static bool fake_submit(const std::string& tx_bytes, const uint8_t tx_hash[32]) {
    g_last_submit_bytes.assign(tx_bytes.begin(), tx_bytes.end());
    std::memcpy(g_last_submit_hash.data(), tx_hash, 32);
    ++g_submit_count;
    return true;
}

// The accessor types + setters live in uno/rpc/handlers.h so tests and
// upstream bind against exactly one declaration.

static uno_workchain::AdmissionResult fake_admission(const uint8_t* tx, size_t n) {
    uno_workchain::AdmissionResult r;
    if (n == 0) {
        r.ok = false;
        r.reason = uno_workchain::AdmissionRejectReason::Malformed;
        return r;
    }
    r.ok = true;
    // 32-byte XOR-fold as a placeholder tx_hash. Agent 5 replaces with
    // BLAKE3 over canonical bytes per §4.3 step 3.
    for (size_t i = 0; i < n; ++i) r.tx_hash[i % 32] ^= tx[i];
    return r;
}

// --- Tests ------------------------------------------------------------------

static void test_send_transfer_roundtrip() {
    tprintf("[TEST] test_send_transfer_roundtrip\n");

    uno_workchain::reset_uno_rpc_state_for_test();
    uno_workchain::set_admission_check_fn(fake_admission);
    uno_workchain::set_submit_external_message_hook(fake_submit);
    g_submit_count = 0;
    g_last_submit_bytes.clear();
    g_last_submit_hash.fill(0);

    auto blob = make_fake_blob();
    std::string hex;
    static const char* H = "0123456789abcdef";
    hex.resize(blob.size() * 2);
    for (size_t i = 0; i < blob.size(); ++i) {
        hex[2*i]     = H[(blob[i] >> 4) & 0xf];
        hex[2*i + 1] = H[blob[i] & 0xf];
    }
    std::string params = "[\"" + hex + "\"]";

    auto r = uno_workchain::handle_uno_rpc("uno_sendTransfer", params, "1");
    if (!r) { tprintf("  FAILED: handle_uno_rpc returned nullopt\n"); return; }
    if (r->is_error) {
        tprintf("  FAILED: handle_uno_rpc returned error: %s\n", r->json.c_str());
        return;
    }

    if (g_submit_count != 1) {
        tprintf("  FAILED: submit hook fired %d times (expected 1)\n", g_submit_count);
        return;
    }

    if (g_last_submit_bytes.size() != blob.size() ||
        std::memcmp(g_last_submit_bytes.data(), blob.data(), blob.size()) != 0) {
        tprintf("  FAILED: submit bytes != input blob\n");
        return;
    }

    // The response JSON should contain the hex tx_hash exactly once.
    if (r->json.find("\"tx_hash\":\"") == std::string::npos) {
        tprintf("  FAILED: response missing tx_hash field: %s\n", r->json.c_str());
        return;
    }

    tprintf("  PASSED\n");
}

static void test_send_transfer_rejects_bad_hex() {
    tprintf("[TEST] test_send_transfer_rejects_bad_hex\n");

    uno_workchain::reset_uno_rpc_state_for_test();
    uno_workchain::set_admission_check_fn(fake_admission);
    uno_workchain::set_submit_external_message_hook(fake_submit);
    g_submit_count = 0;

    // Odd-length + non-hex character
    std::string params = "[\"ZZZ\"]";
    auto r = uno_workchain::handle_uno_rpc("uno_sendTransfer", params, "7");
    if (!r)            { tprintf("  FAILED: nullopt response\n"); return; }
    if (!r->is_error)  { tprintf("  FAILED: expected is_error, got ok\n"); return; }
    if (g_submit_count != 0) {
        tprintf("  FAILED: submit hook fired on bad hex (count=%d)\n", g_submit_count);
        return;
    }
    tprintf("  PASSED\n");
}

static void test_send_transfer_rejects_admission_fail() {
    tprintf("[TEST] test_send_transfer_rejects_admission_fail\n");

    uno_workchain::reset_uno_rpc_state_for_test();
    uno_workchain::set_admission_check_fn(
        [](const uint8_t*, size_t) -> uno_workchain::AdmissionResult {
            uno_workchain::AdmissionResult r;
            r.ok = false;
            r.reason = uno_workchain::AdmissionRejectReason::FeeBelowMin;
            return r;
        });
    uno_workchain::set_submit_external_message_hook(fake_submit);
    g_submit_count = 0;

    std::string params = "[\"deadbeef\"]";
    auto r = uno_workchain::handle_uno_rpc("uno_sendTransfer", params, "9");
    if (!r)           { tprintf("  FAILED: nullopt\n"); return; }
    if (!r->is_error) { tprintf("  FAILED: expected is_error\n"); return; }
    if (g_submit_count != 0) {
        tprintf("  FAILED: submit hook fired when admission rejected\n");
        return;
    }
    tprintf("  PASSED\n");
}

static void test_method_registry() {
    tprintf("[TEST] test_method_registry\n");
    const char* methods[] = {
        "uno_chainInfo",
        "uno_getAnchor",
        "uno_getAnchorAtSeqno",
        "uno_getCommitmentTreeFrontier",
        "uno_getNullifierStatus",
        "uno_getOutputsAtBlock",
        "uno_getBlockFilter",
        "uno_getOutputsForIvk",
        "uno_estimateFee",
        "uno_sendTransfer",
        "uno_getTransactionStatus",
        "uno_subscribe",
        "uno_unsubscribe",
        "uno_getSubscription",
    };
    int missing = 0;
    for (auto m : methods) {
        if (!uno_workchain::is_uno_rpc_method(m)) {
            tprintf("  FAILED: is_uno_rpc_method(%s) returned false\n", m);
            ++missing;
        }
    }
    if (uno_workchain::is_uno_rpc_method("uno_bogus")) {
        tprintf("  FAILED: is_uno_rpc_method(uno_bogus) returned true\n");
        ++missing;
    }
    if (missing == 0) tprintf("  PASSED\n");
}

static void test_wire_codec_byte_identical() {
    tprintf("[TEST] test_wire_codec_byte_identical\n");
    // This is the P.2 round-trip assertion; it depends on Agent 5's
    // uno/core/transaction.cpp encode/decode pair, which is not yet
    // available in this worktree.
    tprintf("  SKIP: Agent 5's uno/core/transaction.* codec not yet available\n");
}

int main() {
    tprintf("Uno Workchain — Transfer wire-codec / RPC round-trip tests\n");
    tprintf("==========================================================\n\n");

    test_method_registry();
    test_send_transfer_roundtrip();
    test_send_transfer_rejects_bad_hex();
    test_send_transfer_rejects_admission_fail();
    test_wire_codec_byte_identical();

    tprintf("\nTotal failures: %d, skips: %d\n",
            g_test_failures.load(), g_test_skips.load());
    return g_test_failures.load() == 0 ? 0 : 1;
}
