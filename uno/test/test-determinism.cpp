/*
    Uno Workchain — cross-validator determinism fixture scaffold (P.5).

    Per §12 P.5 of doc/uno-workchain.md, we must prove that a fixed sequence
    of txs applied against a fresh state produces byte-identical post-state
    across:
      (a) multiple runs in the same process
      (b) multiple processes
      (c) multiple validators (4-node replay, permuted mempool order)

    This file is the RPC-side scaffold for (a). The state machine itself
    (verify_transfer, apply_transfer, cell-state serialise) is owned by
    Agents 1/2/5; when those are available this test drives the full loop.
    Until then we verify the scaffold's determinism — the RPC layer's own
    admission path, the filter-service pointer registry, and the
    subscription manager — across repeated runs.

    What we test locally (no upstream needed):
      * handle_uno_rpc() is a pure function of (method, params, id) + the
        registered accessors. Given identical hooks and identical inputs,
        the output JSON is byte-identical.
      * The admission-check → submit-hook path is side-effect deterministic
        (same input bytes ⇒ same submit bytes, same tx_hash).
      * Subscription-manager poll output is insertion-ordered and
        deterministic within a single run.

    The full state-machine determinism check is left as GTEST_SKIP-style
    informational SKIP until Agent 2's UnoShardState accessors are bound.
*/
#include "uno/rpc/handlers.h"
#include "uno/rpc/subscriptions.h"
#include "uno/rpc/filter-service.h"

#include <atomic>
#include <cassert>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

// ----- Test-harness boilerplate ---------------------------------------------

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

// ----- Deterministic RPC scaffold -------------------------------------------

static std::vector<std::string> g_submit_log;  // cleared per run

static bool submit_capture(const std::string& bytes, const uint8_t hash[32]) {
    // Record "bytes|hash" so two runs produce string-comparable logs.
    std::string line;
    line.assign(bytes);
    line += "|";
    for (int i = 0; i < 32; ++i) {
        char b[3];
        std::snprintf(b, sizeof(b), "%02x", hash[i]);
        line += b;
    }
    g_submit_log.push_back(std::move(line));
    return true;
}

static uno_workchain::AdmissionResult det_admission(const uint8_t* tx, size_t n) {
    uno_workchain::AdmissionResult r;
    if (n == 0) {
        r.ok = false;
        r.reason = uno_workchain::AdmissionRejectReason::Malformed;
        return r;
    }
    r.ok = true;
    // XOR-fold hash = fully deterministic, no RNG, no wall-clock.
    for (size_t i = 0; i < n; ++i) r.tx_hash[i % 32] ^= tx[i];
    return r;
}

static uno_workchain::HeadStateSnapshot det_head() {
    uno_workchain::HeadStateSnapshot s;
    s.chain_id = 0x554E4F54;   // "UNOT"
    s.workchain_id = 2;
    s.head_seqno = 42;
    s.anchor_window_size = 100;
    s.min_fee_nano = 1000;
    s.fee_per_byte_nano = 1;
    s.fee_per_spend_nano = 100;
    s.fee_per_output_nano = 200;
    s.max_spends_per_tx = 4;
    s.max_outputs_per_tx = 4;
    s.scheme_id = 0x01;
    for (int i = 0; i < 32; ++i) s.current_anchor_root[i] = (uint8_t)i;
    for (int i = 0; i < 32; ++i) s.executor_address[i] = (uint8_t)(i ^ 0xAA);
    for (int k = 0; k < 3; ++k) {
        std::array<uint8_t, 32> a{};
        for (int i = 0; i < 32; ++i) a[i] = (uint8_t)(k * 7 + i);
        s.anchor_window.push_back(a);
    }
    return s;
}

static std::string run_once(const std::vector<std::string>& requests) {
    uno_workchain::reset_uno_rpc_state_for_test();
    uno_workchain::set_admission_check_fn(det_admission);
    uno_workchain::set_submit_external_message_hook(submit_capture);
    uno_workchain::set_head_state_fn(det_head);

    g_submit_log.clear();

    std::string out;
    for (size_t i = 0; i < requests.size(); ++i) {
        // One request per line of the canonical output, prefixed with the
        // request index so interleaved results are unambiguous.
        //
        // format per line: "<idx>|<method>|<json-response>"
        // We assume each entry is "<method>|<params-json>".
        auto sep = requests[i].find('|');
        std::string method = requests[i].substr(0, sep);
        std::string params = requests[i].substr(sep + 1);
        auto r = uno_workchain::handle_uno_rpc(method, params, std::to_string(i));
        out += std::to_string(i);
        out += "|";
        out += method;
        out += "|";
        out += (r ? r->json : std::string("<NOTFOUND>"));
        out += "\n";
    }
    for (size_t i = 0; i < g_submit_log.size(); ++i) {
        out += "submit[";
        out += std::to_string(i);
        out += "]=";
        out += g_submit_log[i];
        out += "\n";
    }
    return out;
}

// ----- Tests ----------------------------------------------------------------

static void test_rpc_dispatch_is_deterministic() {
    tprintf("[TEST] test_rpc_dispatch_is_deterministic\n");

    std::vector<std::string> reqs = {
        "uno_chainInfo|[]",
        "uno_getAnchor|[]",
        "uno_estimateFee|[2, 3]",
        "uno_sendTransfer|[\"deadbeef0011223344\"]",
        "uno_sendTransfer|[\"aabbccdd\"]",
        "uno_estimateFee|[1, 1]",
    };

    std::string a = run_once(reqs);
    std::string b = run_once(reqs);
    std::string c = run_once(reqs);

    if (a != b) {
        tprintf("  FAILED: run1 != run2\n---run1---\n%s\n---run2---\n%s\n",
                a.c_str(), b.c_str());
        return;
    }
    if (b != c) {
        tprintf("  FAILED: run2 != run3\n");
        return;
    }
    tprintf("  PASSED (%zu bytes of canonical output, reproduced 3x)\n", a.size());
}

static void test_subscription_order_is_deterministic() {
    tprintf("[TEST] test_subscription_order_is_deterministic\n");

    uno_workchain::reset_uno_rpc_state_for_test();
    auto& mgr = uno_workchain::global_uno_subscription_manager();

    uint64_t s1 = mgr.subscribe(uno_workchain::UnoSubscriptionType::IncludedTx);
    uint64_t s2 = mgr.subscribe(uno_workchain::UnoSubscriptionType::NewHead);

    mgr.notify_included_tx("deadbeef", 10, 1234);
    mgr.notify_new_head(10, "abcd", 3, 6);
    mgr.notify_included_tx("cafef00d", 10, 5678);

    auto e1 = mgr.poll(s1);
    auto e2 = mgr.poll(s2);

    if (e1.size() != 2) { tprintf("  FAILED: included-tx drain size=%zu\n", e1.size()); return; }
    if (e2.size() != 1) { tprintf("  FAILED: new-head drain size=%zu\n", e2.size()); return; }
    if (e1[0].json.find("deadbeef") == std::string::npos ||
        e1[1].json.find("cafef00d") == std::string::npos) {
        tprintf("  FAILED: included-tx events out of order\n");
        return;
    }
    tprintf("  PASSED\n");
}

static void test_state_machine_determinism_skipped() {
    tprintf("[TEST] test_state_machine_determinism (full P.5 fixture)\n");
    // The full P.5 fixture drives verify_transfer → apply_transfer against
    // a fresh UnoShardState and compares the serialised post-state across
    // N permuted mempool orders. That needs Agent 1/2/5's state + codec.
    tprintf("  SKIP: waiting on UnoShardState + verify_transfer + cell-state serialiser\n");
}

int main() {
    tprintf("Uno Workchain — determinism fixture (RPC scope)\n");
    tprintf("================================================\n\n");

    test_rpc_dispatch_is_deterministic();
    test_subscription_order_is_deterministic();
    test_state_machine_determinism_skipped();

    tprintf("\nTotal failures: %d, skips: %d\n",
            g_test_failures.load(), g_test_skips.load());
    return g_test_failures.load() == 0 ? 0 : 1;
}
