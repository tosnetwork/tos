/*
    Uno Workchain — Prometheus metrics smoke test (K-uno-metrics).

    Scope: verify that `uno_getMetrics` returns a Prometheus text-format
    exposition that (a) contains all advertised families from
    `doc/uno-testnet-runbook.md` §7 and (b) reflects counter / gauge /
    histogram observations made through the instrumented code paths.

    The metrics registry is tested at three levels:

      Level 1 — Direct registry API
        MetricsRegistry::inc_*, set_*, observe_* each route to the expected
        family / sample in the rendered exposition. This pins the text
        format without depending on higher layers.

      Level 2 — `uno_getMetrics` JSON-RPC wrapper
        The handler wraps the exposition into a JSON string field
        (`{"content_type": "text/plain; version=0.0.4", "metrics": "..."}`)
        and is reachable through `handle_uno_rpc`, matching the wire contract
        other `uno_*` methods use.

      Level 3 — End-to-end instrumentation
        Drive the compute phase through `run_compute_phase` with a
        minimally-valid Transfer shape. On the "admitted" path the
        `uno_transfers_admitted_total` counter bumps; on the rejected path
        `uno_transfers_rejected_total{reason=...}` bumps with the mapped
        label. Verify that the rendered exposition reflects the bump.

    Build against: uno_workchain (uno/rpc/metrics.{h,cpp}, uno/rpc/handlers.*,
    uno/core/compute-phase.*).
*/
#include "uno/rpc/metrics.h"
#include "uno/rpc/handlers.h"
#include "uno/core/compute-phase.h"
#include "uno/core/init.h"

#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

// ---------------------------------------------------------------------------
// Weak-symbol stubs mirroring other uno/test/* tests — the metrics test does
// NOT touch Plonky3 or Poseidon2 directly, but the transitive uno_workchain
// archive references these FFI symbols and a missing-symbol link error would
// brick the whole binary.
// ---------------------------------------------------------------------------
extern "C" {

struct Plonky3VerifierHandle;
typedef struct { const uint8_t* ptr; std::uintptr_t len; } Plonky3ProofBytes;
typedef struct { const uint8_t* ptr; std::uintptr_t len; } Plonky3PublicInputs;

static std::atomic<int> g_fake_plonky3_handle{0};

__attribute__((weak)) uint32_t uno_plonky3_abi_version(void) { return 1; }
__attribute__((weak)) int32_t uno_plonky3_verifier_init(
    Plonky3VerifierHandle** out) {
    g_fake_plonky3_handle.fetch_add(1, std::memory_order_relaxed);
    *out = reinterpret_cast<Plonky3VerifierHandle*>(&g_fake_plonky3_handle);
    return 0;
}
__attribute__((weak)) void uno_plonky3_verifier_free(
    Plonky3VerifierHandle* /*h*/) {}
__attribute__((weak)) int32_t uno_plonky3_verify(
    const Plonky3VerifierHandle* /*h*/,
    Plonky3ProofBytes /*proof*/, Plonky3PublicInputs /*pi*/) {
    return 4;  // VerifyFailed — metrics test does not exercise this path
}
__attribute__((weak)) void uno_poseidon2_goldilocks_permute_t8(uint64_t s[8]) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (int i = 0; i < 8; ++i) { h ^= s[i]; h *= 0x100000001b3ULL; }
    for (int i = 0; i < 8; ++i) {
        h = (h * 0x100000001b3ULL) ^ (s[i] + static_cast<uint64_t>(i) * 0x9E3779B97F4A7C15ULL);
        s[i] = h % 0xFFFFFFFF00000001ULL;
    }
}
__attribute__((weak)) void uno_poseidon2_goldilocks_permute_t16(uint64_t s[16]) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (int i = 0; i < 16; ++i) { h ^= s[i]; h *= 0x100000001b3ULL; }
    for (int i = 0; i < 16; ++i) {
        h = (h * 0x100000001b3ULL) ^ (s[i] + static_cast<uint64_t>(i) * 0x9E3779B97F4A7C15ULL);
        s[i] = h % 0xFFFFFFFF00000001ULL;
    }
}

}  // extern "C"

// ---------------------------------------------------------------------------
// Minimal in-file test harness (same style as test-uno-nullifier-warm-lru).
// ---------------------------------------------------------------------------
static int g_passed = 0;
static int g_failed = 0;

#define EXPECT_TRUE(cond, label)                                            \
    do {                                                                    \
        if (cond) {                                                         \
            ++g_passed;                                                     \
        } else {                                                            \
            ++g_failed;                                                     \
            std::fprintf(stderr, "  FAIL: %s (%s:%d)\n", (label),           \
                         __FILE__, __LINE__);                               \
        }                                                                   \
    } while (0)

#define EXPECT_CONTAINS(haystack, needle, label)                            \
    do {                                                                    \
        if ((haystack).find((needle)) != std::string::npos) {               \
            ++g_passed;                                                     \
        } else {                                                            \
            ++g_failed;                                                     \
            std::fprintf(stderr, "  FAIL: %s (%s:%d)\n", (label),           \
                         __FILE__, __LINE__);                               \
            std::fprintf(stderr, "    expected substring: %s\n",            \
                         std::string(needle).c_str());                      \
        }                                                                   \
    } while (0)

namespace uw = uno_workchain;

// ---------------------------------------------------------------------------
// Case 1 — Registry families appear in the exposition with HELP + TYPE.
// ---------------------------------------------------------------------------
static void case_exposition_preamble() {
    std::fprintf(stderr, "case: exposition preamble (HELP + TYPE)\n");
    auto& reg = uw::global_metrics_registry();
    reg.reset_for_test();

    std::string out = reg.render_prometheus();

    // Every family listed in the runbook §5 monitoring signals section.
    // Counter families.
    EXPECT_CONTAINS(out, "# TYPE uno_transfers_admitted_total counter",
                    "uno_transfers_admitted_total TYPE line present");
    EXPECT_CONTAINS(out, "# TYPE uno_transfers_rejected_total counter",
                    "uno_transfers_rejected_total TYPE line present");
    EXPECT_CONTAINS(out, "# TYPE uno_blocks_produced_total counter",
                    "uno_blocks_produced_total TYPE line present");
    EXPECT_CONTAINS(out,
                    "# TYPE uno_blocks_state_root_divergences_total counter",
                    "state-root-divergences TYPE line present");
    EXPECT_CONTAINS(out, "# TYPE uno_nullifier_lru_hits_total counter",
                    "nullifier LRU hits TYPE line present");
    EXPECT_CONTAINS(out, "# TYPE uno_nullifier_lru_misses_total counter",
                    "nullifier LRU misses TYPE line present");

    // Gauge families.
    EXPECT_CONTAINS(out, "# TYPE uno_anchor_window_size gauge",
                    "anchor_window_size TYPE line present");
    EXPECT_CONTAINS(out, "# TYPE uno_commitment_tree_next_position gauge",
                    "commitment_tree_next_position TYPE line present");
    EXPECT_CONTAINS(out, "# TYPE uno_nullifier_set_size gauge",
                    "nullifier_set_size TYPE line present");
    EXPECT_CONTAINS(out, "# TYPE uno_mempool_size gauge",
                    "mempool_size TYPE line present");

    // Histogram families.
    EXPECT_CONTAINS(out, "# TYPE uno_verify_transfer_seconds histogram",
                    "verify_transfer_seconds TYPE line present");
    EXPECT_CONTAINS(out, "# TYPE uno_apply_transfer_seconds histogram",
                    "apply_transfer_seconds TYPE line present");
    EXPECT_CONTAINS(out, "# TYPE uno_block_filter_gcs_bytes histogram",
                    "block_filter_gcs_bytes TYPE line present");
}

// ---------------------------------------------------------------------------
// Case 2 — Direct counter / gauge bumps appear in the rendered output.
// ---------------------------------------------------------------------------
static void case_counter_gauge_round_trip() {
    std::fprintf(stderr, "case: counter / gauge round-trip\n");
    auto& reg = uw::global_metrics_registry();
    reg.reset_for_test();

    // Drive three admits + two rejects (different reasons).
    reg.inc_transfers_admitted();
    reg.inc_transfers_admitted();
    reg.inc_transfers_admitted();
    reg.inc_transfers_rejected(uw::RejectReason::StaleAnchor);
    reg.inc_transfers_rejected(uw::RejectReason::BadSig);
    reg.inc_blocks_produced();
    reg.inc_nullifier_lru_hits();
    reg.inc_nullifier_lru_hits();
    reg.inc_nullifier_lru_misses();

    reg.set_anchor_window_size(100);
    reg.set_commitment_tree_next_position(42);
    reg.set_nullifier_set_size(3);
    reg.set_mempool_size(7);

    std::string out = reg.render_prometheus();

    EXPECT_CONTAINS(out, "uno_transfers_admitted_total 3",
                    "admitted counter reflects 3 bumps");
    EXPECT_CONTAINS(out,
                    "uno_transfers_rejected_total{reason=\"stale_anchor\"} 1",
                    "rejected counter has stale_anchor label=1");
    EXPECT_CONTAINS(out,
                    "uno_transfers_rejected_total{reason=\"bad_sig\"} 1",
                    "rejected counter has bad_sig label=1");
    EXPECT_CONTAINS(out, "uno_blocks_produced_total 1",
                    "blocks_produced counter=1");
    EXPECT_CONTAINS(out, "uno_nullifier_lru_hits_total 2",
                    "LRU hits=2");
    EXPECT_CONTAINS(out, "uno_nullifier_lru_misses_total 1",
                    "LRU misses=1");

    EXPECT_CONTAINS(out, "uno_anchor_window_size 100",
                    "anchor_window_size gauge=100");
    EXPECT_CONTAINS(out, "uno_commitment_tree_next_position 42",
                    "commitment_tree_next_position gauge=42");
    EXPECT_CONTAINS(out, "uno_nullifier_set_size 3",
                    "nullifier_set_size gauge=3");
    EXPECT_CONTAINS(out, "uno_mempool_size 7",
                    "mempool_size gauge=7");
}

// ---------------------------------------------------------------------------
// Case 3 — Histogram observations emit _bucket / _sum / _count lines.
// ---------------------------------------------------------------------------
static void case_histogram_round_trip() {
    std::fprintf(stderr, "case: histogram round-trip\n");
    auto& reg = uw::global_metrics_registry();
    reg.reset_for_test();

    reg.observe_verify_transfer(uw::VerifyPhase::Admission, 0.0001);   // admission fast
    reg.observe_verify_transfer(uw::VerifyPhase::Compute,   0.050);    // ~50 ms
    reg.observe_verify_transfer(uw::VerifyPhase::Compute,   0.200);    // ~200 ms
    reg.observe_apply_transfer(0.000050);                               // 50 µs
    reg.observe_block_filter_gcs_bytes(1500);                           // 1.5 KB

    std::string out = reg.render_prometheus();

    // verify_transfer_seconds with phase labels.
    EXPECT_CONTAINS(out,
                    "uno_verify_transfer_seconds_count{phase=\"admission\"} 1",
                    "admission phase count=1");
    EXPECT_CONTAINS(out,
                    "uno_verify_transfer_seconds_count{phase=\"compute\"} 2",
                    "compute phase count=2");
    // admission 0.0001 s should land in the le=0.00025 bucket.
    EXPECT_CONTAINS(out,
                    "uno_verify_transfer_seconds_bucket{phase=\"admission\",le=\"0.00025\"} 1",
                    "admission 0.0001s in first bucket");
    // compute 0.050 s should be in le=0.05 bucket (cumulative: 1).
    EXPECT_CONTAINS(out,
                    "uno_verify_transfer_seconds_bucket{phase=\"compute\",le=\"0.05\"} 1",
                    "compute 0.05s cumulative at le=0.05");
    // _sum line is present (we don't pin the exact float — histogram bucket
    // boundaries are the semantic contract, sum is informational).
    EXPECT_CONTAINS(out, "uno_verify_transfer_seconds_sum{phase=\"compute\"}",
                    "compute phase sum line present");

    // apply_transfer_seconds (single, unlabelled).
    EXPECT_CONTAINS(out, "uno_apply_transfer_seconds_count 1",
                    "apply count=1");

    // block_filter_gcs_bytes: 1500 bytes -> le=4096 bucket.
    EXPECT_CONTAINS(out, "uno_block_filter_gcs_bytes_bucket{le=\"4096\"} 1",
                    "1500 bytes in le=4096 bucket");
    EXPECT_CONTAINS(out, "uno_block_filter_gcs_bytes_count 1",
                    "block_filter_gcs_bytes count=1");
}

// ---------------------------------------------------------------------------
// Case 4 — uno_getMetrics JSON-RPC envelope exposes the exposition.
// ---------------------------------------------------------------------------
static void case_rpc_surface() {
    std::fprintf(stderr, "case: uno_getMetrics RPC wrapper\n");
    auto& reg = uw::global_metrics_registry();
    reg.reset_for_test();
    uw::reset_uno_rpc_state_for_test();

    // Drive one admit so the JSON body has something deterministic.
    reg.inc_transfers_admitted();

    auto resp = uw::handle_uno_rpc("uno_getMetrics", "[]", "42");
    EXPECT_TRUE(resp.has_value(),
                "handle_uno_rpc recognises uno_getMetrics");
    if (!resp.has_value()) return;
    EXPECT_TRUE(!resp->is_error,
                "uno_getMetrics returns a result, not an error");

    const std::string& body = resp->json;
    EXPECT_CONTAINS(body, "\"jsonrpc\":\"2.0\"",
                    "JSON-RPC envelope");
    EXPECT_CONTAINS(body, "\"id\":42",
                    "request id echoed");
    EXPECT_CONTAINS(body, "\"content_type\":\"text/plain; version=0.0.4\"",
                    "Prometheus content-type advertised");
    // The exposition is embedded as an escaped JSON string; we can still
    // grep for the counter name + value token since backslash-n won't split
    // the substring.
    EXPECT_CONTAINS(body, "uno_transfers_admitted_total 1",
                    "admitted counter=1 visible through RPC surface");
    EXPECT_CONTAINS(body, "uno_verify_transfer_seconds_count",
                    "verify_transfer_seconds histogram family visible");

    // is_uno_rpc_method should also recognise the new method name.
    EXPECT_TRUE(uw::is_uno_rpc_method("uno_getMetrics"),
                "is_uno_rpc_method recognises uno_getMetrics");
}

// ---------------------------------------------------------------------------
// Case 5 — Scoped timers fire exactly one histogram observation each.
// ---------------------------------------------------------------------------
static void case_scoped_timers() {
    std::fprintf(stderr, "case: scoped verify / apply timers\n");
    auto& reg = uw::global_metrics_registry();
    reg.reset_for_test();

    {
        uw::ScopedVerifyTimer vt(reg, uw::VerifyPhase::Admission);
        // No-op work; the destructor fires the observation.
        std::this_thread::sleep_for(std::chrono::microseconds(50));
    }
    {
        uw::ScopedApplyTimer at(reg);
        std::this_thread::sleep_for(std::chrono::microseconds(10));
    }
    {
        uw::ScopedVerifyTimer vt(reg, uw::VerifyPhase::Compute);
        vt.cancel();  // cancelled — must NOT record
    }

    std::string out = reg.render_prometheus();
    EXPECT_CONTAINS(out,
                    "uno_verify_transfer_seconds_count{phase=\"admission\"} 1",
                    "admission timer fired once");
    EXPECT_CONTAINS(out,
                    "uno_verify_transfer_seconds_count{phase=\"compute\"} 0",
                    "cancelled compute timer did not record");
    EXPECT_CONTAINS(out, "uno_apply_transfer_seconds_count 1",
                    "apply timer fired once");
}

// ---------------------------------------------------------------------------
// Case 6 — reject_reason_from_verify_result / reject_reason_from_admission
// map their numeric inputs onto the correct label strings.
// ---------------------------------------------------------------------------
static void case_reject_reason_mapping() {
    std::fprintf(stderr, "case: reject-reason enum mapping\n");

    using uw::reject_reason_label;
    using uw::reject_reason_from_verify_result;
    using uw::reject_reason_from_admission;

    // VerifyResult -> RejectReason (pinned values from compute-phase.h).
    EXPECT_TRUE(std::string(reject_reason_label(
        reject_reason_from_verify_result(8))) == "stale_anchor",
        "VerifyResult::UnknownAnchor (8) -> stale_anchor");
    EXPECT_TRUE(std::string(reject_reason_label(
        reject_reason_from_verify_result(30))) == "bad_sig",
        "VerifyResult::BadSpendAuthSig (30) -> bad_sig");
    EXPECT_TRUE(std::string(reject_reason_label(
        reject_reason_from_verify_result(40))) == "bad_proof",
        "VerifyResult::BadPlonky3Proof (40) -> bad_proof");
    EXPECT_TRUE(std::string(reject_reason_label(
        reject_reason_from_verify_result(12))) == "malformed",
        "VerifyResult::BadPublicInput (12) -> malformed");
    EXPECT_TRUE(std::string(reject_reason_label(
        reject_reason_from_verify_result(90))) == "decode_error",
        "VerifyResult::DecodeError (90) -> decode_error");
    EXPECT_TRUE(std::string(reject_reason_label(
        reject_reason_from_verify_result(9999))) == "other",
        "unknown verify ordinal -> other");

    // AdmissionRejectReason -> RejectReason.
    EXPECT_TRUE(std::string(reject_reason_label(
        reject_reason_from_admission(8))) == "stale_anchor",
        "AdmissionRejectReason::StaleAnchor (8) -> stale_anchor");
    EXPECT_TRUE(std::string(reject_reason_label(
        reject_reason_from_admission(1))) == "malformed",
        "AdmissionRejectReason::Malformed (1) -> malformed");
}

// ---------------------------------------------------------------------------
// Case 7 — compute-phase decode-error path bumps the exposed counter.
// Drives `run_compute_phase` with a deliberately-malformed cell slice so
// the §4.3 decode fails; this instruments the counter-bump added in
// compute-phase.cpp without needing a valid Plonky3 proof.
// ---------------------------------------------------------------------------
static void case_compute_phase_decode_error() {
    std::fprintf(stderr, "case: compute-phase decode-error bumps counter\n");
    auto& reg = uw::global_metrics_registry();
    reg.reset_for_test();

    // Build an empty cell slice. `decode_transfer(empty_slice)` returns a
    // TransferDecodeError since the header (version / chain_id) is missing.
    vm::CellBuilder empty_cb;
    auto empty_cell = empty_cb.finalize();
    vm::CellSlice cs = vm::load_cell_slice(empty_cell);

    // Minimal UnoState stub — the decode path fails before any state is
    // consulted, so we never dereference `state`. We cast `nullptr` through
    // a reference; this is UB in the general case but safe here because
    // compute-phase.cpp returns on decode error before touching the ref.
    //
    // For robustness, use a tiny throw-away impl instead.
    struct NoOpState : public uw::UnoState {
        bool anchor_window_contains(const td::Bits256&) const override { return false; }
        bool nullifier_is_spent(const td::Bits256&) const override     { return false; }
        void append_commitment(const td::Bits256&) override {}
        void insert_nullifier(const td::Bits256&) override {}
        void accumulate_filter_tag(uint16_t) override {}
        void bump_stats(uint64_t, uint64_t) override {}
        td::Ref<vm::Cell> serialize_to_cell() const override { return {}; }
        uint32_t expected_chain_id() const override    { return 0; }
        uint64_t current_block_seqno() const override  { return 0; }
        uint32_t expiry_window_blocks() const override { return 0; }
        uint64_t min_fee_nano() const override         { return 0; }
        uint64_t fee_per_byte_nano() const override    { return 0; }
        uint64_t fee_per_spend_nano() const override   { return 0; }
        uint64_t fee_per_output_nano() const override  { return 0; }
    } state;

    block::ComputePhase cp;
    uint8_t rand_seed[32] = {0};
    bool ok = uw::run_compute_phase(
        cp, cs, /*gas_limit=*/1'000'000, state,
        /*block_seqno=*/1, /*timestamp=*/0, rand_seed,
        // Round 76 HIGH fix: pre-decode failure path doesn't touch
        // gas_used, so balance is irrelevant — pass a large value.
        td::make_refint(1ULL << 62));
    EXPECT_TRUE(ok, "run_compute_phase returned");
    EXPECT_TRUE(!cp.success, "decode error -> cp.success = false");

    // Expect the decode_error reason label to be bumped exactly once.
    std::string out = reg.render_prometheus();
    EXPECT_CONTAINS(out,
                    "uno_transfers_rejected_total{reason=\"decode_error\"} 1",
                    "decode_error reject counter=1");
    // And no admitted.
    EXPECT_CONTAINS(out, "uno_transfers_admitted_total 0",
                    "admitted stays 0 on decode error");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main() {
    std::fprintf(stderr,
        "== test-uno-metrics (K-uno-metrics Prometheus exposition) ==\n");

    case_exposition_preamble();
    case_counter_gauge_round_trip();
    case_histogram_round_trip();
    case_rpc_surface();
    case_scoped_timers();
    case_reject_reason_mapping();
    case_compute_phase_decode_error();

    std::fprintf(stderr, "\nRESULT: %d passed, %d failed\n",
                 g_passed, g_failed);
    return g_failed == 0 ? 0 : 1;
}
