/*
    Uno Workchain — Prometheus metrics registry (K-uno-metrics).

    Exposes the §7 monitoring signals from doc/uno-testnet-runbook.md so the
    60-day testnet operator dashboard can scrape the validator-engine.

    Design constraints (from K-uno-metrics task spec):

      * No external Prometheus client library. The exposition format is
        simple enough that ~200 lines of hand-rolled emission is cheaper
        than pulling in a dependency and its license audit.
      * No separate HTTP endpoint. Metrics are surfaced through the existing
        JSON-RPC facade as `uno_getMetrics`. The response body is a JSON
        object with a single `metrics` field whose value is the
        Prometheus text-format exposition (Content-Type
        `text/plain; version=0.0.4` in spirit).
      * Thread-safe counter / gauge / histogram primitives. std::atomic for
        counters + gauges; histogram buckets use per-bucket atomics with a
        seq-lock-free single-writer-per-observation pattern. Contention is
        non-issue — every call site fires once per tx or once per block.
      * Zero-cost if unused. The registry is an always-on `inline static`
        singleton (one atomic pointer, constructed on first access). A
        no-op registry is the "unused" state — when no instrumentation
        code runs, the registry remains empty and the exposition emits
        only the `# HELP` / `# TYPE` preamble.

    Signals covered (maps to doc/uno-testnet-runbook.md §7):

      Counters:
        uno_transfers_admitted_total                          — §7.2 cadence
        uno_transfers_rejected_total{reason="<enum>"}         — §7.1, §7.4
            reasons: stale_anchor, bad_sig, bad_proof, duplicate_nf,
                     malformed, bad_version, wrong_chain_id, bad_point,
                     insufficient_fee, expiry_out_of_range, bad_spend_count,
                     bad_output_count, duplicate_cm_in_tx,
                     nullifier_already_spent, decode_error, other
        uno_blocks_produced_total                             — §7.2
        uno_blocks_state_root_divergences_total               — §7.1, §9.1
            (Bumped by the external reconciliation harness when it observes
             a cross-validator state-root mismatch; local code does not
             produce divergences, but the counter is exposed here so the
             harness can POST into the same dashboard that scrapes the rest
             of the metrics.)
        uno_nullifier_lru_hits_total                          — §7.3
        uno_nullifier_lru_misses_total                        — §7.3

      Gauges:
        uno_anchor_window_size                                — §7.1
        uno_commitment_tree_next_position                     — §7.1
        uno_nullifier_set_size                                — §7.3
        uno_mempool_size                                      — §7.2

      Histograms:
        uno_verify_transfer_seconds{phase="admission"}        — §7.4
        uno_verify_transfer_seconds{phase="compute"}          — §7.4
        uno_apply_transfer_seconds                            — §7.2
        uno_block_filter_gcs_bytes                            — §7.2 (size
            distribution of the emitted GCS blob per block; lets ops catch
            a pathologically-growing filter before it hits the RPC budget)

    Source: TOS-specific (new module; no upstream equivalent).
*/
#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

namespace uno_workchain {

// ===========================================================================
// Reject-reason enum used by the `uno_transfers_rejected_total` label.
//
// Exposition labels (the string form) are stable and consumed by dashboard
// queries — do not rename them without migrating the dashboard. Adding new
// variants is safe (unknown variants are rendered as `other`).
// ===========================================================================

enum class RejectReason : uint8_t {
    Malformed               = 0,
    BadVersion              = 1,
    WrongChainId            = 2,
    ExpiryOutOfRange        = 3,
    BadSpendCount           = 4,
    BadOutputCount          = 5,
    InsufficientFee         = 6,
    StaleAnchor             = 7,       // unknown anchor
    DuplicateNfInTx         = 8,
    DuplicateCmInTx         = 9,
    BadPoint                = 10,      // bad ristretto point
    NullifierAlreadySpent   = 11,
    BadSig                  = 12,      // bad spend_auth_sig
    BadProof                = 13,      // bad plonky3 proof
    DecodeError             = 14,
    Other                   = 15,
};

const char* reject_reason_label(RejectReason r) noexcept;

// ===========================================================================
// Verify phases for the `uno_verify_transfer_seconds` histogram label.
// ===========================================================================

enum class VerifyPhase : uint8_t {
    Admission = 0,   // §4.3a subset (mempool admission)
    Compute   = 1,   // §4.3 full verify (compute phase)
};

const char* verify_phase_label(VerifyPhase p) noexcept;

// ===========================================================================
// MetricsRegistry — thread-safe counter / gauge / histogram store.
//
// Thread-safety: every mutator is non-blocking (std::atomic). The
// `render_prometheus()` path snapshots per-metric atomics without a global
// lock; a concurrently-updated counter may therefore appear slightly
// behind in one render pass, which matches the Prometheus convention
// (scrape is a moment-in-time view).
// ===========================================================================

class MetricsRegistry {
  public:
    MetricsRegistry();

    // --- Counters -----------------------------------------------------------
    void inc_transfers_admitted() noexcept;
    void inc_transfers_rejected(RejectReason reason) noexcept;
    void inc_blocks_produced() noexcept;
    void inc_blocks_state_root_divergences() noexcept;
    void inc_nullifier_lru_hits() noexcept;
    void inc_nullifier_lru_misses() noexcept;

    // --- Gauges -------------------------------------------------------------
    void set_anchor_window_size(uint64_t v) noexcept;
    void set_commitment_tree_next_position(uint64_t v) noexcept;
    void set_nullifier_set_size(uint64_t v) noexcept;
    void set_mempool_size(uint64_t v) noexcept;

    // --- Histograms ---------------------------------------------------------
    /// Record a verify-transfer observation. `seconds` is the wall-clock
    /// duration of the verify call (admission subset or full §4.3 verify).
    void observe_verify_transfer(VerifyPhase phase, double seconds) noexcept;
    /// Record an apply-transfer observation (§4.3 step 5).
    void observe_apply_transfer(double seconds) noexcept;
    /// Record a block-filter GCS blob size observation, in bytes.
    void observe_block_filter_gcs_bytes(uint64_t bytes) noexcept;

    // --- Exposition ---------------------------------------------------------
    /// Render the current snapshot into Prometheus text exposition format.
    /// Never throws. Content is self-describing (# HELP / # TYPE lines).
    std::string render_prometheus() const;

    // --- Test-only ----------------------------------------------------------
    /// Reset every counter, gauge, and histogram bucket to zero. Tests use
    /// this between scenarios so they can assert on exact counts without
    /// ordering to the global process lifetime.
    void reset_for_test() noexcept;

    // --- Histogram storage --------------------------------------------------
    //
    // Bucket boundaries are expressed in seconds for verify / apply, and in
    // bytes for GCS size. Chosen to span the relaxed §9.4 envelope (verify
    // median < 150 ms, P99 < 500 ms) plus headroom on both ends.
    //
    // Prometheus convention: each bucket is cumulative (le = "less than or
    // equal"). We store per-bucket counts that the renderer converts to
    // the cumulative form at emission time.
    //
    // The "+Inf" bucket is implicit (= sum of all per-bucket counts, also
    // equal to `count`). `sum` tracks the double-precision sum of
    // observations so the renderer can emit `_sum` / `_count` pairs.
    //
    // Declared public so internal helpers + inline renderers can name the
    // type; no external caller is expected to construct one.
    struct Histogram {
        std::array<std::atomic<uint64_t>, 16> bucket_counts{};
        std::atomic<uint64_t> count{0};
        // Sum stored as uint64 of bit-casted double, updated by CAS. This
        // avoids a platform-dependent std::atomic<double> that is not
        // lock-free on every libstdc++. See `atomic_add_double` impl.
        std::atomic<uint64_t> sum_bits{0};
        size_t n_buckets{0};
        const double* boundaries{nullptr};  // size == n_buckets
    };

  private:
    static constexpr size_t kVerifyBuckets   = 12;  // <= 1ms ... >= 10s
    static constexpr size_t kApplyBuckets    = 10;
    static constexpr size_t kFilterBuckets   = 10;

    // --- Counters (process-global, monotonic) -------------------------------
    std::atomic<uint64_t> c_admitted_{0};
    std::atomic<uint64_t> c_blocks_produced_{0};
    std::atomic<uint64_t> c_state_root_divergences_{0};
    std::atomic<uint64_t> c_nf_lru_hits_{0};
    std::atomic<uint64_t> c_nf_lru_misses_{0};
    // Rejected counters, keyed by RejectReason enum ordinal (16 slots).
    std::array<std::atomic<uint64_t>, 16> c_rejected_{};

    // --- Gauges -------------------------------------------------------------
    std::atomic<uint64_t> g_anchor_window_size_{0};
    std::atomic<uint64_t> g_ct_next_position_{0};
    std::atomic<uint64_t> g_nf_set_size_{0};
    std::atomic<uint64_t> g_mempool_size_{0};

    // --- Histograms ---------------------------------------------------------
    // One histogram per (metric, label) pair; two phases for
    // verify_transfer_seconds, a singleton for apply_transfer_seconds and
    // block_filter_gcs_bytes.
    mutable Histogram h_verify_admission_{};
    mutable Histogram h_verify_compute_{};
    mutable Histogram h_apply_{};
    mutable Histogram h_filter_gcs_{};
};

// ===========================================================================
// Process-global registry singleton.
//
// The registry is always present — there is no "metrics disabled" mode. When
// no instrumentation runs, the counters sit at zero and the renderer emits
// the type/help preamble plus zeroed samples. The cost of an unused
// instrumentation call site is a single atomic add.
// ===========================================================================

/// Returns the process-global metrics registry. Never null.
MetricsRegistry& global_metrics_registry() noexcept;

// ===========================================================================
// Convenience helpers for common instrumentation points. Using these keeps
// call sites to one line so the instrumentation overhead stays visible in
// diffs (the stated K-uno-metrics goal of "ifdef-free, ~5–10 LoC per hook").
// ===========================================================================

/// Map a `VerifyResult` enum (uno/core/compute-phase.h) into the Prometheus
/// reject-reason label. The `VerifyResult` enum is forward-declared here to
/// avoid pulling compute-phase.h into metrics-consumers; the implementation
/// does the mapping by integer value. Returns `RejectReason::Other` for
/// unknown codes.
RejectReason reject_reason_from_verify_result(int verify_result_ord) noexcept;

/// Map an `AdmissionRejectReason` (uno/rpc/handlers.h) into the Prometheus
/// reject-reason label. Integer-valued mapping to avoid the header-include
/// cycle.
RejectReason reject_reason_from_admission(int admission_ord) noexcept;

/// Scoped timer — RAII wrapper that records a verify-transfer observation at
/// destruction. Move-only; `cancel()` discards the observation (e.g. on an
/// early-exit parse error path that shouldn't count against the histogram).
class ScopedVerifyTimer {
  public:
    ScopedVerifyTimer(MetricsRegistry& reg, VerifyPhase phase) noexcept;
    ~ScopedVerifyTimer();
    ScopedVerifyTimer(const ScopedVerifyTimer&) = delete;
    ScopedVerifyTimer& operator=(const ScopedVerifyTimer&) = delete;
    ScopedVerifyTimer(ScopedVerifyTimer&&) = delete;
    ScopedVerifyTimer& operator=(ScopedVerifyTimer&&) = delete;

    /// Discard the pending observation.
    void cancel() noexcept { cancelled_ = true; }

  private:
    MetricsRegistry& reg_;
    VerifyPhase phase_;
    uint64_t    start_ns_;
    bool        cancelled_{false};
};

/// Scoped timer for apply-transfer. Same semantics as ScopedVerifyTimer.
class ScopedApplyTimer {
  public:
    explicit ScopedApplyTimer(MetricsRegistry& reg) noexcept;
    ~ScopedApplyTimer();
    ScopedApplyTimer(const ScopedApplyTimer&) = delete;
    ScopedApplyTimer& operator=(const ScopedApplyTimer&) = delete;
    ScopedApplyTimer(ScopedApplyTimer&&) = delete;
    ScopedApplyTimer& operator=(ScopedApplyTimer&&) = delete;

    void cancel() noexcept { cancelled_ = true; }

  private:
    MetricsRegistry& reg_;
    uint64_t         start_ns_;
    bool             cancelled_{false};
};

}  // namespace uno_workchain
