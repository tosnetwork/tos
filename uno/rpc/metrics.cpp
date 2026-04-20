/*
    Uno Workchain — Prometheus metrics registry implementation (K-uno-metrics).

    See header for scope, thread-safety, and the signal list. This TU is
    deliberately dependency-light: no external Prometheus client library,
    no blockchain-specific includes, just std::atomic plumbing and a hand-
    rolled text-format renderer.

    Source: TOS-specific (new module).
*/
#include "uno/rpc/metrics.h"

#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>

namespace uno_workchain {

// ===========================================================================
// Label helpers
// ===========================================================================

const char* reject_reason_label(RejectReason r) noexcept {
    switch (r) {
        case RejectReason::Malformed:             return "malformed";
        case RejectReason::BadVersion:            return "bad_version";
        case RejectReason::WrongChainId:          return "wrong_chain_id";
        case RejectReason::ExpiryOutOfRange:      return "expiry_out_of_range";
        case RejectReason::BadSpendCount:         return "bad_spend_count";
        case RejectReason::BadOutputCount:        return "bad_output_count";
        case RejectReason::InsufficientFee:       return "insufficient_fee";
        case RejectReason::StaleAnchor:           return "stale_anchor";
        case RejectReason::DuplicateNfInTx:       return "duplicate_nf";
        case RejectReason::DuplicateCmInTx:       return "duplicate_cm";
        case RejectReason::BadPoint:              return "bad_point";
        case RejectReason::NullifierAlreadySpent: return "nullifier_already_spent";
        case RejectReason::BadSig:                return "bad_sig";
        case RejectReason::BadProof:              return "bad_proof";
        case RejectReason::DecodeError:           return "decode_error";
        case RejectReason::Other:                 return "other";
    }
    return "other";
}

const char* verify_phase_label(VerifyPhase p) noexcept {
    switch (p) {
        case VerifyPhase::Admission: return "admission";
        case VerifyPhase::Compute:   return "compute";
    }
    return "compute";
}

// ===========================================================================
// Enum-to-reason mappers (integer-valued to avoid header-include cycles)
//
// The `VerifyResult` enum values are pinned in compute-phase.h:
//   0  Ok                       -> (n/a)
//   1  BadVersion
//   2  BadSchemeId              -> BadVersion (same class)
//   3  BadChainId               -> WrongChainId
//   4  ExpiryOutOfRange
//   5  BadSpendCount
//   6  BadOutputCount
//   7  InsufficientFee
//   8  UnknownAnchor            -> StaleAnchor
//   9  DuplicateNullifierInTx   -> DuplicateNfInTx
//  10  DuplicateCommitmentInTx  -> DuplicateCmInTx
//  11  BadRistrettoPoint        -> BadPoint
//  20  NullifierAlreadySpent
//  30  BadSpendAuthSig          -> BadSig
//  40  BadPlonky3Proof          -> BadProof
//  90  DecodeError
//
// The `AdmissionRejectReason` enum values are pinned in handlers.h:
//   0 None, 1 Malformed, 2 WrongChainId, 3 BadVersion, 4 ExpiryOutOfRange,
//   5 TooManySpends (-> BadSpendCount), 6 TooManyOutputs (-> BadOutputCount),
//   7 FeeBelowMin (-> InsufficientFee), 8 StaleAnchor, 9 DuplicateNf,
//   10 DuplicateCm, 11 BadPoint, 12 NullifierSeen (-> NullifierAlreadySpent),
//   13 BadSpendAuthSig (-> BadSig), 14 UnavailableState (-> Other).
// ===========================================================================

RejectReason reject_reason_from_verify_result(int v) noexcept {
    switch (v) {
        case 1:  return RejectReason::BadVersion;
        case 2:  return RejectReason::BadVersion;
        case 3:  return RejectReason::WrongChainId;
        case 4:  return RejectReason::ExpiryOutOfRange;
        case 5:  return RejectReason::BadSpendCount;
        case 6:  return RejectReason::BadOutputCount;
        case 7:  return RejectReason::InsufficientFee;
        case 8:  return RejectReason::StaleAnchor;
        case 9:  return RejectReason::DuplicateNfInTx;
        case 10: return RejectReason::DuplicateCmInTx;
        case 11: return RejectReason::BadPoint;
        case 20: return RejectReason::NullifierAlreadySpent;
        case 30: return RejectReason::BadSig;
        case 40: return RejectReason::BadProof;
        case 90: return RejectReason::DecodeError;
        default: return RejectReason::Other;
    }
}

RejectReason reject_reason_from_admission(int v) noexcept {
    switch (v) {
        case 1:  return RejectReason::Malformed;
        case 2:  return RejectReason::WrongChainId;
        case 3:  return RejectReason::BadVersion;
        case 4:  return RejectReason::ExpiryOutOfRange;
        case 5:  return RejectReason::BadSpendCount;
        case 6:  return RejectReason::BadOutputCount;
        case 7:  return RejectReason::InsufficientFee;
        case 8:  return RejectReason::StaleAnchor;
        case 9:  return RejectReason::DuplicateNfInTx;
        case 10: return RejectReason::DuplicateCmInTx;
        case 11: return RejectReason::BadPoint;
        case 12: return RejectReason::NullifierAlreadySpent;
        case 13: return RejectReason::BadSig;
        default: return RejectReason::Other;
    }
}

// ===========================================================================
// Histogram bucket boundaries.
//
// Verify boundaries: spans 250 µs … 10 s to cover the relaxed §9.4 envelope
// (median < 150 ms, P99 < 500 ms) with enough fidelity on either side of the
// target to detect drift. 12 buckets keep the emitted text size bounded.
//
// Apply boundaries: sub-ms dominant (pure in-memory state mutation).
//
// GCS-blob boundaries: tens of bytes … 1 MB. Under expected 1-s blocks the
// blob sits near low-kilobytes; headroom to 1 MB catches the adversarial
// filter-bloat scenario (§7.5 memory/disk note).
// ===========================================================================

namespace {

constexpr double kVerifyBoundaries[] = {
    0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.010,
    0.025,   0.050,  0.100, 0.250,  0.500, 1.000
};
constexpr size_t kVerifyBoundariesN =
    sizeof(kVerifyBoundaries) / sizeof(kVerifyBoundaries[0]);

constexpr double kApplyBoundaries[] = {
    0.00001, 0.00005, 0.0001, 0.00025, 0.0005,
    0.001,   0.0025,  0.005,  0.010,   0.025
};
constexpr size_t kApplyBoundariesN =
    sizeof(kApplyBoundaries) / sizeof(kApplyBoundaries[0]);

constexpr double kFilterBoundaries[] = {
    64,    256,    1024,   4096,   16384,
    65536, 131072, 262144, 524288, 1048576
};
constexpr size_t kFilterBoundariesN =
    sizeof(kFilterBoundaries) / sizeof(kFilterBoundaries[0]);

// ---------------------------------------------------------------------------
// CAS-based add on a uint64-bitcasted double. Lock-free on every target we
// build on (libstdc++ backs this with a CMPXCHG16B-family intrinsic on x86
// and an LL/SC loop on ARM). The `sum` of a Prometheus histogram must
// accumulate the raw observation values — counter-style integer arithmetic
// would be wrong (a 25 µs sample plus a 7.5 ms sample != integer add).
// ---------------------------------------------------------------------------
inline void atomic_add_double(std::atomic<uint64_t>& bits, double x) noexcept {
    uint64_t cur = bits.load(std::memory_order_relaxed);
    for (;;) {
        double cur_d;
        std::memcpy(&cur_d, &cur, sizeof(cur_d));
        double next_d = cur_d + x;
        uint64_t next;
        std::memcpy(&next, &next_d, sizeof(next));
        if (bits.compare_exchange_weak(cur, next,
                                       std::memory_order_acq_rel,
                                       std::memory_order_relaxed)) {
            return;
        }
    }
}

inline double atomic_load_double(const std::atomic<uint64_t>& bits) noexcept {
    uint64_t u = bits.load(std::memory_order_acquire);
    double d;
    std::memcpy(&d, &u, sizeof(d));
    return d;
}

inline uint64_t now_ns() noexcept {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

// ---------------------------------------------------------------------------
// Histogram observe helper: find the bucket whose boundary is >= x and
// increment it. Monotonic boundaries are required (enforced by construction).
// ---------------------------------------------------------------------------
inline void histogram_observe(MetricsRegistry::Histogram& h, double x) noexcept {
    size_t b = h.n_buckets;  // default = "overflow" bucket (+Inf)
    for (size_t i = 0; i < h.n_buckets; ++i) {
        if (x <= h.boundaries[i]) {
            b = i;
            break;
        }
    }
    // b is in [0, n_buckets]; we reserve slot [n_buckets] as +Inf.
    if (b < h.bucket_counts.size()) {
        h.bucket_counts[b].fetch_add(1, std::memory_order_relaxed);
    }
    h.count.fetch_add(1, std::memory_order_relaxed);
    atomic_add_double(h.sum_bits, x);
}

// ---------------------------------------------------------------------------
// Exposition-format helpers.
// ---------------------------------------------------------------------------

inline void append_u64(std::string& out, uint64_t v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%llu",
                  static_cast<unsigned long long>(v));
    out += buf;
}

inline void append_double(std::string& out, double v) {
    // Prometheus accepts either Inf or a plain decimal. We emit fixed-point
    // for human-readability at typical scales; scientific for very small /
    // very large values keeps precision.
    char buf[64];
    if (std::isinf(v))      { out += (v < 0 ? "-Inf" : "+Inf"); return; }
    if (std::isnan(v))      { out += "NaN"; return; }
    if (v == 0.0)           { out += "0"; return; }
    double absv = v < 0 ? -v : v;
    if (absv >= 1e-4 && absv < 1e12) {
        std::snprintf(buf, sizeof(buf), "%.9g", v);
    } else {
        std::snprintf(buf, sizeof(buf), "%.9e", v);
    }
    out += buf;
}

inline void emit_header(std::string& out, const char* name,
                        const char* type, const char* help) {
    out += "# HELP ";
    out += name;
    out += ' ';
    out += help;
    out += '\n';
    out += "# TYPE ";
    out += name;
    out += ' ';
    out += type;
    out += '\n';
}

inline void emit_counter(std::string& out, const char* name, uint64_t value,
                         const char* help) {
    emit_header(out, name, "counter", help);
    out += name;
    out += ' ';
    append_u64(out, value);
    out += '\n';
}

inline void emit_gauge(std::string& out, const char* name, uint64_t value,
                       const char* help) {
    emit_header(out, name, "gauge", help);
    out += name;
    out += ' ';
    append_u64(out, value);
    out += '\n';
}

// Emit all counters for a labelled family in one block (single HELP / TYPE,
// N samples differing by label value).
inline void emit_labelled_counter_family(
    std::string& out, const char* name, const char* help,
    const char* label_key,
    const std::array<std::atomic<uint64_t>, 16>& counters,
    const char* (*label_fn)(uint8_t)) {
    emit_header(out, name, "counter", help);
    for (size_t i = 0; i < counters.size(); ++i) {
        uint64_t v = counters[i].load(std::memory_order_relaxed);
        if (v == 0 && i >= 16) continue;  // never trimmed in practice
        out += name;
        out += '{';
        out += label_key;
        out += "=\"";
        out += label_fn(static_cast<uint8_t>(i));
        out += "\"} ";
        append_u64(out, v);
        out += '\n';
    }
}

// Histogram emission. Buckets are cumulative (Prometheus convention).
inline void emit_histogram(std::string& out, const char* name,
                           const char* help,
                           const std::string& extra_labels,  // e.g. phase="compute"
                           const MetricsRegistry::Histogram& h) {
    // HELP / TYPE emitted once per call. The caller groups multi-label
    // histograms by emitting the preamble once then calling this per label.
    uint64_t cumulative = 0;
    std::string bucket_labels;
    for (size_t i = 0; i < h.n_buckets; ++i) {
        cumulative += h.bucket_counts[i].load(std::memory_order_relaxed);
        out += name;
        out += "_bucket{";
        if (!extra_labels.empty()) { out += extra_labels; out += ','; }
        out += "le=\"";
        append_double(out, h.boundaries[i]);
        out += "\"} ";
        append_u64(out, cumulative);
        out += '\n';
        (void)bucket_labels;
    }
    // +Inf bucket: total count.
    uint64_t total = h.count.load(std::memory_order_relaxed);
    out += name;
    out += "_bucket{";
    if (!extra_labels.empty()) { out += extra_labels; out += ','; }
    out += "le=\"+Inf\"} ";
    append_u64(out, total);
    out += '\n';
    // _sum
    out += name;
    out += "_sum";
    if (!extra_labels.empty()) { out += '{'; out += extra_labels; out += '}'; }
    out += ' ';
    append_double(out, atomic_load_double(h.sum_bits));
    out += '\n';
    // _count
    out += name;
    out += "_count";
    if (!extra_labels.empty()) { out += '{'; out += extra_labels; out += '}'; }
    out += ' ';
    append_u64(out, total);
    out += '\n';
}

const char* reject_reason_label_from_ord(uint8_t i) noexcept {
    if (i > static_cast<uint8_t>(RejectReason::Other)) {
        return "other";
    }
    return reject_reason_label(static_cast<RejectReason>(i));
}

}  // anonymous namespace

// ===========================================================================
// MetricsRegistry
// ===========================================================================

MetricsRegistry::MetricsRegistry() {
    // Wire histogram boundaries once at construction. The pointers are
    // stable (pointing to the anonymous-namespace constexpr arrays), so
    // the renderer can read them without taking a lock.
    h_verify_admission_.n_buckets  = kVerifyBoundariesN;
    h_verify_admission_.boundaries = kVerifyBoundaries;
    h_verify_compute_.n_buckets    = kVerifyBoundariesN;
    h_verify_compute_.boundaries   = kVerifyBoundaries;
    h_apply_.n_buckets             = kApplyBoundariesN;
    h_apply_.boundaries            = kApplyBoundaries;
    h_filter_gcs_.n_buckets        = kFilterBoundariesN;
    h_filter_gcs_.boundaries       = kFilterBoundaries;
}

void MetricsRegistry::inc_transfers_admitted() noexcept {
    c_admitted_.fetch_add(1, std::memory_order_relaxed);
}
void MetricsRegistry::inc_transfers_rejected(RejectReason reason) noexcept {
    auto i = static_cast<size_t>(reason);
    if (i >= c_rejected_.size()) i = static_cast<size_t>(RejectReason::Other);
    c_rejected_[i].fetch_add(1, std::memory_order_relaxed);
}
void MetricsRegistry::inc_blocks_produced() noexcept {
    c_blocks_produced_.fetch_add(1, std::memory_order_relaxed);
}
void MetricsRegistry::inc_blocks_state_root_divergences() noexcept {
    c_state_root_divergences_.fetch_add(1, std::memory_order_relaxed);
}
void MetricsRegistry::inc_nullifier_lru_hits() noexcept {
    c_nf_lru_hits_.fetch_add(1, std::memory_order_relaxed);
}
void MetricsRegistry::inc_nullifier_lru_misses() noexcept {
    c_nf_lru_misses_.fetch_add(1, std::memory_order_relaxed);
}

void MetricsRegistry::set_anchor_window_size(uint64_t v) noexcept {
    g_anchor_window_size_.store(v, std::memory_order_relaxed);
}
void MetricsRegistry::set_commitment_tree_next_position(uint64_t v) noexcept {
    g_ct_next_position_.store(v, std::memory_order_relaxed);
}
void MetricsRegistry::set_nullifier_set_size(uint64_t v) noexcept {
    g_nf_set_size_.store(v, std::memory_order_relaxed);
}
void MetricsRegistry::set_mempool_size(uint64_t v) noexcept {
    g_mempool_size_.store(v, std::memory_order_relaxed);
}

void MetricsRegistry::observe_verify_transfer(VerifyPhase phase,
                                                double seconds) noexcept {
    if (phase == VerifyPhase::Admission) {
        histogram_observe(h_verify_admission_, seconds);
    } else {
        histogram_observe(h_verify_compute_, seconds);
    }
}
void MetricsRegistry::observe_apply_transfer(double seconds) noexcept {
    histogram_observe(h_apply_, seconds);
}
void MetricsRegistry::observe_block_filter_gcs_bytes(uint64_t bytes) noexcept {
    histogram_observe(h_filter_gcs_, static_cast<double>(bytes));
}

void MetricsRegistry::reset_for_test() noexcept {
    c_admitted_.store(0, std::memory_order_relaxed);
    c_blocks_produced_.store(0, std::memory_order_relaxed);
    c_state_root_divergences_.store(0, std::memory_order_relaxed);
    c_nf_lru_hits_.store(0, std::memory_order_relaxed);
    c_nf_lru_misses_.store(0, std::memory_order_relaxed);
    for (auto& c : c_rejected_) c.store(0, std::memory_order_relaxed);

    g_anchor_window_size_.store(0, std::memory_order_relaxed);
    g_ct_next_position_.store(0, std::memory_order_relaxed);
    g_nf_set_size_.store(0, std::memory_order_relaxed);
    g_mempool_size_.store(0, std::memory_order_relaxed);

    auto clear_hist = [](Histogram& h) {
        for (auto& b : h.bucket_counts) b.store(0, std::memory_order_relaxed);
        h.count.store(0, std::memory_order_relaxed);
        h.sum_bits.store(0, std::memory_order_relaxed);
    };
    clear_hist(h_verify_admission_);
    clear_hist(h_verify_compute_);
    clear_hist(h_apply_);
    clear_hist(h_filter_gcs_);
}

// ===========================================================================
// Renderer — Prometheus text exposition v0.0.4.
// ===========================================================================

std::string MetricsRegistry::render_prometheus() const {
    std::string out;
    out.reserve(4096);

    // Counters (scalar)
    emit_counter(out, "uno_transfers_admitted_total",
                 c_admitted_.load(std::memory_order_relaxed),
                 "Total Transfers admitted to the mempool / accepted by the compute phase.");
    emit_counter(out, "uno_blocks_produced_total",
                 c_blocks_produced_.load(std::memory_order_relaxed),
                 "Total wc=2 blocks this process has finalized (end-of-block hook fires).");
    emit_counter(out, "uno_blocks_state_root_divergences_total",
                 c_state_root_divergences_.load(std::memory_order_relaxed),
                 "Cross-validator state-root divergences observed by the local reconciliation harness (runbook §7.1 / §9.1).");
    emit_counter(out, "uno_nullifier_lru_hits_total",
                 c_nf_lru_hits_.load(std::memory_order_relaxed),
                 "Nullifier-set lookups answered from the in-memory LRU (runbook §7.3).");
    emit_counter(out, "uno_nullifier_lru_misses_total",
                 c_nf_lru_misses_.load(std::memory_order_relaxed),
                 "Nullifier-set lookups that fell through the LRU to the on-cell dictionary (runbook §7.3).");

    // Labelled counter (rejected)
    emit_labelled_counter_family(
        out, "uno_transfers_rejected_total",
        "Transfers rejected at admission or in the compute phase, labelled by reason (runbook §7.1, §7.4).",
        "reason", c_rejected_, &reject_reason_label_from_ord);

    // Gauges
    emit_gauge(out, "uno_anchor_window_size",
               g_anchor_window_size_.load(std::memory_order_relaxed),
               "Number of anchors held in the rolling anchor window (runbook §7.1; doc §5.4).");
    emit_gauge(out, "uno_commitment_tree_next_position",
               g_ct_next_position_.load(std::memory_order_relaxed),
               "Next leaf index in the note-commitment tree (equals the total number of notes ever committed; doc §5.2).");
    emit_gauge(out, "uno_nullifier_set_size",
               g_nf_set_size_.load(std::memory_order_relaxed),
               "Number of entries in the authoritative nullifier set (runbook §7.3; doc §5.3).");
    emit_gauge(out, "uno_mempool_size",
               g_mempool_size_.load(std::memory_order_relaxed),
               "Number of admitted but not-yet-included Transfers in the local mempool (runbook §7.2).");

    // Histograms — verify_transfer_seconds has two labels (admission / compute)
    emit_header(out, "uno_verify_transfer_seconds",
                "histogram",
                "Wall-clock duration of verify_transfer, by phase (runbook §7.4).");
    emit_histogram(out, "uno_verify_transfer_seconds",
                   "Wall-clock duration of verify_transfer, by phase (runbook §7.4).",
                   std::string("phase=\"admission\""),
                   h_verify_admission_);
    emit_histogram(out, "uno_verify_transfer_seconds",
                   "Wall-clock duration of verify_transfer, by phase (runbook §7.4).",
                   std::string("phase=\"compute\""),
                   h_verify_compute_);

    emit_header(out, "uno_apply_transfer_seconds",
                "histogram",
                "Wall-clock duration of apply_transfer (in-memory state mutation; runbook §7.2).");
    emit_histogram(out, "uno_apply_transfer_seconds",
                   "", std::string(), h_apply_);

    emit_header(out, "uno_block_filter_gcs_bytes",
                "histogram",
                "Per-block compact GCS filter blob size in bytes (runbook §7.2; doc §5.7).");
    emit_histogram(out, "uno_block_filter_gcs_bytes",
                   "", std::string(), h_filter_gcs_);

    return out;
}

// ===========================================================================
// Process-global registry
// ===========================================================================

MetricsRegistry& global_metrics_registry() noexcept {
    // Function-local static gives us Meyers-singleton semantics — the
    // registry is constructed on first access and never destroyed (avoids
    // the static-destruction-order fiasco if a metrics-consumer runs from
    // another TU's global dtor).
    static MetricsRegistry g_registry;
    return g_registry;
}

// ===========================================================================
// Scoped timers
// ===========================================================================

ScopedVerifyTimer::ScopedVerifyTimer(MetricsRegistry& reg,
                                      VerifyPhase phase) noexcept
    : reg_(reg), phase_(phase), start_ns_(now_ns()) {}

ScopedVerifyTimer::~ScopedVerifyTimer() {
    if (cancelled_) return;
    uint64_t end_ns = now_ns();
    double seconds = static_cast<double>(end_ns - start_ns_) / 1e9;
    reg_.observe_verify_transfer(phase_, seconds);
}

ScopedApplyTimer::ScopedApplyTimer(MetricsRegistry& reg) noexcept
    : reg_(reg), start_ns_(now_ns()) {}

ScopedApplyTimer::~ScopedApplyTimer() {
    if (cancelled_) return;
    uint64_t end_ns = now_ns();
    double seconds = static_cast<double>(end_ns - start_ns_) / 1e9;
    reg_.observe_apply_transfer(seconds);
}

}  // namespace uno_workchain
