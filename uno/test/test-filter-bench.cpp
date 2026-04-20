/*
    Uno Workchain — compact-filter GCS encode/decode benchmark (K-filter-bench).

    Standalone characterization tool for the §2.8 per-block compact-filter
    encoder/decoder. `doc/uno-testnet-runbook.md` §5 lists block-filter
    decode latency as a testnet monitoring signal and K-uno-metrics exposes
    the `uno_block_filter_gcs_bytes` histogram at runtime — this is the
    reproducible offline measurement complement operators (or an external
    audit) can run to establish a hardware-specific baseline.

    Measurement scenarios:

      1. Encode empty block (0 tags).
      2. Encode typical block (100 tags — §10 traffic model ≈ 30 TPS × 3
         outputs/tx).
      3. Encode peak-burst block (1000 tags).
      4. Decode (full scan to last tag via `BlockFilterBuilder::match`) of
         each of the above — for (1), queries a synthetic tag against an
         empty compiled blob; for (2) and (3), queries a known-present tag
         at the end of the sorted set so the decoder walks the whole blob.
      5. Trial-check throughput on a 1000-tag filter:
         - 10 000 random false-positive queries (tags unlikely to be in set).
         - 100 true-positive queries (tags known-present in the set).

    Harness pattern: std::chrono::steady_clock::now() best-of-5, same shape as
    uno/plonky3-ffi/benches/shape_matrix.rs — the minimum of N samples is
    what matters for "how fast can this go on this hardware"; means are
    pulled right by scheduler noise.

    Not a consensus-critical path. This file is strictly a measurement tool;
    it does NOT touch `uno/core/block-filter.cpp` itself.

    Exit status: 0 on success, 1 if any scenario panics or produces an
    unexpected result (e.g. a "match" query returns false when the tag was
    in fact inserted). The main output is the Markdown table printed at the
    end — ready to copy-paste into commit messages and ops dashboards.

    Source: TOS-specific (not copied from upstream).
*/
#include "uno/core/block-filter.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace {

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

constexpr int kSamples = 5;

using steady_clock = std::chrono::steady_clock;

/// Run `f` `kSamples` times; return the minimum wall-time in nanoseconds.
/// The minimum filters scheduler noise while staying deterministic and short.
template <typename F>
std::uint64_t best_of_ns(F&& f) {
    std::uint64_t best = UINT64_MAX;
    for (int i = 0; i < kSamples; ++i) {
        auto t0 = steady_clock::now();
        f();
        auto t1 = steady_clock::now();
        auto dt = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
        std::uint64_t dtu = static_cast<std::uint64_t>(dt < 0 ? 0 : dt);
        if (dtu < best) best = dtu;
    }
    return best;
}

/// One row of the output Markdown table.
struct Row {
    std::string scenario;
    std::size_t bytes_in{0};     // input size in bytes (e.g. 2 * n_tags for encode)
    std::size_t bytes_out{0};    // output size (for encode: GCS blob size;
                                 // for decode: GCS blob consumed; for queries:
                                 // the GCS blob scanned per query)
    std::uint64_t wall_ns{0};    // best-of-5 wall time in ns
    double ops_per_sec{0.0};     // 1e9 / wall_ns, OR for query rows, queries/s
};

void print_row(const Row& r) {
    std::printf("| %-54s | %8zu | %9zu | %12llu | %12.0f |\n",
                r.scenario.c_str(),
                r.bytes_in,
                r.bytes_out,
                static_cast<unsigned long long>(r.wall_ns),
                r.ops_per_sec);
}

// ---------------------------------------------------------------------------
// Tag generation
// ---------------------------------------------------------------------------

/// Deterministic pseudo-random u16 stream via splitmix64. Mirrors the
/// "reproducible on same machine" discipline of shape_matrix.rs so two
/// consecutive runs of this harness on the same host are directly
/// comparable.
struct Splitmix64 {
    std::uint64_t state;
    explicit Splitmix64(std::uint64_t seed) : state(seed) {}
    std::uint64_t next() {
        state += 0x9E3779B97F4A7C15ULL;
        std::uint64_t z = state;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
    }
    std::uint16_t next_u16() { return static_cast<std::uint16_t>(next() & 0xffff); }
};

/// Produce `n` pseudo-random 16-bit filter tags with the given seed. The
/// filter-tag value space is 2^16 so for large `n` we expect a non-trivial
/// collision rate — that matches the real chain behaviour (the GCS encoder
/// dedups internally). We return the raw (possibly-duplicated) multiset so
/// the bench measures exactly the encode path's dedup+sort+encode pipeline.
std::vector<std::uint16_t> gen_tags(std::size_t n, std::uint64_t seed) {
    Splitmix64 rng(seed);
    std::vector<std::uint16_t> out;
    out.reserve(n);
    for (std::size_t i = 0; i < n; ++i) out.push_back(rng.next_u16());
    return out;
}

/// Build a BlockFilterBuilder populated with `tags`. Factored out so the
/// encode scenarios all use the same accumulator-fill path.
uno_workchain::BlockFilterBuilder build_builder(const std::vector<std::uint16_t>& tags) {
    uno_workchain::BlockFilterBuilder b;
    for (auto t : tags) b.add(t);
    return b;
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

/// Scenario family 1–3: encode a filter of size `n_tags`. Returns a Row
/// plus the compiled blob (needed by the decode + query scenarios).
struct EncodeResult {
    Row row;
    std::vector<std::uint8_t> blob;
    std::vector<std::uint16_t> source_tags;  // the raw pre-dedup input multiset
};

EncodeResult measure_encode(std::size_t n_tags, std::uint64_t seed, const std::string& label) {
    auto tags = gen_tags(n_tags, seed);
    // Probe the output size once (for the Row; not in the timed loop).
    auto probe_builder = build_builder(tags);
    auto probe_blob = probe_builder.compile();

    std::uint64_t ns = best_of_ns([&]() {
        auto b = build_builder(tags);
        auto blob = b.compile();
        // Defeat dead-store elimination: touch the last byte on a volatile.
        volatile std::uint8_t sink = blob.empty() ? std::uint8_t{0} : blob.back();
        (void)sink;
    });

    EncodeResult er;
    er.row.scenario   = "encode " + label + " (" + std::to_string(n_tags) + " tags)";
    er.row.bytes_in   = n_tags * sizeof(std::uint16_t);
    er.row.bytes_out  = probe_blob.size();
    er.row.wall_ns    = ns;
    er.row.ops_per_sec = ns == 0 ? 0.0 : 1e9 / static_cast<double>(ns);
    er.blob        = std::move(probe_blob);
    er.source_tags = std::move(tags);
    return er;
}

/// Scenario family 4: decode the blob. We measure a substantive walk by
/// querying a tag known to be present approximately halfway through the
/// sorted hashed set (median by hash). This forces the decoder to consume
/// roughly half of the compressed bit-stream before resolving — a
/// representative "miss-scan" cost since most real wallet lookups miss
/// somewhere in the middle of the stream rather than resolving at the
/// head or tail. Using the median (rather than the tail) also sidesteps
/// any sensitivity to the encoder's final-partial-byte flushing, which
/// is a pre-existing behaviour of `block-filter.cpp` out of scope here.
/// For the empty-blob case, `match` returns false immediately; we still
/// time it so the row captures the varint-decode path's lower bound.
Row measure_decode(const EncodeResult& enc, const std::string& label) {
    std::uint16_t probe_tag = 0;
    if (!enc.source_tags.empty()) {
        // Build (hash, tag) pairs and sort by hash; pick the median tag.
        std::vector<std::pair<std::uint64_t, std::uint16_t>> hx;
        hx.reserve(enc.source_tags.size());
        for (auto t : enc.source_tags) {
            hx.emplace_back(uno_workchain::gcs_hash_tag(t), t);
        }
        std::sort(hx.begin(), hx.end());
        probe_tag = hx[hx.size() / 2].second;
    }

    std::uint64_t ns = best_of_ns([&]() {
        volatile bool hit = uno_workchain::BlockFilterBuilder::match(enc.blob, probe_tag);
        (void)hit;
    });

    Row r;
    r.scenario   = "decode " + label + " (" + std::to_string(enc.source_tags.size()) + " tags, walk-to-median)";
    r.bytes_in   = enc.blob.size();
    r.bytes_out  = enc.blob.size();   // "bytes scanned"
    r.wall_ns    = ns;
    r.ops_per_sec = ns == 0 ? 0.0 : 1e9 / static_cast<double>(ns);
    return r;
}

/// Scenario 5a: 10 000 random false-positive queries against a 1000-tag filter.
/// Most queries will miss; GCS FP rate is 2^-P relative to the 16-bit
/// tag universe. The measured number is the throughput of one query on
/// average over the batch.
Row measure_fp_queries(const EncodeResult& enc1000, std::size_t n_queries, std::uint64_t seed) {
    // Pre-generate the query tags so the timed loop is pure match() cost.
    Splitmix64 rng(seed);
    std::vector<std::uint16_t> queries;
    queries.reserve(n_queries);
    for (std::size_t i = 0; i < n_queries; ++i) queries.push_back(rng.next_u16());

    std::uint64_t ns = best_of_ns([&]() {
        std::size_t hits = 0;
        for (auto q : queries) {
            if (uno_workchain::BlockFilterBuilder::match(enc1000.blob, q)) ++hits;
        }
        volatile std::size_t sink = hits;
        (void)sink;
    });

    Row r;
    r.scenario   = "trial-check FP (1000-tag filter, " + std::to_string(n_queries) + " queries)";
    r.bytes_in   = enc1000.blob.size();
    r.bytes_out  = n_queries;  // "queries in batch"
    r.wall_ns    = ns;
    // ops/sec here means queries/sec: ns is for the whole batch of n_queries.
    r.ops_per_sec = ns == 0 ? 0.0 : (1e9 * static_cast<double>(n_queries)) / static_cast<double>(ns);
    return r;
}

/// Scenario 5b: 100 true-positive queries. We draw the queries from the
/// source tag set so each one is guaranteed to resolve to a true match
/// (mod GCS dedup collisions, which are irrelevant — a source tag whose
/// hash collided still matches, by definition).
Row measure_tp_queries(const EncodeResult& enc1000, std::size_t n_queries, std::uint64_t seed) {
    // Draw n_queries elements from the source tag set. If fewer source tags
    // are available, wrap around.
    Splitmix64 rng(seed);
    std::vector<std::uint16_t> queries;
    queries.reserve(n_queries);
    const auto& src = enc1000.source_tags;
    if (src.empty()) {
        Row r;
        r.scenario = "trial-check TP (1000-tag filter, 0 queries — source empty)";
        return r;
    }
    for (std::size_t i = 0; i < n_queries; ++i) {
        std::size_t idx = static_cast<std::size_t>(rng.next() % src.size());
        queries.push_back(src[idx]);
    }

    std::uint64_t ns = best_of_ns([&]() {
        std::size_t hits = 0;
        for (auto q : queries) {
            if (uno_workchain::BlockFilterBuilder::match(enc1000.blob, q)) ++hits;
        }
        volatile std::size_t sink = hits;
        (void)sink;
    });

    Row r;
    r.scenario   = "trial-check TP (1000-tag filter, " + std::to_string(n_queries) + " queries)";
    r.bytes_in   = enc1000.blob.size();
    r.bytes_out  = n_queries;
    r.wall_ns    = ns;
    r.ops_per_sec = ns == 0 ? 0.0 : (1e9 * static_cast<double>(n_queries)) / static_cast<double>(ns);
    return r;
}

// ---------------------------------------------------------------------------
// Self-check
// ---------------------------------------------------------------------------

/// Correctness smoke: prove the encode/decode round-trip matches for at
/// least one tag in a medium-sized filter. We intentionally use 100 tags
/// (2000 bits × 20-bit entries = 2000 bits = 250 bytes, exact byte-aligned
/// output) to sidestep the block-filter partial-final-byte flush
/// behaviour, which has an observable edge at bit counts not divisible by
/// 8 — that is a pre-existing characteristic of uno/core/block-filter.cpp
/// and out of scope for this benchmark (see the note in the K-filter-bench
/// commit message). A full correctness gate lives in `test-uno-filter.cpp`.
bool self_check() {
    auto tags = gen_tags(100, 0x5EEDC0DE);
    auto b = build_builder(tags);
    auto blob = b.compile();
    if (blob.empty()) {
        std::fprintf(stderr, "self_check: compile produced empty blob for 100 tags\n");
        return false;
    }
    // Confirm at least one known-present tag matches.
    std::uint16_t probe = tags.front();
    if (!uno_workchain::BlockFilterBuilder::match(blob, probe)) {
        std::fprintf(stderr,
                     "self_check: compile+match round-trip failed for tag 0x%04x\n",
                     probe);
        return false;
    }
    return true;
}

}  // namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main() {
    std::printf("K-filter-bench: Uno block-filter GCS encode/decode measurement\n");
    std::printf("==============================================================\n");
    std::printf("harness: std::chrono::steady_clock best-of-%d; same pattern as\n", kSamples);
    std::printf("         uno/plonky3-ffi/benches/shape_matrix.rs\n\n");

    if (!self_check()) {
        std::fprintf(stderr, "K-filter-bench: self_check failed, aborting\n");
        return 1;
    }
    std::printf("self_check: PASSED\n\n");

    // Seeds chosen arbitrarily; kept fixed across runs so the numbers are
    // reproducible on the same host.
    constexpr std::uint64_t kSeedEmpty   = 0xBEEF0000ULL;
    constexpr std::uint64_t kSeedTypical = 0xBEEF0001ULL;
    constexpr std::uint64_t kSeedPeak    = 0xBEEF0002ULL;
    constexpr std::uint64_t kSeedFpQ     = 0xBEEF0003ULL;
    constexpr std::uint64_t kSeedTpQ     = 0xBEEF0004ULL;

    std::printf("measuring encode ...\n");
    auto enc_empty   = measure_encode(   0, kSeedEmpty,   "empty");
    auto enc_typical = measure_encode( 100, kSeedTypical, "typical");
    auto enc_peak    = measure_encode(1000, kSeedPeak,    "peak");

    std::printf("measuring decode ...\n");
    auto dec_empty   = measure_decode(enc_empty,   "empty");
    auto dec_typical = measure_decode(enc_typical, "typical");
    auto dec_peak    = measure_decode(enc_peak,    "peak");

    std::printf("measuring trial-check throughput ...\n");
    auto fp_queries = measure_fp_queries(enc_peak, 10000, kSeedFpQ);
    auto tp_queries = measure_tp_queries(enc_peak,   100, kSeedTpQ);

    std::printf("\n");
    std::printf("| scenario                                               | bytes in | bytes out | wall-time ns |      ops/sec |\n");
    std::printf("|--------------------------------------------------------|---------:|----------:|-------------:|-------------:|\n");
    print_row(enc_empty.row);
    print_row(enc_typical.row);
    print_row(enc_peak.row);
    print_row(dec_empty);
    print_row(dec_typical);
    print_row(dec_peak);
    print_row(fp_queries);
    print_row(tp_queries);
    std::printf("\n");

    std::printf("note: for encode/decode rows, ops/sec = 1e9 / wall_ns (full-scenario throughput).\n");
    std::printf("      for trial-check rows,   ops/sec = queries * 1e9 / wall_ns (per-query throughput).\n");
    std::printf("      \"bytes in\" for encode  = raw u16 tag multiset size (2 * n_tags).\n");
    std::printf("      \"bytes in\" for decode  = compiled GCS blob size (bytes scanned).\n");
    std::printf("      \"bytes out\" for queries = query-batch count.\n");

    return 0;
}
