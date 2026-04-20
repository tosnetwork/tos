/*
    Uno Workchain — NullifierSet::warm_lru() unit test (K-nullifier-warm-lru).

    Per §5.9 / §4.3 step 2 of doc/uno-workchain.md: the validator maintains
    an in-memory LRU of recently-inserted nullifiers so that the hot-path
    nullifier check is ~1 ms instead of the ~10 ms cold-cell-dict walk. On
    a cold validator start the LRU is empty; `warm_lru(k)` pre-populates
    it from the in-memory recent-insertions ring buffer so the first
    blocks after restart don't pay the cold-dict cliff.

    This test pins the semantic contract from the K-nullifier-warm-lru
    task description:

      1. `warm_lru(k)` with `N > k` pre-existing inserts MUST populate the
         LRU with the *most-recent k* insertions — not the oldest, not an
         arbitrary dict-key slice.
      2. Older entries (outside the tail-k) MUST NOT be in the LRU after
         warm-up.
      3. `warm_lru(k)` with `k >= N` warms all N entries.
      4. `warm_lru(0)` is a no-op.

    The test never touches the consensus state root — it asserts only the
    advisory LRU (via `lru_contains`), which is the surface `warm_lru`
    targets.

    Build against: uno_workchain (uno/core/nullifier-set.{h,cpp}).
*/
#include "uno/core/nullifier-set.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace {

// -- Minimal test harness (mirrors the other uno/test/* tests) ---------------

int g_passed = 0;
int g_failed = 0;

#define EXPECT_TRUE(cond, label)                                            \
    do {                                                                    \
        if (cond) {                                                         \
            ++g_passed;                                                     \
        } else {                                                            \
            ++g_failed;                                                     \
            std::fprintf(stderr,                                            \
                         "  FAIL: %s (%s:%d)\n", (label), __FILE__,         \
                         __LINE__);                                         \
        }                                                                   \
    } while (0)

#define EXPECT_FALSE(cond, label) EXPECT_TRUE(!(cond), label)

#define EXPECT_EQ(a, b, label)                                              \
    do {                                                                    \
        auto _a = (a);                                                      \
        auto _b = (b);                                                      \
        if (_a == _b) {                                                     \
            ++g_passed;                                                     \
        } else {                                                            \
            ++g_failed;                                                     \
            std::fprintf(stderr,                                            \
                         "  FAIL: %s (%s:%d): %lld != %lld\n", (label),     \
                         __FILE__, __LINE__,                                \
                         static_cast<long long>(_a),                        \
                         static_cast<long long>(_b));                       \
        }                                                                   \
    } while (0)

// -- Fixture helpers ---------------------------------------------------------

// Deterministic 32-byte nullifier from a monotonic counter. The high-order
// byte carries the low 8 bits of the counter; the rest are a padding that
// makes the byte pattern unique (no collisions inside a single test).
uno_workchain::Nullifier make_nf(std::uint64_t seq) {
    uno_workchain::Nullifier nf{};
    // Little-endian 64-bit seq in the first 8 bytes; remaining bytes form
    // a sentinel so the value survives a round-trip through the dict.
    for (int i = 0; i < 8; ++i) {
        nf[i] = static_cast<std::uint8_t>((seq >> (8 * i)) & 0xFF);
    }
    for (int i = 8; i < 32; ++i) {
        nf[i] = static_cast<std::uint8_t>(0xA0 + (i - 8));
    }
    return nf;
}

// -- Case 1 ------------------------------------------------------------------
// Insert N > k nullifiers; `warm_lru(k)` after `clear_lru()` must cover
// exactly the tail-k insertions.

void case_warm_covers_most_recent_k() {
    std::fprintf(stderr, "case: warm_lru covers most-recent k\n");
    uno_workchain::NullifierSet set;

    constexpr std::size_t N = 200;
    constexpr std::size_t K = 50;

    for (std::size_t i = 0; i < N; ++i) {
        bool inserted = set.insert(make_nf(i));
        EXPECT_TRUE(inserted, "insert should add new nullifier");
    }
    EXPECT_EQ(static_cast<long long>(set.size()),
              static_cast<long long>(N),
              "size after N inserts");

    // Drop the LRU (but KEEP the ring buffer — clear_lru() does not touch it).
    set.clear_lru();

    // All nullifiers are in the authoritative dict, but the LRU is empty.
    for (std::size_t i = 0; i < N; ++i) {
        EXPECT_FALSE(set.lru_contains(make_nf(i)),
                     "lru should be empty after clear_lru");
    }

    // Warm up.
    set.warm_lru(K);

    // Tail-k (indices [N-K, N)) MUST be in the LRU.
    for (std::size_t i = N - K; i < N; ++i) {
        EXPECT_TRUE(set.lru_contains(make_nf(i)),
                    "most-recent k nullifier present in LRU");
    }

    // Older entries (indices [0, N-K)) MUST NOT be in the LRU. Note:
    // `lru_contains` has a promote-on-hit side effect; we called it for
    // the tail-K entries above, which promoted each to front of LRU. That
    // does not affect these assertions because nothing was inserted
    // between — we're only asking whether older entries ARE present, and
    // the LRU can hold at most ~capacity entries. Our capacity is the
    // default 1'000'000, far above K, so no eviction occurred.
    for (std::size_t i = 0; i < N - K; ++i) {
        EXPECT_FALSE(set.lru_contains(make_nf(i)),
                     "older nullifier (before tail-k) absent from LRU");
    }

    std::fprintf(stderr, "  ring snapshot size = %zu\n",
                 set.warm_snapshot_size());
}

// -- Case 2 ------------------------------------------------------------------
// `k >= N` warms all entries.

void case_warm_k_exceeds_n() {
    std::fprintf(stderr, "case: warm_lru with k >= N warms everything\n");
    uno_workchain::NullifierSet set;

    constexpr std::size_t N = 37;
    for (std::size_t i = 0; i < N; ++i) {
        set.insert(make_nf(1000 + i));
    }
    set.clear_lru();

    set.warm_lru(N * 4);  // Far beyond N.

    for (std::size_t i = 0; i < N; ++i) {
        EXPECT_TRUE(set.lru_contains(make_nf(1000 + i)),
                    "all N entries warmed when k >= N");
    }
}

// -- Case 3 ------------------------------------------------------------------
// `warm_lru(0)` is a no-op.

void case_warm_zero_is_noop() {
    std::fprintf(stderr, "case: warm_lru(0) is a no-op\n");
    uno_workchain::NullifierSet set;

    for (std::size_t i = 0; i < 5; ++i) {
        set.insert(make_nf(9000 + i));
    }
    set.clear_lru();
    set.warm_lru(0);

    for (std::size_t i = 0; i < 5; ++i) {
        EXPECT_FALSE(set.lru_contains(make_nf(9000 + i)),
                     "warm_lru(0) leaves LRU empty");
    }
}

// -- Case 4 ------------------------------------------------------------------
// Warm-up on an empty NullifierSet is a no-op, not a crash.

void case_warm_on_empty_set() {
    std::fprintf(stderr, "case: warm_lru on empty set is safe\n");
    uno_workchain::NullifierSet set;

    set.warm_lru(1024);
    EXPECT_EQ(static_cast<long long>(set.size()), 0LL,
              "size unchanged by warm_lru on empty");
}

}  // namespace

int main() {
    case_warm_covers_most_recent_k();
    case_warm_k_exceeds_n();
    case_warm_zero_is_noop();
    case_warm_on_empty_set();

    std::fprintf(stderr, "\nnullifier-warm-lru: passed=%d failed=%d\n",
                 g_passed, g_failed);
    return g_failed == 0 ? 0 : 1;
}
