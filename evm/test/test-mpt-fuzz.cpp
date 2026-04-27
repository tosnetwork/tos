/*
    EVM Workchain — randomized MPT / witness fuzz target.

    Pre-public-exposure fuzz coverage required by the security review for the
    fail-closed `_safe` API surface of the persisted Ethereum MPT witness:

        MptTrie::load_from_cell(Shallow / StrictRecursive)
        MptTrie::proof_safe
        MptTrie::value_at_hashed_safe
        MptTrie::root_hash_safe
        MptTrie::upsert_hashed_safe
        MptTrie::erase_hashed_safe
        CellEvmState::load_trie_witness_from_cell(TrustedShallow)
        CellEvmState::ethereum_storage_root_hash_safe_no_cache

    The hand-crafted regression tests in `test-executor.cpp` exercise specific
    known attack shapes (tampered cached RLP, branch with substituted child,
    truncated payload). This binary complements those by feeding randomly
    generated cells / byte streams into every listed entry point. The contract
    under fuzz is:

      (a) NO crash. No segfault, no SIGABRT, no assert(), no CHECK abort.
      (b) NO C++ exception leaks past the API boundary. Every API is documented
          to either return `bool false` / `td::Status::Error` / a canonical
          empty result on rejection, never to throw.
      (c) Outcomes partition cleanly: every iteration is either `rejected`
          (fail-closed) or `accepted` (legitimate parse of an
          accidentally-valid byte stream). No third "diverged / undefined"
          bucket.

    Determinism. A fixed list of 64-bit seeds drives a portable Mulberry32-
    style PRNG (NOT std::mt19937, whose output differs across libstdc++ and
    libc++). When CI surfaces a failing iteration, the printout includes the
    driver name, seed, and 0-based iteration index — that triple uniquely
    reproduces the offending cell on any host.

    Build target: test-mpt-fuzz (see evm/test/CMakeLists.txt).
*/

#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <optional>
#include <string>
#include <vector>

#include <evmc/evmc.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/empty_hashes.hpp>

#include "evm/core/cell-state.h"
#include "evm/core/mpt-trie.h"

#include "td/utils/Slice.h"
#include "td/utils/Status.h"

#include "vm/cells/Cell.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellTraits.h"

namespace ew = evm_workchain;

// ---------------------------------------------------------------------------
// Tracked-printf harness.
//
// Mirrors the convention used by `test-evm-compute-purity.cpp` so a single
// `g_failures` counter drives the binary's exit code. The fuzz drivers do
// NOT use the harness for per-iteration outcomes — they aggregate counts
// in their own struct and emit a one-line PASSED / FAILED at the end.
// ---------------------------------------------------------------------------

static std::atomic<int> g_failures{0};

static int tracked_printf(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    va_list copy;
    va_copy(copy, args);
    int needed = std::vsnprintf(nullptr, 0, fmt, copy);
    va_end(copy);
    std::string rendered;
    if (needed >= 0) {
        rendered.resize(static_cast<size_t>(needed) + 1);
        va_copy(copy, args);
        std::vsnprintf(rendered.data(), rendered.size(), fmt, copy);
        va_end(copy);
        rendered.resize(static_cast<size_t>(needed));
    }
    int written = std::vprintf(fmt, args);
    va_end(args);
    if (!rendered.empty() &&
        rendered.find("FAILED") != std::string::npos) {
        g_failures.fetch_add(1);
    }
    return written;
}
#define tprintf tracked_printf

// ---------------------------------------------------------------------------
// Deterministic PRNG.
//
// Mulberry32 over a 64-bit state. Same algorithm on every host; a fuzz hit
// reproduces from (seed, iteration_index) without needing the host's STL
// RNG implementation.
// ---------------------------------------------------------------------------

namespace {

class DeterministicRng {
  public:
    explicit DeterministicRng(uint64_t seed) noexcept
        : state_(seed != 0 ? seed : 0xCAFEBABEull) {}

    uint32_t next32() noexcept {
        // Mulberry32: tiny PRNG with good statistical properties for
        // fuzzing-grade randomness. NOT cryptographic, intentionally so —
        // we want speed, determinism, and portability.
        state_ += 0x6D2B79F5ull;
        uint64_t z = state_;
        z = (z ^ (z >> 15)) * (z | 1ull);
        z ^= z + (z ^ (z >> 7)) * (z | 61ull);
        return static_cast<uint32_t>(z ^ (z >> 14));
    }

    uint64_t next64() noexcept {
        uint64_t hi = next32();
        uint64_t lo = next32();
        return (hi << 32) | lo;
    }

    uint8_t next_byte() noexcept {
        return static_cast<uint8_t>(next32() & 0xFFu);
    }

    bool next_bool() noexcept { return (next32() & 1u) != 0; }

    /// Uniform integer in [lo, hi]. Saturates if hi < lo.
    size_t next_range(size_t lo, size_t hi) noexcept {
        if (hi <= lo) return lo;
        const size_t span = hi - lo + 1;
        return lo + (static_cast<size_t>(next64()) % span);
    }

    std::vector<uint8_t> next_bytes(size_t min_len, size_t max_len) {
        size_t len = next_range(min_len, max_len);
        std::vector<uint8_t> out;
        out.resize(len);
        for (size_t i = 0; i < len; ++i) {
            out[i] = next_byte();
        }
        return out;
    }

  private:
    uint64_t state_;
};

}  // namespace

// ---------------------------------------------------------------------------
// Random cell construction.
//
// The fuzz drivers need to hand random cells to the API surfaces. We build
// a small DAG of randomly-shaped cells. vm::Cell refs are immutable
// reference-counted, so genuine cycles are structurally impossible — the
// "cyclic-like" coverage requirement is met by feeding RLP shapes that
// LOOK like they could nest infinitely (e.g. a leaf claiming a 100 MiB
// value) and confirming the API path-budget caps the descent.
// ---------------------------------------------------------------------------

namespace {

constexpr unsigned kCellMaxBits = vm::Cell::max_bits;   // 1023
constexpr unsigned kCellMaxRefs = vm::Cell::max_refs;   // 4

td::Ref<vm::Cell> finalize_safe(vm::CellBuilder& cb, bool special = false) {
    // CellBuilder::finalize() throws CellWriteError on overflow; we use the
    // nothrow form so the fuzzer never leaks an exception via construction
    // logic. A null return signals "could not build that shape" — we then
    // try a different shape.
    auto res = cb.finalize_novm_nothrow(special);
    if (res.is_error()) {
        return {};
    }
    return res.move_as_ok();
}

td::Ref<vm::Cell> build_random_leaf_cell(DeterministicRng& rng);
td::Ref<vm::Cell> build_random_cell(DeterministicRng& rng, int depth_budget);

/// Build an empty cell (0 bits, 0 refs). Edge case: minimal cell.
td::Ref<vm::Cell> build_empty_cell() {
    vm::CellBuilder cb;
    return finalize_safe(cb);
}

/// Build a cell with bits at the cap (1023) and 0 refs. Edge case: oversized
/// data payload.
td::Ref<vm::Cell> build_max_data_cell(DeterministicRng& rng) {
    vm::CellBuilder cb;
    // Fill close to capacity in 8-bit chunks; remainder as bits.
    const unsigned target_bits = kCellMaxBits;
    unsigned written = 0;
    while (written + 8 <= target_bits) {
        cb.store_long(rng.next_byte(), 8);
        written += 8;
    }
    while (written < target_bits) {
        cb.store_long(rng.next32() & 1u, 1);
        ++written;
    }
    return finalize_safe(cb);
}

/// Build a "special" cell. The CellBuilder allows the special flag to be set
/// on any byte payload — the deserializer must reject it on every fail-closed
/// path that classifies special cells as malformed witness input.
td::Ref<vm::Cell> build_special_cell(DeterministicRng& rng) {
    vm::CellBuilder cb;
    // Tag byte indicates one of the SpecialType values, but we deliberately
    // emit garbage tags too.
    uint8_t tag = static_cast<uint8_t>(rng.next32() % 6u);  // 0..5
    cb.store_long(tag, 8);
    // Random body up to 32 bytes.
    auto body = rng.next_bytes(0, 32);
    for (uint8_t b : body) cb.store_long(b, 8);
    return finalize_safe(cb, /*special=*/true);
}

/// Build a leaf-like cell using the MPT node serialization layout:
///   2 bits kind=0 (leaf) | 7 bits path length | path nibbles | rlp ref | value ref
/// All sub-fields are randomized, including pathological lengths that exceed
/// the MPT spec.
td::Ref<vm::Cell> build_random_leaf_cell(DeterministicRng& rng) {
    vm::CellBuilder cb;
    cb.store_long(0, 2);  // kind = leaf
    // Path length: legal range is 0..64 nibbles, but we deliberately push
    // beyond to exercise the validator's bound checks.
    unsigned path_len = static_cast<unsigned>(rng.next_range(0, 96));
    if (path_len > 127) path_len = 127;  // 7-bit field
    cb.store_long(path_len, 7);
    // Cell can only hold ~1014 bits of data on top of the kind+len header,
    // so cap the actual path-bit emission at the cell capacity.
    const unsigned remaining = kCellMaxBits - 2 - 7;
    unsigned nibble_bits = path_len * 4;
    if (nibble_bits > remaining) nibble_bits = remaining & ~3u;
    unsigned emitted = 0;
    while (emitted + 4 <= nibble_bits) {
        cb.store_long(rng.next32() & 0xFu, 4);
        emitted += 4;
    }
    // Rlp ref: a random byte payload wrapped in a child cell.
    {
        vm::CellBuilder rlp_cb;
        auto rlp_bytes = rng.next_bytes(0, 64);
        for (uint8_t b : rlp_bytes) rlp_cb.store_long(b, 8);
        auto rlp_cell = finalize_safe(rlp_cb);
        if (rlp_cell.not_null()) cb.store_ref(rlp_cell);
    }
    // Value ref: same pattern.
    if (rng.next_bool()) {
        vm::CellBuilder val_cb;
        auto val_bytes = rng.next_bytes(0, 64);
        for (uint8_t b : val_bytes) val_cb.store_long(b, 8);
        auto val_cell = finalize_safe(val_cb);
        if (val_cell.not_null()) cb.store_ref(val_cell);
    }
    return finalize_safe(cb);
}

/// Build an extension-like cell:
///   2 bits kind=1 | 7 bits path length | path nibbles | rlp ref | child ref
td::Ref<vm::Cell> build_random_extension_cell(DeterministicRng& rng,
                                                int depth_budget) {
    vm::CellBuilder cb;
    cb.store_long(1, 2);  // kind = extension
    unsigned path_len = static_cast<unsigned>(rng.next_range(0, 96));
    if (path_len > 127) path_len = 127;
    cb.store_long(path_len, 7);
    const unsigned remaining = kCellMaxBits - 2 - 7;
    unsigned nibble_bits = path_len * 4;
    if (nibble_bits > remaining) nibble_bits = remaining & ~3u;
    unsigned emitted = 0;
    while (emitted + 4 <= nibble_bits) {
        cb.store_long(rng.next32() & 0xFu, 4);
        emitted += 4;
    }
    {
        vm::CellBuilder rlp_cb;
        auto rlp_bytes = rng.next_bytes(0, 64);
        for (uint8_t b : rlp_bytes) rlp_cb.store_long(b, 8);
        auto rlp_cell = finalize_safe(rlp_cb);
        if (rlp_cell.not_null()) cb.store_ref(rlp_cell);
    }
    if (depth_budget > 0 && rng.next_bool()) {
        auto child = build_random_cell(rng, depth_budget - 1);
        if (child.not_null()) cb.store_ref(child);
    }
    return finalize_safe(cb);
}

/// Build a branch-like cell:
///   2 bits kind=2 | rlp ref | dict ref (the branch dict ref is used by the
///   real MPT serializer; we just feed garbage)
td::Ref<vm::Cell> build_random_branch_cell(DeterministicRng& rng,
                                             int depth_budget) {
    vm::CellBuilder cb;
    cb.store_long(2, 2);  // kind = branch
    {
        vm::CellBuilder rlp_cb;
        auto rlp_bytes = rng.next_bytes(0, 32);
        for (uint8_t b : rlp_bytes) rlp_cb.store_long(b, 8);
        auto rlp_cell = finalize_safe(rlp_cb);
        if (rlp_cell.not_null()) cb.store_ref(rlp_cell);
    }
    if (depth_budget > 0 && rng.next_bool()) {
        auto dict_like = build_random_cell(rng, depth_budget - 1);
        if (dict_like.not_null()) cb.store_ref(dict_like);
    }
    return finalize_safe(cb);
}

/// Build a cell with a deliberately malformed kind tag (3) — the strict
/// validator must reject this immediately.
td::Ref<vm::Cell> build_invalid_kind_cell(DeterministicRng& rng) {
    vm::CellBuilder cb;
    cb.store_long(3, 2);  // kind = reserved/invalid
    auto body = rng.next_bytes(0, 16);
    for (uint8_t b : body) cb.store_long(b, 8);
    return finalize_safe(cb);
}

/// Build a truncated leaf — kind+len header but missing refs. The deserializer
/// must reject when `size_refs() < required`.
td::Ref<vm::Cell> build_truncated_leaf(DeterministicRng& rng) {
    vm::CellBuilder cb;
    cb.store_long(0, 2);
    cb.store_long(static_cast<unsigned>(rng.next_range(0, 64)), 7);
    // No path nibbles, no refs.
    return finalize_safe(cb);
}

/// Top-level random cell dispatcher. Each call picks a shape uniformly at
/// random; depth_budget bounds the DAG so large fuzz iters do not balloon
/// memory.
td::Ref<vm::Cell> build_random_cell(DeterministicRng& rng, int depth_budget) {
    if (depth_budget <= 0) {
        return build_empty_cell();
    }
    uint32_t shape = rng.next32() % 9u;
    switch (shape) {
        case 0: return build_empty_cell();
        case 1: return build_max_data_cell(rng);
        case 2: return build_special_cell(rng);
        case 3: return build_random_leaf_cell(rng);
        case 4: return build_random_extension_cell(rng, depth_budget);
        case 5: return build_random_branch_cell(rng, depth_budget);
        case 6: return build_invalid_kind_cell(rng);
        case 7: return build_truncated_leaf(rng);
        default: {
            // Pure-random: grab a random byte payload and stash it in a flat
            // cell. Probability mass on this branch covers byte streams the
            // structural shape generators would never emit (e.g. weird bit
            // alignment).
            vm::CellBuilder cb;
            unsigned target_bits =
                static_cast<unsigned>(rng.next_range(0, kCellMaxBits));
            while (target_bits >= 8) {
                cb.store_long(rng.next_byte(), 8);
                target_bits -= 8;
            }
            while (target_bits-- > 0) {
                cb.store_long(rng.next32() & 1u, 1);
            }
            // 0..3 random refs.
            unsigned refs = static_cast<unsigned>(rng.next_range(0, kCellMaxRefs));
            for (unsigned i = 0; i < refs; ++i) {
                auto child = build_random_cell(rng, depth_budget - 1);
                if (child.not_null()) cb.store_ref(child);
            }
            return finalize_safe(cb);
        }
    }
}

/// Build a witness-shaped cell: header (24-bit magic + 8-bit version + 2 bits
/// for has_account/has_storage flags) + optional refs. We randomize all
/// fields including the magic so the fuzzer covers both "valid header but
/// garbage account-trie ref" and "invalid magic" paths.
td::Ref<vm::Cell> build_random_witness_cell(DeterministicRng& rng) {
    vm::CellBuilder cb;
    // Magic: occasionally use the canonical "TRI" so the parser progresses
    // past the header check.
    uint64_t magic = rng.next_bool() ? 0x545249ull : (rng.next64() & 0xFFFFFFull);
    cb.store_long(magic, 24);
    uint64_t version = rng.next_bool() ? 1ull : (rng.next32() & 0xFFu);
    cb.store_long(version, 8);
    bool has_account = rng.next_bool();
    bool has_storage = rng.next_bool();
    cb.store_long(has_account ? 1 : 0, 1);
    cb.store_long(has_storage ? 1 : 0, 1);
    if (has_account) {
        auto account_trie = build_random_cell(rng, 4);
        if (account_trie.not_null()) cb.store_ref(account_trie);
    }
    if (has_storage) {
        auto storage_index = build_random_cell(rng, 4);
        if (storage_index.not_null()) cb.store_ref(storage_index);
    }
    return finalize_safe(cb);
}

}  // namespace

// ---------------------------------------------------------------------------
// Per-driver outcome aggregation.
// ---------------------------------------------------------------------------

namespace {

struct DriverStats {
    const char* name;
    uint64_t seed;
    size_t iters;
    size_t accepted{0};
    size_t rejected{0};
    size_t exceptions{0};        // must always remain 0
    long long first_failing_iter{-1};
    std::string first_failing_what;
};

void print_driver_summary(const DriverStats& s) {
    tprintf("=== %s (seed=0x%llx, iters=%zu) ===\n",
            s.name, static_cast<unsigned long long>(s.seed), s.iters);
    tprintf("  rejected:      %zu\n", s.rejected);
    tprintf("  accepted:      %zu\n", s.accepted);
    tprintf("  exceptions:    %zu\n", s.exceptions);
    bool ok = (s.exceptions == 0) &&
              ((s.accepted + s.rejected) == s.iters) &&
              (s.first_failing_iter < 0);
    if (!ok) {
        tprintf("  FIRST FAIL @ iter=%lld: %s\n",
                s.first_failing_iter,
                s.first_failing_what.empty()
                    ? "<unknown>" : s.first_failing_what.c_str());
    }
    tprintf("  no crashes:    %s\n\n", ok ? "PASSED" : "FAILED");
}

/// Wrap an API call so any thrown exception (which would already be a
/// breach of the API's noexcept-ish contract) is captured into the stats
/// object and never propagates out of the fuzz loop. The `op` lambda must
/// return `true` on a clean accept and `false` on a clean reject; an
/// exception falls into the "exceptions" bucket and registers a failure.
template <class Op>
void run_one(DriverStats& s, size_t iter, Op&& op) {
    try {
        bool accepted = op();
        if (accepted) ++s.accepted; else ++s.rejected;
    } catch (const std::exception& e) {
        ++s.exceptions;
        if (s.first_failing_iter < 0) {
            s.first_failing_iter = static_cast<long long>(iter);
            s.first_failing_what = std::string("std::exception: ") + e.what();
        }
    } catch (...) {
        ++s.exceptions;
        if (s.first_failing_iter < 0) {
            s.first_failing_iter = static_cast<long long>(iter);
            s.first_failing_what = "non-std exception leaked";
        }
    }
}

}  // namespace

// ---------------------------------------------------------------------------
// Fuzz drivers.
//
// Each driver targets one entry point in the security review's API list. The
// loop body:
//   1. Builds a random input via the cell generators.
//   2. Wraps the API call in `run_one` so any exception is recorded.
//   3. Classifies the outcome as `accepted` / `rejected`. Both are legal —
//      the fuzz contract is "no crash, no exception, no CHECK abort".
// ---------------------------------------------------------------------------

namespace {

/// Build a small canonical 1-key trie so we can run mutation/proof drivers
/// on a non-empty starting state. Returns the trie and the keccak-hashed key
/// the caller can drive inputs against.
struct CanonicalTrie {
    ew::MptTrie trie;
    evmc::bytes32 hashed_key;
};

CanonicalTrie make_canonical_trie() {
    CanonicalTrie ct;
    evmc::bytes32 raw{};
    raw.bytes[31] = 0x42;
    ct.hashed_key = ew::keccak_bytes32_value(raw);
    silkworm::Bytes value{0x82, 0x00, 0x01};
    (void)ct.trie.upsert_hashed(silkworm::ByteView{ct.hashed_key.bytes, 32},
                                 silkworm::ByteView{value});
    return ct;
}

void fuzz_mpt_load_from_cell_shallow(DriverStats& s) {
    DeterministicRng rng(s.seed);
    for (size_t i = 0; i < s.iters; ++i) {
        run_one(s, i, [&]() {
            auto cell = build_random_cell(rng, /*depth_budget=*/4);
            ew::MptTrie trie;
            if (cell.is_null()) {
                // Null cell is documented as "empty trie" — accept.
                bool ok = trie.load_from_cell(
                    cell, ew::MptWitnessValidationMode::Shallow);
                return ok;
            }
            return trie.load_from_cell(
                cell, ew::MptWitnessValidationMode::Shallow);
        });
    }
}

void fuzz_mpt_load_from_cell_strict(DriverStats& s) {
    DeterministicRng rng(s.seed);
    for (size_t i = 0; i < s.iters; ++i) {
        run_one(s, i, [&]() {
            auto cell = build_random_cell(rng, /*depth_budget=*/4);
            ew::MptTrie trie;
            return trie.load_from_cell(
                cell, ew::MptWitnessValidationMode::StrictRecursive);
        });
    }
}

void fuzz_mpt_proof_safe(DriverStats& s) {
    DeterministicRng rng(s.seed);
    for (size_t i = 0; i < s.iters; ++i) {
        run_one(s, i, [&]() {
            auto cell = build_random_cell(rng, /*depth_budget=*/4);
            ew::MptTrie trie;
            // Try shallow; if rejected, the trie stays empty. Either way the
            // safe proof must not crash.
            (void)trie.load_from_cell(
                cell, ew::MptWitnessValidationMode::Shallow);
            evmc::bytes32 key{};
            // Random 32-byte key.
            for (int b = 0; b < 32; ++b) key.bytes[b] = rng.next_byte();
            auto res = trie.proof_safe(silkworm::ByteView{key.bytes, 32});
            return res.is_ok();
        });
    }
}

void fuzz_mpt_value_at_hashed_safe(DriverStats& s) {
    DeterministicRng rng(s.seed);
    for (size_t i = 0; i < s.iters; ++i) {
        run_one(s, i, [&]() {
            auto cell = build_random_cell(rng, /*depth_budget=*/4);
            ew::MptTrie trie;
            (void)trie.load_from_cell(
                cell, ew::MptWitnessValidationMode::Shallow);
            evmc::bytes32 key{};
            for (int b = 0; b < 32; ++b) key.bytes[b] = rng.next_byte();
            auto res = trie.value_at_hashed_safe(
                silkworm::ByteView{key.bytes, 32});
            return res.is_ok();
        });
    }
}

void fuzz_mpt_root_hash_safe(DriverStats& s) {
    DeterministicRng rng(s.seed);
    for (size_t i = 0; i < s.iters; ++i) {
        run_one(s, i, [&]() {
            auto cell = build_random_cell(rng, /*depth_budget=*/4);
            ew::MptTrie trie;
            (void)trie.load_from_cell(
                cell, ew::MptWitnessValidationMode::Shallow);
            auto res = trie.root_hash_safe();
            return res.is_ok();
        });
    }
}

void fuzz_mpt_upsert_hashed_safe(DriverStats& s) {
    DeterministicRng rng(s.seed);
    for (size_t i = 0; i < s.iters; ++i) {
        run_one(s, i, [&]() {
            // Mix of cases: a) start from canonical trie, b) start from
            // shallow-loaded random cell. Either should accept upsert with a
            // fail-closed status on a corrupt descendant rather than crash.
            ew::MptTrie trie;
            if (rng.next_bool()) {
                auto canon = make_canonical_trie();
                trie = std::move(canon.trie);
            } else {
                auto cell = build_random_cell(rng, /*depth_budget=*/3);
                (void)trie.load_from_cell(
                    cell, ew::MptWitnessValidationMode::Shallow);
            }
            evmc::bytes32 key{};
            for (int b = 0; b < 32; ++b) key.bytes[b] = rng.next_byte();
            auto value = rng.next_bytes(0, 128);
            silkworm::Bytes value_bytes(value.begin(), value.end());
            auto status = trie.upsert_hashed_safe(
                silkworm::ByteView{key.bytes, 32},
                silkworm::ByteView{value_bytes});
            // Empty value is rejected by the API; non-empty key+value should
            // either succeed or fail closed. Either is "no crash".
            return status.is_ok();
        });
    }
}

void fuzz_mpt_erase_hashed_safe(DriverStats& s) {
    DeterministicRng rng(s.seed);
    for (size_t i = 0; i < s.iters; ++i) {
        run_one(s, i, [&]() {
            ew::MptTrie trie;
            if (rng.next_bool()) {
                auto canon = make_canonical_trie();
                trie = std::move(canon.trie);
            } else {
                auto cell = build_random_cell(rng, /*depth_budget=*/3);
                (void)trie.load_from_cell(
                    cell, ew::MptWitnessValidationMode::Shallow);
            }
            evmc::bytes32 key{};
            for (int b = 0; b < 32; ++b) key.bytes[b] = rng.next_byte();
            auto status = trie.erase_hashed_safe(
                silkworm::ByteView{key.bytes, 32});
            // Erasing a non-existent key returns OK; corrupt subtree returns
            // status error. Either is fail-closed.
            return status.is_ok();
        });
    }
}

void fuzz_cell_state_load_trie_witness_trusted_shallow(DriverStats& s) {
    DeterministicRng rng(s.seed);
    for (size_t i = 0; i < s.iters; ++i) {
        run_one(s, i, [&]() {
            auto witness = build_random_witness_cell(rng);
            ew::CellEvmState state;
            return state.load_trie_witness_from_cell(
                witness, ew::TrieWitnessLoadMode::TrustedShallow);
        });
    }
}

void fuzz_cell_state_storage_root_safe_no_cache(DriverStats& s) {
    DeterministicRng rng(s.seed);
    for (size_t i = 0; i < s.iters; ++i) {
        run_one(s, i, [&]() {
            // 50%: feed a random witness cell; 50%: feed a "shallow" witness
            // header that points to garbage subtrees. This stresses the
            // storage-root path on both pre-load (witness-not-ready) and
            // post-load (lazy storage-trie index walk) regimes.
            ew::CellEvmState state;
            if (rng.next_bool()) {
                auto witness = build_random_witness_cell(rng);
                (void)state.load_trie_witness_from_cell(
                    witness, ew::TrieWitnessLoadMode::TrustedShallow);
            }
            evmc::address addr{};
            for (int b = 0; b < 20; ++b) addr.bytes[b] = rng.next_byte();
            auto res = state.ethereum_storage_root_hash_safe_no_cache(addr);
            // Both OK and Error are clean fail-closed outcomes; the contract
            // is "no crash". Treat OK as accepted, Error as rejected.
            return res.is_ok();
        });
    }
}

}  // namespace

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

int main(int /*argc*/, char** /*argv*/) {
    // Fixed seed list. A regression on `seed=0xC0DECAFE iter=4231` is
    // reproducible by re-running with the same binary on any host.
    const uint64_t seeds[] = {
        0xC0DECAFEull,
        0xDEADBEEFull,
        0xFEEDFACEull,
        0xBADC0FFEEull,
        0x1337CAFEull,
        0x2026A11Cull,  // year + audit-listing tag
    };
    constexpr size_t kIters = 2000;  // ~ 6 drivers × 9 calls × 2k = 108k inputs

    struct DriverDef {
        const char* name;
        void (*fn)(DriverStats&);
    };
    const DriverDef drivers[] = {
        {"fuzz_mpt_load_from_cell_shallow",
         &fuzz_mpt_load_from_cell_shallow},
        {"fuzz_mpt_load_from_cell_strict",
         &fuzz_mpt_load_from_cell_strict},
        {"fuzz_mpt_proof_safe",
         &fuzz_mpt_proof_safe},
        {"fuzz_mpt_value_at_hashed_safe",
         &fuzz_mpt_value_at_hashed_safe},
        {"fuzz_mpt_root_hash_safe",
         &fuzz_mpt_root_hash_safe},
        {"fuzz_mpt_upsert_hashed_safe",
         &fuzz_mpt_upsert_hashed_safe},
        {"fuzz_mpt_erase_hashed_safe",
         &fuzz_mpt_erase_hashed_safe},
        {"fuzz_cell_state_load_trie_witness_trusted_shallow",
         &fuzz_cell_state_load_trie_witness_trusted_shallow},
        {"fuzz_cell_state_storage_root_safe_no_cache",
         &fuzz_cell_state_storage_root_safe_no_cache},
    };

    tprintf("test-mpt-fuzz: randomized fuzz target for the MPT/witness "
            "fail-closed `_safe` API surface\n\n");

    for (const auto& d : drivers) {
        for (uint64_t seed : seeds) {
            DriverStats s;
            s.name = d.name;
            s.seed = seed;
            s.iters = kIters;
            d.fn(s);
            print_driver_summary(s);
        }
    }

    int failures = g_failures.load();
    tprintf("test-mpt-fuzz: %d driver-summary failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
