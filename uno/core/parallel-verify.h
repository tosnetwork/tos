/*
    Uno Workchain — parallel Plonky3 / Schnorr verify pool (P.3).

    Implements §13 P.3 of doc/uno-workchain.md: the activation-prerequisite
    parallel verify stage that lifts the sustained throughput of the wc=2
    compute phase from the single-thread ~25 ms/tx ceiling (~16 TPS) to
    the design target of ~30 TPS sustained on 4-core validator hardware
    (§1.4, §7.4, §5.9).

    Shape:
      * A process-lifetime `ParallelVerifyPool` owns `num_cores` worker
        threads and one `uno::crypto::Plonky3Verifier` per worker (so the
        FFI contract — see `uno/crypto/plonky3-verifier.h` — is satisfied
        even if a future change makes `Plonky3Verifier::verify` non-const).
      * `verify_batch(state, txs)` hands every tx's §4.3 step 1-4 checks
        (cheap syntax, anchor window, nullifier-LRU/dict read, Ristretto
        decompression, Schnorr sigs, Plonky3 proof) to the workers, then
        blocks until every result is in. Results are returned in input
        order — worker completion order is irrelevant.
      * Step 5 (state mutation / apply) is deliberately NOT in scope.
        The caller applies `apply_transfer` serially in declared tx-order,
        skipping any tx whose `VerifyResult != Ok`. That preserves the
        byte-identical commitment tree root / nullifier set / anchor
        window post-state demanded by §12 P.5 "Cross-validator
        determinism".

    Determinism invariants enforced here:
      1. The `const UnoState&` handed to workers is read-only — workers
         never call any mutator. The `UnoState` abstract class already
         declares mutators `non-const`, so this is type-checked by the
         compiler.
      2. No cross-thread mutable state during verify. Each worker holds
         its own `Plonky3Verifier` handle; Schnorr verify goes through
         libsodium which is thread-safe; nullifier LRU is touched only
         through the state's (implementation-provided) thread-safe
         `nullifier_is_spent` — A2 documents that path as safe for
         compute-phase read from multiple threads.
      3. Results vector is indexed by input order; scheduling order has
         no observable effect on the caller's apply loop.

    Source: TOS-specific adapter.
*/
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "uno/core/compute-phase.h"   // UnoState, VerifyResult

namespace uno_workchain {

struct Transfer;  // forward — full def in uno/core/transaction.h

// ---------------------------------------------------------------------------
// ParallelVerifyPool
// ---------------------------------------------------------------------------

/// Thread pool that runs §4.3 step 1-4 verify concurrently across a bounded
/// number of worker threads. Intended to live for the process lifetime;
/// construct once at startup via `install_parallel_verify_pool(num_cores)`
/// and reuse for every block.
///
/// Thread safety: `verify_batch()` is re-entrant from the caller's
/// perspective — multiple concurrent calls from different threads are
/// supported, but each call dispatches sequentially onto the worker
/// queue. For the compute-phase path, only one block is verified at a
/// time (the consensus thread), so contention is a non-issue in practice.
///
/// Non-copyable, non-movable: the worker threads are bound to `this`.
class ParallelVerifyPool {
public:
    /// Construct a pool with `num_workers` threads. `num_workers == 0`
    /// is clamped to 1 (single-threaded fall-back; never a hard error
    /// to keep validators with exotic `hardware_concurrency()` reports
    /// bootable).
    explicit ParallelVerifyPool(std::size_t num_workers);

    ~ParallelVerifyPool();

    ParallelVerifyPool(const ParallelVerifyPool&)            = delete;
    ParallelVerifyPool& operator=(const ParallelVerifyPool&) = delete;
    ParallelVerifyPool(ParallelVerifyPool&&)                 = delete;
    ParallelVerifyPool& operator=(ParallelVerifyPool&&)      = delete;

    /// Number of worker threads the pool owns. Accurate after construction.
    std::size_t num_workers() const noexcept { return num_workers_; }

    /// Verify a batch of transfers in parallel.
    ///
    /// @param state   Immutable reference to the live UnoState. All
    ///                verify-phase calls (`anchor_window_contains`,
    ///                `nullifier_is_spent`, the fee-config getters) go
    ///                through its `const` surface; the pool does not
    ///                mutate.
    /// @param txs     Pointer to N `Transfer`s. The pool never takes
    ///                ownership and never mutates them. Pointers MUST
    ///                remain live until `verify_batch` returns.
    /// @param n_txs   Length of the `txs` array.
    /// @return        Vector of N `VerifyResult`s, indexed by input
    ///                order. `results[i]` is the outcome of
    ///                `verify_transfer(state, txs[i])`.
    ///
    /// Post-condition: byte-identical to running `verify_transfer` in a
    /// simple for-loop. This is the property the P.5 determinism test
    /// fixes.
    std::vector<VerifyResult> verify_batch(const UnoState& state,
                                           const Transfer* txs,
                                           std::size_t     n_txs);

private:
    class Impl;                      // pImpl: keeps <thread>, <mutex>,
    std::unique_ptr<Impl> impl_;     // <condition_variable> out of the header.
    std::size_t num_workers_{0};
};

// ---------------------------------------------------------------------------
// Process-singleton accessors (for compute-phase.cpp / init.cpp)
// ---------------------------------------------------------------------------

/// Install (or replace) the process-lifetime parallel-verify pool. Called
/// once from `init_uno_workchain` after config load (N-P5's wiring).
/// `num_cores == 0` means "auto-detect via std::thread::hardware_concurrency()"
/// and is the recommended default.
///
/// Calling this twice in the same process replaces the previous pool and
/// joins its workers; intended for test harnesses that vary worker count
/// between runs.
void install_parallel_verify_pool(std::size_t num_cores);

/// Return the installed pool, or `nullptr` if `install_parallel_verify_pool`
/// has not been called yet. `run_compute_phase` / `run_compute_phase_batch`
/// check this and fall back to the serial path when no pool is available
/// (keeps the skeleton build / unit tests that don't wire init green).
ParallelVerifyPool* global_parallel_verify_pool() noexcept;

/// Tear down the installed pool. Intended for test teardown; production
/// nodes just leak the pool at exit (worker threads are joined in the
/// destructor, no OS resource leak).
void shutdown_parallel_verify_pool() noexcept;

// ---------------------------------------------------------------------------
// Adapter exposed for unit tests — not part of the compute-phase ABI
// ---------------------------------------------------------------------------

/// Serial reference verify used by both the fallback path in
/// `run_compute_phase_batch` and the `test-uno-parallel-verify` determinism
/// fixture. Bit-for-bit identical to the inline verify in
/// `run_compute_phase` (same `uno_crypto::*` helpers, same short-circuits,
/// same ordering). Exposed here to avoid duplication in the test.
VerifyResult verify_transfer_serial(const UnoState& state,
                                    const Transfer& tx);

}  // namespace uno_workchain
