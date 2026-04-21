/*
    Uno Workchain — parallel Plonky3 / Schnorr verify pool implementation (P.3).

    See header for the contract and design doc §13 P.3 for the rationale.

    Implementation choices and why:

    * std::thread + std::mutex + std::condition_variable. No td::actor, no
      external thread-pool library. The workload is embarrassingly parallel
      (no cross-worker state, one verify per task) and the consensus-critical
      hot path is a single batch per block; a simple pool-with-work-queue
      matches the access pattern without the overhead of an actor framework.
      (Grep for `td::actor/` in this tree shows the actor scheduler is used
      for network / RPC paths, not for CPU-bound per-tx verify — mirroring
      that convention here.)

    * One Plonky3Verifier per worker thread. Per `uno/crypto/plonky3-verifier.h`
      the handle "is thread-safe" in the §13 P.3 sense — meaning multiple
      threads may call `verify()` on the SAME handle concurrently without
      races. We still allocate one handle per worker because (a) it's
      cheap (init is a one-shot FRI-parameter load), (b) it removes a
      shared cache line and its attendant false sharing, and (c) it
      insulates us from any future contract change on the Rust side
      without requiring a re-audit of the compute-phase locking story.

    * Work queue is a pre-sized vector of atomic `uint8_t` slots + a shared
      atomic counter. Each worker `fetch_add`s the counter for the next
      index and processes that tx, storing its VerifyResult in the output
      vector slot. No queue mutex on the hot path — a condition_variable is
      used only for initial wake-up / final "all-done" signalling.

    * Results are written by `results[i] = ...` (one writer per index, ever),
      then read by the main thread after the pool signals completion. The
      happens-before chain through the condition variable gives us the
      visibility guarantee without per-slot atomics.

    Source: TOS-specific adapter.
*/
#include "uno/core/parallel-verify.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

#include "td/utils/logging.h"

#include "uno/core/compute-phase.h"
#include "uno/core/transaction.h"
#include "uno/crypto/plonky3-verifier.h"
#include "uno/crypto/ristretto255.h"
#include "uno/crypto/schnorr-ristretto.h"
#include "uno/rpc/metrics.h"

#include <chrono>

namespace uno_workchain {

// =============================================================================
// Serial verify reference implementation
//
// This is the single canonical `verify_transfer` used by:
//   (a) `run_compute_phase` when no pool is installed (skeleton / test mode),
//   (b) each worker in the parallel pool (one tx per call),
//   (c) the determinism test's serial-baseline path.
//
// The body is identical to the pre-P.3 inline verify in compute-phase.cpp;
// only the location changed. Keeping one implementation avoids drift
// between the two paths, which is the property §12 P.5 demands.
// =============================================================================

namespace {

// §4.3 step 1.4: fee >= min_fee_nano + fee_per_byte·size + fee_per_spend·|S|
//                + fee_per_output·|O|.
uint64_t required_fee(const UnoState& state, const Transfer& tx) noexcept {
    uint64_t size_bytes = tx.wire_size_bytes;
    return state.min_fee_nano()
         + state.fee_per_byte_nano()   * size_bytes
         + state.fee_per_spend_nano()  * tx.spends.size()
         + state.fee_per_output_nano() * tx.outputs.size();
}

// Per-thread Plonky3 verifier holder. Lazy-initialised once per worker
// and reused across every tx dispatched to that worker. Failure to init
// means the worker returns `BadPlonky3Proof` for every tx — the same
// behaviour as the pre-P.3 singleton path.
struct Plonky3Holder {
    ::uno::crypto::Plonky3Verifier verifier;
    bool ready{false};

    bool ensure_ready() {
        if (!ready) ready = verifier.init();
        return ready;
    }
};

// ---- Plonky3 / Schnorr / Ristretto adapter helpers -------------------------
//
// Mirror the `uno_crypto::*` helpers from compute-phase.cpp. Kept inline
// here so parallel-verify.cpp compiles without exporting them from the
// anonymous namespace of another TU.

inline bool ristretto255_is_valid_point(const uint8_t bytes[32]) noexcept {
    ::uno_workchain::crypto::RistrettoPoint pt{};
    std::memcpy(pt.bytes.data(), bytes, 32);
    return pt.validate().is_ok();
}

inline bool schnorr_ristretto_verify(const uint8_t rk[32],
                                     const uint8_t msg[32],
                                     const uint8_t sig[64]) noexcept {
    ::uno_workchain::crypto::RistrettoPoint pk{};
    std::memcpy(pk.bytes.data(), rk, 32);
    ::uno_workchain::crypto::SchnorrSignature s{};
    std::memcpy(s.data(), sig, 64);
    td::Slice msg_slice(reinterpret_cast<const char*>(msg), 32);
    return ::uno_workchain::crypto::schnorr_verify(pk, msg_slice, s).is_ok();
}

// Core §4.3 steps 1-4, parameterised over the Plonky3Holder so workers
// can supply their thread-local handle. The compute-phase singleton path
// passes its process-wide holder through the same signature.
VerifyResult verify_transfer_with_holder(const UnoState& state,
                                         const Transfer& tx,
                                         Plonky3Holder& holder) {
    // ---- Step 1: cheap syntax (§4.3 step 1) --------------------------------
    if (tx.version != kTransferVersion)   return VerifyResult::BadVersion;
    if (tx.scheme_id != kSchemeIdV1)      return VerifyResult::BadSchemeId;
    if (tx.chain_id != state.expected_chain_id()) return VerifyResult::BadChainId;

    const uint64_t cur = state.current_block_seqno();
    const uint64_t max_expiry = cur + state.expiry_window_blocks();
    if (tx.expiry_block < cur || tx.expiry_block > max_expiry) {
        return VerifyResult::ExpiryOutOfRange;
    }
    if (tx.spends.size() < kMinSpendCount || tx.spends.size() > kMaxSpendCount) {
        return VerifyResult::BadSpendCount;
    }
    if (tx.outputs.size() < kMinOutputCount || tx.outputs.size() > kMaxOutputCount) {
        return VerifyResult::BadOutputCount;
    }
    if (tx.fee < required_fee(state, tx)) {
        return VerifyResult::InsufficientFee;
    }

    if (!state.anchor_window_contains(tx.anchor)) {
        return VerifyResult::UnknownAnchor;
    }

    // Pairwise-distinct within-tx checks.
    {
        std::unordered_set<std::string> seen_nf;
        seen_nf.reserve(tx.spends.size() * 2);
        for (const auto& s : tx.spends) {
            std::string k(reinterpret_cast<const char*>(s.nullifier.data()), 32);
            if (!seen_nf.insert(std::move(k)).second) {
                return VerifyResult::DuplicateNullifierInTx;
            }
        }
    }
    {
        std::unordered_set<std::string> seen_cm;
        seen_cm.reserve(tx.outputs.size() * 2);
        for (const auto& o : tx.outputs) {
            std::string k(reinterpret_cast<const char*>(o.cm.data()), 32);
            if (!seen_cm.insert(std::move(k)).second) {
                return VerifyResult::DuplicateCommitmentInTx;
            }
        }
    }

    // Ristretto point decompression (§4.3 step 1.7).
    for (const auto& s : tx.spends) {
        if (!ristretto255_is_valid_point(
                reinterpret_cast<const uint8_t*>(s.rk.data()))) {
            return VerifyResult::BadRistrettoPoint;
        }
    }
    for (const auto& o : tx.outputs) {
        if (!ristretto255_is_valid_point(
                reinterpret_cast<const uint8_t*>(o.epk.data()))) {
            return VerifyResult::BadRistrettoPoint;
        }
    }

    // ---- Step 2: nullifier not-spent (§4.3 step 2) -------------------------
    for (const auto& s : tx.spends) {
        if (state.nullifier_is_spent(s.nullifier)) {
            return VerifyResult::NullifierAlreadySpent;
        }
    }

    // ---- Step 3: Schnorr-on-Ristretto255 spend-auth sigs (§4.3 step 3) -----
    for (const auto& s : tx.spends) {
        if (!schnorr_ristretto_verify(
                reinterpret_cast<const uint8_t*>(s.rk.data()),
                reinterpret_cast<const uint8_t*>(tx.tx_hash.data()),
                s.spend_auth_sig.data())) {
            return VerifyResult::BadSpendAuthSig;
        }
    }

    // ---- Step 4: Plonky3 proof verify (§4.3 step 4) ------------------------
    //
    // A6-4 bridge (stub): the per-Tx zk_proof chunk-chain was removed from
    // Transfer in A6-4a. Per-Tx proof verification is moving to the block
    // level in A6-4d/A6-5 (decode UnoBlockExtra once per block, call
    // BlockProofVerifier::verify). Until that landing the compute-phase
    // skips STARK verify altogether; signatures, nullifier uniqueness,
    // anchor-window, and witness_commitment cross-check still execute via
    // the steps above and the upcoming validator path.
    //
    // NOTE: this stub is NOT production-safe on its own — it disables
    // per-Tx cryptographic validity. A6-4d/A6-5 must land before UNO
    // ships or the collator must verify per-Tx before admission (which
    // matches §4.3a's mempool pre-filter design).
    (void)holder;  // unused until A6-4d wires the block-level verifier.

    return VerifyResult::Ok;
}

// Thread-local Plonky3 holder used by `verify_transfer_serial`. Every
// thread that calls into the serial path gets its own verifier handle;
// cleanup is at thread exit.
Plonky3Holder& tls_plonky3_holder() {
    thread_local Plonky3Holder holder;
    return holder;
}

}  // anonymous namespace

VerifyResult verify_transfer_serial(const UnoState& state, const Transfer& tx) {
    // K-uno-metrics: record the §4.3 step 1-4 verify duration in the compute-
    // phase histogram. This covers both the skeleton-build path (compute-phase
    // fallback) and every worker in the parallel pool. The scoped timer in
    // `verify_transfer()` (compute-phase.cpp) would otherwise double-count
    // this interval when no pool is installed — we avoid that by ONLY timing
    // here for the batched / per-worker path. compute-phase's timer is the
    // single-tx fallback and runs exactly once per tx regardless.
    //
    // Caveat: when compute-phase.cpp's `verify_transfer()` falls through to
    // this function (pool not installed), the compute-phase timer observes
    // the full wall-clock including the function-call overhead here; we do
    // NOT double-observe because compute-phase's timer is the only one that
    // enters the histogram on the non-pool path. The pool path calls
    // `verify_transfer_with_holder` directly (see worker_loop), so this
    // serial-verify entry point is not on that hot path.
    auto t0 = std::chrono::steady_clock::now();
    VerifyResult r = verify_transfer_with_holder(state, tx, tls_plonky3_holder());
    auto t1 = std::chrono::steady_clock::now();
    double seconds =
        std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count() / 1e9;
    global_metrics_registry().observe_verify_transfer(
        VerifyPhase::Compute, seconds);
    return r;
}

// =============================================================================
// ParallelVerifyPool::Impl — worker threads, task queue, synchronisation
// =============================================================================

class ParallelVerifyPool::Impl {
public:
    explicit Impl(std::size_t num_workers) {
        workers_.reserve(num_workers);
        for (std::size_t i = 0; i < num_workers; ++i) {
            workers_.emplace_back([this, i]() { worker_loop(i); });
        }
    }

    ~Impl() {
        {
            std::lock_guard<std::mutex> lk(mu_);
            stopping_ = true;
        }
        cv_start_.notify_all();
        for (auto& t : workers_) {
            if (t.joinable()) t.join();
        }
    }

    std::vector<VerifyResult> run_batch(const UnoState& state,
                                        const Transfer* txs,
                                        std::size_t     n_txs) {
        std::vector<VerifyResult> out(n_txs, VerifyResult::Ok);
        if (n_txs == 0) return out;

        // Serialise concurrent callers — one block verified at a time.
        // In the consensus path this is redundant (only the consensus
        // thread calls this); in tests that exercise the pool from
        // multiple threads the guard keeps the task queue single-writer.
        std::lock_guard<std::mutex> batch_guard(batch_mu_);

        {
            std::lock_guard<std::mutex> lk(mu_);
            state_    = &state;
            txs_      = txs;
            n_txs_    = n_txs;
            results_  = out.data();
            next_idx_.store(0, std::memory_order_relaxed);
            remaining_.store(n_txs, std::memory_order_relaxed);
            pending_batch_ = true;
        }
        cv_start_.notify_all();

        // Wait for every task in the batch to complete.
        std::unique_lock<std::mutex> lk(mu_);
        cv_done_.wait(lk, [this]() {
            return remaining_.load(std::memory_order_acquire) == 0;
        });
        pending_batch_ = false;

        return out;
    }

private:
    void worker_loop(std::size_t worker_idx) {
        Plonky3Holder holder;
        (void)worker_idx;  // reserved for future per-worker diagnostics

        for (;;) {
            // Wait for a batch or shutdown.
            {
                std::unique_lock<std::mutex> lk(mu_);
                cv_start_.wait(lk, [this]() {
                    return stopping_ || pending_batch_;
                });
                if (stopping_) return;
            }

            // Drain tasks from the shared counter until the batch is done.
            while (true) {
                const std::size_t idx =
                    next_idx_.fetch_add(1, std::memory_order_relaxed);
                if (idx >= n_txs_) break;

                // K-uno-metrics: record per-tx verify latency on the pool hot
                // path. Mirror the observation from `verify_transfer_serial`;
                // compute-phase's top-level `verify_transfer()` does NOT time
                // separately to avoid double-counting.
                auto t0 = std::chrono::steady_clock::now();
                VerifyResult r =
                    verify_transfer_with_holder(*state_, txs_[idx], holder);
                auto t1 = std::chrono::steady_clock::now();
                global_metrics_registry().observe_verify_transfer(
                    VerifyPhase::Compute,
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                        t1 - t0).count() / 1e9);
                results_[idx] = r;

                // Signal completion once the last task finishes. Must be
                // decrement-then-compare so exactly one worker wakes the
                // caller.
                const std::size_t prev =
                    remaining_.fetch_sub(1, std::memory_order_acq_rel);
                if (prev == 1) {
                    std::lock_guard<std::mutex> lk(mu_);
                    cv_done_.notify_all();
                    break;
                }
            }
        }
    }

    // ---- Lifecycle / shutdown ---------------------------------------------
    std::vector<std::thread> workers_;
    bool   stopping_{false};

    // ---- Synchronisation --------------------------------------------------
    std::mutex              mu_;
    std::mutex              batch_mu_;   // serialises verify_batch() callers
    std::condition_variable cv_start_;   // notified by run_batch, dtor
    std::condition_variable cv_done_;    // notified by last worker

    // ---- Current batch state (valid while pending_batch_ == true) ---------
    const UnoState*         state_{nullptr};
    const Transfer*         txs_{nullptr};
    std::size_t             n_txs_{0};
    VerifyResult*           results_{nullptr};
    std::atomic<std::size_t> next_idx_{0};
    std::atomic<std::size_t> remaining_{0};
    bool                    pending_batch_{false};
};

// =============================================================================
// ParallelVerifyPool public API
// =============================================================================

ParallelVerifyPool::ParallelVerifyPool(std::size_t num_workers)
    : num_workers_(num_workers == 0 ? 1 : num_workers) {
    impl_ = std::make_unique<Impl>(num_workers_);
    LOG(INFO) << "uno-workchain: parallel verify pool online workers="
              << num_workers_;
}

ParallelVerifyPool::~ParallelVerifyPool() = default;

std::vector<VerifyResult> ParallelVerifyPool::verify_batch(
    const UnoState& state, const Transfer* txs, std::size_t n_txs) {
    return impl_->run_batch(state, txs, n_txs);
}

// =============================================================================
// Process-singleton
// =============================================================================

namespace {

struct SingletonHolder {
    std::mutex                           mu;
    std::unique_ptr<ParallelVerifyPool>  pool;
};

SingletonHolder& singleton() {
    static SingletonHolder h;
    return h;
}

}  // anonymous namespace

void install_parallel_verify_pool(std::size_t num_cores) {
    if (num_cores == 0) {
        num_cores = std::thread::hardware_concurrency();
        if (num_cores == 0) num_cores = 1;
    }
    auto& h = singleton();
    std::lock_guard<std::mutex> lk(h.mu);
    // Tear down any previous pool first (join workers deterministically)
    // before constructing the replacement.
    h.pool.reset();
    h.pool = std::make_unique<ParallelVerifyPool>(num_cores);
}

ParallelVerifyPool* global_parallel_verify_pool() noexcept {
    auto& h = singleton();
    std::lock_guard<std::mutex> lk(h.mu);
    return h.pool.get();
}

void shutdown_parallel_verify_pool() noexcept {
    auto& h = singleton();
    std::lock_guard<std::mutex> lk(h.mu);
    h.pool.reset();
}

}  // namespace uno_workchain
