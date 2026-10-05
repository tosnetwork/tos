#pragma once

#include <algorithm>
#include <chrono>
#include <functional>

#include "td/utils/Status.h"
#include "tos/tos-shard.h"
#include "tos/tos-types.h"
#include "vm/cells.h"
#include "vm/vm.h"

namespace tos_wallet_index {

constexpr long long kWalletIndexGetMethodGasLimit = 1'000'000;
constexpr long long kWalletIndexBlockVerificationGasLimit = 10'000'000;

enum class WalletIndexGetMethodStatus { Success, ContractFailure, Indeterminate };

// A failed get-method is indeterminate only when the node, rather than the
// contract, prevented a conclusive answer. In particular, preserve an old
// ownership claim when the fair-share scheduler supplied less than the normal
// per-method limit and that reduced share was exhausted. A contract that burns
// the full normal limit still fails verification, otherwise it could pin stale
// ownership forever by deliberately running out of gas.
inline WalletIndexGetMethodStatus wallet_index_classify_get_method_failure(long long reserved_gas, td::int32 exit_code,
                                                                           long long gas_used) {
  auto out_of_gas = ~static_cast<td::int32>(vm::Excno::out_of_gas);
  auto virtualization_error = ~static_cast<td::int32>(vm::Excno::virt_err);
  if (exit_code == virtualization_error || (reserved_gas > 0 && reserved_gas < kWalletIndexGetMethodGasLimit &&
                                            exit_code == out_of_gas && gas_used >= reserved_gas)) {
    return WalletIndexGetMethodStatus::Indeterminate;
  }
  return WalletIndexGetMethodStatus::ContractFailure;
}

// Both limit and max must be bounded. A hostile get-method may execute ACCEPT,
// which raises the current limit up to gas_max.
inline vm::GasLimits wallet_index_get_method_gas_limits(
    long long remaining = kWalletIndexGetMethodGasLimit) {
  auto limit = std::min(kWalletIndexGetMethodGasLimit, std::max(0LL, remaining));
  return vm::GasLimits{limit, limit};
}

inline bool wallet_index_state_contains(tos::ShardIdFull shard, const td::Bits256& address) {
  return tos::shard_contains(shard, tos::AccountIdPrefixFull{0, tos::extract_top64(address)});
}

class WalletIndexVerificationBudget {
 public:
  void begin_candidate(size_t remaining_candidates) {
    candidate_remaining_ = remaining_candidates == 0 ? 0 : remaining_ / static_cast<long long>(remaining_candidates);
  }

  long long acquire() {
    auto limit = std::min({kWalletIndexGetMethodGasLimit, remaining_, candidate_remaining_});
    remaining_ -= limit;
    candidate_remaining_ -= limit;
    return limit;
  }

  void refund_unused(long long reserved, long long used) {
    auto refund = reserved - std::clamp(used, 0LL, reserved);
    remaining_ += refund;
    candidate_remaining_ += refund;
  }

 private:
  long long remaining_{kWalletIndexBlockVerificationGasLimit};
  long long candidate_remaining_{kWalletIndexGetMethodGasLimit};
};

// Index every wc=0 transaction in an applied block into the wallet index, and
// (re)index token ownership verified against the post-apply shard state.
// Best-effort: swallows parse errors so it never affects block application.
// `state_root` may be null; token candidates are then deferred (fail-closed).
// Called by the indexing worker and by startup recovery, never by block
// application itself.
// `block_id` must be the full BlockIdExt (not just workchain+seqno): the
// crash-recovery marker is keyed off it, and workchain+seqno alone is not
// unique across a shard split/merge.
// Returns AtPendingCap, without touching the block, when the index already
// holds kMaxPendingTokenBlocks blocks with persisted candidates: the caller
// finishes some first and tries again; the block keeps its recovery mark
// meanwhile.
enum class Wc0IndexResult { Done, AtPendingCap, NotDone };
Wc0IndexResult wc0_index_block(td::Ref<vm::Cell> block_root, td::Ref<vm::Cell> state_root, tos::BlockIdExt block_id);

// Blocks waiting to be indexed at most. Each holds its block and state cells.
constexpr size_t kWc0IndexQueueCapacity = 256;
// Blocks the queue keeps beyond its capacity when they cannot be read back
// later (archive pruning already gave up their package).
constexpr size_t kWc0IndexPinnedExtra = 64;
// How long the worker waits for block data it asked the fetcher for. A block
// whose data does not come in time stays marked for recovery.
constexpr std::chrono::seconds kWc0IndexFetchTimeout{60};

// Block data the block-apply hook did not have, as the fetcher found it. The
// state may be null when it was not asked for or is not available.
struct Wc0FetchedBlock {
  td::Ref<vm::Cell> block_root;
  td::Ref<vm::Cell> state_root;
};
// Reads an applied block's data (and, when `need_state`, its post-apply
// state) for the indexing worker. Called on the worker thread; it must return
// at once and answer `done` exactly once, from any thread, possibly much
// later. The worker does not wait for an answer forever: it gives up after
// kWc0IndexFetchTimeout or when it is stopped, and a late answer is ignored.
using Wc0IndexBlockFetcher = std::function<void(const tos::BlockIdExt& block_id, bool need_state,
                                                std::function<void(td::Result<Wc0FetchedBlock>)> done)>;
// Install (or, with nullptr, remove) the fetcher. Without one, a block handed
// over without its data stays marked for recovery.
void set_wc0_index_block_fetcher(Wc0IndexBlockFetcher fetcher);

// The newest state of the shard holding an address, for the indexing worker
// to verify waiting candidates against when no block it indexed gives a new
// enough state (after a restart, with no new block). Same contract as the
// block fetcher.
struct Wc0NewestState {
  tos::BlockIdExt block_id;
  uint64_t end_lt = 0;
  td::Ref<vm::Cell> state_root;
};
using Wc0IndexStateFetcher =
    std::function<void(const td::Bits256& address, std::function<void(td::Result<Wc0NewestState>)> done)>;
void set_wc0_index_state_fetcher(Wc0IndexStateFetcher fetcher);

// Start indexing for this run. Call once, before installing
// enqueue_wc0_index_block as the block-apply hook, and only install it when
// this returns true. It needs the index open (wallet_index_db()). A previous
// run that did not finish cleanly (flush_wc0_index_for_exit) may have lost a
// block between its apply and its mark, so the index is first durably marked
// as needing a rebuild; then this run is durably recorded as active, and only
// then can blocks be handed over. If any step fails, or no index is open,
// nothing is started, the index is closed and reported unavailable, and false
// is returned: a worker with no index to mark into would hold every queued
// block in memory and retry forever.
// A paused worker records queued blocks but indexes none until resumed:
// startup recovery re-indexes blocks from earlier runs first, so no older
// block is indexed after a newer.
bool start_wc0_index_worker(bool paused);
void resume_wc0_index_worker();
// Whether block application can still call the hook when the index is
// flushed for exit.
enum class Wc0IndexProducers { MayStillApply, Quiesced };

// Before an exit: stop indexing and wait (up to `limit`) until every block
// handed over is marked for recovery. Blocks handed over from then on are
// only recorded for recovery, by the recorder thread; the hook still never
// waits. Shutdown may wait here, block application never does.
// The run is recorded as finished cleanly only when `producers` is Quiesced
// (no block can be applied any more), every queued block was marked in time,
// nothing was lost, no block arrived after the queue was closed, and the
// record itself was written; true is returned then. Otherwise the run stays
// recorded as active and the next start reports that the index needs a
// rebuild. Crash safety after the run is recorded as finished rests on the
// caller's Quiesced claim being true: no block may be applied any more. A
// block that still arrives makes the recorder record the run as active again
// before marking it, but that is a defence only; a crash before the recorder
// runs leaves no trace of the block.
bool flush_wc0_index_for_exit(Wc0IndexProducers producers,
                              std::chrono::milliseconds limit = std::chrono::milliseconds(2000));
// Stop it: a block being fetched is abandoned, the block in hand is
// finished, queued ones stay marked. Call before the index database is
// closed.
void stop_wc0_index_worker();
// Whether this run lost track of a block it could not mark for recovery
// (in memory, for when recording that fact durably failed too).
bool wc0_index_degraded();
// The block-apply hook: hands the block to the indexing worker and returns at
// once, so block application never waits on the index's lock, TVM getters,
// block-data reads or WAL sync. Either cell may be null; the worker fetches a
// missing block itself (set_wc0_index_block_fetcher). When the worker is
// kWc0IndexQueueCapacity blocks behind, the block is not indexed now; it is
// marked incomplete instead, and the startup recovery re-indexes marked
// blocks.
// `gen_utime` is the block's generation time (0 when unknown). Before the
// block is handed over, archive pruning is told to keep it (an in-memory
// floor, lowered atomically; pruning re-reads it before each deletion), and
// it stays kept until its marker is durable, after which the marker keeps it
// until its candidates are extracted.
void enqueue_wc0_index_block(td::Ref<vm::Cell> block_root, td::Ref<vm::Cell> state_root, tos::BlockIdExt block_id,
                             uint32_t gen_utime = 0);

// Tests only: make the recorder's writes (marking blocks for recovery, and
// recording that the index needs a rebuild) fail, as a failing disk would.
void set_wc0_index_marking_fault_for_testing(bool fail);
// Tests only: hold the recorder's writes until released, as a stalled disk
// would.
void set_wc0_index_marking_stall_for_testing(bool stall);
// Tests only: how long the worker waits between rounds of parked retries.
void set_wc0_index_parked_retry_pause_for_testing(std::chrono::milliseconds pause);
// Tests only: how many handed-over blocks are tracked one by one before the
// rest fold into one floor, and how many are tracked now.
void set_wc0_index_tracking_capacity_for_testing(size_t capacity);
size_t wc0_index_tracked_handovers_for_testing();
// Tests only: make the next `count` block commits fail, as a failing write
// would.
void set_wc0_index_commit_faults_for_testing(int count);
// Tests only: lower how many unfinished blocks the index may hold.
void set_wc0_index_pending_block_limit_for_testing(uint64_t limit);
// Tests only: shorten how long the worker waits for fetched block data.
void set_wc0_index_fetch_timeout_for_testing(std::chrono::milliseconds limit);

}  // namespace tos_wallet_index
