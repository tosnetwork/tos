#pragma once

#include <algorithm>
#include <chrono>

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
// Installed as tos::validator::g_wc0_block_index_hook by validator-engine.
// Best-effort: swallows parse errors so it never affects block application.
// `state_root` may be null; token indexing is then skipped (fail-closed).
// `block_id` must be the full BlockIdExt (not just workchain+seqno): the
// crash-recovery marker is keyed off it, and workchain+seqno alone is not
// unique across a shard split/merge.
void wc0_index_block(td::Ref<vm::Cell> block_root, td::Ref<vm::Cell> state_root, tos::BlockIdExt block_id);

// Blocks waiting to be indexed at most. Each holds its block and state cells.
constexpr size_t kWc0IndexQueueCapacity = 256;

// Start indexing for this run. Call once, before installing
// enqueue_wc0_index_block as the block-apply hook, and only install it when
// this returns true. It needs the index open (wallet_index_db()). A previous
// run that did not finish cleanly (flush_wc0_index_for_exit) may have lost a
// block between its apply and its mark, so the index is first durably marked
// as needing a rebuild; then this run is durably recorded as active, and only
// then does the worker start. If any step fails, or no index is open, nothing
// is started, the index is closed and reported unavailable, and false is
// returned: a worker with no index to mark into would hold every queued block
// in memory and retry forever.
// A paused worker records queued blocks but indexes none until resumed:
// startup recovery re-indexes blocks from earlier runs first, so no older
// block is indexed after a newer.
bool start_wc0_index_worker(bool paused);
void resume_wc0_index_worker();
// Before an exit: stop indexing and wait (up to `limit`) until every queued
// block is marked for recovery. From then on the hook marks each block it is
// given before returning, so no block can be applied unmarked. If every block
// was marked in time, nothing was lost and no mark failed, the run is recorded
// as finished cleanly, and true is returned; otherwise the run stays recorded
// as active and the next start reports that the index needs a rebuild.
bool flush_wc0_index_for_exit(std::chrono::milliseconds limit = std::chrono::milliseconds(2000));
// Stop it: the block in hand is finished, queued ones stay marked. Call
// before the index database is closed.
void stop_wc0_index_worker();
// Whether this run lost track of a block it could not mark for recovery
// (in memory, for when recording that fact durably failed too).
bool wc0_index_degraded();
// The block-apply hook: hands the block to the indexing worker and returns at
// once, so applying a block never waits on the index's lock, TVM getters or
// WAL sync. When the worker is kWc0IndexQueueCapacity blocks behind, the block is not
// indexed now; it is marked incomplete instead, and the startup recovery
// re-indexes marked blocks.
void enqueue_wc0_index_block(td::Ref<vm::Cell> block_root, td::Ref<vm::Cell> state_root, tos::BlockIdExt block_id);

// Tests only: make the recorder's writes (marking blocks for recovery, and
// recording that the index needs a rebuild) fail, as a failing disk would.
void set_wc0_index_marking_fault_for_testing(bool fail);

}  // namespace tos_wallet_index
