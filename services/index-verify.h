/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "td/utils/Status.h"
#include "td/utils/optional.h"
#include "tos/tos-types.h"
#include "validator-engine/wallet-index-lineage.h"
#include "validator-engine/wallet-index-writer.h"
#include "validator-engine/wallet-index.h"

namespace tos::services {

class IndexReader;

// Verification of an index imported from an untrusted snapshot, against the
// local node's own chain. The import keeps only the snapshot's history rows
// and its replay checkpoint C, and leaves the index Quarantined. Then:
//
// 1. prepare_quarantined_index: C must be a masterchain block this node holds
//    and has applied, with the same full identity. Walking down from C, each
//    masterchain block must be held, linked to the one above it, and readable;
//    the walk stops at the window base (the last block generated more than
//    the retention period before C) or at the first block the node does not
//    hold, whichever comes first. That block is the verified base B_v. Each
//    imported row is given the masterchain block that first referenced it, from
//    the shard tips of the walked blocks, exactly as replay keys the rows it
//    writes; rows already referenced by B_v are dropped, and a row no block up
//    to C references is a refusal. The window base is set to B_v in the batch
//    that records this step.
// 2. Normal replay from C to the source tip H. Nothing is served meanwhile.
// 3. verify_index_at_head: every account's rows above its window bound are
//    checked against H's state with verify_account_lineage. A contradiction
//    refuses the index; an account the state cannot vouch for (created in the
//    window, or absent from H) is marked unverified (0x31) for the window's
//    blocks to decide. The result is Partial: ownership is not yet derived
//    at H and the marked accounts are not yet checked, so it is never Full.

// The window bound of `account` given the tips of the window's base block:
// 0 when the window starts at the chain's first block (no base block).
td::Result<uint64_t> base_lt_bound(const std::vector<tos_wallet_index::WindowShardTip>& tips, bool has_base,
                                   const td::Bits256& account);

// A masterchain block as verification reads it from the local node.
struct VerifyMasterchainBlock {
  BlockIdExt id;
  // The previous masterchain block as the block's own checked bytes name it,
  // and as the node's handle records it; both unset for block 1. The walk
  // requires them to agree.
  td::optional<BlockIdExt> prev;
  td::optional<BlockIdExt> handle_prev;
  bool applied = false;
  uint32_t unix_time = 0;
  // The basechain shard tips the block records, with their end lt, read from
  // the block's checked bytes.
  std::vector<tos_wallet_index::WindowShardTip> tips;
};

// The accounts of a masterchain block's basechain shard states.
class HeadAccounts {
 public:
  virtual ~HeadAccounts() = default;
  // Every account, with its last transaction.
  virtual td::Status for_each(
      const std::function<td::Status(const td::Bits256&, const tos_wallet_index::AccountHead&)>& cb) = 0;
  // One account's last transaction, or nothing when the state does not hold it.
  virtual td::Result<td::optional<tos_wallet_index::AccountHead>> find(const td::Bits256& account) = 0;
};

// What verification reads from the local node.
class VerifySource {
 public:
  virtual ~VerifySource() = default;
  // The source's applied masterchain tip.
  virtual td::Result<BlockIdExt> tip() = 0;
  // Masterchain block `seqno`, or nothing when the node does not hold it (its
  // handle or its bytes). Any other failure is an error, never "not held".
  virtual td::Result<td::optional<VerifyMasterchainBlock>> masterchain_block(uint32_t seqno) = 0;
  // The accounts in the shard states masterchain block `head` names.
  virtual td::Result<std::unique_ptr<HeadAccounts>> accounts(const BlockIdExt& head) = 0;
  // The sorted root hashes of those shard states.
  virtual td::Result<std::vector<td::Bits256>> state_roots(const BlockIdExt& head) = 0;
  // Those shard states themselves, each with its block and end lt.
  virtual td::Result<std::vector<tos_wallet_index::OwnershipHeadState>> head_states(const BlockIdExt& head) = 0;
  // Every basechain transaction of the shard blocks masterchain block
  // `master` first referenced, each block's bytes checked against its
  // identity: (account, lt, transaction cell hash). `cancel` is checked
  // between blocks.
  virtual td::Status for_each_interval_transaction(
      const VerifyMasterchainBlock& master,
      const std::function<td::Status(const td::Bits256&, uint64_t, const td::Bits256&)>& cb,
      const std::atomic<bool>* cancel) = 0;
};

// Walk one interval's shard blocks in order: `read_root` gives a block's
// checked root, or nothing when the node does not hold its bytes, which is a
// gap in the window and terminal; `cancel` is checked between blocks.
template <class Block, class ReadRoot>
td::Status walk_interval_blocks(const std::vector<Block>& blocks, ReadRoot read_root,
                                const std::function<td::Status(const td::Bits256&, uint64_t, const td::Bits256&)>& cb,
                                const std::atomic<bool>* cancel);

// The basechain transactions a block's checked root holds, as replay indexes
// them (entries replay skips are skipped here too): (account, lt, hash).
td::Status walk_block_transactions(
    const td::Ref<vm::Cell>& root,
    const std::function<td::Status(const td::Bits256&, uint64_t, const td::Bits256&)>& cb);

// The production source: the node database through the index reader.
std::unique_ptr<VerifySource> make_reader_verify_source(IndexReader& reader);

// The code of a verification error that retrying cannot clear: a capacity
// bound, malformed data, or the node's own blocks not linking. The service
// stops on it. Any other error (a source or database request failing, the
// source not ready) is retried with a growing delay.
constexpr int kVerifyTerminalError = 4801;
inline bool is_terminal_verify_error(const td::Status& status) {
  return status.is_error() && status.code() == kVerifyTerminalError;
}

struct VerifyLimits {
  // The per-block shard tips kept for the window walk.
  size_t tip_table_bytes = size_t{256} << 20;
  // One account's retained rows held at once while it is checked.
  size_t account_rows_bytes = size_t{64} << 20;
  // Index writes per committed batch.
  size_t batch_writes = 4096;
  // Block pass work per step: masterchain blocks authenticated, intervals
  // collected, accounts compared.
  uint32_t authenticate_per_step = 1024;
  uint32_t intervals_per_step = 16;
  uint32_t compare_per_step = 1024;
  // Accounts, or recorded accounts, the ownership derivation examines per step.
  size_t ownership_per_step = 1024;
  // Rows the block pass may collect before it stops as over capacity.
  uint64_t collected_rows_max = uint64_t{64} << 20;
  // Memory one interval's collection may hold before it is committed: its
  // write batch and the per-account scope decisions.
  size_t interval_bytes = size_t{64} << 20;
};

enum class VerifyStep {
  // The step finished; for the head check the index is now Partial.
  Done,
  // The node is not there yet (it has not reached the checkpoint): try again
  // later. Nothing was decided.
  Wait,
  // The snapshot contradicts the chain: the index is now Refused.
  Refused,
  // Progress was made and more is left: call again.
  Working,
};

struct VerifyOutcome {
  VerifyStep step = VerifyStep::Done;
  std::string reason;
  // The first account that refused the index, when one did.
  td::optional<td::Bits256> account;
  // For prepare: rows given age keys and rows dropped as outside the window.
  uint64_t kept = 0;
  uint64_t dropped = 0;
  // For the head check: accounts marked unverified.
  uint64_t unverified = 0;
  // For the ownership step: the derivation is done and token work is still
  // owed; the service drains it with H's states (drain_wc0_ownership).
  bool drain = false;
};

// Step 1 above. Requires a Quarantined index without a verification record.
td::Result<VerifyOutcome> prepare_quarantined_index(tos_wallet_index::WalletIndexDb& db, VerifySource& source,
                                                    const VerifyLimits& limits = {});
// Step 3 above, at the index's replay checkpoint, which must be the masterchain
// block `head`. Requires a Quarantined index with a verification record.
td::Result<VerifyOutcome> verify_index_at_head(tos_wallet_index::WalletIndexDb& db, VerifySource& source,
                                               const BlockIdExt& head, const VerifyLimits& limits = {});

// One bounded step of the block pass (stage 4a) over the window (B, H] of a
// Partial index verified at H, while replay is held at H. Phases, each
// resumable from the pass record and bound to H, H's state roots, B and the
// schema (a different binding discards the pass and its dependants):
// 1. authenticate the masterchain chain from H down to B + 1;
// 2. collect, interval by interval from B + 1 up to H, every transaction of
//    an account that H's state cannot vouch for (absent from it, or marked
//    unverified) into 0x35, each interval's identity matched to the chain;
// 3. compare, account by account: the newest kMaxEventsPerAccount rows above
//    the account's bound must equal the collected ones in lt, hash and
//    count; equal clears the account's mark, anything else refuses the
//    index. A collected account with no imported rows refuses it.
// Returns Working while work is left, Done when the pass is complete,
// Refused when the index is refused. Errors follow kVerifyTerminalError.
td::Result<VerifyOutcome> run_block_pass_step(tos_wallet_index::WalletIndexDb& db, VerifySource& source,
                                              const VerifyLimits& limits = {},
                                              const std::atomic<bool>* cancel = nullptr);
// Whether the block pass of the index is complete under its current binding.
td::Result<bool> block_pass_done(tos_wallet_index::WalletIndexDb& db);

td::Status terminal_gap(const std::string& block);

template <class Block, class ReadRoot>
td::Status walk_interval_blocks(const std::vector<Block>& blocks, ReadRoot read_root,
                                const std::function<td::Status(const td::Bits256&, uint64_t, const td::Bits256&)>& cb,
                                const std::atomic<bool>* cancel) {
  for (const auto& block : blocks) {
    if (cancel != nullptr && cancel->load()) {
      return td::Status::Error("block pass interrupted");
    }
    TRY_RESULT(root, read_root(block));
    if (!root) {
      return terminal_gap(block->id().to_str());
    }
    TRY_STATUS(walk_block_transactions(root.value(), cb));
  }
  return td::Status::OK();
}

// What the service's replay thread does next with its index. Replay, its
// drain and its pruning run only for a Quarantined index being replayed to
// the head (after its rows are placed) and for a Full one: a Partial index
// holds them at the verified head until the block pass and the ownership
// derivation are complete, across restarts too. Refused stops the service.
enum class ServiceAction { Prepare, Replay, BlockPass, HoldForOwnership, Stop };
inline ServiceAction next_service_action(tos_wallet_index::VerificationState state, bool prepared, bool pass_done) {
  switch (state) {
    case tos_wallet_index::VerificationState::Quarantined:
      return prepared ? ServiceAction::Replay : ServiceAction::Prepare;
    case tos_wallet_index::VerificationState::Partial:
      return pass_done ? ServiceAction::HoldForOwnership : ServiceAction::BlockPass;
    case tos_wallet_index::VerificationState::Full:
      return ServiceAction::Replay;
    case tos_wallet_index::VerificationState::Refused:
      return ServiceAction::Stop;
  }
  return ServiceAction::Stop;
}

// One bounded step of the ownership derivation (stage 4b) at the verified
// head H of a Partial index whose block pass is Done, replay still held:
// 1. every account of each H shard state, in key order, through
//    derive_ownership_range;
// 2. the recorded token wallets, then NFT owners, of accounts not active with
//    code at H, through reconcile_ownership_records;
// 3. the token work owed (queued candidates, unfinished blocks, parked
//    candidates): `drain` is set, and the service drains it against H's
//    states only;
// 4. when none is owed and nothing is degraded, the index becomes Full in
//    one batch, the candidate losses H superseded being cleared.
// Progress is per shard under the block pass's binding; H's state roots
// must still be the bound ones. Returns Working (with `drain` when token work
// is owed), Done when Full. Errors follow kVerifyTerminalError.
td::Result<VerifyOutcome> run_ownership_step(tos_wallet_index::WalletIndexDb& db, VerifySource& source,
                                             const VerifyLimits& limits = {},
                                             const std::atomic<bool>* cancel = nullptr);

// A state fetcher for the writer pinned to H's shard states: every token
// retry reads H, never a newer state. Install it (after
// release_wc0_index_state(), which drops the writer's cached state) for the
// drain of step 3.
tos_wallet_index::Wc0IndexStateFetcher make_head_state_fetcher(
    std::vector<tos_wallet_index::OwnershipHeadState> states);
// Pin the writer to H's states: drop the state it cached, then install the
// pinned fetcher. The service does this before draining the token work.
void pin_writer_to_head(std::vector<tos_wallet_index::OwnershipHeadState> states);

// Reason codes stored with an unverified account (0x31).
enum class UnverifiedReason : uint8_t { Absent = 1, StartsInWindow = 2 };

// The retry of a verification step after a retryable error. A fault that
// never clears must not look like verification in progress: /readyz shows
// the attempts, since when they fail and the last error, the delay grows to
// a cap, and the log line is rate-limited. Times passed in: `now` is
// monotonic seconds, `unix_now` wall-clock seconds.
class VerifyRetry {
 public:
  static constexpr double kFirstDelaySeconds = 5;
  static constexpr double kMaxDelaySeconds = 300;
  static constexpr double kLogIntervalSeconds = 300;
  static constexpr size_t kMaxErrorBytes = 512;
  // Record a failure; returns whether it should be logged now.
  bool failed(td::Slice error, double now, uint32_t unix_now);
  // A step succeeded (or legitimately waits for the node): failures reset.
  void succeeded();
  // When the next attempt is due (monotonic); 0 when nothing failed.
  double next_attempt() const;
  uint64_t attempts() const;
  // The delay after `attempts` consecutive failures: 5 s doubling to 300 s.
  static double delay_after(uint64_t attempts);
  // The error as reported: at most kMaxErrorBytes, never splitting a UTF-8
  // sequence.
  static std::string truncated(td::Slice error);
  // `null`, or {"attempts":N,"since":T,"last_error":"..."}.
  std::string json() const;

 private:
  mutable std::mutex mutex_;
  uint64_t attempts_ = 0;
  uint32_t since_ = 0;
  std::string last_error_;
  double next_attempt_ = 0;
  double last_logged_ = 0;
};

// Whether, and how, the index may be served; read by the RPC threads.
class ServingGate {
 public:
  explicit ServingGate(bool allow_partial) : allow_partial_(allow_partial) {
  }
  void set(tos_wallet_index::VerificationState state) {
    state_.store(static_cast<uint8_t>(state));
  }
  void set_horizon(uint32_t seqno, uint32_t unix_time, uint64_t unverified) {
    horizon_seqno_.store(seqno);
    horizon_time_.store(unix_time);
    unverified_.store(unverified);
    horizon_known_.store(true);
  }
  tos_wallet_index::VerificationState state() const {
    return static_cast<tos_wallet_index::VerificationState>(state_.load());
  }
  // Full always; Partial only when the operator allowed it.
  bool serving() const {
    auto s = state();
    return s == tos_wallet_index::VerificationState::Full ||
           (allow_partial_ && s == tos_wallet_index::VerificationState::Partial);
  }
  bool partial() const {
    return state() == tos_wallet_index::VerificationState::Partial;
  }
  // Replay is held at the verified head while the block pass and the
  // ownership derivation run; the index is never ready meanwhile.
  void hold(std::string phase) {
    std::lock_guard<std::mutex> guard(phase_mutex_);
    held_ = true;
    phase_ = std::move(phase);
  }
  void release() {
    std::lock_guard<std::mutex> guard(phase_mutex_);
    held_ = false;
    phase_.clear();
  }
  bool held() const {
    std::lock_guard<std::mutex> guard(phase_mutex_);
    return held_;
  }
  // `,"verification":...,"verified_horizon":...,"verification_retry":...`
  // for the /readyz body.
  std::string json_fields() const;
  VerifyRetry retry;

 private:
  bool allow_partial_;
  mutable std::mutex phase_mutex_;
  bool held_ = false;
  std::string phase_;
  std::atomic<uint8_t> state_{static_cast<uint8_t>(tos_wallet_index::VerificationState::Quarantined)};
  std::atomic<uint32_t> horizon_seqno_{0};
  std::atomic<uint32_t> horizon_time_{0};
  std::atomic<uint64_t> unverified_{0};
  std::atomic<bool> horizon_known_{false};
};

const char* verification_state_name(tos_wallet_index::VerificationState state);

}  // namespace tos::services
