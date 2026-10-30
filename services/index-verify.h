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
};

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
};

enum class VerifyStep {
  // The step finished; for the head check the index is now Partial.
  Done,
  // The node is not there yet (it has not reached the checkpoint): try again
  // later. Nothing was decided.
  Wait,
  // The snapshot contradicts the chain: the index is now Refused.
  Refused,
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
};

// Step 1 above. Requires a Quarantined index without a verification record.
td::Result<VerifyOutcome> prepare_quarantined_index(tos_wallet_index::WalletIndexDb& db, VerifySource& source,
                                                    const VerifyLimits& limits = {});
// Step 3 above, at the index's replay checkpoint, which must be the masterchain
// block `head`. Requires a Quarantined index with a verification record.
td::Result<VerifyOutcome> verify_index_at_head(tos_wallet_index::WalletIndexDb& db, VerifySource& source,
                                               const BlockIdExt& head, const VerifyLimits& limits = {});

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
  // `,"verification":...,"verified_horizon":...,"verification_retry":...`
  // for the /readyz body.
  std::string json_fields() const;
  VerifyRetry retry;

 private:
  bool allow_partial_;
  std::atomic<uint8_t> state_{static_cast<uint8_t>(tos_wallet_index::VerificationState::Quarantined)};
  std::atomic<uint32_t> horizon_seqno_{0};
  std::atomic<uint32_t> horizon_time_{0};
  std::atomic<uint64_t> unverified_{0};
  std::atomic<bool> horizon_known_{false};
};

const char* verification_state_name(tos_wallet_index::VerificationState state);

}  // namespace tos::services
