/*
    This file is part of TOS Blockchain.

    TOS Blockchain is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include <functional>
#include <optional>
#include <string>
#include <utility>

#include "common/errorcode.h"
#include "td/db/KeyValue.h"
#include "td/utils/Slice.h"
#include "td/utils/Status.h"
#include "tos/tos-types.h"
#include "validator/consensus/validator-cleanup.h"

// Consensus-cleanup checkpoint.
//
// A retired validator session's consensus database holds the node's own votes.
// It may be deleted only once a masterchain block proves the session can never
// be recreated. State GC alone is too slow to provide that block (it never
// passes the last key block), and the applied masterchain state alone is not
// durable against rollback: truncation and hardfork installation lower it, and
// startup replays from an older init block. A node that reopened a deleted
// session could vote twice.
//
// The checkpoint is a durable, monotonic masterchain block, separate from the GC
// block. It only advances to a coherent applied shard-client block that extends
// it on the same chain, it is synced before any deletion relies on it, and it
// bounds three other mechanisms:
//  - state GC never advances past it, so its handle and state stay loadable;
//  - validator groups are not built or started until the applied head reaches
//    it, and a head on a branch that excludes it is refused;
//  - truncation and hardfork rollback below it, or off its branch, are refused.
//
// Importing persistent states or archives into an existing database, and the
// reinitialization path, never write the checkpoint. Restoring a whole older
// database backup replaces the checkpoint along with everything else and cannot
// be detected here: it is not a safe rollback for the same signing identity, for
// the same reason a truncation below the checkpoint is refused. Copying a
// consensus directory into a database without the checkpoint is unsupported.
//
// This header holds the pure parts (encoding, persistence helpers over a
// KeyValue, the head/rollback relation and the advancement state machine), so
// the safety logic is exercised by tests with the same functions the node uses.
namespace tos::validator::consensus {

// StateDb key. Raw local metadata, like the cleanup queue key.
constexpr td::Slice consensus_cleanup_checkpoint_key() {
  return td::Slice{"tos.state.consensus_cleanup_checkpoint"};
}

namespace detail {
constexpr unsigned char kCheckpointMagic[4] = {'T', 'C', 'C', 'P'};
constexpr uint32_t kCheckpointVersion = 1;
// magic(4) + version(4) + workchain(4) + shard(8) + seqno(4) + root_hash(32) + file_hash(32)
constexpr size_t kCheckpointEncodedSize = 4 + 4 + 4 + 8 + 4 + 32 + 32;
}  // namespace detail

// A checkpoint is always a full masterchain block id.
inline bool is_consensus_cleanup_checkpoint_id(const BlockIdExt& id) {
  return id.is_valid_full() && id.is_masterchain_ext();
}

inline std::string encode_consensus_cleanup_checkpoint(const BlockIdExt& id) {
  std::string out;
  out.reserve(detail::kCheckpointEncodedSize);
  out.append(reinterpret_cast<const char*>(detail::kCheckpointMagic), sizeof(detail::kCheckpointMagic));
  detail::put_u32_le(out, detail::kCheckpointVersion);
  detail::put_u32_le(out, static_cast<uint32_t>(id.id.workchain));
  detail::put_u64_le(out, static_cast<uint64_t>(id.id.shard));
  detail::put_u32_le(out, id.id.seqno);
  auto rh = id.root_hash.as_slice();
  auto fh = id.file_hash.as_slice();
  out.append(rh.data(), rh.size());
  out.append(fh.data(), fh.size());
  return out;
}

// Strict decode. A record that is not exactly one version-1 full masterchain id
// is an error, never an absent checkpoint: treating a damaged record as absent
// would silently drop the protection it carries.
inline td::Result<BlockIdExt> decode_consensus_cleanup_checkpoint(td::Slice value) {
  if (value.size() < 8) {
    return td::Status::Error(ErrorCode::error, PSLICE() << "consensus cleanup checkpoint record is truncated ("
                                                        << value.size() << " bytes)");
  }
  const auto* p = reinterpret_cast<const unsigned char*>(value.data());
  for (size_t i = 0; i < sizeof(detail::kCheckpointMagic); i++) {
    if (p[i] != detail::kCheckpointMagic[i]) {
      return td::Status::Error(ErrorCode::error, "consensus cleanup checkpoint record has a foreign format");
    }
  }
  auto version = detail::get_u32_le(p + 4);
  if (version != detail::kCheckpointVersion) {
    return td::Status::Error(ErrorCode::error,
                             PSLICE() << "consensus cleanup checkpoint record has unsupported version " << version);
  }
  if (value.size() != detail::kCheckpointEncodedSize) {
    return td::Status::Error(ErrorCode::error, PSLICE()
                                                   << "consensus cleanup checkpoint record has length " << value.size()
                                                   << ", expected " << detail::kCheckpointEncodedSize);
  }
  BlockIdExt id;
  id.id.workchain = static_cast<WorkchainId>(detail::get_u32_le(p + 8));
  id.id.shard = static_cast<ShardId>(detail::get_u64_le(p + 12));
  id.id.seqno = detail::get_u32_le(p + 20);
  id.root_hash.as_slice().copy_from(td::Slice{value.data() + 24, 32});
  id.file_hash.as_slice().copy_from(td::Slice{value.data() + 56, 32});
  if (!is_consensus_cleanup_checkpoint_id(id)) {
    return td::Status::Error(ErrorCode::error, PSLICE() << "consensus cleanup checkpoint record is not a full "
                                                           "masterchain block id: "
                                                        << id.to_str());
  }
  return id;
}

// Reads the checkpoint. nullopt means the key is genuinely absent (a fresh
// database or one that predates the checkpoint); only then may cleanup fall back
// to the GC block. A read error or a damaged record is an error.
inline td::Result<std::optional<BlockIdExt>> load_consensus_cleanup_checkpoint(td::KeyValue& kv) {
  std::string value;
  auto r_get = kv.get(consensus_cleanup_checkpoint_key(), value);
  if (r_get.is_error()) {
    return r_get.move_as_error_prefix("cannot read the consensus cleanup checkpoint: ");
  }
  if (r_get.move_as_ok() == td::KeyValue::GetStatus::NotFound) {
    return std::optional<BlockIdExt>{};
  }
  TRY_RESULT(id, decode_consensus_cleanup_checkpoint(td::Slice{value}));
  return std::optional<BlockIdExt>{id};
}

// Persists a new checkpoint in its own synced write batch. The store refuses a
// regression or a different block at the stored height, so the stored value is
// monotonic even if a caller is wrong; rewriting the stored value is a no-op.
// Ancestry cannot be checked here (it needs the candidate's state); the manager
// checks it before issuing the write.
inline td::Status store_consensus_cleanup_checkpoint(td::KeyValue& kv, const BlockIdExt& id) {
  if (!is_consensus_cleanup_checkpoint_id(id)) {
    return td::Status::Error(ErrorCode::error, PSLICE() << "refusing to store consensus cleanup checkpoint "
                                                        << id.to_str() << ": not a full masterchain block id");
  }
  TRY_RESULT(current, load_consensus_cleanup_checkpoint(kv));
  if (current) {
    if (*current == id) {
      return td::Status::OK();
    }
    if (id.seqno() <= current->seqno()) {
      return td::Status::Error(ErrorCode::error, PSLICE() << "refusing to move consensus cleanup checkpoint from "
                                                          << current->to_str() << " to " << id.to_str()
                                                          << ": it never moves back or sideways");
    }
  }
  auto value = encode_consensus_cleanup_checkpoint(id);
  TRY_STATUS(kv.begin_write_batch());
  auto set = kv.set(consensus_cleanup_checkpoint_key(), td::Slice{value});
  if (set.is_error()) {
    kv.abort_write_batch().ignore();
    return set.move_as_error_prefix("cannot write the consensus cleanup checkpoint: ");
  }
  // A synced write (RocksDb::commit_write_batch sets WriteOptions::sync). The
  // batch is consumed by the commit whether or not it succeeds.
  auto commit = kv.commit_write_batch();
  if (commit.is_error()) {
    return commit.move_as_error_prefix("cannot commit the consensus cleanup checkpoint: ");
  }
  return td::Status::OK();
}

// How a masterchain block relates to the checkpoint. `verifies_strict_ancestor`
// answers, from that block's own state, whether a given id is one of its strict
// masterchain ancestors (MasterchainState::check_old_mc_block_id(id, true)).
enum class CheckpointRelation {
  Behind,    // below the checkpoint height: still replaying toward it
  Reached,   // the checkpoint itself, or a verified descendant of it
  Conflict,  // at or above its height on a branch that excludes it
};

using VerifiesStrictAncestorFn = std::function<bool(const BlockIdExt&)>;

inline CheckpointRelation relate_to_consensus_cleanup_checkpoint(
    const BlockIdExt& checkpoint, const BlockIdExt& block, const VerifiesStrictAncestorFn& verifies_strict_ancestor) {
  if (block.seqno() < checkpoint.seqno()) {
    return CheckpointRelation::Behind;
  }
  if (block == checkpoint) {
    return CheckpointRelation::Reached;
  }
  if (block.seqno() == checkpoint.seqno()) {
    return CheckpointRelation::Conflict;
  }
  return verifies_strict_ancestor && verifies_strict_ancestor(checkpoint) ? CheckpointRelation::Reached
                                                                          : CheckpointRelation::Conflict;
}

// Error code for a refusal that must stop the process with exit status 2.
constexpr int kConsensusCheckpointRefusalCode = 2;

inline td::Status consensus_checkpoint_refusal(td::Slice message) {
  return td::Status::Error(kConsensusCheckpointRefusalCode, message);
}

inline bool is_consensus_checkpoint_refusal(const td::Status& status) {
  return status.is_error() && status.code() == kConsensusCheckpointRefusalCode;
}

// A rollback (truncation or hardfork installation) to `target` keeps the blocks up
// to and including it. It is allowed only when the target is the checkpoint or a
// verified descendant of it: rolling back below the checkpoint would let a node
// rebuild validator sessions whose own-vote records cleanup has already deleted,
// and the same signing identity could then vote twice. Removing the consensus
// directory or the checkpoint does not make that safe, so there is no override.
inline td::Status check_consensus_checkpoint_rollback(const std::optional<BlockIdExt>& checkpoint,
                                                      const BlockIdExt& target,
                                                      const VerifiesStrictAncestorFn& target_verifies_strict_ancestor) {
  if (!checkpoint) {
    return td::Status::OK();
  }
  auto relation = relate_to_consensus_cleanup_checkpoint(*checkpoint, target, target_verifies_strict_ancestor);
  if (relation == CheckpointRelation::Reached) {
    return td::Status::OK();
  }
  return consensus_checkpoint_refusal(
      PSLICE() << "refusing to roll the database back to " << target.to_str() << ": "
               << (relation == CheckpointRelation::Behind ? "it is below" : "it is not on the branch of")
               << " the consensus cleanup checkpoint " << checkpoint->to_str()
               << ". Consensus databases of sessions retired before the checkpoint may already be deleted, so "
                  "rolling back with the same validator signing identity could make this node vote twice; this is "
                  "prohibited. Recovery under a different signing identity needs a separately reviewed procedure.");
}

// The advancement state machine. The manager owns the actor glue and the block
// handles and states (Payload); this class owns the ordering rules:
//  - one write in flight; newer candidates coalesce into one pending candidate;
//  - a completion is applied only if it is the write in flight, and never moves
//    the installed checkpoint back;
//  - attempts are rate-limited on a monotonic clock, failed ones included;
//  - no write is issued while GC is advancing, and GC may neither start nor
//    persist an advance while a write is between issue and installation, nor
//    pass the installed checkpoint.
template <class Payload>
class ConsensusCleanupCheckpointTracker {
 public:
  // An attempt is allowed when the candidate is this many blocks past the
  // installed checkpoint, or this many seconds after the previous attempt, and
  // never sooner than kMinAttemptSeconds after it.
  static constexpr BlockSeqno kAdvanceBlocks = 64;
  static constexpr double kAdvanceSeconds = 60.0;
  static constexpr double kMinAttemptSeconds = 1.0;

  // What the manager knows at the moment of an attempt.
  struct Environment {
    bool gc_advancing = false;
    // The GC block, present only when its handle and state describe the same
    // block. It authorizes the first checkpoint.
    std::optional<BlockIdExt> gc_block;
    // The candidate's handle is applied and its loaded state is the candidate.
    std::function<bool(const Payload&)> candidate_coherent;
    // The candidate's state verifies the given id as a strict ancestor.
    std::function<bool(const Payload&, const BlockIdExt&)> candidate_verifies;
    // The manager's applied head is the given id or verifies it as an ancestor.
    std::function<bool(const BlockIdExt&)> head_covers;
  };

  enum class Outcome {
    Issued,   // a write was issued for the returned id
    Idle,     // nothing to do
    Waiting,  // a candidate is kept for a later attempt
    Dropped,  // the candidate was refused and discarded
  };

  struct Attempt {
    Outcome outcome = Outcome::Idle;
    BlockIdExt id;
    std::string reason;
  };

  void set_installed(std::optional<BlockIdExt> id) {
    installed_ = std::move(id);
  }
  const std::optional<BlockIdExt>& installed() const {
    return installed_;
  }
  const std::optional<BlockIdExt>& in_flight() const {
    return in_flight_;
  }
  bool has_pending() const {
    return pending_.has_value();
  }

  // Offers a candidate. It replaces an older pending candidate; an older or equal
  // one than what is pending is ignored.
  void offer(const BlockIdExt& id, Payload payload) {
    if (pending_ && pending_->first.seqno() >= id.seqno()) {
      return;
    }
    pending_.emplace(id, std::move(payload));
  }

  // GC may start advancing from `gc_seqno` to the next block.
  bool gc_may_start_advance(BlockSeqno gc_seqno) const {
    if (in_flight_) {
      return false;
    }
    if (!installed_) {
      return true;
    }
    // The next GC block is gc_seqno + 1; it may equal the checkpoint (state GC
    // deletes strictly older states only), never pass it.
    if (gc_seqno >= installed_->seqno()) {
      return false;
    }
    return true;
  }

  // GC may persist a new GC block at `new_gc_seqno`.
  bool gc_may_persist(BlockSeqno new_gc_seqno) const {
    if (in_flight_) {
      return false;
    }
    return !installed_ || new_gc_seqno <= installed_->seqno();
  }

  // Tries to issue a write. On Issued the caller writes the returned id and then
  // reports the result with complete().
  Attempt try_issue(double now, const Environment& env) {
    if (in_flight_) {
      return {Outcome::Idle, {}, "a checkpoint write is in flight"};
    }
    if (!pending_) {
      return {Outcome::Idle, {}, "no candidate"};
    }
    auto id = pending_->first;
    if (env.gc_advancing) {
      return {Outcome::Waiting, id, "GC is advancing; the candidate is revalidated afterwards"};
    }
    if (!is_consensus_cleanup_checkpoint_id(id)) {
      return drop(id, "not a full masterchain block id");
    }
    if (!env.candidate_coherent || !env.candidate_coherent(pending_->second)) {
      return drop(id, "the candidate is not applied or its state does not match it");
    }
    if (installed_) {
      if (id == *installed_) {
        return drop(id, "already the checkpoint");
      }
      if (id.seqno() <= installed_->seqno()) {
        return drop(id, PSTRING() << "not above the checkpoint " << installed_->to_str());
      }
      if (!env.candidate_verifies || !env.candidate_verifies(pending_->second, *installed_)) {
        return drop(
            id, PSTRING() << "its state does not verify the checkpoint " << installed_->to_str() << " as an ancestor");
      }
    } else {
      if (!env.gc_block) {
        return drop(id, "the GC block handle and state do not match");
      }
      const auto& gc = *env.gc_block;
      bool extends_gc = id == gc || (id.seqno() > gc.seqno() && env.candidate_verifies &&
                                     env.candidate_verifies(pending_->second, gc));
      if (!extends_gc) {
        return drop(id, PSTRING() << "it is neither the GC block " << gc.to_str() << " nor a verified descendant");
      }
    }
    if (!env.head_covers || !env.head_covers(id)) {
      return {Outcome::Waiting, id, "the applied masterchain head has not reached the candidate"};
    }
    if (last_attempt_) {
      double elapsed = now - *last_attempt_;
      if (elapsed < kMinAttemptSeconds) {
        return {Outcome::Waiting, id, "rate limited"};
      }
      if (elapsed < kAdvanceSeconds && !far_enough(id)) {
        return {Outcome::Waiting, id, "rate limited"};
      }
    }
    last_attempt_ = now;
    in_flight_ = id;
    in_flight_payload_ = std::move(pending_->second);
    pending_.reset();
    return {Outcome::Issued, id, {}};
  }

  // The result of a write. Returns the payload to install when the write is the
  // one in flight, succeeded, and moves the checkpoint forward; nullopt otherwise
  // (a stale or failed completion changes nothing).
  std::optional<Payload> complete(const BlockIdExt& id, bool ok) {
    if (!in_flight_ || !(*in_flight_ == id)) {
      return std::nullopt;
    }
    in_flight_.reset();
    auto payload = std::move(in_flight_payload_);
    in_flight_payload_.reset();
    if (!ok || !payload) {
      return std::nullopt;
    }
    if (installed_ && id.seqno() <= installed_->seqno()) {
      return std::nullopt;
    }
    installed_ = id;
    return payload;
  }

 private:
  bool far_enough(const BlockIdExt& id) const {
    if (!installed_) {
      return true;
    }
    // installed + kAdvanceBlocks without overflow: id.seqno() - installed >= kAdvanceBlocks,
    // and id.seqno() > installed is already established by the caller.
    return id.seqno() > installed_->seqno() && id.seqno() - installed_->seqno() >= kAdvanceBlocks;
  }

  Attempt drop(const BlockIdExt& id, std::string reason) {
    pending_.reset();
    return {Outcome::Dropped, id, std::move(reason)};
  }

  std::optional<BlockIdExt> installed_;
  std::optional<BlockIdExt> in_flight_;
  std::optional<Payload> in_flight_payload_;
  std::optional<std::pair<BlockIdExt, Payload>> pending_;
  std::optional<double> last_attempt_;
};

}  // namespace tos::validator::consensus
