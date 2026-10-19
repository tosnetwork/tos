/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <cstddef>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <utility>
#include <vector>

#include "td/actor/MultiPromise.h"
#include "validator/validator.h"

namespace tos::validator {

// Bounds on what confirmations from trusted shard-block verifiers may make
// this node retain before those blocks are needed.
struct ShardBlockConfirmationLimits {
  // A collator refuses to build a shard block more than 8 blocks past the one
  // the masterchain registers for that shard, so each masterchain block can
  // register at most that much shard progress. A confirmation further ahead of
  // this node's masterchain view than 8 blocks for each of
  // kTolerableMasterchainLag masterchain blocks names a block this node cannot
  // need before it has caught up. It is held, not counted: a verifier sends
  // each confirmation once, so a refused genuine one would otherwise be lost.
  static constexpr BlockSeqno kUnregisteredChainLimit = 8;
  static constexpr BlockSeqno kTolerableMasterchainLag = 16;
  BlockSeqno max_lookahead = kUnregisteredChainLimit * kTolerableMasterchainLag;
  // Entries created by peer confirmations, all peers together and per peer.
  std::size_t max_entries = 16384;
  std::size_t max_bytes = std::size_t{8} << 20;
  std::size_t max_entries_per_peer = 4096;
  std::size_t max_bytes_per_peer = std::size_t{2} << 20;
  // Confirmations held for a later retry because they were beyond the
  // lookahead or over a budget, per peer and in total. Each holds one block
  // id. Past these the newest is dropped and its peer is asked to send its
  // confirmations again (see shard-block-subscription.h).
  std::size_t max_deferred_per_peer = 1024;
  std::size_t max_deferred = 4096;
};

// The blocks awaited or confirmed by trusted shard-block verifiers, and who
// confirmed them. Owned by one actor; not thread-safe.
//
// A local wait creates the entry it waits on without limit: the local
// collator and validator only wait for blocks they are processing, and a wait
// that found no entry would complete as if no confirmation were required. A
// peer confirmation creates an entry only within the lookahead and within its
// own and the global entry and byte budgets; the entry is charged to that peer
// until it is pruned, which happens once the masterchain registers the block's
// shard at or past it. A confirmation that cannot create its entry yet,
// because it is beyond the lookahead or over a budget, is held within bounded
// per-peer and global queues and offered again whenever that may have changed:
// the masterchain advances, entries are released, the configuration changes,
// or a local wait creates the entry. If the queues overflow, the dropped
// confirmation's peer is recorded so the owner can ask it to send its
// confirmations again.
class ShardBlockConfirmations {
 public:
  using Peer = adnl::AdnlNodeIdShort;
  // The seqno of the top block the masterchain registers for the shard of the
  // given block, or nullopt when the masterchain registers no such shard.
  using RegisteredSeqno = std::function<std::optional<BlockSeqno>(const BlockIdExt &)>;

  enum class ConfirmResult {
    Accepted,       // counted; the block still needs more confirmations
    Confirmed,      // counted, and it completed the required confirmations
    Duplicate,      // this peer already confirmed the block
    UnknownSource,  // the peer is not trusted for the block's shard
    NotTracked,     // the shard is not configured, or the block is outdated
    Deferred,       // too far ahead of the registered shard top, or the shard is unknown; held for retry
    PeerBudget,     // the peer's entry or byte budget is exhausted; held for retry
    GlobalBudget,   // the global entry or byte budget is exhausted; held for retry
    Dropped,        // could not be held: the retry queues are full; the peer is asked to resend
  };

  ShardBlockConfirmations(RegisteredSeqno registered, ShardBlockConfirmationLimits limits = {})
      : registered_(std::move(registered)), limits_(limits) {
  }

  // Replaces the verifier configuration. Entries for shards no longer
  // configured release their waiters; confirmations by nodes still trusted for
  // the block's shard are carried over. Entries a local wait created stay
  // local. A peer-created entry is re-admitted against the budgets on behalf
  // of its creator or, if the creator is no longer admitted, of another node
  // that confirmed it; failing both it is dropped.
  void set_config(td::Ref<ShardBlockVerifierConfig> config) {
    auto old_config = std::move(config_);
    config_ = std::move(config);
    auto old_blocks = std::move(blocks_);
    blocks_.clear();
    peers_.clear();
    total_ = {};
    for (auto &[block_id, old_info] : old_blocks) {
      BlockInfo *info = nullptr;
      if (!old_info.creator || !old_info.promises.empty()) {
        info = get_or_create_local(block_id);
      } else {
        std::vector<Peer> sponsors{*old_info.creator};
        if (old_config.not_null()) {
          const auto &old_nodes = old_config->shards[old_info.config_shard_idx].trusted_nodes;
          for (std::size_t i = 0; i < old_info.confirmed_by.size() && i < old_nodes.size(); ++i) {
            if (old_info.confirmed_by[i]) {
              sponsors.push_back(old_nodes[i]);
            }
          }
        }
        for (const auto &sponsor : sponsors) {
          if (admit(sponsor, block_id) == ConfirmResult::Accepted) {
            info = create(block_id, sponsor);
            break;
          }
        }
      }
      if (info == nullptr) {
        old_info.finalize_promises();
        continue;
      }
      info->promises = std::move(old_info.promises);
      if (info->confirmed) {
        info->finalize_promises();
      }
      if (old_config.is_null()) {
        continue;
      }
      const auto &old_nodes = old_config->shards[old_info.config_shard_idx].trusted_nodes;
      for (std::size_t i = 0; i < old_info.confirmed_by.size() && i < old_nodes.size(); ++i) {
        if (old_info.confirmed_by[i]) {
          count_confirmation(*info, old_nodes[i]);
        }
      }
    }
    // Deferred confirmations are offered again under the new configuration.
    retry_deferred();
  }

  // Waits until each of `blocks` is confirmed. A block whose shard is not
  // configured, or which the masterchain already registers, needs nothing.
  void wait(const std::vector<BlockIdExt> &blocks, td::Promise<td::Unit> promise) {
    td::MultiPromise mp;
    auto ig = mp.init_guard();
    ig.add_promise(std::move(promise));
    bool created = false;
    for (const BlockIdExt &block_id : blocks) {
      bool existed = blocks_.contains(block_id);
      BlockInfo *info = get_or_create_local(block_id);
      created = created || (info != nullptr && !existed);
      if (info != nullptr && !info->confirmed) {
        info->promises.push_back(ig.get_promise());
      }
    }
    if (created) {
      // Held confirmations for these blocks count now that their entries exist.
      retry_deferred();
    }
  }

  ConfirmResult confirm(const Peer &src, const BlockIdExt &block_id) {
    if (config_.is_null()) {
      return ConfirmResult::NotTracked;
    }
    auto it = blocks_.find(block_id);
    BlockInfo *info = nullptr;
    if (it != blocks_.end()) {
      info = &it->second;
    } else {
      int shard_idx = config_shard_idx(block_id.shard_full());
      if (shard_idx < 0 || is_outdated(block_id)) {
        return ConfirmResult::NotTracked;
      }
      if (trusted_index(static_cast<std::size_t>(shard_idx), src) < 0) {
        return ConfirmResult::UnknownSource;
      }
      auto admission = admit(src, block_id);
      if (admission == ConfirmResult::Deferred || admission == ConfirmResult::PeerBudget ||
          admission == ConfirmResult::GlobalBudget) {
        return hold(src, block_id, admission);
      }
      if (admission != ConfirmResult::Accepted) {
        return admission;
      }
      info = create(block_id, src);
    }
    return count_confirmation(*info, src);
  }

  // Drops every entry the masterchain now registers, completing its waiters
  // and releasing its charge, then offers the held confirmations again.
  void prune_registered() {
    for (auto it = blocks_.begin(); it != blocks_.end();) {
      if (is_outdated(it->first)) {
        it->second.finalize_promises();
        release(it->second);
        it = blocks_.erase(it);
      } else {
        ++it;
      }
    }
    retry_deferred();
  }

  std::size_t size() const {
    return blocks_.size();
  }
  std::size_t peer_entries() const {
    return total_.entries;
  }
  std::size_t peer_bytes() const {
    return total_.bytes;
  }
  std::size_t peer_entries(const Peer &peer) const {
    auto it = peers_.find(peer);
    return it == peers_.end() ? 0 : it->second.entries;
  }
  std::size_t peer_bytes(const Peer &peer) const {
    auto it = peers_.find(peer);
    return it == peers_.end() ? 0 : it->second.bytes;
  }
  // Peers whose confirmations were dropped since the last call, so the owner
  // can ask them to send their confirmations again.
  std::set<Peer> take_resend_requests() {
    return std::exchange(resend_requests_, {});
  }
  // For every local wait not yet resolved, the trusted nodes of its shard
  // that have not confirmed the block, as (node, configured shard) pairs: the
  // subscriptions recovery must keep asking while the wait is outstanding.
  std::set<std::pair<Peer, ShardIdFull>> unresolved_wait_sources() const {
    std::set<std::pair<Peer, ShardIdFull>> result;
    if (config_.is_null()) {
      return result;
    }
    for (const auto &[block_id, info] : blocks_) {
      if (info.confirmed || info.promises.empty()) {
        continue;
      }
      const auto &shard_config = config_->shards[info.config_shard_idx];
      for (std::size_t i = 0; i < shard_config.trusted_nodes.size() && i < info.confirmed_by.size(); ++i) {
        if (!info.confirmed_by[i]) {
          result.emplace(shard_config.trusted_nodes[i], shard_config.shard_id);
        }
      }
    }
    return result;
  }
  std::size_t deferred() const {
    return deferred_total_;
  }
  std::size_t deferred(const Peer &peer) const {
    auto it = deferred_.find(peer);
    return it == deferred_.end() ? 0 : it->second.size();
  }
  bool contains(const BlockIdExt &block_id) const {
    return blocks_.contains(block_id);
  }
  bool is_confirmed(const BlockIdExt &block_id) const {
    auto it = blocks_.find(block_id);
    return it != blocks_.end() && it->second.confirmed;
  }
  const ShardBlockConfirmationLimits &limits() const {
    return limits_;
  }

  // What one peer-created entry is charged: the map node holding it and the
  // per-verifier confirmation bits. Waiters are local and not charged.
  std::size_t entry_charge(std::size_t trusted_nodes) const {
    constexpr std::size_t kMapNodeOverhead = 4 * sizeof(void *);
    return sizeof(std::pair<const BlockIdExt, BlockInfo>) + kMapNodeOverhead + (trusted_nodes + 7) / 8;
  }

 private:
  struct BlockInfo {
    std::size_t config_shard_idx = 0;
    std::vector<bool> confirmed_by;
    td::uint32 confirmed_by_cnt = 0;
    bool confirmed = false;
    std::optional<Peer> creator;
    std::size_t charge = 0;
    std::vector<td::Promise<td::Unit>> promises;

    void finalize_promises() {
      for (auto &promise : promises) {
        promise.set_value(td::Unit());
      }
      promises.clear();
    }
  };
  struct Usage {
    std::size_t entries = 0;
    std::size_t bytes = 0;
  };

  int config_shard_idx(const ShardIdFull &shard) const {
    for (std::size_t i = 0; i < config_->shards.size(); i++) {
      if (shard_intersects(shard, config_->shards[i].shard_id)) {
        return static_cast<int>(i);
      }
    }
    return -1;
  }

  int trusted_index(std::size_t shard_idx, const Peer &src) const {
    const auto &nodes = config_->shards[shard_idx].trusted_nodes;
    for (std::size_t i = 0; i < nodes.size(); ++i) {
      if (nodes[i] == src) {
        return static_cast<int>(i);
      }
    }
    return -1;
  }

  bool is_outdated(const BlockIdExt &block_id) const {
    auto top = registered_(block_id);
    return top && *top >= block_id.seqno();
  }

  // Whether `src` may create an entry for `block_id`. Read-only.
  ConfirmResult admit(const Peer &src, const BlockIdExt &block_id) const {
    int shard_idx = config_shard_idx(block_id.shard_full());
    if (shard_idx < 0) {
      return ConfirmResult::NotTracked;
    }
    if (trusted_index(static_cast<std::size_t>(shard_idx), src) < 0) {
      return ConfirmResult::UnknownSource;
    }
    auto top = registered_(block_id);
    if (!top) {
      return ConfirmResult::Deferred;
    }
    if (*top >= block_id.seqno()) {
      return ConfirmResult::NotTracked;
    }
    if (block_id.seqno() - *top > limits_.max_lookahead) {
      return ConfirmResult::Deferred;
    }
    std::size_t charge = entry_charge(config_->shards[static_cast<std::size_t>(shard_idx)].trusted_nodes.size());
    Usage peer;
    if (auto it = peers_.find(src); it != peers_.end()) {
      peer = it->second;
    }
    if (peer.entries >= limits_.max_entries_per_peer || charge > limits_.max_bytes_per_peer ||
        peer.bytes > limits_.max_bytes_per_peer - charge) {
      return ConfirmResult::PeerBudget;
    }
    if (total_.entries >= limits_.max_entries || charge > limits_.max_bytes ||
        total_.bytes > limits_.max_bytes - charge) {
      return ConfirmResult::GlobalBudget;
    }
    return ConfirmResult::Accepted;
  }

  // Creates an entry; with a creator, charges it. Call only after admit()
  // accepted it, or for a local wait.
  BlockInfo *create(const BlockIdExt &block_id, std::optional<Peer> creator) {
    int shard_idx = config_shard_idx(block_id.shard_full());
    if (shard_idx < 0) {
      return nullptr;
    }
    const auto &shard_config = config_->shards[static_cast<std::size_t>(shard_idx)];
    BlockInfo &info = blocks_[block_id];
    info.config_shard_idx = static_cast<std::size_t>(shard_idx);
    info.confirmed_by.assign(shard_config.trusted_nodes.size(), false);
    info.confirmed = shard_config.required_confirms == 0;
    if (creator) {
      info.creator = creator;
      info.charge = entry_charge(shard_config.trusted_nodes.size());
      auto &peer = peers_[*creator];
      peer.entries += 1;
      peer.bytes += info.charge;
      total_.entries += 1;
      total_.bytes += info.charge;
    }
    return &info;
  }

  BlockInfo *get_or_create_local(const BlockIdExt &block_id) {
    auto it = blocks_.find(block_id);
    if (it != blocks_.end()) {
      return &it->second;
    }
    if (config_.is_null() || config_shard_idx(block_id.shard_full()) < 0 || is_outdated(block_id)) {
      return nullptr;
    }
    return create(block_id, std::nullopt);
  }

  void release(BlockInfo &info) {
    if (!info.creator) {
      return;
    }
    auto it = peers_.find(*info.creator);
    if (it != peers_.end()) {
      it->second.entries -= 1;
      it->second.bytes -= info.charge;
      if (it->second.entries == 0) {
        peers_.erase(it);
      }
    }
    total_.entries -= 1;
    total_.bytes -= info.charge;
    info.creator.reset();
    info.charge = 0;
  }

  // Holds a confirmation that could not create its entry, for `reason`, or
  // drops it and records its peer when the queues are full.
  ConfirmResult hold(const Peer &src, const BlockIdExt &block_id, ConfirmResult reason) {
    auto &queue = deferred_[src];
    for (const auto &held : queue) {
      if (held == block_id) {
        return reason;
      }
    }
    if (queue.size() >= limits_.max_deferred_per_peer || deferred_total_ >= limits_.max_deferred) {
      if (queue.empty()) {
        deferred_.erase(src);
      }
      resend_requests_.insert(src);
      return ConfirmResult::Dropped;
    }
    queue.push_back(block_id);
    ++deferred_total_;
    return reason;
  }

  // Offers every held confirmation again, in arrival order. confirm() counts
  // the ones that can now create or reach their entry, holds again the ones
  // still refused for the lookahead or a budget, and discards the ones no
  // longer relevant (outdated, untracked, untrusted).
  void retry_deferred() {
    if (config_.is_null() || deferred_total_ == 0) {
      return;
    }
    auto held = std::move(deferred_);
    deferred_.clear();
    deferred_total_ = 0;
    for (auto &[src, queue] : held) {
      for (const auto &block_id : queue) {
        confirm(src, block_id);
      }
    }
  }

  ConfirmResult count_confirmation(BlockInfo &info, const Peer &src) {
    const auto &shard_config = config_->shards[info.config_shard_idx];
    int src_idx = trusted_index(info.config_shard_idx, src);
    if (src_idx < 0) {
      return ConfirmResult::UnknownSource;
    }
    if (info.confirmed_by[static_cast<std::size_t>(src_idx)]) {
      return ConfirmResult::Duplicate;
    }
    info.confirmed_by[static_cast<std::size_t>(src_idx)] = true;
    ++info.confirmed_by_cnt;
    if (info.confirmed_by_cnt == shard_config.required_confirms) {
      info.confirmed = true;
      info.finalize_promises();
      return ConfirmResult::Confirmed;
    }
    return ConfirmResult::Accepted;
  }

  RegisteredSeqno registered_;
  ShardBlockConfirmationLimits limits_;
  td::Ref<ShardBlockVerifierConfig> config_;
  std::map<BlockIdExt, BlockInfo> blocks_;
  std::map<Peer, Usage> peers_;
  Usage total_;
  std::map<Peer, std::vector<BlockIdExt>> deferred_;
  std::size_t deferred_total_ = 0;
  std::set<Peer> resend_requests_;
};

}  // namespace tos::validator
