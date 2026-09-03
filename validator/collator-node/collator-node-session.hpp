/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once

#include <map>
#include <optional>

#include "interfaces/validator-manager.h"
#include "rldp/rldp.h"
#include "rldp2/rldp.h"

namespace tos::validator {

class ValidatorManager;

class CollatorNodeSession : public td::actor::Actor {
 public:
  CollatorNodeSession(ShardIdFull shard, std::vector<BlockIdExt> prev, td::Ref<block::ValidatorSet> validator_set,
                      BlockIdExt min_masterchain_block_id, bool can_generate, td::Ref<MasterchainState> state,
                      adnl::AdnlNodeIdShort local_id, td::Ref<ValidatorManagerOptions> opts,
                      td::actor::ActorId<ValidatorManager> manager, td::actor::ActorId<adnl::Adnl> adnl,
                      td::actor::ActorId<rldp2::Rldp> rldp);

  void start_up() override;
  void tear_down() override;

  void update_options(td::Ref<ValidatorManagerOptions> opts) {
    opts_ = std::move(opts);
  }

  void new_shard_block_accepted(BlockIdExt block_id, bool can_generate);

  void process_request(adnl::AdnlNodeIdShort src, std::vector<BlockIdExt> prev_blocks, BlockCandidatePriority priority,
                       Ed25519_PublicKey creator, td::Timestamp timeout, td::Promise<BlockCandidate> promise);
  void update_masterchain_config(td::Ref<MasterchainState> state);

 private:
  ShardIdFull shard_;
  std::vector<BlockIdExt> prev_;
  td::Ref<block::ValidatorSet> validator_set_;
  BlockIdExt min_masterchain_block_id_;
  bool can_generate_;
  adnl::AdnlNodeIdShort local_id_;
  td::Ref<ValidatorManagerOptions> opts_;
  td::actor::ActorId<ValidatorManager> manager_;
  td::actor::ActorId<adnl::Adnl> adnl_;
  td::actor::ActorId<rldp2::Rldp> rldp_;

  struct CacheEntry {
    bool started = false;
    td::Timestamp has_internal_query_at;
    td::Timestamp has_external_query_at;
    td::Timestamp has_result_at;
    BlockSeqno block_seqno = 0;
    std::vector<BlockIdExt> key;  // this entry's key in cache_, for self-erase on failure
    td::optional<BlockCandidate> result;
    td::CancellationTokenSource cancellation_token_source;
    std::vector<td::Promise<BlockCandidate>> promises;

    void cancel(td::Status reason);
  };

  // Upper bound on callers coalesced onto a single in-flight collation. Sized
  // from the validator set (each member may legitimately ask for the same
  // block once, plus this session's own internal request and a retry margin),
  // so a flood of identical requests cannot grow the waiter vector -- or the
  // per-waiter completion work -- without bound. Set in the constructor.
  size_t max_waiters_per_collation_ = 64;

  BlockSeqno next_block_seqno_;
  std::map<std::vector<BlockIdExt>, std::shared_ptr<CacheEntry>> cache_;

  // Upper bound on Collator actors running at once for this shard session.
  // Honest collation needs only a couple (the current block and maybe one
  // optimistic lookahead); the rest of the +10 seqno window exists for
  // reordering tolerance, not concurrency.
  static constexpr size_t MAX_CONCURRENT_COLLATIONS = 4;

  td::uint32 proto_version_ = 0;
  td::uint32 max_candidate_size_ = 0;

  void generate_block(std::vector<BlockIdExt> prev_blocks, td::optional<BlockCandidatePriority> o_priority,
                      td::Timestamp timeout, td::Promise<BlockCandidate> promise);
  void process_result(std::shared_ptr<CacheEntry> cache_entry, td::Result<BlockCandidate> R);
};

}  // namespace tos::validator
