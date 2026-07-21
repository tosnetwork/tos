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

    Copyright 2017-2020 Telegram Systems LLP
    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include <set>

#include "interfaces/validator-manager.h"
#include "td/actor/SharedFuture.h"

namespace tos {

namespace validator {

class ShardClient : public td::actor::Actor {
 private:
  struct DownloadableShard {
    BlockIdExt shard;
    td::uint32 split_depth;
  };

  td::Ref<ValidatorManagerOptions> opts_;

  BlockHandle masterchain_block_handle_;
  td::Ref<MasterchainState> init_mode_mc_state_;
  BlockSeqno processed_masterchain_block_{0};

  std::vector<td::actor::ActorOwn<ShardClient>> children_;

  bool started_ = false;
  bool init_mode_ = false;
  td::actor::SharedFuture<td::Unit> initialize_waiter_;
  std::vector<td::Promise<>> waiters_;

  td::actor::ActorId<ValidatorManager> manager_;
  td::Promise<> initialize_promise_;

  td::actor::StartedTask<> wait() {
    auto [task, promise] = td::actor::StartedTask<>::make_bridge();
    waiters_.push_back(std::move(promise));
    return std::move(task);
  }

  void notify() {
    auto waiters = std::move(waiters_);
    waiters_.clear();
    for (auto &p : waiters) {
      p.set_value(td::Unit{});
    }
  }

 public:
  ShardClient(td::Ref<ValidatorManagerOptions> opts, BlockHandle masterchain_block_handle,
              td::Ref<MasterchainState> masterchain_state, td::actor::ActorId<ValidatorManager> manager,
              td::Promise<> promise)
      : opts_(std::move(opts))
      , masterchain_block_handle_(masterchain_block_handle)
      , init_mode_mc_state_(std::move(masterchain_state))
      , manager_(manager)
      , initialize_promise_(std::move(promise)) {
    init_mode_ = true;
  }
  ShardClient(td::Ref<ValidatorManagerOptions> opts, td::actor::ActorId<ValidatorManager> manager, td::Promise<> promise)
      : opts_(std::move(opts)), manager_(manager), initialize_promise_(std::move(promise)) {
  }

  void start_up() override;

  td::actor::Task<> initialize();
  td::actor::Task<> initialize_init_mode();

  void start();
  td::actor::Task<> run();
  td::actor::Task<> run_preprocess();

  td::actor::Task<> apply_all_shards(td::Ref<MasterchainState> mc_state);
  td::actor::Task<> apply_shard(BlockIdExt block_id);
  td::actor::Task<> wait_shard_states(td::Ref<MasterchainState> mc_state);
  td::actor::Task<td::Ref<MasterchainState>> wait_mc_state(BlockHandle handle);

  void new_masterchain_block_notification();
  void get_processed_masterchain_block(td::Promise<BlockSeqno> promise);
  td::actor::Task<> force_update_shard_client_ex(BlockHandle handle, td::Ref<MasterchainState> state);

  void update_options(td::Ref<ValidatorManagerOptions> opts);

 private:
  static constexpr td::uint32 SHARD_CLIENT_PRIORITY = 2;
  static constexpr td::uint32 MAX_PREPROCESS_DELTA = 10;
};

}  // namespace validator

}  // namespace tos
