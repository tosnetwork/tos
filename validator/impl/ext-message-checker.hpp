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

#include <functional>
#include <memory>

#include "block/mc-config.h"
#include "interfaces/validator-manager.h"
#include "td/actor/coro_utils.h"

#include "external-message.hpp"

namespace tos::validator {

// Off-pool worker for the expensive, pool-state-independent part of external-message admission:
// structural parsing, workchain policy checks, shard-state resolution, account lookup and the
// full VM execution of recv_external (including signature verification inside the VM).
class ExtMessageChecker : public td::actor::Actor {
 public:
  explicit ExtMessageChecker(td::actor::ActorId<ValidatorManager> manager) : manager_(std::move(manager)) {
  }

  struct StageTimings {
    double parse{0};
    double fetch_state{0};
    double lookup{0};
    double vm{0};
  };

  struct CheckedExtMsg {
    td::Ref<ExtMessage> message;
    StageTimings timings;
  };

  td::actor::Task<CheckedExtMsg> check(td::BufferSlice data, block::SizeLimitsConfig::ExtMsgLimits limits,
                                       td::Ref<MasterchainState> mc_state);

  void alarm() override;

 private:
  td::actor::ActorId<ValidatorManager> manager_;

  // ConfigInfo is pinned per task across shard-state awaits. This avoids pairing an older state
  // with a newer config when another coroutine on the same checker advances the config cache.
  struct ConfigSnapshot {
    BlockIdExt mc_block_id;
    std::shared_ptr<block::ConfigInfo> config;
  };
  BlockIdExt cached_config_mc_block_id_;
  std::shared_ptr<block::ConfigInfo> cached_config_;
  td::Result<ConfigSnapshot> resolve_config(const td::Ref<MasterchainState>& mc_state);

  struct ExecConfigKey {
    BlockIdExt mc_block_id;
    WorkchainId workchain{workchainInvalid};
    UnixTime utime{0};

    bool operator<(const ExecConfigKey& other) const {
      if (mc_block_id != other.mc_block_id) {
        return mc_block_id < other.mc_block_id;
      }
      if (workchain != other.workchain) {
        return workchain < other.workchain;
      }
      return utime < other.utime;
    }
  };
  struct ExecConfigPair {
    std::unique_ptr<ExtMessageQ::ExecutionConfig> nolog;
    std::unique_ptr<ExtMessageQ::ExecutionConfig> log;
  };
  std::map<ExecConfigKey, ExecConfigPair> exec_configs_;

  td::Status run_message(WorkchainId wc, block::Account acc,
                         const std::function<td::Result<block::Account>()>& rebuild_account, UnixTime utime,
                         LogicalTime lt, const td::Ref<vm::Cell>& msg_root, ExecConfigPair& exec_config);

  struct CachedState {
    BlockIdExt block_id;
    td::Ref<ShardState> state;
    td::Ref<vm::CellSlice> accounts_root;
    UnixTime utime{0};
    LogicalTime lt{0};
  };
  std::map<ShardIdFull, CachedState> states_;

  struct ResolvedState {
    td::Ref<vm::CellSlice> accounts_root;
    UnixTime utime{0};
    LogicalTime lt{0};
  };
  td::actor::Task<ResolvedState> resolve_state(td::Ref<MasterchainState> mc_state, AccountIdPrefixFull prefix);

  td::Result<bool> check_workchain_execution(const td::Ref<ExtMessage>& message,
                                             block::SizeLimitsConfig::ExtMsgLimits limits,
                                             const block::ConfigInfo& config) const;
};

}  // namespace tos::validator
