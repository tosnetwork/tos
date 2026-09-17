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

#include "auth/native-collation-authority.h"

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
  // Established by the node from its own zero state. Fetched once it exists and
  // never rebuilt here: the chain domain lives in the registry this would be
  // used to check, so a context derived locally would have that registry
  // confirm its own name.
  std::shared_ptr<const tos::auth::ChainContext> validator_auth_chain_;
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

  // `authority` is called immediately before each execution attempt. It may
  // therefore be called again for the diagnostic logging run, but it creates a
  // fresh host from material admitted once before run_message: host state and
  // work allowances are independent without re-opening attacker-chosen bytes.
  td::Status run_message(WorkchainId wc, block::Account acc,
                         const std::function<td::Result<block::Account>()>& rebuild_account, UnixTime utime,
                         LogicalTime lt, const td::Ref<vm::Cell>& msg_root, ExecConfigPair& exec_config,
                         const std::function<std::shared_ptr<vm::ValidatorAuthHost>()>& authority);

  // Assembles the registry authority for one external message at the current
  // masterchain tip, or refuses. The returned transaction is also the immutable
  // admission seed for a diagnostic retry: clone_for_execution() shares its
  // already-opened evidence while constructing a new reader and host.
  //
  // This is not a consensus authority and decides nothing about any block. It
  // answers whether this message can execute at all, which is what admission to
  // the pool means: the configuration contract runs the privileged instruction
  // before it accepts the message, so an update offered nothing here is
  // rejected at the door and never reaches a collator. Inclusion is decided
  // later, by a collator assembling from the facts of the block it is building
  // and a validator assembling again from the same facts.
  //
  // It goes through the same assembler for the same reason both of those do: a
  // second way to build this authority is a second answer waiting to differ.
  bool offer_validator_auth(const td::Ref<vm::Cell>& msg_root, const ConfigSnapshot& snapshot,
                            const td::Ref<MasterchainState>& mc_state, UnixTime now,
                            std::shared_ptr<tos::auth::NativeConfigTransaction>& authority) const;

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
