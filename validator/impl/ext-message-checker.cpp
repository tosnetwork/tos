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
#include <cstring>
#include <unordered_set>
#include <vector>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/transaction.h"
#include "block/workchain-execution-dispatch.h"
#include "td/utils/Timer.h"
#include "vm/dict.h"

#include "ext-message-checker.hpp"
#include "fabric.h"

namespace tos::validator {

namespace {

td::Status reject_special_cells_for_custom_compute(td::Ref<vm::Cell> root,
                                                   block::SizeLimitsConfig::ExtMsgLimits limits) {
  std::unordered_set<const vm::Cell*> visited;
  std::vector<td::Ref<vm::Cell>> stack{std::move(root)};
  const size_t cells_from_size = static_cast<size_t>(limits.max_size) / 64u;
  const size_t max_scanned_cells =
      std::min(static_cast<size_t>(65536), std::max(static_cast<size_t>(4096), cells_from_size));
  size_t popped = 0;
  while (!stack.empty()) {
    auto cell = std::move(stack.back());
    stack.pop_back();
    if (cell.is_null() || !visited.insert(cell.get()).second) {
      continue;
    }
    if (++popped > max_scanned_cells) {
      return td::Status::Error("external message tree too large for special-cell scan");
    }
    bool special = false;
    vm::CellSlice cs;
    try {
      cs = vm::load_cell_slice_special(cell, special);
    } catch (...) {
      return td::Status::Error("external message tree contains an unloadable cell");
    }
    if (special) {
      return td::Status::Error("external message tree contains a special cell");
    }
    for (unsigned i = 0, n = cs.size_refs(); i < n; ++i) {
      stack.push_back(cs.prefetch_ref(i));
    }
  }
  return td::Status::OK();
}

}  // namespace

td::actor::Task<ExtMessageChecker::CheckedExtMsg> ExtMessageChecker::check(td::BufferSlice data,
                                                                           block::SizeLimitsConfig::ExtMsgLimits limits,
                                                                           td::Ref<MasterchainState> mc_state) {
  CheckedExtMsg result;
  td::Timer timer;
  auto message = CO_TRY(create_ext_message(std::move(data), limits));
  result.message = message;
  result.timings.parse = timer.elapsed();

  WorkchainId wc = message->wc();
  StdSmcAddress addr = message->addr();

  timer = td::Timer();
  auto config_snapshot = CO_TRY(resolve_config(mc_state));
  bool use_tvm = CO_TRY(check_workchain_execution(message, limits, *config_snapshot.config));
  if (!use_tvm) {
    result.timings.fetch_state = timer.elapsed();
    co_return result;
  }

  auto state = co_await resolve_state(mc_state, message->shard());
  result.timings.fetch_state = timer.elapsed();

  timer = td::Timer();
  vm::AugmentedDictionary accounts_dict{state.accounts_root, 256, block::tlb::aug_ShardAccounts};
  auto shard_acc = accounts_dict.lookup(addr);
  result.timings.lookup = timer.elapsed();

  timer = td::Timer();
  bool special = wc == masterchainId && config_snapshot.config->is_special_smartcontract(addr);
  auto unpack_account = [shard_acc, special, utime = state.utime, lt = state.lt]() -> td::Result<block::Account> {
    block::Account account;
    if (!account.unpack(shard_acc, utime, special)) {
      return td::Status::Error("Failed to unpack account state");
    }
    account.block_lt = lt;
    return std::move(account);
  };
  auto account = CO_TRY(unpack_account());

  // Nothing from taking this reference through run_message suspends. Other tasks on this actor
  // therefore cannot mutate exec_configs_ while the reference is live.
  ExecConfigKey key{config_snapshot.mc_block_id, wc, state.utime};
  auto& exec_config = exec_configs_[key];
  alarm_timestamp().relax(td::Timestamp::in(60.0));
  if (exec_config.nolog == nullptr) {
    exec_config.nolog = CO_TRY(ExtMessageQ::ExecutionConfig::create(*config_snapshot.config, wc, state.utime, false));
    exec_config.log = CO_TRY(ExtMessageQ::ExecutionConfig::create(*config_snapshot.config, wc, state.utime, true));
    if (exec_configs_.size() > 16) {
      std::erase_if(exec_configs_, [&](const auto& item) {
        return item.second.nolog == nullptr || item.first.utime + 60 < state.utime;
      });
    }
  }

  CO_TRY(run_message(wc, std::move(account), unpack_account, state.utime, state.lt + 1, message->root_cell(),
                     exec_config));
  result.timings.vm = timer.elapsed();
  co_return result;
}

td::Result<ExtMessageChecker::ConfigSnapshot> ExtMessageChecker::resolve_config(
    const td::Ref<MasterchainState>& mc_state) {
  if (mc_state.is_null()) {
    return td::Status::Error(ErrorCode::notready, "masterchain state is not ready");
  }
  const auto& mc_block_id = mc_state->get_block_id();
  if (cached_config_ == nullptr || cached_config_mc_block_id_ != mc_block_id) {
    TRY_RESULT(config, block::ConfigInfo::extract_config(mc_state->root_cell(), mc_block_id, 0xFFFF));
    cached_config_ = std::shared_ptr<block::ConfigInfo>(std::move(config));
    cached_config_mc_block_id_ = mc_block_id;
    // No execution-config reference can be live across this synchronous method: references are
    // acquired only after all awaits and consumed without suspension.
    exec_configs_.clear();
  }
  return ConfigSnapshot{cached_config_mc_block_id_, cached_config_};
}

td::Result<bool> ExtMessageChecker::check_workchain_execution(const td::Ref<ExtMessage>& message,
                                                              block::SizeLimitsConfig::ExtMsgLimits limits,
                                                              const block::ConfigInfo& config) const {
  WorkchainId wc = message->wc();
  TRY_RESULT_PREFIX(
      execution,
      block::default_workchain_execution_registry().resolve_workchain(config.get_workchain_list(), wc, config),
      "cannot resolve workchain execution for external message: ");
  if (!execution.has_value() ||
      block::workchain_engine_key_is_tvm(block::workchain_engine_key_from_descriptor(execution->descriptor))) {
    return true;
  }
  if (!execution->descriptor.accept_msgs) {
    return td::Status::Error(PSTRING() << "configured workchain " << wc << " does not accept external messages");
  }
  TRY_STATUS(reject_special_cells_for_custom_compute(message->root_cell(), limits));
  auto policy = execution->executor->account_policy(execution->descriptor, *execution->engine_config);
  if (!policy.accepts_external_inbound) {
    return td::Status::Error("configured workchain engine does not accept external inbound messages");
  }
  TRY_STATUS_PREFIX(block::validate_account_execution_policy_supported(policy),
                    "configured workchain engine policy is not supported: ");
  if (policy.kind == block::AccountExecutionPolicyKind::SingletonExecutor &&
      std::memcmp(message->addr().data(), policy.singleton_address.value().data(), 32) != 0) {
    return td::Status::Error(PSTRING() << "ext-msg destination is not the configured singleton executor for workchain "
                                       << wc);
  }
  return false;
}

td::Status ExtMessageChecker::run_message(WorkchainId wc, block::Account account,
                                          const std::function<td::Result<block::Account>()>& rebuild_account,
                                          UnixTime utime, LogicalTime lt, const td::Ref<vm::Cell>& msg_root,
                                          ExecConfigPair& exec_config) {
  auto status = ExtMessageQ::run_message_on_account(wc, &account, utime, lt, msg_root, *exec_config.nolog);
  if (status.is_ok()) {
    return status;
  }
  auto rebuilt = rebuild_account();
  if (rebuilt.is_error()) {
    return status;
  }
  auto retry_account = rebuilt.move_as_ok();
  auto status_with_log = ExtMessageQ::run_message_on_account(wc, &retry_account, utime, lt, msg_root, *exec_config.log);
  if (status_with_log.is_error()) {
    return status_with_log;
  }
  return status;
}

td::actor::Task<ExtMessageChecker::ResolvedState> ExtMessageChecker::resolve_state(td::Ref<MasterchainState> mc_state,
                                                                                   AccountIdPrefixFull prefix) {
  BlockIdExt block_id;
  if (prefix.workchain == masterchainId) {
    block_id = mc_state->get_block_id();
  } else {
    auto shard_hash = mc_state->get_shard_from_config(shard_prefix(prefix, 60), false);
    if (shard_hash.is_null()) {
      co_return td::Status::Error(ErrorCode::notready, PSTRING() << "no shard in masterchain state for account "
                                                                 << prefix.workchain << ":"
                                                                 << td::format::as_hex(prefix.account_id_prefix));
    }
    block_id = shard_hash->top_block_id();
  }

  auto make_resolved = [](const CachedState& entry) {
    return ResolvedState{entry.accounts_root, entry.utime, entry.lt};
  };
  auto cached = states_.find(block_id.shard_full());
  if (cached != states_.end() && cached->second.block_id == block_id) {
    alarm_timestamp().relax(td::Timestamp::in(60.0));
    co_return make_resolved(cached->second);
  }

  td::Ref<ShardState> state;
  if (prefix.workchain == masterchainId) {
    state = std::move(mc_state);
  } else {
    state = co_await td::actor::ask(manager_, &ValidatorManager::wait_block_state_short, block_id, (td::uint32)0,
                                    td::Timestamp::in(10.0), false);
  }
  auto& entry = states_[block_id.shard_full()];
  if (entry.block_id != block_id || entry.state.is_null()) {
    block::gen::ShardStateUnsplit::Record shard_state;
    if (!tlb::unpack_cell(state->root_cell(), shard_state)) {
      co_return td::Status::Error("cannot unpack shard state header");
    }
    entry = CachedState{block_id, std::move(state), vm::load_cell_slice_ref(shard_state.accounts),
                        shard_state.gen_utime, shard_state.gen_lt};
  }
  alarm_timestamp().relax(td::Timestamp::in(60.0));
  co_return make_resolved(entry);
}

void ExtMessageChecker::alarm() {
  states_.clear();
  exec_configs_.clear();
}

}  // namespace tos::validator
