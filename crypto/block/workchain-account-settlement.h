#pragma once

#include "block/workchain-account-effects.h"
#include "block/workchain-payout-overlay.h"

namespace block {

struct WorkchainAccountSettlement {
  td::Ref<vm::Cell> input, effects;
  WorkchainStorageOverlay state;
  td::Ref<vm::Cell> message;
};

// One engine invocation followed by private Native materialization. No caller
// supplies the input/effects hashes or a second set of account data updates.
// This post-admission operation does not authenticate roles, resource policy,
// old state or withdrawal authorization. The resolved engine must derive its
// payout request from verified obligations, not forward an unverified request.
// Registration and inbound settlement need additional Native record shapes;
// this path materializes existing-account storage and one optional payout only.
inline td::Result<WorkchainAccountSettlement> execute_and_settle_workchain_accounts(
    const WorkchainAccountEngine& engine, td::Ref<vm::Cell> old_accounts,
    const WorkchainHostIdentity& identity, const AdmittedInput& admitted,
    const WorkchainAccountDeclarations& declarations,
    const std::vector<td::Ref<vm::Cell>>& authenticated_inbox,
    std::uint64_t max_reads, std::uint64_t max_writes, std::uint64_t max_inbound,
    const td::Bits256& custody, const td::Bits256& coordinator, td::RefInt256 fee_budget,
    const SerializeConfig& cfg, const ActionPhaseConfig& message_cfg) {
  if (!authenticated_inbox.empty()) {
    return td::Status::Error("inbound Native settlement requires the coordinator entry path");
  }
  TRY_RESULT(executed, execute_workchain_account_engine(engine, old_accounts, identity, admitted, declarations,
      authenticated_inbox, max_reads, max_writes, max_inbound));
  TRY_RESULT(effects_root, encode_workchain_account_effects(executed.effects, max_writes));
  std::vector<WorkchainStorageWrite> writes;
  writes.reserve(executed.effects.updates.size());
  for (const auto& update : executed.effects.updates) {
    auto read = std::lower_bound(declarations.reads.begin(), declarations.reads.end(), update.account,
        [](const auto& entry, const auto& key) { return entry.account < key; });
    if (read == declarations.reads.end() || read->account != update.account || !read->old_account_hash) {
      return td::Status::Error("account creation requires a registration participant");
    }
    writes.push_back({update.account, *read->old_account_hash, update.data});
  }
  const td::Bits256 input_hash(executed.input->get_hash().bits());
  const td::Bits256 effects_hash(effects_root->get_hash().bits());
  WorkchainStorageOverlay state;
  td::Ref<vm::Cell> message;
  if (executed.effects.payout_request.not_null()) {
    TRY_RESULT(payout, build_workchain_payout_overlay(old_accounts, identity.workchain_id, identity.gen_utime,
        identity.host_after_lt, input_hash, effects_hash, writes, custody, coordinator,
        executed.effects.payout_request, fee_budget, max_writes, cfg, message_cfg));
    state = std::move(payout.state);
    message = std::move(payout.message);
  } else {
    TRY_RESULT(storage, build_workchain_storage_overlay(old_accounts, identity.workchain_id, identity.gen_utime,
        identity.host_after_lt, input_hash, effects_hash, writes, max_writes, cfg));
    state = std::move(storage);
  }
  return WorkchainAccountSettlement{std::move(executed.input), std::move(effects_root),
                                    std::move(state), std::move(message)};
}

}  // namespace block
