#pragma once

#include "block/workchain-account-settlement.h"

namespace block {

// Post-admission replay of an independently authenticated context. Claimed
// closures must already be bounded and materialized. This is not a production
// error-classification boundary; acquisition exceptions retain their provenance.
// The claimed caches are never authorization and are never returned to callers.
namespace account_replay_detail {
inline td::Status compare_rebuilt(const WorkchainAccountSettlement& rebuilt,
                                  const WorkchainAccountSettlement& claimed) {
  if (rebuilt.effects->get_hash() != claimed.effects->get_hash() ||
      rebuilt.state.accounts->get_hash() != claimed.state.accounts->get_hash() ||
      rebuilt.state.account_blocks->get_hash() != claimed.state.account_blocks->get_hash() ||
      rebuilt.imports.in_msg_descr->get_hash() != claimed.imports.in_msg_descr->get_hash() ||
      rebuilt.state.end_lt != claimed.state.end_lt ||
      rebuilt.message.is_null() != claimed.message.is_null() ||
      (rebuilt.message.not_null() && rebuilt.message->get_hash() != claimed.message->get_hash())) {
    return td::Status::Error("claimed account settlement artifacts differ from independent replay");
  }
  return td::Status::OK();
}

inline td::Result<WorkchainAccountSettlement> replay(
    const WorkchainAccountEngine& engine, td::Ref<vm::Cell> old_accounts,
    const WorkchainHostIdentity& identity, const AdmittedInput& admitted,
    const WorkchainAccountDeclarations& declarations, const MaterializedNativeCells& native_cells,
    std::uint64_t max_reads, std::uint64_t max_writes, std::uint64_t max_inbound,
    std::uint64_t max_transfers, const td::Bits256& custody, const td::Bits256& coordinator,
    td::RefInt256 fee_budget, int extra_validation_cells,
    const SerializeConfig& cfg, const ActionPhaseConfig& message_cfg,
    const WorkchainAccountSettlement& claimed, const WorkchainDisposalEntryContext* disposal) {
  if (claimed.input.is_null() || claimed.effects.is_null() || claimed.state.accounts.is_null() ||
      claimed.state.account_blocks.is_null() || claimed.imports.in_msg_descr.is_null()) {
    return td::Status::Error("missing claimed account settlement artifacts");
  }
  // This bounded, post-admission construction precedes old-account acquisition
  // and engine invocation. Rebuilding it again in the runner is deliberate;
  // both constructions must be charged by the enclosing admission policy.
  TRY_RESULT(expected_input, encode_workchain_host_input(identity, admitted, declarations,
      native_cells.roots(), max_reads, max_writes, max_inbound));
  if (expected_input->get_hash() != claimed.input->get_hash()) {
    return td::Status::Error("claimed account settlement input differs from authenticated input");
  }
  TRY_RESULT(rebuilt, account_settlement_detail::execute(engine, std::move(old_accounts), identity,
      admitted, declarations, native_cells, max_reads, max_writes, max_inbound, max_transfers,
      custody, coordinator, std::move(fee_budget), extra_validation_cells, cfg, message_cfg, disposal));
  TRY_STATUS(compare_rebuilt(rebuilt, claimed));
  return rebuilt;
}
}  // namespace account_replay_detail

// Complete-input replay checks the claimed commitment before semantic inbox
// reconstruction, old-account acquisition or execution. It returns independently
// rebuilt artifacts, never proposer caches. The enclosing live host still owes
// state/proof/output admission and source-aware failure classification.
inline td::Result<WorkchainAccountSettlement> replay_workchain_account_settlement(
    const WorkchainAccountEngine& engine, td::Ref<vm::Cell> old_accounts,
    const WorkchainHostIdentity& identity, const AdmittedBatchInput& admitted,
    const MaterializedNativeCells& native_cells,
    const td::Bits256& custody, const td::Bits256& coordinator, td::RefInt256 fee_budget,
    int extra_validation_cells, const SerializeConfig& cfg, const ActionPhaseConfig& message_cfg,
    const WorkchainAccountSettlement& claimed) {
  if (claimed.input.is_null() || claimed.effects.is_null() || claimed.state.accounts.is_null() ||
      claimed.state.account_blocks.is_null() || claimed.imports.in_msg_descr.is_null()) {
    return td::Status::Error("missing claimed account settlement artifacts");
  }
  if (claimed.input->get_hash() != admitted.root()->get_hash()) {
    return td::Status::Error("claimed account settlement input differs from admitted input");
  }
  TRY_RESULT(rebuilt, execute_and_settle_workchain_accounts(engine, std::move(old_accounts), identity,
      admitted, native_cells, custody, coordinator, std::move(fee_budget), extra_validation_cells, cfg, message_cfg));
  TRY_STATUS(account_replay_detail::compare_rebuilt(rebuilt, claimed));
  return rebuilt;
}

inline td::Result<WorkchainAccountSettlement> replay_workchain_account_settlement(
    const WorkchainAccountEngine& engine, td::Ref<vm::Cell> old_accounts,
    const WorkchainHostIdentity& identity, const AdmittedInput& admitted,
    const WorkchainAccountDeclarations& declarations, const MaterializedNativeCells& native_cells,
    std::uint64_t max_reads, std::uint64_t max_writes, std::uint64_t max_inbound,
    std::uint64_t max_transfers, const td::Bits256& custody, const td::Bits256& coordinator,
    td::RefInt256 fee_budget, int extra_validation_cells,
    const SerializeConfig& cfg, const ActionPhaseConfig& message_cfg, const WorkchainAccountSettlement& claimed) {
  return account_replay_detail::replay(engine, old_accounts, identity, admitted, declarations, native_cells,
      max_reads, max_writes, max_inbound, max_transfers, custody, coordinator, std::move(fee_budget),
      extra_validation_cells, cfg, message_cfg, claimed, nullptr);
}

inline td::Result<WorkchainAccountSettlement> replay_workchain_disposal_settlement(
    const WorkchainAccountEngine& engine, td::Ref<vm::Cell> old_accounts,
    const WorkchainHostIdentity& identity, const AdmittedBatchInput& admitted,
    const MaterializedNativeCells& native_cells, const td::Bits256& coordinator,
    td::RefInt256 fee_budget, int extra_validation_cells,
    const SerializeConfig& cfg, const WorkchainDisposalEntryContext& context,
    const WorkchainAccountSettlement& claimed) {
  if (claimed.input.is_null() || claimed.effects.is_null() || claimed.state.accounts.is_null() ||
      claimed.state.account_blocks.is_null() || claimed.imports.in_msg_descr.is_null()) {
    return td::Status::Error("missing claimed disposal settlement artifacts");
  }
  if (claimed.input->get_hash() != admitted.root()->get_hash()) {
    return td::Status::Error("claimed disposal input differs from admitted input");
  }
  TRY_RESULT(rebuilt, execute_and_settle_workchain_disposal(engine, std::move(old_accounts), identity,
      admitted, native_cells, coordinator, std::move(fee_budget), extra_validation_cells, cfg, context));
  TRY_STATUS(account_replay_detail::compare_rebuilt(rebuilt, claimed));
  return rebuilt;
}

inline td::Result<WorkchainAccountSettlement> replay_workchain_disposal_settlement(
    const WorkchainAccountEngine& engine, td::Ref<vm::Cell> old_accounts,
    const WorkchainHostIdentity& identity, const AdmittedInput& admitted,
    const WorkchainAccountDeclarations& declarations, const MaterializedNativeCells& native_cells,
    std::uint64_t max_reads, std::uint64_t max_writes, std::uint64_t max_transfers,
    const td::Bits256& coordinator, td::RefInt256 fee_budget, int extra_validation_cells,
    const SerializeConfig& cfg, const WorkchainDisposalEntryContext& context,
    const WorkchainAccountSettlement& claimed) {
  return account_replay_detail::replay(engine, old_accounts, identity, admitted, declarations, native_cells,
      max_reads, max_writes, context.max_inbound, max_transfers, context.custody, coordinator, std::move(fee_budget),
      extra_validation_cells, cfg, context.messages, claimed, &context);
}

}  // namespace block
