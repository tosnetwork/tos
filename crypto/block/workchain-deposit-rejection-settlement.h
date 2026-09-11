#pragma once

#include "block/workchain-rejected-deposit.h"
#include "block/workchain-coordinator-state.h"
#include "block/workchain-host-input.h"
#include "block/workchain-participant-lt.h"

namespace block {

// A local result of independent admission, never a candidate-decoded authority.
// It grants no generic source-rewriting capability: settlement binds exactly
// one actual inbox message to the coordinator and the acquired old record.
struct WorkchainDepositRejectionExecution {
  td::Bits256 message, old_coordinator_data;
  WorkchainNativeIngressPolicy ingress;
  WorkchainExecutionDescriptor descriptor;
  WorkchainSet workchains;
  WorkchainUnexpectedLimits bucket_limits;
};

struct WorkchainDepositRejectionMaterial {
  td::Ref<vm::Cell> coordinator_data;
  WorkchainRejectedDeposit plan;
};

inline td::Result<WorkchainDepositRejectionMaterial> prepare_workchain_deposit_rejection_settlement(
    const WorkchainDepositRejectionExecution& executed, td::Ref<vm::Cell> old_accounts,
    const WorkchainHostIdentity& identity, td::Ref<vm::Cell> input,
    const WorkchainAccountDeclarations& declarations, std::uint64_t max_writes,
    std::uint64_t max_inbound, int extra_validation_cells, const ActionPhaseConfig& messages) {
  auto local = [](td::Slice reason) { return td::Status::Error(-7201, reason); };
  gen::UnoV2HostInput::Record host;
  if (!tlb::unpack_cell(input, host) || identity.workchain_id != executed.ingress.workchain_id)
    return local("rejected Deposit settlement identity unavailable");
  const auto coordinator = executed.ingress.executor_address;
  vm::AugmentedDictionary old(vm::load_cell_slice_ref(old_accounts), 256, tlb::aug_ShardAccounts);
  Account budget(identity.workchain_id, coordinator.bits());
  if (!budget.unpack(old.lookup(coordinator), identity.gen_utime, false) || budget.data.is_null() ||
      executed.old_coordinator_data != budget.data->get_hash().bits())
    return local("rejected Deposit execution belongs to another coordinator snapshot");
  auto decoded = decode_workchain_coordinator_state(budget.data);
  if (decoded.is_error()) return local("rejected Deposit coordinator unavailable");
  auto system = decoded.move_as_ok();
  auto bucket = decode_workchain_unexpected_bucket(system.unexpected, executed.bucket_limits, extra_validation_cells);
  if (bucket.is_error()) return local("rejected Deposit bucket unavailable");
  auto inbox_root = host.inbox->prefetch_ulong(1) ? host.inbox->prefetch_ref() : td::Ref<vm::Cell>{};
  TRY_RESULT(inbox, plan_workchain_native_inbox(inbox_root, identity.workchain_id, {coordinator},
      identity.host_after_lt, max_inbound));
  if (inbox.envelopes.size() != 1) return local("rejected Deposit continuation requires one input");
  std::vector<WorkchainParticipantTiming> timing;
  for (const auto& address : declarations.writes) {
    Account account(identity.workchain_id, address.bits());
    if (!account.unpack(old.lookup(address), identity.gen_utime, false))
      return local("rejected Deposit participant unavailable");
    timing.push_back({address, account.last_trans_end_lt_, 0});
  }
  TRY_RESULT(schedule, plan_workchain_participant_lts(inbox.after_lt, timing, max_writes, 0));
  TRY_RESULT(outgoing_lt, participant_lt_detail::checked_add(schedule.start_lt, 1));
  TRY_RESULT(plan, plan_workchain_rejected_deposit(executed.ingress, executed.descriptor, inbox,
      executed.message, budget.balance, bucket.ok(), executed.bucket_limits, outgoing_lt,
      identity.gen_utime, messages, executed.workchains, extra_validation_cells));
  TRY_RESULT(encoded_bucket, encode_workchain_unexpected_bucket(plan.unexpected,
      executed.bucket_limits, extra_validation_cells));
  system.unexpected = std::move(encoded_bucket);
  TRY_RESULT(data, encode_workchain_coordinator_state(system));
  return WorkchainDepositRejectionMaterial{std::move(data), std::move(plan)};
}
}  // namespace block
