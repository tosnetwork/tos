#pragma once

#include "block/workchain-resource-policy.h"

namespace block {

// Two independent layout axes. Neither is inferred from admission_version.
// No initialized default is supplied: callers must provide both versions.
struct WorkchainCoordinatorState {
  std::uint16_t layout_version;
  gen::UnoV2SystemState::Record system;
  // Dedicated refundable deposit sub-bucket, in nanotomi. Not principal and
  // never available for other spending. Refund requires exhausted available,
  // empty pending and no in-flight obligations, established by the host.
  std::uint64_t refundable_deposits;

  WorkchainCoordinatorState(std::uint16_t layout, gen::UnoV2SystemState::Record state, std::uint64_t deposits)
      : layout_version(layout), system(state), refundable_deposits(deposits) {}
};

inline td::Result<td::Ref<vm::Cell>> encode_workchain_coordinator_state(
    const WorkchainCoordinatorState& value) {
  if (value.layout_version != 2 || value.system.layout_version != 1) {
    return td::Status::Error("unsupported coordinator or system layout");
  }
  gen::UnoV2CoordinatorDeposits::Record record;
  record.layout_version = value.layout_version;
  td::Ref<vm::Cell> result;
  if (!tlb::pack_cell(record.system, value.system) ||
      !tlb::pack_cell(record.budget, gen::UnoV2CoordinatorBudget::Record{value.refundable_deposits}) ||
      !tlb::pack_cell(result, record)) {
    return td::Status::Error("coordinator state field is not representable");
  }
  return result;
}

// Decode exactly three ordinary records. No optional/default budget exists in
// layout 2, and no legacy constructor is reinterpreted as layout 2. This is not
// account authentication or validation of counter transitions/fee parameters.
// Acquisition exceptions propagate to the caller's provenance boundary, as
// for resource-policy decoding; malformed data is not itself a consensus code.
inline td::Result<WorkchainCoordinatorState> decode_workchain_coordinator_state(
    const td::Ref<vm::Cell>& root) {
  gen::UnoV2CoordinatorDeposits::Record record;
  using resource_policy_detail::unpack_exact;
  if (!unpack_exact(root, record)) {
    return td::Status::Error("malformed coordinator container");
  }
  if (record.layout_version != 2) {
    return td::Status::Error("unsupported coordinator layout");
  }
  gen::UnoV2SystemState::Record system;
  if (!unpack_exact(record.system, system)) {
    return td::Status::Error("malformed system state");
  }
  if (system.layout_version != 1) {
    return td::Status::Error("unsupported system layout");
  }
  gen::UnoV2CoordinatorBudget::Record budget;
  if (!unpack_exact(record.budget, budget)) return td::Status::Error("malformed coordinator budget");
  return WorkchainCoordinatorState{static_cast<std::uint16_t>(record.layout_version), std::move(system), budget.refundable_deposits};
}

// Explicit migration only; ordinary decoding never takes this branch. No prior
// registrations/system receipts means no registered deposit liability exists.
// Nonempty legacy states require a separately specified migration, not a guessed
// zero bucket. The caller authenticates the old state and authorizes migration.
inline td::Result<td::Ref<vm::Cell>> migrate_empty_workchain_coordinator_state(const td::Ref<vm::Cell>& legacy) {
  gen::UnoV2CoordinatorState::Record outer;
  gen::UnoV2SystemState::Record system;
  using resource_policy_detail::unpack_exact;
  if (!unpack_exact(legacy, outer) || outer.layout_version != 1 ||
      !unpack_exact(outer.system, system) || system.layout_version != 1) {
    return td::Status::Error("malformed legacy coordinator state");
  }
  if (system.registered_accounts != 0 || system.system_pending_count != 0) {
    return td::Status::Error("legacy coordinator is not empty");
  }
  return encode_workchain_coordinator_state({2, system, 0});
}

// Checked scalar operation only. The host determines which registrations were
// admitted; validator transition derivation remains independent. Account closure
// must not decrement registered_accounts. This helper does not commit a state.
inline td::Result<std::uint64_t> checked_increment_workchain_registered_accounts(std::uint64_t count) {
  if (count == UINT64_MAX) {
    return td::Status::Error("registered_accounts overflow");
  }
  return count + 1;  // Checked above: count is strictly below UINT64_MAX.
}

}  // namespace block
