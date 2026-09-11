#pragma once

#include "block/workchain-resource-policy.h"
#include <optional>

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

  // Absent only in the explicitly identified legacy layout 2. Layout 3 requires
  // both fields; decoding never substitutes a zero counter or an empty bucket.
  std::optional<std::uint64_t> deposit_sequence;
  td::Ref<vm::Cell> unexpected;

  WorkchainCoordinatorState(std::uint16_t layout, gen::UnoV2SystemState::Record state, std::uint64_t deposits)
      : layout_version(layout), system(state), refundable_deposits(deposits) {}
  WorkchainCoordinatorState(std::uint16_t layout, gen::UnoV2SystemState::Record state,
      std::uint64_t deposits, std::uint64_t sequence, td::Ref<vm::Cell> buckets)
      : layout_version(layout), system(state), refundable_deposits(deposits),
        deposit_sequence(sequence), unexpected(std::move(buckets)) {}

};

inline td::Result<td::Ref<vm::Cell>> encode_workchain_coordinator_state(
    const WorkchainCoordinatorState& value) {
  if (value.layout_version == 3) {
    if (value.system.layout_version != 1 || !value.deposit_sequence || value.unexpected.is_null())
      return td::Status::Error("incomplete coordinator ingress state");
    gen::UnoV2CoordinatorIngress::Record record;
    record.layout_version = 3;
    record.deposit_sequence = *value.deposit_sequence;
    record.unexpected = value.unexpected;
    td::Ref<vm::Cell> result;
    if (!tlb::pack_cell(record.system, value.system) ||
        !tlb::pack_cell(record.budget, gen::UnoV2CoordinatorBudget::Record{value.refundable_deposits}) ||
        !tlb::pack_cell(result, record))
      return td::Status::Error("coordinator ingress field is not representable");
    return result;
  }
  if (value.layout_version != 2 || value.system.layout_version != 1 ||
      value.deposit_sequence || value.unexpected.not_null()) {
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

// Decode the explicitly tagged layout and its exact ordinary records. Layout 3
// requires an opaque bucket root; that root is parsed by its owning codec. No
// missing sequence is reinterpreted as zero. This is not
// account authentication or validation of counter transitions/fee parameters.
// Cell loading errors are returned without a consensus classification. The caller
// distinguishes candidate bytes from unavailable authenticated state by provenance.
inline td::Result<WorkchainCoordinatorState> decode_workchain_coordinator_state(
    const td::Ref<vm::Cell>& root) try {
  using resource_policy_detail::unpack_exact;
  if (root.is_null()) return td::Status::Error("missing coordinator state");
  // Dispatch by the generated constructor tag, never by trying legacy fallback.
  bool special = false;
  auto slice = vm::load_cell_slice_special(root, special);
  if (special || slice.size() < 32) return td::Status::Error("invalid coordinator root framing");
  if (slice.prefetch_ulong(32) == gen::UnoV2CoordinatorIngress::cons_tag[0]) {
    gen::UnoV2CoordinatorIngress::Record record;
    gen::UnoV2SystemState::Record system;
    gen::UnoV2CoordinatorBudget::Record budget;
    if (!unpack_exact(root, record) || record.layout_version != 3 ||
        !unpack_exact(record.system, system) || system.layout_version != 1 ||
        !unpack_exact(record.budget, budget) || record.unexpected.is_null())
      return td::Status::Error("malformed coordinator ingress state");
    return WorkchainCoordinatorState{3, system, budget.refundable_deposits,
                                     record.deposit_sequence, record.unexpected};
  }
  gen::UnoV2CoordinatorDeposits::Record record;
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
} catch (const vm::VmError& error) {
  return error.as_status("coordinator cell loading: ");
} catch (const vm::VmVirtError& error) {
  return error.as_status("coordinator cell acquisition: ");
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

// Checked scalar only: the host installs this result with successful admission,
// never on failed issuance (D52). Configuration cannot write this state counter.
inline td::Result<std::uint64_t> next_workchain_deposit_sequence(std::uint64_t old) {
  if (old == UINT64_MAX) return td::Status::Error("deposit_sequence overflow");
  return old + 1;
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
