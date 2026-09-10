#pragma once

#include "block/workchain-resource-policy.h"

namespace block {

// Two independent layout axes. Neither is inferred from admission_version.
// No initialized default is supplied: callers must provide both versions.
struct WorkchainCoordinatorState {
  std::uint16_t layout_version;
  gen::UnoV2SystemState::Record system;
};

inline td::Result<td::Ref<vm::Cell>> encode_workchain_coordinator_state(
    const WorkchainCoordinatorState& value) {
  if (value.layout_version != 1 || value.system.layout_version != 1) {
    return td::Status::Error("unsupported coordinator or system layout");
  }
  gen::UnoV2CoordinatorState::Record record;
  record.layout_version = value.layout_version;
  td::Ref<vm::Cell> result;
  if (!tlb::pack_cell(record.system, value.system) || !tlb::pack_cell(result, record)) {
    return td::Status::Error("coordinator state field is not representable");
  }
  return result;
}

// Decode exactly two ordinary records. No optional bond placeholder exists in
// layout 1, and no unknown version is reinterpreted as layout 1. This is not
// account authentication or validation of counter transitions/fee parameters.
// Acquisition exceptions propagate to the caller's provenance boundary, as
// for resource-policy decoding; malformed data is not itself a consensus code.
inline td::Result<WorkchainCoordinatorState> decode_workchain_coordinator_state(
    const td::Ref<vm::Cell>& root) {
  gen::UnoV2CoordinatorState::Record record;
  using resource_policy_detail::unpack_exact;
  if (!unpack_exact(root, record)) {
    return td::Status::Error("malformed coordinator container");
  }
  if (record.layout_version != 1) {
    return td::Status::Error("unsupported coordinator layout");
  }
  gen::UnoV2SystemState::Record system;
  if (!unpack_exact(record.system, system)) {
    return td::Status::Error("malformed system state");
  }
  if (system.layout_version != 1) {
    return td::Status::Error("unsupported system layout");
  }
  return WorkchainCoordinatorState{static_cast<std::uint16_t>(record.layout_version), std::move(system)};
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
