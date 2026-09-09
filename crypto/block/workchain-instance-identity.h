#pragma once

#include <optional>
#include "block/block-auto.h"
#include "td/utils/Status.h"
#include "vm/dict.h"

namespace block {

// Mechanical transition failures. The host classifies by input provenance:
// predecessor storage faults are local; candidate mismatches are invalid.
enum class InstanceIdentityError {
  MissingLedger = 7401,
  MalformedLedger,
  MissingGenesis,
  MissingDescriptor,
  SuccessorUnsupported,
  IdentityMismatch,
  UnexpectedLedgerDelta,
  MalformedRecord,
  InvalidConfiguration,
};

struct StagedFirstInstance {
  td::Ref<vm::Cell> ledger;
  td::Bits256 instance_id;
};

// An explicit zerostate operation, never a fallback for unavailable state.
td::Result<td::Ref<vm::Cell>> make_initial_workchain_instance_ledger();
td::Result<gen::WorkchainInstanceLedger::Record> read_workchain_instance_ledger(
    const td::Ref<vm::Cell>& root);
td::Result<std::optional<gen::WorkchainInstanceRecord::Record>> read_workchain_instance_record(
    const td::Ref<vm::Cell>& ledger, std::int32_t workchain);
td::Result<td::Bits256> derive_workchain_instance_id(
    const std::optional<td::Bits256>& authenticated_genesis, std::int32_t workchain,
    const gen::WorkchainInstanceRecord::Record& record);

// The host triggers first installation only for a descriptor whose workchain
// has no predecessor ledger entry. Existing entries cannot be overwritten,
// including retired ones; successor issuance is explicitly unsupported.
// Returned cells are private until the containing masterchain state commits.
td::Result<StagedFirstInstance> stage_first_workchain_instance(
    const td::Ref<vm::Cell>& predecessor_ledger, std::int32_t workchain,
    const std::optional<td::Bits256>& authenticated_genesis,
    const td::Ref<vm::Cell>& creation_descriptor, const td::Bits256& claimed_id);

// Reconstruct this workchain's permitted change from the proposed configuration.
// The predecessor is authenticated state, never the candidate ledger. D40 is
// applied to wc=2 by the current host; other ledger keys remain immutable.
td::Result<td::Ref<vm::Cell>> reconstruct_workchain_instance_ledger(
    const td::Ref<vm::Cell>& predecessor, const td::Ref<vm::Cell>& proposed_config,
    const std::optional<td::Bits256>& authenticated_genesis, std::int32_t workchain);

// Compare the complete independently reconstructed root, including unread keys
// and deletions. For a non-creation block expected is the predecessor root.
td::Status check_workchain_instance_ledger_delta(const td::Ref<vm::Cell>& expected,
                                               const td::Ref<vm::Cell>& candidate);

}  // namespace block
