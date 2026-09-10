#include "block/workchain-instance-identity.h"
#include "block/workchain-resource-policy.h"
#include "block/workchain-execution-dispatch.h"

namespace block {
namespace {
td::Status error(InstanceIdentityError code, const char* detail) {
  return td::Status::Error(static_cast<int>(code), td::Slice(detail));
}
template <class Record>
bool unpack_ordinary(const td::Ref<vm::Cell>& root, Record& record) {
  bool special = false;
  auto cs = vm::load_cell_slice_special(root, special);
  typename Record::type_class type;
  return !special && type.unpack(cs, record) && cs.empty_ext();
}
}  // namespace

td::Result<td::Ref<vm::Cell>> make_initial_workchain_instance_ledger() {
  vm::Dictionary empty(32);
  gen::WorkchainInstanceLedger::Record record{empty.get_root()};
  td::Ref<vm::Cell> root;
  if (!tlb::pack_cell(root, record)) return error(InstanceIdentityError::MalformedLedger, "cannot encode initial ledger");
  return root;
}

td::Result<gen::WorkchainInstanceLedger::Record> read_workchain_instance_ledger(
    const td::Ref<vm::Cell>& root) {
  if (root.is_null()) return error(InstanceIdentityError::MissingLedger, "instance ledger is missing");
  gen::WorkchainInstanceLedger::Record record;
  if (!unpack_ordinary(root, record)) return error(InstanceIdentityError::MalformedLedger, "malformed instance ledger");
  return record;
}

td::Result<std::optional<gen::WorkchainInstanceRecord::Record>> read_workchain_instance_record(
    const td::Ref<vm::Cell>& ledger, std::int32_t workchain) {
  TRY_RESULT(header, read_workchain_instance_ledger(ledger));
  vm::Dictionary entries(header.entries, 32);
  auto leaf = entries.lookup(td::BitArray<32>{static_cast<long long>(workchain)});
  if (leaf.is_null()) return std::optional<gen::WorkchainInstanceRecord::Record>{};
  gen::WorkchainInstanceRecord::Record record;
  if (!tlb::csr_unpack(leaf, record) || !record.instance_seq) {
    return error(InstanceIdentityError::MalformedRecord, "malformed issued instance record");
  }
  return std::optional<gen::WorkchainInstanceRecord::Record>{record};
}

td::Result<td::Bits256> derive_workchain_instance_id(
    std::int32_t authenticated_global_id, std::int32_t workchain, const gen::WorkchainInstanceRecord::Record& record) {
  if (!authenticated_global_id) return error(InstanceIdentityError::InvalidConfiguration, "authenticated global id is zero");
  if (!record.instance_seq) return error(InstanceIdentityError::MalformedRecord, "issued sequence is zero");
  gen::WorkchainInstanceIdentity::Record identity{authenticated_global_id, workchain, record.creation_descriptor_hash, record.instance_seq};
  td::Ref<vm::Cell> root;
  if (!tlb::pack_cell(root, identity)) return error(InstanceIdentityError::MalformedRecord, "cannot encode instance identity");
  return root->get_hash().bits();
}

td::Result<StagedFirstInstance> stage_first_workchain_instance(
    const td::Ref<vm::Cell>& predecessor_ledger, std::int32_t workchain,
    std::int32_t authenticated_global_id,
    const td::Ref<vm::Cell>& creation_descriptor, const td::Bits256& claimed_id) {
  TRY_RESULT(header, read_workchain_instance_ledger(predecessor_ledger));
  if (creation_descriptor.is_null()) return error(InstanceIdentityError::MissingDescriptor, "creation descriptor is missing");
  // No prior issuance exists. First installation issues exactly 1; no caller
  // counter, arithmetic wrap, or successor reset is available in this phase.
  gen::WorkchainInstanceRecord::Record record{1, creation_descriptor->get_hash().bits()};
  TRY_RESULT(instance_id, derive_workchain_instance_id(authenticated_global_id, workchain, record));
  vm::CellBuilder value;
  if (!tlb::pack(value, record)) return error(InstanceIdentityError::MalformedRecord, "cannot encode instance record");
  vm::Dictionary staged(header.entries, 32);
  if (!staged.set_builder(td::BitArray<32>{static_cast<long long>(workchain)}, value, vm::Dictionary::SetMode::Add)) {
    return error(InstanceIdentityError::SuccessorUnsupported, "instance record already exists");
  }
  header.entries = staged.get_root();
  td::Ref<vm::Cell> next;
  if (!tlb::pack_cell(next, header)) return error(InstanceIdentityError::MalformedLedger, "cannot encode staged ledger");
  // Deliberately after private construction: failure cannot consume a sequence
  // in the immutable predecessor, even after the staged write has occurred.
  if (instance_id != claimed_id) return error(InstanceIdentityError::IdentityMismatch, "instance identity differs");
  return StagedFirstInstance{next, instance_id};
}

td::Result<td::Ref<vm::Cell>> reconstruct_workchain_instance_ledger(
    const td::Ref<vm::Cell>& predecessor, const td::Ref<vm::Cell>& proposed_config,
    std::int32_t authenticated_global_id, std::int32_t workchain) {
  TRY_RESULT(header, read_workchain_instance_ledger(predecessor));
  if (proposed_config.is_null()) return error(InstanceIdentityError::InvalidConfiguration, "configuration is missing");
  vm::Dictionary config(proposed_config, 32);
  auto workchains_root = config.lookup_ref(td::BitArray<32>{12});
  if (workchains_root.is_null()) return predecessor;
  vm::Dictionary descriptors(vm::load_cell_slice(workchains_root), 32);
  auto descriptor_slice = descriptors.lookup(td::BitArray<32>{static_cast<long long>(workchain)});
  if (descriptor_slice.is_null()) return predecessor;
  if (!gen::t_WorkchainDescr.validate_csr(10000, descriptor_slice)) {
    return error(InstanceIdentityError::InvalidConfiguration, "invalid creation descriptor");
  }
  auto descriptor = vm::CellBuilder().append_cellslice(*descriptor_slice).finalize();
  auto ingress_root = config.lookup_ref(td::BitArray<32>{84});
  if (ingress_root.is_null()) return error(InstanceIdentityError::InvalidConfiguration, "instance configuration is missing");
  TRY_RESULT(ingress, decode_workchain_native_ingress_table(ingress_root));
  auto policy = ingress.find(workchain);
  if (policy == ingress.end()) return error(InstanceIdentityError::InvalidConfiguration, "instance policy is missing");
  TRY_RESULT(shell, decode_workchain_engine_parameters(policy->second.engine_configuration));
  TRY_RESULT(record, read_workchain_instance_record(predecessor, workchain));
  if (!record) {
    TRY_RESULT(staged, stage_first_workchain_instance(predecessor, workchain, authenticated_global_id,
                                                     descriptor, shell.instance_id));
    return staged.ledger;
  }
  // Historical descriptor comes from the ledger, never the proposed descriptor.
  TRY_RESULT(expected_id, derive_workchain_instance_id(authenticated_global_id, workchain, *record));
  if (shell.instance_id != expected_id) {
    return error(InstanceIdentityError::SuccessorUnsupported, "successor identity issuance is not supported");
  }
  return predecessor;
}

td::Status validate_workchain_instance_ledger_records(const td::Ref<vm::Cell>& ledger) {
  TRY_RESULT(header, read_workchain_instance_ledger(ledger));
  vm::Dictionary entries(header.entries, 32);
  if (!entries.check_for_each([](td::Ref<vm::CellSlice> value, td::ConstBitPtr, int) {
        gen::WorkchainInstanceRecord::Record record;
        return tlb::csr_unpack(value, record) && record.instance_seq != 0;
      })) {
    return error(InstanceIdentityError::MalformedRecord, "malformed authenticated instance record");
  }
  return td::Status::OK();
}

td::Result<td::Ref<vm::Cell>> reconstruct_configured_workchain_instances(
    const td::Ref<vm::Cell>& predecessor, const td::Ref<vm::Cell>& proposed_config,
    std::int32_t authenticated_global_id) {
  TRY_STATUS(validate_workchain_instance_ledger_records(predecessor));
  TRY_RESULT(staged, reconstruct_workchain_instance_ledger(predecessor, proposed_config, authenticated_global_id, 2));
  vm::Dictionary config(proposed_config, 32);
  auto ingress_root = config.lookup_ref(td::BitArray<32>{84});
  if (ingress_root.is_null()) return staged;
  TRY_RESULT(ingress, decode_workchain_native_ingress_table(ingress_root));
  for (const auto& entry : ingress) {
    if (entry.first == 2) continue;
    TRY_RESULT(next, reconstruct_workchain_instance_ledger(staged, proposed_config, authenticated_global_id, entry.first));
    staged = std::move(next);
  }
  return staged;
}

td::Status check_workchain_instance_ledger_delta(const td::Ref<vm::Cell>& expected,
                                               const td::Ref<vm::Cell>& candidate) {
  TRY_RESULT(expected_header, read_workchain_instance_ledger(expected));
  TRY_RESULT(candidate_header, read_workchain_instance_ledger(candidate));
  if (expected->get_hash() != candidate->get_hash()) {
    return error(InstanceIdentityError::UnexpectedLedgerDelta, "instance ledger differs from reconstructed transition");
  }
  return td::Status::OK();
}
}  // namespace block
