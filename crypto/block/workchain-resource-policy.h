#pragma once

#include "block/block-auto.h"
#include "block/workchain-input-admission.h"
#include "td/utils/Status.h"
#include "vm/cells.h"

namespace block {

// Wire values only, not an authenticated or executable policy. Zero/unsupported
// values remain representable; configuration installation must reject them as
// appropriate. This codec installs no defaults or production limit values.
struct WorkchainResourcePolicy {
  std::uint32_t admission_version;
  gen::UnoV2ResourceInput::Record input;
  gen::UnoV2ResourceState::Record state;
  gen::UnoV2ResourceWorkOutput::Record work_output;
};

inline bool workchain_batch_input_bounds_nonzero(const WorkchainResourcePolicy& resources) {
  // An executable batch profile must permit state access, state progress and
  // Native ingress. Zero budgets are not a pause/retirement control. This is a
  // necessary installation condition, not proof of full budget compatibility.
  return resources.input.max_cells && resources.input.max_bits && resources.input.max_roots &&
         resources.input.max_reads && resources.input.max_writes && resources.input.max_inbound &&
         resources.state.max_cells && resources.state.max_bits && resources.state.max_account_cells &&
         resources.state.max_account_bits && resources.state.max_account_depth > 0;
}

inline bool workchain_batch_admission_version_supported(std::uint32_t version) {
  // Installation also revalidates old configuration: extend this set when
  // adding a profile; never retire an installed profile by replacing its value.
  return version == 2;
}

// An authenticated binding's resource cut, not proof of full batch admission.
// Deliberately not convertible to the singleton prototype's ResolvedInputPolicy.
// Configuration installation and full limit compatibility are separate gates.
class ResolvedBatchInputPolicy {
 public:
  static std::variant<ResolvedBatchInputPolicy, ConfigInvalid, LocalUnavailable> from_resolved_fields(
      WorkchainResourcePolicy resources, InputPolicyIdentity identity) {
    if (!workchain_batch_admission_version_supported(resources.admission_version) ||
        !workchain_batch_admission_version_supported(identity.admission_version)) {
      return LocalUnavailable{LocalUnavailableCode::UnsupportedAdmissionVersion};
    }
    if (!workchain_batch_input_bounds_nonzero(resources)) {
      return ConfigInvalid{ConfigInvalidCode::ZeroLimit};
    }
    return ResolvedBatchInputPolicy(resources, identity);
  }
  WorkchainInputLimits limits() const {
    return {resources_.input.max_cells, resources_.input.max_bits, resources_.input.max_roots};
  }
  const WorkchainResourcePolicy& resources() const { return resources_; }
  const InputPolicyIdentity& identity() const { return identity_; }

 private:
  ResolvedBatchInputPolicy(WorkchainResourcePolicy resources, InputPolicyIdentity identity)
      : resources_(resources), identity_(identity) {}
  WorkchainResourcePolicy resources_;
  InputPolicyIdentity identity_;
};

inline td::Result<td::Ref<vm::Cell>> encode_workchain_resource_policy(const WorkchainResourcePolicy& value) {
  gen::UnoV2ResourcePolicy::Record root;
  root.admission_version = value.admission_version;
  td::Ref<vm::Cell> result;
  if (!tlb::pack_cell(root.input, value.input) || !tlb::pack_cell(root.state, value.state) ||
      !tlb::pack_cell(root.work_output, value.work_output) || !tlb::pack_cell(result, root)) {
    return td::Status::Error("resource policy field is not representable");
  }
  return result;
}

namespace resource_policy_detail {
// Do not use the generated quiet cell loader: unavailable authenticated data
// must propagate to the provenance-aware caller rather than look malformed.
// Fixed schema, at most four ordinary slices; no attacker-selected traversal.
template <class Record>
bool unpack_exact(const td::Ref<vm::Cell>& root, Record& record) {
  if (root.is_null()) return false;
  bool special = false;
  auto cs = vm::load_cell_slice_special(root, special);
  if (special) return false;
  typename Record::type_class type;
  // Enforce the ordinary profile independently of generated constructor tags.
  return type.unpack(cs, record) && cs.empty_ext();
}
}  // namespace resource_policy_detail

// Malformed encoding returns Error. Loader/builder/allocation exceptions are
// deliberately not converted to a malformed-configuration result. This does
// not authenticate the input, validate limit combinations or enable a version.
inline td::Result<WorkchainResourcePolicy> decode_workchain_resource_policy(const td::Ref<vm::Cell>& root) {
  gen::UnoV2ResourcePolicy::Record header;
  WorkchainResourcePolicy value{};
  using resource_policy_detail::unpack_exact;
  if (!unpack_exact(root, header) || !unpack_exact(header.input, value.input) ||
      !unpack_exact(header.state, value.state) || !unpack_exact(header.work_output, value.work_output)) {
    return td::Status::Error("malformed resource policy encoding");
  }
  value.admission_version = header.admission_version;
  return value;
}

// The host parses the mandatory resource component itself. The registered
// engine must fully validate parameters; this framing does not approve an
// opaque payload or replace configuration-transition validation.
struct WorkchainEngineParameters {
  WorkchainResourcePolicy resources;
  td::Ref<vm::Cell> parameters;
};

inline td::Result<td::Ref<vm::Cell>> encode_workchain_engine_parameters(
    const WorkchainEngineParameters& value) {
  if (value.parameters.is_null()) return td::Status::Error("missing engine parameters");
  TRY_RESULT(resources, encode_workchain_resource_policy(value.resources));
  gen::UnoV2EngineConfiguration::Record record;
  record.resource_policy = std::move(resources);
  record.parameters = value.parameters;
  td::Ref<vm::Cell> result;
  if (!tlb::pack_cell(result, record)) return td::Status::Error("cannot encode engine configuration");
  return result;
}

inline td::Result<WorkchainEngineParameters> decode_workchain_engine_parameters(
    const td::Ref<vm::Cell>& root) {
  gen::UnoV2EngineConfiguration::Record record;
  if (!resource_policy_detail::unpack_exact(root, record)) {
    return td::Status::Error("malformed engine configuration framing");
  }
  TRY_RESULT(resources, decode_workchain_resource_policy(record.resource_policy));
  return WorkchainEngineParameters{std::move(resources), std::move(record.parameters)};
}

}  // namespace block
