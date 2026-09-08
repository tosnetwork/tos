#pragma once

#include <cstdint>
#include <functional>

#include "common/bitstring.h"
#include "block/workchain-input-admission.h"
#include "td/utils/Status.h"
#include "vm/cells.h"

namespace block {

// Values must be derived from the authenticated host/configuration context.
// This codec does not authenticate them or select a supported policy version.
struct WorkchainHostIdentity {
  std::int32_t global_id;
  td::Bits256 genesis_hash;
  td::Bits256 instance_id;
  std::int32_t workchain_id;
  std::uint64_t shard_id;
  td::Bits256 configuration_hash;
  bool extended;
  std::int64_t engine_selector;
  std::uint64_t vm_mode;
  std::uint32_t descriptor_version;
  std::uint32_t admission_version;
  td::Bits256 previous_shard_hash;
  std::uint32_t height;
  std::uint32_t gen_utime;
  std::uint64_t host_after_lt;
  td::Ref<vm::Cell> finality;
};

// Local fields have fixed widths; finality is a separately admitted reference.
// Construction and allocation failures propagate to the provenance-aware host.
inline td::Result<td::Ref<vm::Cell>> encode_workchain_host_identity(
    const WorkchainHostIdentity& value,
    const std::function<td::Status(const td::Ref<vm::Cell>&)>& admit_derived = {}) {
  if (value.finality.is_null()) return td::Status::Error("missing host finality context");
  auto domain = vm::CellBuilder().store_long(0x5ab37c9a, 32)
      .store_long(value.global_id, 32).store_bits(value.genesis_hash.bits(), 256)
      .store_bits(value.instance_id.bits(), 256).store_long(value.workchain_id, 32)
      .store_long(value.shard_id, 64).finalize();
  if (admit_derived) TRY_STATUS(admit_derived(domain));
  auto policy = vm::CellBuilder().store_long(0xf704b16c, 32)
      .store_bits(value.configuration_hash.bits(), 256).store_long(value.extended, 1)
      .store_long(value.engine_selector, 64).store_long(value.vm_mode, 64)
      .store_long(value.descriptor_version, 32).store_long(value.admission_version, 32).finalize();
  if (admit_derived) TRY_STATUS(admit_derived(policy));
  auto context = vm::CellBuilder().store_long(0x8a4ca5dc, 32)
      .store_bits(value.previous_shard_hash.bits(), 256).store_long(value.height, 32)
      .store_long(value.gen_utime, 32).store_long(value.host_after_lt, 64)
      .store_ref(value.finality).finalize();
  if (admit_derived) TRY_STATUS(admit_derived(context));
  auto root = vm::CellBuilder().store_long(0x7d71caf4, 32).store_ref(domain)
      .store_ref(policy).store_ref(context).finalize();
  if (admit_derived) TRY_STATUS(admit_derived(root));
  return root;
}

// Keep admission and commitment on the same resolved configuration cut.
// Authenticating that cut remains the host's responsibility.
inline td::Result<td::Ref<vm::Cell>> encode_admitted_workchain_host_identity(
    const WorkchainHostIdentity& value, const AdmittedInput& admitted) {
  const auto& policy = admitted.policy_identity();
  if (value.configuration_hash != td::Bits256(policy.configuration_hash.bits()) ||
      value.extended != policy.extended || value.engine_selector != policy.engine_selector ||
      value.vm_mode != policy.vm_mode || value.descriptor_version != policy.descriptor_version ||
      value.admission_version != policy.admission_version) {
    return td::Status::Error("host identity differs from admitted input policy");
  }
  return encode_workchain_host_identity(value);
}

}  // namespace block
