#pragma once

#include <cstdint>

#include "common/bitstring.h"
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
inline td::Result<td::Ref<vm::Cell>> encode_workchain_host_identity(const WorkchainHostIdentity& value) {
  if (value.finality.is_null()) return td::Status::Error("missing host finality context");
  auto domain = vm::CellBuilder().store_long(0x5ab37c9a, 32)
      .store_long(value.global_id, 32).store_bits(value.genesis_hash.bits(), 256)
      .store_bits(value.instance_id.bits(), 256).store_long(value.workchain_id, 32)
      .store_long(value.shard_id, 64).finalize();
  auto policy = vm::CellBuilder().store_long(0xf704b16c, 32)
      .store_bits(value.configuration_hash.bits(), 256).store_long(value.extended, 1)
      .store_long(value.engine_selector, 64).store_long(value.vm_mode, 64)
      .store_long(value.descriptor_version, 32).store_long(value.admission_version, 32).finalize();
  auto context = vm::CellBuilder().store_long(0x8a4ca5dc, 32)
      .store_bits(value.previous_shard_hash.bits(), 256).store_long(value.height, 32)
      .store_long(value.gen_utime, 32).store_long(value.host_after_lt, 64)
      .store_ref(value.finality).finalize();
  return vm::CellBuilder().store_long(0x7d71caf4, 32).store_ref(domain)
      .store_ref(policy).store_ref(context).finalize();
}

}  // namespace block
