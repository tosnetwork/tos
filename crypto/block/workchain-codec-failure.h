#pragma once

#include "td/utils/Status.h"
#include "vm/excno.hpp"

namespace block {
// Exception mechanisms only: not data provenance, wire tags or verdicts.
// VmVirtError may originate in candidate-supplied pruned data OR local reads.
// The host must supply the arena/view identity at the access boundary.
// Legacy code 0 remains UNKNOWN. Rejected only means an explicit codec check
// failed; it says nothing about the arena that supplied the offending data.
enum class WorkchainCodecFailure : int {
  Virtualization = -7300,
  Construction = -7301,
  Rejected = -7302,
  UnknownVm = -7303,
  VmBase = -7500,
};
inline td::Status workchain_codec_rejected(td::Slice message) {
  return td::Status::Error(static_cast<int>(WorkchainCodecFailure::Rejected), message);
}
inline td::Status workchain_codec_vm_error(const vm::VmError& error) {
  const auto number = error.get_errno();
  // Preserve the VM category AND errno; neither alone determines provenance.
  const auto code = number >= 0 && number <= 255
      ? static_cast<int>(WorkchainCodecFailure::VmBase) - number
      : static_cast<int>(WorkchainCodecFailure::UnknownVm);
  return td::Status::Error(code, td::Slice(error.get_msg()));
}
inline td::Status workchain_codec_virtualization_error(const vm::VmVirtError& error) {
  return td::Status::Error(static_cast<int>(WorkchainCodecFailure::Virtualization), td::Slice(error.get_msg()));
}
} // namespace block
