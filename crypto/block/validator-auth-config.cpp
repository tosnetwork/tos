#include "tos/tos-types.h"
#include "vm/cells/CellSlice.h"

#include "validator-auth-config.h"
#include "validator-auth-profile.h"
namespace block {
namespace {
struct Header {
  bool enabled = false;
  td::Bits256 domain;
  std::uint64_t revision = 0;
  td::Ref<vm::Cell> identities, keys;
};
td::Result<Header> read_registry(td::Ref<vm::Cell> registry) {
  Header header;
  header.enabled = true;
  if (registry.is_null() || registry->get_level())
    return td::Status::Error("validator-auth-registry");
  vm::CellSlice root{vm::NoVm{}, registry};
  if (!root.is_valid() || root.is_special() || root.size() != 880 || root.size_refs() != 4 ||
      root.fetch_ulong(32) != 0x76617131 || root.fetch_ulong(16) != 1)
    return td::Status::Error("validator-auth-registry");
  td::Bits256 fingerprint, policy;
  if (!root.fetch_bits_to(header.domain) || header.domain.is_zero() || !root.fetch_bits_to(fingerprint) ||
      fingerprint.as_slice() !=
          td::Slice(validator_auth_profile_fingerprint.data(), validator_auth_profile_fingerprint.size()))
    return td::Status::Error("validator-auth-profile");
  header.revision = root.fetch_ulong(64);
  if (!root.fetch_bits_to(policy) || policy.is_zero())
    return td::Status::Error("validator-auth-registry");
  header.identities = root.fetch_ref();
  header.keys = root.fetch_ref();
  auto dictionary_shape = [](td::Ref<vm::Cell> cell) {
    vm::CellSlice s{vm::NoVm{}, cell};
    return s.is_valid() && !s.is_special() && s.size() == 1 && s.size_refs() == s.prefetch_ulong(1);
  };
  if (!dictionary_shape(header.identities) || !dictionary_shape(header.keys) || !dictionary_shape(root.fetch_ref()))
    return td::Status::Error("validator-auth-dictionary");
  vm::CellSlice control{vm::NoVm{}, root.fetch_ref()};
  if (!control.is_valid() || control.is_special() || control.size() != 32 || control.size_refs() != 2 ||
      control.fetch_ulong(32) != 0x76616331 || !dictionary_shape(control.fetch_ref()) ||
      !dictionary_shape(control.fetch_ref()))
    return td::Status::Error("validator-auth-control");
  return header;
}
td::Result<Header> read(vm::Dictionary& config) {
  Header header;
  auto capability = config.lookup_ref(td::BitArray<32>{8});
  if (capability.is_null())
    return header;
  vm::CellSlice cap{vm::NoVm{}, capability};
  if (!cap.is_valid() || cap.is_special() || cap.size() != 104 || cap.size_refs() || cap.fetch_ulong(8) != 0xc4)
    return td::Status::Error("validator-auth-config8");
  auto version = cap.fetch_ulong(32), flags = cap.fetch_ulong(64);
  if (!(flags & tos::capValidatorAuth))
    return header;
  header.enabled = true;
  if (version < 16)
    return td::Status::Error("validator-auth-version");
  for (int index : {9, 10}) {
    auto root = config.lookup_ref(td::BitArray<32>{index});
    if (root.is_null())
      return td::Status::Error("validator-auth-required");
    vm::Dictionary required(root, 32);
    auto entry = required.lookup(td::BitArray<32>{46});
    if (entry.is_null() || entry->size() || entry->size_refs())
      return td::Status::Error("validator-auth-required");
  }
  auto counts = config.lookup_ref(td::BitArray<32>{16});
  if (counts.is_null())
    return td::Status::Error("validator-auth-count");
  vm::CellSlice count{vm::NoVm{}, counts};
  if (!count.is_valid() || count.is_special() || count.size() != 48 || count.size_refs())
    return td::Status::Error("validator-auth-count");
  auto maximum = count.fetch_ulong(16), main = count.fetch_ulong(16), minimum = count.fetch_ulong(16);
  if (maximum > 400 || main > maximum || minimum < 1 || minimum > main)
    return td::Status::Error("validator-auth-count");
  return read_registry(config.lookup_ref(td::BitArray<32>{46}));
}
}  // namespace
td::Status validate_validator_auth_root_shape(td::Ref<vm::Cell> root) {
  try {
    auto result = read_registry(std::move(root));
    return result.is_error() ? result.move_as_error() : td::Status::OK();
  } catch (const vm::VmError&) {
    return td::Status::Error("validator-auth-config-cell");
  } catch (const vm::VmVirtError&) {
    return td::Status::Error("validator-auth-config-pruned");
  }
}
td::Status validate_validator_auth_config(vm::Dictionary& config) {
  try {
    auto result = read(config);
    return result.is_error() ? result.move_as_error() : td::Status::OK();
  } catch (const vm::VmError&) {
    return td::Status::Error("validator-auth-config-cell");
  } catch (const vm::VmVirtError&) {
    return td::Status::Error("validator-auth-config-pruned");
  }
}
td::Status validate_validator_auth_transition(vm::Dictionary& before, vm::Dictionary& after) {
  TRY_RESULT(old, read(before));
  TRY_RESULT(next, read(after));
  if (!old.enabled && !next.enabled)
    return td::Status::OK();
  if (!old.enabled)
    return td::Status::Error("validator-auth-transition-unapproved");
  if (!next.enabled)
    return td::Status::Error("validator-auth-downgrade");
  if (old.domain != next.domain)
    return td::Status::Error("validator-auth-domain");
  bool changed =
      old.identities->get_hash() != next.identities->get_hash() || old.keys->get_hash() != next.keys->get_hash();
  if (next.revision < old.revision || next.revision - old.revision != std::uint64_t(changed))
    return td::Status::Error("validator-auth-revision");
  return td::Status::OK();
}
}  // namespace block
