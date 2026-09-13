#include "vm/cells/CellSlice.h"
#include "vm/dict.h"

#include "registry-view.h"
namespace tos::auth {
Result<std::uint64_t> RegistryView::latest_epoch(const Hash&, KeySlot) const {
  return Error{"read-only-view"};
}
Result<bool> RegistryView::ever_registered(const Hash&) const {
  return Error{"read-only-view"};
}
Result<Bytes> RegistryView::read(td::Ref<vm::Cell> root, const Hash& id, std::size_t maximum) const {
  try {
    vm::CellSlice wrapper{vm::NoVm{}, root};
    if (!wrapper.is_valid() || wrapper.is_special() || wrapper.size() != 1 ||
        wrapper.size_refs() != wrapper.prefetch_ulong(1))
      return Error{"dictionary-shape"};
    vm::Dictionary dict(wrapper, 256);
    auto leaf = dict.lookup(td::ConstBitPtr(id.data()), 256);
    if (leaf.is_null())
      return Error{"history-unavailable"};
    if (leaf->size() != 0 || leaf->size_refs() != 1)
      return Error{"dictionary-shape"};
    if (budget_.entries == 0)
      return Error{"state-resource"};
    --budget_.entries;
    auto raw = unpack_bytes(leaf->prefetch_ref(), std::min(budget_.bytes, maximum));
    if (!raw.ok())
      return raw.error();
    budget_.bytes -= raw.value().size();
    return raw;
  } catch (const vm::VmError&) {
    return Error{"registry-cell"};
  } catch (const vm::VmVirtError&) {
    return Error{"registry-pruned"};
  }
}
Result<RegistryView> RegistryView::open(td::Ref<vm::Cell> root, std::uint32_t coordinate, StateReadBudget budget) {
  try {
    if (coordinate == std::numeric_limits<std::uint32_t>::max())
      return Error{"config-context"};
    vm::CellSlice s{vm::NoVm{}, root};
    if (!s.is_valid() || s.is_special() || s.size() != 880 || s.size_refs() != 4 || s.fetch_ulong(32) != 0x76617131 ||
        s.fetch_ulong(16) != 1)
      return Error{"config-shape"};
    RegistryView result;
    result.budget_ = budget;
    Hash fingerprint{};
    auto read_hash = [&](Hash& out) {
      return s.fetch_bytes(td::MutableSlice(reinterpret_cast<char*>(out.data()), out.size()));
    };
    if (!read_hash(result.chain_domain_) || result.chain_domain_ == Hash{} || !read_hash(fingerprint) ||
        fingerprint != interface_fingerprint)
      return Error{"interface-digest"};
    s.fetch_ulong(64);
    if (!read_hash(result.current_policy_))
      return Error{"config-shape"};
    result.identities_root_ = s.fetch_ref();
    result.keys_root_ = s.fetch_ref();
    result.policies_root_ = s.fetch_ref();
    auto raw = result.read(result.policies_root_, result.current_policy_, 4096);
    if (!raw.ok())
      return raw.error();
    auto policy = decode<Policy>(raw.value());
    if (!policy.ok())
      return policy.error();
    auto id = object_id("policy", policy.value());
    if (!id.ok())
      return id.error();
    if (id.value() != result.current_policy_)
      return Error{"policy-hash"};
    const auto& p = policy.value();
    if (p.revision_ == 0 || p.effective_from_ > coordinate || p.interface_digest_ != interface_fingerprint ||
        p.phase_ != 0 || p.suites_ != std::vector<Suite>{{1, 1}} || p.max_envelope_ != 4096 ||
        p.max_certificate_ != 524288)
      return Error{"unsupported-profile"};
    result.policy_ = p;
    return result;
  } catch (const vm::VmError&) {
    return Error{"registry-cell"};
  } catch (const vm::VmVirtError&) {
    return Error{"registry-pruned"};
  }
}
Result<Identity> RegistryView::identity(const Hash& id) const {
  auto cached = identities_.find(id);
  if (cached != identities_.end())
    return cached->second;
  if (id == Hash{})
    return Error{"identity-key"};
  auto raw = read(identities_root_, id, 4096);
  if (!raw.ok())
    return raw.error();
  auto value = decode<Identity>(raw.value());
  if (!value.ok())
    return value.error();
  if (value.value().identity_ != id || value.value().stake_id_ == Hash{})
    return Error{"identity-key"};
  identities_.emplace(id, value.value());
  return value;
}
Result<Key> RegistryView::find(const Hash& id) const {
  auto cached = keys_.find(id);
  if (cached != keys_.end())
    return cached->second;
  auto raw = read(keys_root_, id, 32768);
  if (!raw.ok())
    return raw.error();
  auto value = decode<Key>(raw.value());
  if (!value.ok())
    return value.error();
  const auto& key = value.value();
  auto hash = object_id("key", key);
  if (!hash.ok())
    return hash.error();
  if (hash.value() != id)
    return Error{"key-hash"};
  if (key.identity_ == Hash{} || key.role_ < 1 || key.role_ > 5 || key.suite_ != 1 || key.parameters_ != 1 ||
      key.epoch_ == 0 || key.epoch_ == std::numeric_limits<std::uint64_t>::max() ||
      key.valid_from_ >= key.valid_until_ || key.capacity_domain_ != Hash{} || key.capacity_limit_ != 0)
    return Error{"key-descriptor"};
  auto admitted = AdmittedKey::admit(key.public_key_);
  if (!admitted.ok())
    return admitted.error();
  keys_.emplace(id, key);
  return value;
}
}  // namespace tos::auth
