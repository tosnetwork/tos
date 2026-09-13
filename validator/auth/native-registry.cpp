#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"
#include "vm/dict.h"

#include "native-registry.h"
namespace tos::auth {
namespace {
void need(bool ok, const char* reason) {
  if (!ok)
    throw Error{reason};
}
template <class T>
T take(Result<T> value) {
  if (!value.ok())
    throw value.error();
  return std::move(value.value());
}
template <class F>
auto capture(F fn) -> Result<decltype(fn())> {
  try {
    return fn();
  } catch (const Error& e) {
    return e;
  } catch (const vm::VmError&) {
    return Error{"registry-cell"};
  } catch (const vm::VmVirtError&) {
    return Error{"registry-pruned"};
  }
}
void charge(StateReadBudget& budget, std::size_t bytes) {
  need(budget.entries != 0 && bytes <= budget.bytes, "state-resource");
  --budget.entries;
  budget.bytes -= bytes;
}
td::Slice slice(const Hash& h) {
  return {reinterpret_cast<const char*>(h.data()), h.size()};
}
Hash hash(td::Ref<vm::Cell> cell) {
  Hash result{};
  std::copy_n(cell->get_hash().as_slice().ubegin(), result.size(), result.begin());
  return result;
}
vm::Dictionary dict(td::Ref<vm::Cell> root, int width) {
  vm::CellSlice s{vm::NoVm{}, root};
  need(s.is_valid() && !s.is_special() && s.size() == 1 && s.size_refs() == s.prefetch_ulong(1), "index-shape");
  return vm::Dictionary(s, width);
}
td::Ref<vm::Cell> wrap(vm::Dictionary& d) {
  vm::CellBuilder b;
  need(d.append_dict_to_bool(b), "index-shape");
  return b.finalize();
}
template <std::size_t N>
td::ConstBitPtr bits(const std::array<std::uint8_t, N>& key) {
  return td::ConstBitPtr(key.data());
}
std::array<std::uint8_t, 4> height(std::uint32_t at) {
  return {static_cast<std::uint8_t>(at >> 24), static_cast<std::uint8_t>(at >> 16), static_cast<std::uint8_t>(at >> 8),
          static_cast<std::uint8_t>(at)};
}
std::array<std::uint8_t, 37> slot_key(const Hash& identity, KeySlot slot) {
  std::array<std::uint8_t, 37> key{};
  std::copy(identity.begin(), identity.end(), key.begin());
  auto [role, suite, parameters] = slot;
  key[32] = role;
  key[33] = suite >> 8;
  key[34] = static_cast<std::uint8_t>(suite);
  key[35] = parameters >> 8;
  key[36] = static_cast<std::uint8_t>(parameters);
  return key;
}
std::array<std::uint8_t, 36> due_key(std::uint32_t at, const Hash& identity) {
  std::array<std::uint8_t, 36> key{};
  auto h = height(at);
  std::copy(h.begin(), h.end(), key.begin());
  std::copy(identity.begin(), identity.end(), key.begin() + 4);
  return key;
}
template <class T>
T read(td::Ref<vm::Cell> root, const Hash& key, StateReadBudget& budget) {
  charge(budget, 0);
  auto d = dict(root, 256);
  auto leaf = d.lookup(bits(key), 256);
  need(leaf.not_null(), "unknown-entry");
  need(leaf->size() == 0 && leaf->size_refs() == 1, "dictionary-shape");
  auto bytes = take(unpack_bytes(leaf->prefetch_ref(), std::min<std::size_t>(32768, budget.bytes)));
  need(bytes.size() <= budget.bytes, "state-resource");
  budget.bytes -= bytes.size();
  return take(decode<T>(bytes));
}
template <class T>
void put(td::Ref<vm::Cell>& root, const Hash& key, const T& value, vm::Dictionary::SetMode mode,
         StateReadBudget& budget) {
  auto bytes = take(encode(value));
  charge(budget, bytes.size());
  auto d = dict(root, 256);
  need(d.set_ref(bits(key), 256, take(pack_bytes(bytes)), mode), "dictionary-write");
  root = wrap(d);
}
void epoch_put(td::Ref<vm::Cell>& root, const Key& key) {
  auto d = dict(root, 296);
  auto id = slot_key(key.identity_, {key.role_, key.suite_, key.parameters_});
  auto old = d.lookup(bits(id), 296);
  std::uint64_t epoch = old.is_null() ? 0 : old->prefetch_ulong(64);
  vm::CellBuilder b;
  b.store_long(std::max(epoch, key.epoch_), 64);
  need(d.set_builder(bits(id), 296, b), "epoch-index");
  root = wrap(d);
}
void schedules(td::Ref<vm::Cell>& root, const Identity& identity, bool insert) {
  auto d = dict(root, 288);
  std::set<std::uint32_t> heights;
  for (const auto& p : identity.pending_)
    heights.insert(p.effective_from_);
  for (auto at : heights) {
    auto key = due_key(at, identity.identity_);
    if (insert)
      need(d.set_builder(bits(key), 288, vm::CellBuilder()), "due-index");
    else
      need(d.lookup_delete(bits(key), 288).not_null(), "due-index");
  }
  root = wrap(d);
}
}  // namespace
Result<NativeRegistry> NativeRegistry::bootstrap(td::Ref<vm::Cell> root, std::uint32_t at, StateReadBudget budget) {
  return capture([&] {
    auto validated = take(RegistryState::decode_cell(root, at, budget));
    NativeRegistry result;
    result.domain_ = validated.chain_domain();
    result.policy_ = validated.current_policy();
    result.coordinate_ = at;
    result.revision_ = validated.revision();
    vm::CellSlice s{vm::NoVm{}, root};
    result.identities_ = s.fetch_ref();
    result.keys_ = s.fetch_ref();
    result.policies_ = s.fetch_ref();
    result.control_ = s.fetch_ref();
    vm::Dictionary epochs(296), due(288), schedule(32);
    result.epochs_ = wrap(epochs);
    result.due_ = wrap(due);
    for (const auto& [id, key] : validated.keys())
      epoch_put(result.epochs_, key);
    for (const auto& [id, identity] : validated.identities())
      schedules(result.due_, identity, true);
    for (const auto& [id, policy] : validated.policies()) {
      auto key = height(policy.effective_from_);
      vm::CellBuilder b;
      b.store_bytes(slice(id));
      need(schedule.set_builder(bits(key), 32, b, vm::Dictionary::SetMode::Add), "policy-index");
    }
    result.schedule_ = wrap(schedule);
    return result;
  });
}
Result<td::Ref<vm::Cell>> NativeRegistry::encode_cell() const {
  return capture([&]() -> td::Ref<vm::Cell> {
    return vm::CellBuilder()
        .store_long(0x76617131, 32)
        .store_long(1, 16)
        .store_bytes(slice(domain_))
        .store_bytes(slice(interface_fingerprint))
        .store_long(revision_, 64)
        .store_bytes(slice(policy_))
        .store_ref(identities_)
        .store_ref(keys_)
        .store_ref(policies_)
        .store_ref(control_)
        .finalize();
  });
}
Result<td::Ref<vm::Cell>> NativeRegistry::checkpoint() const {
  return capture([&]() -> td::Ref<vm::Cell> {
    return vm::CellBuilder()
        .store_long(0x76616e31, 32)
        .store_long(1, 16)
        .store_long(coordinate_, 32)
        .store_ref(take(encode_cell()))
        .store_ref(epochs_)
        .store_ref(due_)
        .store_ref(schedule_)
        .finalize();
  });
}
Result<NativeRegistry> NativeRegistry::restore(td::Ref<vm::Cell> checkpoint, const Hash& expected,
                                               std::uint32_t coordinate, StateReadBudget budget) {
  return capture([&] {
    vm::CellSlice s{vm::NoVm{}, checkpoint};
    need(s.is_valid() && !s.is_special() && s.size() == 80 && s.size_refs() == 4 && s.fetch_ulong(32) == 0x76616e31 &&
             s.fetch_ulong(16) == 1,
         "checkpoint-shape");
    need(s.fetch_ulong(32) == coordinate, "checkpoint-coordinate");
    auto root = s.fetch_ref();
    need(hash(root) == expected, "checkpoint-registry");
    auto result = take(bootstrap(root, coordinate, budget));
    need(hash(take(result.checkpoint())) == hash(checkpoint), "checkpoint-index");
    return result;
  });
}
Result<Identity> NativeRegistry::identity(const Hash& id) const {
  return capture([&] { return read<Identity>(identities_, id, budget_); });
}
Result<std::optional<Identity>> NativeRegistry::lookup_identity(const Hash& id) const {
  auto found = identity(id);
  if (!found.ok()) {
    if (found.error().code == "unknown-entry")
      return std::optional<Identity>{};
    return found.error();
  }
  return std::optional<Identity>{std::move(found.value())};
}
Result<Key> NativeRegistry::find(const Hash& id) const {
  return capture([&] { return read<Key>(keys_, id, budget_); });
}
Result<std::uint64_t> NativeRegistry::latest_epoch(const Hash& id, KeySlot slot) const {
  return capture([&]() -> std::uint64_t {
    charge(budget_, 8);
    auto d = dict(epochs_, 296);
    auto key = slot_key(id, slot);
    auto value = d.lookup(bits(key), 296);
    if (value.is_null())
      return 0;
    need(value->size() == 64 && value->size_refs() == 0, "epoch-index");
    return value->prefetch_ulong(64);
  });
}
Result<bool> NativeRegistry::ever_registered(const Hash& id) const {
  return capture([&] {
    charge(budget_, 8);
    auto d = dict(epochs_, 296);
    auto key = slot_key(id, {});
    auto value = d.lookup_nearest_key(td::BitPtr(key.data()), 296, true, true);
    return value.not_null() && std::equal(id.begin(), id.end(), key.begin());
  });
}
void NativeRegistry::apply_updates(NativeRegistry& next, const std::vector<std::pair<Update, Authorizations>>& updates,
                                   const Apply& apply) {
  for (const auto& [update, evidence] : updates) {
    need(update.identity_ != Hash{}, "unknown-identity");
    auto before = take(next.identity(update.identity_));
    auto effect = take(apply(next, before, update, evidence));
    if (effect.archived_key) {
      const auto& key = *effect.archived_key;
      put(next.keys_, take(object_id("key", key)), key, vm::Dictionary::SetMode::Add, next.budget_);
      epoch_put(next.epochs_, key);
    }
    schedules(next.due_, before, false);
    schedules(next.due_, effect.identity, true);
    put(next.identities_, update.identity_, effect.identity, vm::Dictionary::SetMode::Replace, next.budget_);
  }
}
Result<NativeRegistry> NativeRegistry::apply(std::uint32_t at,
                                             const std::vector<std::pair<Update, Authorizations>>& updates,
                                             const Apply& apply, StateReadBudget budget) const {
  return capture([&] {
    need(coordinate_ < UINT32_MAX - 1 && at == coordinate_ + 1, "block-gap");
    NativeRegistry next = *this;
    next.budget_ = budget;
    bool changed = false;
    while (true) {
      charge(next.budget_, 0);
      auto d = dict(next.due_, 288);
      std::array<std::uint8_t, 36> key{};
      auto due = d.get_minmax_key(td::BitPtr(key.data()), 288);
      if (due.is_null())
        break;
      auto height = static_cast<std::uint32_t>(bits(key).get_uint(32));
      need(height >= at, "state-overdue");
      if (height != at)
        break;
      Hash id{};
      std::copy(key.begin() + 4, key.end(), id.begin());
      auto before = take(next.identity(id));
      auto after = take(apply_due_transitions(before, next, coordinate_, at));
      schedules(next.due_, before, false);
      schedules(next.due_, after, true);
      put(next.identities_, id, after, vm::Dictionary::SetMode::Replace, next.budget_);
      changed = true;
    }
    next.coordinate_ = at;
    charge(next.budget_, 32);
    auto schedule = dict(next.schedule_, 32);
    auto at_key = height(at);
    auto selected = schedule.lookup_nearest_key(td::BitPtr(at_key.data()), 32, false, true);
    need(selected.not_null() && selected->size() == 256 && selected->size_refs() == 0, "policy-index");
    need(selected.write().fetch_bytes(td::MutableSlice(next.policy_.data(), next.policy_.size())), "policy-index");
    apply_updates(next, updates, apply);
    changed = changed || !updates.empty();
    if (changed) {
      need(revision_ != UINT64_MAX, "registry-revision");
      next.revision_ = revision_ + 1;
    }
    return next;
  });
}
Result<NativeRegistry> NativeRegistry::apply_block(std::uint32_t at,
                                                   const std::vector<std::pair<Update, Authorizations>>& updates,
                                                   const LifecycleAuthority& authority, StateReadBudget budget) const {
  return apply(
      at, updates,
      [&](const NativeRegistry& current, const Identity& identity, const Update& update,
          const Authorizations& evidence) {
        return apply_identity_update(identity, current, update, evidence, at, authority);
      },
      budget);
}
Result<NativeRegistry> NativeRegistry::apply_native_block(std::uint32_t at,
                                                          const std::vector<std::pair<Update, Authorizations>>& updates,
                                                          const NativeIdentityContext& context, ObjectReader& reader,
                                                          StateReadBudget budget) const {
  return apply(
      at, updates,
      [&](const NativeRegistry& current, const Identity& identity, const Update& update,
          const Authorizations& evidence) -> Result<IdentityChange> {
        NativeLifecycleAuthority authority(current, context, reader);
        auto valid = authority.validate_context();
        if (!valid.ok())
          return valid.error();
        return apply_identity_update(identity, current, update, evidence, at, authority);
      },
      budget);
}
}  // namespace tos::auth
