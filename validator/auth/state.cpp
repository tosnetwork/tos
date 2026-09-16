#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"
#include "vm/dict.h"
#include "vm/excno.hpp"

#include "state.h"
namespace tos::auth {
namespace {
td::ConstBitPtr bits(const Hash& hash) {
  return td::ConstBitPtr(hash.data());
}
td::Slice slice(const Hash& hash) {
  return {reinterpret_cast<const char*>(hash.data()), 32};
}
bool read_hash(vm::CellSlice& s, Hash& out) {
  return s.fetch_bytes(td::MutableSlice(reinterpret_cast<char*>(out.data()), 32));
}
Result<td::Ref<vm::Cell>> wrapper(vm::Dictionary& dict) {
  vm::CellBuilder b;
  if (!dict.append_dict_to_bool(b))
    return Error{"dictionary-shape"};
  return td::Ref<vm::Cell>(b.finalize());
}
template <class T>
Result<td::Ref<vm::Cell>> dictionary(const std::map<Hash, T>& values) {
  vm::Dictionary dict(256);
  for (const auto& [id, value] : values) {
    auto raw = encode(value);
    if (!raw.ok())
      return raw.error();
    auto cell = pack_bytes(raw.value());
    if (!cell.ok())
      return cell.error();
    if (!dict.set_ref(bits(id), 256, cell.value(), vm::Dictionary::SetMode::Add))
      return Error{"dictionary-key"};
  }
  return wrapper(dict);
}
template <class T>
Result<bool> load_dictionary(td::Ref<vm::Cell> root, std::map<Hash, T>& values, StateReadBudget& budget) {
  if (root.is_null() || root->get_level() != 0)
    return Error{"dictionary-shape"};
  vm::CellSlice s{vm::NoVm{}, root};
  if (!s.is_valid() || s.is_special() || s.size() != 1 || s.size_refs() != s.prefetch_ulong(1))
    return Error{"dictionary-shape"};
  vm::Dictionary dict(s, 256);
  Error failure{"dictionary-shape"};
  bool ok = dict.check_for_each([&](td::Ref<vm::CellSlice> value, td::ConstBitPtr key, int width) {
    if (width != 256 || value.is_null() || value->size() != 0 || value->size_refs() != 1)
      return false;
    if (budget.entries == 0) {
      failure = {"state-resource"};
      return false;
    }
    --budget.entries;
    Hash id{};
    td::BitPtr(id.data()).copy_from(key, 256);
    auto raw = unpack_bytes(value->prefetch_ref(), budget.bytes);
    if (!raw.ok()) {
      failure = raw.error();
      return false;
    }
    if (raw.value().size() > budget.bytes) {
      failure = {"state-resource"};
      return false;
    }
    budget.bytes -= raw.value().size();
    auto decoded = decode<T>(raw.value());
    if (!decoded.ok()) {
      failure = decoded.error();
      return false;
    }
    return values.emplace(id, std::move(decoded.value())).second;
  });
  if (!ok)
    return failure;
  return true;
}
}  // namespace
Result<std::optional<Identity>> RegistryState::lookup_identity(const Hash& id) const {
  auto it = identities_.find(id);
  return it == identities_.end() ? std::optional<Identity>{} : std::optional<Identity>{it->second};
}
Result<Key> RegistryState::find(const Hash& id) const {
  auto i = keys_.find(id);
  if (i == keys_.end())
    return Error{"unknown-key"};
  return i->second;
}
Result<std::uint64_t> RegistryState::latest_epoch(const Hash& identity, KeySlot slot) const {
  auto i = epochs_.find({identity, slot});
  return i == epochs_.end() ? 0 : i->second;
}
Result<bool> RegistryState::ever_registered(const Hash& identity) const {
  auto i = epochs_.lower_bound({identity, KeySlot{}});
  return i != epochs_.end() && i->first.first == identity;
}
Result<bool> RegistryState::rebuild_indexes() {
  epochs_.clear();
  due_.clear();
  std::set<std::tuple<Hash, KeySlot, std::uint64_t>> unique_epochs;
  for (const auto& [id, k] : keys_) {
    if (!unique_epochs.emplace(k.identity_, KeySlot{k.role_, k.suite_, k.parameters_}, k.epoch_).second)
      return Error{"duplicate-key-epoch"};
    auto& epoch = epochs_[{k.identity_, {k.role_, k.suite_, k.parameters_}}];
    epoch = std::max(epoch, k.epoch_);
  }
  for (const auto& [id, state] : identities_)
    for (const auto& pending : state.pending_) {
      if (pending.effective_from_ <= coordinate_)
        return Error{"state-overdue"};
      due_[pending.effective_from_].insert(id);
    }
  return true;
}
Result<Policy> RegistryState::policy_at(std::uint32_t at) const {
  if (at == std::numeric_limits<std::uint32_t>::max() || policies_.empty())
    return Error{"policy-history"};
  std::vector<std::pair<Hash, const Policy*>> ordered;
  for (const auto& [id, p] : policies_)
    ordered.push_back({id, &p});
  std::sort(ordered.begin(), ordered.end(),
            [](auto a, auto b) { return a.second->effective_from_ < b.second->effective_from_; });
  Hash previous{};
  std::uint64_t revision = 0;
  std::optional<std::uint32_t> height;
  const Policy* selected = nullptr;
  for (const auto& [id, p] : ordered) {
    if (revision == std::numeric_limits<std::uint64_t>::max() || p->revision_ != revision + 1 ||
        p->previous_ != previous || (!height && p->effective_from_ != 0) || (height && p->effective_from_ <= *height))
      return Error{"policy-history"};
    if (p->interface_digest_ != interface_fingerprint || p->phase_ != 0 || p->suites_ != std::vector<Suite>{{1, 1}} ||
        p->max_envelope_ != 4096 || p->max_certificate_ != 524288)
      return Error{"unsupported-profile"};
    if (p->effective_from_ <= at)
      selected = p;
    previous = id;
    revision = p->revision_;
    height = p->effective_from_;
  }
  if (!selected)
    return Error{"policy-history"};
  return *selected;
}
Result<bool> RegistryState::validate() {
  if (chain_domain_ == Hash{} || coordinate_ == std::numeric_limits<std::uint32_t>::max())
    return Error{"config-context"};
  for (const auto& [id, p] : policies_) {
    auto hash = object_id("policy", p);
    if (!hash.ok())
      return hash.error();
    if (hash.value() != id)
      return Error{"policy-hash"};
  }
  auto policy = policy_at(coordinate_);
  if (!policy.ok())
    return policy.error();
  auto pid = object_id("policy", policy.value());
  if (!pid.ok())
    return pid.error();
  if (pid.value() != current_policy_)
    return Error{"current-policy"};
  for (const auto& [id, k] : keys_) {
    auto hash = object_id("key", k);
    if (!hash.ok())
      return hash.error();
    if (hash.value() != id || !identities_.contains(k.identity_) || k.identity_ == Hash{})
      return Error{"key-hash-identity"};
    if (k.role_ < 1 || k.role_ > 5 || k.suite_ != 1 || k.parameters_ != 1 || k.epoch_ == 0 ||
        k.epoch_ == std::numeric_limits<std::uint64_t>::max() || k.valid_from_ >= k.valid_until_ ||
        k.capacity_domain_ != Hash{} || k.capacity_limit_ != 0)
      return Error{"key-descriptor"};
    auto admitted = AdmittedKey::admit(k.suite_, k.parameters_, k.public_key_);
    if (!admitted.ok())
      return admitted.error();
  }
  for (const auto& [id, state] : identities_) {
    if (id != state.identity_)
      return Error{"identity-key"};
    if (id == Hash{}) {
      if (!state.active_.empty() || !state.pending_.empty())
        return Error{"global-identity"};
      continue;
    }
    auto checked = validate_identity(state, *this);
    if (!checked.ok())
      return checked.error();
  }
  // Activation records are checked even before their effective boundary.
  Hash previous_activation{};
  std::uint64_t activation_revision = 0;
  for (const auto& [at, a] : activations_) {
    auto p = policies_.find(a.next_policy_);
    if (at != a.effective_from_ || p == policies_.end() || p->second.effective_from_ != at ||
        a.checkpoint_seqno_ >= at || a.checkpoint_root_ == Hash{} || a.checkpoint_file_ == Hash{} ||
        a.checkpoint_state_ == Hash{} || activation_revision == std::numeric_limits<std::uint64_t>::max() ||
        a.revision_ != activation_revision + 1 || a.previous_ != previous_activation)
      return Error{"activation-history"};
    auto id = object_id("activation", a);
    if (!id.ok())
      return id.error();
    previous_activation = id.value();
    activation_revision = a.revision_;
  }
  // The converse, which nothing checked: a policy that takes effect is a policy
  // something attested to. The activation carries the finalized checkpoint that
  // witnessed the change, and policy_at() selects purely by coordinate, so a
  // policy with no activation would govern every committee and session from its
  // boundary onward with no record that the change ever happened.
  //
  // Which policy the attestation is about needs no check here: the loop above
  // requires every activation to name a policy effective at its own coordinate,
  // and policy_at() refuses two policies sharing one. Checking it again would
  // be a guard no input can reach.
  for (const auto& [at, p] : policies_) {
    (void)at;
    if (p.effective_from_ == 0)
      continue;
    if (!activations_.contains(p.effective_from_))
      return Error{"policy-activation"};
  }
  for (const auto& [id, o] : observations_) {
    auto hash = object_id("observation", o);
    if (!hash.ok())
      return hash.error();
    if (id != hash.value() || o.suite_ == 0 || o.parameters_ == 0 || o.valid_from_ >= o.valid_until_ || o.enabled_ > 1)
      return Error{"observation"};
    if (o.enabled_)
      return Error{"unapproved-observation"};
  }
  return rebuild_indexes();
}
Result<RegistryState> RegistryState::genesis(Hash domain, const Policy& policy, std::vector<Identity> identities,
                                             std::vector<Key> keys) {
  RegistryState state;
  state.chain_domain_ = domain;
  auto id = object_id("policy", policy);
  if (!id.ok())
    return id.error();
  state.current_policy_ = id.value();
  state.policies_.emplace(id.value(), policy);
  for (auto& identity : identities)
    if (!state.identities_.emplace(identity.identity_, std::move(identity)).second)
      return Error{"duplicate-identity"};
  for (auto& key : keys) {
    auto hash = object_id("key", key);
    if (!hash.ok())
      return hash.error();
    if (!state.keys_.emplace(hash.value(), std::move(key)).second)
      return Error{"duplicate-key"};
  }
  auto valid = state.validate();
  if (!valid.ok())
    return valid.error();
  return state;
}
Result<td::Ref<vm::Cell>> RegistryState::encode_cell() const {
  try {
    auto identities = dictionary(identities_);
    if (!identities.ok())
      return identities.error();
    auto keys = dictionary(keys_);
    if (!keys.ok())
      return keys.error();
    auto policies = dictionary(policies_);
    if (!policies.ok())
      return policies.error();
    auto observations = dictionary(observations_);
    if (!observations.ok())
      return observations.error();
    vm::Dictionary activations(32);
    for (const auto& [at, a] : activations_) {
      std::array<std::uint8_t, 4> bytes{};
      for (unsigned i = 0; i < 4; ++i)
        bytes[i] = static_cast<std::uint8_t>(at >> (24 - i * 8));
      auto raw = encode(a);
      if (!raw.ok())
        return raw.error();
      auto cell = pack_bytes(raw.value());
      if (!cell.ok())
        return cell.error();
      if (!activations.set_ref(td::ConstBitPtr(bytes.data()), 32, cell.value(), vm::Dictionary::SetMode::Add))
        return Error{"activation-key"};
    }
    auto acts = wrapper(activations);
    if (!acts.ok())
      return acts.error();
    vm::CellBuilder control;
    control.store_long(0x76616331, 32).store_ref(acts.value()).store_ref(observations.value());
    vm::CellBuilder root;
    root.store_long(0x76617131, 32)
        .store_long(1, 16)
        .store_bytes(slice(chain_domain_))
        .store_bytes(slice(interface_fingerprint))
        .store_long(revision_, 64)
        .store_bytes(slice(current_policy_))
        .store_ref(identities.value())
        .store_ref(keys.value())
        .store_ref(policies.value())
        .store_ref(control.finalize());
    return td::Ref<vm::Cell>(root.finalize());
  } catch (const vm::VmError&) {
    return Error{"config-cell"};
  } catch (const vm::VmVirtError&) {
    return Error{"config-pruned"};
  }
}
Result<RegistryState> RegistryState::decode_cell(td::Ref<vm::Cell> root, std::uint32_t coordinate,
                                                 StateReadBudget budget) {
  try {
    if (root.is_null() || root->get_level() != 0)
      return Error{"config-cell"};
    vm::CellSlice s{vm::NoVm{}, root};
    if (!s.is_valid() || s.is_special() || s.size() != 880 || s.size_refs() != 4)
      return Error{"config-shape"};
    if (s.fetch_ulong(32) != 0x76617131 || s.fetch_ulong(16) != 1)
      return Error{"config-version"};
    RegistryState state;
    state.coordinate_ = coordinate;
    Hash fingerprint{};
    if (!read_hash(s, state.chain_domain_) || !read_hash(s, fingerprint) || fingerprint != interface_fingerprint)
      return Error{"interface-digest"};
    state.revision_ = s.fetch_ulong(64);
    if (!read_hash(s, state.current_policy_))
      return Error{"config-shape"};
    auto identities = load_dictionary(s.fetch_ref(), state.identities_, budget);
    if (!identities.ok())
      return identities.error();
    auto keys = load_dictionary(s.fetch_ref(), state.keys_, budget);
    if (!keys.ok())
      return keys.error();
    auto policies = load_dictionary(s.fetch_ref(), state.policies_, budget);
    if (!policies.ok())
      return policies.error();
    vm::CellSlice control{vm::NoVm{}, s.fetch_ref()};
    if (!control.is_valid() || control.is_special() || control.size() != 32 || control.size_refs() != 2 ||
        control.fetch_ulong(32) != 0x76616331)
      return Error{"control-shape"};
    auto activations_root = control.fetch_ref();
    vm::CellSlice ac{vm::NoVm{}, activations_root};
    if (!ac.is_valid() || ac.is_special() || ac.size() != 1 || ac.size_refs() != ac.prefetch_ulong(1))
      return Error{"activation-dictionary"};
    vm::Dictionary acts(ac, 32);
    Error failure{"activation-dictionary"};
    if (!acts.check_for_each([&](td::Ref<vm::CellSlice> value, td::ConstBitPtr key, int width) {
          if (width != 32 || value->size() != 0 || value->size_refs() != 1)
            return false;
          if (budget.entries == 0) {
            failure = {"state-resource"};
            return false;
          }
          --budget.entries;
          auto raw = unpack_bytes(value->prefetch_ref(), budget.bytes);
          if (!raw.ok()) {
            failure = raw.error();
            return false;
          }
          if (raw.value().size() > budget.bytes) {
            failure = {"state-resource"};
            return false;
          }
          budget.bytes -= raw.value().size();
          auto a = decode<Activation>(raw.value());
          if (!a.ok()) {
            failure = a.error();
            return false;
          }
          return state.activations_.emplace(static_cast<std::uint32_t>(key.get_uint(32)), a.value()).second;
        }))
      return failure;
    auto observations = load_dictionary(control.fetch_ref(), state.observations_, budget);
    if (!observations.ok())
      return observations.error();
    auto valid = state.validate();
    if (!valid.ok())
      return valid.error();
    return state;
  } catch (const vm::VmError&) {
    return Error{"config-cell"};
  } catch (const vm::VmVirtError&) {
    return Error{"config-pruned"};
  }
}
Result<RegistryState> RegistryState::apply_block(std::uint32_t at,
                                                 const std::vector<std::pair<Update, Authorizations>>& updates,
                                                 const LifecycleAuthority& authority) const {
  return apply_identity_block(at, updates,
                              [&](const RegistryState& current, const Update& update,
                                  const Authorizations& evidence) -> Result<IdentityChange> {
                                auto identity = current.identities_.find(update.identity_);
                                if (identity == current.identities_.end())
                                  return Error{"unknown-identity"};
                                return apply_identity_update(identity->second, current, update, evidence, at,
                                                             authority);
                              },
                              [&](const RegistryState& current, const Update& update,
                                  const Authorizations& evidence) -> Result<GlobalChange> {
                                return current.apply_global(update, evidence, at, authority);
                              });
}
// The pieces a global operation needs, gathered from this state rather than
// from the caller: the policy in force, the record holding the global nonce and
// the newest activation. A caller assembling them itself would be a second
// reading of what the state already holds.
Result<GlobalChange> RegistryState::apply_global(const Update& update, const Authorizations& evidence,
                                                 std::uint32_t at, const LifecycleAuthority& authority) const {
  auto in_force = policies_.find(current_policy_);
  if (in_force == policies_.end())
    return Error{"global-current-policy"};
  // Absent until a global operation first writes one. Its only content is the
  // nonce, and the encoding already admits a zero-identity record with no keys
  // and no pending transitions, so the first operation creates it rather than
  // requiring every chain to have been seeded with an empty one.
  Identity global;
  auto existing = identities_.find(Hash{});
  if (existing != identities_.end())
    global = existing->second;
  const Activation* latest = activations_.empty() ? nullptr : &activations_.rbegin()->second;
  return apply_global_update(update, evidence, *this, in_force->second, global, latest, at, authority);
}

Result<RegistryState> RegistryState::apply_identity_block(std::uint32_t at,
                                                          const std::vector<std::pair<Update, Authorizations>>& updates,
                                                          const IdentityApply& apply,
                                                          const GlobalApply& global) const {
  if (coordinate_ >= std::numeric_limits<std::uint32_t>::max() - 1 || at != coordinate_ + 1)
    return Error{"block-gap"};
  RegistryState next = *this;
  bool changed = false;
  auto due = due_.find(at);
  if (due != due_.end())
    for (const auto& id : due->second) {
      auto current = next.identities_.find(id);
      if (current == next.identities_.end())
        return Error{"due-index"};
      auto effect = apply_due_transitions(current->second, next, coordinate_, at);
      if (!effect.ok())
        return effect.error();
      current->second = effect.value();
      changed = true;
    }
  next.coordinate_ = at;
  auto selected = next.policy_at(at);
  if (!selected.ok())
    return selected.error();
  auto id = object_id("policy", selected.value());
  if (!id.ok())
    return id.error();
  next.current_policy_ = id.value();
  for (const auto& [update, evidence] : updates) {
    if (update.identity_ == Hash{}) {
      auto effect = global(next, update, evidence);
      if (!effect.ok())
        return effect.error();
      auto policy_id = object_id("policy", effect.value().policy);
      if (!policy_id.ok())
        return policy_id.error();
      if (!next.policies_.emplace(policy_id.value(), effect.value().policy).second)
        return Error{"duplicate-policy"};
      if (!next.activations_.emplace(effect.value().activation.effective_from_, effect.value().activation).second)
        return Error{"duplicate-activation"};
      next.identities_[Hash{}] = effect.value().global;
      changed = true;
      continue;
    }
    auto current = next.identities_.find(update.identity_);
    if (current == next.identities_.end())
      return Error{"unknown-identity"};
    auto effect = apply(next, update, evidence);
    if (!effect.ok())
      return effect.error();
    if (effect.value().archived_key) {
      const auto& k = *effect.value().archived_key;
      auto id = object_id("key", k);
      if (!id.ok())
        return id.error();
      if (!next.keys_.emplace(id.value(), k).second)
        return Error{"duplicate-key"};
      next.epochs_[{k.identity_, {k.role_, k.suite_, k.parameters_}}] = k.epoch_;
    }
    current->second = effect.value().identity;
    changed = true;
  }
  if (changed) {
    if (revision_ == std::numeric_limits<std::uint64_t>::max())
      return Error{"registry-revision"};
    next.revision_ = revision_ + 1;
  }
  auto indexes = next.rebuild_indexes();
  if (!indexes.ok())
    return indexes.error();
  return next;
}
}  // namespace tos::auth
