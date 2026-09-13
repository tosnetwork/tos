#include <set>

#include "lifecycle.h"
namespace tos::auth {
namespace {
KeySlot slot(const Key& k) {
  return {k.role_, k.suite_, k.parameters_};
}
KeySlot slot(const Roleref& r) {
  return {r.role_, r.key_.suite_, r.key_.parameters_};
}
KeySlot slot(const Transition& t) {
  return {t.role_, t.suite_, t.parameters_};
}
constexpr std::uint32_t max_coordinate = 0xffffffffu, max_delay = 65536;
class Overlay final : public KeyHistory {
  const KeyHistory& parent_;
  const Key& key_;
  Hash id_;

 public:
  Overlay(const KeyHistory& parent, const Key& key, Hash id) : parent_(parent), key_(key), id_(id) {
  }
  Result<Key> find(const Hash& id) const override {
    return id == id_ ? Result<Key>(key_) : parent_.find(id);
  }
  Result<std::uint64_t> latest_epoch(const Hash& identity, KeySlot s) const override {
    return parent_.latest_epoch(identity, s);
  }
  Result<bool> ever_registered(const Hash& identity) const override {
    return parent_.ever_registered(identity);
  }
};
Result<bool> verified(bool needed, const auto& rows, const auto& callback) {
  if (rows.size() != static_cast<std::size_t>(needed))
    return Error{"authority-shape"};
  if (!needed)
    return true;
  auto result = callback(rows[0]);
  if (!result.ok())
    return result.error();
  if (!result.value())
    return Error{"authority-refused"};
  return true;
}
}  // namespace
Result<bool> validate_identity(const Identity& state, const KeyHistory& archive) {
  auto encoded = encode(state);
  if (!encoded.ok())
    return encoded.error();
  if (state.identity_ == Hash{} || state.stake_id_ == Hash{})
    return Error{"identity-allocation"};
  std::map<KeySlot, Hash> active;
  std::set<KeySlot> pending, all;
  std::array<unsigned, 5> count{};
  KeySlot previous{};
  for (const auto& ref : state.active_) {
    auto s = slot(ref);
    if (s <= previous || ref.role_ < 1 || ref.role_ > 5 || ref.key_.suite_ == 0 || ref.key_.parameters_ == 0)
      return Error{"state-order"};
    previous = s;
    auto key = archive.find(ref.key_.key_id_);
    if (!key.ok())
      return key.error();
    auto canonical = key_reference(key.value());
    if (!canonical.ok())
      return canonical.error();
    if (canonical.value() != ref.key_ || key.value().identity_ != state.identity_ || key.value().role_ != ref.role_)
      return Error{"archive-binding"};
    active.emplace(s, ref.key_.key_id_);
    all.insert(s);
  }
  previous = {};
  for (const auto& p : state.pending_) {
    auto s = slot(p);
    if (s <= previous || p.role_ < 1 || p.role_ > 5 || p.suite_ == 0 || p.parameters_ == 0)
      return Error{"state-order"};
    previous = s;
    pending.insert(s);
    all.insert(s);
    if (p.operation_ < 1 || p.operation_ > 3)
      return Error{"pending-operation"};
    if (p.accepted_at_ >= p.effective_from_ || p.effective_from_ >= max_coordinate ||
        p.effective_from_ - p.accepted_at_ > max_delay)
      return Error{"pending-coordinate"};
    if (p.nonce_ >= state.next_nonce_ || p.update_id_ == Hash{} || p.authorization_id_ == Hash{} ||
        p.predecessor_ == Hash{})
      return Error{"pending-acceptance"};
    auto current = active.find(s);
    Hash old = current == active.end() ? Hash{} : current->second;
    if (old != p.old_key_ || (p.old_key_ == Hash{}) != (p.operation_ == 1) ||
        (p.new_key_ == Hash{}) != (p.operation_ == 3))
      return Error{"pending-old"};
    if (p.new_key_ != Hash{}) {
      auto k = archive.find(p.new_key_);
      if (!k.ok())
        return k.error();
      auto id = object_id("key", k.value());
      if (!id.ok())
        return id.error();
      if (id.value() != p.new_key_ || k.value().identity_ != state.identity_ || slot(k.value()) != s ||
          k.value().valid_from_ != p.effective_from_ || k.value().valid_until_ <= p.effective_from_)
        return Error{"pending-key"};
    }
  }
  if (all.size() > 10)
    return Error{"role-component-bound"};
  for (const auto& s : all)
    if (++count[std::get<0>(s) - 1] > 2)
      return Error{"role-component-bound"};
  return true;
}
Result<Identity> apply_due_transitions(const Identity& parent, const KeyHistory& archive,
                                       std::uint32_t parent_coordinate, std::uint32_t coordinate) {
  if (parent_coordinate >= max_coordinate - 1 || coordinate != parent_coordinate + 1)
    return Error{"block-gap"};
  auto checked = validate_identity(parent, archive);
  if (!checked.ok())
    return checked.error();
  for (const auto& p : parent.pending_)
    if (p.effective_from_ <= parent_coordinate)
      return Error{"stale-parent-state"};
  Identity result = parent;
  std::map<KeySlot, Roleref> active;
  for (const auto& ref : parent.active_)
    active.emplace(slot(ref), ref);
  bool changed = false;
  result.pending_.clear();
  for (const auto& p : parent.pending_) {
    if (p.effective_from_ > coordinate) {
      result.pending_.push_back(p);
      continue;
    }
    changed = true;
    active.erase(slot(p));
    if (p.new_key_ != Hash{}) {
      auto k = archive.find(p.new_key_);
      if (!k.ok())
        return k.error();
      auto ref = key_reference(k.value());
      if (!ref.ok())
        return ref.error();
      active.emplace(slot(p), Roleref{p.role_, ref.value()});
    }
  }
  if (changed) {
    auto previous = object_id("identity", parent);
    if (!previous.ok())
      return previous.error();
    result.previous_ = previous.value();
    result.active_.clear();
    for (const auto& [s, ref] : active)
      result.active_.push_back(ref);
  }
  return result;
}
Result<IdentityChange> apply_identity_update(const Identity& state, const KeyHistory& archive, const Update& update,
                                             const Authorizations& evidence, std::uint32_t at,
                                             const LifecycleAuthority& authority) {
  auto checked = validate_identity(state, archive);
  if (!checked.ok())
    return checked.error();
  auto uid = object_id("update", update);
  if (!uid.ok())
    return uid.error();
  auto aid = object_id("authorizations", evidence);
  if (!aid.ok())
    return aid.error();
  auto predecessor = object_id("identity", state);
  if (!predecessor.ok())
    return predecessor.error();
  if (at >= max_coordinate)
    return Error{"coordinate"};
  for (const auto& p : state.pending_)
    if (p.effective_from_ <= at)
      return Error{"due-phase-required"};
  auto op = update.operation_;
  if ((op != 1 && op != 2 && op != 3 && op != 7) || update.identity_ != state.identity_)
    return Error{"operation-target"};
  if (update.nonce_ < state.next_nonce_ || update.nonce_ == std::numeric_limits<std::uint64_t>::max())
    return Error{"nonce"};
  if (update.previous_ != predecessor.value())
    return Error{"predecessor"};
  if (!update.new_policy_.empty())
    return Error{"unused-field"};
  auto effective = (op == 3 || op == 7) && update.effective_from_ == 0 ? at : update.effective_from_;
  if (effective < at || effective >= max_coordinate || effective - at > max_delay)
    return Error{"effective-coordinate"};
  IdentityChange result{state, std::nullopt};
  KeySlot target{};
  Hash new_id{}, old_id{};
  if (op == 7) {
    if (update.effective_from_ != 0 || update.old_key_ != Hash{} || !update.new_key_.empty() ||
        update.operation_data_.size() != 32)
      return Error{"cancel-shape"};
    std::optional<std::size_t> found;
    for (std::size_t i = 0; i < state.pending_.size(); ++i) {
      auto id = object_id("transition", state.pending_[i]);
      if (!id.ok())
        return id.error();
      if (std::equal(id.value().begin(), id.value().end(), update.operation_data_.begin()))
        found = i;
    }
    if (!found)
      return Error{"cancel-target"};
    result.identity.pending_.erase(result.identity.pending_.begin() + *found);
  } else {
    if (!update.operation_data_.empty())
      return Error{"unused-field"};
    if (op == 1 || op == 2) {
      auto decoded = decode<Key>(update.new_key_);
      if (!decoded.ok())
        return decoded.error();
      auto key = decoded.value();
      target = slot(key);
      if (key.identity_ != state.identity_ || key.role_ < 1 || key.role_ > 5 || key.suite_ != 1 || key.parameters_ != 1)
        return Error{"new-key-identity"};
      if (key.valid_from_ != effective || key.valid_until_ <= effective)
        return Error{"new-key-validity"};
      auto epoch = archive.latest_epoch(key.identity_, target);
      if (!epoch.ok())
        return epoch.error();
      if (key.epoch_ <= epoch.value() || key.epoch_ == std::numeric_limits<std::uint64_t>::max())
        return Error{"epoch"};
      if (key.capacity_domain_ != Hash{} || key.capacity_limit_ != 0)
        return Error{"c0-capacity"};
      auto admitted = AdmittedKey::admit(key.public_key_);
      if (!admitted.ok())
        return admitted.error();
      auto id = object_id("key", key);
      if (!id.ok())
        return id.error();
      new_id = id.value();
      result.archived_key = key;
    } else {
      if (!update.new_key_.empty())
        return Error{"unused-field"};
      auto old = archive.find(update.old_key_);
      if (!old.ok())
        return old.error();
      if (old.value().identity_ != state.identity_)
        return Error{"old-key"};
      target = slot(old.value());
    }
    for (const auto& ref : state.active_)
      if (slot(ref) == target)
        old_id = ref.key_.key_id_;
    if (update.old_key_ != old_id || (old_id == Hash{}) != (op == 1))
      return Error{"old-key"};
    for (const auto& p : state.pending_)
      if (slot(p) == target)
        return Error{"pending-conflict"};
    if (effective == at) {
      auto& refs = result.identity.active_;
      refs.erase(std::remove_if(refs.begin(), refs.end(), [&](const auto& ref) { return slot(ref) == target; }),
                 refs.end());
      if (result.archived_key) {
        auto ref = key_reference(*result.archived_key);
        if (!ref.ok())
          return ref.error();
        refs.push_back({std::get<0>(target), ref.value()});
      }
      std::sort(refs.begin(), refs.end(), [](const auto& a, const auto& b) { return slot(a) < slot(b); });
    } else {
      result.identity.pending_.push_back({op, std::get<0>(target), std::get<1>(target), std::get<2>(target), old_id,
                                          new_id, effective, at, update.nonce_, update.previous_, uid.value(),
                                          aid.value()});
      std::sort(result.identity.pending_.begin(), result.identity.pending_.end(),
                [](const auto& a, const auto& b) { return slot(a) < slot(b); });
    }
  }
  auto registered = archive.ever_registered(state.identity_);
  if (!registered.ok())
    return registered.error();
  bool initial = !registered.value();
  if (initial && (op != 1 || std::get<0>(target) != 5))
    return Error{"initial-register"};
  if (!evidence.governance_.empty())
    return Error{"authority-shape"};
  auto owner = verified(op == 1 || op == 2, evidence.owner_, [&](const OwnerAuth& proof) -> Result<bool> {
    if (proof.update_id_ != uid.value() || proof.stake_id_ != state.stake_id_ ||
        proof.owner_workchain_ != state.owner_workchain_ || proof.owner_address_ != state.owner_address_)
      return Error{"owner-binding"};
    return authority.owner(proof, update, state);
  });
  if (!owner.ok())
    return owner.error();
  auto pop = verified(op == 1 || op == 2, evidence.possession_, [&](const PossessionAuth& proof) -> Result<bool> {
    if (!result.archived_key)
      return Error{"pop-key"};
    auto ref = key_reference(*result.archived_key);
    if (!ref.ok())
      return ref.error();
    if (proof.update_id_ != uid.value() || proof.key_ != ref.value())
      return Error{"pop-binding"};
    return authority.possession(proof, update, *result.archived_key);
  });
  if (!pop.ok())
    return pop.error();
  auto admin = verified(!initial, evidence.administration_, [&](const IdentityAuth& proof) -> Result<bool> {
    if (proof.update_id_ != uid.value() || proof.identity_ != state.identity_)
      return Error{"admin-binding"};
    return authority.administration(proof, update, state, at);
  });
  if (!admin.ok())
    return admin.error();
  result.identity.next_nonce_ = update.nonce_ + 1;
  result.identity.previous_ = predecessor.value();
  auto final = result.archived_key ? validate_identity(result.identity, Overlay(archive, *result.archived_key, new_id))
                                   : validate_identity(result.identity, archive);
  if (!final.ok())
    return final.error();
  return result;
}
Result<std::vector<Key>> select_identity_keys(const Identity& state, const KeyHistory& archive, std::uint32_t anchor,
                                              const std::vector<KeySlot>& required) {
  auto checked = validate_identity(state, archive);
  if (!checked.ok())
    return checked.error();
  for (const auto& p : state.pending_)
    if (p.effective_from_ <= anchor)
      return Error{"snapshot-state-not-current"};
  std::vector<Key> result;
  for (const auto& wanted : required) {
    bool found = false;
    for (const auto& ref : state.active_)
      if (slot(ref) == wanted) {
        auto k = archive.find(ref.key_.key_id_);
        if (!k.ok())
          return k.error();
        if (k.value().valid_from_ > anchor || k.value().valid_until_ <= anchor)
          return Error{"snapshot-validity"};
        result.push_back(k.value());
        found = true;
        break;
      }
    if (!found)
      return Error{"snapshot-missing"};
  }
  return result;
}
}  // namespace tos::auth
